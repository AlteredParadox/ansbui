package ansible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// AdhocRequest is a request to run `ansible <target> -m <module> -a
// "<args>"` on the remote control node.
type AdhocRequest struct {
	Target  string            `json:"target"`
	Module  string            `json:"module"`
	Args    map[string]string `json:"args"`
	Become  bool              `json:"become"`
	Check   bool              `json:"check"`
	Forks   int               `json:"forks"`
	Timeout int               `json:"timeout"`
}

// PlaybookRequest is a request to run `ansible-playbook <path>`.
//
// VaultPassword, when set, is fed to ansible-playbook via stdin + a
// /dev/fd/3 password file so the value never appears in argv. The
// field is intentionally not copied into RunRecord by
// buildPlaybookRecord (in internal/api/ws.go) — anyone adding new
// persistence paths must keep that invariant.
type PlaybookRequest struct {
	Path          string         `json:"path"`
	Limit         string         `json:"limit,omitempty"`
	Tags          []string       `json:"tags,omitempty"`
	ExtraVars     map[string]any `json:"extraVars,omitempty"`
	Check         bool           `json:"check"`
	Become        bool           `json:"become"`
	VaultPassword string         `json:"vaultPassword,omitempty"`
}

// Event is a single message streamed to the UI while a run is in flight.
type Event struct {
	Type   string `json:"type"`
	Host   string `json:"host,omitempty"`
	Status string `json:"status,omitempty"`
	Text   string `json:"text,omitempty"`
	Stream string `json:"stream,omitempty"`
}

// RunAdhoc streams events over the supplied channel. The channel is
// closed when the run finishes. ctx cancels the remote process.
func RunAdhoc(ctx context.Context, pool *sshpool.Pool, srv config.Server, req AdhocRequest, out chan<- Event) (err error) {
	defer close(out)
	defer func() { err = recoverRunner(recover(), out, err) }()
	cmd, berr := buildAdhocCmd(srv, req)
	if berr != nil {
		return berr
	}
	return runStreaming(ctx, pool, srv, cmd, "", out)
}

// RunPlaybook streams events from `ansible-playbook`. If
// req.VaultPassword is set, the password is piped via stdin to a
// bash-wrapped script that exposes it on /dev/fd/3 for
// ansible-playbook's --vault-password-file. Argv stays clean.
//
// req.Limit is used verbatim. Auto-include from the playbook's
// `# ansbui-include:` annotation is applied by the API handler
// (internal/api/ws.go's prepPlaybook) before this is called, so
// the persisted RunRecord and the live event log both reflect
// the merged target set.
func RunPlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, req PlaybookRequest, out chan<- Event) (err error) {
	defer close(out)
	defer func() { err = recoverRunner(recover(), out, err) }()
	if req.VaultPassword != "" {
		if verr := validateVaultPassword(req.VaultPassword); verr != nil {
			out <- Event{Type: "error", Text: verr.Error()}
			return verr
		}
	}
	cmd, berr := buildPlaybookCmd(srv, req)
	if berr != nil {
		return berr
	}
	return runStreaming(ctx, pool, srv, cmd, req.VaultPassword, out)
}

// recoverRunner converts a panic in RunAdhoc/RunPlaybook into a
// returned error, so a regression that nil-derefs in the regex
// classification or a misuse of the SSH session doesn't crash the
// whole binary and kill every other in-flight run. We emit an
// error event BEFORE the deferred close(out) fires (defers run
// LIFO; this function is registered after `defer close(out)` so
// it runs first), which keeps the WS consumer's render loop
// telling the operator something happened. The original panic
// value is logged with a stack — the WS event is intentionally
// generic since `r` could carry secrets.
func recoverRunner(r any, out chan<- Event, prev error) error {
	if r == nil {
		return prev
	}
	log.Printf("ansible runner panic: %v\n%s", r, debug.Stack())
	out <- Event{Type: "error", Text: "ansbui internal error — see server log"}
	return errors.New("internal error in ansible runner")
}

func runStreaming(ctx context.Context, pool *sshpool.Pool, srv config.Server, cmd, stdin string, out chan<- Event) error {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	out <- Event{Type: "meta", Text: fmt.Sprintf("$ %s", cmd)}

	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	done := make(chan error, 1)

	var stdinR io.Reader
	if stdin != "" {
		stdinR = strings.NewReader(stdin)
	}
	go func() {
		done <- sshpool.Stream(ctx, cli, cmd, stdinR, stdoutW, stderrW)
		_ = stdoutW.Close()
		_ = stderrW.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); scanLines(ctx, stdoutR, "stdout", out) }()
	go func() { defer wg.Done(); scanLines(ctx, stderrR, "stderr", out) }()

	// On cancel the scanners stop reading, but the ssh session's
	// io.Copy may still be blocked mid-Write into one of these
	// unbuffered pipes. sess.Close() only unblocks channel reads,
	// not pipe writes, so Session.Wait() — and therefore Stream and
	// this function — would park forever: the run never persists and
	// the whole pipeline (goroutines + ssh session) leaks per event.
	// Failing the read ends makes those blocked writes return an
	// error so the session can unwind.
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stdoutR.CloseWithError(ctx.Err())
			_ = stderrR.CloseWithError(ctx.Err())
		case <-watchDone:
		}
	}()

	start := time.Now()
	runErr := <-done
	// Drain both pipe scanners before we send any further events —
	// otherwise close(out) in our caller can race with an in-flight
	// scanLines send and panic on "send on closed channel".
	wg.Wait()
	close(watchDone)
	out <- Event{Type: "done", Text: fmt.Sprintf("completed in %.1fs", time.Since(start).Seconds())}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

// line matchers for ansible output. We don't try to fully parse — we
// tag common prefixes so the UI can colour them.
var (
	okLine       = regexp.MustCompile(`^ok: \[([^\]]+)\]`)
	changedLine  = regexp.MustCompile(`^changed: \[([^\]]+)\]`)
	failedLine   = regexp.MustCompile(`^fatal: \[([^\]]+)\]`)
	unreachLine  = regexp.MustCompile(`^unreachable: \[([^\]]+)\]`)
	skippedLine  = regexp.MustCompile(`^skipping: \[([^\]]+)\]`)
	playHeadLine = regexp.MustCompile(`^(PLAY|TASK|PLAY RECAP)\b`)
	recapLine    = regexp.MustCompile(`^(\S+)\s*:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)`)
)

func scanLines(ctx context.Context, r io.Reader, stream string, out chan<- Event) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		select {
		case out <- classify(sc.Text(), stream):
		case <-ctx.Done():
			return
		}
	}
}

func classify(line, stream string) Event {
	switch {
	case playHeadLine.MatchString(line):
		return Event{Type: "meta", Text: line, Stream: stream}
	case recapLine.MatchString(line):
		m := recapLine.FindStringSubmatch(line)
		// Capture groups: 1=host, 2=ok, 3=changed, 4=unreachable, 5=failed.
		// A task that failed *or* a host we couldn't reach both count
		// as a recap-fail; changed>0 with no hard errors is recap-warn.
		t := "recap"
		switch {
		case m[5] != "0" || m[4] != "0":
			t = "recap-fail"
		case m[3] != "0":
			t = "recap-warn"
		}
		return Event{Type: t, Host: m[1], Text: line, Stream: stream}
	case okLine.MatchString(line):
		return Event{Type: "ok", Host: okLine.FindStringSubmatch(line)[1], Text: line, Stream: stream}
	case changedLine.MatchString(line):
		return Event{Type: "changed", Host: changedLine.FindStringSubmatch(line)[1], Text: line, Stream: stream}
	case failedLine.MatchString(line):
		return Event{Type: "fail", Host: failedLine.FindStringSubmatch(line)[1], Text: line, Stream: stream}
	case unreachLine.MatchString(line):
		return Event{Type: "fail", Host: unreachLine.FindStringSubmatch(line)[1], Text: line, Stream: stream}
	case skippedLine.MatchString(line):
		return Event{Type: "meta", Host: skippedLine.FindStringSubmatch(line)[1], Text: line, Stream: stream}
	}
	return Event{Type: "line", Text: line, Stream: stream}
}

func buildAdhocCmd(srv config.Server, req AdhocRequest) (string, error) {
	if strings.TrimSpace(req.Target) == "" {
		return "", errors.New("target is required")
	}
	if strings.TrimSpace(req.Module) == "" {
		return "", errors.New("module is required")
	}
	var b strings.Builder
	if srv.WorkDir != "" {
		fmt.Fprintf(&b, "cd %s && ", shellQuote(srv.WorkDir))
	}
	b.WriteString("ANSIBLE_FORCE_COLOR=0 ansible ")
	b.WriteString(shellQuote(req.Target))
	b.WriteString(" -m ")
	b.WriteString(shellQuote(req.Module))
	if srv.Inventory != "" {
		b.WriteString(" -i ")
		b.WriteString(shellQuote(srv.Inventory))
	}
	if args := buildArgString(req.Args); args != "" {
		b.WriteString(" -a ")
		b.WriteString(shellQuote(args))
	}
	if req.Become {
		b.WriteString(" --become")
	}
	if req.Check {
		b.WriteString(" --check")
	}
	if req.Forks > 0 {
		fmt.Fprintf(&b, " --forks %d", req.Forks)
	}
	if req.Timeout > 0 {
		fmt.Fprintf(&b, " --timeout %d", req.Timeout)
	}
	b.WriteString(" 2>&1")
	return b.String(), nil
}

func buildPlaybookCmd(srv config.Server, req PlaybookRequest) (string, error) {
	if err := validateRelPath(req.Path); err != nil {
		return "", err
	}
	var b strings.Builder
	if srv.WorkDir != "" {
		fmt.Fprintf(&b, "cd %s && ", shellQuote(srv.WorkDir))
	}
	b.WriteString("ANSIBLE_FORCE_COLOR=0 ansible-playbook ")
	b.WriteString(shellQuote(req.Path))
	if srv.Inventory != "" {
		b.WriteString(" -i ")
		b.WriteString(shellQuote(srv.Inventory))
	}
	if req.Limit != "" {
		b.WriteString(" --limit ")
		b.WriteString(shellQuote(req.Limit))
	}
	if len(req.Tags) > 0 {
		b.WriteString(" --tags ")
		b.WriteString(shellQuote(strings.Join(req.Tags, ",")))
	}
	if extra, err := buildExtraVarsArg(req.ExtraVars); err != nil {
		return "", err
	} else if extra != "" {
		b.WriteString(" --extra-vars ")
		b.WriteString(shellQuote(extra))
	}
	if req.Check {
		b.WriteString(" --check")
	}
	if req.Become {
		b.WriteString(" --become")
	}
	if req.VaultPassword != "" {
		b.WriteString(" --vault-password-file=/dev/fd/3")
	}
	b.WriteString(" 2>&1")
	cmd := b.String()
	if req.VaultPassword != "" {
		// PASS=$(cat) reads the password from stdin into a shell var,
		// then exec 3< <(printf '%s' "$PASS") exposes it on FD 3 so
		// ansible-playbook's --vault-password-file=/dev/fd/3 can read
		// it. printf is a bash builtin (no exec) writing into the FIFO
		// from process substitution — keeps the value entirely in
		// pipes, with no chance of a /tmp window even on older bash
		// where here-strings (<<<) could spill to disk. The password
		// never appears in argv or in the saved log.
		script := `PASS=$(cat) && exec 3< <(printf '%s' "$PASS") && ` + cmd
		cmd = "/usr/bin/env bash -c " + shellQuote(script)
	}
	return cmd, nil
}

var argKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// buildExtraVarsArg serialises a typed key/value map to the JSON form
// that ansible-playbook accepts with `--extra-vars`. Keys are
// validated against the same safe-name regex we use for ad-hoc args so
// we don't splice arbitrary shell tokens; values are passed through as
// whatever JSON type the caller supplied (string, number, bool, list,
// nested object) and re-encoded with json.Marshal, which handles all
// escaping. nil values are dropped so a half-filled row doesn't send
// `"key": null` unless the user explicitly typed it.
func buildExtraVarsArg(vars map[string]any) (string, error) {
	if len(vars) == 0 {
		return "", nil
	}
	clean := make(map[string]any, len(vars))
	for k, v := range vars {
		if !argKeyRE.MatchString(k) {
			return "", fmt.Errorf("invalid extra-var name %q (must match %s)", k, argKeyRE)
		}
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		clean[k] = v
	}
	if len(clean) == 0 {
		return "", nil
	}
	data, err := json.Marshal(clean)
	if err != nil {
		return "", fmt.Errorf("encode extra-vars: %w", err)
	}
	return string(data), nil
}

func buildArgString(args map[string]string) string {
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, 0, len(args))
	for k, v := range args {
		if !argKeyRE.MatchString(k) {
			continue
		}
		if v == "" {
			continue
		}
		// Ansible parses k=v with shlex, which interprets backslash
		// as a POSIX escape character — `path=C:\Users\foo` would
		// reach the module as `path=C:Usersfoo` after shlex strips
		// the unescaped backslashes. Escape `\` to `\\` BEFORE we
		// escape `"` (so the trailing backslash of `\"` doesn't
		// double-escape itself), then wrap the value in `"…"` so
		// embedded spaces survive shlex's word split.
		escaped := strings.ReplaceAll(v, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `"`, `\"`)
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escaped))
	}
	return strings.Join(parts, " ")
}
