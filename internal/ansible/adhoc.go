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
	"sort"
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
	cmd, preview, berr := buildAdhocCmd(srv, req)
	if berr != nil {
		out <- Event{Type: "error", Text: berr.Error()}
		return berr
	}
	return runStreaming(ctx, pool, srv, cmd, preview, "", out)
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
	cmd, preview, berr := buildPlaybookCmd(srv, req)
	if berr != nil {
		out <- Event{Type: "error", Text: berr.Error()}
		return berr
	}
	return runStreaming(ctx, pool, srv, cmd, preview, req.VaultPassword, out)
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

// runStreaming executes cmd on the control node and streams its
// output as events. preview is what the operator is shown, and what
// is saved, as the command that ran: the same command line built from
// inputs whose secrets were already removed by key (see
// buildPlaybookCmd). It is never derived from cmd. cmd is shell-quoted
// and JSON-encoded, and no pattern can reliably find the end of a
// secret in that — a single quote in a password becomes '"'"', a list
// of tokens has no closing quote where the pattern expects one — so
// redacting cmd's text left the tail of the value in history.
func runStreaming(ctx context.Context, pool *sshpool.Pool, srv config.Server, cmd, preview, stdin string, out chan<- Event) error {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		// Every early return must leave an error event behind —
		// the persisted status is derived solely from the event
		// stream, so a silent return here recorded the run as "ok".
		out <- Event{Type: "error", Text: "connect to control node: " + err.Error()}
		return err
	}
	// RedactText is a second pass over text that is already clean of
	// structured secrets: it catches key=value shapes inside free-text
	// inputs (a --limit, a tag) that have no key to redact by.
	out <- Event{Type: "meta", Text: fmt.Sprintf("$ %s", RedactText(preview))}

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
	elapsed := fmt.Sprintf("%.1fs", time.Since(start).Seconds())
	// The terminal event decides the persisted status (ws.go's
	// consumeAndPersist/finalStatus), so every outcome must be
	// explicit here. Before this, a cancelled run emitted a plain
	// "done" and a remote failure was only returned to a goroutine
	// that logged it — both could be recorded as "ok" if no
	// recognisable per-task failure line happened to land first.
	if errors.Is(runErr, context.Canceled) || ctx.Err() != nil {
		out <- Event{Type: "cancelled", Text: "run cancelled after " + elapsed}
		return context.Canceled
	}
	if runErr != nil {
		out <- Event{Type: "error", Text: fmt.Sprintf("run failed after %s: %v", elapsed, runErr)}
		return runErr
	}
	out <- Event{Type: "done", Text: "completed in " + elapsed}
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

// maxScanLine caps a single output line. Lines beyond it abort that
// stream's scan with bufio.ErrTooLong — see scanLines for why that
// must fail the pipe rather than silently stop reading.
const maxScanLine = 1024 * 1024

// maxLiveLineBytes caps the text of one EVENT, applied before the
// line enters the events channel. The scanner tolerates lines up to
// maxScanLine so a long line doesn't abort the run, but shipping
// them whole meant a 64-event channel could buffer ~64 MiB per run
// against a slow WebSocket peer (× 8 concurrent runs) — the history
// cap only applied after the live write. 64 KiB matches the history
// per-event ceiling, so nothing that would have been retained is
// lost; the byte-slice cut can split a UTF-8 rune, same accepted
// tradeoff as the history cap.
const maxLiveLineBytes = 64 << 10

func scanLines(ctx context.Context, r *io.PipeReader, stream string, out chan<- Event) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxScanLine)
	for sc.Scan() {
		line := sc.Text()
		if len(line) > maxLiveLineBytes {
			line = line[:maxLiveLineBytes] + "… [line truncated]"
		}
		select {
		case out <- classify(line, stream):
		case <-ctx.Done():
			_ = r.CloseWithError(ctx.Err())
			return
		}
	}
	// A scan abort (line over maxScanLine, or any read error) used to
	// just return, leaving the pipe open with nobody reading: the SSH
	// session's next Write into it would block forever and the whole
	// run wedged waiting for a completion that could never come.
	// Failing the read end makes those writes error so the session
	// unwinds, and the event tells the operator output was dropped.
	if err := sc.Err(); err != nil {
		_ = r.CloseWithError(fmt.Errorf("%s aborted: %w", stream, err))
		out <- Event{Type: "error", Text: fmt.Sprintf("%s stream aborted: %v (single lines over %d bytes can't be streamed — remaining %s output is dropped)", stream, err, maxScanLine, stream)}
		return
	}
	_ = r.Close()
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

// buildAdhocCmd returns the command to execute and its preview: the
// same command line with every module argument under a secret-looking
// name replaced before quoting (see runStreaming for why the preview
// is built separately and not redacted from cmd).
func buildAdhocCmd(srv config.Server, req AdhocRequest) (cmd, preview string, err error) {
	if strings.TrimSpace(req.Target) == "" {
		return "", "", errors.New("target is required")
	}
	if strings.TrimSpace(req.Module) == "" {
		return "", "", errors.New("module is required")
	}
	return adhocCommandLine(srv, req, req.Args), adhocCommandLine(srv, req, redactedArgs(req.Args)), nil
}

// redactedArgs is RedactStringMap, except that an empty value stays
// empty: buildArgString drops empty arguments, and the preview must
// not show one the real command does not carry.
func redactedArgs(args map[string]string) map[string]string {
	red := RedactStringMap(args)
	for k, v := range args {
		if v == "" {
			red[k] = ""
		}
	}
	return red
}

// adhocCommandLine renders the `ansible` invocation for req with the
// given module arguments.
func adhocCommandLine(srv config.Server, req AdhocRequest, args map[string]string) string {
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
	if argStr := buildArgString(args); argStr != "" {
		b.WriteString(" -a ")
		b.WriteString(shellQuote(argStr))
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
	return b.String()
}

// buildPlaybookCmd returns the command to execute and its preview.
//
// The preview is the ansible-playbook command line rendered from
// extra-vars whose secret-named entries were replaced BEFORE the JSON
// encoding and shell quoting (RedactAnyMap), so a whole value goes —
// a password containing a quote, a list of tokens, a nested object —
// whatever it looks like once encoded. See runStreaming.
//
// The preview also leaves out the bash wrapper that feeds the vault
// password on fd 3. That is plumbing, it contains the text
// `PASS=$(cat)` which reads as a secret assignment, and the flag that
// matters to the operator (--vault-password-file=/dev/fd/3) is on the
// command line itself.
func buildPlaybookCmd(srv config.Server, req PlaybookRequest) (cmd, preview string, err error) {
	if err := validateRelPath(req.Path); err != nil {
		return "", "", err
	}
	vars, err := cleanExtraVars(req.ExtraVars)
	if err != nil {
		return "", "", err
	}
	line, err := playbookCommandLine(srv, req, vars)
	if err != nil {
		return "", "", err
	}
	preview, err = playbookCommandLine(srv, req, RedactAnyMap(vars))
	if err != nil {
		return "", "", err
	}
	cmd = line
	if req.VaultPassword != "" {
		// PASS=$(cat) reads the password from stdin into a shell var,
		// then exec 3< <(printf '%s' "$PASS") exposes it on FD 3 so
		// ansible-playbook's --vault-password-file=/dev/fd/3 can read
		// it. printf is a bash builtin (no exec) writing into the FIFO
		// from process substitution — keeps the value entirely in
		// pipes, with no chance of a /tmp window even on older bash
		// where here-strings (<<<) could spill to disk. The password
		// never appears in argv or in the saved log.
		script := `PASS=$(cat) && exec 3< <(printf '%s' "$PASS") && ` + line
		cmd = "/usr/bin/env bash -c " + shellQuote(script)
	}
	return cmd, preview, nil
}

// playbookCommandLine renders the `ansible-playbook` invocation for
// req with the given (already cleaned) extra-vars.
func playbookCommandLine(srv config.Server, req PlaybookRequest, vars map[string]any) (string, error) {
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
	if extra, err := encodeExtraVars(vars); err != nil {
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
	return b.String(), nil
}

var argKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// cleanExtraVars validates the extra-var names and drops the entries
// that are not sent. Keys are validated against the same safe-name
// regex we use for ad-hoc args so we don't splice arbitrary shell
// tokens. nil and empty-string values are dropped so a half-filled row
// doesn't send `"key": null` unless the user explicitly typed it.
// Split from the encoding so the command and its preview are rendered
// from the same set of entries.
func cleanExtraVars(vars map[string]any) (map[string]any, error) {
	if len(vars) == 0 {
		return nil, nil
	}
	clean := make(map[string]any, len(vars))
	for k, v := range vars {
		if !argKeyRE.MatchString(k) {
			return nil, fmt.Errorf("invalid extra-var name %q (must match %s)", k, argKeyRE)
		}
		if v == nil {
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		clean[k] = v
	}
	return clean, nil
}

// encodeExtraVars serialises cleaned extra-vars to the JSON form that
// ansible-playbook accepts with `--extra-vars`. Values are whatever
// JSON type the caller supplied (string, number, bool, list, nested
// object), re-encoded with json.Marshal, which handles all escaping
// and writes keys in sorted order.
func encodeExtraVars(clean map[string]any) (string, error) {
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
	// Sorted, so the command and its preview list the arguments in the
	// same order (map iteration would shuffle each independently).
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(args))
	for _, k := range keys {
		v := args[k]
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
