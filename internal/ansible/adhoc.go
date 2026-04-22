package ansible

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/AlteredParadox/relay/internal/config"
	"github.com/AlteredParadox/relay/internal/sshpool"
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
type PlaybookRequest struct {
	Path    string   `json:"path"`
	Limit   string   `json:"limit,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	Check   bool     `json:"check"`
	Become  bool     `json:"become"`
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
func RunAdhoc(ctx context.Context, pool *sshpool.Pool, srv config.Server, req AdhocRequest, out chan<- Event) error {
	defer close(out)
	cmd, err := buildAdhocCmd(srv, req)
	if err != nil {
		return err
	}
	return runStreaming(ctx, pool, srv, cmd, out)
}

// RunPlaybook streams events from `ansible-playbook`.
func RunPlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, req PlaybookRequest, out chan<- Event) error {
	defer close(out)
	cmd, err := buildPlaybookCmd(srv, req)
	if err != nil {
		return err
	}
	return runStreaming(ctx, pool, srv, cmd, out)
}

func runStreaming(ctx context.Context, pool *sshpool.Pool, srv config.Server, cmd string, out chan<- Event) error {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	out <- Event{Type: "meta", Text: fmt.Sprintf("$ %s", cmd)}

	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	done := make(chan error, 1)

	go func() {
		done <- sshpool.Stream(ctx, cli, cmd, stdoutW, stderrW)
		_ = stdoutW.Close()
		_ = stderrW.Close()
	}()

	go scanLines(stdoutR, "stdout", out)
	go scanLines(stderrR, "stderr", out)

	start := time.Now()
	runErr := <-done
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

func scanLines(r io.Reader, stream string, out chan<- Event) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		out <- classify(line, stream)
	}
}

func classify(line, stream string) Event {
	switch {
	case playHeadLine.MatchString(line):
		return Event{Type: "meta", Text: line, Stream: stream}
	case recapLine.MatchString(line):
		m := recapLine.FindStringSubmatch(line)
		t := "recap"
		if m[4] != "0" {
			t = "recap-fail"
		} else if m[3] != "0" {
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
	if req.Check {
		b.WriteString(" --check")
	}
	if req.Become {
		b.WriteString(" --become")
	}
	b.WriteString(" 2>&1")
	return b.String(), nil
}

var argKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
		// Ansible's k=v parser needs the value quoted if it contains
		// spaces. We wrap every value defensively.
		escaped := strings.ReplaceAll(v, `"`, `\"`)
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escaped))
	}
	return strings.Join(parts, " ")
}
