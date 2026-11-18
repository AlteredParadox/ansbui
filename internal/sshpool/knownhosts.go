package sshpool

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsMu guards appendKnownHost. Concurrent dials to new hosts
// can otherwise interleave writes and corrupt the file.
var knownHostsMu sync.Mutex

// knownHostsCallback verifies against ~/.ssh/known_hosts when the host is
// recorded; when it isn't, it records it on first use. knownhosts.New
// won't create the file — it opens for read and returns ENOENT if
// missing — so we touch it (0o600) on a fresh system before loading
// the strict callback.
//
// TOFU race: the outer strict callback is loaded once and its
// in-memory DB is a snapshot. If two parallel first-contact dials
// to the same host see different keys, both observe an empty DB
// in this snapshot and would both append. appendKnownHost re-loads
// under the mutex and re-verifies before writing, so only the
// first key gets recorded — the second dial fails on mismatch
// like any other key change.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	if err := ensureKnownHostsExists(path); err != nil {
		return nil, err
	}
	if err := ensureKnownHostsMode(path); err != nil {
		return nil, err
	}
	warnKnownHostsWildcardsOnce(path)
	strict, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := strict(hostname, remote, key)
		if err == nil {
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		// A KeyError with a populated Want slice means the host is
		// recorded with a *different* key — that's a hard fail
		// (potential MITM), not an accept-on-first-use.
		if len(keyErr.Want) > 0 {
			return err
		}
		return appendKnownHost(path, hostname, remote, key)
	}, nil
}

// ensureKnownHostsExists creates the file 0o600 if missing.
// knownhosts.New opens-for-read and returns ENOENT otherwise,
// which would push every fresh-system dial into fail-closed mode.
// Touching the file is equivalent to the empty-file the user would
// have ended up with on first ssh anyway.
func ensureKnownHostsExists(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create known_hosts: %w", err)
	}
	return f.Close()
}

// ensureKnownHostsMode chmods the file to 0o600 if it is group- or
// world-readable. ssh-agent and sshd both warn / refuse on permissive
// known_hosts files; we should not silently write to one either.
func ensureKnownHostsMode(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Missing file is fine — appendKnownHost creates it 0o600.
			return nil
		}
		return fmt.Errorf("stat known_hosts: %w", err)
	}
	if st.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("tighten known_hosts perms: %w", err)
	}
	return nil
}

// appendKnownHost serialises the TOFU write and re-verifies under
// the mutex. Re-loading is what closes the race the snapshot-based
// outer strict callback can't see: another goroutine may have
// appended a *different* key for this host between the outer
// strict() check and now. Three outcomes:
//
//   - fresh.New + fresh callback says "match" → another dial just
//     recorded the same key (we raced ourselves to the empty-DB
//     observation but both saw the right key); nothing to do.
//   - fresh callback says "mismatch with Want" → another dial
//     recorded a *different* key; refuse to append. The caller
//     gets a real KeyError, same as a long-after-recording MITM.
//   - fresh callback says "still empty" → we're the first; append.
func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
	fresh, err := knownhosts.New(path)
	if err != nil {
		return fmt.Errorf("reload known_hosts under lock: %w", err)
	}
	if err := fresh(hostname, remote, key); err != nil {
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}
		if len(keyErr.Want) > 0 {
			return err
		}
		// Empty Want → not yet recorded; fall through to append.
	} else {
		// Already recorded with this key — nothing to do.
		return nil
	}
	if !safeKnownHostsName(knownhosts.Normalize(hostname)) {
		return fmt.Errorf("refusing to record a host key for %q: the name contains characters that have a meaning in known_hosts", hostname)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("append known_hosts: %w", err)
	}
	defer f.Close()
	line := knownhosts.Line([]string{hostname}, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	return nil
}

// knownHostsNameRE is the only shape of host name appendKnownHost will
// write: a bare name or address, or "[name]:port" for a non-default
// port — the two forms knownhosts.Normalize produces.
//
// known_hosts gives several characters a meaning: ',' separates
// patterns, '*' and '?' are wildcards, '!' negates, '#' starts a
// comment, a leading '@' is a marker, '|' starts a hashed entry, and
// whitespace or a newline ends the field or the line. The name comes
// from the server record, which config.ValidateServerHost already
// restricts; this is the same rule applied where the file is written,
// so the file cannot be corrupted through a record that reached the
// dialer some other way.
var knownHostsNameRE = regexp.MustCompile(`^(\[[A-Za-z0-9_.:%-]+\]:[0-9]{1,5}|[A-Za-z0-9_.:%-]+)$`)

func safeKnownHostsName(normalized string) bool {
	return knownHostsNameRE.MatchString(normalized)
}

// knownHostsWarned records which files have been scanned, so the
// warning below is logged once per file per process.
var knownHostsWarned sync.Map

// warnKnownHostsWildcardsOnce logs the line numbers of known_hosts
// entries whose host pattern contains a wildcard. Such an entry makes
// its key acceptable for every host it matches, including hosts that
// have their own pinned key — the host-key check passes if ANY
// matching line holds the presented key. Releases before the host
// check in config.ValidateServerHost could be made to write one, and
// nothing removes it automatically: an operator may have added a
// wildcard on purpose (a certificate authority line, a lab subnet), so
// the file is theirs to edit. Only line numbers are logged.
func warnKnownHostsWildcardsOnce(path string) {
	if _, seen := knownHostsWarned.LoadOrStore(path, struct{}{}); seen {
		return
	}
	lines := knownHostsWildcardLines(path)
	if len(lines) == 0 {
		return
	}
	log.Printf("known_hosts: %s has wildcard host patterns on line(s) %s. A key on such a line is accepted for every matching host, pinned or not. If you did not add these lines, remove them (see DEPLOYMENT.md, \"Checks after upgrading\").", path, strings.Join(lines, ", "))
}

// knownHostsWildcardLines returns the 1-based numbers of lines whose
// host field contains '*' or '?'. Hashed entries cannot hold a
// wildcard and are skipped; an unreadable file yields nothing (the
// caller is about to load it and will report that error itself).
func knownHostsWildcardLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		hosts := fields[0]
		if strings.HasPrefix(hosts, "@") { // @cert-authority / @revoked marker
			if len(fields) < 2 {
				continue
			}
			hosts = fields[1]
		}
		if strings.HasPrefix(hosts, "|") {
			continue
		}
		if strings.ContainsAny(hosts, "*?") {
			out = append(out, fmt.Sprint(n))
		}
	}
	return out
}
