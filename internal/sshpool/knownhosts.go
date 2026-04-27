package sshpool

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
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
// the strict callback. The append path takes the mutex so two
// parallel dials to a brand-new host can't interleave writes;
// subsequent dials re-load the file via a fresh hostKeyCallback
// invocation, which is when the new entry is verified against.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	if err := ensureKnownHostsExists(path); err != nil {
		return nil, err
	}
	if err := ensureKnownHostsMode(path); err != nil {
		return nil, err
	}
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
		return appendKnownHost(path, hostname, key)
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

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	knownHostsMu.Lock()
	defer knownHostsMu.Unlock()
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
