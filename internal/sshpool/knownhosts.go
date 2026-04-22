package sshpool

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownHostsCallback verifies against ~/.ssh/known_hosts when the host is
// recorded; when it isn't, it records it on first use.
func knownHostsCallback(path string) (ssh.HostKeyCallback, error) {
	strict, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := strict(hostname, remote, key)
		if err == nil {
			return nil
		}
		if _, ok := err.(*knownhosts.KeyError); ok {
			return appendKnownHost(path, hostname, key)
		}
		return err
	}, nil
}

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
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
