// Host-header validation for the origin guard. The Origin == Host
// comparison alone is defeated by DNS rebinding: the attacker's page
// at http://evil.example:8787 re-resolves evil.example to 127.0.0.1,
// after which every request it makes is *same-origin* from the
// browser's point of view — Origin (when sent at all) matches Host,
// and same-origin GETs carry no Origin header whatsoever. The only
// reliable tell is the Host header itself, which still says
// evil.example. Rebinding fundamentally requires a DNS name, so
// IP-literal Hosts are safe; every other name must be one we expect.
package api

import (
	"net"
	"os"
	"strings"
)

// allowedHostsEnv lets a reverse-proxy deployment (the documented
// posture for non-loopback exposure) register the public hostnames
// the proxy forwards, comma-separated.
const allowedHostsEnv = "ANSBUI_ALLOWED_HOSTS"

// allowedHostnames builds the set of acceptable DNS-name hosts: the
// hostname the operator bound via -addr (when it is a name, not an
// IP) plus anything in ANSBUI_ALLOWED_HOSTS. Loopback names and IP
// literals are handled structurally in hostAllowed and don't need
// enumerating here.
func allowedHostnames(boundAddr string) map[string]struct{} {
	allowed := make(map[string]struct{})
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			allowed[h] = struct{}{}
		}
	}
	if h, _, err := net.SplitHostPort(boundAddr); err == nil && net.ParseIP(h) == nil {
		add(h)
	}
	for _, h := range strings.Split(os.Getenv(allowedHostsEnv), ",") {
		add(h)
	}
	return allowed
}

// hostAllowed reports whether the request's Host header names this
// server. IP literals can't be DNS-rebound (the browser would show
// the IP as the page origin, and cross-origin requests to it are
// caught by the Origin comparison), localhost / *.localhost resolve
// to loopback by spec, and anything else must be explicitly allowed.
func hostAllowed(hostport string, allowed map[string]struct{}) bool {
	h := hostport
	if only, _, err := net.SplitHostPort(hostport); err == nil {
		h = only
	}
	h = strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]"))
	if h == "" {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	_, ok := allowed[h]
	return ok
}
