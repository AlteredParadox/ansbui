// Package provision drives the multi-step "set up a fresh server
// for ansible" workflow:
//
//  1. read porkbun creds from an inline vault on the control node
//  2. ensure an A record for the new hostname exists at porkbun
//  3. SSH to the new server with the operator-supplied password
//  4. install sudo + python3 (Debian/Ubuntu only in v1)
//  5. create an `ansible` user with a random password and
//     passwordless sudo, populated authorized_keys, and the
//     control node's public key
//  6. flip sshd to port 4242 and reload
//  7. add the FQDN to the configured inventory file under a
//     provider-named group, creating the group if needed
//
// Each step emits a streaming Event so the UI can show live
// progress through the same channel adhoc/playbook runs use.
package provision

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/porkbun"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// Request is the operator-supplied form payload for one
// provisioning run.
type Request struct {
	Provider      string         `json:"provider"`
	IP            string         `json:"ip"`
	Port          int            `json:"port"`
	Username      string         `json:"username"`
	Password      string         `json:"password"`
	UseSudo       bool           `json:"useSudo"`
	SudoPassword  string         `json:"sudoPassword"`
	Hostname      string         `json:"hostname"`
	VaultPassword string         `json:"vaultPassword"`
	Reinstall     ReinstallOpts  `json:"reinstall"`
}

// Defaults: where porkbun creds live, what they're named, where
// the control node's public key sits. Hardcoded for now — if a
// future operator's setup diverges these become server-config
// fields. The private-key path IS configurable via Store.
// ControlPrivKeyPath; this constant is the fallback when unset.
const (
	defaultPorkbunVaultPath   = "inventory/group_vars/all/vault.yml"
	defaultPorkbunAPIKeyVar   = "porkbun_api_key"
	defaultPorkbunSecretVar   = "porkbun_secret_key"
	defaultControlPubKeyPath  = "~/.ssh/ansible_ed25519.pub"
	defaultControlPrivKeyPath = "~/.ssh/ansible_ed25519"
	targetSSHPort             = 4242
	dnsTTLSeconds             = 300
)

// targetMu serialises provisioning runs against the same target.
// Two operators (or a single one with two browser tabs) submitting
// the same form would otherwise race the SSH bootstrap — `chpasswd`
// runs twice with different random passwords, the sshd-port flip
// can interleave with another reload, etc. The mutex is keyed on
// `<ip>:<port>`; a process-local sync.Mutex per key is enough
// because the WS handler always lives in this process.
var (
	targetMuRegistry sync.Mutex
	targetMu         = map[string]*sync.Mutex{}
)

// lockTarget returns a mutex specific to the IP:port pair. The
// caller takes ownership and is responsible for unlocking; a Done
// channel from ctx isn't honoured because provisioning steps are
// short and a queued operator behind a lock is the correct UX.
func lockTarget(key string) *sync.Mutex {
	targetMuRegistry.Lock()
	defer targetMuRegistry.Unlock()
	m, ok := targetMu[key]
	if !ok {
		m = &sync.Mutex{}
		targetMu[key] = m
	}
	return m
}

// Run executes the full provisioning workflow, invoking emit for
// every progress event. ctx cancels the workflow; emit must be
// safe to call concurrently with itself only if the caller says so
// (the jobs.Manager hosts emit under its mutex).
//
// emit's text is redacted for password:/passphrase: shapes before
// it reaches the caller. stderr from sudo/sshd/apt sometimes
// includes the operator's password — the redact pass guards
// against future debug-log regressions and against the live event
// landing in browser memory in a recoverable form.
func Run(ctx context.Context, pool *sshpool.Pool, srv config.Server, req Request, ctrlPrivKeyPath string, rawEmit func(typ, text string)) error {
	emit := func(t, text string) {
		rawEmit(t, ansible.RedactText(text))
	}

	// Belt-and-suspenders: the API handler also validates before
	// creating the job, but Run is exported so a future caller
	// might bypass that path.
	if err := Validate(req); err != nil {
		emit("fail", err.Error())
		return err
	}
	// Canonicalise the hostname once: porkbun's `Name` field comes
	// back lowercase and the inventory key, WS log lines, and DNS
	// record all benefit from a single form. Mixed-case input from
	// the operator (`Vps01.Example.com`) is silently normalised.
	req.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	// Trim req.IP too. Validate's net.ParseIP runs on a trimmed
	// copy and accepts " 1.2.3.4 ", but the un-trimmed value
	// flows into lockTarget's key, dialPasswordTarget's address,
	// and the porkbun A-record content — all of which fail or
	// behave wrong with surrounding whitespace.
	req.IP = strings.TrimSpace(req.IP)
	// A forged / stale client could submit `username=root` together
	// with `useSudo=true`. Root never needs sudo; coerce to false so
	// the orchestrator skips the wrapper entirely instead of running
	// `sudo` as root just to wrap a noop. Trim first so a sloppy
	// `"root "` doesn't bypass the coercion and produce confusing
	// SSH-auth-as-"root " errors downstream.
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "root" {
		req.UseSudo = false
		req.SudoPassword = ""
	}

	mu := lockTarget(fmt.Sprintf("%s:%d", req.IP, req.Port))
	mu.Lock()
	defer mu.Unlock()

	emit("meta", "Decrypting porkbun credentials from "+defaultPorkbunVaultPath+"...")
	apiKey, secretKey, err := readPorkbunCreds(ctx, pool, srv, req.VaultPassword)
	if err != nil {
		emit("fail", "vault decrypt: "+err.Error())
		return err
	}
	emit("ok", "porkbun credentials decrypted")

	domain, subdomain := splitFQDN(req.Hostname)
	if domain == "" {
		emit("fail", "could not derive registered domain from hostname "+req.Hostname)
		return errors.New("invalid hostname")
	}
	emit("meta", fmt.Sprintf("Checking porkbun A record for %s under %s...", subdomainOrApex(subdomain), domain))
	if err := ensureARecord(ctx, porkbun.New(apiKey, secretKey), domain, subdomain, req.IP, req.Hostname, emit); err != nil {
		return err
	}

	emit("meta", "Reading control-node public key...")
	pubKey, err := readControlNodePubkey(ctx, pool, srv)
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	emit("ok", "public key loaded")

	emit("meta", fmt.Sprintf("Connecting to %s@%s:%d...", req.Username, req.IP, req.Port))
	target, err := connectAndPrecheck(ctx, req, emit)
	if err != nil {
		return err
	}
	// The defer captures the variable, not the value, so swapping
	// `target` after a reinstall closes the post-reinstall session
	// at function return rather than the pre-reinstall one (already
	// dead from reboot by then).
	defer func() { _ = target.Close() }()
	emit("ok", "connected.")

	if req.Reinstall.Enabled {
		newTarget, err := doReinstall(ctx, target, req, reinstallInputs{
			pubKey:          pubKey,
			ctrlPrivKeyPath: ctrlPrivKeyPath,
			pool:            pool,
			srv:             srv,
		}, emit)
		if err != nil {
			emit("fail", err.Error())
			return err
		}
		_ = target.Close()
		target = newTarget
	}

	if err := bootstrapTarget(ctx, target, pubKey, emit); err != nil {
		return err
	}

	providerGroup := normalizeProviderName(req.Provider)
	emit("meta", fmt.Sprintf("Adding %s to inventory under group %q...", req.Hostname, providerGroup))
	if err := updateInventoryFile(ctx, pool, srv, providerGroup, req.Hostname); err != nil {
		emit("fail", "inventory edit: "+err.Error())
		return err
	}
	emit("ok", "inventory updated")

	emit("done", fmt.Sprintf("Provisioning complete. Reach via ansible@%s:%d", req.Hostname, targetSSHPort))
	return nil
}

// Validate catches the obvious form errors before we kick off any
// side effects. The rest (DNS resolution, SSH reachability,
// password correctness) surfaces from the actual subsystems.
//
// Exposed (capitalised) so the API handler can reject malformed
// requests with a 400 before allocating a job slot — important
// because the job's Summary captures fields verbatim and the
// registry retains them across the run's lifetime.
func Validate(req Request) error {
	if strings.TrimSpace(req.Provider) == "" {
		return errors.New("provider is required")
	}
	trimmedIP := strings.TrimSpace(req.IP)
	if trimmedIP == "" {
		return errors.New("IP address is required")
	}
	// porkbun A records are IPv4-only and the SSH bootstrap
	// connects directly to this address — accept only dotted-quad
	// literals. Rejecting hostnames stops a DNS change from moving
	// the box mid-run; rejecting IPv6 (including IPv4-mapped
	// `::ffff:1.2.3.4` forms that net.ParseIP would otherwise
	// accept) avoids a confusing failure later when porkbun
	// rejects the A record content.
	if strings.Contains(trimmedIP, ":") {
		return errors.New("IP must be in dotted-quad form (e.g. 203.0.113.42) — IPv6 addresses, including IPv4-mapped forms like ::ffff:1.2.3.4, are not supported")
	}
	if ip := net.ParseIP(trimmedIP); ip == nil || ip.To4() == nil {
		return errors.New("IP must be a valid IPv4 literal address — hostnames are rejected so DNS changes can't move the box mid-run")
	}
	if req.Port <= 0 || req.Port > 65535 {
		return errors.New("invalid SSH port")
	}
	if strings.TrimSpace(req.Username) == "" {
		return errors.New("username is required")
	}
	if req.Password == "" {
		return errors.New("password is required")
	}
	if req.UseSudo && req.SudoPassword == "" && req.Username != "root" {
		return errors.New("sudo password is required when 'use sudo' is checked")
	}
	if strings.TrimSpace(req.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if strings.TrimSpace(req.VaultPassword) == "" {
		return errors.New("vault password is required (used to decrypt porkbun credentials)")
	}
	if !strings.Contains(req.Hostname, ".") {
		return errors.New("hostname must be fully-qualified (include the domain)")
	}
	if strings.ContainsAny(req.Hostname, " \t") {
		return errors.New("hostname must not contain whitespace")
	}
	// Per-field length caps — every value here is summarised /
	// retained in the in-memory job registry, and the redact pass
	// on event text doesn't bound size. 256 bytes is comfortably
	// over any realistic provider/hostname/username and below
	// what a misuse-shape input would aim for.
	if err := boundLength("provider", req.Provider, 64); err != nil {
		return err
	}
	if err := boundLength("hostname", req.Hostname, 253); err != nil {
		return err
	}
	if err := boundLength("username", req.Username, 64); err != nil {
		return err
	}
	if err := validateReinstall(req.Reinstall); err != nil {
		return err
	}
	return nil
}

func boundLength(name, value string, max int) error {
	if len(value) > max {
		return fmt.Errorf("%s is too long (max %d bytes)", name, max)
	}
	return nil
}

// bootstrapTarget runs the distro-detect + apt + ansible-user +
// sshd-port pipeline against a connected target. Extracted from
// Run so the orchestrator stays under the cognitive-complexity
// budget after the reinstall branch landed; same script either
// way (post-reinstall the sshd-port flip is a no-op since
// reinstall.sh already baked :4242 into the new image).
func bootstrapTarget(ctx context.Context, target *targetSession, pubKey string, emit func(typ, text string)) error {
	emit("meta", "Detecting distro...")
	distroOut, _, err := target.runRoot(ctx, "cat /etc/os-release", "")
	if err != nil {
		emit("fail", "read /etc/os-release: "+err.Error())
		return err
	}
	distro := detectDistro(distroOut)
	emit("ok", "distro: "+distro)
	if !isDebianFamily(distro) {
		err := fmt.Errorf("unsupported distro %q — v1 only handles debian/ubuntu", distro)
		emit("fail", err.Error())
		return err
	}

	emit("meta", "Installing sudo + python3 via apt...")
	_, stderr, err := target.runRoot(ctx,
		"DEBIAN_FRONTEND=noninteractive apt-get update -qq && "+
			"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo python3",
		"")
	if err != nil {
		emit("fail", "apt install: "+stderr)
		return err
	}
	emit("ok", "sudo + python3 installed")

	emit("meta", "Creating ansible user with passwordless sudo + key auth...")
	randomPw, err := generatePassword()
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	_, stderr, err = target.runRoot(ctx, ansibleUserSetupScript(pubKey), randomPw+"\n")
	if err != nil {
		emit("fail", "ansible-user setup: "+stderr)
		return err
	}
	emit("ok", "ansible user ready")

	emit("meta", fmt.Sprintf("Configuring sshd to listen on port %d...", targetSSHPort))
	portOut, stderr, err := target.runRoot(ctx, sshdPortScript(targetSSHPort), "")
	if err != nil {
		emit("fail", "sshd port change: "+stderr)
		return err
	}
	emit("ok", strings.TrimSpace(portOut))
	return nil
}

// reinstallInputs bundles the control-node-side resources that
// doReinstall needs. Packing them into a struct keeps the
// function signature under the 7-parameter limit (S107) without
// dropping the privkey-load step from the orchestrator's progress
// emits.
type reinstallInputs struct {
	pubKey          string
	ctrlPrivKeyPath string
	pool            *sshpool.Pool
	srv             config.Server
}

// doReinstall reads the configured private key from the control
// node, then drives reinstall.sh + reboot + wait-for-ssh against
// the target. On success the caller should swap to the returned
// session and close the original. The privkey is held only for
// the duration of this call; runReinstall doesn't retain it.
func doReinstall(ctx context.Context, target *targetSession, req Request, in reinstallInputs, emit func(typ, text string)) (*targetSession, error) {
	privKeyPath := in.ctrlPrivKeyPath
	if privKeyPath == "" {
		privKeyPath = defaultControlPrivKeyPath
	}
	emit("meta", fmt.Sprintf("Reading control-node private key from %s...", privKeyPath))
	privKey, err := readControlNodePrivkey(ctx, in.pool, in.srv, privKeyPath)
	if err != nil {
		return nil, err
	}
	emit("ok", "private key loaded")
	return runReinstall(ctx, target, req.Reinstall, in.pubKey, privKey, req.IP, emit)
}

// readControlNodePrivkey reads the SSH private key file from the
// active control node and validates that it parses as an OpenSSH
// key. The bytes are returned to the caller, who passes them to
// dialKeyTarget for the post-reinstall reconnect. The key never
// touches disk on ansbui's side and goes out of scope when the
// provisioning run finishes.
//
// The early ssh.ParsePrivateKey check converts a vague "auth
// failed" 30 minutes from now into a fast, specific error before
// the reinstall is even kicked off. Encrypted keys are rejected
// with a hint — we can't prompt for the passphrase mid-run.
func readControlNodePrivkey(ctx context.Context, pool *sshpool.Pool, srv config.Server, path string) ([]byte, error) {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return nil, err
	}
	var so, se bytes.Buffer
	if err := sshpool.Stream(ctx, cli, "cat "+shellQuotePath(path), nil, &so, &se); err != nil {
		msg := strings.TrimSpace(se.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("read %s on control node: %s", path, msg)
	}
	body := so.Bytes()
	if len(body) == 0 {
		return nil, fmt.Errorf("control node private key %s is empty", path)
	}
	if _, err := ssh.ParsePrivateKey(body); err != nil {
		// Encrypted keys surface as a specific error from
		// crypto/ssh; rather than prompting (which would force a
		// whole new field on the form) we ask the operator to
		// generate or unlock an unencrypted key. Other parse
		// errors are NOT wrapped — the underlying error message
		// from ssh.ParsePrivateKey can include fragments of the
		// key bytes for some malformed inputs, and the wrapped
		// error flows through emit() into the in-memory event
		// log of the manager. A generic "did not parse" message
		// is good enough for the operator to recheck their
		// settings.
		if strings.Contains(err.Error(), "encrypted") {
			return nil, fmt.Errorf("control node private key %s is passphrase-protected — provisioning needs an unencrypted key for the post-reinstall reconnect", path)
		}
		return nil, fmt.Errorf("control node private key at %s did not parse as an OpenSSH private key", path)
	}
	return body, nil
}

// connectAndPrecheck dials the target, then verifies sudo is
// reachable for non-root sessions. Extracted from Run so the
// orchestrator's cognitive-complexity budget stays under the
// Sonar S3776 ceiling. The caller closes the returned session.
func connectAndPrecheck(ctx context.Context, req Request, emit func(string, string)) (*targetSession, error) {
	sudoPw := ""
	if req.UseSudo {
		sudoPw = req.SudoPassword
	}
	target, err := dialPasswordTarget(ctx, req.IP, req.Port, req.Username, req.Password, sudoPw)
	if err != nil {
		emit("fail", err.Error())
		return nil, err
	}
	if err := target.requireSudo(ctx); err != nil {
		_ = target.Close()
		emit("fail", err.Error())
		return nil, err
	}
	return target, nil
}

// ensureARecord makes the porkbun A record set for fqdn match ip.
// Three outcomes:
//   - no records → create one and emit ok
//   - all existing records point at ip → emit ok (idempotent)
//   - any record points elsewhere → emit fail and return, listing
//     every conflicting IP. The operator fixes the typo / stale
//     entry / multi-A round-robin manually before retrying
//
// We refuse to add a parallel record when one already conflicts
// because porkbun allows multiple A records under the same name —
// silently appending a "correct" one alongside a stale one would
// round-robin traffic between the new box and a stranger.
func ensureARecord(ctx context.Context, pb *porkbun.Client, domain, subdomain, ip, fqdn string, emit func(string, string)) error {
	records, err := pb.FindARecords(ctx, domain, subdomain, fqdn)
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	if len(records) == 0 {
		emit("meta", "No record exists; creating...")
		if err := pb.CreateARecord(ctx, domain, subdomain, ip, dnsTTLSeconds); err != nil {
			emit("fail", err.Error())
			return err
		}
		emit("ok", fmt.Sprintf("created A record %s -> %s", fqdn, ip))
		return nil
	}
	var conflicts []string
	for _, r := range records {
		if r.Content != ip {
			conflicts = append(conflicts, r.Content)
		}
	}
	if len(conflicts) > 0 {
		msg := fmt.Sprintf("A record(s) exist pointing to %s, not %s — update via porkbun manually before retrying", strings.Join(conflicts, ", "), ip)
		emit("fail", msg)
		return errors.New(msg)
	}
	emit("ok", "A record already correct")
	return nil
}

// normalizeProviderName lowercases the operator's free-form
// provider label, collapses whitespace runs into single
// underscores, and drops any character outside [a-z0-9_-]. So
// "Little Creek Hosting" becomes "little_creek_hosting" and a
// hostile/sloppy label like "foo;rm" → "foorm". The strict
// character class avoids producing YAML keys that need quoting
// (e.g. starting with `!` or containing `:`) and stops shell-meta
// characters from sneaking through any future code path that
// might splice the name into a command.
func normalizeProviderName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !prevSpace && b.Len() > 0 {
				b.WriteByte('_')
			}
			prevSpace = true
			continue
		}
		prevSpace = false
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// splitFQDN returns the registered domain (last two labels) and the
// subdomain (everything before). Naive — fails for ccTLDs like
// `example.co.uk`. Sufficient for the fleet's actual usage.
func splitFQDN(fqdn string) (domain, subdomain string) {
	fqdn = strings.TrimSuffix(strings.TrimSpace(fqdn), ".")
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", ""
	}
	domain = strings.Join(parts[len(parts)-2:], ".")
	if len(parts) > 2 {
		subdomain = strings.Join(parts[:len(parts)-2], ".")
	}
	return
}

func subdomainOrApex(s string) string {
	if s == "" {
		return "apex"
	}
	return s
}

// readPorkbunCreds decrypts the api/secret keys from the configured
// inline vault file using the operator-supplied vault password.
// Reuses the inline-vault decrypt path so the password protocol is
// the same as everywhere else.
func readPorkbunCreds(ctx context.Context, pool *sshpool.Pool, srv config.Server, vaultPassword string) (apiKey, secretKey string, err error) {
	apiKey, err = ansible.DecryptInlineVaultValue(ctx, pool, srv, defaultPorkbunVaultPath, defaultPorkbunAPIKeyVar, vaultPassword)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", defaultPorkbunAPIKeyVar, err)
	}
	secretKey, err = ansible.DecryptInlineVaultValue(ctx, pool, srv, defaultPorkbunVaultPath, defaultPorkbunSecretVar, vaultPassword)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", defaultPorkbunSecretVar, err)
	}
	return strings.TrimSpace(apiKey), strings.TrimSpace(secretKey), nil
}

// readControlNodePubkey cats the control node's public key file
// and validates that it looks like an OpenSSH public key (starts
// with one of the known key-type prefixes). The sanity check
// catches honest mistakes — e.g. the operator pointed the constant
// at the private key by accident, or the file was overwritten with
// a comment-only stub — before the orchestrator splices the
// content into a target's authorized_keys and corrupts it.
func readControlNodePubkey(ctx context.Context, pool *sshpool.Pool, srv config.Server) (string, error) {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return "", err
	}
	var so, se bytes.Buffer
	if err := sshpool.Stream(ctx, cli, "cat "+shellQuotePath(defaultControlPubKeyPath), nil, &so, &se); err != nil {
		msg := strings.TrimSpace(se.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("read %s on control node: %s", defaultControlPubKeyPath, msg)
	}
	pub := strings.TrimSpace(so.String())
	if pub == "" {
		return "", fmt.Errorf("control node public key %s is empty", defaultControlPubKeyPath)
	}
	if !looksLikePublicKey(pub) {
		return "", fmt.Errorf("control node file %s does not look like an OpenSSH public key (expected ssh-ed25519 / ssh-rsa / ecdsa-sha2-* prefix)", defaultControlPubKeyPath)
	}
	return pub, nil
}

// looksLikePublicKey is a coarse check on whatever
// readControlNodePubkey just cat'd. We only want to catch
// "operator pointed at the wrong file" mistakes — full key
// parsing is sshd's job. Authorized-keys-style option prefixes
// (e.g. `command="..." ssh-ed25519 AAAA...`) are accepted by
// looking for the type token anywhere in the line preceded by
// whitespace.
func looksLikePublicKey(s string) bool {
	for _, kt := range []string{"ssh-ed25519", "ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"} {
		if strings.HasPrefix(s, kt+" ") || strings.Contains(s, " "+kt+" ") {
			return true
		}
	}
	return false
}

// updateInventoryFile reads the configured inventory, adds the host
// to the provider group (creating it if missing), and writes the
// result back atomically via the same hardened helper that
// inline-vault edits use (symlink guard, mode preservation,
// tempfile + rename, EXIT trap).
func updateInventoryFile(ctx context.Context, pool *sshpool.Pool, srv config.Server, provider, fqdn string) error {
	if srv.Inventory == "" {
		return errors.New("server has no inventory path configured — set it before provisioning so the new host can be registered")
	}
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return err
	}
	full := path.Join(srv.WorkDir, srv.Inventory)
	var so, se bytes.Buffer
	if err := sshpool.Stream(ctx, cli, "cat "+shellQuote(full), nil, &so, &se); err != nil {
		msg := strings.TrimSpace(se.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("read %s: %s", srv.Inventory, msg)
	}
	updated, err := addHostToInventoryYAML(so.Bytes(), provider, fqdn)
	if err != nil {
		return err
	}
	if bytes.Equal(updated, so.Bytes()) {
		return nil // already present, nothing to write
	}
	return ansible.WriteRemoteFile(ctx, cli, full, string(updated))
}

// generatePassword returns a 32-character base64-url-encoded
// random string suitable for setting via `chpasswd`. Source is
// crypto/rand so it's cryptographically random.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// detectDistro is a coarse classifier — we only need to know
// whether to apt-install. ID= line of /etc/os-release is the
// standard machine-readable hint.
func detectDistro(osRelease string) string {
	for _, line := range strings.Split(osRelease, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id := strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
			return strings.ToLower(id)
		}
	}
	return "unknown"
}

func isDebianFamily(distro string) bool {
	switch distro {
	case "debian", "ubuntu", "raspbian":
		return true
	}
	return false
}

// ansibleUserSetupScript builds a bash one-liner that creates the
// ansible user (idempotent), reads a random password from stdin,
// applies it, sets up authorized_keys with the control-node public
// key (idempotent), and adds NOPASSWD sudo via /etc/sudoers.d.
//
// The random password rides on stdin so it never lands in argv.
// The public key is fine in argv (it's a public credential).
func ansibleUserSetupScript(pubKey string) string {
	return strings.Join([]string{
		`set -e`,
		`IFS= read -r ANSPW`,
		`if ! id ansible >/dev/null 2>&1; then useradd -m -s /bin/bash ansible; fi`,
		`printf '%s\n' "ansible:$ANSPW" | chpasswd`,
		`install -d -m 700 -o ansible -g ansible /home/ansible/.ssh`,
		`PUBKEY=` + shellQuote(pubKey),
		`touch /home/ansible/.ssh/authorized_keys`,
		`grep -qxF "$PUBKEY" /home/ansible/.ssh/authorized_keys || printf '%s\n' "$PUBKEY" >> /home/ansible/.ssh/authorized_keys`,
		`chown -R ansible:ansible /home/ansible/.ssh`,
		`chmod 600 /home/ansible/.ssh/authorized_keys`,
		`printf 'ansible ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/ansible`,
		`chmod 440 /etc/sudoers.d/ansible`,
		`visudo -cf /etc/sudoers.d/ansible >/dev/null`,
	}, "; ")
}

// sshdPortScript flips the active sshd Port directive to target,
// validates the config, and SIGHUPs the daemon (reload, not
// restart, so the connection we're typing through survives).
//
// Handles three layouts:
//   - sshd_config has a Port line → rewrite it
//   - sshd_config has no Port line → append one
//   - /etc/ssh/sshd_config.d/*.conf overrides → rewrite in place
//
// If the active port is already target the script no-ops.
func sshdPortScript(target int) string {
	t := fmt.Sprintf("%d", target)
	return strings.Join([]string{
		`set -e`,
		`TARGET=` + t,
		`CURRENT=$(grep -hE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | tail -1)`,
		`if [ "$CURRENT" = "$TARGET" ]; then echo "sshd already on port $TARGET"; exit 0; fi`,
		`if grep -qE '^[[:space:]]*Port[[:space:]]+' /etc/ssh/sshd_config; then sed -i -E "s/^[[:space:]]*Port[[:space:]]+.*/Port $TARGET/" /etc/ssh/sshd_config; else printf 'Port %s\n' "$TARGET" >> /etc/ssh/sshd_config; fi`,
		`for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] || continue; if grep -qE '^[[:space:]]*Port[[:space:]]+' "$f"; then sed -i -E "s/^[[:space:]]*Port[[:space:]]+.*/Port $TARGET/" "$f"; fi; done`,
		`sshd -t`,
		`systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload`,
		`echo "sshd reloaded on port $TARGET"`,
	}, "; ")
}
