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
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/porkbun"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

// Request is the operator-supplied form payload for one
// provisioning run.
type Request struct {
	Provider      string `json:"provider"`
	IP            string `json:"ip"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	UseSudo       bool   `json:"useSudo"`
	SudoPassword  string `json:"sudoPassword"`
	Hostname      string `json:"hostname"`
	VaultPassword string `json:"vaultPassword"`
}

// Defaults: where porkbun creds live, what they're named, where
// the control node's public key sits. Hardcoded for now — if a
// future operator's setup diverges these become server-config
// fields.
const (
	defaultPorkbunVaultPath  = "group_vars/all/vault.yml"
	defaultPorkbunAPIKeyVar  = "porkbun_api_key"
	defaultPorkbunSecretVar  = "porkbun_secret_key"
	defaultControlPubKeyPath = "~/.ssh/id_ed25519.pub"
	targetSSHPort            = 4242
	dnsTTLSeconds            = 300
)

// Run executes the full provisioning workflow, streaming progress
// events on `out`. The channel is closed when Run returns. ctx
// cancels the workflow.
func Run(ctx context.Context, pool *sshpool.Pool, srv config.Server, req Request, out chan<- ansible.Event) error {
	defer close(out)
	emit := func(t, text string) {
		select {
		case out <- ansible.Event{Type: t, Text: text}:
		case <-ctx.Done():
		}
	}

	if err := validateRequest(req); err != nil {
		emit("fail", err.Error())
		return err
	}

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
	pb := porkbun.New(apiKey, secretKey)
	rec, err := pb.FindARecord(ctx, domain, subdomain)
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	switch {
	case rec == nil:
		emit("meta", "No record exists; creating...")
		if err := pb.CreateARecord(ctx, domain, subdomain, req.IP, dnsTTLSeconds); err != nil {
			emit("fail", err.Error())
			return err
		}
		emit("ok", fmt.Sprintf("created A record %s -> %s", req.Hostname, req.IP))
	case rec.Content != req.IP:
		msg := fmt.Sprintf("A record exists pointing to %s, not %s — update via porkbun manually before retrying", rec.Content, req.IP)
		emit("fail", msg)
		return errors.New(msg)
	default:
		emit("ok", "A record already correct")
	}

	emit("meta", fmt.Sprintf("Connecting to %s@%s:%d...", req.Username, req.IP, req.Port))
	sudoPw := ""
	if req.UseSudo {
		sudoPw = req.SudoPassword
	}
	target, err := dialPasswordTarget(ctx, req.IP, req.Port, req.Username, req.Password, sudoPw)
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	defer target.Close()
	emit("ok", "connected.")

	emit("meta", "Detecting distro...")
	distroOut, _, err := target.runRoot(ctx, "cat /etc/os-release", "")
	if err != nil {
		emit("fail", "read /etc/os-release: "+err.Error())
		return err
	}
	distro := detectDistro(distroOut)
	emit("ok", "distro: "+distro)
	if !isDebianFamily(distro) {
		emit("fail", fmt.Sprintf("unsupported distro %q — v1 only handles debian/ubuntu", distro))
		return errors.New("unsupported distro")
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

	emit("meta", "Reading control-node public key...")
	pubKey, err := readControlNodePubkey(ctx, pool, srv)
	if err != nil {
		emit("fail", err.Error())
		return err
	}
	emit("ok", "public key loaded")

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

	emit("meta", "Configuring sshd to listen on port 4242...")
	portOut, stderr, err := target.runRoot(ctx, sshdPortScript(targetSSHPort), "")
	if err != nil {
		emit("fail", "sshd port change: "+stderr)
		return err
	}
	emit("ok", strings.TrimSpace(portOut))

	emit("meta", fmt.Sprintf("Adding %s to inventory under group %q...", req.Hostname, req.Provider))
	if err := updateInventoryFile(ctx, pool, srv, req.Provider, req.Hostname); err != nil {
		emit("fail", "inventory edit: "+err.Error())
		return err
	}
	emit("ok", "inventory updated")

	emit("done", fmt.Sprintf("Provisioning complete. Reach via ansible@%s:%d", req.Hostname, targetSSHPort))
	return nil
}

// validateRequest catches the obvious form errors before we kick
// off any side effects. The rest (DNS resolution, SSH reachability,
// password correctness) surfaces from the actual subsystems.
func validateRequest(req Request) error {
	if strings.TrimSpace(req.Provider) == "" {
		return errors.New("provider is required")
	}
	if strings.TrimSpace(req.IP) == "" {
		return errors.New("IP address is required")
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
	return nil
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

// readControlNodePubkey cats the control node's public key file. We
// expand `~/` to whatever the SSH user's home is (relying on the
// remote shell's tilde expansion is unreliable when the command is
// run through bash -c). Empty result -> caller errors out.
func readControlNodePubkey(ctx context.Context, pool *sshpool.Pool, srv config.Server) (string, error) {
	cli, err := pool.Client(ctx, srv)
	if err != nil {
		return "", err
	}
	stdout, stderr, err := sshpool.Run(cli, "cat "+defaultControlPubKeyPath)
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("read %s on control node: %s", defaultControlPubKeyPath, msg)
	}
	pub := strings.TrimSpace(stdout)
	if pub == "" {
		return "", fmt.Errorf("control node public key %s is empty", defaultControlPubKeyPath)
	}
	return pub, nil
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
	stdout, stderr, err := sshpool.Run(cli, "cat "+shellQuote(full))
	if err != nil {
		msg := strings.TrimSpace(stderr)
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("read %s: %s", srv.Inventory, msg)
	}
	updated, err := addHostToInventoryYAML([]byte(stdout), provider, fqdn)
	if err != nil {
		return err
	}
	if string(updated) == stdout {
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
		`grep -qF "$PUBKEY" /home/ansible/.ssh/authorized_keys || printf '%s\n' "$PUBKEY" >> /home/ansible/.ssh/authorized_keys`,
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
