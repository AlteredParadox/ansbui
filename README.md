# ansbui — Ansible Control Plane UI

A single-binary web UI for an Ansible control node.

- **Backend**: Go 1.25 (stdlib HTTP + gorilla/websocket + golang.org/x/crypto/ssh)
- **Frontend**: React / Babel served from an embedded static bundle (design by [claude.ai/design](https://claude.ai/design), ported from the `ansible-ui` handoff bundle)
- **Integration**: connects to a remote ansible control node over SSH and runs `ansible-inventory`, `ansible`, and `ansible-playbook` there — no local Ansible install required
- **Observability**: optionally enriches inventory with live CPU / memory / load / uptime / OS from Prometheus (node_exporter), matched by hostname

## Quick start (Debian 13)

```sh
sudo apt install -y golang-go openssh-client
go build -o ansbui .
./ansbui              # default: -addr 127.0.0.1:8787 (loopback only)
```

Open `http://127.0.0.1:8787/` in a browser. On first load you'll be prompted to add an ansible server — the SSH coordinates of a remote machine that already has `ansible` installed.

To expose ansbui on another interface, put authentication in front of it first, then bind explicitly:

```sh
./ansbui -addr 0.0.0.0:8787
```

## Configuration

ansbui writes to `~/.config/ansbui/config.json` (and `runs.json`). The UI is the only writer — do not hand-edit while the binary is running.

### Ansible server fields

| Field        | Notes |
|--------------|-------|
| Name         | UI-only label. |
| Host / Port  | SSH endpoint. |
| SSH user     | Must be able to run `ansible-*` non-interactively. |
| Key path     | Optional. Leave blank to use the local `ssh-agent`. Encrypted keys aren't parsed — add them to the agent instead. |
| Working dir  | Directory on the remote that contains your playbooks / inventory. Passed to `cd` before every command. |
| Inventory    | Optional path (relative to workDir) of a specific inventory file. |

### Prometheus

Paste your Prometheus URL (e.g. `http://prom.example.com:9090`) in **Settings**. The host label defaults to `instance` — change if your node_exporter scrapes use a different label. Matching strips any `:port` suffix (bracketed IPv6 instance labels are handled).

The Prometheus URL is fetched **server-side with no auth in front of it**, so it's constrained by an SSRF allowlist. By default only loopback hosts (`127.0.0.1`, `::1`, `localhost`) are accepted, and cloud-metadata addresses (169.254.0.0/16, `metadata.google.internal`, …) are always rejected. To point at a Prometheus on another host, list it in `ANSBUI_PROM_ALLOWED_HOSTS` (see below). This is enforced both when you save the URL and on every metrics fetch, so a hand-edited `config.json` can't bypass it.

### Environment variables

All optional. The security-relevant ones (`ANSBUI_ALLOWED_HOSTS`, `ANSBUI_PROM_ALLOWED_HOSTS`) matter mainly for non-loopback / reverse-proxy deployments.

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANSBUI_ALLOWED_HOSTS` | Comma-separated `host` or `host:port` values the DNS-rebinding guard accepts in the request `Host` header. **Required when behind a reverse proxy that forwards a public hostname** (see below). The port is optional — it's stripped on both sides before matching. | Only loopback (`localhost`, `*.localhost`, IP literals) and the hostname from `-addr` are accepted. |
| `ANSBUI_PROM_ALLOWED_HOSTS` | Comma-separated `host` or `host:port` allowed as the Prometheus scrape target (SSRF guard). | Loopback only. |
| `ANSBUI_INSECURE_SSH` | `1` or `true` disables SSH **host-key** verification for connections ansbui itself makes (the bootstrap flow's first contact with a fresh box). Lab-only; MITM is undetectable in this mode and it logs a warning on startup. | Off — host keys are verified against `~/.ssh/known_hosts` (TOFU on first sight, hard fail on mismatch). |
| `ANSBUI_AUTH_REQUIRED` | `1` or `true` makes ansbui **refuse to start** when no login credential file exists, instead of falling back to the unauthenticated posture. Set it in the service unit after `-set-password` so a lost data dir (bad restore, missing mount, accidental delete) can't silently expose the control plane. | Off — a missing credential file just disables built-in login (with a startup warning). |
| `ANSBUI_AUTH_CREDENTIAL` | Path to the login password hash written by `-set-password`. | `auth_credential` next to `config.json`. |
| `ANSBUI_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` is believed when attributing login attempts to a client IP (per-source throttling). Set it when running behind a proxy (e.g. `127.0.0.1` for a same-host Caddy); otherwise all proxied clients share one throttle bucket. `X-Forwarded-For` from unlisted peers is ignored. | Empty — the TCP peer address is always the source. |
| `ANSBUI_CONFIG` | Path to `config.json`. | `$XDG_CONFIG_HOME/ansbui/config.json` (i.e. `~/.config/ansbui/config.json`). |
| `ANSBUI_RUNS` | Path to `runs.json` (run history). | Alongside the config file. |
| `SSH_AUTH_SOCK` | Standard. If set, ansbui uses the running `ssh-agent` for controller auth when no key path is configured. | — |

`RELAY_CONFIG` / `RELAY_RUNS` are accepted as back-compat aliases for the `ANSBUI_*` path variables.

### Remote access & the DNS-rebinding guard

ansbui binds to loopback by default. Before exposing it on another interface, put authentication in front: either the **built-in login** (`ansbui -set-password` — see [Security posture](#security-posture)) or a **reverse proxy that terminates TLS and adds auth**, or both. Note that enabling the built-in login guards **every** `/api/*` endpoint including the WebSocket run streams — cookie sessions are the only mechanism (there are no API tokens), so any unauthenticated script you had pointed at the API will need the proxy route or a session cookie from `POST /api/login`.

Independent of login state, ansbui defends its API against DNS rebinding (a malicious page that re-resolves its own domain to `127.0.0.1` and then drives the local API from the victim's browser). The guard rejects any `/api/` request whose `Host` header isn't a recognised name. A reverse proxy forwards the browser's original `Host` (e.g. `ansbui.example.com`), which ansbui doesn't know about by default — so **you must list the proxy's public hostname in `ANSBUI_ALLOWED_HOSTS`**, or every API call returns `403` and the UI loads but does nothing. (The static page under `/` stays public so it still loads; only `/api/` is guarded.)

Example — Caddy in front, ansbui on loopback, run under systemd:

```
# Caddyfile — forwards the public Host header unchanged
ansbui.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

```ini
# /etc/systemd/system/ansbui.service.d/allowed-hosts.conf
[Service]
Environment=ANSBUI_ALLOWED_HOSTS=ansbui.example.com
```

```sh
sudo systemctl daemon-reload && sudo systemctl restart ansbui
```

List multiple names comma-separated (`ANSBUI_ALLOWED_HOSTS=ansbui.example.com,ansbui.internal`). If the `403` error names a `Host` with a port, copying that value verbatim works too — the port is ignored when matching.

## Repo layout

```
main.go                 # boot + HTTP server
internal/config/        # JSON config store (servers, prometheus url)
internal/sshpool/       # cached *ssh.Client pool
internal/ansible/       # inventory / playbook / adhoc / runs
internal/prom/          # prometheus query client
internal/api/           # HTTP + WebSocket handlers
web/                    # static bundle (embedded)
.claude/                # Claude Code project config (see CI)
```

## Security posture

- **Built-in login is optional and single-operator.** Run `ansbui -set-password` to require a password (argon2id hash stored 0600 in the config dir; session cookie is `HttpOnly` + `SameSite=Strict`, `Secure` over HTTPS). With no password set, ansbui runs **unauthenticated** — anyone who can reach the listen port can drive `ansible-playbook` as the configured SSH user — and logs a warning on startup when bound to a non-loopback address. Either set a password, or put it behind an SSH tunnel (`ssh -L 8787:localhost:8787 host`), a VPN, or a reverse proxy (Caddy / Nginx) with auth before exposing to untrusted networks. For multi-user or SSO, terminate auth at the proxy. See [DEPLOYMENT.md](DEPLOYMENT.md#0-built-in-login-optional-but-recommended).
- SSH auth to the ansible controller is key-based only (agent or on-disk key) — no password prompt. Host keys are verified (see `ANSBUI_INSECURE_SSH` to opt out in a lab).
- **DNS-rebinding guard:** every `/api/` request must carry a recognised `Host` header (loopback, the `-addr` hostname, or an `ANSBUI_ALLOWED_HOSTS` entry). Reverse-proxy deployments must set `ANSBUI_ALLOWED_HOSTS` — see [Remote access](#remote-access--the-dns-rebinding-guard).
- **CSRF guard:** every `/api/` request — reads included — additionally requires `Origin` to match `Host` when an `Origin` header is present; the WebSocket upgrader enforces the same same-origin check. Browsers omit `Origin` on same-origin GETs and CLI clients omit it entirely, so only a present-and-mismatched `Origin` is rejected. Reads are covered because a cross-origin trigger still does the server-side work (e.g. `/api/facts` can run `ansible … -m setup` across the fleet) even though the response stays opaque to the caller.
- **SSRF guard:** the server-side Prometheus fetch is constrained to loopback / `ANSBUI_PROM_ALLOWED_HOSTS`, with cloud-metadata addresses always denied — enforced at both save time and fetch time.
- Playbook paths are validated against `^[A-Za-z0-9._-]+$` per segment, blocking `..` traversal.
- Ansible argument keys are validated; values are shell-quoted.
- The binary writes config with mode `0600` in `~/.config/ansbui/`.

## CI

`.gitea/workflows/ci.yml` runs build + vet + test, and kicks off a SonarQube scan using `SONAR_TOKEN` and `SONAR_HOST_URL` from the repo secrets. The Sonar project key is `ansbui`.

The repo also ships a Claude Code hook (`.claude/settings.json` + `.claude/hooks/post-edit-lint.sh`): if you open this project in [Claude Code](https://claude.com/claude-code), every file it edits is linted immediately (`golangci-lint` for Go, `eslint` for JS/JSX) so issues surface before commit. It's a plain, inspectable shell script and a silent no-op when those tools aren't installed — but note it does auto-run on edits, so review it if that's a concern. It has no effect if you use a different editor.

## SonarQube hotspot notes

A few of Sonar's hotspots are not real concerns in this project; leaving them here so they aren't re-raised on every review:

- **Missing Subresource Integrity on Google Fonts** (`web/index.html`, `Web:S5725`). SRI intentionally isn't used for `fonts.googleapis.com` — Google serves different CSS per User-Agent, so a pinned hash would break for most browsers. The React / Babel / React-DOM CDN references that actually ship code do carry `integrity=` attributes.
- **Regex ReDoS hotspots** (`javascript:S5852`) on the YAML tokenisers in `Inventory.jsx`, `Playbooks.jsx`, `data/api.js`. Every regex we flag is anchored to a single line, uses character classes over broad alternation, and has no nested or overlapping quantifiers — input size per match is bounded by the line length pulled out of `.split('\n')`. Inputs come from playbook files authored on the controller (trusted operator-supplied YAML), not from external request bodies.
- **Weak PRNG** (`History.jsx`, `javascript:S2245`). The previous implementation synthesised per-task / per-host cells with `Math.random()` for the prototype. The view now reads the real streamed run log instead, so no PRNG is used in the production path.
