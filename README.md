# ansbui — Ansible Control Plane UI

A single-binary web UI for an Ansible control node.

- **Backend**: Go 1.27 (stdlib HTTP + gorilla/websocket + golang.org/x/crypto/ssh)
- **Frontend**: React / Babel served from an embedded static bundle (design by [claude.ai/design](https://claude.ai/design), ported from the `ansible-ui` handoff bundle)
- **Integration**: connects to a remote ansible control node over SSH and runs `ansible-inventory`, `ansible`, and `ansible-playbook` there — no local Ansible install required
- **Observability**: optionally enriches inventory with live CPU / memory / load / uptime / OS from Prometheus (node_exporter), matched by hostname
- **Bootstrap**: prepares a fresh Debian or Ubuntu machine for ansible (DNS record, `ansible` user, sshd port, inventory entry), optionally reinstalling its OS first — see [Bootstrap](#bootstrap)

## Quick start (Debian 13)

```sh
sudo apt install -y golang-go openssh-client
go build -o ansbui .
./ansbui -set-password   # once: choose the login password
./ansbui                 # default: -addr 127.0.0.1:8787 (loopback only)
```

ansbui does not start until a login password is set. A loopback port is open to every user and process on the machine, so "only I can reach it" is true only on a machine nobody else uses; if that is your case and you want no login, start it with `./ansbui -allow-unauthenticated`.

ansbui targets Go 1.27 (see `go.mod`). Debian 13 packages an older Go; the `go` command fetches the toolchain `go.mod` names on the first build. If your environment sets `GOTOOLCHAIN=local`, install a current Go from [go.dev/dl](https://go.dev/dl/) instead.

Open `http://127.0.0.1:8787/` in a browser. On first load you'll be prompted to add an ansible server — the SSH coordinates of a remote machine that already has `ansible` installed. The host is a DNS name or an IP address, and the account's login shell there must be a POSIX shell (`sh`, `bash`, `dash`, `ksh`, `zsh`); **Test connection** checks both that `ansible` answers and that the shell reads quoted arguments correctly.

To expose ansbui on another interface, put authentication in front of it first, then bind explicitly:

```sh
./ansbui -addr 0.0.0.0:8787
```

## Configuration

ansbui keeps its state in `~/.config/ansbui/`: `config.json` (connections and settings), `runs.json` (run history), `auth_credential` (the login password hash) and `bootstrap_known_hosts.json` (host keys recorded by bootstrap). All are written `0600`. ansbui is the only writer — do not hand-edit while the binary is running. Host keys of control nodes go to `~/.ssh/known_hosts` of the user ansbui runs as.

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

Paste your Prometheus URL (e.g. `http://prom.example.com:9090`) in **Settings**. It is a base address: a path prefix is fine (`https://host/prometheus`), a `?query` or `#fragment` is refused. The host label defaults to `instance` — change if your node_exporter scrapes use a different label. Matching strips any `:port` suffix (bracketed IPv6 instance labels are handled).

The Prometheus URL is fetched **server-side with no auth in front of it**, so it's constrained by an SSRF allowlist. By default only loopback hosts (`127.0.0.1`, `::1`, `localhost`) are accepted, and cloud-metadata addresses (169.254.0.0/16, `metadata.google.internal`, …) are always rejected. To point at a Prometheus on another host, list it in `ANSBUI_PROM_ALLOWED_HOSTS` (see below). This is enforced both when you save the URL and on every metrics fetch, so a hand-edited `config.json` can't bypass it.

A URL written without a scheme gets `http://`, which is what Prometheus serves by default and is fine for the loopback default. For a Prometheus on another host, plain HTTP means the metrics can be read or altered on the way: the inventory would show wrong CPU / memory / uptime figures, and nothing else is affected. If that matters on your network, put TLS in front of Prometheus and write the URL with `https://`.

ansbui adds no credentials of its own to these requests. If your Prometheus needs a login, write it into the URL (`https://user:password@prom.example.com`); it is sent as HTTP Basic auth on every query. Because of that, **a URL with credentials is accepted only with `https://`**. With `http://`, or with no scheme, it is refused when you save it and again on every metrics fetch, so an `http://` URL with credentials already in `config.json` stops returning metrics until it is changed to `https://`. This applies to loopback too. The URL, credentials included, is stored in ansbui's `config.json` and shown in **Settings**.

### Other settings

Also in **Settings**:

- **Auto-gather facts when the host drawer opens** — runs `ansible <host> -m setup` each time a host's detail drawer is opened. Off: the drawer shows a button instead.
- **Look up host regions via ipinfo.io** — off by default. When on, ansbui sends the **public IP addresses of your inventory hosts** to `ipinfo.io` to fill the Region column; private, loopback and CGNAT addresses are never sent. This and the Porkbun call in [Bootstrap](#bootstrap) are the only requests ansbui makes to a third party.
- **Control-node private key path** — used by the bootstrap reinstall flow; see [Bootstrap](#bootstrap).

### Environment variables

All optional. A loopback-only instance with a login password needs none of them; a reverse-proxy deployment needs `ANSBUI_ALLOWED_HOSTS` and should set `ANSBUI_TRUSTED_PROXIES`.

| Variable | Purpose | Default |
|----------|---------|---------|
| `ANSBUI_ALLOWED_HOSTS` | Comma-separated `host` or `host:port` values the DNS-rebinding guard accepts in the request `Host` header. **Required when behind a reverse proxy that forwards a public hostname** (see below). The port is optional — it's stripped on both sides before matching. | Only loopback (`localhost`, `*.localhost`, IP literals) and the hostname from `-addr` are accepted. |
| `ANSBUI_PROM_ALLOWED_HOSTS` | Comma-separated `host` or `host:port` allowed as the Prometheus scrape target (SSRF guard). | Loopback only. |
| `ANSBUI_PROM_ALLOWED_CIDRS` | Comma-separated CIDRs an allowlisted Prometheus **hostname** is permitted to resolve to, enforced at dial time. Closes DNS rebinding: the hostname allowlist can only vet the name, so whoever controls its DNS otherwise chooses the destination. Set it to the network your Prometheus actually lives on (e.g. `10.0.0.0/8`). A malformed entry fails closed. | Unset — any address resolves except unspecified/multicast/link-local and the cloud-metadata addresses, which are always denied. |
| `ANSBUI_INSECURE_SSH` | `1` or `true` disables SSH **host-key** verification for connections to the **control node**. Lab-only; MITM is undetectable in this mode. The warning is logged when the first SSH connection is made, not at startup. Bootstrap targets are not affected: their keys are checked against ansbui's own fingerprint store (next row). | Off — control-node host keys are verified against `~/.ssh/known_hosts` (TOFU on first sight, hard fail on mismatch). |
| `ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY` | `1` or `true` requires a bootstrap target's SSH host-key fingerprint to be pinned (in the form) or already recorded before ansbui will connect, so even the first contact is authenticated. Also gates the **reinstall** option: a reinstall regenerates the box's host keys and the replacement can't be authenticated in band, so such a run is rejected up front unless the operator ticks the per-run host-key acknowledgement in the bootstrap form (recorded in the job log). Per-run rather than a second env var, so strict mode keeps meaning "nothing is trusted *silently*". | Off — the first bootstrap of a target trusts the key it presents (with a loud warning), records it, and enforces it on every later run; the reinstall acknowledgement is not shown and is ignored. |
| `ANSBUI_ALLOW_UNAUTHENTICATED` | `1` or `true` lets ansbui start with **no login password** (same as the `-allow-unauthenticated` flag). Every `/api` route, including the ones that run ansible, then answers anyone who can connect to the listen address — and on a loopback bind that is every user and process on the host, whatever a reverse proxy in front requires. Remove it once a password is set: with it left on, a lost credential file starts ansbui without login. | Off — with no credential file ansbui **refuses to start** and says to run `-set-password`. |
| `ANSBUI_AUTH_REQUIRED` | `1` or `true` makes ansbui refuse to start when no login credential file exists **even if the opt-out above is set**. Only useful together with it, as a guard for a unit that still carries the opt-out; without the opt-out a missing credential already stops the start. | Off. |
| `ANSBUI_AUTH_CREDENTIAL` | Path to the login password hash written by `-set-password`. | `auth_credential` next to `config.json`. |
| `ANSBUI_TRUSTED_PROXIES` | Comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` is believed when attributing login attempts to a client IP (per-source throttling). Set it when running behind a proxy (e.g. `127.0.0.1` for a same-host Caddy); otherwise all proxied clients share one throttle bucket. The proxy must **write the client address into the header itself** — Caddy does; nginx only with `proxy_set_header X-Forwarded-For $remote_addr;` — or clients choose their own throttle bucket. Anything that connects from a listed address is believed, so with `127.0.0.1` listed every local process is. `X-Forwarded-For` from unlisted peers is ignored. | Empty — the TCP peer address is always the source. |
| `ANSBUI_CONFIG` | Path to `config.json`. | `$XDG_CONFIG_HOME/ansbui/config.json` (i.e. `~/.config/ansbui/config.json`). |
| `ANSBUI_RUNS` | Path to `runs.json` (run history). | Alongside the config file. |
| `SSH_AUTH_SOCK` | Standard. If set, ansbui uses the running `ssh-agent` for controller auth when no key path is configured. | — |

`RELAY_CONFIG` / `RELAY_RUNS` are accepted as back-compat aliases for the `ANSBUI_*` path variables.

### Remote access & the DNS-rebinding guard

ansbui binds to loopback by default and requires its **built-in login** (`ansbui -set-password` — see [Security posture](#security-posture)). To reach it from elsewhere, put a **reverse proxy that terminates TLS** in front; the proxy may add its own auth as well. The built-in login guards **every** `/api/*` endpoint including the WebSocket run streams — cookie sessions are the only mechanism (there are no API tokens), so a script needs a session cookie from `POST /api/login`. Authenticating at the proxy **instead of** the built-in login is possible (`-allow-unauthenticated`) but leaves the backend port open to every local user and process on the ansbui host, because they connect to `127.0.0.1:8787` directly, not through the proxy.

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

The proxy must also tell ansbui the browser's connection was HTTPS by sending `X-Forwarded-Proto: https`. Caddy's `reverse_proxy` does this by default; with nginx add `proxy_set_header X-Forwarded-Proto $scheme;`. Without it, logging in and every other action fail with a `403` that names the header. And because ansbui answers HTTPS requests with a one-year `Strict-Transport-Security` header that covers the hostname on **every port**, the name you put in front of it should serve nothing over plain HTTP — see [DEPLOYMENT.md](DEPLOYMENT.md#hsts-give-ansbui-its-own-hostname).

List multiple names comma-separated (`ANSBUI_ALLOWED_HOSTS=ansbui.example.com,ansbui.internal`). If the `403` error names a `Host` with a port, copying that value verbatim works too — the port is ignored when matching.

## Bootstrap

The **Bootstrap** view takes a fresh machine (Debian or Ubuntu) and its root or sudo password, and makes it an ansible-managed host:

1. If the target was given as an IP address, creates or updates the DNS record for the new hostname at Porkbun. The API key and secret are read from the vault on the control node (`porkbun_api_key` / `porkbun_secret_key` in `inventory/group_vars/all/vault.yml`) using the vault password typed into the form. A target given as a hostname skips this step.
2. Connects to the target over SSH **from the ansbui host** with the password from the form, and installs `sudo` and `python3`.
3. Creates an `ansible` user with passwordless sudo and the control node's public key (`~/.ssh/ansible_ed25519.pub` there) in its `authorized_keys`.
4. Moves `sshd` to port `4242`.
5. Adds the host to the inventory file on the control node, under a group named after the provider.

The passwords typed into the form are used for that job and are not stored. The target's SSH host key is recorded on first contact and enforced on later runs; `ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY` makes a pinned fingerprint mandatory instead.

**Reinstall the OS first** wipes the target and installs a fresh Debian or Ubuntu before those steps, using the upstream [bin456789/reinstall](https://github.com/bin456789/reinstall) script. Two things to know before ticking it: ansbui verifies that script but **not the installer or OS image it downloads**, and for the reconnect it reads the control node's ansible private key over SSH into memory. Both are described in [DEPLOYMENT.md](DEPLOYMENT.md#reinstall-what-is-and-is-not-verified).

## Repo layout

```
main.go                 # boot, flags, HTTP server
legal.go                # embeds LICENSE + THIRD_PARTY_LICENSES.md, version stamp
internal/api/           # HTTP + WebSocket handlers, request guards, login throttle
internal/auth/          # password hash + sessions
internal/config/        # JSON config store (servers, settings), Prometheus URL rules
internal/sshpool/       # cached *ssh.Client pool, known_hosts handling
internal/ansible/       # inventory / playbook / adhoc / vault / run history + redaction
internal/bootstrap/     # new-host bootstrap and OS reinstall
internal/jobs/          # background jobs (bootstrap) and their logs
internal/prom/          # prometheus query client
internal/geoip/         # ipinfo.io region lookup (opt-in)
internal/porkbun/       # Porkbun DNS API client (bootstrap)
internal/ttlcache/      # small bounded cache
web/                    # static bundle (embedded): JSX views, vendored React/Babel, fonts
tests/web/              # unit tests for the browser scripts
eslint-rules/           # local lint rule
scripts/                # licence header stamper, third-party notices generators
Makefile                # build (stamped, notices regenerated), license-check, notices-check
deploy/                 # hardened systemd unit
.github/                # CI, release and Dependabot config
.claude/                # Claude Code project config (see CI)
```

## Security posture

- **Built-in login is on by default and single-operator.** ansbui refuses to start until `ansbui -set-password` has been run (argon2id hash stored 0600 in the config dir; session cookie is `HttpOnly` + `SameSite=Strict`, `Secure` over HTTPS). Running without it is an explicit choice: `-allow-unauthenticated` or `ANSBUI_ALLOW_UNAUTHENTICATED=1`. In that mode anyone who can connect to the listen port can drive `ansible-playbook` as the configured SSH user, and **a loopback bind does not narrow that to you**: TCP on `127.0.0.1` is open to every account and process on the host, and a reverse proxy with auth in front does not change that, since local processes connect to the backend port directly. For multi-user or SSO, terminate auth at the proxy **and** keep the built-in password. Failed logins are throttled per source address (per `/64` for IPv6). See [DEPLOYMENT.md](DEPLOYMENT.md#0-built-in-login).
- SSH auth to the ansible controller is key-based only (agent or on-disk key) — no password prompt. Host keys are verified (see `ANSBUI_INSECURE_SSH` to opt out in a lab). A connection's host must be a DNS name or an IP address, and the account's login shell must be a POSIX shell. Bootstrap targets are the one place a password is used for SSH: the one typed into the bootstrap form, sent only after the target's host key has been recorded or matched.
- **Run history is redacted, best effort.** Values of extra-vars and module arguments whose name looks like a secret (`password`, `token`, `secret`, `…_pass`, …) are replaced before a run is saved, and the same names are scrubbed from output lines. A secret under any other name is stored as typed, and so is anything a task prints. `runs.json` stays sensitive — see [DEPLOYMENT.md](DEPLOYMENT.md#10-whats-still-on-the-operator).
- **DNS-rebinding guard:** every `/api/` request must carry a recognised `Host` header (loopback, the `-addr` hostname, or an `ANSBUI_ALLOWED_HOSTS` entry). Reverse-proxy deployments must set `ANSBUI_ALLOWED_HOSTS` — see [Remote access](#remote-access--the-dns-rebinding-guard).
- **CSRF guard:** every `/api/` request — reads included — must be same-origin, and the WebSocket upgrader enforces the same check. Three rules: (1) if the browser sent `Sec-Fetch-Site`, it must be `same-origin` or `none`; (2) if an `Origin` header is present, its **scheme and host:port** must match the request's — behind a TLS-terminating proxy the scheme comes from `X-Forwarded-Proto`, so the proxy **must** send `X-Forwarded-Proto: https` (Caddy does by default) or every action returns `403`; (3) a `GET` without an `Origin` to a route that contacts the control node or Prometheus (`/api/inventory`, `/api/facts`, `/api/metrics`, `/api/playbooks`, `/api/playbooks/content`, `/api/vault`) must carry the header `X-Ansbui-Request: 1`, which the UI sends and a page on another site cannot — scripts add `-H 'X-Ansbui-Request: 1'`. Reads are covered because a cross-origin trigger still does the server-side work (e.g. `/api/facts` can run `ansible … -m setup` across the fleet) even though the response stays opaque to the caller.
- **Nothing is loaded from another origin.** The page, its styles, scripts and fonts (Inter and JetBrains Mono, in `web/fonts/`) are all embedded in the binary, and a `Content-Security-Policy` on every response keeps it that way: styles, fonts, images and network connections are limited to ansbui itself (`style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'`), with `Referrer-Policy: no-referrer`. This matters because one page holds every password field — a stylesheet from elsewhere is enough to read a password as it is typed. `script-src` still allows inline scripts, which the in-browser JSX compiler needs; the policy bounds what a script could load or contact, not whether one could run.
- **Response headers:** every response forbids framing (`Content-Security-Policy: … frame-ancestors 'none'`, `X-Frame-Options: DENY`) and content sniffing (`X-Content-Type-Options: nosniff`). Over HTTPS ansbui also sends `Strict-Transport-Security: max-age=31536000`. HSTS applies to the **hostname on every port** for a year, so a plain-HTTP service sharing ansbui's hostname would stop loading in the operator's browser — give ansbui its own hostname. See [DEPLOYMENT.md](DEPLOYMENT.md#hsts-give-ansbui-its-own-hostname).
- **SSRF guard:** the server-side Prometheus fetch is constrained to loopback / `ANSBUI_PROM_ALLOWED_HOSTS`, with cloud-metadata addresses always denied — enforced at save time, at fetch time, and again at **dial time** against the address DNS actually returned. The host allowlist alone can't stop rebinding (it vets the name, not the destination), so the client resolves the target itself, checks each candidate, and connects to the exact IP it approved; `ANSBUI_PROM_ALLOWED_CIDRS` narrows that to a specific network.
- **Bootstrap's reinstall option trusts the target's network.** ansbui checksum-verifies the reinstall script it runs on the target, but the installer that script boots is downloaded by the target over plain HTTP, and the OS image is not checked against a digest. Someone on the target's network path could substitute either, so use the option only where you trust that path. See [DEPLOYMENT.md](DEPLOYMENT.md#reinstall-what-is-and-is-not-verified).
- Playbook paths are validated against `^[A-Za-z0-9._-]+$` per segment, blocking `..` traversal.
- Ansible argument keys are validated; values are shell-quoted.
- The binary writes config with mode `0600` in `~/.config/ansbui/`.

## CI

CI runs on GitHub Actions (`.github/workflows/`):

- **`ci.yml`** — `check` is the required merge gate: Go build + vet + race tests, `make license-check` (every first-party source file carries the AGPL notice), `golangci-lint`, `eslint` over `web/`, and `npm test` (the local lint rule in `eslint-rules/`, plus unit tests in `tests/web/` for the plain functions of the browser scripts). Two advisory jobs run alongside it: `vuln` (`govulncheck` + `npm audit`) and `fuzz` (a short pass over every `Fuzz*` target).
- **`sonarqube.yml`** — SonarQube Cloud scan with Go coverage, using `SONAR_TOKEN` from the repo secrets. Two jobs: `coverage` runs the tests with no secret in scope and hands `coverage.out` to `scan`, which holds the token and executes nothing from the checkout. The project is `AlteredParadox_ansbui` in the `alteredparadox` organization; rule exceptions live in `sonar-project.properties`.
- **`release.yml`** — pushing a `vX.Y.Z` tag builds `linux/amd64` + `linux/arm64` binaries, stamped with the tag, and publishes them with a `SHA256SUMS` as a GitHub Release; a manual dispatch is a build-only dry run. Before building it runs `make notices-check`, which fails the release if `THIRD_PARTY_LICENSES.md` no longer matches what is linked into the binary.

Dependabot (`.github/dependabot.yml`) opens weekly grouped PRs for Go modules, GitHub Actions and the npm lint toolchain.

The repo also ships a Claude Code hook (`.claude/settings.json` + `.claude/hooks/post-edit-lint.sh`): if you open this project in [Claude Code](https://claude.com/claude-code), every file it edits is linted immediately (`golangci-lint` for Go, `eslint` for JS/JSX) so issues surface before commit. It's a plain, inspectable shell script and a silent no-op when those tools aren't installed — but note it does auto-run on edits, so review it if that's a concern. It has no effect if you use a different editor.

## SonarQube hotspot notes

A few of Sonar's hotspots are not real concerns in this project; leaving them here so they aren't re-raised on every review:

- **`'unsafe-inline'` in the Content-Security-Policy's `script-src`.** Deliberate: the JSX is compiled in the browser by Babel, which runs its output as inline scripts. Every other directive is `'self'` or stricter, and nothing is loaded from a third party — React, ReactDOM and Babel are vendored in `web/vendor/` (checksums in `web/index.html`), the fonts in `web/fonts/` (checksums in its README). Removing `'unsafe-inline'` needs a build step that ships compiled `.js`.
- **Regex ReDoS hotspots** (`javascript:S5852`) on the YAML tokenisers in `Inventory.jsx`, `Playbooks.jsx`, `data/api.js`. Every regex we flag is anchored to a single line, uses character classes over broad alternation, and has no nested or overlapping quantifiers — input size per match is bounded by the line length pulled out of `.split('\n')`. Inputs come from playbook files authored on the controller (trusted operator-supplied YAML), not from external request bodies.
- **Weak PRNG** (`History.jsx`, `javascript:S2245`). The previous implementation synthesised per-task / per-host cells with `Math.random()` for the prototype. The view now reads the real streamed run log instead, so no PRNG is used in the production path.

## License

ansbui is free software under the **GNU Affero General Public License v3 or later** ([`LICENSE`](LICENSE)).

The AGPL's §13 obligation is to offer the Corresponding Source to everyone who interacts with the program *over a network*, so these three routes are deliberately served **without login** — a login wall would defeat the offer:

| Route | Serves |
| --- | --- |
| `/license` | the AGPL text embedded in this binary |
| `/third-party-licenses` | every bundled dependency's licence and notices |
| `/source` | redirects to the Corresponding Source, pinned to the running version |

They are linked from the sign-in screen and from **Settings → About & licensing**. A stamped release points `/source` at its own tag, so the source you are offered is the source that is running; an unstamped build (`go build`) can only point at the repository. They reveal nothing about the deployment: two texts compiled into the binary and a redirect to this repository.

If you run a modified ansbui for others to use over a network, the same obligation is yours: change `sourceBaseURL` in `internal/api/legal.go` to where your source is published.

Every first-party source file carries the AGPL notice; `make license-headers` stamps new files and `make license-check` (in CI) fails on one without it.

[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) is generated from what is **actually distributed**: the Go modules linked into the binary (read back off a probe build) and the third-party files embedded from `web/` — React, ReactDOM, Babel and the two fonts — whose licence texts are kept beside them in `web/vendor/` and `web/fonts/`.

```sh
make notices        # regenerate after a dependency change
make notices-check  # fail if the committed copy is stale (the release workflow runs this)
make build          # regenerates the notices, then builds a stamped binary
```

`web/vendor/babel.min.js` is a special case. It is Babel's single-file browser build, which also contains a few dozen separately published packages, most of them from outside the Babel project and so not covered by Babel's own licence (MIT, ISC, BSD-2-Clause, and CC-BY-4.0 for the caniuse-lite browser data). `web/vendor/babel-standalone.THIRD-PARTY.txt` lists each with the licence it ships. It is produced by `scripts/babel-bundle-licenses.py <version>` from the source map upstream publishes with the file, and must be regenerated in the same commit that replaces `babel.min.js`; the script refuses to run if the vendored file is not the upstream file for that version.
