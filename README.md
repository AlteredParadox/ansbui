# Relay — Ansible Control Plane UI

A single-binary web UI for an Ansible control node.

- **Backend**: Go 1.25 (stdlib HTTP + gorilla/websocket + golang.org/x/crypto/ssh)
- **Frontend**: React / Babel served from an embedded static bundle (design by [claude.ai/design](https://claude.ai/design), ported from the `ansible-ui` handoff bundle)
- **Integration**: connects to a remote ansible control node over SSH and runs `ansible-inventory`, `ansible`, and `ansible-playbook` there — no local Ansible install required
- **Observability**: optionally enriches inventory with live CPU / memory / load / uptime / OS from Prometheus (node_exporter), matched by hostname

## Quick start (Debian 13)

```sh
sudo apt install -y golang-go openssh-client
go build -o relay .
./relay -addr 127.0.0.1:8787
```

Open `http://127.0.0.1:8787/` in a browser. On first load you'll be prompted to add an ansible server — the SSH coordinates of a remote machine that already has `ansible` installed.

## Configuration

Relay writes to `~/.config/relay/config.json` (and `runs.json`). The UI is the only writer — do not hand-edit while the binary is running.

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

Paste your Prometheus URL (e.g. `http://prom.example.com:9090`) in **Settings**. The host label defaults to `instance` — change if your node_exporter scrapes use a different label. Matching strips any `:port` suffix.

## Repo layout

```
main.go                 # boot + HTTP server
internal/config/        # JSON config store (servers, prometheus url)
internal/sshpool/       # cached *ssh.Client pool
internal/ansible/       # inventory / playbook / adhoc / runs
internal/prom/          # prometheus query client
internal/api/           # HTTP + WebSocket handlers
web/                    # static bundle (embedded)
```

## Security posture

- SSH auth is key-based only (agent or on-disk key) — no password prompt.
- The websocket upgrader enforces same-origin.
- Playbook paths are validated against `^[A-Za-z0-9._-]+$` per segment, blocking `..` traversal.
- Ansible argument keys are validated; values are shell-quoted.
- The binary writes config with mode `0600` in `~/.config/relay/`.

## CI

`.gitea/workflows/ci.yml` runs build + vet + test, and kicks off a SonarQube scan using `SONAR_TOKEN` and `SONAR_HOST_URL` from the repo secrets. The Sonar project key is `ansbui`.

## SonarQube hotspot notes

A few of Sonar's hotspots are not real concerns in this project; leaving them here so they aren't re-raised on every review:

- **Missing Subresource Integrity on Google Fonts** (`web/index.html`, `Web:S5725`). SRI intentionally isn't used for `fonts.googleapis.com` — Google serves different CSS per User-Agent, so a pinned hash would break for most browsers. The React / Babel / React-DOM CDN references that actually ship code do carry `integrity=` attributes.
- **Regex ReDoS hotspots** (`javascript:S5852`) on the YAML tokenisers in `Inventory.jsx`, `Playbooks.jsx`, `data/api.js`. Every regex we flag is anchored to a single line, uses character classes over broad alternation, and has no nested or overlapping quantifiers — input size per match is bounded by the line length pulled out of `.split('\n')`. Inputs come from playbook files authored on the controller (trusted operator-supplied YAML), not from external request bodies.
- **Weak PRNG** (`History.jsx`, `javascript:S2245`). The previous implementation synthesised per-task / per-host cells with `Math.random()` for the prototype. The view now reads the real streamed run log instead, so no PRNG is used in the production path.
