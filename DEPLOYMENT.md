# ansbui deployment hardening

ansbui drives ansible-playbook and bootstrap as the configured SSH
user, so "can reach the port and get past auth" = "can run anything
ansible can". This doc is the checklist for getting from `go build`
to a production deployment.

## 0. Built-in login (optional but recommended)

ansbui ships an optional single-operator login. Set a password:

```
sudo -u ansbui ANSBUI_CONFIG=/opt/ansbui/data/config.json \
  /opt/ansbui/bin/ansbui -set-password
```

It prompts twice (echo off) and writes an argon2id hash to
`auth_credential` **next to `config.json`** (0600) — so pointing
`ANSBUI_CONFIG` at the same file the service uses is all it needs.
Set `ANSBUI_AUTH_CREDENTIAL` to override the location. **Restart
ansbui** for it to take effect. Rotate by re-running the command.

Once a credential exists, every `/api/*` request (reads, writes, and
the WebSocket run streams) requires a session cookie obtained by
logging in through the UI. The cookie is `HttpOnly`, `SameSite=Strict`,
and `Secure` whenever the browser reached ansbui over HTTPS (direct
TLS or a proxy that sets `X-Forwarded-Proto: https`). Sessions are
held in memory — a restart logs the operator out — with a 12h idle
timeout and a 7-day absolute cap. Five consecutive failed logins trip
a short backoff.

When **no** credential is set ansbui runs UNAUTHENTICATED (the
historical posture) and logs a loud startup warning; the reverse
proxy below is then mandatory, not optional. Built-in login and a
proxy compose fine — defence in depth. Note the login is
single-operator with no roles; for multi-user or SSO, terminate auth
at the proxy (oauth2-proxy / authelia).

## 1. Loopback bind

The default since `9003515` is `127.0.0.1:8787`. Don't override
unless there's something authenticated in front (built-in login
and/or a proxy). The startup warning fires when `-addr` resolves to
a non-loopback host — treat it as a deployment-time error, not a
notice.

## 2. Reverse proxy with auth

Put ansbui behind nginx / Caddy / Apache and require auth on every
request — unless you've set a built-in login password (section 0)
and accept single-operator access. ansbui's `withOriginGuard`
middleware mitigates browser CSRF but doesn't substitute for
authentication — anyone who can TCP-connect to an instance with no
password set bypasses both.

Caddy is the easiest:

```
ansbui.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8787
    basicauth {
        admin <bcrypt-hash>
    }
}
```

mTLS or oauth2-proxy / authelia are stronger. Whatever you pick,
the proxy should:

- terminate TLS (let's encrypt or your CA)
- authenticate every request, including the WebSocket run streams.
  These live under `/api/`, NOT a separate `/ws/` prefix, so a proxy
  rule that only guards `/ws/*` protects nothing. The upgrade
  endpoints are `/api/adhoc/stream`, `/api/playbook/stream`, and
  `/api/bootstrap/jobs/{id}/stream` — a blanket auth rule over `/`
  (or at minimum `/api/*`) covers them all.
- keep ansbui bound to loopback

## 3. TLS

Always. Never expose ansbui over plain HTTP — sessions carry
playbook output that often includes inventory hostnames, vault
plaintext briefly during view, and SSH config decisions.

## 4. Firewall

Belt-and-suspenders against a misconfigured proxy:

```
sudo nft add rule inet filter input tcp dport 8787 drop
```

or with ufw:

```
sudo ufw deny 8787
```

Loopback bind already prevents external dials, but the firewall
catches an accidental `-addr 0.0.0.0:8787`.

## 5. systemd sandboxing

The hardened unit lives at `deploy/ansbui.service`. Key
properties:

- runs as a dedicated `ansbui:ansbui` user/group
- `ProtectSystem=strict` + `ReadWritePaths=/opt/ansbui/data
  /opt/ansbui/.ssh` — only the runtime-state dirs are writable.
  The install tree (`/opt/ansbui`, `/opt/ansbui/bin`, the
  binary itself) is owned by root and read-only to the service,
  so a compromise can't overwrite its own binary.
- `PrivateIPC=true` + `RemoveIPC=true` — service runs in its
  own SysV/POSIX IPC namespace and any objects it creates are
  cleaned up on exit.
- `CapabilityBoundingSet=` (empty) — no caps inherited
- `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` — no
  netlink, packet, bluetooth sockets
- `SystemCallFilter=@system-service` — blocks @privileged
- `MemoryDenyWriteExecute=true`, `LockPersonality=true`,
  `RestrictNamespaces=true`
- `ProtectProc=invisible` + `ProcSubset=pid` — can't see other
  users' processes via /proc
- `UMask=0077` — defaults to 600 for any incidental writes

`systemd-analyze security ansbui.service` should report ≤ 2.0.

To install:

```
sudo cp deploy/ansbui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ansbui
```

First-time directory layout — install tree owned by root,
runtime state owned by the service user:

```
sudo install -d -o root   -g root   -m 0755 /opt/ansbui /opt/ansbui/bin
sudo install -d -o ansbui -g ansbui -m 0700 /opt/ansbui/data /opt/ansbui/.ssh
sudo install    -o root   -g root   -m 0755 /tmp/ansbui    /opt/ansbui/bin/
```

## 6. File permissions

ansbui creates everything 0600 / 0700, but verify after a fresh
install:

```
$ sudo ls -la /opt/ansbui/data/
drwx------ 3 ansbui ansbui  config.json  (0600)
drwx------ 2 ansbui ansbui  runs/
-rw------- 1 ansbui ansbui  runs.json    (0600)
```

`config.json` contains the Prometheus URL, server connection
details, and the ssh KeyPath strings (not the keys themselves).
`runs.json` contains historical playbook stdout/stderr — treat
both as sensitive.

## 7. Environment hardening

Optional env vars worth knowing about:

- `ANSBUI_PROM_ALLOWED_HOSTS=host1,host2` — pin the Prometheus
  URL setting to a known allowlist. Without it, only loopback
  hosts are accepted by `normalisePromURL`. Set this when the
  Prom server lives anywhere other than the same host.
- `ANSBUI_INSECURE_SSH=1` — skip SSH host-key verification.
  **Lab only.** MITM attacks become undetectable. The startup
  log emits a one-time warning when this is set.
- `ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY=1` — refuse bootstrap first
  contacts without a host key fingerprint. By default the first
  bootstrap of a target trusts whatever key it presents, records
  the fingerprint in `data/bootstrap_known_hosts.json`, and
  enforces it on every later run; with this set, the operator
  must supply the fingerprint (from the provider console) up
  front, so even the first contact is authenticated. Recommended
  wherever the provider exposes host keys out of band.

## 8. Backup & restore

Two paths matter:

- `/opt/ansbui/data/config.json` — configuration. Tiny. Back
  up on every change.
- `/opt/ansbui/data/runs.json` — run history. Grows over time;
  bounded to ~200 records by `Recorder.limit`. Lossy backup is
  fine.
- `/opt/ansbui/data/bootstrap_known_hosts.json` — SSH host key
  fingerprints recorded by bootstrap (TOFU store). Losing it
  means the next bootstrap of each target silently re-trusts on
  first use, so back it up with the rest; to deliberately reset
  trust for one target (e.g. after an out-of-band reinstall),
  remove its `"host:port"` entry or supply the new fingerprint
  in the bootstrap form.
- `/opt/ansbui/data/auth_credential` — the argon2id login password
  hash (0600), present only if you ran `-set-password`. Losing it
  disables built-in auth on next start (falls back to the
  unauthenticated posture); restore it or re-run `-set-password`.
  It's a slow hash, not plaintext, but treat it as sensitive.

A nightly tar-and-restic of `/opt/ansbui/data/` covers both. To
restore: stop the service, replace the directory, restart.

```
sudo systemctl stop ansbui
sudo tar -xzf ansbui-data-2026-04-26.tgz -C /opt/ansbui/
sudo chown -R ansbui:ansbui /opt/ansbui/data
sudo systemctl start ansbui
```

The SSH keys ansbui uses (`KeyPath` in each server config) live
in `/opt/ansbui/.ssh/` — back those up too if rotation is
expensive.

## 9. Upgrade path

```
git pull && go build -trimpath -ldflags='-s -w' -o /tmp/ansbui .
sudo install -o root -g root -m 0755 /tmp/ansbui /opt/ansbui/bin/
sudo systemctl restart ansbui
sudo systemctl status ansbui
curl -fsS -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8787/
```

The binary is owned by root (not the service user) so the
running service can't overwrite it — a compromise can't
self-update with malicious code. The deploying operator needs
sudo, which is fine for an upgrade flow that's usually
manual or driven by CI with elevated privileges.

`-trimpath` strips local paths from binary; `-ldflags='-s -w'`
strips the symbol table. Neither affects the security posture
but both are good hygiene for a prod binary.

## 10. What's still on the operator

- Auth in front of the proxy.
- Rotation of `KeyPath` SSH keys when staff turn over.
- Watching the upstream Go security advisories — `govulncheck`
  runs in CI but a published CVE doesn't update your binary.
- Regular `npm audit` — also in CI but worth a manual check
  before each release.
- Reviewing `runs.json` for accidental secrets in playbook output.
  ansbui redacts common password/token/key shapes, but arbitrary
  module output can still contain sensitive material under unusual
  names.
