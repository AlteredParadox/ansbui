# ansbui deployment hardening

ansbui has no built-in authentication. The control plane drives
ansible-playbook and provisioning as the configured SSH user, so
"can reach the port" = "can run anything ansible can". This doc
is the checklist for getting from `go build` to a production
deployment.

## 1. Loopback bind

The default since `9003515` is `127.0.0.1:8787`. Don't override
unless there's something authenticated in front. The startup
warning fires when `-addr` resolves to a non-loopback host —
treat it as a deployment-time error, not a notice.

## 2. Reverse proxy with auth

Put ansbui behind nginx / Caddy / Apache and require auth on every
request. ansbui's `withOriginGuard` middleware mitigates browser
CSRF but doesn't substitute for authentication — anyone who can
TCP-connect bypasses both.

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
- authenticate every request (including websockets — `/ws/*`)
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
- `ProtectSystem=strict` + `ReadWritePaths=/opt/ansbui` — only
  /opt/ansbui is writable
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

## 8. Backup & restore

Two paths matter:

- `/opt/ansbui/data/config.json` — configuration. Tiny. Back
  up on every change.
- `/opt/ansbui/data/runs.json` — run history. Grows over time;
  bounded to ~200 records by `Recorder.limit`. Lossy backup is
  fine.

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
sudo install -o ansbui -g ansbui -m 0755 /tmp/ansbui /opt/ansbui/bin/
sudo systemctl restart ansbui
sudo systemctl status ansbui
curl -fsS -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:8787/
```

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
- Reviewing `runs.json` for accidental secrets in playbook
  output (extra-vars, stdout) — the recorder doesn't redact.
