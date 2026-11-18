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
timeout and a 7-day absolute cap.

Failed logins are throttled with a per-source-IP token bucket: five
attempts of burst, one refilling every three seconds. Recovery is
purely time-based — throttled requests consume nothing and failures
never push it out — so a hostile client can't extend a lockout, and
the bucket is scoped per IP so it can't lock the operator out either.
The number of concurrently-verifying attempts is also capped globally
to bound argon2's memory cost.

Behind a reverse proxy every client reaches ansbui from the proxy's
IP. Set `ANSBUI_TRUSTED_PROXIES` to the proxy's address(es) (IPs or
CIDRs, e.g. `127.0.0.1` for a same-host Caddy) and ansbui attributes
login attempts to the rightmost non-trusted `X-Forwarded-For` hop —
the address the proxy itself recorded, which a client can't forge.
Without it, all proxied clients share one bucket: an attacker still
can't extend the lockout (see above), but does race the operator for
each refilled token — so either set the variable or rate-limit logins
at the proxy. `X-Forwarded-For` is never believed unless the
connection comes from a listed proxy. Clients behind one NAT
genuinely share an address and therefore a bucket; that contention
has no in-band fix.

Cookie-session login is deliberately the **only** authentication
mechanism — there is no separate API-token scheme. Non-browser
clients (curl, scripts) hitting `/api/*` on a password-protected
instance must either present a session cookie from `POST /api/login`
or go through whatever auth the reverse proxy adds. Enabling a
password will therefore break any unauthenticated API consumer you
may have pointed at the instance — that's the point.

When **no** credential is set ansbui runs UNAUTHENTICATED (the
historical posture) and logs a loud startup warning; the reverse
proxy below is then mandatory, not optional. Built-in login and a
proxy compose fine — defence in depth. Note the login is
single-operator with no roles; for multi-user or SSO, terminate auth
at the proxy (oauth2-proxy / authelia).

After setting the password, add `ANSBUI_AUTH_REQUIRED=1` to the
service environment (there's a commented line in
`deploy/ansbui.service`). With it set, ansbui **refuses to start**
when the credential file is missing instead of silently falling back
to the unauthenticated posture — which is what would otherwise
happen after an incomplete restore, an unmounted data dir, or an
accidental delete. The variable lives in the unit file precisely so
it survives the loss of the data dir it guards.

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
- be listed in `ANSBUI_TRUSTED_PROXIES` (and forward
  `X-Forwarded-For`, which nginx/Caddy do by default) so login
  throttling sees real client IPs instead of one shared proxy IP
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

  This also affects the **reinstall** option. A reinstall wipes the
  box and the new system generates fresh host keys, so no
  fingerprint pinned beforehand can cover the reconnect — and
  nothing in band can authenticate the replacement, because the
  installer and first-boot sessions are reached over the very
  connection that would need verifying. Rather than quietly
  falling back to trust-on-first-use, such a run is rejected up
  front (a 400, before a job starts and before the target is
  touched) **unless the operator ticks the host-key
  acknowledgement in the bootstrap form**.

  That acknowledgement is deliberately per-run, not a second
  environment variable: strict mode's real guarantee is that no
  unauthenticated key is trusted *silently*, and an explicit
  per-invocation waiver preserves that, while a config knob would
  switch the exemption on permanently and record nothing about who
  decided or when. The waiver is written into the job log, so it
  survives in run history. Compare the fingerprint ansbui reports
  afterwards against the provider console.

  The checkbox only appears when this variable is set; with strict
  mode off (the default) reinstall behaves exactly as before and
  the field is ignored.

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
  unauthenticated posture) — unless `ANSBUI_AUTH_REQUIRED=1` is set
  in the unit, in which case ansbui refuses to start until you
  restore it or re-run `-set-password` (see section 0; recommended).
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

  What is redacted: any extra-var or module argument whose **name**
  contains `password`, `passphrase`, `passwd`, `token`, `secret`,
  `api_key`, `private_key` or `credential`, or **ends in** `pass`
  (`ansible_become_pass`, `ansible_ssh_pass`, …) — the whole value,
  whatever its type, in the saved inputs and in the `$ …` command
  line at the top of the run. The same names followed by `:` or `=`
  are scrubbed from output lines, best effort. A secret passed under
  any other name (`db_pw`, `auth`) is stored as typed.

  **Upgrading from a release without the `pass` / `passwd` rules.**
  Those releases stored `ansible_become_pass` and friends in the
  clear. They also saved each run's `$ …` command line by scrubbing
  the text of the executed command, which left the tail of any secret
  containing a single quote, and every element of a list-valued one,
  right after the `<REDACTED>` marker. The first start after the
  upgrade repairs the live `runs.json`:

  - every stored value under a secret-looking name is replaced, by
    the current rules;
  - each older run's command line is **cut after its first redacted
    value** and marked as such. A leftover tail cannot be told apart
    from the rest of the command, so the rest goes. The run's limit,
    tags and other settings are still on the record. Command lines
    with nothing redacted in them are left whole, and runs recorded
    from now on are not cut.

  What the upgrade cannot reach is copies ansbui does not own:
  backups of the data directory, and the `runs.json.bad-<timestamp>`
  files left when a corrupt history was set aside. If such values
  were ever supplied through the UI, treat those copies as holding
  them: delete what you do not need, and rotate the passwords if a
  copy left the host. Rotate them too if the history API was
  reachable by anyone who should not have had them — the repair
  removes the values from now on, not from what was already read.
