# ansbui deployment hardening

ansbui drives ansible-playbook and bootstrap as the configured SSH
user, so "can reach the port and get past auth" = "can run anything
ansible can". This doc is the checklist for getting from `go build`
to a production deployment.

## 0. Built-in login

ansbui has a single-operator login and **does not start without
it**. Set a password before the first start:

```
sudo -u ansbui ANSBUI_CONFIG=/opt/ansbui/data/config.json \
  /opt/ansbui/bin/ansbui -set-password
```

It prompts twice (echo off) and writes an argon2id hash to
`auth_credential` **next to `config.json`** (0600) — so pointing
`ANSBUI_CONFIG` at the same file the service uses is all it needs.
Set `ANSBUI_AUTH_CREDENTIAL` to override the location. **Restart
ansbui** for it to take effect. Rotate by re-running the command.

Run it **as the service user**, as shown, not as root. A credential
file written by root is owned by root; the service cannot read it,
and ansbui stops at startup rather than run without a login.

Once a credential exists, every `/api/*` request (reads, writes, and
the WebSocket run streams) requires a session cookie obtained by
logging in through the UI. The cookie is `HttpOnly`, `SameSite=Strict`,
and `Secure` whenever the browser reached ansbui over HTTPS (direct
TLS or a proxy that sets `X-Forwarded-Proto: https`). Sessions are
held in memory — a restart logs the operator out — with a 12h idle
timeout and a 7-day absolute cap.

Failed logins are throttled per source: five attempts of burst, one
refilling every three seconds. Recovery is purely time-based —
throttled requests consume nothing and failures never push it out —
so a hostile client can't extend a lockout. A source is an IPv4
address or, for IPv6, the **/64** the address is in (one host
controls every address of its /64, so keying on the exact address
gave it a fresh budget for each). Two more limits protect the
password check itself, which is deliberately expensive (argon2):
at most two checks run at once, and one source can have only one in
progress. An attempt that finds both slots busy waits up to three
seconds for one before answering `429`.

What this does and does not give you:

- **One client cannot lock the operator out.** Its failures spend
  only its own budget, and it can occupy only one of the two slots.
- **Many clients can still get in the way.** A sender with addresses
  in many networks (a botnet, or one routed IPv6 prefix wider than a
  /64) has many sources. Each gets its own budget, and between them
  they can keep both slots busy, so a real login may wait and then
  get `429` while that lasts. Guessing speed stays bounded by the two
  slots and argon2's cost; existing sessions are unaffected. ansbui
  cannot tell such senders apart from separate users — rate-limit
  `/api/login` at the proxy, or do not expose it to them.
- **Clients behind one address share a budget** (a NAT, or a proxy
  that is not listed in `ANSBUI_TRUSTED_PROXIES`): an attacker there
  cannot extend the lockout but does race the operator for each
  refilled token.

Behind a reverse proxy every client reaches ansbui from the proxy's
IP. Set `ANSBUI_TRUSTED_PROXIES` to the proxy's address(es) (IPs or
CIDRs, e.g. `127.0.0.1` for a same-host Caddy) and ansbui attributes
login attempts to the rightmost non-trusted `X-Forwarded-For` hop.
`X-Forwarded-For` is never believed unless the connection comes from
a listed proxy. Two things that setting relies on:

- **The proxy must write the client's address into the header
  itself.** ansbui cannot tell a hop the proxy appended from one the
  client sent and the proxy passed along. Caddy's `reverse_proxy`
  sets the header by default. **nginx does not**: a plain
  `proxy_pass` relays whatever `X-Forwarded-For` the client sent, so
  every client picks its own throttle bucket — a fresh budget per
  request, or someone else's address to exhaust. With nginx you need
  `proxy_set_header X-Forwarded-For $remote_addr;` (section 2 has the
  full block). Check any other proxy the same way: send a request
  with a made-up `X-Forwarded-For` and look at what reaches ansbui.
- **Everything that connects from a listed address is believed.**
  With `127.0.0.1` listed, that is the proxy and also every other
  process on the host: any of them can connect to ansbui's port
  directly and claim any client address, to dodge the throttle or to
  use up the operator's budget. The password is still required, so
  this affects throttling only. Closing it needs the proxy and ansbui
  to share something a local process lacks (a Unix socket with
  restricted permissions, or a secret header), which ansbui does not
  have yet; until then, treat other local accounts on the ansbui host
  as able to interfere with login throttling.

Cookie-session login is deliberately the **only** authentication
mechanism — there is no separate API-token scheme. Non-browser
clients (curl, scripts) hitting `/api/*` must present a session
cookie from `POST /api/login`, in addition to whatever auth the
reverse proxy asks for. An API consumer that sends neither gets
`401` — that's the point.

Separately from login, a script must send the header
`X-Ansbui-Request: 1` on the API reads that make ansbui contact the
control node or Prometheus (`/api/inventory`, `/api/facts`,
`/api/metrics`, `/api/playbooks`, `/api/playbooks/content`,
`/api/vault`, and the two run WebSockets when opened without an
`Origin`):

```
curl -H 'X-Ansbui-Request: 1' http://127.0.0.1:8787/api/inventory
```

Without it those routes answer `403`. The web UI sends the header
itself. It is not a credential — the value is ignored — it exists
because a web page on another site can make the operator's browser
send a plain `GET` to ansbui (an image tag or a link is enough) but
cannot attach a custom header to it. Reads answered from ansbui's own
state (`/api/health`, `/api/auth/status`, `/api/servers`,
`/api/settings`, `/api/runs`, `/api/bootstrap/jobs`) and all
`POST`/`PUT`/`DELETE` requests do not need it.

### Running without the built-in login

With **no** credential file ansbui refuses to start:

```
no login password is set (no credential at …/auth_credential) — refusing to start.
```

This is also what happens after an incomplete restore, an unmounted
data dir or an accidental delete of the file: the service stays down
instead of coming up open.

Starting without a password is possible, by asking for it: the
`-allow-unauthenticated` flag, or `ANSBUI_ALLOW_UNAUTHENTICATED=1` in
the environment. Every `/api` route, including the WebSockets that
run ansible, then answers whoever can connect. Before choosing it,
note what "can connect" means:

- **A loopback bind does not limit access to you.** `127.0.0.1:8787`
  is a TCP port, and TCP has no notion of which user is connecting.
  Every account on the host, and every process running there
  (a compromised web app, a CI job, a container sharing the host
  network), can open it. The data directory is `0700` so those same
  accounts cannot read `config.json` or `runs.json`; without a login,
  the API hands them the same contents and more.
- **A reverse proxy with auth does not change that.** The proxy
  authenticates what comes through the proxy. A local process does
  not go through it; it connects to the backend port directly.

So the opt-out fits a machine that only the operator uses, or a
network namespace or firewall rule that keeps everything except the
proxy away from the port. Otherwise set a password, with or without
a proxy in front. The two compose: the proxy for TLS, SSO or several
users (oauth2-proxy / authelia), the built-in password so the backend
port is not open behind it. The login itself is single-operator with
no roles.

**Upgrading from a release that started without a password:** the
service will not come up until you either run `-set-password` or add
the opt-out. If you add the opt-out and set a password later, take
the opt-out out again — ansbui logs a reminder at every start while
both are present, because a lost credential file would then start it
without login. `ANSBUI_AUTH_REQUIRED=1` is still honoured and beats
the opt-out: with it set there is no start without a credential,
whatever else the unit says. On its own it no longer changes
anything.

## 1. Loopback bind

The default is `127.0.0.1:8787`. Don't override unless TLS
terminates in front. ansbui logs a line at startup when `-addr` is a
wildcard (`0.0.0.0`, `::`, or no host at all) or a non-loopback IP
address — treat it as a deployment-time error, not a notice. A
**hostname** in `-addr` is not resolved for this check, so it never
triggers the line even when it points at a public address; bind by
IP address.

Loopback keeps other *machines* out. It does not keep other *users
of this machine* out: any local account or process can connect to
the port. The built-in login (section 0) is what stands between them
and the API.

## 2. Reverse proxy with auth

Put ansbui behind nginx / Caddy / Apache for TLS, and for auth if
you need more than the single built-in password (several users,
SSO). Keep the built-in password as well: proxy auth covers requests
that come through the proxy, and anything on the ansbui host can
connect to the backend port without going through it (section 0,
"Running without the built-in login"). ansbui's `withOriginGuard`
middleware mitigates browser CSRF but doesn't substitute for
authentication.

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

The same with nginx. The two `X-Forwarded-*` lines are not optional
(see the list below for what each one is for), and nginx sends
neither unless told to:

```
server {
    listen 443 ssl;
    server_name ansbui.example.com;
    # ssl_certificate / ssl_certificate_key …

    auth_basic           "ansbui";
    auth_basic_user_file /etc/nginx/ansbui.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        # $remote_addr, not $proxy_add_x_forwarded_for: this proxy is
        # the first hop, so the connecting address is the client and
        # nothing the client sent belongs in the header.
        proxy_set_header X-Forwarded-For   $remote_addr;

        # WebSocket run streams (/api/adhoc/stream, /api/playbook/stream, …)
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
    }
}
```

mTLS or oauth2-proxy / authelia are stronger. Whatever you pick,
the proxy should:

- terminate TLS (let's encrypt or your CA)
- forward the browser's original `Host` header and list that name in
  `ANSBUI_ALLOWED_HOSTS` (see the README's "Remote access" section).
  A proxy that replaces `Host` with the backend address — nginx does
  when the `proxy_set_header Host $host;` line is missing — makes
  login and every other action fail with `403`, because the browser's
  `Origin` no longer matches the host ansbui was asked for
- send `X-Forwarded-Proto: https`. This is **required**, not
  advisory: ansbui compares the scheme of the browser's `Origin`
  with the scheme the request arrived on, so that a plain-HTTP page
  for your hostname (which someone on the operator's network can
  serve) is not mistaken for the real UI. A proxy that terminates TLS
  without sending the header makes every login and every action fail
  with a `403` that names this header. Caddy's `reverse_proxy` sends
  it by default; for nginx add
  `proxy_set_header X-Forwarded-Proto $scheme;` next to
  `proxy_set_header Host $host;`
- be listed in `ANSBUI_TRUSTED_PROXIES` **and set `X-Forwarded-For`
  to the connecting client's address itself**, so login throttling
  sees real client IPs instead of one shared proxy IP. Caddy does
  this by default. nginx does not: without
  `proxy_set_header X-Forwarded-For $remote_addr;` it passes on
  whatever the client sent, and each client then chooses the address
  it is throttled as (section 0)
- leave `/license`, `/third-party-licenses` and `/source` reachable if
  people other than you use this instance. ansbui serves them without
  login because the AGPL entitles everyone who uses it over a network
  to its license and source (README, "License"); they return two
  texts compiled into the binary and a redirect to the public
  repository, nothing about your deployment
- authenticate every other request, including the WebSocket run streams.
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

### HSTS: give ansbui its own hostname

On every response to a request that arrived over HTTPS (direct TLS,
or `X-Forwarded-Proto: https` from the proxy) ansbui sends

```
Strict-Transport-Security: max-age=31536000
```

A browser that has seen this header refuses to use plain HTTP for
that hostname for one year, renewed on each visit. That is the
intent: it stops a network attacker from serving the operator a
plain-HTTP page under ansbui's name.

What to know before deploying:

- **It covers the hostname on every port, not just ansbui's.** If
  `ops.example.com` serves ansbui over HTTPS and something else over
  plain HTTP on another port (`http://ops.example.com:9090`), the
  operator's browser will rewrite that to `https://` and the other
  service stops loading in that browser. ansbui holds the keys to the
  whole fleet and should have a hostname to itself
  (`ansbui.example.com`); give it one rather than sharing.
- It does **not** cover subdomains or sibling names — the header
  carries no `includeSubDomains` — so `prometheus.example.com` is
  unaffected by `ansbui.example.com`.
- It is never sent over plain HTTP, so a loopback or SSH-tunnel
  instance (`http://127.0.0.1:8787`) does not pin anything.
- There is no switch to turn it off. If the proxy also sets the
  header, the browser uses the first one it receives; either is fine.
- To undo it in one browser (after moving ansbui off a shared name,
  say): Chrome/Edge `chrome://net-internals/#hsts` → "Delete domain
  security policies"; Firefox: forget the site from History. It
  otherwise expires a year after the last HTTPS visit.

### Other response headers

Every response also carries:

- `Content-Security-Policy` with `frame-ancestors 'none'`, plus
  `X-Frame-Options: DENY`: no other site can embed the UI in a frame
  and trick the operator into clicking in it.
- The same `Content-Security-Policy` limits what the page may load and
  contact to ansbui itself: `default-src 'self'`, `style-src 'self'`,
  `font-src 'self'`, `img-src 'self' data:`, `connect-src 'self'`,
  `object-src 'none'`, `base-uri 'none'`, `form-action 'self'`. The
  UI needs nothing from anywhere else — its fonts are in the binary —
  and the page that holds every password field should not be able to
  fetch a stylesheet from, or send a request to, another host.
  `script-src 'self' 'unsafe-inline'` is the exception: the UI
  compiles its JSX in the browser and runs the result as inline
  scripts.
- `Referrer-Policy: no-referrer`: links out of the UI do not tell the
  destination where ansbui lives.
- `X-Content-Type-Options: nosniff`.

Nothing needs configuring. If the proxy adds its own copies, make
sure it does not *relax* them (e.g. an `X-Frame-Options: SAMEORIGIN`
override), and note that a proxy which **injects** content into the
page — an analytics snippet, a banner, a login widget loading from
another host — will be blocked by this policy. That is the policy
working; serve such things from the proxy's own pages instead.

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

### Outbound connections

Two separate lists: what the **ansbui host** connects to, which is
complete, and what a **bootstrap target** connects to, which is not.
The browser is in neither: the UI loads nothing from anywhere but
ansbui.

From the ansbui host, this is everything:

- **The control node(s)**, SSH on the port in each connection. Every
  ansible command runs there.
- **Bootstrap targets**, SSH on the port typed into the form and then
  on `4242`, which bootstrap moves `sshd` to. ansbui dials the target
  itself, not through the control node.
- **Prometheus**, only if a URL is set, and only hosts permitted by
  `ANSBUI_PROM_ALLOWED_HOSTS` / `ANSBUI_PROM_ALLOWED_CIDRS`.
- **`https://ipinfo.io`**, only while *Look up host regions via
  ipinfo.io* is switched on in Settings (off by default). It sends
  the **public IP addresses of your inventory hosts** to that service
  to fill the Region column. Private and loopback addresses are never
  sent.
- **`https://api.porkbun.com`**, during a bootstrap whose target was
  given as an IP address: ansbui creates or updates the DNS record
  for the new hostname. The API key and secret are read from the
  vault file on the control node (`porkbun_api_key` and
  `porkbun_secret_key` in `inventory/group_vars/all/vault.yml`) with
  the vault password typed into the form; ansbui does not store them.

From a bootstrap target, without the reinstall option: its
distribution's package mirrors, for `apt-get install` of `sudo` and
`python3`.

From a bootstrap target, **with** the reinstall option, at least the
following. This part is driven by the upstream script and the
installer it boots, not by ansbui, and has **not been inventoried in
full** — expect more (the installer's package repository and time
synchronisation, and the new system's own first-boot traffic), and
treat the list as a starting point for an egress policy, not as the
policy:

- its package mirrors, as above, plus `curl`;
- `raw.githubusercontent.com` (HTTPS): the script and its helpers;
- `http://www.qualcomm.cn/cdn-cgi/trace` (**plain HTTP**, following
  redirects): the script asks this address which country the target
  is in before doing anything else, and **stops with "Can not get
  location." if it gets no answer**. A target that cannot reach it
  cannot be reinstalled;
- `dl-cdn.alpinelinux.org` (**plain HTTP**): the installer;
- the public resolvers `1.1.1.1` and `8.8.8.8` (and their IPv6
  addresses) on TCP ports 443 and 80: the installer decides whether
  it has a working network by connecting to them, and configures the
  new system's network from the answer;
- `cdimage.debian.org` or `cloud-images.ubuntu.com` (HTTPS): the OS
  image;
- if the location answer is `CN`, `mirror.nju.edu.cn` instead of the
  last two — plain HTTP for the installer, HTTPS for the image.

See "Reinstall: what is and is not verified" in section 7 before
allowing any of these.

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
drwx------ ansbui ansbui  .
-rw------- ansbui ansbui  auth_credential
-rw------- ansbui ansbui  bootstrap_known_hosts.json
-rw------- ansbui ansbui  config.json
-rw------- ansbui ansbui  runs.json
```

(`bootstrap_known_hosts.json` appears after the first bootstrap.)

- `config.json` holds the server connection details, the SSH
  `KeyPath` strings (not the keys themselves) and the Prometheus URL
  — **including a username and password if you wrote one into it**.
- `runs.json` holds the output of past playbook, ad-hoc and bootstrap
  runs, and the values they were started with (secret-looking ones
  redacted, see section 10).
- `auth_credential` is the login password hash, and
  `bootstrap_known_hosts.json` the host keys bootstrap has recorded.
- `runs.json.bad-<timestamp>` appears if ansbui found the history
  unreadable at startup and set it aside. It is a full copy of the
  old history. ansbui never deletes it and never applies newer
  redaction rules to it; remove it once you have looked at it.

Treat all of them as sensitive. The service user's `~/.ssh`
(`/opt/ansbui/.ssh` with the shipped unit) holds the private keys for
the control nodes and the `known_hosts` file their host keys are
checked against.

## 7. Environment hardening

Optional env vars worth knowing about:

- `ANSBUI_PROM_ALLOWED_HOSTS=host1,host2` — the hosts the
  Prometheus URL setting may name. Without it only loopback hosts
  are accepted. Set this when the Prom server lives anywhere other
  than the same host.
- `ANSBUI_PROM_ALLOWED_CIDRS=10.0.0.0/8` — the networks an allowed
  Prometheus **hostname** may resolve to, checked when ansbui
  connects. The host allowlist only vets the name; without this,
  whoever controls that name's DNS chooses where ansbui's metrics
  requests go (link-local and cloud-metadata addresses are refused
  regardless). Set it to the network Prometheus is actually on.
- `ANSBUI_INSECURE_SSH=1` — skip SSH host-key verification **for
  connections to the control node**. **Lab only.** MITM attacks
  become undetectable. The warning is logged once, when ansbui makes
  its first SSH connection, not at startup — so it can be missing
  from the log of a service that has not been used yet. Bootstrap
  targets are not affected by this variable; their keys go through
  the fingerprint store described next.
- `ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY=1` — refuse bootstrap first
  contacts without a host key fingerprint. By default the first
  bootstrap of a target trusts whatever key it presents, records
  the fingerprint in `data/bootstrap_known_hosts.json`, and
  enforces it on every later run; with this set, the operator
  must supply the fingerprint (from the provider console) up
  front, so even the first contact is authenticated. Recommended
  wherever the provider exposes host keys out of band.

  In either mode the fingerprint is written to the store **before**
  the password is sent, and a bootstrap whose record cannot be
  written (full disk, wrong owner after a restore, read-only mount)
  stops there with "refusing to authenticate … no credential was
  sent". Fix the data directory and retry. Two consequences worth
  knowing: a key is on record even if the login then fails (a
  mistyped password — the job log still shows the first-contact
  warning for that run), and after bootstrap moves sshd to port 4242
  the same fingerprint is recorded for `host:4242` too, so a re-run
  against the new port is verified rather than trusted afresh. Before
  writing that second record ansbui connects to port 4242 (key
  exchange only, no login) to check it presents the same key; if
  something else answers there with a different key, nothing is
  written, any existing record for `host:4242` is kept, and the job
  log says so.

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

### Reinstall: what is and is not verified

The **reinstall the OS first** option in the bootstrap form wipes the
target and installs a fresh Debian or Ubuntu by running the upstream
[bin456789/reinstall](https://github.com/bin456789/reinstall) script
as root on the target. Everything below is downloaded **by the
target**, first from its current OS and then from the installer it
reboots into. ansbui verifies the first item and not the rest:

- **`reinstall.sh` — verified.** Fetched over HTTPS from
  `raw.githubusercontent.com` at a commit fixed in the ansbui source,
  and its SHA-256 is compared with a value compiled into ansbui. A
  mismatch stops the run before anything from it executes.
- **Its helper scripts (`trans.sh` and others) — HTTPS only.** ansbui
  points them at the same commit and removes the `--insecure` the
  upstream script passes to `curl`, so they come from that commit
  over a checked TLS connection. ansbui holds no digest for them.
- **Which mirrors to use — decided by an unauthenticated answer.**
  Before downloading anything else the script asks
  `http://www.qualcomm.cn/cdn-cgi/trace` (plain HTTP) which country
  the target is in. For `CN` it takes the installer and the OS image
  from `mirror.nju.edu.cn`; for anything else, from the hosts named
  below. Nothing authenticates that answer, so whoever can alter it
  chooses between the two sets of mirrors. With no answer at all the
  script stops.
- **The installer: an Alpine Linux netboot kernel, initramfs and
  modules — not verified, and plain HTTP.** They come from
  `http://dl-cdn.alpinelinux.org` (or `http://mirror.nju.edu.cn`).
  Upstream uses HTTP there on purpose (some machines have a wrong
  clock that early, which breaks HTTPS), and nothing checks a digest
  or signature of the files.
- **The OS image — not verified.** A Debian `…/latest/…qcow2` from
  `cdimage.debian.org` or an Ubuntu `…/release/…img` from
  `cloud-images.ubuntu.com` (or either from `mirror.nju.edu.cn`),
  over HTTPS, with no digest or signature check. The path always serves the newest build, so two reinstalls
  can install different images. It is downloaded by the installer,
  which was itself not verified.

What follows from that: whoever can alter traffic between the target
and the Alpine mirror while a reinstall runs can swap the installer,
and with it control the system that gets installed — including the
`ansible` account and key that bootstrap then puts on it. That is the
target's hosting network, any network between it and the mirror, or
whoever can answer its DNS query for the mirror. The same holds for
anyone able to change what a mirror or image server hands out.
ansbui cannot notice: the reinstalled host comes back and answers
normally. The exposure is on the **target's** network path and lasts
for the minutes the downloads take; the path between you and ansbui,
and between ansbui and the control node, is not involved.

There is no setting that adds the missing checks. So:

- Use the reinstall option only where you are willing to trust the
  target's network path that far — in practice, a provider's
  datacenter network you already rely on.
- Where the provider can rebuild the machine from its own image, do
  that instead and run bootstrap without the reinstall option.
- A reinstalled host has a new host key that ansbui could not verify
  either (above). Comparing the fingerprint ansbui reports against
  the provider console tells you that you reached the right machine;
  it says nothing about what was installed on it.

A reinstall also brings the control node's ansible **private key**
onto the ansbui host. The freshly installed system accepts only that
key, so ansbui reads it from the control node over SSH
(`~/.ssh/ansible_ed25519` there, or the path set in Settings) and
uses it to reconnect. It is held in memory for that job and never
written to disk on the ansbui host. A bootstrap without the reinstall
option reads only the public key.

This describes the upstream script at the commit ansbui currently
pins (`reinstallScriptCommit` in `internal/bootstrap/reinstall.go`).

### Reinstall: when it starts failing

The script is pinned, so it never changes under you. Everything it
downloads does: the Alpine installer is rebuilt at every Alpine point
release, the Debian and Ubuntu images about weekly, and upstream
adapts the script to those changes only on its `main` branch. A pin
that worked for months can therefore start failing without anything
in ansbui having changed. Two things to do:

- From a checkout of ansbui, run `scripts/check-reinstall-pin.sh`.
  It downloads the pinned files and checks them against everything
  ansbui depends on — the checksum, the rewrites ansbui applies, the
  flags it passes, the output it parses — and that the location
  lookup, the installer files and the OS images still answer. It runs
  nothing from the script. A failure names what broke. A pass means
  the pin is intact, **not** that a reinstall works.
- If it passes and reinstalls still fail, the pin is probably too old
  for today's installer and images. Compare with upstream: if the
  current upstream script reinstalls the same machine by hand, update
  ansbui to a release with a newer pin (or bump it — the steps are in
  the comment above `reinstallScriptCommit`). A box that failed in
  the installer stays up in the installer environment: `ssh root@host
  -p 4242` with the bootstrap key and read `/reinstall.log`.

### SSH peers that stop answering

Every command ansbui runs goes over an SSH session to a control node
or, during bootstrap, to the machine being set up. A peer that logs
in normally and then stops answering cannot hold ansbui's shared
capacity (16 metadata queries, 8 runs, 4 bootstrap jobs):

- A request for a new session or command that gets **no reply for
  20 seconds** fails with *"the SSH server did not answer a session
  request"* and ansbui **closes that connection**. Anything else
  running over the same connection ends with it — a healthy `sshd`
  answers in milliseconds, so this only happens on a link that is
  already broken. The next request dials a new connection.
- A request that is cancelled, times out or whose browser tab closes
  returns at once, whether or not the peer has answered.
- A cancelled command is sent `SIGTERM`, then its channel is closed
  after 2 seconds; if the peer does not acknowledge the close within
  another 5 seconds the connection is closed.
- **Cancel** on a bootstrap job takes effect within a few seconds in
  every state, including a job queued behind another bootstrap of the
  same target.

Bootstrap logs are bounded too. Text a target sends back (its
`os-release`, command output, error messages) is cut to 16 KiB per
log line with the middle removed, and a job keeps at most 2000 lines
or 1 MiB — the same limits run history has always applied to ad-hoc
and playbook runs. A log that hits a limit says so and still ends
with the job's result.

## 8. Backup & restore

Four files matter:

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
  in the bootstrap form. Every value must be a `SHA256:…`
  fingerprint: a hand-edited file with an empty value, or one
  that is not a JSON object, is treated as corrupt and stops
  every bootstrap until it is fixed — it is never read as "no
  record".
- `/opt/ansbui/data/auth_credential` — the argon2id login password
  hash (0600), written by `-set-password`. Without it ansbui refuses
  to start until you restore it or re-run `-set-password` — unless
  the unit carries the `-allow-unauthenticated` opt-out, in which
  case it would start with no login (see section 0; one more reason
  to remove the opt-out once a password exists). It's a slow hash,
  not plaintext, but treat it as sensitive.

A nightly tar-and-restic of `/opt/ansbui/data/` covers all four. To
restore: stop the service, replace the directory, restart.

A backup is a copy of everything in section 6, including run history
as it was redacted on the day of the backup. Store it with the same
care as the live directory.

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
git pull && make build && cp ansbui /tmp/ansbui
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

`make build` regenerates `THIRD_PARTY_LICENSES.md` (it is embedded in
the binary), stamps the version from `git describe`, and builds with
`-trimpath` (strips local paths) and `-ldflags='-s -w'` (strips the
symbol table). The stamp is what **Settings → About & licensing**
shows and what `/source` points at. A plain `go build -o ansbui .`
also works; it reports version `dev`. Or skip the build and install a
release binary, checking it against the release's `SHA256SUMS`.

### Checks after upgrading

Newer releases require things older ones did not. If ansbui does not
come up, or the UI loads and then nothing works, check these first:

- **No login password, no start.** A release that used to start
  without a credential file now refuses to. Run `-set-password`, or
  opt out explicitly (section 0).
- **Behind a TLS proxy, `X-Forwarded-Proto: https` is required.**
  Without it login and every action answer `403` naming the header.
  Caddy sends it; nginx needs the line shown in section 2.
- **Scripts need `X-Ansbui-Request: 1`** on the reads listed in
  section 0, or they get `403`.
- **The proxy must not add third-party content to the page.** The
  `Content-Security-Policy` ansbui sends blocks anything not served
  by ansbui itself (section 3, "Other response headers").
- **HSTS covers the whole hostname for a year** once a browser has
  loaded ansbui over HTTPS (section 3).

Newer releases also refuse some input that older ones stored. Nothing
is rewritten for you; these are worth one look after an upgrade.

- **`~/.ssh/known_hosts` of the service user.** A connection's host
  must now be a DNS name or an IP address. Before that rule, a host
  written as an IPv6 address with a crafted zone (`::1%…`) could add
  a line of its own to `known_hosts`, including a `*` pattern, and a
  key on a `*` line is accepted for **every** host, even one with a
  different key already pinned. ansbui never removes lines from this
  file. On the first SSH connection after start it logs
  `known_hosts: … has wildcard host patterns on line(s) …` if any
  host pattern contains `*` or `?`. If you did not put those lines
  there (a certificate-authority line or a lab subnet are the usual
  legitimate ones), delete them and compare the keys of your control
  nodes against a source you trust.
- **Connections with an unusual host.** A stored connection whose host
  is not a DNS name or IP address (a `user@host`, a bracketed IPv6
  address, a name with a space) now fails to connect with *"this
  connection's host cannot be used"*. Edit it. An IPv6 link-local
  address may keep its zone when the zone is an interface name
  (`fe80::1%eth0`).
- **Prometheus URL.** It must be a base address — scheme, host,
  optional path prefix — with no `?query` and no `#fragment`. A stored
  URL that has one is refused on every fetch (the log says so) and
  host metrics stay empty until it is saved again without it.
- **Login shell on the control node.** ansbui builds every command for
  a POSIX shell (`sh`, `bash`, `dash`, `ksh`, `zsh`), and the SSH
  account's login shell is what reads them. Under `fish`, for example,
  a value containing a backslash followed by a quote is split into
  separate commands. **Test connection** now checks this by sending a
  quoted value through the shell and comparing what comes back; if it
  reports that the shell *"does not read quoted arguments the way a
  POSIX shell does"*, change the account's shell
  (`chsh -s /bin/bash <user>`). The check runs only when you press
  Test connection.

## 10. What's still on the operator

- Keeping the built-in login password set, and strong: it is the only
  thing between other accounts on the ansbui host and the API.
- Rate-limiting `/api/login` at the proxy if it is reachable from
  networks you do not control (section 0 explains what the built-in
  throttle cannot bound).
- Rotation of `KeyPath` SSH keys when staff turn over.
- Deciding where the bootstrap **reinstall** option may be used. Its
  installer and OS image downloads are not verified (section 7), so
  it is only as trustworthy as the target's network.
- Keeping other accounts off the ansbui host. They cannot get past
  the login, but they can connect to the backend port directly, and
  with `127.0.0.1` in `ANSBUI_TRUSTED_PROXIES` they can interfere
  with login throttling (section 0).
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
