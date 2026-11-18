// ansbui API client — populates globalThis.AnsibleData with data fetched
// from the Go backend. The existing view scripts continue to read from
// globalThis.AnsibleData; this module owns the fetches, WebSocket
// streaming, and the bootstrap translation.

(function () {
  const api = {};

  // errorMessage unwraps the backend's {"error":"..."} envelope so
  // banners show the message itself, not raw JSON. Non-JSON bodies
  // pass through unchanged.
  const errorMessage = (text) => {
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed.error === 'string') return parsed.error;
    } catch { /* not JSON — use the body as-is */ }
    return text;
  };

  // onUnauthorized is invoked once per 401 from any endpoint other
  // than the auth endpoints themselves, so the shell can drop to the
  // login screen when a session expires mid-session.
  let onUnauthorized = null;
  api.setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };
  const AUTH_PATHS = new Set(['/api/login', '/api/logout', '/api/auth/status']);

  // Every call carries X-Ansbui-Request. The server requires it on the
  // reads that make it contact the control node (withOriginGuard in
  // internal/api/api.go): those are GETs with no Origin header, which
  // a page on another site could otherwise fire blind through an
  // <img> or a link. Such a page cannot add a custom header, so its
  // presence is what tells the server the request is ours. Sent on
  // every call so a new endpoint needs nothing done here.
  const json = async (path, opts) => {
    const options = opts || {};
    const headers = options.headers || {};
    const res = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', 'X-Ansbui-Request': '1', ...headers }
    });
    if (!res.ok) {
      if (res.status === 401 && !AUTH_PATHS.has(path) && onUnauthorized) {
        onUnauthorized();
      }
      const text = await res.text();
      const err = new Error(errorMessage(text) || `${res.status} ${res.statusText}`);
      // Callers that need to distinguish "gone" from "backend blip"
      // (e.g. the bootstrap re-attach probe) read this.
      err.status = res.status;
      throw err;
    }
    if (res.status === 204) return null;
    return res.json();
  };

  api.authStatus = () => json('/api/auth/status');
  api.login = (password) => json('/api/login', { method: 'POST', body: JSON.stringify({ password }) });
  api.logout = () => json('/api/logout', { method: 'POST' });

  api.listServers = () => json('/api/servers');
  api.upsertServer = (srv) => json('/api/servers', { method: 'POST', body: JSON.stringify(srv) });
  api.deleteServer = (id) => json(`/api/servers/${encodeURIComponent(id)}`, { method: 'DELETE' });
  api.activateServer = (id) => json(`/api/servers/${encodeURIComponent(id)}/activate`, { method: 'POST' });
  api.testServer = (id) => json(`/api/servers/${encodeURIComponent(id)}/test`, { method: 'POST' });
  api.getSettings = () => json('/api/settings');
  api.setSettings = (body) => json('/api/settings', { method: 'POST', body: JSON.stringify(body) });

  api.inventory = () => json('/api/inventory');
  api.metrics = () => json('/api/metrics');
  api.listPlaybooks = () => json('/api/playbooks');
  api.getPlaybook = (path) => json(`/api/playbooks/content?path=${encodeURIComponent(path)}`);
  api.savePlaybook = (path, yaml) => json('/api/playbooks/content', {
    method: 'PUT',
    body: JSON.stringify({ path, yaml })
  });

  api.listRuns = () => json('/api/runs');
  api.getRun = (id) => json(`/api/runs/${encodeURIComponent(id)}`);

  api.listVaultFiles = () => json('/api/vault');
  api.viewVault = (path, password) => json('/api/vault/view', {
    method: 'POST', body: JSON.stringify({ path, password })
  });
  api.writeVault = (path, password, content) => json('/api/vault/content', {
    method: 'POST', body: JSON.stringify({ path, password, content })
  });
  api.listInlineVaultKeys = (path) => json('/api/vault/inline/list', {
    method: 'POST', body: JSON.stringify({ path })
  });
  api.decryptInlineVault = (path, name, password) => json('/api/vault/inline/decrypt', {
    method: 'POST', body: JSON.stringify({ path, name, password })
  });
  api.upsertInlineVault = (path, name, value, password) => json('/api/vault/inline/upsert', {
    method: 'POST', body: JSON.stringify({ path, name, value, password })
  });

  api.gatherFacts = (host) => json(`/api/facts?host=${encodeURIComponent(host)}`);

  // Open a WebSocket to stream ad-hoc / playbook output. Bootstrap
  // uses the job-backed flow below — its lifecycle is decoupled from
  // any single WS attachment.
  const STREAM_PATHS = {
    adhoc: '/api/adhoc/stream',
    playbook: '/api/playbook/stream'
  };
  api.openStream = (kind, request) => {
    const wsProto = globalThis.location.protocol === 'https:' ? 'wss' : 'ws';
    const path = STREAM_PATHS[kind];
    if (!path) {
      // Refusing the open is the right move — the form payload
      // could carry secrets and a typo in `kind` would otherwise
      // have shipped them to whichever handler the fallback
      // selected.
      throw new Error(`api.openStream: unknown stream kind "${kind}"`);
    }
    const ws = new WebSocket(`${wsProto}://${globalThis.location.host}${path}`);
    const listeners = new Set();
    ws.addEventListener('open', () => ws.send(JSON.stringify(request)));
    ws.addEventListener('message', (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      listeners.forEach(fn => fn(msg));
    });
    return {
      onEvent: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },
      close: () => ws.close(),
      onClose: (fn) => ws.addEventListener('close', fn),
      onError: (fn) => ws.addEventListener('error', fn),
      readyState: () => ws.readyState
    };
  };

  // Bootstrap is backed by a server-side job manager so the run
  // outlives the operator's tab — important for the reinstall flow
  // which reboots the target and waits up to ~30 minutes for SSH
  // to come back. Lifecycle:
  //   1. startBootstrapJob(payload)    POST creates the job
  //   2. attachBootstrapJob(jobId)     WS subscribes (replay + tail)
  //   3. cancelBootstrapJob(jobId)     POST signals ctx-cancel
  // Closing the WS does NOT cancel; only the explicit cancel call
  // does. getBootstrapJob backs the on-mount re-attach probe in
  // Bootstrap.jsx.
  api.startBootstrapJob = (payload) => json('/api/bootstrap/start', {
    method: 'POST', body: JSON.stringify(payload)
  });
  api.getBootstrapJob = (id) => json(`/api/bootstrap/jobs/${encodeURIComponent(id)}`);
  api.listBootstrapJobs = () => json('/api/bootstrap/jobs');
  // REST twin of attachBootstrapJob's backlog replay — returns
  // { job, events } for a (usually finished) job so the "recent
  // runs" panel can show why a run failed without opening a WS.
  api.getBootstrapJobLog = (id) => json(`/api/bootstrap/jobs/${encodeURIComponent(id)}/log`);
  api.cancelBootstrapJob = (id) => json(`/api/bootstrap/jobs/${encodeURIComponent(id)}/cancel`, {
    method: 'POST'
  });
  api.attachBootstrapJob = (id) => {
    const wsProto = globalThis.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${wsProto}://${globalThis.location.host}/api/bootstrap/jobs/${encodeURIComponent(id)}/stream`);
    const listeners = new Set();
    ws.addEventListener('message', (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      listeners.forEach(fn => fn(msg));
    });
    return {
      onEvent: (fn) => { listeners.add(fn); return () => listeners.delete(fn); },
      close: () => ws.close(),
      onClose: (fn) => ws.addEventListener('close', fn),
      onError: (fn) => ws.addEventListener('error', fn),
      readyState: () => ws.readyState
    };
  };

  // Ansible-style event types are the same for ad-hoc and playbook
  // runs, so both views translate them into terminal log entries
  // using the same table.
  const DEFAULT_EVENT_MAPPING = {
    ok: { t: 'ok', state: 'ok' },
    changed: { t: 'changed', state: 'changed' },
    fail: { t: 'fail', state: 'failed' },
    recap: { t: 'recap' },
    'recap-warn': { t: 'recap-warn' },
    'recap-fail': { t: 'recap-fail' },
    meta: { t: 'meta' },
    line: { t: 'meta' },
    error: { t: 'fail' },
    cancelled: { t: 'meta' }
  };

  // runCommand wraps openStream with the finish-latch, event
  // classification, and done/run-complete deduplication that both
  // Adhoc and Playbooks views need. Callers only supply their own
  // onEntry / onHostState / onDone / onClose / onError and get back
  // a handle with close() for cleanup on unmount.
  api.runCommand = (kind, payload, handlers) => {
    const { onEntry, onHostState, onDone, onClose, onError } = handlers || {};
    const mapping = handlers?.mapping || DEFAULT_EVENT_MAPPING;
    const started = Date.now();
    const stream = api.openStream(kind, payload);
    let finished = false;
    const finish = (text) => {
      if (finished) return;
      finished = true;
      onEntry?.({ t: 'done', text });
      onDone?.();
      stream.close();
    };
    stream.onEvent((evt) => {
      const m = mapping[evt.type];
      if (m) {
        onEntry?.({ t: m.t, text: evt.text || '' });
        if (m.state) onHostState?.(evt.host, m.state);
        return;
      }
      if (evt.type === 'done') {
        finish(evt.text || `completed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
        return;
      }
      if (evt.type === 'run-complete') {
        finish(`completed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
      }
    });
    stream.onClose(() => onClose?.());
    stream.onError(() => onError?.());
    return { close: () => stream.close() };
  };

  // (Re)load globalThis.AnsibleData with the shape the views expect.
  // Called once at boot and any time a view wants to re-sync after
  // an action that mutated server-side state (inventory edits,
  // playbook runs, vault writes, etc).
  api.refreshData = async () => {
    const [inv, pbs, runs, settings] = await Promise.all([
      api.inventory().catch(() => ({ groups: [], hosts: [] })),
      api.listPlaybooks().catch(() => ({ playbooks: [] })),
      api.listRuns().catch(() => ({ runs: [] })),
      api.getSettings().catch(() => ({}))
    ]);
    globalThis.AnsbuiSettings = settings || {};
    const GROUPS = buildGroups(inv.groups);
    const HOSTS = annotateHosts(inv.hosts);
    const rawRuns = runs.runs || [];
    const RUNS = rawRuns.map(toRunCard);
    const PLAYBOOKS = annotatePlaybooksWithRuns(
      (pbs.playbooks || []).map(toPlaybookCard),
      rawRuns
    );
    const ACTIVITY = activityFromRuns(RUNS);
    globalThis.AnsibleData = {
      GROUPS,
      HOSTS,
      PLAYBOOKS,
      MODULES: BUILTIN_MODULES,
      SECRETS: [],
      RUNS,
      ACTIVITY
    };
    return globalThis.AnsibleData;
  };

  // refreshRuns re-syncs only the run list + activity — one cheap GET.
  // The History view uses this on mount instead of refreshData(), whose
  // /api/inventory leg runs `ansible-inventory` over SSH plus Prometheus
  // and geo lookups just to repaint a runs table the backend serves
  // from memory. Falls back to the full refresh if AnsibleData hasn't
  // been built yet (nothing else to merge into).
  api.refreshRuns = async () => {
    if (!globalThis.AnsibleData) return api.refreshData();
    const runs = await api.listRuns().catch(() => ({ runs: [] }));
    const RUNS = (runs.runs || []).map(toRunCard);
    globalThis.AnsibleData = {
      ...globalThis.AnsibleData,
      RUNS,
      ACTIVITY: activityFromRuns(RUNS)
    };
    return globalThis.AnsibleData;
  };

  // annotatePlaybooksWithRuns walks the raw run records (before
  // toRunCard's string friendlification) and picks the most recent
  // run per playbook path. Populates lastRun, lastStatus, and a
  // per-playbook run counter so the Playbooks library can show live
  // "last ran 2h ago" / status dots without a second API call.
  function annotatePlaybooksWithRuns(playbooks, rawRuns) {
    const latest = {};
    const counts = {};
    for (const r of rawRuns) {
      const key = r.playbook;
      if (!key) continue;
      counts[key] = (counts[key] || 0) + 1;
      const current = latest[key];
      const startedAt = r.startedAt || '';
      if (!current || startedAt > current.startedAt) {
        latest[key] = r;
      }
    }
    // Matched on the path alone. A run records the path it executed;
    // falling back to the file name credited staging/deploy.yml with
    // the runs (and the last status) of deploy.yml.
    return playbooks.map(p => {
      const r = latest[p.path];
      const runCount = counts[p.path] || 0;
      if (!r) return { ...p, runs: runCount };
      return {
        ...p,
        runs: runCount,
        lastRun: friendly(r.startedAt),
        lastStatus: r.status || 'ok'
      };
    });
  }

  const BUILTIN_MODULES = [
    { id: 'ping', name: 'ansible.builtin.ping', desc: 'Try to connect, verify a usable Python', args: [] },
    { id: 'command', name: 'ansible.builtin.command', desc: 'Execute a command on a remote node', args: ['cmd'] },
    { id: 'shell', name: 'ansible.builtin.shell', desc: 'Run a command through the shell', args: ['cmd'] },
    { id: 'copy', name: 'ansible.builtin.copy', desc: 'Copy files to remote locations', args: ['src', 'dest', 'mode'] },
    { id: 'file', name: 'ansible.builtin.file', desc: 'Manage files, links, and permissions', args: ['path', 'state', 'mode'] },
    { id: 'service', name: 'ansible.builtin.service', desc: 'Manage services', args: ['name', 'state'] },
    { id: 'systemd', name: 'ansible.builtin.systemd', desc: 'Manage systemd units', args: ['name', 'state', 'daemon_reload'] },
    { id: 'apt', name: 'ansible.builtin.apt', desc: 'Install / upgrade Debian packages', args: ['name', 'state'] },
    { id: 'dnf', name: 'ansible.builtin.dnf', desc: 'Install / upgrade RPM packages', args: ['name', 'state'] },
    { id: 'uri', name: 'ansible.builtin.uri', desc: 'Interact with web services', args: ['url', 'status_code'] },
    { id: 'setup', name: 'ansible.builtin.setup', desc: 'Gather facts about remote hosts', args: [] },
    { id: 'reboot', name: 'ansible.builtin.reboot', desc: 'Reboot a machine', args: ['msg'] }
  ];

  function buildGroups(groups) {
    if (!groups?.length) return [];
    return groups.map(g => ({
      id: g.id || g.name,
      name: g.name,
      parent: g.parent || null,
      vars: g.vars || {}
    }));
  }

  function annotateHosts(hosts) {
    if (!hosts) return [];
    return hosts.map(h => ({
      id: h.id || `host-${h.name}`,
      name: h.name,
      ip: h.ip || '',
      groups: h.groups || [],
      region: h.region || '',
      os: h.os || '—',
      status: h.status || 'ok',
      cpu: h.cpu || 0,
      mem: h.mem || 0,
      load: typeof h.load === 'number' ? h.load : 0,
      uptime: h.uptime || 0,
      lastPlaybook: h.lastPlaybook || '',
      lastPlaybookAt: h.lastPlaybookAt || '',
      lastRun: h.lastRun || '',
      tags: h.tags || []
    }));
  }

  // First `- name: <text>` line of the playbook. The text must start
  // with a non-blank so it cannot overlap the blanks before it; that
  // keeps the match linear by construction. A name that is nothing but
  // blanks is skipped rather than used as a (blank) title.
  // tests/web/api-playbook-title.test.js covers both points.
  const TITLE_RE = /^-[ \t]+name:[ \t]+([^ \t\n][^\n]*)$/m;
  const QUOTES_RE = /["']/g;

  function playbookTitle(p) {
    if (p.title) return p.title;
    const yaml = p.yaml || '';
    const m = TITLE_RE.exec(yaml);
    if (!m) return p.name;
    return m[1].replaceAll(QUOTES_RE, '');
  }

  function toPlaybookCard(p) {
    return {
      id: p.id,
      name: p.name,
      title: playbookTitle(p),
      description: p.description || '',
      tags: p.tags || [],
      lastRun: '',
      lastStatus: '',
      runs: 0,
      targets: p.targets || '',
      path: p.path,
      modified: p.modified || '',
      yaml: p.yaml || ''
    };
  }

  function toRunCard(r) {
    return {
      id: r.id,
      kind: r.kind || 'adhoc',
      pb: r.playbook || r.module || (r.kind === 'bootstrap' ? 'bootstrap' : ''),
      playbook: r.playbook || '',
      server: r.server || '',
      serverId: r.serverId || '',
      module: r.module || '',
      target: r.target || '',
      status: r.status || 'ok',
      when: friendly(r.startedAt),
      startedAt: r.startedAt || '',
      duration: r.duration || '',
      ok: r.ok || 0,
      changed: r.changed || 0,
      failed: r.failed || 0,
      skipped: r.skipped || 0,
      who: r.who || 'ui',
      // replay fields — only one kind's set is populated at a time
      args: r.args || {},
      become: !!r.become,
      check: !!r.check,
      forks: r.forks || 0,
      timeout: r.timeout || 0,
      limit: r.limit || '',
      tags: r.tags || [],
      extraVars: r.extraVars || {}
    };
  }

  function friendly(iso) {
    if (!iso) return '';
    const then = new Date(iso).getTime();
    const diff = (Date.now() - then) / 1000;
    if (diff < 60) return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  }

  // Bounded regex — matches the short friendly-time strings we produce
  // above (e.g. "12m ago"). No nested repetition. Safe for S5852.
  const FRIENDLY_RE = /^(\d+)([smhd])/;
  const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86400 };

  function labelToSeconds(label) {
    const match = FRIENDLY_RE.exec(label || '');
    if (!match) return null;
    const amount = Number.parseInt(match[1], 10);
    const unit = UNIT_SECONDS[match[2]] || 0;
    return amount * unit;
  }

  function activityFromRuns(runs) {
    const buckets = new Array(30).fill(0);
    for (const r of runs) {
      const seconds = labelToSeconds(r.when);
      if (seconds == null) {
        buckets[29] += 1;
        continue;
      }
      const daysAgo = Math.min(29, Math.floor(seconds / 86400));
      buckets[29 - daysAgo] += 1;
    }
    return buckets;
  }

  globalThis.AnsbuiAPI = api;
})();
