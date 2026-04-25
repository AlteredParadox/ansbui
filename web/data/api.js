// ansbui API client — populates globalThis.AnsibleData with data fetched
// from the Go backend. The existing view scripts continue to read from
// globalThis.AnsibleData; this module owns the fetches, WebSocket
// streaming, and the bootstrap translation.

(function () {
  const api = {};

  const json = async (path, opts) => {
    const options = opts || {};
    const headers = options.headers || {};
    const res = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...headers }
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || `${res.status} ${res.statusText}`);
    }
    if (res.status === 204) return null;
    return res.json();
  };

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

  // Open a WebSocket to stream ad-hoc / playbook output.
  api.openStream = (kind, request) => {
    const wsProto = globalThis.location.protocol === 'https:' ? 'wss' : 'ws';
    const path = kind === 'adhoc' ? '/api/adhoc/stream' : '/api/playbook/stream';
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
    error: { t: 'fail' }
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

  // Bootstrap globalThis.AnsibleData with the shape the views expect.
  api.bootstrap = async () => {
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

  // annotatePlaybooksWithRuns walks the raw run records (before
  // toRunCard's string friendlification) and picks the most recent
  // run per playbook path/name. Populates lastRun, lastStatus, and a
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
    return playbooks.map(p => {
      const r = latest[p.path] || latest[p.name];
      const runCount = counts[p.path] || counts[p.name] || 0;
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
      lastRun: h.lastRun || '',
      tags: h.tags || []
    }));
  }

  // Bounded regex — input is a single YAML line up to the first newline
  // because the /m anchor only lets `.+` run to end-of-line. Safe for
  // S5852 (ReDoS).
  const TITLE_RE = /^-[ \t]+name:[ \t]+([^\n]+)$/m;
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
      pb: r.playbook || r.module || '',
      playbook: r.playbook || '',
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
