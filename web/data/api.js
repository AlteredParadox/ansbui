// Relay API client — populates window.AnsibleData with data fetched from
// the Go backend instead of the static mock. The existing view scripts
// continue to read from window.AnsibleData; this module just owns the
// fetches and exposes helpers for mutations and live streaming.

(function () {
  const api = {};

  const json = async (path, opts = {}) => {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
      ...opts
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

  // Open a WebSocket to stream ad-hoc / playbook output. Returns
  // { send, close, onEvent } — caller sends the request payload after
  // opening, then receives events via onEvent.
  api.openStream = (kind, request) => {
    const wsProto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const path = kind === 'adhoc' ? '/api/adhoc/stream' : '/api/playbook/stream';
    const ws = new WebSocket(`${wsProto}://${window.location.host}${path}`);
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

  // Bootstrap window.AnsibleData with the shape the views expect.
  api.bootstrap = async () => {
    const [inv, pbs, runs] = await Promise.all([
      api.inventory().catch(() => ({ groups: [], hosts: [] })),
      api.listPlaybooks().catch(() => ({ playbooks: [] })),
      api.listRuns().catch(() => ({ runs: [] }))
    ]);
    const GROUPS = buildGroups(inv.groups);
    const HOSTS = annotateHosts(inv.hosts);
    const PLAYBOOKS = pbs.playbooks.map(toPlaybookCard);
    const RUNS = runs.runs.map(toRunCard);
    const ACTIVITY = activityFromRuns(RUNS);
    window.AnsibleData = {
      GROUPS,
      HOSTS,
      PLAYBOOKS,
      MODULES: BUILTIN_MODULES,
      SECRETS: [], // secrets/vault surfaced separately in a future step
      RUNS,
      ACTIVITY
    };
    return window.AnsibleData;
  };

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
    if (!groups || !groups.length) return [];
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

  function toPlaybookCard(p) {
    const titleFromYAML = (p.yaml || '').match(/^-\s+name:\s+(.+)$/m);
    return {
      id: p.id,
      name: p.name,
      title: p.title || (titleFromYAML ? titleFromYAML[1].replace(/["']/g, '') : p.name),
      description: p.description || '',
      tags: p.tags || [],
      lastRun: '',
      lastStatus: 'ok',
      author: '',
      runs: 0,
      avgDuration: '',
      targets: p.targets || '',
      path: p.path,
      yaml: p.yaml || ''
    };
  }

  function toRunCard(r) {
    return {
      id: r.id,
      pb: r.playbook || r.module || '',
      status: r.status || 'ok',
      when: friendly(r.startedAt),
      duration: r.duration || '',
      ok: r.ok || 0,
      changed: r.changed || 0,
      failed: r.failed || 0,
      skipped: r.skipped || 0,
      who: r.who || 'ui'
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

  function activityFromRuns(runs) {
    const buckets = new Array(30).fill(0);
    const now = Date.now();
    const day = 86400000;
    runs.forEach(r => {
      const label = r.when;
      const m = /([0-9]+)(s|m|h|d)/.exec(label || '');
      if (!m) { buckets[29] += 1; return; }
      const n = +m[1];
      const unit = m[2];
      const seconds = unit === 's' ? n : unit === 'm' ? n * 60 : unit === 'h' ? n * 3600 : n * 86400;
      const daysAgo = Math.min(29, Math.floor(seconds / 86400));
      buckets[29 - daysAgo] += 1;
    });
    return buckets;
  }

  window.RelayAPI = api;
})();
