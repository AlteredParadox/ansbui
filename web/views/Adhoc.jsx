// Ad-hoc runner — command-palette style, keyboard-first.
// Target picker, module picker, args, preview, Run → live streaming log.

const { useState: useStateA, useEffect: useEffectA, useRef: useRefA, useMemo: useMemoA } = React;

// buildTargetDescendants walks the inventory group tree to produce
// id → Set of that id + all transitive children, mirroring the logic
// in Inventory.jsx so that selecting a parent group (e.g. vps_servers)
// includes all hosts under its descendants.
function buildTargetDescendants(groups) {
  const childrenOf = groupChildrenIndex(groups);
  const cache = {};
  for (const g of groups) descendantSet(g.id, childrenOf, cache);
  return cache;
}

function groupChildrenIndex(groups) {
  const children = {};
  for (const g of groups) {
    const key = g.parent ?? '__root__';
    const list = children[key] || [];
    list.push(g.id);
    children[key] = list;
  }
  return children;
}

function descendantSet(id, childrenOf, cache) {
  if (cache[id]) return cache[id];
  const set = new Set([id]);
  for (const child of childrenOf[id] || []) {
    for (const d of descendantSet(child, childrenOf, cache)) set.add(d);
  }
  cache[id] = set;
  return set;
}

// suggestedTargets returns 'all' plus the inventory groups that have
// at least one host, sorted by host count descending. Empty groups and
// the synthetic 'ungrouped' bucket are elided to keep the chip row
// focused on things you'd actually want to target.
function suggestedTargets(hosts, groups, descendants) {
  const counts = {};
  for (const g of groups) {
    if (g.id === 'all' || g.id === 'ungrouped') continue;
    const set = descendants[g.id];
    if (!set) continue;
    let n = 0;
    for (const h of hosts) {
      if ((h.groups || []).some(x => set.has(x))) n += 1;
    }
    if (n > 0) counts[g.id] = n;
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([id, n]) => ({ id, count: n }));
  return [{ id: 'all', count: hosts.length }, ...sorted];
}

// splitTargetPattern splits an ansible target string on the ':' and
// ',' pattern separators, but NOT inside '[...]' host ranges — so
// `web[01:05]` stays one token instead of being torn into `web[01`
// and `05]`. Whitespace-trimmed, empties dropped.
function splitTargetPattern(pattern) {
  const toks = [];
  let cur = '';
  let depth = 0;
  for (const ch of pattern) {
    if (ch === '[') depth += 1;
    else if (ch === ']') depth = Math.max(0, depth - 1);
    if ((ch === ':' || ch === ',') && depth === 0) {
      if (cur.trim()) toks.push(cur.trim());
      cur = '';
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) toks.push(cur.trim());
  return toks;
}

// resolveTargetHosts approximates what ansible will expand `target`
// to: 'all', host names and group names (with their descendant
// groups), joined by ':' or ','. It does not model the pattern
// operators ('!' exclusion, '&' intersection, wildcards, regexes,
// ranges); a pattern using them resolves to more hosts than ansible
// would pick, or to none.
//
// Used for the composer's host count and status grid, and by History
// (as AnsbuiResolveTargetHosts) to keep "Retry failed" inside the
// hosts the original run was aimed at.
function resolveTargetHosts(target, hosts, descendants) {
  const byName = new Map(hosts.map(h => [h.name, h]));
  const out = [];
  const seen = new Set();
  const add = (h) => { if (!seen.has(h.id)) { seen.add(h.id); out.push(h); } };
  for (const tok of splitTargetPattern(target || '')) {
    if (tok === 'all') { hosts.forEach(add); continue; }
    const host = byName.get(tok);
    if (host) { add(host); continue; }
    const set = descendants[tok];
    const matches = set
      ? hosts.filter(h => (h.groups || []).some(g => set.has(g)))
      : hosts.filter(h => (h.groups || []).includes(tok));
    matches.forEach(add);
  }
  return out;
}

const STATE_TO_CLASS = { ok: 'ok', changed: 'changed', failed: 'err' };

function hstickClass(state) {
  return STATE_TO_CLASS[state] || 'pending';
}

function outputStatus(running, hasOutput, finished, total) {
  if (running) return <><span className="dot run"/> streaming · {finished}/{total}</>;
  if (hasOutput) return <span className="pill ok"><Icon name="check" size={10}/> finished</span>;
  return <span className="mute">waiting to run</span>;
}

function AdhocView({ prefill }) {
  const data = globalThis.AnsibleData || {};
  const MODULES = data.MODULES || [];
  const HOSTS = data.HOSTS || [];
  const GROUPS = data.GROUPS || [];

  const descendants = useMemoA(() => buildTargetDescendants(GROUPS), [GROUPS]);
  const targetChips = useMemoA(
    () => suggestedTargets(HOSTS, GROUPS, descendants),
    [HOSTS, GROUPS, descendants]
  );

  const [target, setTarget] = useStateA(prefill?.target || 'all');
  const [moduleName, setModuleName] = useStateA(prefill?.module || 'ansible.builtin.ping');
  const [args, setArgs] = useStateA({});
  const [become, setBecome] = useStateA(false);
  const [check, setCheck] = useStateA(false);
  const [forks, setForks] = useStateA(20);
  const [timeout, setTimeoutState] = useStateA(30);
  const [running, setRunning] = useStateA(false);
  const [output, setOutput] = useStateA([]);
  const [recentOpen, setRecentOpen] = useStateA(false);
  const [saveOpen, setSaveOpen] = useStateA(false);
  const [hostStates, setHostStates] = useStateA({});
  const outRef = useRefA(null);
  const streamRef = useRefA(null);

  useEffectA(() => {
    if (!prefill) return;
    if (prefill.target) setTarget(prefill.target);
    if (prefill.module) setModuleName(prefill.module);
    if (prefill.args) setArgs(prefill.args);
    if (typeof prefill.become === 'boolean') setBecome(prefill.become);
    if (typeof prefill.check === 'boolean') setCheck(prefill.check);
    if (prefill.forks) setForks(prefill.forks);
    if (prefill.timeout) setTimeoutState(prefill.timeout);
  }, [prefill]);

  // resolvedHosts approximates what ansible will expand `target` to,
  // for the header count and the per-host status grid (the payload
  // sends the raw `target` regardless).
  //
  // When the composer was opened from Inventory's multi-select, the
  // prefill carries the concrete host objects plus a `target` equal to
  // their joined names. We use those directly WHILE the target still
  // matches the prefill — this keeps host names that contain ':' (IPv6
  // literals) intact, since the token parser below splits on ':'. Once
  // the operator picks a different target chip, `target` diverges from
  // `prefill.target` and we fall through to parsing (which fixes the
  // old stale-selection bug where an edited target still showed the
  // original selection's count).
  //
  // The parser tokenises on ansible's ':'/',' separators but not
  // inside '[...]' host ranges (web[01:05]); group tokens expand via
  // descendants. Negation/intersection ('!', '&') aren't modelled, so
  // a pattern using them can over-count — the safe direction for a
  // blast-radius warning.
  const resolvedHosts = useMemoA(() => {
    if (prefill?.selectedHosts && target === prefill.target) {
      return prefill.selectedHosts;
    }
    return resolveTargetHosts(target, HOSTS, descendants);
  }, [target, HOSTS, descendants, prefill]);

  const mod = MODULES.find(m => m.name === moduleName)
    || { id: moduleName.split('.').pop() || 'custom', name: moduleName, desc: '', args: [] };

  const run = () => {
    if (running || !globalThis.AnsbuiAPI) return;
    setOutput([]);
    const initial = {};
    resolvedHosts.forEach(h => { initial[h.id] = 'pending'; });
    setHostStates(initial);
    setRunning(true);

    const log = [];
    const appendLog = (entry) => { log.push(entry); setOutput([...log]); };

    const payload = {
      target,
      module: mod.name,
      args,
      become,
      check,
      forks: Number(forks) || 0,
      timeout: Number(timeout) || 0
    };

    const idByName = {};
    resolvedHosts.forEach(h => { idByName[h.name] = h.id; });
    const markHost = (name, state) => {
      if (!name) return;
      setHostStates(prev => ({ ...prev, [idByName[name] || name]: state }));
    };

    streamRef.current = globalThis.AnsbuiAPI.runCommand('adhoc', payload, {
      onEntry: appendLog,
      onHostState: markHost,
      onDone: () => setRunning(false),
      onClose: () => { setRunning(false); streamRef.current = null; },
      onError: () => {
        appendLog({ t: 'fail', text: 'WebSocket error — check backend logs.' });
        setRunning(false);
      }
    });
  };

  const cancelRun = () => {
    if (streamRef.current) {
      streamRef.current.close();
      streamRef.current = null;
    }
    setRunning(false);
  };

  useEffectA(() => () => {
    if (streamRef.current) streamRef.current.close();
  }, []);

  // Closing the WebSocket kills the remote ansible process, so warn
  // before navigation / tab close can do it silently mid-run.
  globalThis.useRunGuard(running, 'An ad-hoc run');

  useEffectA(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  const hostCount = resolvedHosts.length;
  const finishedCount = Object.values(hostStates).filter(s => s !== 'pending').length;
  const previewArgs = Object.entries(args).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' ');

  return (
    <div className="view view-adhoc">
      <div className="view-head">
        <div>
          <h1 className="view-title">Ad-hoc command</h1>
          <div className="view-sub mute">Fire a single module at a selection of hosts. Keyboard-first.</div>
        </div>
        <div className="view-actions">
          <button type="button" className="btn small" onClick={() => setRecentOpen(true)}>
            <Icon name="history" size={12}/> Recent
          </button>
        </div>
      </div>

      <div className="adhoc-body">
        <div className="adhoc-composer card">
          <div className="composer-row">
            <span className="composer-label">target</span>
            <div className="composer-chip-wrap">
              <span className="chip on lg"><Icon name="inventory" size={11}/> <span className="mono">{target}</span> <span className="mute-2 mono">· {hostCount} hosts</span></span>
              <div className="composer-suggest">
                {targetChips.length === 0 && (
                  <span className="mute" style={{ fontSize: 12 }}>No groups in inventory yet.</span>
                )}
                {targetChips.map(t => (
                  <button type="button" key={t.id} className={`chip ${target === t.id ? 'on' : ''}`} onClick={() => setTarget(t.id)}>
                    <span className="mono">{t.id}</span>
                    <span className="mute-2 mono" style={{ marginLeft: 4 }}>{t.count}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="composer-row">
            <span className="composer-label">module</span>
            <div className="composer-chip-wrap">
              <span className="chip on lg"><Icon name="code" size={11}/> <span className="mono">{mod.name}</span></span>
              <div className="composer-suggest">
                {MODULES.slice(0, 8).map(m => (
                  <button type="button" key={m.id} className={`chip ${m.name === moduleName ? 'on' : ''}`} onClick={() => { setModuleName(m.name); setArgs({}); }}>
                    <span className="mono">{m.id}</span>
                  </button>
                ))}
              </div>
              <input
                className="input mono"
                aria-label="Module name (any ansible module, e.g. community.general.haproxy)"
                placeholder="Or type any module name — e.g. community.general.haproxy"
                value={moduleName}
                onChange={(e) => { setModuleName(e.target.value); setArgs({}); }}
                style={{ marginTop: 6 }}
              />
              <div className="mute" style={{ marginTop: 6, fontSize: 12 }}>{mod.desc || 'Custom module — args are free-form.'}</div>
            </div>
          </div>

          {mod.args.length > 0 && (
            <div className="composer-row">
              <span className="composer-label">args</span>
              <div className="composer-args">
                {mod.args.map(a => {
                  const id = `adhoc-arg-${a}`;
                  return (
                    <div key={a} className="arg-row">
                      <label htmlFor={id} className="arg-key mono">{a}</label>
                      <span className="arg-eq mute-2 mono">=</span>
                      <input
                        id={id}
                        className="input arg-val mono"
                        placeholder={placeholderFor(mod.id, a)}
                        value={args[a] || ''}
                        onChange={e => setArgs({ ...args, [a]: e.target.value })}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="composer-row">
            <span className="composer-label">options</span>
            <div className="composer-opts">
              <label className="opt" htmlFor="adhoc-become">
                <input id="adhoc-become" type="checkbox" checked={become} onChange={e => setBecome(e.target.checked)}/>
                <span className="mono">--become</span> <span className="mute">(sudo)</span>
              </label>
              <label className="opt" htmlFor="adhoc-check">
                <input id="adhoc-check" type="checkbox" checked={check} onChange={e => setCheck(e.target.checked)}/>
                <span className="mono">--check</span> <span className="mute">(dry run)</span>
              </label>
              <label className="opt" htmlFor="adhoc-forks">
                <span className="mono">--forks</span>
                <input id="adhoc-forks" type="number" className="input" value={forks} onChange={e => setForks(+e.target.value)} style={{ width: 60, height: 22, padding: '0 6px' }}/>
              </label>
              <label className="opt" htmlFor="adhoc-timeout">
                <span className="mono">--timeout</span>
                <input id="adhoc-timeout" type="number" className="input" value={timeout} onChange={e => setTimeoutState(+e.target.value)} style={{ width: 60, height: 22, padding: '0 6px' }}/>
              </label>
            </div>
          </div>

          <div className="composer-preview">
            <div className="section-title">Preview</div>
            <div className="code-pane small">
              <pre className="code-block">
                <code>
                  <span className="yml-c">$</span>{' '}
                  <span className="mono">ansible</span>{' '}
                  <span className="yml-s mono">{target}</span>{' '}
                  <span className="yml-k mono">-m</span>{' '}
                  <span className="yml-s mono">{mod.name}</span>
                  {previewArgs && (
                    <>
                      {' '}<span className="yml-k mono">-a</span>{' '}
                      <span className="yml-s mono">"{previewArgs}"</span>
                    </>
                  )}
                  {become && <> <span className="yml-k mono">--become</span></>}
                  {check && <> <span className="yml-k mono">--check</span></>}
                  {' '}<span className="yml-k mono">--forks</span> <span className="yml-n mono">{forks}</span>
                </code>
              </pre>
            </div>
          </div>

          <div className="composer-run">
            <div className="mute" style={{ fontSize: 12 }}>
              Will run on <b style={{ color: 'var(--text)' }}>{hostCount}</b> hosts
              {check && <span className="pill warn" style={{ marginLeft: 8 }}>dry run</span>}
              {become && <span className="pill info" style={{ marginLeft: 6 }}>sudo</span>}
            </div>
            <div className="composer-run-actions">
              <button type="button" className="btn small" onClick={() => setSaveOpen(true)}>
                <Icon name="download" size={12}/> Save as playbook…
              </button>
              {running ? (
                <button type="button" className="btn" onClick={cancelRun}>
                  <Icon name="x" size={12}/> Cancel
                </button>
              ) : (
                <button type="button" className="btn primary" onClick={run}>
                  <Icon name="play" size={12}/> Run
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="adhoc-output">
          <div className="adhoc-output-head">
            <div>
              <div className="section-title">Live output</div>
              <div className="mute" style={{ fontSize: 12 }}>
                {outputStatus(running, output.length > 0, finishedCount, hostCount)}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button type="button" className="btn ghost small" onClick={() => downloadLog(output, mod.name)} disabled={output.length === 0}>
                <Icon name="download" size={11}/> Log
              </button>
              <button type="button" className="btn ghost small" onClick={() => setOutput([])} disabled={running || output.length === 0}>
                <Icon name="x" size={11}/> Clear
              </button>
            </div>
          </div>

          <div className="adhoc-progress">
            {resolvedHosts.slice(0, 60).map(h => {
              const state = hostStates[h.id];
              return <div key={h.id} className={`hstick hstick-${hstickClass(state)}`} title={`${h.name} — ${state || 'pending'}`}/>;
            })}
            {resolvedHosts.length > 60 && <div className="mute mono" style={{ fontSize: 11, marginLeft: 6 }}>+{resolvedHosts.length - 60}</div>}
          </div>

          <div className="terminal" ref={outRef}>
            {output.length === 0 && (
              <div className="terminal-empty mute-2 mono">
                <div># press <span className="kbd">⌘</span><span className="kbd">↵</span> to run</div>
                <div># output will stream here, per host</div>
              </div>
            )}
            {output.map((line, i) => (
              <div key={`${i}-${line.t}`} className={`term-line term-${line.t}`}>
                {line.t === 'ok' && <span className="term-prefix">ok</span>}
                {line.t === 'changed' && <span className="term-prefix">changed</span>}
                {line.t === 'fail' && <span className="term-prefix">fail</span>}
                <span className="term-text">{line.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <AdhocRecentDialog
        open={recentOpen}
        onClose={() => setRecentOpen(false)}
        onPick={(run) => {
          setTarget(run.target || 'all');
          setModuleName(run.module || 'ansible.builtin.ping');
          setArgs(run.args || {});
          setBecome(!!run.become);
          setCheck(!!run.check);
          if (run.forks) setForks(run.forks);
          if (run.timeout) setTimeoutState(run.timeout);
          setRecentOpen(false);
        }}
      />
      <AdhocSavePlaybookDialog
        open={saveOpen}
        composition={{ target, module: mod.name, args, become }}
        onClose={() => setSaveOpen(false)}
      />
    </div>
  );
}

const PLACEHOLDER_MAP = {
  'command:cmd': 'uptime',
  'shell:cmd': 'systemctl status nginx',
  'copy:src': '/etc/nginx.conf',
  'copy:dest': '/etc/nginx/nginx.conf',
  'copy:mode': '0644',
  'file:path': '/var/lib/app',
  'file:state': 'directory',
  'service:name': 'nginx',
  'service:state': 'restarted',
  'systemd:name': 'app.service',
  'systemd:state': 'restarted',
  'systemd:daemon_reload': 'true',
  'apt:name': 'nginx',
  'apt:state': 'present',
  'dnf:name': 'httpd',
  'dnf:state': 'latest',
  'uri:url': 'https://api.example.com/health',
  'uri:status_code': '200',
  'reboot:msg': 'scheduled reboot'
};

function placeholderFor(modId, arg) {
  return PLACEHOLDER_MAP[`${modId}:${arg}`] || arg;
}

// downloadLog serialises the terminal buffer to a plain-text file and
// triggers a browser download. We don't attempt ANSI colour fidelity —
// operators usually paste log text into tickets or grep, and plain
// text is what they want.
function downloadLog(lines, moduleName) {
  const body = lines.map(l => (l.text || '')).join('\n');
  const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const stamp = new Date().toISOString().replaceAll(':', '-').replace(/\..*/, '');
  a.download = `adhoc-${moduleName.replaceAll(/[^A-Za-z0-9]+/g, '_')}-${stamp}.log`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------- Recent-commands dialog ----------

function AdhocRecentDialog({ open, onClose, onPick }) {
  const data = globalThis.AnsibleData || {};
  const runs = (data.RUNS || []).filter(r => r.kind === 'adhoc');
  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Recent ad-hoc commands"
      subtitle="Click any row to load its target, module, and arguments back into the composer."
      width="min(720px, 94vw)"
      maxHeight="70vh"
    >
      {runs.length === 0 && (
        <div className="mute" style={{ fontSize: 12 }}>
          No ad-hoc runs yet. Fire one from this view and it'll show up here.
        </div>
      )}
      {runs.length > 0 && (
        <div className="adhoc-recent-list">
          {runs.slice(0, 40).map(r => (
            <button type="button" key={r.id} className="adhoc-recent-row" onClick={() => onPick(r)}>
              <span className={`dot rs-${r.status}`}/>
              <div className="adhoc-recent-main">
                <div className="mono" style={{ fontSize: 12.5, fontWeight: 550 }}>
                  {r.module || '—'} <span className="mute mono" style={{ fontWeight: 400 }}>on {r.target || '—'}</span>
                </div>
                <div className="mute mono" style={{ fontSize: 11 }}>
                  {previewArgsFor(r.args)} {r.become && '· --become'} {r.check && '· --check'}
                </div>
              </div>
              <div className="mute mono" style={{ fontSize: 11, textAlign: 'right' }}>
                <div>{r.when}</div>
                <div>{r.duration}</div>
              </div>
            </button>
          ))}
        </div>
      )}
    </globalThis.AnsbuiCenterDialog>
  );
}

function previewArgsFor(args) {
  if (!args) return '';
  const entries = Object.entries(args).filter(([, v]) => v !== '' && v != null);
  if (!entries.length) return '(no args)';
  return entries.map(([k, v]) => `${k}=${v}`).join(' ');
}

// ---------- Save-as-playbook dialog ----------
//
// Generates a minimal single-play YAML from the current composer
// state and writes it to the remote workDir via /api/playbooks/content.
// The YAML shape is deliberately conservative — no jinja, no loops —
// so the operator can edit it further in the Playbooks view.

function AdhocSavePlaybookDialog({ open, composition, onClose }) {
  const [filename, setFilename] = useStateA('');
  const [busy, setBusy] = useStateA(false);
  const [error, setError] = useStateA('');
  const [done, setDone] = useStateA(false);

  useEffectA(() => {
    if (!open) { setFilename(''); setError(''); setDone(false); return; }
    setFilename(suggestFilename(composition.module));
  }, [open, composition.module]);

  const yaml = useMemoA(() => renderAdhocAsPlaybook(composition), [composition]);

  const submit = async () => {
    setError('');
    const path = (filename || '').trim();
    if (!path) { setError('Filename is required.'); return; }
    if (!globalThis.AnsbuiAPI) return;
    setBusy(true);
    try {
      await globalThis.AnsbuiAPI.savePlaybook(path, yaml);
      await globalThis.AnsbuiAPI.refreshData();
      setDone(true);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Save as playbook"
      subtitle="The current composer state is rendered as a minimal single-play YAML file under the server's workDir."
    >
      {error && <div className="cm-error mono">{error}</div>}
      {done ? (
        <div className="cm-test ok mono">✓ Saved to <b>{filename}</b>. Playbook library updated.</div>
      ) : (
        <>
          <label htmlFor="adhoc-save-name" className="cm-field-label">Target filename (relative to workDir)</label>
          <input
            id="adhoc-save-name"
            className="input mono"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            placeholder="e.g. plays/ping-all.yml"
          />
          <div className="cm-field-label" style={{ marginTop: 10 }}>Preview</div>
          <pre className="code-block" style={{
            background: 'var(--bg-inset)',
            border: '1px solid var(--line-soft)',
            borderRadius: 'var(--r-2)',
            maxHeight: 300,
            overflow: 'auto'
          }}>{yaml}</pre>
        </>
      )}
      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        {done ? (
          <button type="button" className="btn primary small" onClick={onClose}>Close</button>
        ) : (
          <>
            <button type="button" className="btn primary small" disabled={busy} onClick={submit}>
              <Icon name="check" size={12}/> {busy ? 'Saving…' : 'Save'}
            </button>
            <button type="button" className="btn small" disabled={busy} onClick={onClose}>Cancel</button>
          </>
        )}
      </div>
    </globalThis.AnsbuiCenterDialog>
  );
}

function suggestFilename(moduleName) {
  const bare = (moduleName || 'adhoc').split('.').pop() || 'adhoc';
  const safe = bare.replaceAll(/[^A-Za-z0-9_-]+/g, '_');
  return `plays/${safe}.yml`;
}

// renderAdhocAsPlaybook writes the composer's state as a one-task
// playbook. EVERY value that is not a fixed word of the template goes
// through yamlScalar — the target, the module name, the argument
// names and the two descriptive names, as well as the argument values.
//
// Only the values used to be quoted. The target can arrive from
// History's "Retry failed", which takes host names out of run output,
// and run output includes whatever a managed host printed: a "host
// name" with a line break in it (CR and U+2028 are line breaks to a
// YAML parser) added `pre_tasks:` and `become: true` to the saved
// play. The module and argument names are typed by the operator, but
// a file that is saved and later run should not depend on that either.
function renderAdhocAsPlaybook({ target, module, args, become }) {
  const argEntries = Object.entries(args || {}).filter(([, v]) => v !== '' && v != null);
  const hosts = target || 'all';
  const lines = [
    '---',
    `- name: ${yamlScalar(`${module} on ${hosts}`)}`,
    `  hosts: ${yamlScalar(hosts)}`,
    '  gather_facts: false',
    ...(become ? ['  become: true'] : []),
    '  tasks:',
    `    - name: ${yamlScalar(`run ${module}`)}`,
    `      ${yamlScalar(module)}:`,
    ...argEntries.map(([k, v]) => `        ${yamlScalar(k)}: ${yamlScalar(v)}`)
  ];
  return lines.join('\n') + '\n';
}

// yamlScalar quotes a value for safe inclusion in the generated
// playbook. The escape pattern for an embedded double-quote is
// literally `\"` (backslash + quote). NOT String.raw`\"` (what Sonar
// S7780 suggests): every .jsx file is transpiled as a separate
// <script type="text/babel"> sharing one global scope, and Babel caches
// each String.raw tag in a colliding module-level `_templateObject` var
// — this tag once poisoned Bootstrap.jsx's ADDR_OCTET regex. Building
// the backslash from its code point avoids the tagged template and
// leaves no escaped-backslash string literal for S7780 to flag.
const YAML_BACKSLASH = String.fromCodePoint(92);
const YAML_QUOTE_ESCAPE = YAML_BACKSLASH + '"';

// YAML_PLAIN is what may be written without quotes: a word of letters,
// digits and '_' that may contain '.', '/', '@' and '-' inside it.
// Anything else is quoted. That includes every character with a
// meaning in YAML: ':' (a value ending in one, or "a: b", starts a
// mapping), '#', a leading '-', '@', '*', '&', '!' or '%', brackets,
// braces, commas and quotes.
const YAML_PLAIN = /^[A-Za-z0-9_]([\w./@-]*[A-Za-z0-9_])?$/;

// yamlNeedsEscape reports whether a code point must be written as a
// \u escape inside a double-quoted scalar: the C0 and C1 controls,
// DEL, and the characters a YAML parser treats as a line break or
// strips — U+0085, U+2028, U+2029 and the byte-order mark.
function yamlNeedsEscape(code) {
  return code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029 || code === 0xfeff;
}

function yamlScalar(v) {
  if (v == null) return '""';
  const s = String(v);
  if (/^(true|false|null|yes|no|on|off|~|\d+(\.\d+)?)$/i.test(s)) return `"${s}"`;
  if (YAML_PLAIN.test(s)) return s;
  // Build a YAML double-quoted scalar, escaping everything that would
  // otherwise corrupt the saved, executable playbook: backslash (the
  // escape char) and quote must be escaped, and a literal line break
  // or control char would end or fold the scalar (a trailing backslash
  // escapes the closing quote and swallows the next line). Only the
  // escapes JSON also has are used, so the result reads the same to a
  // YAML 1.1 parser, a YAML 1.2 parser and JSON.parse. Scanning code
  // points instead of using a control-char regex keeps eslint's
  // no-control-regex happy and handles astral chars (emoji) correctly.
  let out = '';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (ch === YAML_BACKSLASH) out += YAML_BACKSLASH + YAML_BACKSLASH;
    else if (ch === '"') out += YAML_QUOTE_ESCAPE;
    else if (ch === '\n') out += YAML_BACKSLASH + 'n';
    else if (ch === '\r') out += YAML_BACKSLASH + 'r';
    else if (ch === '\t') out += YAML_BACKSLASH + 't';
    else if (yamlNeedsEscape(code)) out += YAML_BACKSLASH + 'u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  return `"${out}"`;
}

globalThis.AdhocView = AdhocView;
// Shared with History, which uses the same expansion to keep a retry
// inside the hosts the recorded run was aimed at.
globalThis.AnsbuiResolveTargetHosts = (target, hosts, groups) =>
  resolveTargetHosts(target, hosts || [], buildTargetDescendants(groups || []));
