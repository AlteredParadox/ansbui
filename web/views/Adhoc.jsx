// Ad-hoc runner — command-palette style, keyboard-first
// Target picker, module picker, args, preview, Run → live streaming log

const { useState: useStateA, useEffect: useEffectA, useRef: useRefA, useMemo: useMemoA } = React;

function AdhocView({ prefill, selectedHosts }) {
  const { MODULES, HOSTS } = window.AnsibleData;
  const [target, setTarget] = useStateA(prefill?.target || 'all');
  const [moduleName, setModuleName] = useStateA(prefill?.module || 'ansible.builtin.ping');
  const [args, setArgs] = useStateA({});
  const [become, setBecome] = useStateA(false);
  const [check, setCheck] = useStateA(false);
  const [forks, setForks] = useStateA(20);
  const [running, setRunning] = useStateA(false);
  const [output, setOutput] = useStateA([]);
  const [hostStates, setHostStates] = useStateA({});
  const outRef = useRefA(null);

  useEffectA(() => {
    if (prefill?.target) setTarget(prefill.target);
    if (prefill?.module) setModuleName(prefill.module);
  }, [prefill]);

  const resolvedHosts = useMemoA(() => {
    if (prefill?.selectedHosts) return prefill.selectedHosts;
    if (target === 'all') return HOSTS;
    return HOSTS.filter(h => h.groups.includes(target.split(':')[0]));
  }, [target, HOSTS, prefill]);

  const mod = MODULES.find(m => m.name === moduleName) || MODULES[0];

  const streamRef = useRefA(null);

  const run = () => {
    if (running) return;
    if (!window.RelayAPI) return;
    setOutput([]);
    const initial = {};
    resolvedHosts.forEach(h => { initial[h.id] = 'pending'; });
    setHostStates(initial);
    setRunning(true);

    const startTime = Date.now();
    const log = [];
    const appendLog = (entry) => { log.push(entry); setOutput([...log]); };

    const payload = {
      target,
      module: mod.name,
      args,
      become,
      check,
      forks: Number(forks) || 0,
      timeout: 30
    };

    const stream = window.RelayAPI.openStream('adhoc', payload);
    streamRef.current = stream;

    const idByName = {};
    resolvedHosts.forEach(h => { idByName[h.name] = h.id; });

    const markHost = (name, state) => {
      if (!name) return;
      setHostStates(prev => ({ ...prev, [idByName[name] || name]: state }));
    };

    stream.onEvent((evt) => {
      const mapping = {
        ok: { t: 'ok', state: 'ok' },
        changed: { t: 'changed', state: 'changed' },
        fail: { t: 'fail', state: 'failed' },
        recap: { t: 'recap' },
        'recap-warn': { t: 'recap-warn' },
        'recap-fail': { t: 'recap-fail' },
        meta: { t: 'meta' },
        line: { t: 'meta' },
        error: { t: 'fail' },
        done: { t: 'done' }
      };
      const m = mapping[evt.type];
      if (m) {
        appendLog({ t: m.t, text: evt.text || '' });
        if (m.state) markHost(evt.host, m.state);
      }
      if (evt.type === 'done' || evt.type === 'run-complete') {
        appendLog({ t: 'done', text: `completed in ${((Date.now() - startTime) / 1000).toFixed(1)}s` });
        setRunning(false);
        stream.close();
        streamRef.current = null;
      }
    });
    stream.onClose(() => {
      setRunning(false);
      streamRef.current = null;
    });
    stream.onError(() => {
      appendLog({ t: 'fail', text: 'WebSocket error — check backend logs.' });
      setRunning(false);
    });
  };

  useEffectA(() => () => {
    if (streamRef.current) streamRef.current.close();
  }, []);

  useEffectA(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  const suggestedTargets = ['all', 'production', 'webservers', 'appservers', 'dbservers', 'cache', 'staging', 'edge'];

  const hostCount = resolvedHosts.length;
  const finishedCount = Object.values(hostStates).filter(s => s !== 'pending').length;

  return (
    <div className="view view-adhoc">
      <div className="view-head">
        <div>
          <h1 className="view-title">Ad-hoc command</h1>
          <div className="view-sub mute">Fire a single module at a selection of hosts. Keyboard-first.</div>
        </div>
        <div className="view-actions">
          <span className="mute mono" style={{ fontSize: 12 }}>history</span>
          <button className="btn small"><Icon name="history" size={12}/> Recent commands</button>
        </div>
      </div>

      <div className="adhoc-body">
        <div className="adhoc-composer card">
          <div className="composer-row">
            <label className="composer-label">target</label>
            <div className="composer-chip-wrap">
              <span className="chip on lg"><Icon name="inventory" size={11}/> <span className="mono">{target}</span> <span className="mute-2 mono">· {hostCount} hosts</span></span>
              <div className="composer-suggest">
                {suggestedTargets.map(t => (
                  <button key={t} className={`chip ${target === t ? 'on' : ''}`} onClick={() => setTarget(t)}>
                    <span className="mono">{t}</span>
                  </button>
                ))}
                <button className="chip"><Icon name="filter" size={10}/> selector…</button>
              </div>
            </div>
          </div>

          <div className="composer-row">
            <label className="composer-label">module</label>
            <div className="composer-chip-wrap">
              <span className="chip on lg"><Icon name="code" size={11}/> <span className="mono">{mod.name}</span></span>
              <div className="composer-suggest">
                {MODULES.slice(0, 8).map(m => (
                  <button key={m.id} className={`chip ${m.name === moduleName ? 'on' : ''}`} onClick={() => { setModuleName(m.name); setArgs({}); }}>
                    <span className="mono">{m.id}</span>
                  </button>
                ))}
                <button className="chip"><Icon name="search" size={10}/> browse…</button>
              </div>
              <div className="mute" style={{ marginTop: 6, fontSize: 12 }}>{mod.desc}</div>
            </div>
          </div>

          {mod.args.length > 0 && (
            <div className="composer-row">
              <label className="composer-label">args</label>
              <div className="composer-args">
                {mod.args.map(a => (
                  <div key={a} className="arg-row">
                    <span className="arg-key mono">{a}</span>
                    <span className="arg-eq mute-2 mono">=</span>
                    <input
                      className="input arg-val mono"
                      placeholder={placeholderFor(mod.id, a)}
                      value={args[a] || ''}
                      onChange={e => setArgs({ ...args, [a]: e.target.value })}
                    />
                  </div>
                ))}
                <button className="chip"><Icon name="plus" size={10}/> extra arg</button>
              </div>
            </div>
          )}

          <div className="composer-row">
            <label className="composer-label">options</label>
            <div className="composer-opts">
              <label className="opt"><input type="checkbox" checked={become} onChange={e => setBecome(e.target.checked)}/> <span className="mono">--become</span> <span className="mute">(sudo)</span></label>
              <label className="opt"><input type="checkbox" checked={check} onChange={e => setCheck(e.target.checked)}/> <span className="mono">--check</span> <span className="mute">(dry run)</span></label>
              <label className="opt">
                <span className="mono">--forks</span>
                <input type="number" className="input" value={forks} onChange={e => setForks(+e.target.value)} style={{ width: 60, height: 22, padding: '0 6px' }}/>
              </label>
              <label className="opt"><span className="mono">--timeout</span> <input className="input" defaultValue="30" style={{ width: 50, height: 22, padding: '0 6px' }}/></label>
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
                  {Object.keys(args).length > 0 && (
                    <>
                      {' '}<span className="yml-k mono">-a</span>{' '}
                      <span className="yml-s mono">"{Object.entries(args).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join(' ')}"</span>
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
              <button className="btn small">Save as playbook…</button>
              <button className="btn primary" onClick={run} disabled={running}>
                <Icon name="play" size={12}/> {running ? 'Running…' : 'Run'} <span className="kbd" style={{ marginLeft: 8 }}>⌘↵</span>
              </button>
            </div>
          </div>
        </div>

        <div className="adhoc-output">
          <div className="adhoc-output-head">
            <div>
              <div className="section-title">Live output</div>
              <div className="mute" style={{ fontSize: 12 }}>
                {running ? <><span className="dot run"/> streaming · {finishedCount}/{hostCount}</> :
                  output.length ? <span className="pill ok"><Icon name="check" size={10}/> finished</span> :
                  <span className="mute">waiting to run</span>}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn ghost small"><Icon name="download" size={11}/> Log</button>
              <button className="btn ghost small"><Icon name="x" size={11}/> Clear</button>
            </div>
          </div>

          <div className="adhoc-progress">
            {resolvedHosts.slice(0, 60).map(h => {
              const st = hostStates[h.id];
              const cls = st === 'ok' ? 'ok' : st === 'changed' ? 'changed' : st === 'failed' ? 'err' : 'pending';
              return <div key={h.id} className={`hstick hstick-${cls}`} title={`${h.name} — ${st || 'pending'}`}/>;
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
              <div key={i} className={`term-line term-${line.t}`}>
                {line.t === 'ok' && <span className="term-prefix">ok</span>}
                {line.t === 'changed' && <span className="term-prefix">changed</span>}
                {line.t === 'fail' && <span className="term-prefix">fail</span>}
                <span className="term-text">{line.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function placeholderFor(modId, arg) {
  const map = {
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
  return map[`${modId}:${arg}`] || arg;
}

window.AdhocView = AdhocView;
