// Run history + individual job viewer with per-task + per-host state

const { useState: useStateH, useMemo: useMemoH } = React;

function HistoryView() {
  const { RUNS, PLAYBOOKS } = window.AnsibleData;
  const [selectedId, setSelectedId] = useStateH(RUNS[0]?.id || '');
  const [filter, setFilter] = useStateH('all');

  if (!RUNS.length) {
    return (
      <div className="view view-history">
        <div className="view-head">
          <div>
            <h1 className="view-title">Run history</h1>
            <div className="view-sub mute">No runs yet. Launch an ad-hoc command or a playbook to populate this page.</div>
          </div>
        </div>
      </div>
    );
  }

  const rows = RUNS.filter(r => filter === 'all' || r.status === filter);
  const run = RUNS.find(r => r.id === selectedId) || RUNS[0];
  const pb = PLAYBOOKS.find(p => p.name === run.pb);

  // Synthesize task+host matrix for the selected run
  const tasks = useMemoH(() => {
    if (!pb || !pb.yaml) return [];
    const parsed = parseYamlTasks(pb.yaml);
    const targetPrefix = (pb.targets || 'host').split(':')[0];
    return parsed.slice(0, 8).map((t, i) => ({
      ...t,
      hosts: Array.from({ length: Math.min(12, run.ok + run.failed) }, (_, j) => {
        const fail = run.failed > 0 && i === 1 && j < 2;
        return { name: `${targetPrefix}-${String(j + 1).padStart(2, '0')}`, status: fail ? 'err' : (Math.random() < 0.2 ? 'changed' : 'ok'), duration: +(Math.random() * 2 + 0.2).toFixed(2) };
      })
    }));
  }, [run.id]);

  return (
    <div className="view view-history">
      <div className="view-head">
        <div>
          <h1 className="view-title">Run history</h1>
          <div className="view-sub mute">{RUNS.length} recent runs · live runs appear at the top</div>
        </div>
        <div className="view-actions">
          <div className="seg">
            <button className={filter === 'all' ? 'on' : ''} onClick={() => setFilter('all')}>All</button>
            <button className={filter === 'ok' ? 'on' : ''} onClick={() => setFilter('ok')}>Success</button>
            <button className={filter === 'warn' ? 'on' : ''} onClick={() => setFilter('warn')}>Warn</button>
            <button className={filter === 'err' ? 'on' : ''} onClick={() => setFilter('err')}>Failed</button>
          </div>
          <button className="btn small"><Icon name="download" size={12}/> Export</button>
        </div>
      </div>

      <div className="history-body">
        <aside className="history-list card">
          {rows.map(r => (
            <button key={r.id} className={`history-row ${selectedId === r.id ? 'active' : ''}`} onClick={() => setSelectedId(r.id)}>
              <span className={`dot ${r.status}`}/>
              <div className="history-row-main">
                <div className="history-row-top">
                  <span className="mono">{r.id}</span>
                  <span className="mute mono" style={{ fontSize: 11 }}>{r.when}</span>
                </div>
                <div className="history-row-mid mono mute">{r.pb}</div>
                <div className="history-row-bot">
                  <span className="mono" style={{ color: 'var(--ok)' }}>{r.ok} ok</span>
                  {r.changed > 0 && <span className="mono" style={{ color: 'var(--warn)' }}>· {r.changed} ch</span>}
                  {r.failed > 0 && <span className="mono" style={{ color: 'var(--err)' }}>· {r.failed} fail</span>}
                  <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>{r.duration}</span>
                </div>
              </div>
            </button>
          ))}
        </aside>

        <main className="history-detail card">
          <div className="history-detail-head">
            <div>
              <div className="section-title">Run</div>
              <h2 style={{ margin: '4px 0 2px' }}>
                <span className="mono">{run.id}</span>
                <span className="mute" style={{ fontSize: 14, fontWeight: 400, marginLeft: 10 }}>{run.pb}</span>
              </h2>
              <div className="mute" style={{ fontSize: 12.5 }}>
                triggered by <span className="mono" style={{ color: 'var(--text)' }}>{run.who}</span>
                <span className="mute-2"> · </span>
                <span className="mono">{run.when}</span>
                <span className="mute-2"> · </span>
                <span className="mono">{run.duration}</span>
              </div>
            </div>
            <div className="history-detail-actions">
              {run.status === 'err' && <button className="btn small"><Icon name="refresh" size={12}/> Retry failed</button>}
              <button className="btn small"><Icon name="code" size={12}/> View playbook</button>
              <button className="btn primary small"><Icon name="play" size={12}/> Re-run</button>
            </div>
          </div>

          <div className="run-stats">
            <div className="run-stat"><span className="section-title">ok</span><span className="mono" style={{ color: 'var(--ok)' }}>{run.ok}</span></div>
            <div className="run-stat"><span className="section-title">changed</span><span className="mono" style={{ color: 'var(--warn)' }}>{run.changed}</span></div>
            <div className="run-stat"><span className="section-title">failed</span><span className="mono" style={{ color: 'var(--err)' }}>{run.failed}</span></div>
            <div className="run-stat"><span className="section-title">skipped</span><span className="mono">{run.skipped}</span></div>
            <div className="run-stat"><span className="section-title">duration</span><span className="mono">{run.duration}</span></div>
            <div className="run-stat"><span className="section-title">status</span><span className={`pill ${run.status}`}>{run.status === 'ok' ? 'success' : run.status === 'warn' ? 'changed' : 'failed'}</span></div>
          </div>

          <div className="section-title" style={{ marginBottom: 6 }}>Task × host matrix</div>
          <div className="matrix-wrap">
            <table className="matrix">
              <thead>
                <tr>
                  <th className="matrix-task-col">Task</th>
                  {tasks[0]?.hosts.map(h => (
                    <th key={h.name} className="matrix-host-col"><span className="mono">{h.name}</span></th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tasks.map((t, i) => (
                  <tr key={i}>
                    <td className="matrix-task-cell">
                      <div className="mono mute-2" style={{ fontSize: 11 }}>{String(i + 1).padStart(2, '0')}</div>
                      <div>
                        <div className="matrix-task-name">{t.name}</div>
                        <div className="mute mono" style={{ fontSize: 11 }}>{t.module || '—'}</div>
                      </div>
                    </td>
                    {t.hosts.map((h, j) => (
                      <td key={j} className={`matrix-cell matrix-${h.status}`}>
                        <span className="mono" style={{ fontSize: 10.5 }}>{h.duration}s</span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="section-title" style={{ margin: '14px 0 6px' }}>Output</div>
          <div className="terminal" style={{ height: 260 }}>
            <div className="term-line term-meta"><span className="term-text">PLAY [{pb?.targets || 'all'}] ***************************************************</span></div>
            <div className="term-line term-meta"><span className="term-text">TASK [Gathering Facts] **********************************************</span></div>
            {tasks[0]?.hosts.map(h => (
              <div key={h.name} className={`term-line term-${h.status === 'err' ? 'fail' : h.status}`}>
                {h.status === 'err' ? <span className="term-prefix">fail</span> : <span className="term-prefix">{h.status}</span>}
                <span className="term-text">{h.status === 'err' ? `fatal: [${h.name}]: UNREACHABLE! => ssh timeout` : `${h.status}: [${h.name}]`}</span>
              </div>
            ))}
            <div className="term-line term-meta"><span className="term-text">TASK [{tasks[1]?.name || 'apply config'}] ***********</span></div>
            {tasks[1]?.hosts.slice(0, 6).map(h => (
              <div key={h.name} className={`term-line term-${h.status === 'err' ? 'fail' : h.status}`}>
                {h.status === 'err' ? <span className="term-prefix">fail</span> : <span className="term-prefix">{h.status}</span>}
                <span className="term-text">{h.status === 'err' ? `fatal: [${h.name}]: FAILED! => {"changed": false, "msg": "service unit not found"}` : `${h.status}: [${h.name}]`}</span>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  );
}

// Reuse parser from Playbooks
function parseYamlTasks(yaml) {
  const lines = yaml.split('\n');
  const blocks = [];
  let current = null;
  let section = null;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    const sec = l.match(/^(\s*)(tasks|pre_tasks|post_tasks|handlers):\s*$/);
    if (sec) { section = sec[2]; continue; }
    const task = l.match(/^(\s+)- name:\s+(.*)$/);
    if (task && section) {
      if (current) blocks.push(current);
      current = { section, name: task[2].replace(/["']/g, ''), lines: [l] };
    } else if (current) {
      if (l.match(/^(\s*)- name:/) || /^\S/.test(l)) { blocks.push(current); current = null; i--; }
      else current.lines.push(l);
    }
  }
  if (current) blocks.push(current);
  return blocks.map(b => {
    let module = '';
    for (const ln of b.lines) {
      const m = ln.match(/^\s+(ansible\.[a-z_.]+|community\.[a-z_.]+):\s*$/) || ln.match(/^\s+(ansible\.[a-z_.]+|community\.[a-z_.]+):\s+/);
      if (m) { module = m[1]; break; }
    }
    return { ...b, module };
  });
}

window.HistoryView = HistoryView;
