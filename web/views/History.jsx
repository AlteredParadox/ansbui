// Run history + individual job viewer.
//
// The upstream design synthesised a per-task / per-host matrix with
// Math.random() to make the prototype look busy. Now that we have real
// RunRecords from the backend, we show the actual streamed log instead
// — no synthetic data, no weak-PRNG hotspot.

const { useState: useStateH, useEffect: useEffectH } = React;

const STATUS_LABELS = { ok: 'success', warn: 'changed', err: 'failed' };

function runStatusLabel(status) {
  return STATUS_LABELS[status] || status;
}

function filterRuns(runs, filter) {
  if (filter === 'all') return runs;
  return runs.filter(r => r.status === filter);
}

function HistoryView({ onOpenPlaybook, onRunPlaybook, onOpenAdhoc }) {
  const data = globalThis.AnsibleData || {};
  const RUNS = data.RUNS || [];
  const PLAYBOOKS = data.PLAYBOOKS || [];
  const [selectedId, setSelectedId] = useStateH(RUNS[0]?.id || '');
  const [filter, setFilter] = useStateH('all');
  const [detail, setDetail] = useStateH(null);
  const [error, setError] = useStateH('');

  useEffectH(() => {
    if (!selectedId || !globalThis.AnsbuiAPI) { setDetail(null); return; }
    let alive = true;
    setError('');
    globalThis.AnsbuiAPI.getRun(selectedId)
      .then(d => { if (alive) setDetail(d); })
      .catch(e => { if (alive) { setDetail(null); setError(e.message); } });
    return () => { alive = false; };
  }, [selectedId]);

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

  const rows = filterRuns(RUNS, filter);
  const run = RUNS.find(r => r.id === selectedId) || RUNS[0];

  return (
    <div className="view view-history">
      <div className="view-head">
        <div>
          <h1 className="view-title">Run history</h1>
          <div className="view-sub mute">{RUNS.length} recent runs · live runs appear at the top</div>
        </div>
        <div className="view-actions">
          <div className="seg">
            <button type="button" className={filter === 'all' ? 'on' : ''} onClick={() => setFilter('all')}>All</button>
            <button type="button" className={filter === 'ok' ? 'on' : ''} onClick={() => setFilter('ok')}>Success</button>
            <button type="button" className={filter === 'warn' ? 'on' : ''} onClick={() => setFilter('warn')}>Warn</button>
            <button type="button" className={filter === 'err' ? 'on' : ''} onClick={() => setFilter('err')}>Failed</button>
          </div>
          <button type="button" className="btn small" onClick={() => exportRuns(RUNS)} disabled={RUNS.length === 0}>
            <Icon name="download" size={12}/> Export
          </button>
        </div>
      </div>

      <div className="history-body">
        <aside className="history-list card">
          {rows.map(r => (
            <button type="button" key={r.id} className={`history-row ${selectedId === r.id ? 'active' : ''}`} onClick={() => setSelectedId(r.id)}>
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
              {detail?.kind === 'playbook' && (
                <>
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => {
                      const pb = findPlaybookFor(PLAYBOOKS, detail);
                      if (pb) onOpenPlaybook?.(pb.id);
                    }}
                    disabled={!findPlaybookFor(PLAYBOOKS, detail)}
                    title={findPlaybookFor(PLAYBOOKS, detail) ? 'Open in Playbooks' : 'Playbook no longer in library'}
                  >
                    <Icon name="code" size={12}/> View playbook
                  </button>
                  {detail.status === 'err' && (
                    <button
                      type="button"
                      className="btn small"
                      onClick={() => onRunPlaybook?.(buildRetryPrefill(detail))}
                      disabled={failedHostsFromLog(detail.log).length === 0}
                      title="Re-run against only the hosts that failed last time"
                    >
                      <Icon name="refresh" size={12}/> Retry failed
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn primary small"
                    onClick={() => onRunPlaybook?.(buildRerunPrefill(detail))}
                  >
                    <Icon name="play" size={12}/> Re-run
                  </button>
                </>
              )}
              {detail?.kind === 'adhoc' && (
                <>
                  {detail.status === 'err' && (
                    <button
                      type="button"
                      className="btn small"
                      onClick={() => onOpenAdhoc?.(buildAdhocRetryPrefill(detail))}
                      disabled={failedHostsFromLog(detail.log).length === 0}
                      title="Re-run against only the hosts that failed last time"
                    >
                      <Icon name="refresh" size={12}/> Retry failed
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn primary small"
                    onClick={() => onOpenAdhoc?.(buildAdhocRerunPrefill(detail))}
                  >
                    <Icon name="play" size={12}/> Re-run
                  </button>
                </>
              )}
              {detail && (
                <button type="button" className="btn small" onClick={() => exportOneRun(detail)}>
                  <Icon name="download" size={12}/> Download log
                </button>
              )}
            </div>
          </div>

          <div className="run-stats">
            <div className="run-stat"><span className="section-title">ok</span><span className="mono" style={{ color: 'var(--ok)' }}>{run.ok}</span></div>
            <div className="run-stat"><span className="section-title">changed</span><span className="mono" style={{ color: 'var(--warn)' }}>{run.changed}</span></div>
            <div className="run-stat"><span className="section-title">failed</span><span className="mono" style={{ color: 'var(--err)' }}>{run.failed}</span></div>
            <div className="run-stat"><span className="section-title">skipped</span><span className="mono">{run.skipped}</span></div>
            <div className="run-stat"><span className="section-title">duration</span><span className="mono">{run.duration}</span></div>
            <div className="run-stat"><span className="section-title">status</span><span className={`pill ${run.status}`}>{runStatusLabel(run.status)}</span></div>
          </div>

          <div className="section-title" style={{ margin: '14px 0 6px' }}>Output</div>
          {error && <div className="cm-error mono">{error}</div>}
          <div className="terminal" style={{ height: 360 }}>
            {!detail && !error && <div className="terminal-empty mute-2 mono"># loading log…</div>}
            {detail && (!detail.log || detail.log.length === 0) && (
              <div className="terminal-empty mute-2 mono"># no log captured for this run</div>
            )}
            {detail?.log?.map((evt, i) => (
              <div key={`${i}-${evt.type}`} className={`term-line term-${evt.type}`}>
                {evt.type === 'ok' && <span className="term-prefix">ok</span>}
                {evt.type === 'changed' && <span className="term-prefix">changed</span>}
                {evt.type === 'fail' && <span className="term-prefix">fail</span>}
                <span className="term-text">{evt.text || ''}</span>
              </div>
            ))}
          </div>
        </main>
      </div>
    </div>
  );
}

function exportRuns(runs) {
  const blob = new Blob([JSON.stringify(runs, null, 2)], { type: 'application/json;charset=utf-8' });
  triggerDownload(blob, `relay-runs-${timeStamp()}.json`);
}

function exportOneRun(run) {
  const body = (run.log || []).map(l => l.text || '').join('\n');
  const blob = new Blob([body || '(no log captured)'], { type: 'text/plain;charset=utf-8' });
  triggerDownload(blob, `${run.id || 'run'}-${timeStamp()}.log`);
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function timeStamp() {
  return new Date().toISOString().replaceAll(':', '-').replace(/\..*/, '');
}

// findPlaybookFor resolves a run's playbook (stored as the relative
// path the runner used) back to an entry in the library. Falls back
// to matching by basename so a moved file still resolves if the new
// location keeps the same filename.
function findPlaybookFor(playbooks, run) {
  if (!run?.playbook) return null;
  const direct = playbooks.find(p => p.path === run.playbook);
  if (direct) return direct;
  const base = run.playbook.split('/').pop();
  return playbooks.find(p => (p.path || '').split('/').pop() === base || p.name === base) || null;
}

// failedHostsFromLog scans a run's event log for "fail" or
// recap-fail entries that carry a host name. Dedupes and returns
// hostnames in the order they appeared.
function failedHostsFromLog(log) {
  if (!Array.isArray(log)) return [];
  const seen = new Set();
  const out = [];
  for (const evt of log) {
    if ((evt.type === 'fail' || evt.type === 'recap-fail') && evt.host) {
      if (seen.has(evt.host)) continue;
      seen.add(evt.host);
      out.push(evt.host);
    }
  }
  return out;
}

function buildRerunPrefill(run) {
  return {
    playbookPath: run.playbook,
    limit: run.limit || '',
    tags: run.tags || [],
    extraVars: run.extraVars || {},
    check: !!run.check,
    become: !!run.become
  };
}

function buildRetryPrefill(run) {
  const hosts = failedHostsFromLog(run.log);
  return {
    playbookPath: run.playbook,
    limit: hosts.join(','),
    tags: run.tags || [],
    extraVars: run.extraVars || {},
    check: !!run.check,
    become: !!run.become
  };
}

// buildAdhocRerunPrefill / buildAdhocRetryPrefill produce the prefill
// object AdhocView accepts via openAdhoc(). Retry uses the failed-
// host list from the log as the explicit target; the regular re-run
// keeps whatever target/selection the run was originally launched at.
function buildAdhocRerunPrefill(run) {
  return {
    target: run.target || 'all',
    module: run.module || 'ansible.builtin.ping',
    args: run.args || {},
    become: !!run.become,
    check: !!run.check,
    forks: run.forks || 0,
    timeout: run.timeout || 0
  };
}

function buildAdhocRetryPrefill(run) {
  const hosts = failedHostsFromLog(run.log);
  return {
    ...buildAdhocRerunPrefill(run),
    target: hosts.length ? hosts.join(',') : run.target || 'all'
  };
}

globalThis.HistoryView = HistoryView;
