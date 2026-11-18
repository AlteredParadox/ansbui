// Run history + individual job viewer.
//
// The upstream design synthesised a per-task / per-host matrix with
// Math.random() to make the prototype look busy. Now that we have real
// RunRecords from the backend, we show the actual streamed log instead
// — no synthetic data, no weak-PRNG hotspot.

const { useState: useStateH, useEffect: useEffectH } = React;

const STATUS_LABELS = { ok: 'success', warn: 'changed', err: 'failed', cancelled: 'cancelled' };

function runStatusLabel(status) {
  return STATUS_LABELS[status] || status;
}

function filterRuns(runs, filter) {
  if (filter === 'all') return runs;
  return runs.filter(r => r.status === filter);
}

function HistoryView({ onOpenPlaybook, onRunPlaybook, onOpenAdhoc, activeServer }) {
  const data = globalThis.AnsibleData || {};
  const RUNS = data.RUNS || [];
  const PLAYBOOKS = data.PLAYBOOKS || [];
  // The active connection's inventory: what "Retry failed" checks the
  // recorded host names against.
  const INVENTORY = { hosts: data.HOSTS || [], groups: data.GROUPS || [] };
  const [selectedId, setSelectedId] = useStateH(RUNS[0]?.id || '');
  const [filter, setFilter] = useStateH('all');
  const [detail, setDetail] = useStateH(null);
  const [error, setError] = useStateH('');
  // AnsibleData is a snapshot from boot (or the last explicit
  // refresh), so runs executed since — already persisted by the
  // backend — wouldn't show up here until a full page reload.
  // Re-sync just the runs on mount (a single cheap GET, not the full
  // SSH+Prom+geo fan-out); the state bump re-renders with the fresh
  // globals.
  const [, setRunsVersion] = useStateH(0);
  useEffectH(() => {
    let alive = true;
    globalThis.AnsbuiAPI?.refreshRuns()
      .then(() => { if (alive) setRunsVersion(v => v + 1); })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

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
          <div className="view-sub mute">{RUNS.length} recent runs · newest first</div>
        </div>
        <div className="view-actions">
          <div className="seg">
            <button type="button" className={filter === 'all' ? 'on' : ''} onClick={() => setFilter('all')}>All</button>
            <button type="button" className={filter === 'ok' ? 'on' : ''} onClick={() => setFilter('ok')}>Success</button>
            <button type="button" className={filter === 'warn' ? 'on' : ''} onClick={() => setFilter('warn')}>Changed</button>
            <button type="button" className={filter === 'err' ? 'on' : ''} onClick={() => setFilter('err')}>Failed</button>
            <button type="button" className={filter === 'cancelled' ? 'on' : ''} onClick={() => setFilter('cancelled')}>Cancelled</button>
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
              <span className={`dot rs-${r.status}`}/>
              <div className="history-row-main">
                <div className="history-row-top">
                  <span className="mono">{r.id}</span>
                  <span className="mute mono" style={{ fontSize: 11 }}>{r.when}</span>
                </div>
                <div className="history-row-mid mono mute">{r.pb}</div>
                <div className="history-row-bot">
                  <span className="mono" style={{ color: 'var(--ok)' }}>{r.ok} ok</span>
                  {r.changed > 0 && <span className="mono" style={{ color: 'var(--ok)' }}>· {r.changed} ch</span>}
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
                    title={findPlaybookFor(PLAYBOOKS, detail) ? 'Open in Playbooks' : `${detail.playbook} is not in this connection's library`}
                  >
                    <Icon name="code" size={12}/> View playbook
                  </button>
                  {detail.status === 'err' && (
                    <button
                      type="button"
                      className="btn small"
                      onClick={() => onRunPlaybook?.(buildRetryPrefill(detail, INVENTORY))}
                      disabled={!!retryBlocked(detail, INVENTORY) || !!rerunBlocked(PLAYBOOKS, detail, activeServer)}
                      title={rerunBlocked(PLAYBOOKS, detail, activeServer) || retryBlocked(detail, INVENTORY) || 'Re-run against only the hosts that failed last time'}
                    >
                      <Icon name="refresh" size={12}/> Retry failed
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn primary small"
                    onClick={() => onRunPlaybook?.(buildRerunPrefill(detail))}
                    disabled={!!rerunBlocked(PLAYBOOKS, detail, activeServer)}
                    title={rerunBlocked(PLAYBOOKS, detail, activeServer) || 'Open the run dialog with this run\'s settings'}
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
                      onClick={() => onOpenAdhoc?.(buildAdhocRetryPrefill(detail, INVENTORY))}
                      disabled={!!retryBlocked(detail, INVENTORY)}
                      title={retryBlocked(detail, INVENTORY) || 'Re-run against only the hosts that failed last time'}
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
            <div className="run-stat"><span className="section-title">changed</span><span className="mono" style={{ color: 'var(--ok)' }}>{run.changed}</span></div>
            <div className="run-stat"><span className="section-title">failed</span><span className="mono" style={{ color: 'var(--err)' }}>{run.failed}</span></div>
            <div className="run-stat"><span className="section-title">skipped</span><span className="mono">{run.skipped}</span></div>
            <div className="run-stat"><span className="section-title">duration</span><span className="mono">{run.duration}</span></div>
            <div className="run-stat"><span className="section-title">status</span><span className={`pill rs-${run.status}`}>{runStatusLabel(run.status)}</span></div>
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
// path the runner used) back to the library entry with exactly that
// path, or null.
//
// It used to fall back to any entry with the same file name, "so a
// moved file still resolves". But a same-named file somewhere else is
// just as often a different playbook — deploy.yml and
// staging/deploy.yml — and the caller then opened, or re-ran, that one
// under the recorded run's name. No match now means no match.
function findPlaybookFor(playbooks, run) {
  if (!run?.playbook) return null;
  return playbooks.find(p => p.path === run.playbook) || null;
}

// rerunBlocked says why a recorded playbook run must not be replayed
// from here, or '' when it may be. Re-run and Retry failed carry the
// old run's limit, tags, extra vars and --become into the run dialog,
// so they are only offered when the dialog will be for the SAME
// playbook on the SAME control node:
//
//   - the record names a connection other than the active one. Run
//     history is shared across connections, and two control nodes
//     commonly both have a site.yml. Compared by id when the record
//     has one; older records only have the display name.
//   - the active connection's library has no playbook at exactly the
//     recorded path (deleted, renamed, moved).
//
// The operator can still open the playbook they mean and run it by
// hand; what is refused is doing it in one click under another run's
// settings.
function rerunBlocked(playbooks, run, activeServer) {
  if (!run?.playbook) return 'This run did not record a playbook';
  const active = activeServer || {};
  const recordedElsewhere = run.serverId
    ? !!active.id && run.serverId !== active.id
    : !!run.server && !!active.name && run.server !== active.name;
  if (recordedElsewhere) {
    return `Recorded on connection "${run.server || run.serverId}" — switch to it to re-run (active: "${active.name || active.id}")`;
  }
  if (!findPlaybookFor(playbooks, run)) {
    return `${run.playbook} is not in this connection's library — it was deleted, renamed or moved`;
  }
  return '';
}

// failedHostsFromLog scans a run's event log for "fail" or
// recap-fail entries that carry a host name. Dedupes and returns
// hostnames in the order they appeared.
//
// These names are NOT to be acted on as they are — see retryHosts.
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

// retryHosts is the list "Retry failed" may target: the failed hosts
// from the log that are hosts of this connection's inventory and were
// within what the recorded run was aimed at.
//
// The names in the log come from output lines ("fatal: [name]: …"),
// and an output line is free text. A managed host can print one from
// a command's stdout, naming `all`, a group, or another machine. The
// retry used to take those names as its new target, so one line of
// output from one host could turn "retry on the host that failed"
// into the same command on every host. Three checks:
//
//   - the name must be a HOST in the inventory. `all`, group names
//     and patterns are never hosts, so they are dropped.
//   - for an ad-hoc run, it must be one of the hosts the recorded
//     target expands to; for a playbook run that had a --limit, one of
//     the hosts that limit expands to. A retry never reaches a host
//     the original run did not.
//   - a recorded target or limit that uses pattern operators this UI
//     does not evaluate ('!', '&', wildcards, ranges, regexes) cannot
//     be checked that way; then only the inventory check applies.
//
// A playbook run with no --limit ran on whatever its plays name, which
// is not recorded here; a --limit only ever narrows that, so naming an
// inventory host in it cannot add a host the playbook does not target.
function retryHosts(run, inventory) {
  const hosts = inventory?.hosts || [];
  const known = new Set(hosts.map(h => h.name));
  let names = failedHostsFromLog(run?.log).filter(n => known.has(n));
  const scope = run?.kind === 'adhoc' ? (run.target || 'all') : (run?.limit || '');
  if (scope && !/[!&*?~[]/.test(scope)) {
    const resolved = globalThis.AnsbuiResolveTargetHosts?.(scope, hosts, inventory?.groups || []) || [];
    const inScope = new Set(resolved.map(h => h.name));
    names = names.filter(n => inScope.has(n));
  }
  return names;
}

// retryBlocked says why "Retry failed" is not offered, or '' when it
// is. It distinguishes a log with no failed hosts from one whose
// failed hosts were all set aside by retryHosts, so the operator is
// told the names were not usable rather than shown a dead button.
function retryBlocked(run, inventory) {
  if (retryHosts(run, inventory).length > 0) return '';
  if (failedHostsFromLog(run?.log).length === 0) return 'The run\'s output names no failed host';
  return 'None of the failed hosts named in the output is a host of this connection\'s inventory that the run was aimed at';
}

// The two prefill builders below carry the record's connection
// (server, serverId) along with its settings. The prefill outlives the
// click that made it — it is handed to the Playbooks view, which is
// where it is acted on — so the view checks it against the connection
// that is active THEN, with the same rerunBlocked rule the buttons use.
function buildRerunPrefill(run) {
  return {
    playbookPath: run.playbook,
    server: run.server || '',
    serverId: run.serverId || '',
    limit: run.limit || '',
    tags: run.tags || [],
    extraVars: run.extraVars || {},
    check: !!run.check,
    become: !!run.become
  };
}

function buildRetryPrefill(run, inventory) {
  const hosts = retryHosts(run, inventory);
  return {
    playbookPath: run.playbook,
    server: run.server || '',
    serverId: run.serverId || '',
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

function buildAdhocRetryPrefill(run, inventory) {
  const hosts = retryHosts(run, inventory);
  return {
    ...buildAdhocRerunPrefill(run),
    target: hosts.length ? hosts.join(',') : run.target || 'all'
  };
}

globalThis.HistoryView = HistoryView;
// Shared with the Playbooks view, which applies the same rule to a
// re-run prefill at the moment it would open the run dialog.
globalThis.AnsbuiRerunBlocked = rerunBlocked;
