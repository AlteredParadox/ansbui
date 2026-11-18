// Playbooks view — library (left) + split editor (visual tasks ↔ YAML).

const { useState: useStateP, useMemo: useMemoP, useEffect: useEffectP, useRef: useRefP } = React;

// Line regexes. Each is applied to one YAML line and must run in linear
// time, because a playbook can hold a very long line.
//
// The trap is a run of blanks followed by "the rest of the line". If the
// rest may itself start with a blank, the two parts overlap: on a line
// that does not match (a trailing "\r" is enough, "." stops at it) the
// engine retries once per blank and rescans the rest each time, which is
// quadratic. TASK_NAME_RE and DASH_RE therefore spell the rest as "empty,
// or starting with a non-blank". They match exactly what the simpler
// `[ \t]+(.*)$` form matched; tests/web/playbooks-yaml.test.js checks
// that, and the running time, against the old patterns.
const SECTION_RE = /^[ \t]*(tasks|pre_tasks|post_tasks|handlers):[ \t]*$/;
const TASK_NAME_RE = /^[ \t]+- name:[ \t]+((?:[^ \t\n\r\u2028\u2029].*)?)$/;
const TASK_START_RE = /^[ \t]*- name:/;
const MODULE_RE = /^[ \t]+((?:ansible|community)\.[a-z_.]+):[ \t]*/;
const TOP_LEVEL_RE = /^\S/;
const QUOTE_RE = /["']/g;
const DASH_RE = /^([ \t]*)-([ \t]+)((?:[^ \t\n\r\u2028\u2029].*)?)$/;
const KV_RE = /^([^:]+)(:)(.*)$/;
const NUMBER_RE = /^[ \t]+\d+(\.\d+)?$/;
const BOOL_RE = /^[ \t]+(true|false|null|yes|no)\b/;
const STRING_RE = /^[ \t]+["']/;

// True when the value holds a Jinja expression: "{{" with a "}}" after
// it. Two indexOf scans rather than the unanchored /\{\{.*\}\}/ this
// replaces, which rescanned the rest of the line from every "{{" and so
// took quadratic time on a long run of braces. Same answer for any value
// with no line terminator between the braces, which is every value here
// (the source is split on "\n" first).
function hasJinja(value) {
  const open = value.indexOf('{{');
  return open !== -1 && value.includes('}}', open + 2);
}

function PlaybookLibrary({ playbooks, selectedId, onSelect, onNew }) {
  const [q, setQ] = useStateP('');
  const filter = q.toLowerCase();
  const rows = playbooks.filter(p =>
    !filter ||
    (p.path || p.name).toLowerCase().includes(filter) ||
    (p.title || '').toLowerCase().includes(filter)
  );
  return (
    <aside className="pb-lib card">
      <div className="pb-lib-head">
        <div className="section-title">Playbooks · {playbooks.length}</div>
        <button type="button" className="btn primary small" onClick={onNew}><Icon name="plus" size={12}/> New</button>
      </div>
      <div className="pb-lib-search">
        <Icon name="search" size={12} className="mute-2"/>
        <input className="input" value={q} onChange={e => setQ(e.target.value)} placeholder="Filter playbooks" style={{ border: 0, background: 'transparent', paddingLeft: 6, height: 26 }}/>
      </div>
      <div className="pb-lib-list">
        {rows.map(p => (
          <button type="button" key={p.id} className={`pb-lib-item ${selectedId === p.id ? 'active' : ''}`} onClick={() => onSelect(p.id)}>
            <div className="pb-lib-row-1">
              {/* The path, not the file name: two cards for deploy.yml
                  and staging/deploy.yml must not read the same. */}
              <span className="pb-lib-name mono">{p.path || p.name}</span>
              <span className={`dot rs-${p.lastStatus}`} title={`last: ${p.lastStatus}`}/>
            </div>
            <div className="pb-lib-row-2 mute">{p.title}</div>
            <div className="pb-lib-row-3">
              <span className="mini-tag mono">{p.targets}</span>
              <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>{p.lastRun}</span>
            </div>
          </button>
        ))}
      </div>
    </aside>
  );
}

function parseYamlTasks(yaml) {
  const lines = (yaml || '').split('\n');
  const blocks = [];
  let current = null;
  let section = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const sec = SECTION_RE.exec(line);
    if (sec) { section = sec[1]; continue; }
    const task = TASK_NAME_RE.exec(line);
    if (task && section) {
      if (current) blocks.push(current);
      current = {
        section,
        name: task[1].replaceAll(QUOTE_RE, ''),
        lines: [line],
        startLine: i
      };
      continue;
    }
    if (!current) continue;
    if (TASK_START_RE.test(line) || TOP_LEVEL_RE.test(line)) {
      blocks.push(current);
      current = null;
      i -= 1;
    } else {
      current.lines.push(line);
    }
  }
  if (current) blocks.push(current);
  return blocks.map(b => ({ ...b, module: detectModule(b.lines) }));
}

function detectModule(lines) {
  for (const ln of lines) {
    const m = MODULE_RE.exec(ln);
    if (m) return m[1];
  }
  return '';
}

function VisualStructure({ yaml, playbook, editing, onReorder }) {
  const tasks = useMemoP(() => parseYamlTasks(yaml), [yaml]);
  const grouped = {
    pre_tasks: tasks.filter(t => t.section === 'pre_tasks'),
    tasks: tasks.filter(t => t.section === 'tasks'),
    post_tasks: tasks.filter(t => t.section === 'post_tasks'),
    handlers: tasks.filter(t => t.section === 'handlers')
  };

  return (
    <div className="vs-wrap">
      <div className="vs-header">
        <div>
          <div className="section-title">Play</div>
          <h3 className="vs-title">{playbook.title}</h3>
        </div>
        <div className="vs-meta">
          <div className="vs-meta-item">
            <span className="section-title">hosts</span>
            <span className="mono">{playbook.targets || '—'}</span>
          </div>
          <div className="vs-meta-item">
            <span className="section-title">tasks</span>
            <span className="mono">{tasks.length}</span>
          </div>
        </div>
      </div>
      <TaskGroup label="Pre-tasks" items={grouped.pre_tasks} section="pre_tasks" tone="pre" editing={editing} onReorder={onReorder}/>
      <TaskGroup label="Tasks" items={grouped.tasks} section="tasks" tone="main" editing={editing} onReorder={onReorder}/>
      <TaskGroup label="Post-tasks" items={grouped.post_tasks} section="post_tasks" tone="post" editing={editing} onReorder={onReorder}/>
      <TaskGroup label="Handlers" items={grouped.handlers} section="handlers" tone="handlers" editing={editing} onReorder={onReorder}/>
    </div>
  );
}

function TaskGroup({ label, items, section, tone, editing, onReorder }) {
  if (!items.length) return null;
  const last = items.length - 1;
  return (
    <div className={`vs-group vs-${tone}`}>
      <div className="vs-group-head">
        <span className="section-title">{label}</span>
        <span className="mute mono">{items.length}</span>
      </div>
      <div className="vs-tasks">
        {items.map((t, i) => (
          <div className="vs-task" key={`${tone}-${t.startLine ?? i}-${t.name}`}>
            <div className="vs-task-idx mono mute-2">{String(i + 1).padStart(2, '0')}</div>
            <div className="vs-task-body">
              <div className="vs-task-name">{t.name}</div>
              <div className="vs-task-mod mono mute">{t.module || '—'}</div>
            </div>
            {editing && (
              <div className="vs-task-reorder">
                <button
                  type="button"
                  className="btn ghost small"
                  aria-label={`Move ${t.name} up`}
                  disabled={i === 0}
                  onClick={() => onReorder?.(section, i, -1)}
                >
                  <Icon name="chevron-up" size={12}/>
                </button>
                <button
                  type="button"
                  className="btn ghost small"
                  aria-label={`Move ${t.name} down`}
                  disabled={i === last}
                  onClick={() => onReorder?.(section, i, +1)}
                >
                  <Icon name="chevron-down" size={12}/>
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// moveTask splices two adjacent task-block ranges in the YAML so the
// UI reorder buttons result in a real text change, not just a reparse.
// Blocks come from parseYamlTasks which tracks each block's startLine
// and owns every line up to (but not including) the next block or
// top-level entry.
function moveTask(yaml, section, indexInSection, direction) {
  if (!yaml || !section) return yaml;
  const lines = yaml.split('\n');
  const blocks = parseYamlTasks(yaml);
  const sectionBlocks = blocks.filter(b => b.section === section);
  const a = sectionBlocks[indexInSection];
  const b = sectionBlocks[indexInSection + direction];
  if (!a || !b) return yaml;
  const aRange = [a.startLine, a.startLine + a.lines.length];
  const bRange = [b.startLine, b.startLine + b.lines.length];
  const [first, second] = aRange[0] < bRange[0] ? [a, b] : [b, a];
  const fStart = first.startLine;
  const fEnd = fStart + first.lines.length;
  const sStart = second.startLine;
  const sEnd = sStart + second.lines.length;
  const before = lines.slice(0, fStart);
  const between = lines.slice(fEnd, sStart);
  const after = lines.slice(sEnd);
  return [...before, ...second.lines, ...between, ...first.lines, ...after].join('\n');
}

function YamlEditor({ path, value, onChange, editing }) {
  const lines = value.split('\n');
  return (
    <div className="code-pane flex-1">
      <div className="code-head">
        <div className="mono mute" style={{ fontSize: 11.5 }}>{path || 'playbook.yml'}</div>
        <div className="code-head-actions">
          <span className="pill ok"><Icon name="check" size={10}/> syntax ok</span>
          {editing && (
            <span className="mute mono" style={{ fontSize: 11 }}>{lines.length} lines</span>
          )}
        </div>
      </div>
      <div className="code-body">
        <div className="code-gutter mono">
          <pre style={{ margin: 0 }}>{Array.from({ length: lines.length }, (_, i) => i + 1).join('\n')}</pre>
        </div>
        {editing ? (
          <textarea
            className="code-block code-block-edit yaml-textarea"
            aria-label="Edit playbook YAML"
            spellCheck="false"
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        ) : (
          <pre className="code-block code-block-edit">
            <code>{highlightYamlFull(value)}</code>
          </pre>
        )}
      </div>
    </div>
  );
}

function highlightYamlFull(src) {
  return src.split('\n').map((line, i) => (
    <span key={`ln-${i}-${line.length}`}>
      {renderYamlLine(line, i)}
      {'\n'}
    </span>
  ));
}

function renderYamlLine(line, lineIndex) {
  const trimStart = line.trimStart();
  if (trimStart.startsWith('#')) {
    return <span className="yml-c" key="c">{line}</span>;
  }
  if (line.startsWith('---')) {
    return <span className="yml-c" key="doc">{line}</span>;
  }
  const dash = DASH_RE.exec(line);
  if (dash) {
    return (
      <React.Fragment key={`d-${lineIndex}`}>
        {dash[1]}
        <span className="yml-d">-</span>
        {dash[2]}
        {colorizeKV(dash[3])}
      </React.Fragment>
    );
  }
  return colorizeKV(line);
}

function colorizeKV(s) {
  const m = KV_RE.exec(s);
  if (!m) return s;
  const rest = m[3];
  return (
    <>
      <span className="yml-k">{m[1]}</span>
      <span className="yml-p">{m[2]}</span>
      {rest && colorizeValue(rest)}
    </>
  );
}

function colorizeValue(rest) {
  if (NUMBER_RE.test(rest)) return <span className="yml-n">{rest}</span>;
  if (BOOL_RE.test(rest)) return <span className="yml-b">{rest}</span>;
  if (STRING_RE.test(rest)) return <span className="yml-s">{rest}</span>;
  if (hasJinja(rest)) return <span className="yml-j">{rest}</span>;
  return <span className="yml-v">{rest}</span>;
}

function PlaybooksView({ initialId, runnerPrefill, activeServer, onRunnerPrefillConsumed }) {
  const data = globalThis.AnsibleData || {};
  const PLAYBOOKS = data.PLAYBOOKS || [];
  const [selectedId, setSelectedId] = useStateP(initialId || PLAYBOOKS[0]?.id || '');
  const [yaml, setYaml] = useStateP('');
  const [draft, setDraft] = useStateP('');
  const [editing, setEditing] = useStateP(false);
  const [saving, setSaving] = useStateP(false);
  const [error, setError] = useStateP('');
  const [runnerOpen, setRunnerOpen] = useStateP(false);
  const [runnerSeed, setRunnerSeed] = useStateP(null);
  // Why a re-run requested from History was not opened. Separate from
  // `error`, which the selection effect below clears on every change.
  const [rerunError, setRerunError] = useStateP('');
  const [historyOpen, setHistoryOpen] = useStateP(false);
  const [importOpen, setImportOpen] = useStateP(false);

  const pb = PLAYBOOKS.find(p => p.id === selectedId) || PLAYBOOKS[0];

  // External "open runner with prefill" signal from the History view.
  // The prefill carries an issuedAt so repeat clicks on the same
  // playbook re-open the dialog.
  //
  // The run dialog opens only for the playbook at exactly the recorded
  // path. This used to accept a file-name match too, and to open the
  // dialog even with no match at all — on whichever playbook happened
  // to be selected, with the old run's limit, tags, extra vars and
  // --become already filled in.
  //
  // This is also where the prefill's connection is checked, not only
  // on History's buttons. The prefill is state the app shell holds
  // between views, so by the time it arrives here the active
  // connection may no longer be the one History looked at: Re-run on
  // connection A, close the dialog, switch to B, come back — and A's
  // limit, tags, extra vars and --become would open against B's
  // playbook of the same path. So: the same rule as the buttons
  // (AnsbuiRerunBlocked), applied against the connection active now.
  //
  // A prefill is good for one use. The shell is told as soon as it has
  // been looked at, accepted or not, and drops it, so revisiting this
  // view does not act on it a second time.
  useEffectP(() => {
    if (!runnerPrefill) return;
    onRunnerPrefillConsumed?.();
    const recorded = { playbook: runnerPrefill.playbookPath, server: runnerPrefill.server, serverId: runnerPrefill.serverId };
    const blocked = globalThis.AnsbuiRerunBlocked(PLAYBOOKS, recorded, activeServer);
    const match = blocked ? null : PLAYBOOKS.find(p => p.path === runnerPrefill.playbookPath);
    if (!match) {
      setRunnerOpen(false);
      setRunnerSeed(null);
      setRerunError(`Not re-running. ${blocked || 'The recorded playbook is not in this connection\'s library.'}`);
      return;
    }
    setRerunError('');
    setSelectedId(match.id);
    setRunnerSeed(runnerPrefill);
    setRunnerOpen(true);
  }, [runnerPrefill?.issuedAt]);

  useEffectP(() => {
    setEditing(false);
    setError('');
    if (!pb) { setYaml(''); setDraft(''); return; }
    if (pb.yaml) { setYaml(pb.yaml); setDraft(pb.yaml); return; }
    if (!pb.path || !globalThis.AnsbuiAPI) return;
    let alive = true;
    globalThis.AnsbuiAPI.getPlaybook(pb.path)
      .then(res => {
        if (!alive) return;
        pb.yaml = res.yaml || '';
        setYaml(pb.yaml);
        setDraft(pb.yaml);
      })
      .catch(e => { if (alive) { setError(e.message); setYaml(''); setDraft(''); } });
    return () => { alive = false; };
  }, [pb?.id]);

  useEffectP(() => { if (initialId) setSelectedId(initialId); }, [initialId]);

  const startEdit = () => { setDraft(yaml); setEditing(true); setError(''); };
  const cancelEdit = () => { setDraft(yaml); setEditing(false); setError(''); };

  const savePlaybook = async () => {
    if (!pb?.path || !globalThis.AnsbuiAPI) return;
    setSaving(true); setError('');
    try {
      await globalThis.AnsbuiAPI.savePlaybook(pb.path, draft);
      pb.yaml = draft;
      setYaml(draft);
      setEditing(false);
    } catch (e) { setError(e.message); }
    finally { setSaving(false); }
  };

  const reorderTask = (section, sectionIndex, direction) => {
    const next = moveTask(draft, section, sectionIndex, direction);
    if (next !== draft) setDraft(next);
  };

  if (!pb) {
    return (
      <div className="view view-playbooks">
        <div className="view-head">
          <div>
            <h1 className="view-title">Playbooks</h1>
            <div className="view-sub mute">No playbooks found in the server's workDir yet.</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="view view-playbooks">
      <div className="view-head">
        <div>
          <h1 className="view-title">Playbooks</h1>
          <div className="view-sub mute">{PLAYBOOKS.length} playbooks</div>
        </div>
        <div className="view-actions">
          <button type="button" className="btn small" onClick={() => setImportOpen(true)}>
            <Icon name="download" size={12}/> Import
          </button>
          <button type="button" className="btn small" onClick={() => setHistoryOpen(true)}>
            <Icon name="history" size={12}/> History
          </button>
          {editing ? (
            <>
              <button type="button" className="btn small" onClick={cancelEdit} disabled={saving}>Cancel</button>
              <button type="button" className="btn primary small" onClick={savePlaybook} disabled={saving}>
                <Icon name="check" size={12}/> {saving ? 'Saving…' : 'Save'}
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn small" onClick={startEdit}>
                <Icon name="code" size={12}/> Edit
              </button>
              <button type="button" className="btn primary small" onClick={() => setRunnerOpen(true)}>
                <Icon name="play" size={12}/> Run…
              </button>
            </>
          )}
        </div>
      </div>

      {error && <div className="cm-error mono">{error}</div>}
      {rerunError && <div className="cm-error mono">{rerunError}</div>}

      <div className="pb-body">
        <PlaybookLibrary playbooks={PLAYBOOKS} selectedId={selectedId} onSelect={(id) => { setRerunError(''); setSelectedId(id); }} onNew={() => setImportOpen(true)}/>

        <main className="pb-main">
          <div className="pb-head card">
            <div className="pb-head-top">
              <div>
                <div className="section-title">Playbook</div>
                <h2 className="pb-title">{pb.title} <span className="mono mute" style={{ fontWeight: 400, fontSize: 14, marginLeft: 8 }}>{pb.path || pb.name}</span></h2>
                <div className="mute">{pb.description}</div>
              </div>
              <div className="pb-head-stats">
                <div><span className="section-title">Targets</span><div className="mono">{pb.targets || '—'}</div></div>
                <div><span className="section-title">Last run</span><div>{pb.lastRun || '—'} {pb.lastStatus && <span className={`dot rs-${pb.lastStatus}`} style={{ marginLeft: 6 }}/>}</div></div>
                <div><span className="section-title">Modified</span><div className="mono" style={{ fontSize: 12 }}>{pb.modified ? new Date(pb.modified).toLocaleString() : '—'}</div></div>
              </div>
            </div>
            {(pb.tags || []).length > 0 && (
              <div className="pb-head-tags">
                {(pb.tags || []).map(t => <span key={t} className="chip on"><Icon name="tag" size={10}/><span className="mono">{t}</span></span>)}
              </div>
            )}
          </div>

          <div className="pb-split">
            <div className="pb-split-pane pb-visual card">
              <div className="pb-split-head">
                <span className="section-title">Structure</span>
                <span className="mute mono" style={{ fontSize: 11 }}>
                  {editing ? 'click ↑ / ↓ to reorder' : 'read-only — click Edit to change'}
                </span>
              </div>
              <VisualStructure yaml={editing ? draft : yaml} playbook={pb} editing={editing} onReorder={reorderTask}/>
            </div>
            <div className="pb-split-pane pb-yaml card">
              <div className="pb-split-head">
                <span className="section-title">YAML</span>
                <span className="mute mono" style={{ fontSize: 11 }}>{(editing ? draft : yaml).split('\n').length} lines</span>
              </div>
              <YamlEditor
                path={pb.path}
                value={editing ? draft : yaml}
                onChange={setDraft}
                editing={editing}
              />
            </div>
          </div>
        </main>
      </div>
      <PlaybookRunner
        open={runnerOpen}
        pb={pb}
        seed={runnerSeed}
        onClose={() => { setRunnerOpen(false); setRunnerSeed(null); }}
      />
      <PlaybookHistoryDialog open={historyOpen} pb={pb} onClose={() => setHistoryOpen(false)}/>
      <PlaybookImportDialog open={importOpen} onClose={() => setImportOpen(false)} onImported={() => {
        setImportOpen(false);
        globalThis.AnsbuiAPI?.refreshData().catch(() => {});
      }}/>
    </div>
  );
}

function PlaybookRunner({ open, pb, seed, onClose }) {
  // guardRunClose vetoes any close while a run streams (unless the
  // operator confirms). Passed to useDialog so even a browser
  // force-close — a second Escape with no cancelable event — is
  // caught and the dialog re-shown, instead of silently dropping the
  // WebSocket and killing the remote ansible-playbook. It reads the
  // live `running` via a ref so useDialog's listener always sees the
  // current value without re-subscribing on every render.
  const runningRef = useRefP(false);
  const guardRunClose = () => !runningRef.current || globalThis.confirmAbandonRun('This playbook run', 'closing the dialog');
  const dialogRef = globalThis.useDialog(open, onClose, { guardClose: guardRunClose });
  const [limit, setLimit] = useStateP('');
  const [limitPickerOpen, setLimitPickerOpen] = useStateP(false);
  const [tagsRaw, setTagsRaw] = useStateP('');
  const [check, setCheck] = useStateP(false);
  const [become, setBecome] = useStateP(false);
  const [running, setRunning] = useStateP(false);
  const [output, setOutput] = useStateP([]);
  // includeHosts is the parsed `# ansbui-include:` set from the
  // playbook YAML — auto-extended into --limit at run time on the
  // backend. Lazy-loaded on dialog open so the library list stays
  // a single SSH `find` (no per-file cat). Display only; the
  // operator sees what's about to happen.
  const [includeHosts, setIncludeHosts] = useStateP([]);
  // vars are stored as an ordered list of {rid, key, type, value} rows.
  // rid is a stable per-row id so React's reconciler doesn't shuffle
  // DOM nodes (and their focus state) when rows are added or removed
  // from the middle — Sonar S6479 flags naked-index keys for exactly
  // that reason.
  const [vars, setVars] = useStateP(() => [newVarRow()]);
  const [varsError, setVarsError] = useStateP('');
  // vaultPassword is held only in component state for the duration of
  // the run; the dialog clears it on close, the backend pipes it via
  // stdin (never argv), and buildPlaybookRecord deliberately omits it
  // so it doesn't land in the persisted RunRecord.
  const [vaultPassword, setVaultPassword] = useStateP('');
  const streamRef = useRefP(null);
  const outRef = useRefP(null);

  // When `seed` arrives (e.g. from a History re-run action) apply it to
  // the form fields. We key the effect on open+seed-identity so
  // re-opening with the same seed object doesn't spuriously re-apply.
  useEffectP(() => {
    if (!open || !seed) return;
    setLimit(seed.limit || '');
    setTagsRaw((seed.tags || []).join(', '));
    setCheck(!!seed.check);
    setBecome(!!seed.become);
    setVars(varsFromRecord(seed.extraVars));
    setVarsError('');
  }, [open, seed]);

  const setVarAt = (i, patch) => setVars(prev => prev.map((row, j) => (j === i ? { ...row, ...patch } : row)));
  const addVar = () => setVars(prev => [...prev, newVarRow()]);
  const removeVar = (i) => setVars(prev => prev.filter((_, j) => j !== i));

  useEffectP(() => {
    if (!open) {
      // Close any stream when dialog is dismissed and reset every
      // piece of dialog-local state so the next open — for the same
      // or a different playbook — starts clean. Without this,
      // values from a previous run (limit, tags, vars, check/become)
      // bleed into whichever playbook the operator opens next.
      // The seed-apply effect re-fills these when a History re-run
      // launches the dialog with a seed; manual opens get defaults.
      if (streamRef.current) { streamRef.current.close(); streamRef.current = null; }
      setOutput([]);
      setRunning(false);
      setVaultPassword('');
      setIncludeHosts([]);
      setLimit('');
      setLimitPickerOpen(false);
      setTagsRaw('');
      setCheck(false);
      setBecome(false);
      setVars([newVarRow()]);
      setVarsError('');
      return;
    }
    // Lazy-fetch the playbook content so we can show the
    // `# ansbui-include:` hosts as chips. Errors don't matter
    // for the UI surface — if the fetch fails, the chip row is
    // empty and the run still works (backend re-reads at run
    // time anyway).
    if (!pb?.path || !globalThis.AnsbuiAPI) return;
    let cancelled = false;
    globalThis.AnsbuiAPI.getPlaybook(pb.path).then(res => {
      if (cancelled) return;
      setIncludeHosts(Array.isArray(res?.include) ? res.include : []);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [open, pb?.path]);

  useEffectP(() => () => { if (streamRef.current) streamRef.current.close(); }, []);

  // Keep runningRef in sync so guardRunClose (registered once on the
  // dialog's 'close' listener) always sees the live value.
  useEffectP(() => { runningRef.current = running; }, [running]);

  // Closing this dialog (Escape, backdrop, ✕) drops the WebSocket and
  // the backend kills the remote ansible-playbook when the peer goes
  // away — so while a run streams, every close path asks first. The
  // same guard warns on navigation / tab close.
  globalThis.useRunGuard(running, 'A playbook run');
  // requestClose backs the explicit affordances (✕ / backdrop), which
  // set open=false and so bypass useDialog's guardClose — they must
  // run the same confirm themselves.
  const requestClose = () => {
    if (!guardRunClose()) return;
    onClose();
  };

  useEffectP(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  const run = () => {
    if (running || !pb || !globalThis.AnsbuiAPI) return;
    setOutput([]); setRunning(true);
    const log = [];
    const appendLog = (entry) => { log.push(entry); setOutput([...log]); };

    const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);
    let extraVars;
    try {
      extraVars = collectExtraVars(vars);
      setVarsError('');
    } catch (e) {
      setVarsError(e.message);
      setRunning(false);
      return;
    }
    const payload = {
      path: pb.path,
      limit: limit.trim(),
      tags,
      extraVars,
      check,
      become
    };
    if (vaultPassword) payload.vaultPassword = vaultPassword;

    streamRef.current = globalThis.AnsbuiAPI.runCommand('playbook', payload, {
      onEntry: appendLog,
      onDone: () => setRunning(false),
      onClose: () => { setRunning(false); streamRef.current = null; },
      onError: () => {
        appendLog({ t: 'fail', text: 'WebSocket error — check backend logs.' });
        setRunning(false);
      }
    });
  };

  const cancel = () => {
    if (streamRef.current) {
      streamRef.current.close();
      streamRef.current = null;
    }
    setRunning(false);
  };

  if (!pb) return <dialog ref={dialogRef} className="ansbui-dialog ansbui-dialog-runner" aria-hidden="true"/>;

  return (
    <dialog
      ref={dialogRef}
      className="ansbui-dialog ansbui-dialog-runner"
      aria-label={`Run ${pb.path || pb.name}`}
      // Escape fires the cancelable 'cancel' event: preventDefault
      // stops the dialog closing so requestClose decides cleanly (no
      // flicker) on the first press. A second Escape that the browser
      // makes non-cancelable slips past this and force-closes — that
      // path is caught by useDialog's guardClose, which re-shows the
      // dialog. Escape is handled ONLY here; the no-op keydown just
      // keeps the clickable backdrop paired with a keyboard listener
      // (Sonar S1082), like dialogBackdropHandlers.
      onCancel={(e) => { e.preventDefault(); requestClose(); }}
      onClick={(e) => { if (e.target === dialogRef.current) requestClose(); }}
      onKeyDown={() => { /* Escape handled via onCancel + guardClose */ }}
    >
      <div className="pb-runner card">
        <div className="pb-runner-head">
          <div>
            <div className="section-title">Run playbook</div>
            {/* The full path: this is the last thing the operator reads
                before the playbook runs. */}
            <h3 className="mono" style={{ margin: '4px 0 0' }}>{pb.path || pb.name}</h3>
            <div className="mute" style={{ fontSize: 12 }}>
              hosts: <span className="mono">{pb.targets || 'all'}</span>
            </div>
          </div>
          <button type="button" className="btn ghost small" aria-label="Close" onClick={requestClose}><Icon name="x" size={14}/></button>
        </div>

        <div className="pb-runner-form">
          {includeHosts.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div className="cm-field-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>Always included</span>
                <span className="mute" style={{ fontWeight: 'normal', fontSize: 11 }}>
                  <span>(from </span>
                  <span className="mono">{'# ansbui-include:'}</span>
                  <span> in the playbook — merged into </span>
                  <span className="mono">--limit</span>
                  <span> at run time)</span>
                </span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                {includeHosts.map(h => (
                  <span key={h} className="mini-tag mono" style={{ background: 'var(--ansbui-accent-soft, rgba(80,160,255,0.12))' }}>{h}</span>
                ))}
              </div>
            </div>
          )}
          <label htmlFor="pb-limit" className="cm-field-label">Limit (optional — overrides hosts:)</label>
          <div className="pb-limit-row">
            <input id="pb-limit" className="input mono" placeholder={pb.targets || 'e.g. webservers, host1.example.com'} value={limit} onChange={e => setLimit(e.target.value)}/>
            <button type="button" className="btn small" onClick={() => setLimitPickerOpen(true)}>
              <Icon name="filter" size={12}/> Browse…
            </button>
          </div>

          <label htmlFor="pb-tags" className="cm-field-label">Tags (comma-separated, optional)</label>
          <input id="pb-tags" className="input mono" placeholder="deploy, config" value={tagsRaw} onChange={e => setTagsRaw(e.target.value)}/>

          <label htmlFor="pb-vault-pw" className="cm-field-label" style={{ marginTop: 8 }}>
            Vault password <span className="mute">(optional — only if the playbook references a $ANSIBLE_VAULT file)</span>
          </label>
          <input
            id="pb-vault-pw"
            type="password"
            autoComplete="new-password"
            className="input mono"
            placeholder="leave blank if no vault is referenced"
            value={vaultPassword}
            onChange={e => setVaultPassword(e.target.value)}
          />

          <div className="cm-field-label" style={{ marginTop: 8 }}>Extra variables (--extra-vars)</div>
          <div className="pb-vars">
            {vars.map((row, i) => (
              <PlaybookVarRow
                key={row.rid}
                index={i}
                row={row}
                onChange={(patch) => setVarAt(i, patch)}
                onRemove={() => removeVar(i)}
                removable={vars.length > 1 || row.key !== '' || row.value !== ''}
              />
            ))}
            <button type="button" className="btn ghost small" onClick={addVar} style={{ justifySelf: 'start' }}>
              <Icon name="plus" size={11}/> Add variable
            </button>
            {varsError && <div className="cm-error mono" style={{ marginTop: 4 }}>{varsError}</div>}
          </div>

          <div className="pb-runner-opts">
            <label className="opt" htmlFor="pb-check">
              <input id="pb-check" type="checkbox" checked={check} onChange={e => setCheck(e.target.checked)}/>
              <span className="mono">--check</span> <span className="mute">(dry run)</span>
            </label>
            <label className="opt" htmlFor="pb-become">
              <input id="pb-become" type="checkbox" checked={become} onChange={e => setBecome(e.target.checked)}/>
              <span className="mono">--become</span> <span className="mute">(sudo)</span>
            </label>
          </div>

          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            {running ? (
              <button type="button" className="btn small" onClick={cancel}>
                <Icon name="x" size={12}/> Cancel
              </button>
            ) : (
              <button type="button" className="btn primary small" onClick={run}>
                <Icon name="play" size={12}/> Run
              </button>
            )}
            <button type="button" className="btn small" onClick={() => { setOutput([]); }} disabled={running}>
              Clear output
            </button>
          </div>
        </div>

        <div className="terminal" ref={outRef} style={{ flex: 1, minHeight: 320 }}>
          {output.length === 0 && (
            <div className="terminal-empty mute-2 mono">
              <div># fill in any overrides and press Run</div>
              <div># output from ansible-playbook will stream here</div>
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
      <LimitPicker
        open={limitPickerOpen}
        initialValue={limit}
        onClose={() => setLimitPickerOpen(false)}
        onApply={(v) => { setLimit(v); setLimitPickerOpen(false); }}
      />
    </dialog>
  );
}

// ---------- Extra-vars editor ----------

const VAR_TYPES = [
  { id: 'string', label: 'string' },
  { id: 'number', label: 'number' },
  { id: 'bool',   label: 'bool' },
  { id: 'json',   label: 'json' }
];

function PlaybookVarRow({ index, row, onChange, onRemove, removable }) {
  const valueId = `pb-var-${index}-value`;
  return (
    <div className="pb-var-row">
      <input
        className="input mono"
        aria-label={`Variable ${index + 1} name`}
        placeholder="var_name"
        value={row.key}
        onChange={(e) => onChange({ key: e.target.value })}
      />
      <select
        className="input pb-var-type"
        aria-label={`Variable ${index + 1} type`}
        value={row.type}
        onChange={(e) => onChange({ type: e.target.value })}
      >
        {VAR_TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
      </select>
      <PlaybookVarValue id={valueId} row={row} onChange={onChange}/>
      <button
        type="button"
        className="btn ghost small"
        onClick={onRemove}
        disabled={!removable}
        title="Remove variable"
      >
        <Icon name="x" size={12}/>
      </button>
    </div>
  );
}

function PlaybookVarValue({ id, row, onChange }) {
  if (row.type === 'bool') {
    const current = row.value === true || row.value === 'true';
    return (
      <select
        id={id}
        className="input mono"
        aria-label="value"
        value={current ? 'true' : 'false'}
        onChange={(e) => onChange({ value: e.target.value })}
      >
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  }
  if (row.type === 'number') {
    return (
      <input
        id={id}
        className="input mono"
        type="number"
        aria-label="value"
        placeholder="0"
        value={row.value}
        onChange={(e) => onChange({ value: e.target.value })}
      />
    );
  }
  if (row.type === 'json') {
    return (
      <input
        id={id}
        className="input mono"
        aria-label="value"
        placeholder='["a","b"]  or  {"nested":"obj"}'
        value={row.value}
        onChange={(e) => onChange({ value: e.target.value })}
      />
    );
  }
  return (
    <input
      id={id}
      className="input mono"
      aria-label="value"
      placeholder="value"
      value={row.value}
      onChange={(e) => onChange({ value: e.target.value })}
    />
  );
}

let varRowIdSeq = 0;
function newVarRow(patch) {
  varRowIdSeq += 1;
  // Spreading undefined is a valid no-op per the ES spec, so the
  // empty-object fallback (|| {}) was redundant (Sonar S7744).
  return { rid: `var-${varRowIdSeq}`, key: '', type: 'string', value: '', ...patch };
}

// varsFromRecord converts a persisted extraVars map back into the row
// model used by the editor. The persisted values preserve real JSON
// types, so we pick the row type from each value's runtime type.
function varsFromRecord(record) {
  const entries = Object.entries(record || {});
  if (!entries.length) return [newVarRow()];
  return entries.map(([k, v]) => {
    if (typeof v === 'number') return newVarRow({ key: k, type: 'number', value: String(v) });
    if (typeof v === 'boolean') return newVarRow({ key: k, type: 'bool', value: v ? 'true' : 'false' });
    if (v !== null && typeof v === 'object') return newVarRow({ key: k, type: 'json', value: JSON.stringify(v) });
    return newVarRow({ key: k, type: 'string', value: String(v ?? '') });
  });
}

// collectExtraVars walks the row model and builds a typed map ready for
// JSON-serialization on the backend. Throws on bad number/json input so
// the run dialog can surface a targeted error.
function collectExtraVars(rows) {
  const out = {};
  rows.forEach((row, idx) => {
    const key = row.key.trim();
    if (!key) return;
    if (row.type === 'string') {
      if (row.value === '') return;
      out[key] = row.value;
      return;
    }
    if (row.type === 'number') {
      if (row.value === '' || row.value === null) return;
      const n = Number(row.value);
      if (!Number.isFinite(n)) {
        throw new TypeError(`row ${idx + 1} (${key}): "${row.value}" is not a number`);
      }
      out[key] = n;
      return;
    }
    if (row.type === 'bool') {
      out[key] = row.value === true || row.value === 'true';
      return;
    }
    if (row.type === 'json') {
      if (row.value === '') return;
      try {
        out[key] = JSON.parse(row.value);
      } catch (e) {
        throw new TypeError(`row ${idx + 1} (${key}): invalid JSON — ${e.message}`);
      }
    }
  });
  return out;
}

// ---------- Limit picker ----------
//
// Browse inventory groups + hosts with multi-select, then write a
// comma-joined limit expression into the Run dialog's limit field.
// Items map 1:1 to ansible's --limit pattern language — group names
// and host names share a namespace. We keep the selected set as
// ordered unique tokens so the user can see what they picked before
// applying.

function splitTokens(raw) {
  return (raw || '')
    .split(/[\s,]+/)
    .map(s => s.trim())
    .filter(Boolean);
}

function buildLimitDescendants(groups) {
  const childrenOf = limitChildrenIndex(groups);
  const cache = {};
  for (const g of groups) limitDescendantSet(g.id, childrenOf, cache);
  return cache;
}

function limitChildrenIndex(groups) {
  const children = {};
  for (const g of groups) {
    const key = g.parent ?? '__root__';
    const list = children[key] || [];
    list.push(g.id);
    children[key] = list;
  }
  return children;
}

function limitDescendantSet(id, childrenOf, cache) {
  if (cache[id]) return cache[id];
  const set = new Set([id]);
  for (const child of childrenOf[id] || []) {
    for (const d of limitDescendantSet(child, childrenOf, cache)) set.add(d);
  }
  cache[id] = set;
  return set;
}

// countHostsInDescendants — kept separate so the .map in computeGroupRows
// stays at 3 levels of nesting rather than 5 (Sonar S2004).
function countHostsInDescendants(hosts, descendantSet) {
  let n = 0;
  for (const h of hosts) {
    if ((h.groups || []).some(x => descendantSet.has(x))) n += 1;
  }
  return n;
}

function computeGroupRows(groups, hosts, descendants, query) {
  const q = query.trim().toLowerCase();
  const rows = [];
  for (const g of groups) {
    if (g.id === 'ungrouped') continue;
    if (q && !g.name.toLowerCase().includes(q)) continue;
    const set = descendants[g.id] || new Set([g.id]);
    rows.push({ id: g.id, name: g.name, count: countHostsInDescendants(hosts, set) });
  }
  return rows.toSorted((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

function LimitPicker({ open, initialValue, onClose, onApply }) {
  const data = globalThis.AnsibleData || {};
  const GROUPS = data.GROUPS || [];
  const HOSTS = data.HOSTS || [];
  const [selected, setSelected] = useStateP(new Set());
  const [query, setQuery] = useStateP('');

  useEffectP(() => {
    if (!open) return;
    setSelected(new Set(splitTokens(initialValue)));
    setQuery('');
  }, [open, initialValue]);

  const descendants = useMemoP(() => buildLimitDescendants(GROUPS), [GROUPS]);

  const groupRows = useMemoP(
    () => computeGroupRows(GROUPS, HOSTS, descendants, query),
    [GROUPS, HOSTS, descendants, query]
  );

  const hostRows = useMemoP(() => {
    const q = query.trim().toLowerCase();
    if (!q) return HOSTS.slice(0, 200);
    return HOSTS.filter(h =>
      h.name.toLowerCase().includes(q) ||
      (h.ip || '').includes(q) ||
      (h.groups || []).join(' ').toLowerCase().includes(q)
    ).slice(0, 200);
  }, [HOSTS, query]);

  const toggle = (id) => setSelected(prev => {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  const selectedList = [...selected];
  const apply = () => onApply(selectedList.join(','));

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Browse inventory"
      subtitle="Pick groups or hosts — the picker builds a comma-separated --limit expression."
      width="min(720px, 94vw)"
      maxHeight="75vh"
    >
      <input
        className="input"
        aria-label="Filter groups and hosts"
        placeholder="Filter…"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        style={{ marginBottom: 10 }}
      />
      <div className="lp-grid">
              <div>
                <div className="section-title" style={{ marginBottom: 4 }}>Groups · {groupRows.length}</div>
                <div className="lp-list">
                  {groupRows.length === 0 && <div className="mute mono" style={{ fontSize: 12 }}>no matches</div>}
                  {groupRows.map(g => (
                    <label key={`g-${g.id}`} className="lp-row" htmlFor={`lp-g-${g.id}`}>
                      <input
                        id={`lp-g-${g.id}`}
                        type="checkbox"
                        checked={selected.has(g.id)}
                        onChange={() => toggle(g.id)}
                      />
                      <Icon name="group" size={12}/>
                      <span className="mono">{g.name}</span>
                      <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>{g.count}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div className="section-title" style={{ marginBottom: 4 }}>Hosts · {hostRows.length}{HOSTS.length > hostRows.length ? ` of ${HOSTS.length}` : ''}</div>
                <div className="lp-list">
                  {hostRows.length === 0 && <div className="mute mono" style={{ fontSize: 12 }}>no matches</div>}
                  {hostRows.map(h => (
                    <label key={`h-${h.id}`} className="lp-row" htmlFor={`lp-h-${h.id}`}>
                      <input
                        id={`lp-h-${h.id}`}
                        type="checkbox"
                        checked={selected.has(h.name)}
                        onChange={() => toggle(h.name)}
                      />
                      <span className={`dot ${h.status}`}/>
                      <span className="mono">{h.name}</span>
                    </label>
                  ))}
                </div>
              </div>
            </div>

            <div className="lp-selected">
              <div className="section-title" style={{ marginBottom: 4 }}>Selected · {selectedList.length}</div>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {selectedList.length === 0 && <span className="mute" style={{ fontSize: 12 }}>Nothing selected.</span>}
                {selectedList.map(tok => (
                  <button
                    key={tok}
                    type="button"
                    className="chip on"
                    onClick={() => toggle(tok)}
                    title="Remove"
                  >
                    <span className="mono">{tok}</span>
                    <Icon name="x" size={10}/>
                  </button>
                ))}
              </div>
              <div className="mono mute" style={{ fontSize: 11.5, marginTop: 6, wordBreak: 'break-all' }}>
                --limit {selectedList.join(',') || '(empty)'}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              <button type="button" className="btn primary small" onClick={apply} disabled={selectedList.length === 0}>
                <Icon name="check" size={12}/> Apply
              </button>
              <button type="button" className="btn small" onClick={() => setSelected(new Set())} disabled={selectedList.length === 0}>
                Clear
              </button>
              <button type="button" className="btn small" onClick={onClose}>Cancel</button>
            </div>
    </globalThis.AnsbuiCenterDialog>
  );
}

// ---------- History dialog ----------

function PlaybookHistoryDialog({ open, pb, onClose }) {
  const [runs, setRuns] = useStateP([]);
  const [loading, setLoading] = useStateP(false);
  const [error, setError] = useStateP('');

  useEffectP(() => {
    if (!open || !pb || !globalThis.AnsbuiAPI) return;
    setLoading(true); setError('');
    let alive = true;
    globalThis.AnsbuiAPI.listRuns()
      .then(res => {
        if (!alive) return;
        const all = res.runs || [];
        const mine = all.filter(r => r.playbook === pb.path);
        setRuns(mine);
      })
      .catch(e => { if (alive) setError(e.message); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [open, pb?.id]);

  if (!pb) return null;

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Run history"
      subtitle={pb.name}
      ariaLabel={`Run history for ${pb.name}`}
      width="min(720px, 94vw)"
      maxHeight="70vh"
    >
      {error && <div className="cm-error mono">{error}</div>}
      {loading && <div className="mute mono" style={{ fontSize: 12 }}>loading…</div>}
      {!loading && runs.length === 0 && <div className="mute" style={{ fontSize: 12 }}>No runs recorded for this playbook yet.</div>}
      {runs.length > 0 && (
        <table className="t" style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ cursor: 'default', width: 22 }}></th>
              <th style={{ cursor: 'default' }}>When</th>
              <th style={{ cursor: 'default' }}>Duration</th>
              <th style={{ cursor: 'default' }}>ok</th>
              <th style={{ cursor: 'default' }}>changed</th>
              <th style={{ cursor: 'default' }}>failed</th>
              <th style={{ cursor: 'default' }}>By</th>
            </tr>
          </thead>
          <tbody>
            {runs.map(r => (
              <tr key={r.id}>
                <td><span className={`dot rs-${r.status}`}/></td>
                <td className="mono" style={{ fontSize: 12 }}>{r.startedAt ? new Date(r.startedAt).toLocaleString() : '—'}</td>
                <td className="mono">{r.duration || '—'}</td>
                <td className="mono" style={{ color: 'var(--ok)' }}>{r.ok || 0}</td>
                <td className="mono" style={{ color: 'var(--ok)' }}>{r.changed || 0}</td>
                <td className="mono" style={{ color: r.failed ? 'var(--err)' : undefined }}>{r.failed || 0}</td>
                <td className="mute">{r.who || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </globalThis.AnsbuiCenterDialog>
  );
}

// ---------- Import dialog ----------

const PATH_SEGMENT_RE = /^[A-Za-z0-9._-]+$/;

function PlaybookImportDialog({ open, onClose, onImported }) {
  const [filename, setFilename] = useStateP('');
  const [yaml, setYaml] = useStateP('');
  const [busy, setBusy] = useStateP(false);
  const [error, setError] = useStateP('');

  useEffectP(() => {
    if (!open) { setFilename(''); setYaml(''); setError(''); }
  }, [open]);

  const validPath = (raw) => {
    const trimmed = (raw || '').trim();
    if (!trimmed) return false;
    return trimmed.split('/').every(seg => PATH_SEGMENT_RE.test(seg));
  };

  const pickFile = async (file) => {
    if (!file) return;
    try {
      const text = await file.text();
      setYaml(text);
      if (!filename) setFilename(file.name);
    } catch (e) { setError(e.message); }
  };

  const submit = async () => {
    setError('');
    const trimmed = filename.trim();
    if (!validPath(trimmed)) {
      setError('Filename must be alphanumeric with ._- and an optional subdir prefix.');
      return;
    }
    if (!yaml) { setError('YAML content is empty.'); return; }
    setBusy(true);
    try {
      await globalThis.AnsbuiAPI.savePlaybook(trimmed, yaml);
      onImported?.(trimmed);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <globalThis.AnsbuiCenterDialog
      open={open}
      onClose={onClose}
      title="Import playbook"
      subtitle="Upload a .yml/.yaml file or paste content below. It will be written to your server's workDir."
      width="min(720px, 94vw)"
    >
      {error && <div className="cm-error mono">{error}</div>}

      <label htmlFor="pb-import-file" className="cm-field-label">File</label>
      <input
        id="pb-import-file"
        type="file"
        accept=".yml,.yaml,text/yaml"
        onChange={(e) => pickFile(e.target.files?.[0])}
        className="input"
        style={{ padding: '4px 6px' }}
      />

      <label htmlFor="pb-import-name" className="cm-field-label" style={{ marginTop: 10 }}>Target filename (relative to workDir)</label>
      <input
        id="pb-import-name"
        className="input mono"
        placeholder="deploy-app.yml or plays/deploy-app.yml"
        value={filename}
        onChange={(e) => setFilename(e.target.value)}
      />

      <label htmlFor="pb-import-yaml" className="cm-field-label" style={{ marginTop: 10 }}>YAML</label>
      <textarea
        id="pb-import-yaml"
        className="yaml-textarea"
        spellCheck="false"
        style={{ minHeight: 240, fontFamily: 'var(--font-mono)', fontSize: 12 }}
        value={yaml}
        onChange={(e) => setYaml(e.target.value)}
        placeholder="---&#10;- hosts: all&#10;  tasks:&#10;    - name: …"
      />

      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <button type="button" className="btn primary small" disabled={busy} onClick={submit}>
          <Icon name="check" size={12}/> {busy ? 'Saving…' : 'Save'}
        </button>
        <button type="button" className="btn small" disabled={busy} onClick={onClose}>Cancel</button>
      </div>
    </globalThis.AnsbuiCenterDialog>
  );
}

globalThis.PlaybooksView = PlaybooksView;
