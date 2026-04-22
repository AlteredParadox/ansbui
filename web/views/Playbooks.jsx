// Playbooks view — library (left) + split editor (visual tasks ↔ YAML).

const { useState: useStateP, useMemo: useMemoP, useEffect: useEffectP, useRef: useRefP } = React;

const PB_EVENT_MAPPING = {
  ok: 'ok',
  changed: 'changed',
  fail: 'fail',
  recap: 'recap',
  'recap-warn': 'recap-warn',
  'recap-fail': 'recap-fail',
  meta: 'meta',
  line: 'meta',
  error: 'fail'
};

// Bounded regexes — each anchors to a single YAML line and avoids
// nested quantifiers / overlapping alternation, keeping them linear
// (Sonar S5852).
const SECTION_RE = /^[ \t]*(tasks|pre_tasks|post_tasks|handlers):[ \t]*$/;
const TASK_NAME_RE = /^[ \t]+- name:[ \t]+(.*)$/;
const TASK_START_RE = /^[ \t]*- name:/;
const MODULE_RE = /^[ \t]+((?:ansible|community)\.[a-z_.]+):[ \t]*/;
const TOP_LEVEL_RE = /^\S/;
const QUOTE_RE = /["']/g;
const DASH_RE = /^([ \t]*)-([ \t]+)(.*)$/;
const KV_RE = /^([^:]+)(:)(.*)$/;
const NUMBER_RE = /^[ \t]+\d+(\.\d+)?$/;
const BOOL_RE = /^[ \t]+(true|false|null|yes|no)\b/;
const STRING_RE = /^[ \t]+["']/;
const JINJA_RE = /\{\{.*\}\}/;

function PlaybookLibrary({ playbooks, selectedId, onSelect, onNew }) {
  const [q, setQ] = useStateP('');
  const filter = q.toLowerCase();
  const rows = playbooks.filter(p =>
    !filter ||
    p.name.toLowerCase().includes(filter) ||
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
              <span className="pb-lib-name mono">{p.name}</span>
              <span className={`dot ${p.lastStatus}`} title={`last: ${p.lastStatus}`}/>
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
  if (JINJA_RE.test(rest)) return <span className="yml-j">{rest}</span>;
  return <span className="yml-v">{rest}</span>;
}

function PlaybooksView({ initialId }) {
  const data = globalThis.AnsibleData || {};
  const PLAYBOOKS = data.PLAYBOOKS || [];
  const [selectedId, setSelectedId] = useStateP(initialId || PLAYBOOKS[0]?.id || '');
  const [yaml, setYaml] = useStateP('');
  const [draft, setDraft] = useStateP('');
  const [editing, setEditing] = useStateP(false);
  const [saving, setSaving] = useStateP(false);
  const [error, setError] = useStateP('');
  const [runnerOpen, setRunnerOpen] = useStateP(false);
  const [historyOpen, setHistoryOpen] = useStateP(false);
  const [importOpen, setImportOpen] = useStateP(false);

  const pb = PLAYBOOKS.find(p => p.id === selectedId) || PLAYBOOKS[0];

  useEffectP(() => {
    setEditing(false);
    setError('');
    if (!pb) { setYaml(''); setDraft(''); return; }
    if (pb.yaml) { setYaml(pb.yaml); setDraft(pb.yaml); return; }
    if (!pb.path || !globalThis.RelayAPI) return;
    let alive = true;
    globalThis.RelayAPI.getPlaybook(pb.path)
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
    if (!pb?.path || !globalThis.RelayAPI) return;
    setSaving(true); setError('');
    try {
      await globalThis.RelayAPI.savePlaybook(pb.path, draft);
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

      <div className="pb-body">
        <PlaybookLibrary playbooks={PLAYBOOKS} selectedId={selectedId} onSelect={setSelectedId} onNew={() => setImportOpen(true)}/>

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
                <div><span className="section-title">Last run</span><div>{pb.lastRun || '—'} {pb.lastStatus && <span className={`dot ${pb.lastStatus}`} style={{ marginLeft: 6 }}/>}</div></div>
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
      <PlaybookRunner open={runnerOpen} pb={pb} onClose={() => setRunnerOpen(false)}/>
      <PlaybookHistoryDialog open={historyOpen} pb={pb} onClose={() => setHistoryOpen(false)}/>
      <PlaybookImportDialog open={importOpen} onClose={() => setImportOpen(false)} onImported={(newPath) => {
        setImportOpen(false);
        globalThis.RelayAPI?.bootstrap().catch(() => {});
      }}/>
    </div>
  );
}

function PlaybookRunner({ open, pb, onClose }) {
  const dialogRef = globalThis.useDialog(open, onClose);
  const [limit, setLimit] = useStateP('');
  const [tagsRaw, setTagsRaw] = useStateP('');
  const [check, setCheck] = useStateP(false);
  const [become, setBecome] = useStateP(false);
  const [running, setRunning] = useStateP(false);
  const [output, setOutput] = useStateP([]);
  // vars are stored as an ordered list of {key, value} rows so empty
  // rows remain in the UI while the user is typing.
  const [vars, setVars] = useStateP([{ key: '', type: 'string', value: '' }]);
  const [varsError, setVarsError] = useStateP('');
  const streamRef = useRefP(null);
  const outRef = useRefP(null);

  const setVarAt = (i, patch) => setVars(prev => prev.map((row, j) => (j === i ? { ...row, ...patch } : row)));
  const addVar = () => setVars(prev => [...prev, { key: '', type: 'string', value: '' }]);
  const removeVar = (i) => setVars(prev => prev.filter((_, j) => j !== i));

  useEffectP(() => {
    if (!open) {
      // close any stream when dialog is dismissed
      if (streamRef.current) { streamRef.current.close(); streamRef.current = null; }
      setOutput([]);
      setRunning(false);
    }
  }, [open]);

  useEffectP(() => () => { if (streamRef.current) streamRef.current.close(); }, []);

  useEffectP(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  const run = () => {
    if (running || !pb || !globalThis.RelayAPI) return;
    setOutput([]); setRunning(true);
    const start = Date.now();
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

    const stream = globalThis.RelayAPI.openStream('playbook', payload);
    streamRef.current = stream;

    let finished = false;
    const finish = (text) => {
      if (finished) return;
      finished = true;
      appendLog({ t: 'done', text });
      setRunning(false);
      stream.close();
      streamRef.current = null;
    };

    stream.onEvent((evt) => {
      const kind = PB_EVENT_MAPPING[evt.type];
      if (kind) { appendLog({ t: kind, text: evt.text || '' }); return; }
      if (evt.type === 'done') {
        finish(evt.text || `completed in ${((Date.now() - start) / 1000).toFixed(1)}s`);
        return;
      }
      if (evt.type === 'run-complete') {
        finish(`completed in ${((Date.now() - start) / 1000).toFixed(1)}s`);
      }
    });
    stream.onClose(() => { setRunning(false); streamRef.current = null; });
    stream.onError(() => {
      appendLog({ t: 'fail', text: 'WebSocket error — check backend logs.' });
      setRunning(false);
    });
  };

  if (!pb) return <dialog ref={dialogRef} className="relay-dialog relay-dialog-runner" aria-hidden="true"/>;

  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-runner"
      aria-label={`Run ${pb.name}`}
      onClick={(e) => { if (e.target === dialogRef.current) onClose(); }}
    >
      <div className="pb-runner card">
        <div className="pb-runner-head">
          <div>
            <div className="section-title">Run playbook</div>
            <h3 className="mono" style={{ margin: '4px 0 0' }}>{pb.name}</h3>
            <div className="mute" style={{ fontSize: 12 }}>
              hosts: <span className="mono">{pb.targets || 'all'}</span>
            </div>
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>

        <div className="pb-runner-form">
          <label htmlFor="pb-limit" className="cm-field-label">Limit (optional — overrides hosts:)</label>
          <input id="pb-limit" className="input mono" placeholder={pb.targets || 'e.g. webservers, host1.example.com'} value={limit} onChange={e => setLimit(e.target.value)}/>

          <label htmlFor="pb-tags" className="cm-field-label">Tags (comma-separated, optional)</label>
          <input id="pb-tags" className="input mono" placeholder="deploy, config" value={tagsRaw} onChange={e => setTagsRaw(e.target.value)}/>

          <div className="cm-field-label" style={{ marginTop: 8 }}>Extra variables (--extra-vars)</div>
          <div className="pb-vars">
            {vars.map((row, i) => (
              <PlaybookVarRow
                key={i}
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
            <button type="button" className="btn primary small" onClick={run} disabled={running}>
              <Icon name="play" size={12}/> {running ? 'Running…' : 'Run'}
            </button>
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
        throw new Error(`row ${idx + 1} (${key}): "${row.value}" is not a number`);
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
        throw new Error(`row ${idx + 1} (${key}): invalid JSON — ${e.message}`);
      }
    }
  });
  return out;
}

// ---------- History dialog ----------

function PlaybookHistoryDialog({ open, pb, onClose }) {
  const dialogRef = globalThis.useDialog(open, onClose);
  const [runs, setRuns] = useStateP([]);
  const [loading, setLoading] = useStateP(false);
  const [error, setError] = useStateP('');

  useEffectP(() => {
    if (!open || !pb || !globalThis.RelayAPI) return;
    setLoading(true); setError('');
    let alive = true;
    globalThis.RelayAPI.listRuns()
      .then(res => {
        if (!alive) return;
        const all = res.runs || [];
        const mine = all.filter(r => r.playbook === pb.path || r.playbook === pb.name);
        setRuns(mine);
      })
      .catch(e => { if (alive) setError(e.message); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [open, pb?.id]);

  if (!pb) return <dialog ref={dialogRef} className="relay-dialog relay-dialog-center" aria-hidden="true"/>;

  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-center"
      aria-label={`Run history for ${pb.name}`}
      onClick={(e) => { if (e.target === dialogRef.current) onClose(); }}
    >
      <div className="cm" style={{ width: 'min(720px, 94vw)', maxHeight: '70vh' }}>
        <div className="cm-head">
          <div>
            <div className="section-title">Run history</div>
            <div className="mono" style={{ marginTop: 2 }}>{pb.name}</div>
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>
        <div className="cm-body cm-single">
          <div className="cm-pane">
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
                      <td><span className={`dot ${r.status}`}/></td>
                      <td className="mono" style={{ fontSize: 12 }}>{r.startedAt ? new Date(r.startedAt).toLocaleString() : '—'}</td>
                      <td className="mono">{r.duration || '—'}</td>
                      <td className="mono" style={{ color: 'var(--ok)' }}>{r.ok || 0}</td>
                      <td className="mono" style={{ color: 'var(--warn)' }}>{r.changed || 0}</td>
                      <td className="mono" style={{ color: r.failed ? 'var(--err)' : undefined }}>{r.failed || 0}</td>
                      <td className="mute">{r.who || ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </dialog>
  );
}

// ---------- Import dialog ----------

const PATH_SEGMENT_RE = /^[A-Za-z0-9._-]+$/;

function PlaybookImportDialog({ open, onClose, onImported }) {
  const dialogRef = globalThis.useDialog(open, onClose);
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
      await globalThis.RelayAPI.savePlaybook(trimmed, yaml);
      onImported?.(trimmed);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-center"
      aria-label="Import playbook"
      onClick={(e) => { if (e.target === dialogRef.current) onClose(); }}
    >
      <div className="cm" style={{ width: 'min(720px, 94vw)', maxHeight: '82vh' }}>
        <div className="cm-head">
          <div>
            <div className="section-title">Import playbook</div>
            <div className="mute" style={{ fontSize: 12, marginTop: 2 }}>
              Upload a .yml/.yaml file or paste content below. It will be written to your server's workDir.
            </div>
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>
        <div className="cm-body cm-single">
          <div className="cm-pane">
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
          </div>
        </div>
      </div>
    </dialog>
  );
}

globalThis.PlaybooksView = PlaybooksView;
