// Playbooks view — library (left) + split editor (visual tasks ↔ YAML).

const { useState: useStateP, useMemo: useMemoP, useEffect: useEffectP } = React;

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

function VisualStructure({ yaml, playbook }) {
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
            <span className="mono">{playbook.targets}</span>
          </div>
          <div className="vs-meta-item">
            <span className="section-title">become</span>
            <span className="mono">true</span>
          </div>
          <div className="vs-meta-item">
            <span className="section-title">strategy</span>
            <span className="mono">linear</span>
          </div>
        </div>
      </div>
      <TaskGroup label="Pre-tasks" items={grouped.pre_tasks} tone="pre"/>
      <TaskGroup label="Tasks" items={grouped.tasks} tone="main"/>
      <TaskGroup label="Post-tasks" items={grouped.post_tasks} tone="post"/>
      <TaskGroup label="Handlers" items={grouped.handlers} tone="handlers"/>
    </div>
  );
}

function TaskGroup({ label, items, tone }) {
  if (!items.length) return null;
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
            <button type="button" className="vs-task-drag" title="drag to reorder"><Icon name="more" size={14}/></button>
          </div>
        ))}
        <button type="button" className="vs-add"><Icon name="plus" size={12}/> Add task</button>
      </div>
    </div>
  );
}

function YamlEditor({ value, onSave }) {
  const lines = value.split('\n');
  return (
    <div className="code-pane flex-1">
      <div className="code-head">
        <div className="mono mute" style={{ fontSize: 11.5 }}>playbooks/edit.yml</div>
        <div className="code-head-actions">
          <span className="pill ok"><Icon name="check" size={10}/> syntax ok</span>
          <button type="button" className="btn ghost small"><Icon name="refresh" size={11}/> Format</button>
          <button type="button" className="btn small" onClick={onSave}><Icon name="download" size={11}/> Save</button>
        </div>
      </div>
      <div className="code-body">
        <div className="code-gutter mono">
          <pre style={{ margin: 0 }}>{Array.from({ length: lines.length }, (_, i) => i + 1).join('\n')}</pre>
        </div>
        <pre className="code-block code-block-edit">
          <code>{highlightYamlFull(value)}</code>
        </pre>
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

function PlaybooksView({ initialId, onRun }) {
  const data = globalThis.AnsibleData || {};
  const PLAYBOOKS = data.PLAYBOOKS || [];
  const [selectedId, setSelectedId] = useStateP(initialId || PLAYBOOKS[0]?.id || '');
  const [yaml, setYaml] = useStateP('');
  const [error, setError] = useStateP('');

  const pb = PLAYBOOKS.find(p => p.id === selectedId) || PLAYBOOKS[0];

  useEffectP(() => {
    if (!pb) { setYaml(''); return; }
    if (pb.yaml) { setYaml(pb.yaml); return; }
    if (!pb.path || !globalThis.RelayAPI) return;
    let alive = true;
    globalThis.RelayAPI.getPlaybook(pb.path)
      .then(res => {
        if (!alive) return;
        pb.yaml = res.yaml || '';
        setYaml(pb.yaml);
      })
      .catch(e => { if (alive) { setError(e.message); setYaml(''); } });
    return () => { alive = false; };
  }, [pb?.id]);

  useEffectP(() => { if (initialId) setSelectedId(initialId); }, [initialId]);

  const savePlaybook = async () => {
    if (!pb?.path || !globalThis.RelayAPI) return;
    setError('');
    try {
      await globalThis.RelayAPI.savePlaybook(pb.path, yaml);
      pb.yaml = yaml;
    } catch (e) { setError(e.message); }
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
          <button type="button" className="btn small"><Icon name="download" size={12}/> Import</button>
          <button type="button" className="btn small"><Icon name="code" size={12}/> History</button>
          <button type="button" className="btn primary small" onClick={() => onRun(pb.id)}><Icon name="play" size={12}/> Run…</button>
        </div>
      </div>

      {error && <div className="cm-error mono">{error}</div>}

      <div className="pb-body">
        <PlaybookLibrary playbooks={PLAYBOOKS} selectedId={selectedId} onSelect={setSelectedId} onNew={() => {}}/>

        <main className="pb-main">
          <div className="pb-head card">
            <div className="pb-head-top">
              <div>
                <div className="section-title">Playbook</div>
                <h2 className="pb-title">{pb.title} <span className="mono mute" style={{ fontWeight: 400, fontSize: 14, marginLeft: 8 }}>{pb.name}</span></h2>
                <div className="mute">{pb.description}</div>
              </div>
              <div className="pb-head-stats">
                <div><span className="section-title">Targets</span><div className="mono">{pb.targets}</div></div>
                <div><span className="section-title">Last run</span><div>{pb.lastRun} <span className={`dot ${pb.lastStatus}`} style={{ marginLeft: 6 }}/></div></div>
                <div><span className="section-title">Avg duration</span><div className="mono">{pb.avgDuration}</div></div>
                <div><span className="section-title">Runs</span><div className="mono">{pb.runs}</div></div>
              </div>
            </div>
            <div className="pb-head-tags">
              {(pb.tags || []).map(t => <span key={t} className="chip on"><Icon name="tag" size={10}/><span className="mono">{t}</span></span>)}
              <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>by {pb.author}</span>
            </div>
          </div>

          <div className="pb-split">
            <div className="pb-split-pane pb-visual card">
              <div className="pb-split-head">
                <span className="section-title">Structure</span>
                <span className="mute mono" style={{ fontSize: 11 }}>drag to reorder</span>
              </div>
              <VisualStructure yaml={yaml} playbook={pb}/>
            </div>
            <div className="pb-split-pane pb-yaml card">
              <div className="pb-split-head">
                <span className="section-title">YAML</span>
                <span className="mute mono" style={{ fontSize: 11 }}>{yaml.split('\n').length} lines</span>
              </div>
              <YamlEditor value={yaml} onSave={savePlaybook}/>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

globalThis.PlaybooksView = PlaybooksView;
