// Playbooks view — library (left) + split editor (visual tasks ↔ YAML)

const { useState: useStateP, useMemo: useMemoP, useEffect: useEffectP } = React;

function PlaybookLibrary({ playbooks, selectedId, onSelect, onNew }) {
  const [q, setQ] = useStateP('');
  const rows = playbooks.filter(p => !q || p.name.includes(q) || p.title.toLowerCase().includes(q.toLowerCase()));
  return (
    <aside className="pb-lib card">
      <div className="pb-lib-head">
        <div className="section-title">Playbooks · {playbooks.length}</div>
        <button className="btn primary small" onClick={onNew}><Icon name="plus" size={12}/> New</button>
      </div>
      <div className="pb-lib-search">
        <Icon name="search" size={12} className="mute-2"/>
        <input className="input" value={q} onChange={e => setQ(e.target.value)} placeholder="Filter playbooks" style={{ border: 0, background: 'transparent', paddingLeft: 6, height: 26 }}/>
      </div>
      <div className="pb-lib-list">
        {rows.map(p => (
          <button key={p.id} className={`pb-lib-item ${selectedId === p.id ? 'active' : ''}`} onClick={() => onSelect(p.id)}>
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

// Very light YAML parser for task block detection — only what we need
function parseYamlTasks(yaml) {
  // Find top-level task-ish lines (look for "- name:" under tasks:/pre_tasks:/post_tasks:/handlers:)
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
      current = { section, name: task[2].replace(/["']/g, ''), lines: [l], startLine: i };
    } else if (current) {
      if (l.match(/^(\s*)- name:/) || /^\S/.test(l)) {
        blocks.push(current);
        current = null;
        i--; // reprocess
      } else {
        current.lines.push(l);
      }
    }
  }
  if (current) blocks.push(current);
  // Detect module from lines
  return blocks.map(b => {
    let module = '';
    for (const ln of b.lines) {
      const m = ln.match(/^\s+(ansible\.[a-z_.]+|community\.[a-z_.]+):\s*$/) || ln.match(/^\s+(ansible\.[a-z_.]+|community\.[a-z_.]+):\s+/);
      if (m) { module = m[1]; break; }
    }
    return { ...b, module };
  });
}

function VisualStructure({ yaml, playbook }) {
  const tasks = useMemoP(() => parseYamlTasks(yaml), [yaml]);
  const grouped = {
    pre_tasks: tasks.filter(t => t.section === 'pre_tasks'),
    tasks: tasks.filter(t => t.section === 'tasks'),
    post_tasks: tasks.filter(t => t.section === 'post_tasks'),
    handlers: tasks.filter(t => t.section === 'handlers')
  };

  const renderGroup = (label, items, tone) => {
    if (!items.length) return null;
    return (
      <div className={`vs-group vs-${tone}`}>
        <div className="vs-group-head">
          <span className="section-title">{label}</span>
          <span className="mute mono">{items.length}</span>
        </div>
        <div className="vs-tasks">
          {items.map((t, i) => (
            <div className="vs-task" key={i}>
              <div className="vs-task-idx mono mute-2">{String(i + 1).padStart(2, '0')}</div>
              <div className="vs-task-body">
                <div className="vs-task-name">{t.name}</div>
                <div className="vs-task-mod mono mute">{t.module || '—'}</div>
              </div>
              <button className="vs-task-drag" title="drag to reorder"><Icon name="more" size={14}/></button>
            </div>
          ))}
          <button className="vs-add"><Icon name="plus" size={12}/> Add task</button>
        </div>
      </div>
    );
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

      {renderGroup('Pre-tasks', grouped.pre_tasks, 'pre')}
      {renderGroup('Tasks', grouped.tasks, 'main')}
      {renderGroup('Post-tasks', grouped.post_tasks, 'post')}
      {renderGroup('Handlers', grouped.handlers, 'handlers')}
    </div>
  );
}

function YamlEditor({ value, onChange }) {
  const lines = value.split('\n');
  return (
    <div className="code-pane flex-1">
      <div className="code-head">
        <div className="mono mute" style={{ fontSize: 11.5 }}>playbooks/edit.yml</div>
        <div className="code-head-actions">
          <span className="pill ok"><Icon name="check" size={10}/> syntax ok</span>
          <button className="btn ghost small"><Icon name="refresh" size={11}/> Format</button>
          <button className="btn small"><Icon name="download" size={11}/> Save</button>
        </div>
      </div>
      <div className="code-body">
        <div className="code-gutter mono">
          {lines.map((_, i) => <div key={i}>{i + 1}</div>)}
        </div>
        <pre className="code-block code-block-edit">
          <code>{highlightYamlFull(value)}</code>
        </pre>
      </div>
    </div>
  );
}

function highlightYamlFull(src) {
  const lines = src.split('\n');
  return lines.map((line, i) => {
    const out = [];
    if (/^\s*#/.test(line)) {
      out.push(<span className="yml-c" key="c">{line}</span>);
    } else if (/^---/.test(line)) {
      out.push(<span className="yml-c" key="doc">{line}</span>);
    } else {
      const dashMatch = line.match(/^(\s*)-(\s+)(.*)$/);
      if (dashMatch && !dashMatch[3].startsWith('name:')) {
        out.push(dashMatch[1]);
        out.push(<span className="yml-d" key="d">-</span>);
        out.push(dashMatch[2]);
        out.push(...colorizeKV(dashMatch[3]));
      } else if (dashMatch) {
        out.push(dashMatch[1]);
        out.push(<span className="yml-d" key="d">-</span>);
        out.push(dashMatch[2]);
        out.push(...colorizeKV(dashMatch[3]));
      } else {
        out.push(...colorizeKV(line));
      }
    }
    return <span key={i}>{out}{'\n'}</span>;
  });
}

function colorizeKV(s) {
  const m = s.match(/^([^:]+)(:)(.*)$/);
  if (!m) return [s];
  const out = [];
  out.push(<span className="yml-k" key="k">{m[1]}</span>);
  out.push(<span className="yml-p" key="p">{m[2]}</span>);
  const rest = m[3];
  if (!rest) return out;
  if (/^\s+\d+(\.\d+)?$/.test(rest)) out.push(<span className="yml-n" key="v">{rest}</span>);
  else if (/^\s+(true|false|null|yes|no)\b/.test(rest)) out.push(<span className="yml-b" key="v">{rest}</span>);
  else if (/^\s+["']/.test(rest)) out.push(<span className="yml-s" key="v">{rest}</span>);
  else if (/\{\{.*\}\}/.test(rest)) out.push(<span className="yml-j" key="v">{rest}</span>);
  else out.push(<span className="yml-v" key="v">{rest}</span>);
  return out;
}

function PlaybooksView({ initialId, onRun }) {
  const { PLAYBOOKS } = window.AnsibleData;
  const [selectedId, setSelectedId] = useStateP(initialId || PLAYBOOKS[0]?.id || '');
  const [yaml, setYaml] = useStateP('');

  const pb = PLAYBOOKS.find(p => p.id === selectedId) || PLAYBOOKS[0];

  useEffectP(() => {
    if (!pb) { setYaml(''); return; }
    if (pb.yaml) { setYaml(pb.yaml); return; }
    if (pb.path && window.RelayAPI) {
      window.RelayAPI.getPlaybook(pb.path).then(res => {
        pb.yaml = res.yaml || '';
        setYaml(pb.yaml);
      }).catch(() => setYaml(''));
    }
  }, [pb?.id]);
  useEffectP(() => { if (initialId) setSelectedId(initialId); }, [initialId]);

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
          <button className="btn small"><Icon name="download" size={12}/> Import</button>
          <button className="btn small"><Icon name="code" size={12}/> History</button>
          <button className="btn primary small" onClick={() => onRun(pb.id)}><Icon name="play" size={12}/> Run…</button>
        </div>
      </div>

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
              {pb.tags.map(t => <span key={t} className="chip on"><Icon name="tag" size={10}/><span className="mono">{t}</span></span>)}
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
              <YamlEditor value={yaml} onChange={setYaml}/>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

window.PlaybooksView = PlaybooksView;
