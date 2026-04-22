// Inventory view — 5 modes: Table+Tree, Graph, Map, Tags, YAML
// Modes toggle via segmented control at the top.

const { useState: useStateI, useMemo: useMemoI, useRef: useRefI, useEffect: useEffectI } = React;

// ---------- Tree ----------
function InventoryTree({ expanded, setExpanded, selectedGroup, setSelectedGroup, hosts, groups }) {
  const children = (parent) => groups.filter(g => g.parent === parent);
  const countHosts = (groupId) => hosts.filter(h => h.groups.includes(groupId)).length;

  const Node = ({ g, depth }) => {
    const kids = children(g.id);
    const isOpen = expanded[g.id] ?? (depth < 2);
    const hostCount = countHosts(g.id);
    return (
      <div>
        <button
          className={`tree-row ${selectedGroup === g.id ? 'active' : ''}`}
          style={{ paddingLeft: 8 + depth * 14 }}
          onClick={() => setSelectedGroup(g.id)}
        >
          {kids.length > 0 ? (
            <span
              className="tree-caret"
              onClick={(e) => { e.stopPropagation(); setExpanded({ ...expanded, [g.id]: !isOpen }); }}
            >
              <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={11}/>
            </span>
          ) : (
            <span className="tree-caret" />
          )}
          <span className="tree-icon">
            <Icon name={g.parent ? 'group' : 'globe'} size={13}/>
          </span>
          <span className="tree-name mono">{g.name}</span>
          <span className="tree-count mute">{hostCount}</span>
        </button>
        {isOpen && kids.map(k => <Node key={k.id} g={k} depth={depth + 1} />)}
      </div>
    );
  };
  const roots = groups.filter(g => g.parent === null);
  return <div className="tree">{roots.map(r => <Node key={r.id} g={r} depth={0} />)}</div>;
}

// ---------- Table ----------
function HostTable({ rows, selectedIds, toggleSelect, toggleAll, onRowClick, sort, setSort }) {
  const allSelected = rows.length > 0 && rows.every(r => selectedIds.has(r.id));
  const someSelected = !allSelected && rows.some(r => selectedIds.has(r.id));
  const sortArrow = (key) => sort.key === key ? (sort.dir === 'asc' ? '↑' : '↓') : '';
  const col = (key, label, cls) => (
    <th className={cls} onClick={() => setSort({ key, dir: sort.key === key && sort.dir === 'asc' ? 'desc' : 'asc' })}>
      {label} <span className="mute mono">{sortArrow(key)}</span>
    </th>
  );
  return (
    <div className="host-table-wrap">
      <table className="t host-table">
        <thead>
          <tr>
            <th style={{ width: 28 }}>
              <input type="checkbox" checked={allSelected} ref={el => el && (el.indeterminate = someSelected)} onChange={toggleAll}/>
            </th>
            <th style={{ width: 26 }}></th>
            {col('name', 'Host')}
            {col('ip', 'Address')}
            {col('os', 'OS')}
            <th>Groups</th>
            {col('cpu', 'CPU')}
            {col('mem', 'Mem')}
            {col('load', 'Load')}
            {col('lastPlaybook', 'Last play')}
          </tr>
        </thead>
        <tbody>
          {rows.map(h => (
            <tr key={h.id} className={`t-row-click ${selectedIds.has(h.id) ? 'selected' : ''}`} onClick={() => onRowClick(h)}>
              <td onClick={(e) => e.stopPropagation()}>
                <input type="checkbox" checked={selectedIds.has(h.id)} onChange={() => toggleSelect(h.id)}/>
              </td>
              <td><span className={`dot ${h.status}`}/></td>
              <td className="mono" style={{ color: 'var(--text)' }}>{h.name}</td>
              <td className="mono mute">{h.ip}</td>
              <td className="mute" style={{ fontSize: 12 }}>{h.os}</td>
              <td>
                <div className="tag-cluster">
                  {h.groups.filter(g => g !== 'all').slice(0, 3).map(g => <span key={g} className="mini-tag mono">{g}</span>)}
                  {h.groups.length > 4 && <span className="mini-tag mute mono">+{h.groups.length - 4}</span>}
                </div>
              </td>
              <td>
                <MiniBar value={h.cpu} />
              </td>
              <td>
                <MiniBar value={h.mem} warn={70} danger={90}/>
              </td>
              <td className="mono">{h.load.toFixed(2)}</td>
              <td className="mono mute">{h.lastPlaybook}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function MiniBar({ value, warn = 70, danger = 90 }) {
  const color = value >= danger ? 'var(--err)' : value >= warn ? 'var(--warn)' : 'var(--accent)';
  return (
    <div className="mini-bar-wrap">
      <div className="mini-bar"><div style={{ width: `${value}%`, background: color }}/></div>
      <span className="mini-bar-val mono">{value}</span>
    </div>
  );
}

// ---------- Graph ----------
function InventoryGraph({ groups, hosts, onSelectGroup }) {
  // Layout: concentric rings. 'all' center, tier 1 ring, tier 2 ring (with nested positioning).
  const tier = (g) => {
    let t = 0, cur = g;
    while (cur && cur.parent) { t++; cur = groups.find(x => x.id === cur.parent); }
    return t;
  };
  const W = 760, H = 560, CX = W / 2, CY = H / 2;
  const positioned = useMemoI(() => {
    const byTier = { 0: [], 1: [], 2: [] };
    groups.forEach(g => {
      const t = Math.min(2, tier(g));
      byTier[t].push(g);
    });
    const radii = { 0: 0, 1: 140, 2: 250 };
    const result = {};
    Object.entries(byTier).forEach(([t, list]) => {
      list.forEach((g, i) => {
        const ang = (i / list.length) * Math.PI * 2 - Math.PI / 2;
        const r = radii[t];
        result[g.id] = { x: CX + Math.cos(ang) * r, y: CY + Math.sin(ang) * r, tier: +t };
      });
    });
    return result;
  }, [groups]);

  return (
    <div className="graph-wrap">
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} className="graph-svg" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id="gg" cx="50%" cy="50%">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.12"/>
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0"/>
          </radialGradient>
        </defs>
        <circle cx={CX} cy={CY} r="260" fill="url(#gg)"/>
        <circle cx={CX} cy={CY} r="140" fill="none" stroke="var(--line-soft)" strokeDasharray="2 4"/>
        <circle cx={CX} cy={CY} r="250" fill="none" stroke="var(--line-soft)" strokeDasharray="2 4"/>

        {/* Edges */}
        {groups.filter(g => g.parent).map(g => {
          const p = positioned[g.id], pp = positioned[g.parent];
          if (!p || !pp) return null;
          return <line key={g.id} x1={pp.x} y1={pp.y} x2={p.x} y2={p.y} stroke="var(--line)" strokeWidth="1"/>;
        })}
        {/* Host leaves for tier-2 groups */}
        {groups.map(g => {
          const p = positioned[g.id];
          if (!p || p.tier !== 2) return null;
          const gHosts = hosts.filter(h => h.groups.includes(g.id));
          const count = Math.min(12, gHosts.length);
          const ang0 = Math.atan2(p.y - CY, p.x - CX);
          return gHosts.slice(0, count).map((h, i) => {
            const spread = 0.55;
            const ang = ang0 + (i - count / 2) * (spread / count);
            const r = 62;
            const hx = p.x + Math.cos(ang) * r;
            const hy = p.y + Math.sin(ang) * r;
            const color = h.status === 'ok' ? 'var(--ok)' : h.status === 'warn' ? 'var(--warn)' : 'var(--err)';
            return (
              <g key={h.id}>
                <line x1={p.x} y1={p.y} x2={hx} y2={hy} stroke="var(--line-soft)" strokeWidth="0.8"/>
                <circle cx={hx} cy={hy} r="3" fill={color}>
                  <title>{h.name}</title>
                </circle>
              </g>
            );
          });
        })}
        {/* Nodes */}
        {groups.map(g => {
          const p = positioned[g.id];
          if (!p) return null;
          const size = p.tier === 0 ? 32 : p.tier === 1 ? 24 : 18;
          const count = hosts.filter(h => h.groups.includes(g.id)).length;
          return (
            <g key={g.id} className="graph-node" onClick={() => onSelectGroup(g.id)} style={{ cursor: 'pointer' }}>
              <circle cx={p.x} cy={p.y} r={size} fill="var(--bg-2)" stroke="var(--accent)" strokeWidth="1.5"/>
              <circle cx={p.x} cy={p.y} r={size - 4} fill="var(--bg-1)"/>
              <text x={p.x} y={p.y - 2} textAnchor="middle" fontSize={p.tier === 0 ? 12 : 11} fontFamily="var(--font-mono)" fill="var(--text)">{g.name}</text>
              <text x={p.x} y={p.y + 10} textAnchor="middle" fontSize="9" fontFamily="var(--font-mono)" fill="var(--text-3)">{count}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ---------- Map ----------
function InventoryMap({ hosts }) {
  const regions = [
    { id: 'us_east', name: 'us-east-1', x: 280, y: 235, label: 'N. Virginia' },
    { id: 'us_west', name: 'us-west-2', x: 160, y: 225, label: 'Oregon' },
    { id: 'eu_west', name: 'eu-west-1', x: 500, y: 210, label: 'Ireland' }
  ];
  const byRegion = (rid) => hosts.filter(h => h.region === rid);
  return (
    <div className="map-wrap">
      <svg width="100%" height="560" viewBox="0 0 900 480" preserveAspectRatio="xMidYMid meet" className="map-svg">
        {/* Simplified world dot-grid */}
        <g opacity="0.35">
          {Array.from({ length: 30 }).map((_, r) =>
            Array.from({ length: 60 }).map((_, c) => {
              // Rough landmass approximation using sinusoidal bands
              const x = 50 + c * 13;
              const y = 50 + r * 13;
              const seed = Math.sin(c * 0.28) * 20 + Math.cos(r * 0.5) * 20;
              const in1 = (c > 8 && c < 22 && r > 4 && r < 20 && seed > -5); // americas
              const in2 = (c > 26 && c < 38 && r > 3 && r < 15); // europe/africa
              const in3 = (c > 40 && c < 58 && r > 4 && r < 18); // asia
              if (!(in1 || in2 || in3)) return null;
              return <circle key={`${r}-${c}`} cx={x} cy={y} r="1.4" fill="var(--text-4)" opacity="0.45"/>;
            })
          )}
        </g>

        {/* Connection arcs */}
        {regions.map((a, i) => regions.slice(i + 1).map((b) => (
          <path key={`${a.id}-${b.id}`}
            d={`M${a.x},${a.y} Q${(a.x + b.x) / 2},${Math.min(a.y, b.y) - 60} ${b.x},${b.y}`}
            fill="none" stroke="var(--accent)" strokeOpacity="0.3" strokeDasharray="3 4" strokeWidth="1"/>
        )))}

        {regions.map(rg => {
          const hs = byRegion(rg.id);
          const ok = hs.filter(h => h.status === 'ok').length;
          const warn = hs.filter(h => h.status === 'warn').length;
          const err = hs.filter(h => h.status === 'err').length;
          return (
            <g key={rg.id} className="map-region">
              <circle cx={rg.x} cy={rg.y} r="28" fill="var(--accent-weak)" stroke="none"/>
              <circle cx={rg.x} cy={rg.y} r="42" fill="none" stroke="var(--accent)" strokeOpacity="0.3" strokeDasharray="2 3">
                <animate attributeName="r" values="30;50;30" dur="3s" repeatCount="indefinite"/>
                <animate attributeName="stroke-opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite"/>
              </circle>
              <circle cx={rg.x} cy={rg.y} r="6" fill="var(--accent)"/>
              <g transform={`translate(${rg.x + 14}, ${rg.y - 24})`}>
                <rect x="0" y="0" width="150" height="52" rx="6" fill="var(--bg-2)" stroke="var(--line)"/>
                <text x="10" y="16" fontSize="11" fontFamily="var(--font-mono)" fontWeight="600" fill="var(--text)">{rg.name}</text>
                <text x="10" y="29" fontSize="9.5" fill="var(--text-3)">{rg.label} · {hs.length} hosts</text>
                <g transform="translate(10, 40)">
                  <circle cx="0" cy="0" r="3" fill="var(--ok)"/>
                  <text x="7" y="3" fontSize="9.5" fontFamily="var(--font-mono)" fill="var(--text-2)">{ok}</text>
                  <circle cx="38" cy="0" r="3" fill="var(--warn)"/>
                  <text x="45" y="3" fontSize="9.5" fontFamily="var(--font-mono)" fill="var(--text-2)">{warn}</text>
                  <circle cx="76" cy="0" r="3" fill="var(--err)"/>
                  <text x="83" y="3" fontSize="9.5" fontFamily="var(--font-mono)" fill="var(--text-2)">{err}</text>
                </g>
              </g>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ---------- Tags ----------
function InventoryTags({ hosts, filters, setFilters }) {
  const allTags = Array.from(new Set(hosts.flatMap(h => h.tags || []))).sort();
  const allOS = Array.from(new Set(hosts.map(h => h.os))).sort();
  const matches = hosts.filter(h =>
    (!filters.tags.length || filters.tags.every(t => h.tags.includes(t))) &&
    (!filters.os.length || filters.os.includes(h.os))
  );
  const toggleSet = (key, v) => {
    const set = new Set(filters[key]);
    set.has(v) ? set.delete(v) : set.add(v);
    setFilters({ ...filters, [key]: [...set] });
  };
  return (
    <div className="tags-wrap">
      <div className="tags-builder card">
        <div className="section-title">Build a selector</div>
        <div className="tags-group">
          <div className="tags-group-label">tags</div>
          <div className="tag-cluster">
            {allTags.map(t => (
              <button key={t} className={`chip ${filters.tags.includes(t) ? 'on' : ''}`} onClick={() => toggleSet('tags', t)}>
                <Icon name="tag" size={11}/> <span className="mono">{t}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="tags-group">
          <div className="tags-group-label">os</div>
          <div className="tag-cluster">
            {allOS.map(t => (
              <button key={t} className={`chip ${filters.os.includes(t) ? 'on' : ''}`} onClick={() => toggleSet('os', t)}>
                <span className="mono">{t}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="tags-sel">
          <div className="section-title">Resolved selector</div>
          <div className="tags-selector mono">
            {[...filters.tags.map(t => `tag:${t}`), ...filters.os.map(o => `os:"${o}"`)].join(' AND ') || 'all'}
          </div>
          <div className="mute" style={{ marginTop: 8, fontSize: 12 }}>
            Matches <b style={{ color: 'var(--text)' }}>{matches.length}</b> of {hosts.length} hosts
          </div>
        </div>
      </div>
      <div className="tags-results card">
        <div className="section-title">Preview</div>
        <div className="tags-results-grid">
          {matches.slice(0, 80).map(h => (
            <div key={h.id} className="tags-result-chip">
              <span className={`dot ${h.status}`}/>
              <span className="mono">{h.name}</span>
              <span className="mute mono">{h.ip}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------- YAML ----------
function InventoryYAML({ groups, hosts }) {
  const tree = useMemoI(() => {
    const build = (parent, depth) => {
      let out = '';
      const pad = '  '.repeat(depth);
      const kids = groups.filter(g => g.parent === parent);
      for (const g of kids) {
        const gHosts = hosts.filter(h => h.groups.includes(g.id) && h.groups.filter(x => x !== 'all').sort()[0] === g.id);
        out += `${pad}${g.name}:\n`;
        if (Object.keys(g.vars).length) {
          out += `${pad}  vars:\n`;
          for (const [k, v] of Object.entries(g.vars)) {
            out += `${pad}    ${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}\n`;
          }
        }
        if (gHosts.length) {
          out += `${pad}  hosts:\n`;
          for (const h of gHosts.slice(0, 6)) {
            out += `${pad}    ${h.name}:\n`;
            out += `${pad}      ansible_host: ${h.ip}\n`;
          }
          if (gHosts.length > 6) out += `${pad}    # … ${gHosts.length - 6} more\n`;
        }
        const childGroups = groups.filter(x => x.parent === g.id);
        if (childGroups.length) {
          out += `${pad}  children:\n`;
          out += build(g.id, depth + 2);
        }
      }
      return out;
    };
    return build(null, 0);
  }, [groups, hosts]);

  return (
    <div className="yaml-wrap">
      <div className="code-pane">
        <div className="code-head">
          <div className="mono mute" style={{ fontSize: 11.5 }}>inventory/production.yml</div>
          <div className="code-head-actions">
            <button className="btn ghost small"><Icon name="refresh" size={11}/> Format</button>
            <button className="btn ghost small"><Icon name="check" size={11}/> Validate</button>
            <button className="btn small"><Icon name="download" size={11}/> Save</button>
          </div>
        </div>
        <pre className="code-block"><code>{highlightYaml(tree)}</code></pre>
      </div>
    </div>
  );
}

function highlightYaml(src) {
  // Simple tokenizer → React nodes
  const lines = src.split('\n');
  return lines.map((line, i) => {
    const out = [];
    if (/^\s*#/.test(line)) {
      out.push(<span className="yml-c" key="c">{line}</span>);
    } else {
      const m = line.match(/^(\s*)([^:\s][^:]*)(:)(.*)$/);
      if (m) {
        out.push(m[1]);
        out.push(<span className="yml-k" key="k">{m[2]}</span>);
        out.push(<span className="yml-p" key="p">{m[3]}</span>);
        const rest = m[4];
        if (rest) {
          if (/^\s+-?\s*\d+(\.\d+)?$/.test(rest)) out.push(<span className="yml-n" key="v">{rest}</span>);
          else if (/^\s+(true|false|null)$/.test(rest)) out.push(<span className="yml-b" key="v">{rest}</span>);
          else out.push(<span className="yml-s" key="v">{rest}</span>);
        }
      } else {
        out.push(line);
      }
    }
    return <span key={i}>{out}{'\n'}</span>;
  });
}

// ---------- Inventory View ----------
function InventoryView({ onOpenAdhoc, pendingSelection }) {
  const { HOSTS, GROUPS } = window.AnsibleData;
  const [mode, setMode] = useStateI('table');
  const [selectedGroup, setSelectedGroup] = useStateI('all');
  const [expanded, setExpanded] = useStateI({ all: true, production: true, staging: true, dev: false });
  const [search, setSearch] = useStateI('');
  const [selectedIds, setSelectedIds] = useStateI(() => new Set());
  const [sort, setSort] = useStateI({ key: 'name', dir: 'asc' });
  const [detail, setDetail] = useStateI(null);
  const [filters, setFilters] = useStateI({ tags: [], os: [] });

  const filtered = useMemoI(() => {
    let rows = HOSTS.filter(h => selectedGroup === 'all' || h.groups.includes(selectedGroup));
    if (search) {
      const s = search.toLowerCase();
      rows = rows.filter(h => h.name.includes(s) || h.ip.includes(s) || h.groups.join(' ').includes(s));
    }
    const { key, dir } = sort;
    rows = [...rows].sort((a, b) => {
      const av = a[key], bv = b[key];
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === 'number') return dir === 'asc' ? av - bv : bv - av;
      return dir === 'asc' ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
    });
    return rows;
  }, [HOSTS, selectedGroup, search, sort]);

  const toggleSelect = (id) => {
    const s = new Set(selectedIds);
    s.has(id) ? s.delete(id) : s.add(id);
    setSelectedIds(s);
  };
  const toggleAll = () => {
    if (filtered.every(r => selectedIds.has(r.id))) {
      const s = new Set(selectedIds);
      filtered.forEach(r => s.delete(r.id));
      setSelectedIds(s);
    } else {
      const s = new Set(selectedIds);
      filtered.forEach(r => s.add(r.id));
      setSelectedIds(s);
    }
  };

  const selectedHosts = HOSTS.filter(h => selectedIds.has(h.id));

  return (
    <div className="view view-inventory">
      <div className="view-head">
        <div>
          <h1 className="view-title">Inventory</h1>
          <div className="view-sub mute">
            {selectedGroup === 'all' ? 'All hosts' : <span className="mono">{selectedGroup}</span>}
            <span className="mute-2"> · </span>
            {filtered.length} shown · {HOSTS.length} total
          </div>
        </div>
        <div className="view-actions">
          <div className="seg">
            <button className={mode === 'table' ? 'on' : ''} onClick={() => setMode('table')}><Icon name="inventory" size={12}/> Table</button>
            <button className={mode === 'graph' ? 'on' : ''} onClick={() => setMode('graph')}><Icon name="graph" size={12}/> Graph</button>
            <button className={mode === 'map' ? 'on' : ''} onClick={() => setMode('map')}><Icon name="map" size={12}/> Map</button>
            <button className={mode === 'tags' ? 'on' : ''} onClick={() => setMode('tags')}><Icon name="tag" size={12}/> Tags</button>
            <button className={mode === 'yaml' ? 'on' : ''} onClick={() => setMode('yaml')}><Icon name="code" size={12}/> YAML</button>
          </div>
          <button className="btn small"><Icon name="plus" size={12}/> Add host</button>
        </div>
      </div>

      <div className={`inventory-body ${(mode === 'map' || mode === 'yaml' || mode === 'tags') ? 'no-side' : ''}`}>
        {(mode === 'table' || mode === 'graph') && (
          <aside className="inv-side card">
            <div className="inv-side-search">
              <Icon name="search" size={12} className="mute-2"/>
              <input className="input" placeholder="Filter groups & hosts…" value={search} onChange={e => setSearch(e.target.value)} style={{ border: 0, background: 'transparent', paddingLeft: 6, height: 24 }}/>
            </div>
            <div className="divider"/>
            <div className="section-title" style={{ padding: '10px 10px 6px' }}>Groups</div>
            <InventoryTree
              expanded={expanded} setExpanded={setExpanded}
              selectedGroup={selectedGroup} setSelectedGroup={setSelectedGroup}
              hosts={HOSTS} groups={GROUPS}
            />
          </aside>
        )}

        <main className="inv-main">
          {mode === 'table' && (
            <HostTable
              rows={filtered}
              selectedIds={selectedIds}
              toggleSelect={toggleSelect}
              toggleAll={toggleAll}
              onRowClick={setDetail}
              sort={sort} setSort={setSort}
            />
          )}
          {mode === 'graph' && <InventoryGraph groups={GROUPS} hosts={HOSTS} onSelectGroup={setSelectedGroup}/>}
          {mode === 'map' && <InventoryMap hosts={HOSTS}/>}
          {mode === 'tags' && <InventoryTags hosts={HOSTS} filters={filters} setFilters={setFilters}/>}
          {mode === 'yaml' && <InventoryYAML groups={GROUPS} hosts={HOSTS}/>}
        </main>
      </div>

      {/* Selection bar */}
      {selectedIds.size > 0 && (
        <div className="sel-bar">
          <div className="sel-bar-left">
            <span className="pill info"><b>{selectedIds.size}</b> selected</span>
            <span className="mute mono">
              {selectedHosts.slice(0, 3).map(h => h.name).join(', ')}
              {selectedHosts.length > 3 && ` +${selectedHosts.length - 3}`}
            </span>
          </div>
          <div className="sel-bar-right">
            <button className="btn small" onClick={() => setSelectedIds(new Set())}>Clear</button>
            <button className="btn small"><Icon name="hash" size={12}/> Gather facts</button>
            <button className="btn small"><Icon name="playbooks" size={12}/> Run playbook…</button>
            <button className="btn primary small" onClick={() => onOpenAdhoc({ target: `selection(${selectedIds.size})`, selectedHosts })}>
              <Icon name="terminal" size={12}/> Ad-hoc on selection
            </button>
          </div>
        </div>
      )}

      {/* Host detail drawer */}
      {detail && <HostDrawer host={detail} onClose={() => setDetail(null)}/>}
    </div>
  );
}

function HostDrawer({ host, onClose }) {
  return (
    <div className="drawer-scrim" onMouseDown={onClose}>
      <aside className="drawer" onMouseDown={e => e.stopPropagation()}>
        <div className="drawer-head">
          <div>
            <div className="section-title">Host</div>
            <h2 className="mono" style={{ margin: '4px 0 2px' }}>{host.name}</h2>
            <div className="mute mono" style={{ fontSize: 12 }}>{host.ip} · {host.os}</div>
          </div>
          <button className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>
        <div className="drawer-section">
          <div className="stat-grid">
            <div className="stat"><div className="mute section-title">Status</div><div><span className={`dot ${host.status}`}/> <span className="mono" style={{ textTransform: 'capitalize' }}>{host.status === 'ok' ? 'reachable' : host.status === 'warn' ? 'degraded' : 'unreachable'}</span></div></div>
            <div className="stat"><div className="mute section-title">CPU</div><div className="mono">{host.cpu}%</div></div>
            <div className="stat"><div className="mute section-title">Mem</div><div className="mono">{host.mem}%</div></div>
            <div className="stat"><div className="mute section-title">Load</div><div className="mono">{host.load}</div></div>
            <div className="stat"><div className="mute section-title">Uptime</div><div className="mono">{host.uptime}d</div></div>
            <div className="stat"><div className="mute section-title">Region</div><div className="mono">{host.region.replace('_', '-')}</div></div>
          </div>
        </div>
        <div className="drawer-section">
          <div className="section-title">Groups</div>
          <div className="tag-cluster" style={{ marginTop: 6 }}>
            {host.groups.map(g => <span key={g} className="mini-tag mono">{g}</span>)}
          </div>
        </div>
        <div className="drawer-section">
          <div className="section-title">Tags</div>
          <div className="tag-cluster" style={{ marginTop: 6 }}>
            {host.tags.map(t => <span key={t} className="chip on"><Icon name="tag" size={11}/><span className="mono">{t}</span></span>)}
            <button className="chip"><Icon name="plus" size={10}/> add</button>
          </div>
        </div>
        <div className="drawer-section">
          <div className="section-title">Recent plays</div>
          <div className="mini-runs">
            <div className="mini-run"><span className="dot ok"/><span className="mono">deploy-app.yml</span><span className="mute mono">2h ago</span></div>
            <div className="mini-run"><span className="dot ok"/><span className="mono">patch-security.yml</span><span className="mute mono">1d ago</span></div>
            <div className="mini-run"><span className="dot warn"/><span className="mono">bootstrap.yml</span><span className="mute mono">3d ago</span></div>
          </div>
        </div>
        <div className="drawer-foot">
          <button className="btn small"><Icon name="terminal" size={12}/> SSH</button>
          <button className="btn small"><Icon name="hash" size={12}/> Facts</button>
          <button className="btn primary small"><Icon name="play" size={12}/> Run on this host</button>
        </div>
      </aside>
    </div>
  );
}

window.InventoryView = InventoryView;
