// Inventory view — 5 modes: Table+Tree, Graph, Map, Tags, YAML.

const { useState: useStateI, useMemo: useMemoI, useEffect: useEffectI } = React;

// Bounded, single-line regex for YAML highlighting — no nested
// quantifiers, so linear-time (Sonar S5852).
const YAML_KV_RE = /^([ \t]*)([^:\s][^:]*)(:)(.*)$/;
const YAML_COMMENT_RE = /^[ \t]*#/;
const YAML_NUMBER_RE = /^[ \t]+-?\d+(\.\d+)?$/;
const YAML_BOOL_RE = /^[ \t]+(true|false|null)$/;
const SORT_DIRECTION = { asc: 1, desc: -1 };

function ascending(a, b) {
  return String(a).localeCompare(String(b));
}

function statusTone(status) {
  if (status === 'ok') return 'ok';
  if (status === 'warn') return 'warn';
  return 'err';
}

function statusLabel(status) {
  if (status === 'ok') return 'reachable';
  if (status === 'warn') return 'degraded';
  return 'unreachable';
}

function statusColorVar(status) {
  if (status === 'ok') return 'var(--ok)';
  if (status === 'warn') return 'var(--warn)';
  return 'var(--err)';
}

function miniBarColor(value, warn, danger) {
  if (value >= danger) return 'var(--err)';
  if (value >= warn) return 'var(--warn)';
  return 'var(--accent)';
}

function nodeSize(tier) {
  if (tier === 0) return 32;
  if (tier === 1) return 24;
  return 18;
}

function sortHosts(rows, sort) {
  const dir = SORT_DIRECTION[sort.dir] || 1;
  return [...rows].sort((a, b) => {
    const av = a[sort.key];
    const bv = b[sort.key];
    if (av == null) return 1;
    if (bv == null) return -1;
    if (typeof av === 'number') return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });
}

// descendantsByGroup maps each group id → Set of that group's id + all
// transitive descendants. Ansible's `ansible-inventory --list` output
// only lists a host under its immediate group, so to answer "is this
// host under 'vps_servers'?" we need to walk the tree.
function descendantsByGroup(groups) {
  const childrenOf = {};
  for (const g of groups) {
    const key = g.parent ?? '__root__';
    (childrenOf[key] ||= []).push(g.id);
  }
  const cache = {};
  const walk = (id) => {
    if (cache[id]) return cache[id];
    const set = new Set([id]);
    for (const child of childrenOf[id] || []) {
      for (const d of walk(child)) set.add(d);
    }
    cache[id] = set;
    return set;
  };
  for (const g of groups) walk(g.id);
  return cache;
}

function hostMatchesGroup(host, descendants) {
  if (!descendants) return true;
  return (host.groups || []).some(g => descendants.has(g));
}

// ---------- Tree ----------
function InventoryTree({ expanded, setExpanded, selectedGroup, setSelectedGroup, hosts, groups, descendants }) {
  const childrenOf = (parent) => groups.filter(g => g.parent === parent);
  const countHosts = (groupId) => {
    const set = descendants[groupId];
    if (!set) return 0;
    return hosts.filter(h => hostMatchesGroup(h, set)).length;
  };

  const Node = ({ g, depth }) => {
    const kids = childrenOf(g.id);
    const isOpen = expanded[g.id] ?? (depth < 2);
    const hostCount = countHosts(g.id);
    const toggleOpen = (e) => { e.stopPropagation(); setExpanded({ ...expanded, [g.id]: !isOpen }); };
    return (
      <div>
        <div
          className={`tree-row ${selectedGroup === g.id ? 'active' : ''}`}
          style={{ paddingLeft: 8 + depth * 14 }}
        >
          {kids.length > 0 ? (
            <button type="button" className="tree-caret" onClick={toggleOpen} aria-label={isOpen ? 'Collapse' : 'Expand'}>
              <Icon name={isOpen ? 'chevron-down' : 'chevron-right'} size={11}/>
            </button>
          ) : (
            <span className="tree-caret" />
          )}
          <button
            type="button"
            className="tree-select"
            onClick={() => setSelectedGroup(g.id)}
            style={{ display: 'contents' }}
          >
            <span className="tree-icon">
              <Icon name={g.parent ? 'group' : 'globe'} size={13}/>
            </span>
            <span className="tree-name mono">{g.name}</span>
            <span className="tree-count mute">{hostCount}</span>
          </button>
        </div>
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
  const sortArrow = (key) => {
    if (sort.key !== key) return '';
    return sort.dir === 'asc' ? '↑' : '↓';
  };
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
              <input type="checkbox" aria-label="Select all hosts" checked={allSelected} ref={el => el && (el.indeterminate = someSelected)} onChange={toggleAll}/>
            </th>
            <th style={{ width: 26 }} aria-label="Status"></th>
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
                <input type="checkbox" aria-label={`Select ${h.name}`} checked={selectedIds.has(h.id)} onChange={() => toggleSelect(h.id)}/>
              </td>
              <td><span className={`dot ${h.status}`}/></td>
              <td className="mono" style={{ color: 'var(--text)' }}>{h.name}</td>
              <td className="mono mute">{h.ip}</td>
              <td className="mute" style={{ fontSize: 12 }}>{h.os}</td>
              <td>
                <div className="tag-cluster">
                  {(h.groups || []).filter(g => g !== 'all').slice(0, 3).map(g => <span key={g} className="mini-tag mono">{g}</span>)}
                  {h.groups?.length > 4 && <span className="mini-tag mute mono">+{h.groups.length - 4}</span>}
                </div>
              </td>
              <td><MiniBar value={h.cpu} /></td>
              <td><MiniBar value={h.mem} warn={70} danger={90}/></td>
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
  const color = miniBarColor(value, warn, danger);
  return (
    <div className="mini-bar-wrap">
      <div className="mini-bar"><div style={{ width: `${value}%`, background: color }}/></div>
      <span className="mini-bar-val mono">{value}</span>
    </div>
  );
}

// ---------- Graph ----------
function InventoryGraph({ groups, hosts, onSelectGroup }) {
  const tierOf = (g) => {
    let tier = 0;
    let cur = g;
    while (cur?.parent) {
      tier += 1;
      cur = groups.find(x => x.id === cur.parent);
    }
    return tier;
  };
  const W = 760;
  const H = 560;
  const CX = W / 2;
  const CY = H / 2;
  const positioned = useMemoI(() => {
    const byTier = { 0: [], 1: [], 2: [] };
    groups.forEach(g => {
      const t = Math.min(2, tierOf(g));
      byTier[t].push(g);
    });
    const radii = { 0: 0, 1: 140, 2: 250 };
    const result = {};
    Object.entries(byTier).forEach(([t, list]) => {
      list.forEach((g, i) => {
        const ang = (i / Math.max(1, list.length)) * Math.PI * 2 - Math.PI / 2;
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

        {groups.filter(g => g.parent).map(g => {
          const p = positioned[g.id];
          const pp = positioned[g.parent];
          if (!p || !pp) return null;
          return <line key={g.id} x1={pp.x} y1={pp.y} x2={p.x} y2={p.y} stroke="var(--line)" strokeWidth="1"/>;
        })}

        {groups.map(g => {
          const p = positioned[g.id];
          if (p?.tier !== 2) return null;
          const gHosts = hosts.filter(h => (h.groups || []).includes(g.id));
          const count = Math.min(12, gHosts.length);
          const ang0 = Math.atan2(p.y - CY, p.x - CX);
          return gHosts.slice(0, count).map((h, i) => {
            const spread = 0.55;
            const ang = ang0 + (i - count / 2) * (spread / count);
            const r = 62;
            const hx = p.x + Math.cos(ang) * r;
            const hy = p.y + Math.sin(ang) * r;
            return (
              <g key={h.id}>
                <line x1={p.x} y1={p.y} x2={hx} y2={hy} stroke="var(--line-soft)" strokeWidth="0.8"/>
                <circle cx={hx} cy={hy} r="3" fill={statusColorVar(h.status)}>
                  <title>{h.name}</title>
                </circle>
              </g>
            );
          });
        })}

        {groups.map(g => {
          const p = positioned[g.id];
          if (!p) return null;
          const size = nodeSize(p.tier);
          const count = hosts.filter(h => (h.groups || []).includes(g.id)).length;
          return (
            <g
              key={g.id}
              className="graph-node"
              role="button"
              tabIndex={0}
              onClick={() => onSelectGroup(g.id)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelectGroup(g.id); } }}
              style={{ cursor: 'pointer' }}
            >
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
const MAP_REGIONS = [
  { id: 'us_east', name: 'us-east-1', x: 280, y: 235, label: 'N. Virginia' },
  { id: 'us_west', name: 'us-west-2', x: 160, y: 225, label: 'Oregon' },
  { id: 'eu_west', name: 'eu-west-1', x: 500, y: 210, label: 'Ireland' }
];

function isLandMass(col, row) {
  const seed = Math.sin(col * 0.28) * 20 + Math.cos(row * 0.5) * 20;
  if (col > 8 && col < 22 && row > 4 && row < 20 && seed > -5) return true;
  if (col > 26 && col < 38 && row > 3 && row < 15) return true;
  if (col > 40 && col < 58 && row > 4 && row < 18) return true;
  return false;
}

function countByStatus(hosts, status) {
  return hosts.filter(h => h.status === status).length;
}

function InventoryMap({ hosts }) {
  const byRegion = (rid) => hosts.filter(h => h.region === rid);
  return (
    <div className="map-wrap">
      <svg width="100%" height="560" viewBox="0 0 900 480" preserveAspectRatio="xMidYMid meet" className="map-svg">
        <g opacity="0.35">
          {Array.from({ length: 30 }).map((_, r) =>
            Array.from({ length: 60 }).map((_, c) => {
              if (!isLandMass(c, r)) return null;
              return <circle key={`${r}-${c}`} cx={50 + c * 13} cy={50 + r * 13} r="1.4" fill="var(--text-4)" opacity="0.45"/>;
            })
          )}
        </g>

        {MAP_REGIONS.map((a, i) => MAP_REGIONS.slice(i + 1).map((b) => (
          <path key={`${a.id}-${b.id}`}
            d={`M${a.x},${a.y} Q${(a.x + b.x) / 2},${Math.min(a.y, b.y) - 60} ${b.x},${b.y}`}
            fill="none" stroke="var(--accent)" strokeOpacity="0.3" strokeDasharray="3 4" strokeWidth="1"/>
        )))}

        {MAP_REGIONS.map(rg => {
          const hs = byRegion(rg.id);
          const ok = countByStatus(hs, 'ok');
          const warn = countByStatus(hs, 'warn');
          const err = countByStatus(hs, 'err');
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
  const allTags = Array.from(new Set(hosts.flatMap(h => h.tags || []))).sort(ascending);
  const allOS = Array.from(new Set(hosts.map(h => h.os).filter(Boolean))).sort(ascending);
  const matches = hosts.filter(h =>
    (!filters.tags.length || filters.tags.every(t => (h.tags || []).includes(t))) &&
    (!filters.os.length || filters.os.includes(h.os))
  );
  const toggleSet = (key, v) => {
    const set = new Set(filters[key]);
    if (set.has(v)) set.delete(v); else set.add(v);
    setFilters({ ...filters, [key]: [...set] });
  };
  const selector = [...filters.tags.map(t => `tag:${t}`), ...filters.os.map(o => `os:"${o}"`)].join(' AND ') || 'all';
  return (
    <div className="tags-wrap">
      <div className="tags-builder card">
        <div className="section-title">Build a selector</div>
        <div className="tags-group">
          <div className="tags-group-label">tags</div>
          <div className="tag-cluster">
            {allTags.map(t => (
              <button type="button" key={t} className={`chip ${filters.tags.includes(t) ? 'on' : ''}`} onClick={() => toggleSet('tags', t)}>
                <Icon name="tag" size={11}/> <span className="mono">{t}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="tags-group">
          <div className="tags-group-label">os</div>
          <div className="tag-cluster">
            {allOS.map(t => (
              <button type="button" key={t} className={`chip ${filters.os.includes(t) ? 'on' : ''}`} onClick={() => toggleSet('os', t)}>
                <span className="mono">{t}</span>
              </button>
            ))}
          </div>
        </div>
        <div className="tags-sel">
          <div className="section-title">Resolved selector</div>
          <div className="tags-selector mono">{selector}</div>
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
function buildYamlTree(groups, hosts) {
  const lines = [];
  emitChildren(null, 0, lines, groups, hosts);
  return lines.join('\n');
}

function emitChildren(parent, depth, lines, groups, hosts) {
  const pad = '  '.repeat(depth);
  const kids = groups.filter(g => g.parent === parent);
  for (const g of kids) {
    lines.push(`${pad}${g.name}:`);
    emitVars(g, pad, lines);
    emitHosts(g, pad, lines, hosts);
    emitChildrenSection(g, pad, depth, lines, groups, hosts);
  }
}

function emitVars(group, pad, lines) {
  const entries = Object.entries(group.vars || {});
  if (!entries.length) return;
  lines.push(`${pad}  vars:`);
  for (const [k, v] of entries) {
    const val = typeof v === 'string' ? v : JSON.stringify(v);
    lines.push(`${pad}    ${k}: ${val}`);
  }
}

function primaryGroup(host) {
  return (host.groups || []).filter(x => x !== 'all').sort(ascending)[0];
}

function emitHosts(group, pad, lines, hosts) {
  const gHosts = hosts.filter(h => (h.groups || []).includes(group.id) && primaryGroup(h) === group.id);
  if (!gHosts.length) return;
  lines.push(`${pad}  hosts:`);
  for (const h of gHosts.slice(0, 6)) {
    lines.push(
      `${pad}    ${h.name}:`,
      `${pad}      ansible_host: ${h.ip}`
    );
  }
  if (gHosts.length > 6) lines.push(`${pad}    # … ${gHosts.length - 6} more`);
}

function emitChildrenSection(group, pad, depth, lines, groups, hosts) {
  const childGroups = groups.filter(x => x.parent === group.id);
  if (!childGroups.length) return;
  lines.push(`${pad}  children:`);
  emitChildren(group.id, depth + 2, lines, groups, hosts);
}

function InventoryYAML({ groups, hosts }) {
  const tree = useMemoI(() => buildYamlTree(groups, hosts), [groups, hosts]);
  return (
    <div className="yaml-wrap">
      <div className="code-pane">
        <div className="code-head">
          <div className="mono mute" style={{ fontSize: 11.5 }}>inventory/production.yml</div>
          <div className="code-head-actions">
            <button type="button" className="btn ghost small"><Icon name="refresh" size={11}/> Format</button>
            <button type="button" className="btn ghost small"><Icon name="check" size={11}/> Validate</button>
            <button type="button" className="btn small"><Icon name="download" size={11}/> Save</button>
          </div>
        </div>
        <pre className="code-block"><code>{highlightYaml(tree)}</code></pre>
      </div>
    </div>
  );
}

function highlightYaml(src) {
  return src.split('\n').map((line, i) => (
    <span key={`ln-${i}-${line.length}`}>
      {renderYamlLine(line)}
      {'\n'}
    </span>
  ));
}

function renderYamlLine(line) {
  if (YAML_COMMENT_RE.test(line)) return <span className="yml-c">{line}</span>;
  const m = YAML_KV_RE.exec(line);
  if (!m) return line;
  const [, indent, key, colon, rest] = m;
  return (
    <>
      {indent}
      <span className="yml-k">{key}</span>
      <span className="yml-p">{colon}</span>
      {rest && renderYamlValue(rest)}
    </>
  );
}

function renderYamlValue(rest) {
  if (YAML_NUMBER_RE.test(rest)) return <span className="yml-n">{rest}</span>;
  if (YAML_BOOL_RE.test(rest)) return <span className="yml-b">{rest}</span>;
  return <span className="yml-s">{rest}</span>;
}

// ---------- Inventory View ----------
function InventoryView({ onOpenAdhoc }) {
  const [, setRefreshTick] = useStateI(0);
  const [refreshing, setRefreshing] = useStateI(false);
  const [refreshError, setRefreshError] = useStateI('');
  const data = globalThis.AnsibleData || {};
  const HOSTS = data.HOSTS || [];
  const GROUPS = data.GROUPS || [];
  const [mode, setMode] = useStateI('table');
  const [selectedGroup, setSelectedGroup] = useStateI('all');
  const [expanded, setExpanded] = useStateI({ all: true });
  const [search, setSearch] = useStateI('');
  const [selectedIds, setSelectedIds] = useStateI(() => new Set());
  const [sort, setSort] = useStateI({ key: 'name', dir: 'asc' });
  const [detail, setDetail] = useStateI(null);
  const [filters, setFilters] = useStateI({ tags: [], os: [] });

  const reload = async () => {
    if (refreshing || !globalThis.RelayAPI) return;
    setRefreshing(true); setRefreshError('');
    try {
      await globalThis.RelayAPI.bootstrap();
      setRefreshTick(t => t + 1);
    } catch (e) {
      setRefreshError(e.message);
    } finally {
      setRefreshing(false);
    }
  };

  const descendants = useMemoI(() => descendantsByGroup(GROUPS), [GROUPS]);

  const filtered = useMemoI(() => {
    const matchSet = selectedGroup === 'all' ? null : descendants[selectedGroup];
    let rows = HOSTS.filter(h => hostMatchesGroup(h, matchSet));
    if (search) {
      const s = search.toLowerCase();
      rows = rows.filter(h =>
        h.name.toLowerCase().includes(s) ||
        (h.ip || '').includes(s) ||
        (h.groups || []).join(' ').toLowerCase().includes(s)
      );
    }
    return sortHosts(rows, sort);
  }, [HOSTS, selectedGroup, search, sort, descendants]);

  const toggleSelect = (id) => {
    const s = new Set(selectedIds);
    if (s.has(id)) s.delete(id); else s.add(id);
    setSelectedIds(s);
  };
  const toggleAll = () => {
    const next = new Set(selectedIds);
    if (filtered.every(r => next.has(r.id))) {
      filtered.forEach(r => next.delete(r.id));
    } else {
      filtered.forEach(r => next.add(r.id));
    }
    setSelectedIds(next);
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
            <button type="button" className={mode === 'table' ? 'on' : ''} onClick={() => setMode('table')}><Icon name="inventory" size={12}/> Table</button>
            <button type="button" className={mode === 'graph' ? 'on' : ''} onClick={() => setMode('graph')}><Icon name="graph" size={12}/> Graph</button>
            <button type="button" className={mode === 'map' ? 'on' : ''} onClick={() => setMode('map')}><Icon name="map" size={12}/> Map</button>
            <button type="button" className={mode === 'tags' ? 'on' : ''} onClick={() => setMode('tags')}><Icon name="tag" size={12}/> Tags</button>
            <button type="button" className={mode === 'yaml' ? 'on' : ''} onClick={() => setMode('yaml')}><Icon name="code" size={12}/> YAML</button>
          </div>
          <button type="button" className="btn small" onClick={reload} disabled={refreshing}>
            <Icon name="refresh" size={12}/> {refreshing ? 'Reloading…' : 'Reload'}
          </button>
          <button type="button" className="btn small"><Icon name="plus" size={12}/> Add host</button>
        </div>
      </div>
      {refreshError && <div className="cm-error mono" style={{ marginBottom: 12 }}>{refreshError}</div>}

      <div className={`inventory-body ${(mode === 'map' || mode === 'yaml' || mode === 'tags') ? 'no-side' : ''}`}>
        {(mode === 'table' || mode === 'graph') && (
          <aside className="inv-side card">
            <div className="inv-side-search">
              <Icon name="search" size={12} className="mute-2"/>
              <input className="input" aria-label="Filter groups and hosts" placeholder="Filter groups & hosts…" value={search} onChange={e => setSearch(e.target.value)} style={{ border: 0, background: 'transparent', paddingLeft: 6, height: 24 }}/>
            </div>
            <div className="divider"/>
            <div className="section-title" style={{ padding: '10px 10px 6px' }}>Groups</div>
            <InventoryTree
              expanded={expanded} setExpanded={setExpanded}
              selectedGroup={selectedGroup} setSelectedGroup={setSelectedGroup}
              hosts={HOSTS} groups={GROUPS} descendants={descendants}
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
            <button type="button" className="btn small" onClick={() => setSelectedIds(new Set())}>Clear</button>
            <button type="button" className="btn small"><Icon name="hash" size={12}/> Gather facts</button>
            <button type="button" className="btn small"><Icon name="playbooks" size={12}/> Run playbook…</button>
            <button type="button" className="btn primary small" onClick={() => onOpenAdhoc({ target: `selection(${selectedIds.size})`, selectedHosts })}>
              <Icon name="terminal" size={12}/> Ad-hoc on selection
            </button>
          </div>
        </div>
      )}

      <HostDrawer host={detail} onClose={() => setDetail(null)}/>
    </div>
  );
}

function HostDrawer({ host, onClose }) {
  const open = host != null;
  const dialogRef = globalThis.useDialog(open, onClose);
  if (!host) {
    return <dialog ref={dialogRef} className="relay-dialog relay-dialog-drawer" aria-hidden="true"/>;
  }
  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-drawer"
      aria-label={`Host ${host.name}`}
      onClick={(e) => { if (e.target === dialogRef.current) onClose(); }}
    >
      <aside className="drawer">
        <div className="drawer-head">
          <div>
            <div className="section-title">Host</div>
            <h2 className="mono" style={{ margin: '4px 0 2px' }}>{host.name}</h2>
            <div className="mute mono" style={{ fontSize: 12 }}>{host.ip} · {host.os}</div>
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>
        <div className="drawer-section">
          <div className="stat-grid">
            <div className="stat">
              <div className="mute section-title">Status</div>
              <div>
                <span className={`dot ${statusTone(host.status)}`}/>
                {' '}
                <span className="mono" style={{ textTransform: 'capitalize' }}>{statusLabel(host.status)}</span>
              </div>
            </div>
            <div className="stat"><div className="mute section-title">CPU</div><div className="mono">{host.cpu}%</div></div>
            <div className="stat"><div className="mute section-title">Mem</div><div className="mono">{host.mem}%</div></div>
            <div className="stat"><div className="mute section-title">Load</div><div className="mono">{host.load}</div></div>
            <div className="stat"><div className="mute section-title">Uptime</div><div className="mono">{host.uptime}d</div></div>
            <div className="stat"><div className="mute section-title">Region</div><div className="mono">{(host.region || '').replaceAll('_', '-')}</div></div>
          </div>
        </div>
        <div className="drawer-section">
          <div className="section-title">Groups</div>
          <div className="tag-cluster" style={{ marginTop: 6 }}>
            {(host.groups || []).map(g => <span key={g} className="mini-tag mono">{g}</span>)}
          </div>
        </div>
        <div className="drawer-section">
          <div className="section-title">Tags</div>
          <div className="tag-cluster" style={{ marginTop: 6 }}>
            {(host.tags || []).map(t => <span key={t} className="chip on"><Icon name="tag" size={11}/><span className="mono">{t}</span></span>)}
            <button type="button" className="chip"><Icon name="plus" size={10}/> add</button>
          </div>
        </div>
        <div className="drawer-foot">
          <button type="button" className="btn small"><Icon name="terminal" size={12}/> SSH</button>
          <button type="button" className="btn small"><Icon name="hash" size={12}/> Facts</button>
          <button type="button" className="btn primary small"><Icon name="play" size={12}/> Run on this host</button>
        </div>
      </aside>
    </dialog>
  );
}

globalThis.InventoryView = InventoryView;
