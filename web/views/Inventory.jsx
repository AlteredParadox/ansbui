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

function joinNames(hosts) {
  return hosts.map(h => h.name).join(',');
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
  const childrenOf = buildChildrenIndex(groups);
  const cache = {};
  for (const g of groups) collectDescendants(g.id, childrenOf, cache);
  return cache;
}

function buildChildrenIndex(groups) {
  const children = {};
  for (const g of groups) {
    const key = g.parent ?? '__root__';
    const list = children[key] || [];
    list.push(g.id);
    children[key] = list;
  }
  return children;
}

function collectDescendants(id, childrenOf, cache) {
  if (cache[id]) return cache[id];
  const set = new Set([id]);
  for (const child of childrenOf[id] || []) {
    for (const d of collectDescendants(child, childrenOf, cache)) set.add(d);
  }
  cache[id] = set;
  return set;
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
  const col = (key, label, cls) => {
    const toggle = () => setSort({ key, dir: sort.key === key && sort.dir === 'asc' ? 'desc' : 'asc' });
    // aria-sort lives on the <th> (which has implicit
    // role="columnheader" — the only role that supports it; Sonar
    // S6811). The interactive control is a real <button> nested
    // inside, which is what S6819 wants over `role="button"` on
    // the th itself, and gets us native keyboard handling for
    // free (Enter and Space both fire onClick on a button).
    let ariaSort = 'none';
    if (sort.key === key) {
      ariaSort = sort.dir === 'asc' ? 'ascending' : 'descending';
    }
    return (
      <th className={cls} aria-sort={ariaSort}>
        <button type="button" className="text-btn" onClick={toggle}>
          {label} <span className="mute mono">{sortArrow(key)}</span>
        </button>
      </th>
    );
  };
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
            {col('region', 'Region')}
            <th>Groups</th>
            {col('cpu', 'CPU')}
            {col('mem', 'Mem')}
            {col('load', 'Load')}
            {col('lastPlaybook', 'Last play')}
          </tr>
        </thead>
        <tbody>
          {rows.map(h => (
            // The row keeps the .t-row-click hover styling as a
            // visual affordance, but the only interactive control
            // is the host-name <button> below — that satisfies
            // both mouse and keyboard users and lets us drop the
            // S6847/S6819 exclusion that the old whole-row
            // onClick required.
            <tr key={h.id} className={`t-row-click ${selectedIds.has(h.id) ? 'selected' : ''}`}>
              <td>
                <input type="checkbox" aria-label={`Select ${h.name}`} checked={selectedIds.has(h.id)} onChange={() => toggleSelect(h.id)}/>
              </td>
              <td><span className={`dot ${h.status}`}/></td>
              <td className="mono" style={{ color: 'var(--text)' }}>
                <button
                  type="button"
                  className="text-btn"
                  aria-label={`Open details for ${h.name}`}
                  onClick={() => onRowClick(h)}
                >
                  {h.name}
                </button>
              </td>
              <td className="mono mute">{h.ip}</td>
              <td className="mute" style={{ fontSize: 12 }}>{h.os}</td>
              <td className="mute" style={{ fontSize: 12 }}>{h.region || ''}</td>
              <td>
                <div className="tag-cluster">
                  {(() => {
                    const groups = (h.groups || []).filter(g => g !== 'all');
                    return (
                      <>
                        {groups.slice(0, 3).map(g => <span key={g} className="mini-tag mono">{g}</span>)}
                        {groups.length > 3 && <span className="mini-tag mute mono">+{groups.length - 3}</span>}
                      </>
                    );
                  })()}
                </div>
              </td>
              <td><MiniBar value={h.cpu} /></td>
              <td><MiniBar value={h.mem} warn={70} danger={90}/></td>
              <td className="mono">{(h.load ?? 0).toFixed(2)}</td>
              <td className="mono mute" title={lastPlayTitle(h)}>{lastPlayLabel(h)}</td>
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

// lastPlayLabel renders just the playbook filename (last `/`-segment
// of the relative path) so the column stays narrow. The full path
// + a relative-time hint live in the cell's title attribute below.
function lastPlayLabel(h) {
  const p = h.lastPlaybook;
  if (!p) return '';
  const slash = p.lastIndexOf('/');
  return slash === -1 ? p : p.slice(slash + 1);
}

// lastPlayTitle is the hover tooltip — full relative path plus a
// rough "X ago" timestamp so the operator can tell at a glance
// whether the run was recent.
function lastPlayTitle(h) {
  if (!h.lastPlaybook) return '';
  const at = h.lastPlaybookAt ? new Date(h.lastPlaybookAt) : null;
  if (!at || Number.isNaN(at.getTime())) return h.lastPlaybook;
  const ago = relativeTime(at);
  return `${h.lastPlaybook} · ${ago}`;
}

function relativeTime(d) {
  const ms = Date.now() - d.getTime();
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 48) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.round(day / 30);
  if (mo < 24) return `${mo}mo ago`;
  return `${Math.round(mo / 12)}y ago`;
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
//
// Each host's `region` field is rendered as "<Subdivision>, <CC>"
// (set by RegionFromHostname on the backend, or by ipinfo.io
// enrichment). The map groups hosts by country code, projects each
// country's centroid onto an equirectangular world view, and
// renders a dot per country with status counts. Adding a country
// is just one entry in COUNTRY_CENTROIDS.
const COUNTRY_CENTROIDS = {
  US: { lat: 39.8, lon: -98.5,  name: 'United States' },
  CA: { lat: 56.1, lon: -106.3, name: 'Canada' },
  DE: { lat: 51.2, lon: 10.5,   name: 'Germany' },
  NL: { lat: 52.1, lon: 5.3,    name: 'Netherlands' },
  FI: { lat: 64,   lon: 26,     name: 'Finland' },
  IN: { lat: 22,   lon: 79,     name: 'India' },
  GB: { lat: 54,   lon: -2,     name: 'United Kingdom' },
  RO: { lat: 46,   lon: 25,     name: 'Romania' },
  FR: { lat: 46.5, lon: 2.5,    name: 'France' },
  IT: { lat: 42.8, lon: 12.6,   name: 'Italy' },
  ES: { lat: 40,   lon: -3.7,   name: 'Spain' },
  IE: { lat: 53.1, lon: -8.2,   name: 'Ireland' },
  PL: { lat: 52,   lon: 19.4,   name: 'Poland' },
  CH: { lat: 46.8, lon: 8.2,    name: 'Switzerland' },
  AT: { lat: 47.5, lon: 14.5,   name: 'Austria' },
  SE: { lat: 60.1, lon: 18.6,   name: 'Sweden' },
  NO: { lat: 60.5, lon: 8.5,    name: 'Norway' },
  JP: { lat: 36,   lon: 138,    name: 'Japan' },
  SG: { lat: 1.3,  lon: 103.8,  name: 'Singapore' },
  AU: { lat: -25,  lon: 134,    name: 'Australia' },
  BR: { lat: -14,  lon: -52,    name: 'Brazil' },
  ZA: { lat: -30.6, lon: 22.9,  name: 'South Africa' },
};

// projectCentroid maps (lat, lon) onto the SVG's 900×480 viewBox via
// equirectangular projection. Distorts at the poles, but for a
// stylised infrastructure overview it's plenty.
function projectCentroid(lat, lon) {
  const x = ((lon + 180) / 360) * 900;
  const y = ((90 - lat) / 180) * 480;
  return { x, y };
}

// countryFromRegion pulls the trailing 2-letter country code out of
// labels like "Bihor, RO" or "San Francisco, US". Returns null if
// the region doesn't end with a recognisable CC (e.g. an empty
// region or a free-form value some operator typed).
function countryFromRegion(region) {
  if (!region) return null;
  const m = /,\s*([A-Z]{2})$/.exec(region);
  return m ? m[1] : null;
}

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
  // Group every host with a recognisable country code; everything
  // else (no region set, region we don't have a centroid for) stays
  // in `unmapped` and surfaces as a hint below the map.
  const byCountry = {};
  const unmapped = [];
  for (const h of hosts) {
    const cc = countryFromRegion(h.region);
    if (cc && COUNTRY_CENTROIDS[cc]) {
      if (!byCountry[cc]) byCountry[cc] = [];
      byCountry[cc].push(h);
    } else {
      unmapped.push(h);
    }
  }
  const entries = Object.entries(byCountry).map(([cc, hs]) => {
    const c = COUNTRY_CENTROIDS[cc];
    const { x, y } = projectCentroid(c.lat, c.lon);
    return { cc, hs, x, y, name: c.name };
  });

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

        {entries.map((a, i) => entries.slice(i + 1).map((b) => (
          <path key={`${a.cc}-${b.cc}`}
            d={`M${a.x},${a.y} Q${(a.x + b.x) / 2},${Math.min(a.y, b.y) - 60} ${b.x},${b.y}`}
            fill="none" stroke="var(--accent)" strokeOpacity="0.3" strokeDasharray="3 4" strokeWidth="1"/>
        )))}

        {entries.map(({ cc, hs, x, y, name }) => {
          const ok = countByStatus(hs, 'ok');
          const warn = countByStatus(hs, 'warn');
          const err = countByStatus(hs, 'err');
          // Flip the tooltip card to the left when the dot is too
          // close to the right edge of the viewBox so it doesn't
          // clip out of the SVG.
          const tipLeft = x > 720 ? -174 : 14;
          return (
            <g key={cc} className="map-region">
              <circle cx={x} cy={y} r="28" fill="var(--accent-weak)" stroke="none"/>
              <circle cx={x} cy={y} r="42" fill="none" stroke="var(--accent)" strokeOpacity="0.3" strokeDasharray="2 3">
                <animate attributeName="r" values="30;50;30" dur="3s" repeatCount="indefinite"/>
                <animate attributeName="stroke-opacity" values="0.4;0;0.4" dur="3s" repeatCount="indefinite"/>
              </circle>
              <circle cx={x} cy={y} r="6" fill="var(--accent)"/>
              <g transform={`translate(${x + tipLeft}, ${y - 24})`}>
                <rect x="0" y="0" width="160" height="52" rx="6" fill="var(--bg-2)" stroke="var(--line)"/>
                <text x="10" y="16" fontSize="11" fontFamily="var(--font-mono)" fontWeight="600" fill="var(--text)">{cc}</text>
                <text x="10" y="29" fontSize="9.5" fill="var(--text-3)">{name} · {hs.length} hosts</text>
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

        {entries.length === 0 && (
          <text x="450" y="240" textAnchor="middle" fontSize="13" fill="var(--text-3)" fontFamily="var(--font-mono)">
            No hosts have a recognised region yet — set a cc-ss prefix or enable geoip.
          </text>
        )}
      </svg>
      {unmapped.length > 0 && entries.length > 0 && (
        <div className="mute" style={{ fontSize: 12, marginTop: 6, paddingLeft: 8 }}>
          {unmapped.length} host{unmapped.length === 1 ? '' : 's'} not on the map (no recognised region).
        </div>
      )}
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
          <div className="mono mute" style={{ fontSize: 11.5 }}>inventory (rendered from the live ansible-inventory --list snapshot)</div>
          <div className="code-head-actions">
            <span className="mute mono" style={{ fontSize: 11 }}>read-only</span>
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
    if (refreshing || !globalThis.AnsbuiAPI) return;
    setRefreshing(true); setRefreshError('');
    try {
      await globalThis.AnsbuiAPI.refreshData();
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
            <button
              type="button"
              className="btn small"
              onClick={() => onOpenAdhoc({ target: joinNames(selectedHosts), module: 'ansible.builtin.setup', selectedHosts })}
            >
              <Icon name="hash" size={12}/> Gather facts
            </button>
            <button type="button" className="btn primary small" onClick={() => onOpenAdhoc({ target: joinNames(selectedHosts), selectedHosts })}>
              <Icon name="terminal" size={12}/> Ad-hoc on selection
            </button>
          </div>
        </div>
      )}

      <HostDrawer host={detail} onClose={() => setDetail(null)} onOpenAdhoc={onOpenAdhoc}/>
    </div>
  );
}

function HostDrawer({ host, onClose, onOpenAdhoc }) {
  const open = host != null;
  const dialogRef = globalThis.useDialog(open, onClose);
  if (!host) {
    return <dialog ref={dialogRef} className="ansbui-dialog ansbui-dialog-drawer" aria-hidden="true"/>;
  }
  return (
    <dialog
      ref={dialogRef}
      className="ansbui-dialog ansbui-dialog-drawer"
      aria-label={`Host ${host.name}`}
      {...globalThis.dialogBackdropHandlers(dialogRef, onClose)}
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
        {(host.tags || []).length > 0 && (
          <div className="drawer-section">
            <div className="section-title">Tags</div>
            <div className="tag-cluster" style={{ marginTop: 6 }}>
              {host.tags.map(t => <span key={t} className="chip on"><Icon name="tag" size={11}/><span className="mono">{t}</span></span>)}
            </div>
          </div>
        )}
        <div className="drawer-section">
          <FactsPanel host={host}/>
        </div>
        <div className="drawer-foot">
          <button
            type="button"
            className="btn primary small"
            onClick={() => { onClose(); onOpenAdhoc?.({ target: host.name, selectedHosts: [host] }); }}
          >
            <Icon name="play" size={12}/> Run ad-hoc on this host
          </button>
        </div>
      </aside>
    </dialog>
  );
}

// FactsPanel renders the ansible `setup` output for a single host.
// Behaviour is driven by the AnsbuiSettings.autoGatherFacts flag:
//   - true  → fire the gather on mount, show the tree as soon as
//             it lands (identical to the old "click Facts" flow but
//             without a trip through the ad-hoc view).
//   - false → sit on an explicit [Gather facts] button; the operator
//             opts in per host.
// State is intentionally local to the panel so toggling between
// hosts in the inventory table doesn't leak facts across hosts.
function FactsPanel({ host }) {
  const settings = globalThis.AnsbuiSettings || {};
  const autoGather = !!settings.autoGatherFacts;
  const [facts, setFacts] = useStateI(null);
  const [loading, setLoading] = useStateI(false);
  const [error, setError] = useStateI('');
  const [query, setQuery] = useStateI('');

  const load = async () => {
    if (!host?.name || !globalThis.AnsbuiAPI) return;
    setLoading(true); setError('');
    try {
      const res = await globalThis.AnsbuiAPI.gatherFacts(host.name);
      setFacts(res.facts || {});
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffectI(() => {
    // Reset whenever the selected host changes, then maybe auto-load.
    setFacts(null); setError(''); setQuery('');
    if (autoGather) load();
    // We intentionally don't depend on `load` (stable enough for this
    // component) — just the host identity.
  }, [host?.name, autoGather]);

  let status;
  if (loading) status = 'gathering…';
  else if (facts) status = `${Object.keys(facts).length} keys`;
  else status = 'not gathered';

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div className="section-title">Facts</div>
        <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>
          {status}
        </span>
        <button
          type="button"
          className="btn ghost small"
          onClick={load}
          disabled={loading}
        >
          <Icon name="refresh" size={11}/> {facts ? 'Refresh' : 'Gather facts'}
        </button>
      </div>
      {error && <div className="cm-error mono" style={{ marginTop: 6 }}>{error}</div>}
      {facts && (
        <>
          <input
            className="input"
            aria-label="Filter facts"
            placeholder="Filter (e.g. ipv4, distribution, eth0)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ marginTop: 8 }}
          />
          <div className="facts-list" style={{ marginTop: 8 }}>
            {filterFacts(facts, query).map(([k, v]) => (
              <details key={k} className="fact-row">
                <summary>
                  <span className="mono fact-key">{k}</span>
                  <span className="mute fact-preview mono">{factPreview(v)}</span>
                </summary>
                <pre className="fact-body mono">{JSON.stringify(v, null, 2)}</pre>
              </details>
            ))}
            {filterFacts(facts, query).length === 0 && (
              <div className="mute" style={{ fontSize: 12 }}>No keys match.</div>
            )}
          </div>
        </>
      )}
    </>
  );
}

function filterFacts(facts, query) {
  const entries = Object.entries(facts);
  const q = query.trim().toLowerCase();
  if (!q) return entries.toSorted(([a], [b]) => a.localeCompare(b));
  return entries
    .filter(([k, v]) => k.toLowerCase().includes(q) || JSON.stringify(v).toLowerCase().includes(q))
    .toSorted(([a], [b]) => a.localeCompare(b));
}

// factPreview returns a one-line rendering suited for the summary
// row — scalar values show inline, collections show their shape.
function factPreview(v) {
  if (v == null) return '—';
  if (typeof v === 'string') return v.length > 80 ? v.slice(0, 80) + '…' : v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return `[${v.length} items]`;
  if (typeof v === 'object') return `{${Object.keys(v).length} keys}`;
  return '';
}

globalThis.InventoryView = InventoryView;
