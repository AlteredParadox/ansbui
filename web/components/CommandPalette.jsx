// Global command palette — ⌘K
// Fuzzy-ish search across: navigation, hosts, groups, playbooks, modules, actions.

const { useState: useStateCP, useEffect: useEffectCP, useMemo: useMemoCP, useRef: useRefCP } = React;

const NAV_ACTIONS = [
  { id: 'nav-dashboard', label: 'Go to Dashboard', hint: 'g d', icon: 'dashboard', target: 'dashboard' },
  { id: 'nav-inventory', label: 'Go to Inventory', hint: 'g i', icon: 'inventory', target: 'inventory' },
  { id: 'nav-playbooks', label: 'Go to Playbooks', hint: 'g p', icon: 'playbooks', target: 'playbooks' },
  { id: 'nav-adhoc', label: 'Run ad-hoc command…', hint: 'g a', icon: 'terminal', target: 'adhoc' },
  { id: 'nav-history', label: 'Open run history', hint: 'g r', icon: 'history', target: 'history' },
  { id: 'nav-vault', label: 'Open secrets', hint: 'g s', icon: 'vault', target: 'vault' }
];

function buildActions(onNavigate, onOpenAdhoc) {
  const nav = NAV_ACTIONS.map(a => ({
    id: a.id, kind: 'nav', label: a.label, hint: a.hint, icon: a.icon,
    run: () => onNavigate(a.target)
  }));
  const quick = [
    { id: 'act-ping-all', kind: 'action', label: 'Ping all production hosts', icon: 'bolt',
      run: () => onOpenAdhoc({ module: 'ansible.builtin.ping', target: 'production' }) },
    { id: 'act-gather-facts', kind: 'action', label: 'Gather facts across inventory', icon: 'refresh',
      run: () => onOpenAdhoc({ module: 'ansible.builtin.setup', target: 'all' }) }
  ];
  return [...nav, ...quick];
}

function matchesQuery(query, ...texts) {
  if (!query) return true;
  const q = query.toLowerCase();
  return texts.some(t => (t || '').toLowerCase().includes(q));
}

function buildSections({ query, actions, hosts, groups, plays, mods, onNavigate, onRunPlaybook, onOpenAdhoc }) {
  const sections = [];
  const filteredActions = actions.filter(a => matchesQuery(query, a.label, a.hint));
  if (filteredActions.length) sections.push({ title: 'Actions', items: filteredActions.slice(0, 8) });

  const filteredHosts = hosts.filter(h => matchesQuery(query, h.name, (h.groups || []).join(' ')));
  if (filteredHosts.length) {
    sections.push({
      title: `Hosts · ${filteredHosts.length}`,
      items: filteredHosts.slice(0, 5).map(h => ({
        id: `host-${h.id}`,
        kind: 'host',
        label: h.name,
        sub: `${h.ip} · ${(h.groups || []).slice(0, 3).join(', ')}`,
        icon: 'server',
        statusDot: h.status,
        run: () => onNavigate('inventory')
      }))
    });
  }

  const filteredGroups = groups.filter(g => matchesQuery(query, g.name));
  if (filteredGroups.length) {
    sections.push({
      title: 'Groups',
      items: filteredGroups.slice(0, 5).map(g => ({
        id: `group-${g.id}`, kind: 'group',
        label: g.name, sub: g.parent ? `parent: ${g.parent}` : 'root',
        icon: 'group',
        run: () => onNavigate('inventory')
      }))
    });
  }

  const filteredPlays = plays.filter(p => matchesQuery(query, p.name, p.title));
  if (filteredPlays.length) {
    sections.push({
      title: 'Playbooks',
      items: filteredPlays.slice(0, 5).map(p => ({
        id: `pb-${p.id}`, kind: 'pb',
        label: p.name, sub: p.title,
        icon: 'playbooks',
        run: () => onRunPlaybook(p.id)
      }))
    });
  }

  const filteredMods = mods.filter(m => matchesQuery(query, m.name, m.desc));
  if (filteredMods.length) {
    sections.push({
      title: 'Modules',
      items: filteredMods.slice(0, 6).map(m => ({
        id: `mod-${m.id}`, kind: 'mod',
        label: m.name, sub: m.desc,
        icon: 'code',
        run: () => onOpenAdhoc({ module: m.name })
      }))
    });
  }
  return sections;
}

function CommandPalette({ open, onClose, onNavigate, onOpenAdhoc, onRunPlaybook }) {
  const data = globalThis.AnsibleData || {};
  const hosts = data.HOSTS || [];
  const groups = data.GROUPS || [];
  const plays = data.PLAYBOOKS || [];
  const mods = data.MODULES || [];
  const [q, setQ] = useStateCP('');
  const [sel, setSel] = useStateCP(0);
  const inputRef = useRefCP(null);
  const dialogRef = globalThis.useDialog(open, onClose);

  useEffectCP(() => {
    if (!open) return undefined;
    setQ('');
    setSel(0);
    const t = setTimeout(() => inputRef.current?.focus(), 20);
    return () => clearTimeout(t);
  }, [open]);

  const actions = useMemoCP(() => buildActions(onNavigate, onOpenAdhoc), [onNavigate, onOpenAdhoc]);
  const results = useMemoCP(
    () => buildSections({ query: q.trim(), actions, hosts, groups, plays, mods, onNavigate, onRunPlaybook, onOpenAdhoc }),
    [q, actions, hosts, groups, plays, mods, onNavigate, onRunPlaybook, onOpenAdhoc]
  );
  const flat = useMemoCP(() => results.flatMap(s => s.items), [results]);

  useEffectCP(() => { setSel(0); }, [q]);

  const handleKey = (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(flat.length - 1, s + 1)); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(0, s - 1)); return; }
    if (e.key === 'Enter') {
      e.preventDefault();
      const item = flat[sel];
      if (item) { item.run(); onClose(); }
    }
  };

  let running = 0;
  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-center"
      aria-label="Command palette"
      {...globalThis.dialogBackdropHandlers(dialogRef, onClose)}
      onKeyDown={handleKey}
    >
      <div className="cp">
        <div className="cp-head">
          <Icon name="search" size={14} className="mute" />
          <input
            ref={inputRef}
            className="cp-input"
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Type a command, host, playbook…"
            aria-label="Command palette query"
          />
          <span className="kbd">esc</span>
        </div>
        <div className="cp-body">
          {results.length === 0 && (
            <div className="cp-empty">No results. Try <span className="mono">ping</span>, <span className="mono">deploy</span>, or <span className="mono">web</span>.</div>
          )}
          {results.map(section => (
            <div className="cp-section" key={section.title}>
              <div className="cp-section-title">{section.title}</div>
              {section.items.map(it => {
                const idx = running++;
                const active = idx === sel;
                return (
                  <button
                    key={it.id}
                    type="button"
                    className={`cp-row ${active ? 'active' : ''}`}
                    onMouseEnter={() => setSel(idx)}
                    onClick={() => { it.run(); onClose(); }}
                  >
                    <span className="cp-icon"><Icon name={it.icon} size={14} /></span>
                    <span className="cp-row-main">
                      <span className="cp-row-label">
                        {it.statusDot && <span className={`dot ${it.statusDot}`} style={{ marginRight: 6 }}/>}
                        {it.label}
                      </span>
                      {it.sub && <span className="cp-row-sub mute">{it.sub}</span>}
                    </span>
                    {it.hint && <span className="cp-hint mono">{it.hint}</span>}
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="cp-foot">
          <span><span className="kbd">↑</span><span className="kbd">↓</span> navigate</span>
          <span><span className="kbd">↵</span> select</span>
          <span><span className="kbd">esc</span> close</span>
          <span style={{ marginLeft: 'auto' }} className="mute">{flat.length} results</span>
        </div>
      </div>
    </dialog>
  );
}

globalThis.CommandPalette = CommandPalette;
