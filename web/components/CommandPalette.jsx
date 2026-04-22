// Global command palette — ⌘K
// Fuzzy-ish search across: navigation, hosts, groups, playbooks, modules, actions.
// Selecting a module offers to open the ad-hoc runner pre-filled.

const { useState: useStateCP, useEffect: useEffectCP, useMemo: useMemoCP, useRef: useRefCP } = React;

function CommandPalette({ open, onClose, onNavigate, onOpenAdhoc, onRunPlaybook }) {
  const { HOSTS, GROUPS, PLAYBOOKS, MODULES } = window.AnsibleData;
  const [q, setQ] = useStateCP('');
  const [sel, setSel] = useStateCP(0);
  const inputRef = useRefCP(null);

  useEffectCP(() => {
    if (open) {
      setQ('');
      setSel(0);
      setTimeout(() => inputRef.current?.focus(), 20);
    }
  }, [open]);

  const actions = useMemoCP(() => ([
    { id: 'nav-dashboard', kind: 'nav', label: 'Go to Dashboard', hint: 'g d', icon: 'dashboard', run: () => onNavigate('dashboard') },
    { id: 'nav-inventory', kind: 'nav', label: 'Go to Inventory', hint: 'g i', icon: 'inventory', run: () => onNavigate('inventory') },
    { id: 'nav-playbooks', kind: 'nav', label: 'Go to Playbooks', hint: 'g p', icon: 'playbooks', run: () => onNavigate('playbooks') },
    { id: 'nav-adhoc', kind: 'nav', label: 'Run ad-hoc command…', hint: 'g a', icon: 'terminal', run: () => onNavigate('adhoc') },
    { id: 'nav-history', kind: 'nav', label: 'Open run history', hint: 'g r', icon: 'history', run: () => onNavigate('history') },
    { id: 'nav-vault', kind: 'nav', label: 'Open secrets', hint: 'g s', icon: 'vault', run: () => onNavigate('vault') },
    { id: 'act-ping-all', kind: 'action', label: 'Ping all production hosts', icon: 'bolt', run: () => onOpenAdhoc({ module: 'ansible.builtin.ping', target: 'production' }) },
    { id: 'act-gather-facts', kind: 'action', label: 'Gather facts across inventory', icon: 'refresh', run: () => onOpenAdhoc({ module: 'ansible.builtin.setup', target: 'all' }) }
  ]), [onNavigate, onOpenAdhoc]);

  const results = useMemoCP(() => {
    const query = q.trim().toLowerCase();
    const sections = [];

    const matchList = (items, getLabel, getSub) => {
      if (!query) return items;
      return items.filter(i => {
        const l = getLabel(i).toLowerCase();
        return l.includes(query) || (getSub && getSub(i).toLowerCase().includes(query));
      });
    };

    const acts = matchList(actions, a => a.label, a => a.hint || '');
    if (acts.length) sections.push({ title: 'Actions', items: acts.slice(0, 8) });

    const hosts = matchList(HOSTS, h => h.name, h => h.groups.join(' '));
    if (hosts.length) {
      sections.push({
        title: `Hosts · ${hosts.length}`,
        items: hosts.slice(0, 5).map(h => ({
          id: `host-${h.id}`,
          kind: 'host',
          label: h.name,
          sub: `${h.ip} · ${h.groups.slice(0, 3).join(', ')}`,
          icon: 'server',
          statusDot: h.status,
          run: () => { onNavigate('inventory'); }
        }))
      });
    }

    const groups = matchList(GROUPS, g => g.name);
    if (groups.length) {
      sections.push({
        title: 'Groups',
        items: groups.slice(0, 5).map(g => ({
          id: `group-${g.id}`, kind: 'group',
          label: g.name, sub: g.parent ? `parent: ${g.parent}` : 'root',
          icon: 'group',
          run: () => onNavigate('inventory')
        }))
      });
    }

    const plays = matchList(PLAYBOOKS, p => p.name, p => p.title);
    if (plays.length) {
      sections.push({
        title: 'Playbooks',
        items: plays.slice(0, 5).map(p => ({
          id: `pb-${p.id}`, kind: 'pb',
          label: p.name, sub: p.title,
          icon: 'playbooks',
          run: () => onRunPlaybook(p.id)
        }))
      });
    }

    const mods = matchList(MODULES, m => m.name, m => m.desc);
    if (mods.length) {
      sections.push({
        title: 'Modules',
        items: mods.slice(0, 6).map(m => ({
          id: `mod-${m.id}`, kind: 'mod',
          label: m.name, sub: m.desc,
          icon: 'code',
          run: () => onOpenAdhoc({ module: m.name })
        }))
      });
    }

    return sections;
  }, [q, actions]);

  const flat = useMemoCP(() => results.flatMap(s => s.items), [results]);

  useEffectCP(() => { setSel(0); }, [q]);

  useEffectCP(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(flat.length - 1, s + 1)); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(0, s - 1)); }
      else if (e.key === 'Enter') {
        e.preventDefault();
        const item = flat[sel];
        if (item) { item.run(); onClose(); }
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, flat, sel, onClose]);

  if (!open) return null;

  let running = 0;
  return (
    <div className="cp-scrim" onMouseDown={onClose}>
      <div className="cp" onMouseDown={e => e.stopPropagation()}>
        <div className="cp-head">
          <Icon name="search" size={14} className="mute" />
          <input
            ref={inputRef}
            className="cp-input"
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Type a command, host, playbook…"
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
    </div>
  );
}

window.CommandPalette = CommandPalette;
