// App shell: sidebar navigation + top bar.
//
// The upstream handoff bundle shipped an in-browser "tweaks" panel that
// talked to the claude.ai design editor via window.parent.postMessage.
// That protocol is irrelevant once we run standalone, and the wildcard
// target origin ('*') is a genuine vulnerability (Sonar S2819), so the
// panel is intentionally not rendered here.

const { useState, useEffect, useRef, useCallback, useMemo } = React;

const NAV_BASE = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', hint: 'g d' },
  { id: 'inventory', label: 'Inventory', icon: 'inventory', hint: 'g i', countKey: 'HOSTS' },
  { id: 'playbooks', label: 'Playbooks', icon: 'playbooks', hint: 'g p', countKey: 'PLAYBOOKS' },
  { id: 'adhoc', label: 'Ad-hoc', icon: 'terminal', hint: 'g a' },
  { id: 'history', label: 'Runs', icon: 'history', hint: 'g r', countKey: 'RUNS' },
  { id: 'vault', label: 'Secrets', icon: 'vault', hint: 'g s' }
];

const TWEAK_DEFAULTS = {
  theme: 'dark',
  accentHue: 155,
  density: 'balanced',
  navLayout: 'sidebar'
};

function resolveNavItems() {
  const data = globalThis.AnsibleData || {};
  return NAV_BASE.map((item) => {
    if (!item.countKey) return item;
    const list = data[item.countKey] || [];
    return { ...item, count: list.length };
  });
}

function Sidebar({ view, setView, collapsed }) {
  const items = resolveNavItems();
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sb-brand">
        <div className="brand-mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="18" height="18">
            <path d="M4 19 12 4l8 15" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round"/>
            <path d="M7.8 15h8.4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/>
          </svg>
        </div>
        <div className="brand-text">
          <div className="brand-name">Relay</div>
          <div className="brand-sub mono">ops</div>
        </div>
      </div>

      <nav className="sb-nav">
        <div className="sb-group-title">Workspace</div>
        {items.map(item => (
          <button
            key={item.id}
            type="button"
            className={`sb-item ${view === item.id ? 'active' : ''}`}
            onClick={() => setView(item.id)}
          >
            <span className="sb-icon"><Icon name={item.icon} size={15} /></span>
            <span className="sb-label">{item.label}</span>
            {item.count != null && <span className="sb-count">{item.count}</span>}
            <span className="sb-hint mono">{item.hint}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}

function TopNav({ onOpenPalette, breadcrumb, activeName, onManage }) {
  const lastIndex = breadcrumb.length - 1;
  return (
    <header className="topnav">
      <div className="tn-left">
        <div className="tn-crumb">
          {breadcrumb.map((crumb, i) => (
            <React.Fragment key={`${i}-${crumb}`}>
              {i > 0 && <Icon name="chevron-right" size={12} className="mute-2" />}
              <span className={i === lastIndex ? 'tn-crumb-current' : 'mute'}>{crumb}</span>
            </React.Fragment>
          ))}
        </div>
      </div>
      <div className="tn-center">
        <button type="button" className="tn-search" onClick={onOpenPalette}>
          <Icon name="search" size={13} />
          <span>Search hosts, playbooks, runs…</span>
          <span className="kbd">⌘</span><span className="kbd">K</span>
        </button>
      </div>
      <div className="tn-right">
        {activeName && (
          <button type="button" className="btn ghost small" onClick={onManage} title="Manage ansible servers & settings">
            <Icon name="server" size={13} /> <span className="mono">{activeName}</span>
          </button>
        )}
        <div className="tn-sep" />
        <div className="tn-status">
          <span className="dot ok" />
          <span className="mono">relay</span>
        </div>
      </div>
    </header>
  );
}

function TopLayoutNav({ view, setView }) {
  const items = resolveNavItems();
  return (
    <nav className="tn-layout-nav">
      {items.map(item => (
        <button
          key={item.id}
          type="button"
          className={`tn-layout-item ${view === item.id ? 'active' : ''}`}
          onClick={() => setView(item.id)}
        >
          <Icon name={item.icon} size={13} />
          <span>{item.label}</span>
          {item.count != null && <span className="sb-count" style={{ marginLeft: 4 }}>{item.count}</span>}
        </button>
      ))}
    </nav>
  );
}

globalThis.Sidebar = Sidebar;
globalThis.TopNav = TopNav;
globalThis.TopLayoutNav = TopLayoutNav;
globalThis.TWEAK_DEFAULTS = TWEAK_DEFAULTS;
