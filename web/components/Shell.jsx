// App shell: sidebar navigation, top bar, theme + density + accent + layout
// Owns global keyboard shortcuts (⌘K command palette, ⌘/ help, g+d/i/p etc.)

const { useState, useEffect, useRef, useCallback, useMemo } = React;

const NAV_BASE = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', hint: 'g d' },
  { id: 'inventory', label: 'Inventory', icon: 'inventory', hint: 'g i', countKey: 'HOSTS' },
  { id: 'playbooks', label: 'Playbooks', icon: 'playbooks', hint: 'g p', countKey: 'PLAYBOOKS' },
  { id: 'adhoc', label: 'Ad-hoc', icon: 'terminal', hint: 'g a' },
  { id: 'history', label: 'Runs', icon: 'history', hint: 'g r', countKey: 'RUNS' },
  { id: 'vault', label: 'Secrets', icon: 'vault', hint: 'g s' }
];

function resolveNavItems() {
  const d = window.AnsibleData || {};
  return NAV_BASE.map((item) => {
    if (!item.countKey) return item;
    const list = d[item.countKey] || [];
    return { ...item, count: list.length };
  });
}

function Sidebar({ view, setView, collapsed }) {
  const items = resolveNavItems();
  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="sb-brand">
        <div className="brand-mark" aria-hidden>
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

function TopNav({ view, setView, onOpenPalette, breadcrumb, activeName, onManage }) {
  return (
    <header className="topnav">
      <div className="tn-left">
        <div className="tn-crumb">
          {breadcrumb.map((c, i) => (
            <React.Fragment key={i}>
              {i > 0 && <Icon name="chevron-right" size={12} className="mute-2" />}
              <span className={i === breadcrumb.length - 1 ? 'tn-crumb-current' : 'mute'}>{c}</span>
            </React.Fragment>
          ))}
        </div>
      </div>
      <div className="tn-center">
        <button className="tn-search" onClick={onOpenPalette}>
          <Icon name="search" size={13} />
          <span>Search hosts, playbooks, runs…</span>
          <span className="kbd">⌘</span><span className="kbd">K</span>
        </button>
      </div>
      <div className="tn-right">
        {activeName && (
          <button className="btn ghost small" onClick={onManage} title="Manage ansible servers & settings">
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

// ---------- Tweaks panel ----------

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "dark",
  "accentHue": 155,
  "density": "balanced",
  "navLayout": "sidebar"
}/*EDITMODE-END*/;

const ACCENTS = [
  { hue: 155, name: 'Moss' },
  { hue: 235, name: 'Azure' },
  { hue: 280, name: 'Iris' },
  { hue: 25, name: 'Amber' },
  { hue: 340, name: 'Rose' },
  { hue: 190, name: 'Teal' }
];

function TweaksPanel({ visible, tweaks, setTweaks, onClose }) {
  if (!visible) return null;
  const update = (patch) => {
    const next = { ...tweaks, ...patch };
    setTweaks(next);
    window.parent?.postMessage({ type: '__edit_mode_set_keys', edits: patch }, '*');
  };
  return (
    <div className="tweaks">
      <div className="tweaks-head">
        <span className="section-title">Tweaks</span>
        <button className="btn ghost small" onClick={onClose}><Icon name="x" size={12} /></button>
      </div>

      <div className="tweaks-row">
        <div className="tweaks-label">Theme</div>
        <div className="seg">
          <button className={tweaks.theme === 'dark' ? 'on' : ''} onClick={() => update({ theme: 'dark' })}><Icon name="moon" size={12}/> Dark</button>
          <button className={tweaks.theme === 'light' ? 'on' : ''} onClick={() => update({ theme: 'light' })}><Icon name="sun" size={12}/> Light</button>
        </div>
      </div>

      <div className="tweaks-row">
        <div className="tweaks-label">Accent</div>
        <div className="swatches">
          {ACCENTS.map(a => (
            <button key={a.hue}
              className={`sw ${tweaks.accentHue === a.hue ? 'on' : ''}`}
              style={{ '--h': a.hue }}
              title={a.name}
              onClick={() => update({ accentHue: a.hue })}
            />
          ))}
        </div>
      </div>

      <div className="tweaks-row">
        <div className="tweaks-label">Density</div>
        <div className="seg">
          <button className={tweaks.density === 'compact' ? 'on' : ''} onClick={() => update({ density: 'compact' })}>Compact</button>
          <button className={tweaks.density === 'balanced' ? 'on' : ''} onClick={() => update({ density: 'balanced' })}>Balanced</button>
          <button className={tweaks.density === 'comfortable' ? 'on' : ''} onClick={() => update({ density: 'comfortable' })}>Roomy</button>
        </div>
      </div>

      <div className="tweaks-row">
        <div className="tweaks-label">Layout</div>
        <div className="seg">
          <button className={tweaks.navLayout === 'sidebar' ? 'on' : ''} onClick={() => update({ navLayout: 'sidebar' })}>Sidebar</button>
          <button className={tweaks.navLayout === 'topnav' ? 'on' : ''} onClick={() => update({ navLayout: 'topnav' })}>Top nav</button>
        </div>
      </div>

      <div className="tweaks-hint mute">
        Toggle this panel from the toolbar <span className="kbd">Tweaks</span> switch.
      </div>
    </div>
  );
}

function TopLayoutNav({ view, setView }) {
  const items = resolveNavItems();
  return (
    <nav className="tn-layout-nav">
      {items.map(item => (
        <button key={item.id}
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

window.Sidebar = Sidebar;
window.TopNav = TopNav;
window.TopLayoutNav = TopLayoutNav;
window.TweaksPanel = TweaksPanel;
window.TWEAK_DEFAULTS = TWEAK_DEFAULTS;
