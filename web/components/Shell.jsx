// App shell: sidebar navigation + top bar.
//
// The upstream handoff bundle shipped an in-browser "tweaks" panel that
// talked to the claude.ai design editor via window.parent.postMessage.
// That protocol is irrelevant once we run standalone, and the wildcard
// target origin ('*') is a genuine vulnerability (Sonar S2819), so the
// panel is intentionally not rendered here.

const { useState, useEffect, useLayoutEffect, useRef, useCallback, useMemo } = React;

// useDialog binds a <dialog> element to a controlled `open` boolean.
// - open true  → el.showModal() (adds to the top layer + backdrop)
// - open false → el.close() (fires 'close' event)
// - unmount    → close the dialog if still open, so we don't leak a
//                top-layer element on route/phase transitions
// - onClose    → fires when the dialog closes for any reason (Escape,
//                our el.close() call, form method="dialog", etc.)
//
// opts.guardClose (optional): a predicate consulted on every native
// close. When it returns false the close is vetoed and, if the element
// already went away (a browser can force a <dialog> shut on a second
// Escape with no cancelable 'cancel' event), it is re-shown. This is
// the authoritative teardown chokepoint — intercepting 'cancel' alone
// misses the force-close path, so a streamed run could be silently
// aborted. Explicit affordances (✕ / backdrop) must run their own
// confirm before calling onClose, since those set open=false first and
// so slip past this guard.
function useDialog(open, onClose, opts) {
  const ref = useRef(null);
  const guardClose = opts && opts.guardClose;
  // useLayoutEffect so showModal / close runs before paint.
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    // We guard every call with el.open so showModal() can't throw the
    // InvalidStateError that would otherwise come from re-opening, and
    // close() is a no-op on an already-closed dialog.
    if (open && !el.open) el.showModal();
    else if (!open && el.open) el.close();
    return () => {
      // On unmount, if React is removing the element while it's still
      // in the top layer, tear it down explicitly.
      if (el.open) el.close();
    };
  }, [open]);
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    const handler = () => {
      // Only guard closes that happen while the dialog is meant to be
      // open — a programmatic close (open already false) is the app
      // closing it deliberately and must pass through.
      if (guardClose && open && !guardClose()) {
        if (!el.open) el.showModal();
        return;
      }
      if (onClose) onClose();
    };
    el.addEventListener('close', handler);
    return () => el.removeEventListener('close', handler);
  }, [onClose, guardClose, open]);
  return ref;
}

// confirmAbandonRun is the single source of the "a run is streaming —
// leaving aborts it on the remote" prompt, shared by the nav guard,
// the dialog-close guard, and the run-dialog buttons so their wording
// (and any future "skip the confirm once the run's terminal event
// arrived" logic) can't drift. `verb` describes the action, e.g.
// "leaving this page" or "closing the dialog". Returns true when the
// caller may proceed.
function confirmAbandonRun(label, verb) {
  return globalThis.confirm(`${label} is still streaming — ${verb} aborts it on the remote. Continue anyway?`);
}

// useRunGuard registers a global marker while a streamed run is in
// flight. Two consumers: App's navigation wrapper confirms before
// switching views (unmounting the view closes its WebSocket, and the
// backend kills the remote ansible process when the peer drops), and
// a beforeunload handler makes the browser ask before a tab close /
// refresh silently does the same.
function useRunGuard(running, label) {
  useEffect(() => {
    if (!running) return undefined;
    globalThis.AnsbuiActiveRun = { label };
    const onBeforeUnload = (e) => { e.preventDefault(); e.returnValue = ''; };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => {
      globalThis.AnsbuiActiveRun = null;
      window.removeEventListener('beforeunload', onBeforeUnload);
    };
  }, [running, label]);
}

const NAV_BASE = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', hint: 'g d' },
  { id: 'inventory', label: 'Inventory', icon: 'inventory', hint: 'g i', countKey: 'HOSTS' },
  { id: 'playbooks', label: 'Playbooks', icon: 'playbooks', hint: 'g p', countKey: 'PLAYBOOKS' },
  { id: 'adhoc', label: 'Ad-hoc', icon: 'terminal', hint: 'g a' },
  { id: 'bootstrap', label: 'Bootstrap', icon: 'plus', hint: 'g n' },
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
          <div className="brand-name">ansbui</div>
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
          <span className="mono">ansbui</span>
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

// dialogBackdropHandlers builds the onClick / onKeyDown pair that
// every modal dialog in the app uses to close on backdrop click or
// Escape. Native <dialog> already closes on Escape, but having an
// explicit onKeyDown satisfies Sonar S1082 ("visible interactive
// element with click must have at least one keyboard listener").
function dialogBackdropHandlers(ref, onClose) {
  return {
    onClick: (e) => { if (e.target === ref.current) onClose(); },
    onKeyDown: (e) => { if (e.key === 'Escape') onClose(); }
  };
}

// AnsbuiCenterDialog is the shell used by every top-centred modal in
// the app — connection manager, command palette, ad-hoc recent /
// save-as-playbook, playbook history / import / run-limit picker.
// The shell owns:
//   - the <dialog> element with backdrop handlers + useDialog binding
//   - the cm chrome (width / maxHeight sizing, title + subtitle,
//     close button in the header)
//   - a single-pane body; callers render whatever content they need
//     into children
// Extra props on the outer <dialog> can be threaded via dialogProps
// (the command palette uses this for its global onKeyDown).
function AnsbuiCenterDialog({
  open,
  onClose,
  title,
  subtitle,
  ariaLabel,
  width,
  maxHeight,
  dialogProps,
  children
}) {
  const dialogRef = useDialog(open, onClose);
  return (
    <dialog
      ref={dialogRef}
      className="ansbui-dialog ansbui-dialog-center"
      aria-label={ariaLabel || (typeof title === 'string' ? title : undefined)}
      {...dialogBackdropHandlers(dialogRef, onClose)}
      {...(dialogProps || {})}
    >
      <div className="cm" style={{ width: width || 'min(680px, 94vw)', maxHeight: maxHeight || '82vh' }}>
        <div className="cm-head">
          <div>
            <div className="section-title">{title}</div>
            {subtitle && <div className="mute" style={{ fontSize: 12, marginTop: 2 }}>{subtitle}</div>}
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}>
            <Icon name="x" size={14}/>
          </button>
        </div>
        <div className="cm-body cm-single">
          <div className="cm-pane">
            {children}
          </div>
        </div>
      </div>
    </dialog>
  );
}

globalThis.Sidebar = Sidebar;
globalThis.TopNav = TopNav;
globalThis.TopLayoutNav = TopLayoutNav;
globalThis.TWEAK_DEFAULTS = TWEAK_DEFAULTS;
globalThis.useDialog = useDialog;
globalThis.useRunGuard = useRunGuard;
globalThis.confirmAbandonRun = confirmAbandonRun;
globalThis.dialogBackdropHandlers = dialogBackdropHandlers;
globalThis.AnsbuiCenterDialog = AnsbuiCenterDialog;
