// Secrets / Vault view — placeholder.
//
// Vault discovery (scanning the remote workDir for $ANSIBLE_VAULT-
// encrypted files and surfacing their scopes) isn't wired up yet.
// The component renders a single empty-state card so the nav item
// is still present and discoverable, but nothing here makes API
// calls or pretends to show data it doesn't have.

function VaultView() {
  return (
    <div className="view view-vault">
      <div className="view-head">
        <div>
          <h1 className="view-title">Secrets</h1>
          <div className="view-sub mute">
            Vault discovery isn't implemented yet. Once added, this view will list
            {' '}<span className="mono">$ANSIBLE_VAULT</span>{'-'}encrypted files found under the server's workDir,
            their scopes, and the playbooks that reference them.
          </div>
        </div>
      </div>
      <div className="card" style={{ padding: 24, textAlign: 'center', color: 'var(--text-3)' }}>
        <div style={{ fontSize: 12.5 }}>Nothing to show here yet.</div>
      </div>
    </div>
  );
}

globalThis.VaultView = VaultView;
