// Secrets / Vault view

const { useState: useStateV } = React;

function VaultView() {
  const { SECRETS } = window.AnsibleData;
  const [selectedId, setSelectedId] = useStateV(SECRETS[0]?.id || '');
  const [revealed, setRevealed] = useStateV(false);
  if (!SECRETS.length) {
    return (
      <div className="view view-vault">
        <div className="view-head">
          <div>
            <h1 className="view-title">Secrets</h1>
            <div className="view-sub mute">Vault discovery is not wired up yet. Add vault-encrypted variables under the remote workDir and they'll be listed here in a future release.</div>
          </div>
        </div>
      </div>
    );
  }
  const s = SECRETS.find(x => x.id === selectedId) || SECRETS[0];

  const iconFor = (t) => t === 'ssh-key' ? 'key' : t === 'cert' ? 'cert' : 'vault';

  return (
    <div className="view view-vault">
      <div className="view-head">
        <div>
          <h1 className="view-title">Secrets</h1>
          <div className="view-sub mute">Vault-encrypted variables, SSH keys and certs. {SECRETS.length} items.</div>
        </div>
        <div className="view-actions">
          <button className="btn small"><Icon name="download" size={12}/> Rotate schedule</button>
          <button className="btn primary small"><Icon name="plus" size={12}/> New secret</button>
        </div>
      </div>

      <div className="vault-body">
        <aside className="vault-list card">
          {SECRETS.map(x => (
            <button key={x.id} className={`vault-row ${selectedId === x.id ? 'active' : ''}`} onClick={() => setSelectedId(x.id)}>
              <span className="vault-row-icon"><Icon name={iconFor(x.type)} size={14}/></span>
              <div className="vault-row-main">
                <div className="vault-row-name mono">{x.name}</div>
                <div className="vault-row-sub">
                  <span className="mini-tag mono">{x.type}</span>
                  <span className="mute mono">{x.scope}</span>
                </div>
              </div>
              <span className="mute mono" style={{ fontSize: 11 }}>{x.updated}</span>
            </button>
          ))}
        </aside>

        <main className="vault-detail card">
          <div className="vault-detail-head">
            <div>
              <div className="section-title">Secret</div>
              <h2 className="mono" style={{ margin: '4px 0 2px' }}>{s.name}</h2>
              <div className="mute" style={{ fontSize: 12.5 }}>
                <span className="mini-tag mono">{s.type}</span>
                <span style={{ marginLeft: 8 }}>scope <span className="mono" style={{ color: 'var(--text)' }}>{s.scope}</span></span>
                <span className="mute-2"> · </span>
                <span>last updated <span className="mono" style={{ color: 'var(--text)' }}>{s.updated}</span></span>
                <span className="mute-2"> · </span>
                <span>used by <span className="mono" style={{ color: 'var(--text)' }}>{s.usedBy}</span> playbooks</span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn small"><Icon name="history" size={12}/> Audit log</button>
              <button className="btn small"><Icon name="refresh" size={12}/> Rotate</button>
              <button className="btn small"><Icon name="more" size={12}/></button>
            </div>
          </div>

          <div className="divider" style={{ margin: '14px 0' }}/>

          <div className="section-title">Keys</div>
          <div className="vault-keys">
            {s.keys.map(k => (
              <div className="vault-key" key={k}>
                <div className="mono">{k}</div>
                <div className="vault-key-val">
                  {revealed ? (
                    <span className="mono">{fakeValue(k)}</span>
                  ) : (
                    <span className="mono mute-2">••••••••••••••••••••••••••••••••</span>
                  )}
                </div>
                <div className="vault-key-actions">
                  <button className="btn ghost small" onClick={() => setRevealed(r => !r)}>
                    {revealed ? 'Hide' : 'Reveal'}
                  </button>
                  <button className="btn ghost small">Copy</button>
                </div>
              </div>
            ))}
          </div>

          <div className="divider" style={{ margin: '14px 0' }}/>

          <div className="section-title">Encrypted reference</div>
          <div className="code-pane small">
            <pre className="code-block"><code>
              <span className="yml-k mono">vault_ref</span><span className="yml-p">:</span>{' '}
              <span className="yml-s mono">!vault |</span>{'\n'}
              {'          '}<span className="yml-c mono">$ANSIBLE_VAULT;1.2;AES256;acme-prod{'\n'}</span>
              {'          '}<span className="yml-c mono">30613766646137306632306466323966366538356664343635396161353332623762313465{'\n'}</span>
              {'          '}<span className="yml-c mono">31366238346338373162343062623564663665306532616464363665653338303261333631{'\n'}</span>
              {'          '}<span className="yml-c mono">3966633061613964623666363762336466{'\n'}</span>
            </code></pre>
          </div>

          <div className="divider" style={{ margin: '14px 0' }}/>

          <div className="section-title">Used by</div>
          <div className="vault-usedby">
            <div className="usedby-row"><Icon name="playbooks" size={13}/><span className="mono">deploy-app.yml</span><span className="mute" style={{ marginLeft: 'auto' }}>last ran 2h ago</span></div>
            <div className="usedby-row"><Icon name="playbooks" size={13}/><span className="mono">db-backup.yml</span><span className="mute" style={{ marginLeft: 'auto' }}>last ran 12h ago</span></div>
          </div>
        </main>
      </div>
    </div>
  );
}

function fakeValue(key) {
  if (key.includes('pub')) return 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx4… deploy@relay';
  if (key.includes('key')) return '-----BEGIN OPENSSH PRIVATE KEY-----';
  if (key.includes('password')) return 'Jkp2-Lx91vQ!mZ7#eR4tBn8wYc6Fa3Dq';
  if (key.includes('secret') || key.includes('webhook')) return 'stripe-key-redacted';
  if (key.endsWith('.pem')) return '-----BEGIN CERTIFICATE-----';
  return 'opaque-value-redacted';
}

window.VaultView = VaultView;
