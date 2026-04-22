// Connection manager + settings dialog.
//
// Shown at startup when no active server is configured, and accessible
// from the topbar once one is. Owns:
//   - list of saved ansible server connections
//   - add/edit/test/delete + activate
//   - prometheus URL + host-label settings

const {
  useState: useStateCM,
  useEffect: useEffectCM,
  useCallback: useCallbackCM
} = React;

const EMPTY_FORM = Object.freeze({
  id: '',
  name: '',
  host: '',
  port: 22,
  user: '',
  keyPath: '',
  workDir: '',
  inventory: ''
});

function ConnectionManager({ open, onClose, onActivated, initialServers, initialActiveId }) {
  const [servers, setServers] = useStateCM(initialServers || []);
  const [activeId, setActiveId] = useStateCM(initialActiveId || '');
  const [form, setForm] = useStateCM(EMPTY_FORM);
  const [busy, setBusy] = useStateCM(false);
  const [testResult, setTestResult] = useStateCM(null);
  const [error, setError] = useStateCM('');
  const [promUrl, setPromUrl] = useStateCM('');
  const [promLabel, setPromLabel] = useStateCM('instance');
  const [tab, setTab] = useStateCM('servers');

  const refreshServers = useCallbackCM(async () => {
    const res = await globalThis.RelayAPI.listServers();
    setServers(res.servers || []);
    setActiveId(res.activeServerId || '');
  }, []);

  useEffectCM(() => {
    if (!open) return;
    refreshServers();
    globalThis.RelayAPI.getSettings().then(s => {
      setPromUrl(s.prometheusUrl || '');
      setPromLabel(s.prometheusHostLabel || 'instance');
    }).catch(() => {});
  }, [open, refreshServers]);

  const updateForm = (patch) => setForm(prev => ({ ...prev, ...patch }));

  const startEdit = (s) => {
    setForm({
      id: s.id,
      name: s.name || '',
      host: s.host || '',
      port: s.port || 22,
      user: s.user || '',
      keyPath: s.keyPath || '',
      workDir: s.workDir || '',
      inventory: s.inventory || ''
    });
    setTestResult(null);
    setError('');
  };

  const resetForm = () => { setForm(EMPTY_FORM); setTestResult(null); setError(''); };

  const save = async () => {
    setBusy(true); setError('');
    try {
      const payload = { ...form, port: Number(form.port) || 22 };
      const saved = await globalThis.RelayAPI.upsertServer(payload);
      await refreshServers();
      setForm(EMPTY_FORM);
      if (!activeId) {
        await globalThis.RelayAPI.activateServer(saved.id);
        await refreshServers();
        // Tell the parent (Boot/App) a server is now active so it can
        // transition from picker to ready. Without this the modal stays
        // open even though the backend is configured.
        onActivated?.(saved.id);
      }
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const activate = async (id) => {
    setBusy(true); setError('');
    try {
      await globalThis.RelayAPI.activateServer(id);
      await refreshServers();
      onActivated?.(id);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const remove = async (id) => {
    if (!globalThis.confirm('Delete this connection?')) return;
    setBusy(true); setError('');
    try {
      await globalThis.RelayAPI.deleteServer(id);
      await refreshServers();
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const testConnection = async (id) => {
    setBusy(true); setError(''); setTestResult(null);
    try {
      const res = await globalThis.RelayAPI.testServer(id);
      setTestResult(res);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const saveSettings = async () => {
    setBusy(true); setError('');
    try {
      await globalThis.RelayAPI.setSettings({
        prometheusUrl: promUrl.trim(),
        prometheusHostLabel: promLabel.trim() || 'instance'
      });
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const dialogRef = globalThis.useDialog(open, onClose);

  return (
    <dialog
      ref={dialogRef}
      className="relay-dialog relay-dialog-center"
      aria-label="Connections and settings"
      onClick={(e) => { if (e.target === dialogRef.current) onClose(); }}
    >
      <div className="cm">
        <div className="cm-head">
          <div className="seg">
            <button type="button" className={tab === 'servers' ? 'on' : ''} onClick={() => setTab('servers')}>Ansible servers</button>
            <button type="button" className={tab === 'settings' ? 'on' : ''} onClick={() => setTab('settings')}>Settings</button>
          </div>
          <button type="button" className="btn ghost small" onClick={onClose}><Icon name="x" size={14}/></button>
        </div>
        {error && <div className="cm-error mono">{error}</div>}
        {tab === 'servers' ? (
          <ServersTab
            servers={servers} activeId={activeId} form={form} busy={busy}
            testResult={testResult}
            onActivate={activate} onEdit={startEdit} onDelete={remove}
            onTest={testConnection} onReset={resetForm}
            onChangeForm={updateForm} onSubmit={save}
          />
        ) : (
          <SettingsTab
            promUrl={promUrl} promLabel={promLabel} busy={busy}
            onChangeUrl={setPromUrl} onChangeLabel={setPromLabel}
            onSave={saveSettings}
          />
        )}
      </div>
    </dialog>
  );
}

function ServersTab(props) {
  const {
    servers, activeId, form, busy, testResult,
    onActivate, onEdit, onDelete, onTest, onReset,
    onChangeForm, onSubmit
  } = props;
  return (
    <div className="cm-body">
      <div className="cm-pane">
        <div className="section-title">Connections · {servers.length}</div>
        {servers.length === 0 && <div className="mute" style={{ padding: '12px 0', fontSize: 12 }}>No connections yet. Add one on the right.</div>}
        {servers.map(s => (
          <div key={s.id} className={`cm-row ${s.id === activeId ? 'active' : ''}`}>
            <div>
              <div className="mono" style={{ fontSize: 13, fontWeight: 550 }}>{s.name}</div>
              <div className="mute mono" style={{ fontSize: 11.5 }}>
                {s.user}@{s.host}:{s.port || 22}
                {s.workDir && <span> · {s.workDir}</span>}
              </div>
            </div>
            <div className="cm-row-actions">
              {s.id === activeId
                ? <span className="pill ok">active</span>
                : <button type="button" className="btn small" disabled={busy} onClick={() => onActivate(s.id)}>Activate</button>}
              <button type="button" className="btn ghost small" disabled={busy} onClick={() => onTest(s.id)}>Test</button>
              <button type="button" className="btn ghost small" disabled={busy} onClick={() => onEdit(s)}>Edit</button>
              <button type="button" className="btn ghost small" disabled={busy} onClick={() => onDelete(s.id)}><Icon name="x" size={12}/></button>
            </div>
          </div>
        ))}
        {testResult && (
          <div className={`cm-test ${testResult.ok ? 'ok' : 'err'} mono`} style={{ fontSize: 11.5 }}>
            {testResult.ok ? <>✓ {testResult.version || 'ok'}</> : <>✗ {testResult.error}</>}
          </div>
        )}
      </div>
      <div className="cm-pane">
        <div className="section-title">{form.id ? 'Edit connection' : 'New connection'}</div>
        <ServerForm form={form} busy={busy} onChange={onChangeForm} onReset={onReset} onSubmit={onSubmit}/>
      </div>
    </div>
  );
}

function SettingsTab({ promUrl, promLabel, busy, onChangeUrl, onChangeLabel, onSave }) {
  const [probe, setProbe] = useStateCM(null);
  const [probing, setProbing] = useStateCM(false);

  const runProbe = async () => {
    setProbing(true);
    try {
      const res = await globalThis.RelayAPI.metrics();
      setProbe(res);
    } catch (e) {
      setProbe({ error: e.message });
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="cm-body cm-single">
      <div className="cm-pane">
        <div className="section-title">Prometheus</div>
        <div className="mute" style={{ fontSize: 12, marginBottom: 12 }}>
          Live CPU / memory / load / uptime / OS are pulled from Prometheus and matched to inventory hosts by label.
          Leave blank to show static values only.
        </div>
        <Field id="prom-url" label="Prometheus URL" placeholder="http://prom.example.com:9090"
               value={promUrl} onChange={onChangeUrl}/>
        <Field id="prom-label" label="Host label" placeholder="instance"
               value={promLabel} onChange={onChangeLabel}/>
        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          <button type="button" className="btn primary small" disabled={busy} onClick={onSave}>Save</button>
          <button type="button" className="btn small" disabled={probing} onClick={runProbe}>
            {probing ? 'Probing…' : 'Test queries'}
          </button>
        </div>
        {probe && <ProbeReport report={probe}/>}
      </div>
    </div>
  );
}

function ProbeReport({ report }) {
  if (report.error) {
    return <div className="cm-error mono" style={{ marginTop: 12 }}>{report.error}</div>;
  }
  if (!report.configured) {
    return <div className="mute" style={{ marginTop: 12, fontSize: 12 }}>No Prometheus URL configured.</div>;
  }
  const hosts = Object.keys(report.metrics || {});
  return (
    <div style={{ marginTop: 14 }}>
      <div className="section-title" style={{ marginBottom: 6 }}>Query results</div>
      <table className="t" style={{ width: '100%', marginBottom: 10 }}>
        <thead>
          <tr>
            <th style={{ cursor: 'default' }}>Probe</th>
            <th style={{ cursor: 'default' }}>Samples</th>
            <th style={{ cursor: 'default' }}>Error</th>
          </tr>
        </thead>
        <tbody>
          {(report.probes || []).map(p => (
            <tr key={p.name}>
              <td className="mono">{p.name}</td>
              <td className="mono" style={{ color: p.samples > 0 ? 'var(--ok)' : 'var(--text-3)' }}>{p.samples}</td>
              <td className="mono mute" style={{ color: p.error ? 'var(--err)' : undefined, maxWidth: 400, whiteSpace: 'normal' }}>{p.error || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mute" style={{ fontSize: 12 }}>
        Matched hosts in Prometheus: <b style={{ color: 'var(--text)' }}>{hosts.length}</b>
        {hosts.length > 0 && <> — <span className="mono">{hosts.slice(0, 5).join(', ')}{hosts.length > 5 ? `, +${hosts.length - 5}` : ''}</span></>}
      </div>
    </div>
  );
}

function ServerForm({ form, busy, onChange, onReset, onSubmit }) {
  return (
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }}>
      <Field id="srv-name" label="Name" placeholder="prod-ansible" value={form.name} onChange={v => onChange({ name: v })}/>
      <div className="cm-row-grid">
        <Field id="srv-host" label="Host" placeholder="ansible.example.com" value={form.host} onChange={v => onChange({ host: v })}/>
        <Field id="srv-port" label="Port" type="number" value={form.port} onChange={v => onChange({ port: v })}/>
      </div>
      <Field id="srv-user" label="SSH user" placeholder="ansible" value={form.user} onChange={v => onChange({ user: v })}/>
      <Field id="srv-key" label="Key path (optional)" placeholder="~/.ssh/id_ed25519" value={form.keyPath} onChange={v => onChange({ keyPath: v })}/>
      <Field id="srv-workdir" label="Working dir (playbook repo on remote)" placeholder="/home/ansible/ops" value={form.workDir} onChange={v => onChange({ workDir: v })}/>
      <Field id="srv-inv" label="Inventory path (optional)" placeholder="inventory/production.yml" value={form.inventory} onChange={v => onChange({ inventory: v })}/>
      <div className="mute" style={{ fontSize: 11, marginTop: 6 }}>
        SSH auth uses your running ssh-agent by default; specify a key path for unattended keys.
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
        <button className="btn primary small" type="submit" disabled={busy}>{form.id ? 'Update' : 'Create'}</button>
        <button className="btn ghost small" type="button" disabled={busy} onClick={onReset}>Reset</button>
      </div>
    </form>
  );
}

function Field({ id, label, value, onChange, placeholder, type }) {
  return (
    <div className="cm-field">
      <label htmlFor={id} className="cm-field-label">{label}</label>
      <input
        id={id}
        className="input mono"
        type={type || 'text'}
        value={value ?? ''}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

globalThis.ConnectionManager = ConnectionManager;
