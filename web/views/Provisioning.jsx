// Provisioning view — operator enters the credentials for a fresh
// VPS, and the backend orchestrates DNS + SSH bootstrap + ansible
// user setup + sshd hardening + inventory registration. Step output
// streams back over the same event channel adhoc/playbook runs use.

const { useState: useStateProv, useEffect: useEffectProv, useRef: useRefProv } = React;

function ProvisioningView() {
  const [provider, setProvider] = useStateProv('');
  const [ip, setIp] = useStateProv('');
  const [port, setPort] = useStateProv('22');
  const [username, setUsername] = useStateProv('root');
  const [useSudo, setUseSudo] = useStateProv(false);
  const [password, setPassword] = useStateProv('');
  const [sudoPassword, setSudoPassword] = useStateProv('');
  const [hostname, setHostname] = useStateProv('');
  const [vaultPassword, setVaultPassword] = useStateProv('');
  const [running, setRunning] = useStateProv(false);
  const [output, setOutput] = useStateProv([]);
  const [error, setError] = useStateProv('');
  const streamRef = useRefProv(null);
  const outRef = useRefProv(null);

  useEffectProv(() => {
    if (username === 'root' && useSudo) setUseSudo(false);
  }, [username, useSudo]);

  useEffectProv(() => () => { if (streamRef.current) streamRef.current.close(); }, []);

  useEffectProv(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  const start = () => {
    if (running || !globalThis.AnsbuiAPI) return;
    setError('');
    if (!provider.trim()) { setError('Provider is required.'); return; }
    if (!ip.trim()) { setError('IP address is required.'); return; }
    const portNum = Number.parseInt(port, 10);
    if (!Number.isInteger(portNum) || portNum <= 0 || portNum > 65535) {
      setError('SSH port must be a valid TCP port.');
      return;
    }
    if (!username.trim()) { setError('Username is required.'); return; }
    if (!password) { setError('Password is required.'); return; }
    if (useSudo && !sudoPassword) { setError('Sudo password is required when using sudo.'); return; }
    if (!hostname.trim() || !hostname.includes('.')) { setError('Hostname must be fully-qualified (include the domain).'); return; }
    if (!vaultPassword) { setError('Vault password is required (used to decrypt porkbun credentials).'); return; }

    setOutput([]); setRunning(true);
    const log = [];
    const append = (entry) => { log.push(entry); setOutput([...log]); };

    const payload = {
      provider: provider.trim(),
      ip: ip.trim(),
      port: portNum,
      username: username.trim(),
      password,
      useSudo,
      sudoPassword: useSudo ? sudoPassword : '',
      hostname: hostname.trim(),
      vaultPassword
    };

    const ws = globalThis.AnsbuiAPI.openStream('provision', payload);
    streamRef.current = ws;
    let finished = false;
    const finish = (ok, text) => {
      if (finished) return;
      finished = true;
      append({ t: ok ? 'done' : 'fail', text });
      setRunning(false);
      ws.close();
      streamRef.current = null;
    };
    ws.onEvent((evt) => {
      if (evt.type === 'meta') append({ t: 'meta', text: evt.text || '' });
      else if (evt.type === 'ok') append({ t: 'ok', text: evt.text || '' });
      else if (evt.type === 'fail' || evt.type === 'error') finish(false, evt.text || 'failed');
      else if (evt.type === 'done') finish(true, evt.text || 'done');
    });
    ws.onClose(() => { if (!finished) finish(false, 'connection closed before completion'); });
    ws.onError(() => finish(false, 'WebSocket error — check backend logs'));
  };

  const cancel = () => {
    if (streamRef.current) streamRef.current.close();
    streamRef.current = null;
    setRunning(false);
  };

  return (
    <div className="view view-provision">
      <div className="view-head">
        <div>
          <h1 className="view-title">Provision</h1>
          <div className="view-sub mute">
            Bootstrap a fresh VPS into the inventory: porkbun DNS, ansible user with key auth, sshd → 4242, then add to a provider group.
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 16, marginTop: 12, maxWidth: 720 }}>
        {error && <div className="cm-error mono" style={{ marginBottom: 10 }}>{error}</div>}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <label htmlFor="prov-provider" className="cm-field-label">Provider</label>
            <input id="prov-provider" className="input mono" placeholder="hetzner, dartnode, …" value={provider} onChange={e => setProvider(e.target.value)} disabled={running}/>
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>Used as the inventory group name. Created if it doesn&rsquo;t exist.</div>
          </div>
          <div>
            <label htmlFor="prov-hostname" className="cm-field-label">Hostname / FQDN</label>
            <input id="prov-hostname" className="input mono" placeholder="ca-on-vps01.example.com" value={hostname} onChange={e => setHostname(e.target.value)} disabled={running}/>
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>Last two labels become the porkbun domain.</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10, marginTop: 10 }}>
          <div>
            <label htmlFor="prov-ip" className="cm-field-label">IP address</label>
            <input id="prov-ip" className="input mono" placeholder="203.0.113.42" value={ip} onChange={e => setIp(e.target.value)} disabled={running}/>
          </div>
          <div>
            <label htmlFor="prov-port" className="cm-field-label">SSH port</label>
            <input id="prov-port" className="input mono" placeholder="22" value={port} onChange={e => setPort(e.target.value)} disabled={running}/>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 10 }}>
          <div>
            <label htmlFor="prov-user" className="cm-field-label">Username</label>
            <input id="prov-user" className="input mono" placeholder="root" value={username} onChange={e => setUsername(e.target.value)} disabled={running}/>
          </div>
          <div>
            <label htmlFor="prov-pw" className="cm-field-label">Password</label>
            <input id="prov-pw" className="input mono" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} disabled={running}/>
          </div>
        </div>

        {username !== 'root' && (
          <div style={{ marginTop: 10 }}>
            <label className="opt" htmlFor="prov-usesudo">
              <input id="prov-usesudo" type="checkbox" checked={useSudo} onChange={e => setUseSudo(e.target.checked)} disabled={running}/>
              <span className="mono">use sudo</span> <span className="mute">(needed for non-root users to run setup commands)</span>
            </label>
            {useSudo && (
              <div style={{ marginTop: 8 }}>
                <label htmlFor="prov-sudopw" className="cm-field-label">Sudo password</label>
                <input id="prov-sudopw" className="input mono" type="password" autoComplete="new-password" value={sudoPassword} onChange={e => setSudoPassword(e.target.value)} disabled={running}/>
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: 12 }}>
          <label htmlFor="prov-vaultpw" className="cm-field-label">Vault password</label>
          <input id="prov-vaultpw" className="input mono" type="password" autoComplete="new-password" placeholder="decrypts porkbun_api_key + porkbun_secret_key" value={vaultPassword} onChange={e => setVaultPassword(e.target.value)} disabled={running}/>
          <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
            Read from <span className="mono">inventory/group_vars/all/vault.yml</span> on the active control node.
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          {running ? (
            <button type="button" className="btn small" onClick={cancel}>
              <Icon name="x" size={12}/> Cancel
            </button>
          ) : (
            <button type="button" className="btn primary small" onClick={start}>
              <Icon name="play" size={12}/> Provision
            </button>
          )}
          <button type="button" className="btn small" onClick={() => setOutput([])} disabled={running}>
            Clear output
          </button>
        </div>
      </div>

      <div className="terminal" ref={outRef} style={{ marginTop: 14, minHeight: 280 }}>
        {output.length === 0 && (
          <div className="terminal-empty mute-2 mono">
            <div># fill in the form and press Provision</div>
            <div># DNS check, SSH bootstrap, ansible-user setup, sshd flip, inventory edit — streamed live</div>
          </div>
        )}
        {output.map((line, i) => (
          <div key={`${i}-${line.t}`} className={`term-line term-${line.t}`}>
            {line.t === 'ok' && <span className="term-prefix">ok</span>}
            {line.t === 'fail' && <span className="term-prefix">fail</span>}
            {line.t === 'done' && <span className="term-prefix">done</span>}
            <span className="term-text">{line.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

globalThis.ProvisioningView = ProvisioningView;
