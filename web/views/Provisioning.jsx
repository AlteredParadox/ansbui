// Provisioning view — operator enters the credentials for a fresh
// VPS, and the backend orchestrates DNS + SSH bootstrap + ansible
// user setup + sshd hardening + inventory registration. The run
// itself is owned by a backend job (internal/jobs); this view kicks
// it off, then attaches a WebSocket for live output. Closing the
// tab leaves the job running — we re-attach via localStorage on
// mount so a 30-minute reinstall isn't lost to a refresh.

const { useState: useStateProv, useEffect: useEffectProv, useRef: useRefProv } = React;

const PROVISION_JOB_KEY = 'ansbui.provisionJobId';

// REINSTALL_MATRIX must mirror reinstallOSMatrix in
// internal/provision/reinstall.go — the backend re-validates, so a
// drift here just means the form rejects something the backend
// would accept (or vice versa). Versions are listed newest-first
// because the version dropdown defaults to index 0; the set
// matches reinstall.sh's README (Debian 9-13, Ubuntu LTS
// 18.04-26.04).
const REINSTALL_MATRIX = {
  debian: ['13', '12', '11', '10', '9'],
  ubuntu: ['26.04', '24.04', '22.04', '20.04', '18.04']
};
const REINSTALL_OS_LIST = Object.keys(REINSTALL_MATRIX);

// IPV4_RE is the cheap shape check — four dot-separated runs of
// digits. We deliberately don't enforce 0-255 per octet here
// (S5843 flags that as too complex); the backend's net.ParseIP
// is the canonical check and rejects 999.0.0.0 etc. The point of
// this regex is to catch the common UX mistakes — pasted hostname,
// IPv6 literal — fast, before submit.
const IPV4_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

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
  const [reinstallEnabled, setReinstallEnabled] = useStateProv(false);
  const [reinstallOS, setReinstallOS] = useStateProv(REINSTALL_OS_LIST[0]);
  const [reinstallVersion, setReinstallVersion] = useStateProv(REINSTALL_MATRIX[REINSTALL_OS_LIST[0]][0]);
  const [running, setRunning] = useStateProv(false);
  const [output, setOutput] = useStateProv([]);
  const [error, setError] = useStateProv('');
  const [activeSummary, setActiveSummary] = useStateProv(null);
  const streamRef = useRefProv(null);
  const outRef = useRefProv(null);

  useEffectProv(() => {
    if (username === 'root' && useSudo) setUseSudo(false);
  }, [username, useSudo]);

  // Reset version when OS changes — the previous selection isn't
  // valid for the new OS's version list.
  useEffectProv(() => {
    const versions = REINSTALL_MATRIX[reinstallOS] || [];
    if (!versions.includes(reinstallVersion)) {
      setReinstallVersion(versions[0] || '');
    }
  }, [reinstallOS, reinstallVersion]);

  useEffectProv(() => () => { if (streamRef.current) streamRef.current.close(); }, []);

  useEffectProv(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  // On mount: if we left a run going in a previous tab/session,
  // re-attach instead of starting fresh. The backend job survives
  // closed tabs by design — see internal/jobs.
  useEffectProv(() => {
    const id = globalThis.localStorage?.getItem(PROVISION_JOB_KEY);
    if (!id || !globalThis.AnsbuiAPI) return;
    let cancelled = false;
    globalThis.AnsbuiAPI.getProvisionJob(id).then(snap => {
      if (cancelled) return;
      if (snap?.status !== 'running') {
        globalThis.localStorage?.removeItem(PROVISION_JOB_KEY);
        return;
      }
      setActiveSummary(snap.summary || {});
      setRunning(true);
      attachStream(id);
    }).catch(() => {
      globalThis.localStorage?.removeItem(PROVISION_JOB_KEY);
    });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const append = (entry) => setOutput(prev => [...prev, entry]);

  const finish = (ok, text) => {
    append({ t: ok ? 'done' : 'fail', text });
    setRunning(false);
    setActiveSummary(null);
    globalThis.localStorage?.removeItem(PROVISION_JOB_KEY);
    // Drop the secrets out of React state once the run is over.
    // The form is the only path that holds three operator-supplied
    // passwords simultaneously; clearing on every terminal event
    // keeps the next provisioning session — or a forgotten browser
    // tab — from showing the last operator's input pre-filled.
    setPassword('');
    setSudoPassword('');
    setVaultPassword('');
    if (streamRef.current) streamRef.current.close();
    streamRef.current = null;
  };

  // attachStream wires a fresh WebSocket to a job and routes its
  // events into the terminal. The same handler powers both the
  // initial start (via start()) and the re-attach-on-mount path.
  // Local `finished` latch lets us treat an unexpected close as a
  // failure without double-firing finish().
  const attachStream = (jobId) => {
    const ws = globalThis.AnsbuiAPI.attachProvisionJob(jobId);
    streamRef.current = ws;
    let finished = false;
    const fin = (ok, text) => {
      if (finished) return;
      finished = true;
      finish(ok, text);
    };
    ws.onEvent((evt) => {
      if (evt.type === 'meta') append({ t: 'meta', text: evt.text || '' });
      else if (evt.type === 'ok') append({ t: 'ok', text: evt.text || '' });
      else if (evt.type === 'fail' || evt.type === 'error') fin(false, evt.text || 'failed');
      else if (evt.type === 'done') fin(true, evt.text || 'done');
    });
    ws.onClose(() => { if (!finished) fin(false, 'connection closed before completion'); });
    ws.onError(() => fin(false, 'WebSocket error — check backend logs'));
  };

  // validateForm returns either { error } describing the first
  // failed check or { portNum } with the parsed SSH port. Pulled
  // out of start() so each function stays under Sonar's S3776
  // cognitive-complexity ceiling.
  const validateForm = () => {
    if (!provider.trim()) return { error: 'Provider is required.' };
    if (!ip.trim()) return { error: 'IP address is required.' };
    if (!IPV4_RE.test(ip.trim())) return { error: 'IP must be in dotted-quad form (e.g. 203.0.113.42) — hostnames and IPv6 are not supported.' };
    const portNum = Number.parseInt(port, 10);
    const portOk = Number.isInteger(portNum) && portNum > 0 && portNum <= 65535;
    if (!portOk) return { error: 'SSH port must be a valid TCP port.' };
    if (!username.trim()) return { error: 'Username is required.' };
    if (!password) return { error: 'Password is required.' };
    if (useSudo && !sudoPassword) return { error: 'Sudo password is required when using sudo.' };
    if (!hostname.trim() || !hostname.includes('.')) return { error: 'Hostname must be fully-qualified (include the domain).' };
    if (!vaultPassword) return { error: 'Vault password is required (used to decrypt porkbun credentials).' };
    if (reinstallEnabled && !REINSTALL_MATRIX[reinstallOS]) return { error: 'Pick a reinstall OS.' };
    const versions = REINSTALL_MATRIX[reinstallOS] || [];
    if (reinstallEnabled && !versions.includes(reinstallVersion)) return { error: 'Pick a reinstall version.' };
    return { portNum };
  };

  const start = async () => {
    if (running || !globalThis.AnsbuiAPI) return;
    setError('');
    const v = validateForm();
    if (v.error) { setError(v.error); return; }
    const { portNum } = v;

    setOutput([]); setRunning(true);

    const payload = {
      provider: provider.trim(),
      ip: ip.trim(),
      port: portNum,
      username: username.trim(),
      password,
      useSudo,
      sudoPassword: useSudo ? sudoPassword : '',
      hostname: hostname.trim(),
      vaultPassword,
      reinstall: reinstallEnabled
        ? { enabled: true, os: reinstallOS, version: reinstallVersion }
        : { enabled: false }
    };

    try {
      const res = await globalThis.AnsbuiAPI.startProvisionJob(payload);
      const jobId = res?.jobId;
      if (!jobId) {
        setRunning(false);
        setError('Backend did not return a job ID.');
        return;
      }
      globalThis.localStorage?.setItem(PROVISION_JOB_KEY, jobId);
      attachStream(jobId);
    } catch (e) {
      setRunning(false);
      setError(e.message || String(e));
    }
  };

  // Cancel signals the backend job. We don't close the WS here —
  // the orchestrator is expected to honour ctx-cancel and emit its
  // own terminal event, which routes through the normal finish()
  // path.
  const cancel = async () => {
    const id = globalThis.localStorage?.getItem(PROVISION_JOB_KEY);
    if (!id) return;
    try {
      await globalThis.AnsbuiAPI.cancelProvisionJob(id);
    } catch (e) {
      setError(`cancel failed: ${e.message || e}`);
    }
  };

  return (
    <div className="view view-provision">
      <div className="view-head">
        <div>
          <h1 className="view-title">Bootstrap</h1>
          <div className="view-sub mute">
            Bootstrap a fresh VPS into the inventory: porkbun DNS, ansible user with key auth, sshd → 4242, then add to a provider group.
          </div>
        </div>
      </div>

      {activeSummary && (
        <div className="card mono" style={{ padding: 10, marginTop: 10, fontSize: 12 }}>
          <span className="mute">re-attached to active run:</span>{' '}
          {activeSummary.hostname || activeSummary.ip || 'bootstrapping'}
          {activeSummary.provider ? <span className="mute"> · {activeSummary.provider}</span> : null}
        </div>
      )}

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
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
              First contact — the target&rsquo;s SSH host key is not verified, so use a trusted network.
            </div>
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

        <div style={{ marginTop: 14 }}>
          <label className="opt" htmlFor="prov-reinstall">
            <input id="prov-reinstall" type="checkbox" checked={reinstallEnabled} onChange={e => setReinstallEnabled(e.target.checked)} disabled={running}/>
            <span className="mono">reinstall the OS first</span> <span className="mute">(via <a href="https://github.com/bin456789/reinstall" target="_blank" rel="noreferrer">bin456789/reinstall</a>)</span>
          </label>
          {reinstallEnabled && (
            <div style={{ marginTop: 8 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label htmlFor="prov-reinstall-os" className="cm-field-label">OS</label>
                  <select id="prov-reinstall-os" className="input mono" value={reinstallOS} onChange={e => setReinstallOS(e.target.value)} disabled={running}>
                    {REINSTALL_OS_LIST.map(os => <option key={os} value={os}>{os}</option>)}
                  </select>
                </div>
                <div>
                  <label htmlFor="prov-reinstall-ver" className="cm-field-label">Version</label>
                  <select id="prov-reinstall-ver" className="input mono" value={reinstallVersion} onChange={e => setReinstallVersion(e.target.value)} disabled={running}>
                    {(REINSTALL_MATRIX[reinstallOS] || []).map(v => <option key={v} value={v}>{v}</option>)}
                  </select>
                </div>
              </div>
              <div className="mute" style={{ fontSize: 11, marginTop: 6 }}>
                The target reboots into the chosen OS, sshd is set to <span className="mono">:4242</span> with the ansible public key in root&rsquo;s <span className="mono">authorized_keys</span>, then bootstrap continues. Expect 10&ndash;30 minutes; the run lives on the backend so you can close this tab and re-attach later. <b>Assumes your provider preserves the IP through reinstall.</b>
              </div>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
          {running ? (
            <button type="button" className="btn small" onClick={cancel}>
              <Icon name="x" size={12}/> Cancel
            </button>
          ) : (
            <button type="button" className="btn primary small" onClick={start}>
              <Icon name="play" size={12}/> Bootstrap
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
            <div># fill in the form and press Bootstrap</div>
            <div># DNS check, SSH bootstrap, ansible-user setup, sshd flip, inventory edit — streamed live</div>
            <div># the run lives on the backend — you can close this tab and re-attach later</div>
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
