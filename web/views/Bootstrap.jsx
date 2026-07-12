// Bootstrap view — operator enters the credentials for a fresh
// VPS, and the backend orchestrates DNS + SSH bootstrap + ansible
// user setup + sshd hardening + inventory registration. The run
// itself is owned by a backend job (internal/jobs); this view kicks
// it off, then attaches a WebSocket for live output. Closing the
// tab leaves the job running — we re-attach via localStorage on
// mount so a 30-minute reinstall isn't lost to a refresh.

const { useState: useStateBoot, useEffect: useEffectBoot, useRef: useRefBoot } = React;

const BOOTSTRAP_JOB_KEY = 'ansbui.bootstrapJobId';

// REINSTALL_MATRIX must mirror reinstallOSMatrix in
// internal/bootstrap/reinstall.go — the backend re-validates, so a
// drift here just means the form rejects something the backend
// would accept (or vice versa). Versions are listed newest-first
// because the version dropdown defaults to index 0; the set is
// limited to releases whose cloud images are still published
// upstream (installs run in cloud-image mode — see the backend
// matrix comment).
const REINSTALL_MATRIX = {
  debian: ['13', '12', '11'],
  ubuntu: ['26.04', '24.04', '22.04', '20.04']
};
const REINSTALL_OS_LIST = Object.keys(REINSTALL_MATRIX);

// classifyAddress mirrors the backend's classifyAddress: returns
// 'ipv4', 'ipv6', 'host', or '' for inputs that match none. The
// per-octet IPv4 alternation has fixed-width branches (no
// backtracking, S5852-safe). IPv6 requires ≥2 colons and bans
// '.', so the dotted-tail v4-mapped form (`::ffff:1.2.3.4`) is
// rejected here. The all-hex v4-mapped form (`::ffff:0102:0304`)
// passes this gate but is caught by the backend's To4()==nil
// guard with a dedicated error message — the FE doesn't try to
// detect it because a substring guard would false-positive on
// legitimate but exotic IPv6 like `1::ffff:1:2`. Hostnames pass
// a label-shape gate (RFC1035: 1-63 bytes, no leading/trailing
// '-', no empty labels) so a typo like `-bad.example.com` is
// caught inline rather than via a backend 400.
// NB: do NOT rewrite these as String.raw`...` tagged templates (what
// Sonar S7780 suggests). Every .jsx loads as a separate
// <script type="text/babel"> but they share one global scope, and Babel
// caches each tagged template in a module-level `_templateObject` var
// with an `||` guard — so a String.raw tag in any earlier-loaded file
// poisons this one's value, corrupting the regex and rejecting every
// real IPv4. Keeping the backslashes inside regex literals (reading
// .source) sidesteps both the tagged-template collision and the
// escaped-backslash string literals S7780 flags. Each octet branch is
// fixed-width (no backtracking, S5852-safe).
const ADDR_OCTET = /(25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)/.source;
const ADDR_DOT = /\./.source;
const ADDR_IPV4_RE = new RegExp(`^${ADDR_OCTET}${ADDR_DOT}${ADDR_OCTET}${ADDR_DOT}${ADDR_OCTET}${ADDR_DOT}${ADDR_OCTET}$`);
const ADDR_IPV6_RE = /^(?=.*:.*:)[0-9a-fA-F:]+$/;
const ADDR_DIGITDOT_RE = /^[0-9.]+$/;
const ADDR_HOST_RE = /^[a-zA-Z0-9.-]+$/;
const hostLabelsOK = (s) => s.split('.').every(l => l.length >= 1 && l.length <= 63 && l[0] !== '-' && l[l.length - 1] !== '-');

// Small display helpers for the "recent runs" panel. Kept local
// (api.js has its own `friendly` but doesn't export it).
const bootAgo = (iso) => {
  if (!iso) return '';
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
};
const bootDuration = (startIso, endIso) => {
  if (!startIso || !endIso) return '';
  const secs = (new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000;
  if (secs < 0) return '';
  if (secs < 90) return `${Math.round(secs)}s`;
  return `${Math.round(secs / 60)}m`;
};
// Bootstrap jobs share the run-status (rs-*) palette: a success is
// green, a failure red, cancelled grey, running pulses blue.
// Unknown statuses fall back to the neutral grey.
const JOB_DOT_CLASS = { succeeded: 'rs-ok', failed: 'rs-err', cancelled: 'rs-cancelled', running: 'rs-run' };

function jobStatusClass(status) {
  return JOB_DOT_CLASS[status] || 'rs-cancelled';
}

// Hover text for a recent-job row: blocked while a run is active,
// otherwise attach vs view depending on the job's state.
function jobRowTitle(running, status) {
  if (running) return 'finish or cancel the current run first';
  return status === 'running' ? 'attach to this live run' : 'view this run’s log';
}
const classifyAddress = (s) => {
  if (!s || s.length > 253) return '';
  if (s.includes(':')) return ADDR_IPV6_RE.test(s) ? 'ipv6' : '';
  if (ADDR_DIGITDOT_RE.test(s)) return ADDR_IPV4_RE.test(s) ? 'ipv4' : '';
  if (s.includes('.') && ADDR_HOST_RE.test(s) && hostLabelsOK(s)) return 'host';
  return '';
};

function BootstrapView() {
  const [provider, setProvider] = useStateBoot('');
  const [ip, setIp] = useStateBoot('');
  const [port, setPort] = useStateBoot('22');
  const [username, setUsername] = useStateBoot('root');
  const [useSudo, setUseSudo] = useStateBoot(false);
  const [password, setPassword] = useStateBoot('');
  const [sudoPassword, setSudoPassword] = useStateBoot('');
  const [hostname, setHostname] = useStateBoot('');
  const [vaultPassword, setVaultPassword] = useStateBoot('');
  const [hostKeyFingerprint, setHostKeyFingerprint] = useStateBoot('');
  const [reinstallEnabled, setReinstallEnabled] = useStateBoot(false);
  const [reinstallOS, setReinstallOS] = useStateBoot(REINSTALL_OS_LIST[0]);
  const [reinstallVersion, setReinstallVersion] = useStateBoot(REINSTALL_MATRIX[REINSTALL_OS_LIST[0]][0]);
  const [running, setRunning] = useStateBoot(false);
  const [output, setOutput] = useStateBoot([]);
  const [error, setError] = useStateBoot('');
  const [activeSummary, setActiveSummary] = useStateBoot(null);
  const [recentJobs, setRecentJobs] = useStateBoot([]);
  // id of the finished job whose log is loaded in the terminal, or
  // null when the terminal shows a live run / is empty.
  const [viewingJob, setViewingJob] = useStateBoot(null);
  const streamRef = useRefBoot(null);
  // jobIdRef is the job THIS component started or re-attached to.
  // Cancel must use it, never localStorage: the storage key is shared
  // across tabs, so reading it at cancel time can grab a job some
  // other tab started later — tab A's Cancel then killed tab B's run.
  const jobIdRef = useRefBoot(null);
  const outRef = useRefBoot(null);
  // mountedRef gates side-effects in WS callbacks so the unmount
  // cleanup that closes the socket doesn't race a setState on a
  // gone component (React dev warning, no prod impact).
  const mountedRef = useRefBoot(true);

  useEffectBoot(() => {
    if (username === 'root' && useSudo) setUseSudo(false);
  }, [username, useSudo]);

  // Reset version when OS changes — the previous selection isn't
  // valid for the new OS's version list.
  useEffectBoot(() => {
    const versions = REINSTALL_MATRIX[reinstallOS] || [];
    if (!versions.includes(reinstallVersion)) {
      setReinstallVersion(versions[0] || '');
    }
  }, [reinstallOS, reinstallVersion]);

  useEffectBoot(() => () => {
    mountedRef.current = false;
    if (streamRef.current) streamRef.current.close();
  }, []);

  useEffectBoot(() => {
    outRef.current?.scrollTo({ top: outRef.current.scrollHeight });
  }, [output]);

  // On mount: if we left a run going in a previous tab/session,
  // re-attach instead of starting fresh. The backend job survives
  // closed tabs by design — see internal/jobs. Finished jobs are
  // re-attached too: the stream replays the full backlog including
  // the terminal event, so a tab reopened after completion shows the
  // outcome (finish() then clears the stored id) instead of silently
  // discarding the result.
  useEffectBoot(() => {
    const id = globalThis.localStorage?.getItem(BOOTSTRAP_JOB_KEY);
    if (!id || !globalThis.AnsbuiAPI) return;
    let cancelled = false;
    globalThis.AnsbuiAPI.getBootstrapJob(id).then(snap => {
      if (cancelled) return;
      jobIdRef.current = id;
      setActiveSummary(snap?.summary || {});
      if (snap?.status === 'running') setRunning(true);
      attachStream(id);
    }).catch((e) => {
      if (cancelled) return;
      if (e?.status === 404) {
        // The job is genuinely gone (backend restart) — forget it.
        globalThis.localStorage?.removeItem(BOOTSTRAP_JOB_KEY);
        return;
      }
      // Transient error (backend blip, network): keep the stored id
      // so the next mount can still find the run instead of orphaning
      // a 30-minute reinstall.
      append({ t: 'meta', text: 'could not check on a previous bootstrap job — refresh to retry re-attaching' });
    });
    return () => { cancelled = true; };
  }, []);

  const append = (entry) => setOutput(prev => [...prev, entry]);

  // refreshRecent re-syncs the "recent runs" panel from two sources:
  // the live jobs registry (authoritative for running + recently
  // finished runs) and the persisted run history (what survives a
  // backend restart). A finished job appears in both until evicted —
  // the registry row wins so status keeps its cancelled/failed
  // distinction. Both fetches are best-effort; live run UX is
  // unaffected if either fails.
  const refreshRecent = () => {
    if (!globalThis.AnsbuiAPI) return;
    Promise.all([
      globalThis.AnsbuiAPI.listBootstrapJobs().catch(() => ({ jobs: [] })),
      globalThis.AnsbuiAPI.listRuns().catch(() => ({ runs: [] }))
    ]).then(([jobRes, runRes]) => {
      if (!mountedRef.current) return;
      const rows = [...(jobRes?.jobs || [])];
      const seen = new Set(rows.map(j => j.id));
      for (const r of (runRes?.runs || [])) {
        if (r.kind !== 'bootstrap' || seen.has(r.id)) continue;
        rows.push({
          id: r.id,
          // Persisted records collapse to ok/err; cancelled runs read
          // as failed here, but their log ends with a "cancelled" line.
          status: r.status === 'ok' ? 'succeeded' : 'failed',
          // The backend stores the sanitized job summary in the
          // record's args slot — provider/hostname/ip round-trip.
          summary: r.args || { hostname: r.target },
          startedAt: r.startedAt,
          endedAt: r.endedAt,
          error: '',
          persisted: true
        });
      }
      // ISO-8601 UTC strings sort lexicographically.
      rows.sort((a, b) => (b.startedAt || '').localeCompare(a.startedAt || ''));
      setRecentJobs(rows.slice(0, 20));
    });
  };

  useEffectBoot(() => { refreshRecent(); }, []);

  const finish = (ok, text) => {
    append({ t: ok ? 'done' : 'fail', text });
    setRunning(false);
    setActiveSummary(null);
    // The done/fail WS event arrives a beat before the backend marks
    // the job terminal (emit happens inside Run, finish() after it
    // returns) — delay the list refresh so the row shows the final
    // status instead of a stale "running".
    globalThis.setTimeout(refreshRecent, 600);
    // Only clear the shared storage key if it still points at OUR
    // job — another tab may have started a newer run since.
    if (globalThis.localStorage?.getItem(BOOTSTRAP_JOB_KEY) === jobIdRef.current) {
      globalThis.localStorage.removeItem(BOOTSTRAP_JOB_KEY);
    }
    jobIdRef.current = null;
    // Drop the secrets out of React state once the run is over.
    // The form is the only path that holds three operator-supplied
    // passwords simultaneously; clearing on every terminal event
    // keeps the next bootstrap session — or a forgotten browser
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
  // Local `finished` latch lets us treat backend done/fail events
  // as terminal exactly once. WS close/error are NOT treated as
  // failure: the backend job outlives the socket by design (a
  // navigate-away during a 30-minute reinstall closes the socket
  // but the run keeps going), so a non-terminal close just stops
  // the local stream and leaves localStorage so the next mount
  // re-attaches via getBootstrapJob, which reads ground-truth
  // status from the backend registry.
  const attachStream = (jobId) => {
    const ws = globalThis.AnsbuiAPI.attachBootstrapJob(jobId);
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
    ws.onClose(() => {
      if (finished || !mountedRef.current) return;
      append({ t: 'meta', text: 'stream disconnected; refresh to re-attach (backend job continues)' });
      streamRef.current = null;
    });
    ws.onError(() => {
      if (finished || !mountedRef.current) return;
      append({ t: 'meta', text: 'WebSocket error; refresh to re-attach (backend job may still be running)' });
      streamRef.current = null;
    });
  };

  // fetchRunLog returns { snap, events } for a finished run. Registry
  // rows try the live job log first (richer status: cancelled vs
  // failed) and fall back to the persisted run history on 404 — the
  // job may have been evicted between the list fetch and the click.
  // Persisted rows go straight to the run history.
  const fetchRunLog = async (job) => {
    if (!job.persisted) {
      try {
        const res = await globalThis.AnsbuiAPI.getBootstrapJobLog(job.id);
        return { snap: res?.job || job, events: res?.events || [] };
      } catch (e) {
        if (e?.status !== 404) throw e;
      }
    }
    const run = await globalThis.AnsbuiAPI.getRun(job.id);
    // Persisted logs already end with their verdict line (the backend
    // converter synthesizes it), so the caller's synthesis is a no-op.
    return { snap: job, events: run?.log || [] };
  };

  // viewJobLog loads a recent run's buffered log into the terminal.
  // Finished runs come via REST ({job, events}); a still-running run
  // re-attaches the live stream instead, exactly like the on-mount
  // re-attach path, so the operator gets a tail rather than a stale
  // snapshot.
  const viewJobLog = async (job) => {
    if (running || !globalThis.AnsbuiAPI) return;
    if (job.status === 'running') {
      jobIdRef.current = job.id;
      globalThis.localStorage?.setItem(BOOTSTRAP_JOB_KEY, job.id);
      setActiveSummary(job.summary || {});
      setViewingJob(null);
      setOutput([]);
      setRunning(true);
      attachStream(job.id);
      return;
    }
    try {
      const { snap, events } = await fetchRunLog(job);
      if (!mountedRef.current) return;
      const header = {
        t: 'meta',
        text: `# ${snap.summary?.hostname || snap.summary?.ip || 'bootstrap'} · started ${bootAgo(snap.startedAt)} · ${snap.status}`
      };
      const lines = events.map(evt => ({
        t: ['meta', 'ok', 'fail', 'done'].includes(evt.type) ? evt.type : 'meta',
        text: evt.text || ''
      }));
      // Mirror the WS path's synthesized terminal event: a cancelled
      // run (or a panic) dies without emitting its own done/fail, so
      // the log would otherwise just stop mid-step with no verdict.
      const last = lines[lines.length - 1];
      if (!last || (last.t !== 'done' && last.t !== 'fail')) {
        if (snap.status === 'succeeded') lines.push({ t: 'done', text: 'complete' });
        else if (snap.status === 'cancelled') lines.push({ t: 'fail', text: 'cancelled' });
        else if (snap.status === 'failed') lines.push({ t: 'fail', text: snap.error || 'failed' });
      }
      setOutput([header, ...lines]);
      setViewingJob(job.id);
      setError('');
    } catch (e) {
      if (!mountedRef.current) return;
      if (e?.status === 404) {
        // Gone from the registry AND the persisted history (evicted
        // from both) — re-sync so the row disappears.
        setError('run log no longer available (evicted from run history)');
        refreshRecent();
        return;
      }
      setError(`could not load run log: ${e.message || e}`);
    }
  };

  // hostnameError / reinstallError split off the multi-check field
  // groups so validateForm itself stays under Sonar's S3776
  // cognitive-complexity ceiling. Each returns the first failed
  // check's text or null when the field group passes.
  const hostnameError = () => {
    const trimmedHost = hostname.trim();
    if (!trimmedHost?.includes('.')) return 'Hostname must be fully-qualified (include the domain).';
    if (trimmedHost.length > 253 || !ADDR_HOST_RE.test(trimmedHost) || !hostLabelsOK(trimmedHost)) return 'Hostname has an invalid label (RFC1035: 1-63 bytes per label, no leading/trailing "-", no empty labels).';
    return null;
  };
  const reinstallError = () => {
    if (!reinstallEnabled) return null;
    const versions = REINSTALL_MATRIX[reinstallOS];
    if (!versions) return 'Pick a reinstall OS.';
    if (!versions.includes(reinstallVersion)) return 'Pick a reinstall version.';
    return null;
  };

  // validateForm returns either { error } describing the first
  // failed check or { portNum } with the parsed SSH port. Pulled
  // out of start() so each function stays under Sonar's S3776
  // cognitive-complexity ceiling.
  const validateForm = () => {
    if (!provider.trim()) return { error: 'Provider is required.' };
    if (!ip.trim()) return { error: 'Address is required.' };
    if (!classifyAddress(ip.trim())) return { error: 'Address must be an IPv4 address (e.g. 203.0.113.42), IPv6 address (e.g. 2001:db8::1), or DNS hostname (e.g. host.example.com).' };
    const portNum = Number.parseInt(port, 10);
    const portOk = Number.isInteger(portNum) && portNum > 0 && portNum <= 65535;
    if (!portOk) return { error: 'SSH port must be a valid TCP port.' };
    if (!username.trim()) return { error: 'Username is required.' };
    if (!password) return { error: 'Password is required.' };
    if (useSudo && !sudoPassword) return { error: 'Sudo password is required when using sudo.' };
    const hostErr = hostnameError();
    if (hostErr) return { error: hostErr };
    // Vault password is only consumed by the porkbun DNS step, so
    // skip the requirement when the address is itself a hostname
    // (porkbun is bypassed in that case — operator manages DNS
    // out of band).
    if (classifyAddress(ip.trim()) !== 'host' && !vaultPassword) return { error: 'Vault password is required (used to decrypt porkbun credentials).' };
    const reErr = reinstallError();
    if (reErr) return { error: reErr };
    return { portNum };
  };

  const start = async () => {
    if (running || !globalThis.AnsbuiAPI) return;
    setError('');
    const v = validateForm();
    if (v.error) { setError(v.error); return; }
    const { portNum } = v;

    setOutput([]); setRunning(true); setViewingJob(null);

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
      hostKeyFingerprint: hostKeyFingerprint.trim(),
      reinstall: reinstallEnabled
        ? { enabled: true, os: reinstallOS, version: reinstallVersion }
        : { enabled: false }
    };

    try {
      const res = await globalThis.AnsbuiAPI.startBootstrapJob(payload);
      const jobId = res?.jobId;
      if (!jobId) {
        setRunning(false);
        setError('Backend did not return a job ID.');
        return;
      }
      jobIdRef.current = jobId;
      globalThis.localStorage?.setItem(BOOTSTRAP_JOB_KEY, jobId);
      attachStream(jobId);
      refreshRecent();
    } catch (e) {
      setRunning(false);
      setError(e.message || String(e));
    }
  };

  // Cancel signals the backend job. We don't close the WS here —
  // the orchestrator is expected to honour ctx-cancel and emit its
  // own terminal event, which routes through the normal finish()
  // path. Cancels the job THIS tab is streaming (jobIdRef) — the
  // localStorage key is shared across tabs and may point at a newer
  // run some other tab started.
  const cancel = async () => {
    const id = jobIdRef.current;
    if (!id) return;
    try {
      await globalThis.AnsbuiAPI.cancelBootstrapJob(id);
    } catch (e) {
      setError(`cancel failed: ${e.message || e}`);
    }
  };

  return (
    <div className="view view-bootstrap">
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
            <label htmlFor="boot-provider" className="cm-field-label">Provider</label>
            <input id="boot-provider" className="input mono" placeholder="hetzner, dartnode, …" value={provider} onChange={e => setProvider(e.target.value)} disabled={running}/>
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>Used as the inventory group name. Created if it doesn&rsquo;t exist.</div>
          </div>
          <div>
            <label htmlFor="boot-hostname" className="cm-field-label">Hostname / FQDN</label>
            <input id="boot-hostname" className="input mono" placeholder="ca-on-vps01.example.com" value={hostname} onChange={e => setHostname(e.target.value)} disabled={running}/>
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>Last two labels become the porkbun domain.</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10, marginTop: 10 }}>
          <div>
            <label htmlFor="boot-ip" className="cm-field-label">Address</label>
            <input id="boot-ip" className="input mono" placeholder="203.0.113.42, 2001:db8::1, or host.example.com" value={ip} onChange={e => setIp(e.target.value)} disabled={running}/>
            <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
              IPv4, IPv6, or DNS hostname. Hostnames skip the porkbun DNS step.
            </div>
          </div>
          <div>
            <label htmlFor="boot-port" className="cm-field-label">SSH port</label>
            <input id="boot-port" className="input mono" placeholder="22" value={port} onChange={e => setPort(e.target.value)} disabled={running}/>
          </div>
        </div>

        <div style={{ marginTop: 10 }}>
          <label htmlFor="boot-hostkey" className="cm-field-label">Host key fingerprint <span className="mute">(optional)</span></label>
          <input id="boot-hostkey" className="input mono" placeholder="SHA256:… (from the provider console: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)" value={hostKeyFingerprint} onChange={e => setHostKeyFingerprint(e.target.value)} disabled={running}/>
          <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
            Pins the target&rsquo;s SSH host key; a mismatch aborts before the password is sent. Left empty, the key is trusted on FIRST contact only &mdash; it&rsquo;s recorded server-side and enforced on every later bootstrap of the same address. Supply a new fingerprint here after an out-of-band reinstall to update the record.
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 10 }}>
          <div>
            <label htmlFor="boot-user" className="cm-field-label">Username</label>
            <input id="boot-user" className="input mono" placeholder="root" value={username} onChange={e => setUsername(e.target.value)} disabled={running}/>
          </div>
          <div>
            <label htmlFor="boot-pw" className="cm-field-label">Password</label>
            <input id="boot-pw" className="input mono" type="password" autoComplete="new-password" value={password} onChange={e => setPassword(e.target.value)} disabled={running}/>
          </div>
        </div>

        {username !== 'root' && (
          <div style={{ marginTop: 10 }}>
            <label className="opt" htmlFor="boot-usesudo">
              <input id="boot-usesudo" type="checkbox" checked={useSudo} onChange={e => setUseSudo(e.target.checked)} disabled={running}/>
              <span className="mono">use sudo</span> <span className="mute">(needed for non-root users to run setup commands)</span>
            </label>
            {useSudo && (
              <div style={{ marginTop: 8 }}>
                <label htmlFor="boot-sudopw" className="cm-field-label">Sudo password</label>
                <input id="boot-sudopw" className="input mono" type="password" autoComplete="new-password" value={sudoPassword} onChange={e => setSudoPassword(e.target.value)} disabled={running}/>
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: 12 }}>
          <label htmlFor="boot-vaultpw" className="cm-field-label">Vault password</label>
          <input id="boot-vaultpw" className="input mono" type="password" autoComplete="new-password" placeholder="decrypts porkbun_api_key + porkbun_secret_key" value={vaultPassword} onChange={e => setVaultPassword(e.target.value)} disabled={running}/>
          <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
            Read from <span className="mono">inventory/group_vars/all/vault.yml</span> on the active control node.
          </div>
        </div>

        <div style={{ marginTop: 14 }}>
          <label className="opt" htmlFor="boot-reinstall">
            <input id="boot-reinstall" type="checkbox" checked={reinstallEnabled} onChange={e => setReinstallEnabled(e.target.checked)} disabled={running}/>
            <span className="mono">reinstall the OS first</span> <span className="mute">(via <a href="https://github.com/bin456789/reinstall" target="_blank" rel="noreferrer">bin456789/reinstall</a>)</span>
          </label>
          {reinstallEnabled && (
            <div style={{ marginTop: 8 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label htmlFor="boot-reinstall-os" className="cm-field-label">OS</label>
                  <select id="boot-reinstall-os" className="input mono" value={reinstallOS} onChange={e => setReinstallOS(e.target.value)} disabled={running}>
                    {REINSTALL_OS_LIST.map(os => <option key={os} value={os}>{os}</option>)}
                  </select>
                </div>
                <div>
                  <label htmlFor="boot-reinstall-ver" className="cm-field-label">Version</label>
                  <select id="boot-reinstall-ver" className="input mono" value={reinstallVersion} onChange={e => setReinstallVersion(e.target.value)} disabled={running}>
                    {(REINSTALL_MATRIX[reinstallOS] || []).map(v => <option key={v} value={v}>{v}</option>)}
                  </select>
                </div>
              </div>
              <div className="mute" style={{ fontSize: 11, marginTop: 6 }}>
                The target reboots into the chosen OS, sshd is set to <span className="mono">:4242</span> with the ansible public key in root&rsquo;s <span className="mono">authorized_keys</span>, then bootstrap continues. Expect 10&ndash;30 minutes; the run lives on the backend so you can close this tab and re-attach later. <b>Assumes the target&rsquo;s address (IP or hostname&rsquo;s DNS) still points at the same machine after the reboot.</b>
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

      <div className="card" style={{ padding: 12, marginTop: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div className="section-title">Recent runs</div>
          <button type="button" className="btn small" onClick={refreshRecent}>
            <Icon name="refresh" size={12}/> Refresh
          </button>
        </div>
        <div className="mute" style={{ fontSize: 11, marginTop: 4 }}>
          Click a run to load its log above &mdash; failed runs keep the step that broke. Saved to run history; survives restarts.
        </div>
        {recentJobs.length === 0 && (
          <div className="mute-2 mono" style={{ fontSize: 12, marginTop: 10 }}>no bootstrap runs yet</div>
        )}
        <div style={{ marginTop: 8 }}>
          {recentJobs.map(j => (
            <button
              type="button"
              key={j.id}
              className={`history-row ${viewingJob === j.id ? 'active' : ''}`}
              onClick={() => viewJobLog(j)}
              disabled={running}
              title={jobRowTitle(running, j.status)}
            >
              <span className={`dot ${jobStatusClass(j.status)}`}/>
              <div className="history-row-main">
                <div className="history-row-top">
                  <span className="mono">{j.summary?.hostname || j.summary?.ip || j.id}</span>
                  {j.summary?.provider && <span className="mute mono" style={{ fontSize: 11 }}>· {j.summary.provider}</span>}
                  <span className="mute mono" style={{ marginLeft: 'auto', fontSize: 11 }}>{bootAgo(j.startedAt)}</span>
                </div>
                <div className="history-row-bot">
                  <span className={`pill ${jobStatusClass(j.status)}`}>{j.status}</span>
                  {bootDuration(j.startedAt, j.endedAt) && <span className="mute mono" style={{ fontSize: 11 }}>{bootDuration(j.startedAt, j.endedAt)}</span>}
                  {j.status === 'failed' && j.error && (
                    <span className="mono" style={{ color: 'var(--err)', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {j.error}
                    </span>
                  )}
                </div>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

globalThis.BootstrapView = BootstrapView;
