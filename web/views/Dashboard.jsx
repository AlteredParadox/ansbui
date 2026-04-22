// Dashboard — overview stats, activity sparkline, recent runs, quick actions

function Sparkline({ data, w = 240, h = 48, color = 'var(--accent)' }) {
  if (!data?.length) return null;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = Math.max(1, max - min);
  const step = w / Math.max(1, data.length - 1);
  const pts = data.map((v, i) => `${(i * step).toFixed(1)},${(h - ((v - min) / range) * (h - 4) - 2).toFixed(1)}`).join(' ');
  const area = `0,${h} ${pts} ${w},${h}`;
  return (
    <svg className="spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
      <polygon points={area} fill={color} opacity="0.10" />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={w} cy={h - ((data[data.length - 1] - min) / range) * (h - 4) - 2} r="2.5" fill={color} />
    </svg>
  );
}

function DonutStatus({ ok, warn, err, size = 110 }) {
  const total = Math.max(1, ok + warn + err);
  const C = 2 * Math.PI * 42;
  const seg = (v) => (v / total) * C;
  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--bg-3)" strokeWidth="10" />
      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--ok)" strokeWidth="10"
        strokeDasharray={`${seg(ok)} ${C}`} transform="rotate(-90 50 50)" strokeLinecap="round" />
      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--warn)" strokeWidth="10"
        strokeDasharray={`${seg(warn)} ${C}`} strokeDashoffset={-seg(ok)} transform="rotate(-90 50 50)" strokeLinecap="round"/>
      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--err)" strokeWidth="10"
        strokeDasharray={`${seg(err)} ${C}`} strokeDashoffset={-(seg(ok) + seg(warn))} transform="rotate(-90 50 50)" strokeLinecap="round"/>
      <text x="50" y="48" textAnchor="middle" fontSize="20" fontWeight="600" fill="var(--text)">{ok + warn + err}</text>
      <text x="50" y="62" textAnchor="middle" fontSize="8" fill="var(--text-3)" letterSpacing="1">HOSTS</text>
    </svg>
  );
}

function DashboardView({ onNavigate, onOpenAdhoc, onRunPlaybook }) {
  const data = globalThis.AnsibleData || {};
  const HOSTS = data.HOSTS || [];
  const PLAYBOOKS = data.PLAYBOOKS || [];
  const RUNS = data.RUNS || [];
  const ACTIVITY = data.ACTIVITY || [];
  const ok = HOSTS.filter(h => h.status === 'ok').length;
  const warn = HOSTS.filter(h => h.status === 'warn').length;
  const err = HOSTS.filter(h => h.status === 'err').length;

  const recentRuns = RUNS.slice(0, 6);

  return (
    <div className="view view-dashboard">
      <div className="view-head">
        <div>
          <h1 className="view-title">Overview</h1>
          <div className="view-sub mute">{HOSTS.length} hosts · {PLAYBOOKS.length} playbooks · {RUNS.length} runs tracked</div>
        </div>
        <div className="view-actions">
          <button className="btn small"><Icon name="refresh" size={13}/> Re-sync inventory</button>
          <button className="btn small"><Icon name="download" size={13}/> Export</button>
          <button className="btn primary small" onClick={() => onOpenAdhoc()}>
            <Icon name="play" size={12}/> Run command
          </button>
        </div>
      </div>

      <div className="dash-grid">
        <div className="card dash-inventory">
          <div className="dash-card-head">
            <div>
              <div className="section-title">Inventory health</div>
              <div className="dash-card-title">{HOSTS.length} hosts</div>
            </div>
            <button className="btn ghost small" onClick={() => onNavigate('inventory')}>View all →</button>
          </div>
          <div className="dash-inventory-body">
            <DonutStatus ok={ok} warn={warn} err={err} />
            <div className="dash-legend">
              <div className="leg"><span className="dot ok"/> <b>{ok}</b> <span className="mute">reachable</span></div>
              <div className="leg"><span className="dot warn"/> <b>{warn}</b> <span className="mute">degraded</span></div>
              <div className="leg"><span className="dot err"/> <b>{err}</b> <span className="mute">unreachable</span></div>
              <div className="divider" style={{ margin: '8px 0' }}/>
              <div className="leg mute-2" style={{ fontSize: 11.5 }}>
                Last facts gathered <span className="mono" style={{ color: 'var(--text-2)' }}>6m ago</span>
              </div>
            </div>
          </div>
        </div>

        <div className="card dash-activity">
          <div className="dash-card-head">
            <div>
              <div className="section-title">Run activity · 30 days</div>
              <div className="dash-card-title">
                {ACTIVITY.reduce((a, b) => a + b, 0)} runs
                <span className="mute" style={{ fontSize: 12, marginLeft: 8 }}>▲ 12% vs prior</span>
              </div>
            </div>
            <div className="seg small">
              <button className="on">30d</button><button>7d</button><button>24h</button>
            </div>
          </div>
          <Sparkline data={ACTIVITY} w={520} h={100} />
          <div className="dash-activity-foot mute-2 mono">
            <span>mar 23</span><span>apr 07</span><span>apr 22</span>
          </div>
        </div>

        <div className="card dash-quick">
          <div className="section-title">Quick actions</div>
          <button className="quick-row" onClick={() => onOpenAdhoc({ module: 'ansible.builtin.ping', target: 'production' })}>
            <Icon name="bolt" size={14}/>
            <span className="quick-label">Ping production</span>
            <span className="mute mono">⌘K ping</span>
          </button>
          <button className="quick-row" onClick={() => onRunPlaybook('pb-deploy-app')}>
            <Icon name="play" size={14}/>
            <span className="quick-label">Deploy app (latest)</span>
            <span className="mute mono">pb/deploy-app</span>
          </button>
          <button className="quick-row" onClick={() => onRunPlaybook('pb-patch-security')}>
            <Icon name="refresh" size={14}/>
            <span className="quick-label">Apply security patches</span>
            <span className="mute mono">pb/patch-security</span>
          </button>
          <button className="quick-row" onClick={() => onOpenAdhoc({ module: 'ansible.builtin.setup', target: 'all' })}>
            <Icon name="hash" size={14}/>
            <span className="quick-label">Gather facts — all hosts</span>
            <span className="mute mono">setup</span>
          </button>
        </div>

        <div className="card dash-runs">
          <div className="dash-card-head">
            <div className="section-title">Recent runs</div>
            <button className="btn ghost small" onClick={() => onNavigate('history')}>All runs →</button>
          </div>
          <table className="t">
            <thead>
              <tr>
                <th style={{ width: 26 }}></th>
                <th>Run</th>
                <th>Playbook</th>
                <th>Hosts</th>
                <th>Changed</th>
                <th>Duration</th>
                <th>By</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {recentRuns.map(r => (
                <tr key={r.id} className="t-row-click" onClick={() => onNavigate('history')}>
                  <td><span className={`dot ${r.status}`}/></td>
                  <td className="mono">{r.id}</td>
                  <td className="mono">{r.pb}</td>
                  <td><span className="mono">{r.ok}</span><span className="mute"> / </span><span className="mono" style={{ color: 'var(--err)' }}>{r.failed}</span></td>
                  <td className="mono">{r.changed}</td>
                  <td className="mono">{r.duration}</td>
                  <td className="mute">{r.who}</td>
                  <td className="mute">{r.when}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card dash-fleet">
          <div className="section-title">Fleet by group</div>
          {computeFleetByGroup(HOSTS).map(r => {
            const total = r.count || 1;
            return (
              <div key={r.name} className="fleet-row">
                <div className="fleet-row-head">
                  <span className="mono">{r.name}</span>
                  <span className="mute mono">{r.count}</span>
                </div>
                <div className="fleet-bar">
                  <div style={{ width: `${r.ok / total * 100}%`, background: 'var(--ok)' }}/>
                  <div style={{ width: `${r.warn / total * 100}%`, background: 'var(--warn)' }}/>
                  <div style={{ width: `${r.err / total * 100}%`, background: 'var(--err)' }}/>
                </div>
              </div>
            );
          })}
          <div className="divider" style={{ margin: '12px 0 10px' }}/>
          <div className="section-title">Top playbooks · 7d</div>
          {PLAYBOOKS.slice(0, 4).map((p, i) => (
            <div key={p.id} className="pb-top-row">
              <span className="mono" style={{ flex: 1 }}>{p.name}</span>
              <span className="mono mute">{p.runs}</span>
              <div className="pb-bar"><div style={{ width: `${Math.min(100, p.runs / 250 * 100)}%` }}/></div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function statusKey(status) {
  if (status === 'warn') return 'warn';
  if (status === 'err') return 'err';
  return 'ok';
}

function computeFleetByGroup(hosts) {
  const bucket = {};
  for (const h of hosts) {
    for (const g of h.groups || []) {
      if (g === 'all' || g === 'ungrouped') continue;
      if (!bucket[g]) bucket[g] = { name: g, count: 0, ok: 0, warn: 0, err: 0 };
      bucket[g].count += 1;
      bucket[g][statusKey(h.status)] += 1;
    }
  }
  return Object.values(bucket).sort((a, b) => b.count - a.count).slice(0, 4);
}

globalThis.DashboardView = DashboardView;
