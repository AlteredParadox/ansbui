#!/usr/bin/env node
// Regenerates the README screenshots in docs/screenshots/.
//
// Nothing real is ever on screen. The script starts the ansbui binary on a
// free loopback port with an empty, throw-away config, and answers every
// /api call in the browser from the made-up fleet below: names under
// example.com, addresses from the ranges reserved for documentation
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), invented playbooks and
// run history. No control node, Prometheus or target is contacted, and the
// passwords typed into forms are placeholders.
//
// It needs Playwright with Chromium, which is deliberately not a dependency
// of this repository:
//
//   npm install --no-save playwright && npx playwright install chromium
//   make build
//   node scripts/screenshots.mjs
//
// PLAYWRIGHT_MODULE may name an existing install instead (the directory of
// the `playwright` package); ANSBUI_BIN the binary (default ./ansbui).
// Run times are relative to "now", so history always reads "3h ago"; the
// one absolute date on screen (a playbook's modification time) is fixed and
// the browser runs in UTC with an en-US locale. Two runs therefore give
// byte-identical images, and a diff in docs/screenshots/ means the UI
// changed.

import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'docs', 'screenshots');
const BIN = process.env.ANSBUI_BIN || path.join(ROOT, 'ansbui');
const VIEWPORT = { width: 1440, height: 810 };

const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE || 'playwright');

// ---------------------------------------------------------------- data

const ago = (minutes) => new Date(Date.now() - minutes * 60_000).toISOString();
const HOUR = 60;
const DAY = 24 * HOUR;

const SERVER = { id: 'srv-demo', name: 'control-01', host: 'control.example.com', port: 22, user: 'ansible', workDir: '/srv/ansible', inventory: 'inventory/hosts.yml', createdAt: ago(90 * DAY) };

const GROUPS = [
  { id: 'all', name: 'all', parent: null, vars: { ansible_user: 'ansible' } },
  { id: 'hetzner', name: 'hetzner', parent: 'all', vars: {} },
  { id: 'ovh', name: 'ovh', parent: 'all', vars: {} },
  { id: 'vultr', name: 'vultr', parent: 'all', vars: {} },
  { id: 'web', name: 'web', parent: 'all', vars: { http_port: 8080 } },
  { id: 'db', name: 'db', parent: 'all', vars: {} },
];

// [name, ip, provider, role, region, os, status, cpu, mem, load, uptime days]
const HOSTS = [
  ['web-01', '203.0.113.11', 'hetzner', 'web', 'Falkenstein, DE', 'Debian 13', 'ok', 18, 41, 0.42, 63],
  ['web-02', '203.0.113.12', 'hetzner', 'web', 'Falkenstein, DE', 'Debian 13', 'ok', 22, 44, 0.51, 63],
  ['web-03', '203.0.113.42', 'hetzner', 'web', 'Helsinki, FI', 'Debian 13', 'ok', 9, 38, 0.17, 2],
  ['lb-01', '203.0.113.5', 'hetzner', 'web', 'Falkenstein, DE', 'Debian 12', 'ok', 6, 22, 0.08, 211],
  ['db-01', '198.51.100.21', 'ovh', 'db', 'Gravelines, FR', 'Debian 12', 'ok', 37, 71, 1.36, 148],
  ['db-02', '198.51.100.22', 'ovh', 'db', 'Gravelines, FR', 'Debian 12', 'warn', 64, 92, 3.87, 148],
  ['cache-01', '198.51.100.30', 'ovh', 'web', 'Strasbourg, FR', 'Debian 13', 'ok', 11, 57, 0.23, 34],
  ['backup-01', '198.51.100.40', 'ovh', 'db', 'London, GB', 'Ubuntu 24.04', 'ok', 3, 19, 0.02, 301],
  ['mon-01', '192.0.2.10', 'vultr', 'web', 'New York, US', 'Ubuntu 24.04', 'ok', 14, 48, 0.31, 87],
  ['ci-01', '192.0.2.20', 'vultr', 'web', 'New York, US', 'Debian 13', 'ok', 48, 63, 2.05, 19],
  ['mail-01', '192.0.2.25', 'vultr', 'web', 'Toronto, CA', 'Debian 12', 'ok', 5, 33, 0.11, 176],
  ['edge-sg-01', '192.0.2.61', 'vultr', 'web', 'Singapore, SG', 'Debian 13', 'ok', 12, 29, 0.19, 55],
  ['edge-au-01', '192.0.2.62', 'vultr', 'web', 'Sydney, AU', 'Debian 13', 'err', 0, 0, 0, 0],
  ['vpn-01', '192.0.2.90', 'vultr', 'web', 'Tokyo, JP', 'Debian 13', 'ok', 4, 17, 0.05, 122],
].map(([short, ip, provider, role, region, os, status, cpu, mem, load, uptime]) => ({
  id: `host-${short}`,
  name: `${short}.example.com`,
  ip,
  groups: [provider, role],
  region,
  os,
  status,
  cpu,
  mem,
  load,
  uptime,
  tags: [provider, role, os.toLowerCase().replace(' ', '-')],
  vars: { ansible_port: 4242 },
  lastPlaybook: role === 'db' ? 'backup.yml' : 'deploy-web.yml',
  lastPlaybookAt: ago(role === 'db' ? 9 * HOUR : 3 * HOUR),
}));

// Shown as an absolute date, so it must not move with the clock.
const MODIFIED_BASE = Date.UTC(2026, 10, 14, 9, 30);
const playbook = (name, description, tags, targets, modifiedMinutes, yaml) => ({
  id: name, name, path: name, title: '', description, tags, targets, size: yaml.length,
  modified: new Date(MODIFIED_BASE - modifiedMinutes * 60_000).toISOString(), yaml,
});

const PLAYBOOKS = [
  playbook('deploy-web.yml', 'Roll out the web application, one host at a time', ['deploy', 'web'], 'web', 3 * HOUR, `---
- name: Deploy the web application
  hosts: web
  become: true
  serial: 1
  vars:
    app_version: "2.14.0"
    app_dir: /opt/app
  tasks:
    - name: Take the host out of the load balancer
      ansible.builtin.uri:
        url: "http://lb-01.example.com:9000/drain/{{ inventory_hostname }}"
        method: POST

    - name: Install the release
      ansible.builtin.unarchive:
        src: "https://releases.example.com/app-{{ app_version }}.tar.gz"
        dest: "{{ app_dir }}"
        remote_src: true
      notify: Restart app

    - name: Wait for the health check
      ansible.builtin.uri:
        url: "http://127.0.0.1:{{ http_port }}/healthz"
      register: health
      retries: 10
      delay: 3
      until: health.status == 200

  handlers:
    - name: Restart app
      ansible.builtin.systemd:
        name: app
        state: restarted
`),
  playbook('patch.yml', 'Apply pending package updates and reboot if needed', ['maintenance'], 'all', 2 * DAY, `---
- name: Patch Debian and Ubuntu hosts
  hosts: all
  become: true
  serial: "25%"
  tasks:
    - name: Upgrade packages
      ansible.builtin.apt:
        upgrade: dist
        update_cache: true
    - name: Reboot when the kernel changed
      ansible.builtin.reboot:
      when: reboot_required | default(false)
`),
  playbook('backup.yml', 'Dump every database and ship it to backup-01', ['backup', 'db'], 'db', 9 * HOUR, `---
- name: Nightly database backup
  hosts: db
  become: true
  tasks:
    - name: Dump all databases
      ansible.builtin.command: pg_dumpall --file /var/backups/all.sql
    - name: Copy the dump to the backup host
      ansible.posix.synchronize:
        src: /var/backups/all.sql
        dest: "backup-01.example.com:/srv/backups/{{ inventory_hostname }}/"
`),
  playbook('harden-ssh.yml', 'Keys only, no root passwords, modern ciphers', ['security'], 'all', 12 * DAY, `---
- name: Harden sshd
  hosts: all
  become: true
  tasks:
    - name: Disable password logins
      ansible.builtin.lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^#?PasswordAuthentication'
        line: PasswordAuthentication no
      notify: Reload sshd
  handlers:
    - name: Reload sshd
      ansible.builtin.service:
        name: ssh
        state: reloaded
`),
  playbook('rotate-certs.yml', 'Renew TLS certificates and reload the proxies', ['tls', 'web'], 'web', 5 * DAY, `---
- name: Rotate TLS certificates
  hosts: web
  become: true
  tasks:
    - name: Renew certificates
      ansible.builtin.command: certbot renew --quiet
    - name: Reload the proxy
      ansible.builtin.service:
        name: caddy
        state: reloaded
`),
  playbook('site.yml', 'Everything, in order: base, hardening, roles', ['site'], 'all', 20 * DAY, `---
- name: Base configuration
  ansible.builtin.import_playbook: harden-ssh.yml
- name: Web tier
  ansible.builtin.import_playbook: deploy-web.yml
`),
];

const WEB_HOSTS = HOSTS.filter((h) => h.groups.includes('web') && h.status !== 'err').map((h) => h.name);

// The log of the most recent deploy: what the Runs view shows.
const DEPLOY_LOG = [
  { type: 'meta', text: '$ ansible-playbook deploy-web.yml --limit web -e app_version=2.14.0' },
  { type: 'meta', text: 'PLAY [Deploy the web application] **********************************************' },
  ...['Take the host out of the load balancer', 'Install the release', 'Wait for the health check'].flatMap((task, i) => [
    { type: 'meta', text: `TASK [${task}] ${'*'.repeat(Math.max(3, 62 - task.length))}` },
    ...WEB_HOSTS.slice(0, 4).map((h) => ({ type: i === 1 ? 'changed' : 'ok', host: h, text: `${i === 1 ? 'changed' : 'ok'}: [${h}]` })),
  ]),
  { type: 'meta', text: 'RUNNING HANDLER [Restart app] **************************************************' },
  ...WEB_HOSTS.slice(0, 4).map((h) => ({ type: 'changed', host: h, text: `changed: [${h}]` })),
  { type: 'recap', text: 'PLAY RECAP *********************************************************************' },
  ...WEB_HOSTS.slice(0, 4).map((h) => ({ type: 'recap', text: `${h.padEnd(26)} : ok=4    changed=2    unreachable=0    failed=0    skipped=0` })),
  { type: 'done', text: 'completed in 1m 48s' },
];

const run = (id, kind, what, target, status, minutes, duration, counts, extra = {}) => ({
  id, kind, server: SERVER.name, serverId: SERVER.id, target, status,
  [kind === 'playbook' ? 'playbook' : 'module']: what,
  command: kind === 'playbook' ? `ansible-playbook ${what} --limit ${target}` : `ansible ${target} -m ${what}`,
  ok: counts[0], changed: counts[1], failed: counts[2], skipped: counts[3],
  duration, who: 'ui', startedAt: ago(minutes), endedAt: ago(minutes - 1), ...extra,
});

const RUNS = [
  run('run-0f3a91', 'playbook', 'deploy-web.yml', 'web', 'ok', 3 * HOUR, '1m 48s', [16, 8, 0, 0], { extraVars: { app_version: '2.14.0' }, become: true }),
  run('run-0e7c20', 'adhoc', 'ansible.builtin.command', 'web', 'ok', 4 * HOUR, '3.1s', [9, 0, 0, 0], { args: { cmd: 'uptime' } }),
  run('run-0e11b4', 'playbook', 'backup.yml', 'db', 'ok', 9 * HOUR, '4m 12s', [6, 3, 0, 0], { become: true }),
  run('run-0d98aa', 'adhoc', 'ansible.builtin.ping', 'all', 'err', 26 * HOUR, '11.4s', [13, 0, 1, 0]),
  run('run-0d40c7', 'playbook', 'patch.yml', 'all', 'ok', 2 * DAY, '12m 05s', [39, 11, 0, 2], { become: true }),
  run('run-0c5512', 'playbook', 'deploy-web.yml', 'web', 'err', 3 * DAY, '0m 52s', [7, 2, 1, 0], { extraVars: { app_version: '2.13.9' }, become: true }),
  run('run-0c01de', 'bootstrap', '', 'web-03.example.com', 'ok', 2 * DAY + 3 * HOUR, '18m 41s', [1, 0, 0, 0]),
  run('run-0b77f3', 'playbook', 'rotate-certs.yml', 'web', 'ok', 5 * DAY, '0m 34s', [18, 9, 0, 0], { become: true }),
  run('run-0b2a08', 'playbook', 'backup.yml', 'db', 'ok', 5 * DAY + 9 * HOUR, '4m 03s', [6, 3, 0, 0], { become: true }),
  run('run-0a9e64', 'adhoc', 'ansible.builtin.apt', 'db', 'ok', 7 * DAY, '21.9s', [3, 3, 0, 0], { args: { name: 'postgresql-client', state: 'latest' }, become: true }),
  run('run-0a31c9', 'playbook', 'patch.yml', 'all', 'ok', 9 * DAY, '11m 47s', [39, 14, 0, 1], { become: true }),
  run('run-09d2b5', 'playbook', 'harden-ssh.yml', 'all', 'ok', 12 * DAY, '1m 02s', [26, 2, 0, 0], { become: true }),
  run('run-097f10', 'playbook', 'backup.yml', 'db', 'ok', 13 * DAY, '4m 20s', [6, 3, 0, 0], { become: true }),
  run('run-0911ee', 'playbook', 'site.yml', 'all', 'ok', 20 * DAY, '6m 38s', [58, 4, 0, 3], { become: true }),
];

const VAULT_FILES = [
  { path: 'inventory/group_vars/all/vault.yml', name: 'vault.yml', size: 1894, modified: ago(6 * DAY), kind: 'inline' },
  { path: 'inventory/group_vars/db/vault.yml', name: 'vault.yml', size: 742, modified: ago(31 * DAY), kind: 'inline' },
  { path: 'secrets/tls-wildcard.key', name: 'tls-wildcard.key', size: 3311, modified: ago(5 * DAY), kind: 'file', vaultId: 'prod' },
  { path: 'secrets/backup-passphrase.txt', name: 'backup-passphrase.txt', size: 484, modified: ago(140 * DAY), kind: 'file' },
];

const SETTINGS = { prometheusUrl: 'http://127.0.0.1:9090', prometheusHostLabel: 'instance', autoGatherFacts: false, geoIpEnabled: false, controlPrivKeyPath: '', bootstrapRequireHostKey: false, version: 'v0.1.0' };

// What an ad-hoc `uptime` across the web group streams back.
const ADHOC_EVENTS = [
  { type: 'meta', text: '$ ansible web -m ansible.builtin.command -a cmd=uptime' },
  ...WEB_HOSTS.flatMap((h, i) => [
    { type: 'ok', host: h, text: `${h} | CHANGED | rc=0 >>` },
    { type: 'line', text: ` 14:02:2${i % 3} up ${HOSTS.find((x) => x.name === h).uptime} days,  load average: ${HOSTS.find((x) => x.name === h).load.toFixed(2)}, 0.31, 0.28` },
  ]),
  { type: 'done', text: 'completed in 3.1s' },
];

// --------------------------------------------------------------- mocks

const json = (body) => ({ status: 200, contentType: 'application/json', body: JSON.stringify(body) });

async function mockApi(page, { loggedOut = false } = {}) {
  const table = {
    '/api/auth/status': () => (loggedOut ? { enabled: true, authenticated: false } : { enabled: true, authenticated: true }),
    '/api/servers': () => ({ servers: [SERVER], activeServerId: SERVER.id }),
    '/api/settings': () => SETTINGS,
    '/api/inventory': () => ({ groups: GROUPS, hosts: HOSTS }),
    '/api/metrics': () => ({ configured: true, metrics: {} }),
    '/api/playbooks': () => ({ playbooks: PLAYBOOKS }),
    '/api/runs': () => ({ runs: RUNS }),
    '/api/vault': () => ({ files: VAULT_FILES, workDir: SERVER.workDir }),
    '/api/bootstrap/jobs': () => ({ jobs: [] }),
  };
  await page.route('**/api/**', (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/playbooks/content') {
      const pb = PLAYBOOKS.find((p) => p.path === url.searchParams.get('path')) || PLAYBOOKS[0];
      return route.fulfill(json({ path: pb.path, yaml: pb.yaml }));
    }
    if (url.pathname.startsWith('/api/runs/')) {
      const id = decodeURIComponent(url.pathname.slice('/api/runs/'.length));
      const r = RUNS.find((x) => x.id === id) || RUNS[0];
      return route.fulfill(json({ ...r, log: r.id === RUNS[0].id ? DEPLOY_LOG : [{ type: 'meta', text: `$ ${r.command}` }, { type: 'done', text: `completed in ${r.duration}` }] }));
    }
    const handler = table[url.pathname];
    if (handler) return route.fulfill(json(handler()));
    // Anything the script did not plan for fails loudly instead of
    // reaching the real backend.
    return route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: `not mocked: ${url.pathname}` }) });
  });
  // Run streams are WebSockets: reply with the canned ad-hoc output.
  await page.routeWebSocket(/\/api\/(adhoc|playbook)\/stream/, (ws) => {
    ws.onMessage(() => {
      for (const evt of ADHOC_EVENTS) ws.send(JSON.stringify(evt));
    });
  });
}

// ------------------------------------------------------------- capture

// Set once the server is up (see main): the address of the ansbui that
// this run started, and nothing else.
let APP = '';

async function shot(page, name) {
  await page.waitForTimeout(350); // let transitions and fonts settle
  await page.screenshot({ path: path.join(OUT, `${name}.png`) });
  console.log(`  ${name}.png`);
}

async function openView(page, label) {
  await page.locator('.sb-item', { hasText: label }).first().click();
  await page.waitForTimeout(250);
}

async function capture(browser) {
  const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1.5, colorScheme: 'dark', timezoneId: 'UTC', locale: 'en-US' });

  const login = await context.newPage();
  await mockApi(login, { loggedOut: true });
  await login.goto(APP, { waitUntil: 'networkidle' });
  await login.waitForSelector('input[type=password]');
  await shot(login, 'login');
  await login.close();

  const page = await context.newPage();
  const problems = [];
  page.on('pageerror', (e) => problems.push(e.message));
  await mockApi(page);
  await page.goto(APP, { waitUntil: 'networkidle' });
  await page.waitForSelector('.sb-item');

  await openView(page, 'Dashboard');
  await shot(page, 'dashboard');

  await openView(page, 'Inventory');
  await shot(page, 'inventory');

  await openView(page, 'Playbooks');
  await shot(page, 'playbooks');

  // An ad-hoc run with output: `uptime` on the web group. The stream
  // is the canned ADHOC_EVENTS.
  await openView(page, 'Ad-hoc');
  const adhoc = page.locator('.view-adhoc');
  await adhoc.getByRole('button', { name: /^web\s*\d+$/ }).click();
  await adhoc.getByRole('button', { name: 'command', exact: true }).click();
  await adhoc.locator('.arg-key', { hasText: 'cmd' }).locator('xpath=following::input[1]').fill('uptime');
  await adhoc.getByRole('button', { name: 'Run', exact: true }).click();
  await page.getByText('completed in 3.1s').first().waitFor();
  await shot(page, 'adhoc');

  await openView(page, 'Runs');
  await shot(page, 'runs');

  await openView(page, 'Bootstrap');
  await page.fill('#boot-provider', 'hetzner');
  await page.fill('#boot-hostname', 'web-04.example.com');
  await page.fill('#boot-ip', '203.0.113.44');
  await page.fill('#boot-pw', 'placeholder-only');
  await shot(page, 'bootstrap');

  await context.close();
  if (problems.length) throw new Error(`page errors while capturing:\n  ${problems.join('\n  ')}`);
}

// ---------------------------------------------------------------- main

// freePort asks the kernel for a loopback port nobody is using.
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

// startServer runs the binary and resolves once THAT process answers.
//
// The page's HTML, CSS and scripts come from this server, so the pictures
// are of whatever binary is listening. Polling a fixed port would accept
// any ansbui that happened to be there — an older build left running, say —
// while the one just built died on the bind error, and the screenshots
// would quietly show the wrong UI. So the port is one nobody had a moment
// ago, and the child exiting at any point before it answers is a failure,
// reported with what it printed.
async function startServer(dataDir) {
  const port = await freePort();
  const app = `http://127.0.0.1:${port}`;
  const child = spawn(BIN, ['-addr', `127.0.0.1:${port}`, '-allow-unauthenticated'], {
    env: { ...process.env, ANSBUI_CONFIG: path.join(dataDir, 'config.json'), ANSBUI_RUNS: path.join(dataDir, 'runs.json'), HOME: dataDir },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4000); });
  let gone = null;
  child.once('error', (err) => { gone = `could not start ${BIN}: ${err.message}`; });
  child.once('exit', (code, signal) => { gone = `${BIN} exited (${signal || `status ${code}`}) before it was ready:\n${stderr.trim()}`; });

  for (let i = 0; i < 100 && !gone; i++) {
    try {
      const res = await fetch(`${app}/api/health`);
      if (res.ok) {
        // An answer counts only while our child is alive. Give a bind
        // failure a moment to surface as an exit before believing it.
        await new Promise((r) => setTimeout(r, 150));
        if (!gone && child.exitCode === null) return { app, child };
      }
    } catch { /* not listening yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  throw new Error(gone || `ansbui did not answer on ${app} within 10s:\n${stderr.trim()}`);
}

const dataDir = mkdtempSync(path.join(tmpdir(), 'ansbui-shots-'));
let server;
let browser;
try {
  server = await startServer(dataDir);
  APP = server.app;
  mkdirSync(OUT, { recursive: true });
  browser = await chromium.launch();
  console.log(`writing ${path.relative(ROOT, OUT)}/`);
  await capture(browser);
} finally {
  await browser?.close();
  server?.child.kill();
  rmSync(dataDir, { recursive: true, force: true });
}
