// A playbook is identified by its path. These tests cover the places
// the UI used to identify one by file name instead, which made
// deploy.yml and staging/deploy.yml interchangeable: History's
// "View playbook" / "Re-run" / "Retry failed", and the per-playbook
// last-run annotation.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, loadScript } from './browser-script.js';

const historyPage = createPage();
loadScript(historyPage, 'views/History.jsx');
const { findPlaybookFor, rerunBlocked } = historyPage;

const LIBRARY = [
  { id: 'pb-deploy.yml', name: 'deploy.yml', path: 'deploy.yml' },
  { id: 'pb-staging/deploy.yml', name: 'deploy.yml', path: 'staging/deploy.yml' },
  { id: 'pb-site.yaml', name: 'site.yaml', path: 'site.yaml' },
];
const PROD = { id: 'srv-prod', name: 'prod' };

test('a run resolves to the playbook at exactly its recorded path', () => {
  assert.equal(findPlaybookFor(LIBRARY, { playbook: 'staging/deploy.yml' }).id, 'pb-staging/deploy.yml');
  assert.equal(findPlaybookFor(LIBRARY, { playbook: 'deploy.yml' }).id, 'pb-deploy.yml');
});

test('a same-named file elsewhere is not a match', () => {
  // Each of these used to resolve to one of the deploy.yml entries.
  for (const recorded of ['prod/deploy.yml', 'old/staging/deploy.yml', 'deploy.yaml', 'site.yml', 'DEPLOY.yml']) {
    assert.equal(findPlaybookFor(LIBRARY, { playbook: recorded }), null, recorded);
  }
  assert.equal(findPlaybookFor(LIBRARY, { playbook: '' }), null);
  assert.equal(findPlaybookFor(LIBRARY, null), null);
  assert.equal(findPlaybookFor([], { playbook: 'deploy.yml' }), null);
});

test('re-run is offered for the same playbook on the same connection', () => {
  assert.equal(rerunBlocked(LIBRARY, { playbook: 'staging/deploy.yml', server: 'prod', serverId: 'srv-prod' }, PROD), '');
  // Records from before serverId existed carry only the name.
  assert.equal(rerunBlocked(LIBRARY, { playbook: 'deploy.yml', server: 'prod' }, PROD), '');
  // And the oldest carry neither: nothing to compare, so the path decides.
  assert.equal(rerunBlocked(LIBRARY, { playbook: 'deploy.yml' }, PROD), '');
});

test('re-run is refused when the recorded path is not in the library', () => {
  for (const recorded of ['prod/deploy.yml', 'gone.yml', 'deploy.yaml']) {
    const why = rerunBlocked(LIBRARY, { playbook: recorded, server: 'prod', serverId: 'srv-prod' }, PROD);
    assert.match(why, /not in this connection's library/, recorded);
    assert.ok(why.includes(recorded), `the reason should name ${recorded}: ${why}`);
  }
  assert.notEqual(rerunBlocked(LIBRARY, { playbook: '' }, PROD), '');
  assert.notEqual(rerunBlocked(LIBRARY, null, PROD), '');
});

test('re-run is refused for a run recorded on another connection', () => {
  // Same path exists here too — which is exactly the dangerous case.
  const byId = rerunBlocked(LIBRARY, { playbook: 'deploy.yml', server: 'staging', serverId: 'srv-staging' }, PROD);
  assert.match(byId, /Recorded on connection "staging"/);
  assert.match(byId, /active: "prod"/);

  const byName = rerunBlocked(LIBRARY, { playbook: 'deploy.yml', server: 'staging' }, PROD);
  assert.match(byName, /Recorded on connection "staging"/);
});

test('the connection id decides when the record has one, not the name', () => {
  // Renamed connection: same id, different name. Still the same node.
  assert.equal(rerunBlocked(LIBRARY, { playbook: 'deploy.yml', server: 'old-name', serverId: 'srv-prod' }, PROD), '');
  // Two connections sharing a display name are still different nodes.
  assert.notEqual(rerunBlocked(LIBRARY, { playbook: 'deploy.yml', server: 'prod', serverId: 'srv-other' }, PROD), '');
});

// --- web/data/api.js: last-run annotation -------------------------------

async function cardsFor(playbooks, runs) {
  const bodies = {
    '/api/inventory': { groups: [], hosts: [] },
    '/api/playbooks': { playbooks },
    '/api/runs': { runs },
    '/api/settings': {},
  };
  const fetch = async (path) => {
    assert.ok(path in bodies, `unexpected request: ${path}`);
    return { ok: true, status: 200, json: async () => bodies[path] };
  };
  const page = createPage({ fetch });
  loadScript(page, 'data/api.js');
  await page.AnsbuiAPI.refreshData();
  return page.AnsibleData;
}

test('runs are credited to the playbook at their path, not to its namesakes', async () => {
  const data = await cardsFor(
    [
      { id: 'pb-deploy.yml', name: 'deploy.yml', path: 'deploy.yml' },
      { id: 'pb-staging/deploy.yml', name: 'deploy.yml', path: 'staging/deploy.yml' },
    ],
    [
      { id: 'r1', kind: 'playbook', playbook: 'deploy.yml', status: 'err', startedAt: '2026-01-02T00:00:00Z' },
      { id: 'r2', kind: 'playbook', playbook: 'deploy.yml', status: 'ok', startedAt: '2026-01-01T00:00:00Z' },
    ],
  );
  const byPath = Object.fromEntries(Array.from(data.PLAYBOOKS, (p) => [p.path, p]));
  assert.equal(byPath['deploy.yml'].runs, 2);
  assert.equal(byPath['deploy.yml'].lastStatus, 'err');
  // Never ran: no count, no status dot borrowed from the other file.
  assert.equal(byPath['staging/deploy.yml'].runs, 0);
  assert.equal(byPath['staging/deploy.yml'].lastStatus, '');
});

test('run cards carry the connection they were recorded on', async () => {
  const data = await cardsFor([], [
    { id: 'r1', kind: 'playbook', playbook: 'deploy.yml', server: 'prod', serverId: 'srv-prod', startedAt: '2026-01-01T00:00:00Z' },
    { id: 'r0', kind: 'playbook', playbook: 'deploy.yml', startedAt: '2025-01-01T00:00:00Z' },
  ]);
  const [r1, r0] = Array.from(data.RUNS);
  assert.deepEqual([r1.server, r1.serverId], ['prod', 'srv-prod']);
  assert.deepEqual([r0.server, r0.serverId], ['', '']);
});
