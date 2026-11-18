// A playbook is identified by its path. These tests cover the places
// the UI used to identify one by file name instead, which made
// deploy.yml and staging/deploy.yml interchangeable: History's
// "View playbook" / "Re-run" / "Retry failed", and the per-playbook
// last-run annotation.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, findElements, hookRuntime, loadScript, textOf } from './browser-script.js';

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

// --- web/views/Playbooks.jsx: consuming a re-run prefill ----------------
//
// History's buttons are one guard; the Playbooks view is the other, and
// the one that matters, because it is where the prefill is acted on.
// The prefill is state the app shell holds between views, so it can
// arrive after the active connection has changed.


const STAGING = { id: 'srv-staging', name: 'staging' };
const BOTH_HAVE = [
  { id: 'pb-site.yml', name: 'site.yml', path: 'site.yml', yaml: '- hosts: all\n' },
  { id: 'pb-deploy.yml', name: 'deploy.yml', path: 'deploy.yml', yaml: '- hosts: all\n' },
];

// A page with both views loaded, and a stand-in for the part of the app
// shell (App in index.html) that owns the prefill: it holds one, hands
// it to PlaybooksView, and drops it when told it was consumed or when
// the connection changes.
function shell(activeServer) {
  const rt = hookRuntime();
  const page = createPage({ React: rt.React, Icon: 'Icon', AnsibleData: { PLAYBOOKS: BOTH_HAVE } });
  loadScript(page, 'views/History.jsx');
  loadScript(page, 'views/Playbooks.jsx');
  const state = { prefill: null, active: activeServer, consumed: 0, view: null };
  const app = {
    page,
    state,
    // History's Re-run on `run`, as the shell's openPlaybookRunner does it.
    rerun(run) {
      state.prefill = { ...page.buildRerunPrefill(run), issuedAt: ++app.clock };
    },
    clock: 0,
    switchTo(server) {
      state.active = server;
      state.prefill = null; // the shell's effect on activeId
    },
    // Navigating to Playbooks mounts the view with whatever the shell holds.
    openPlaybooks({ prefill = state.prefill } = {}) {
      state.view = rt.mount(page.PlaybooksView, {
        runnerPrefill: prefill,
        activeServer: state.active,
        onRunnerPrefillConsumed: () => {
          state.consumed++;
          state.prefill = null;
        },
      });
      return app;
    },
    leave() {
      state.view.unmount();
      state.view = null;
    },
    runner() {
      const [el] = findElements(state.view.tree, (n) => n.type === page.PlaybookRunner);
      return el.props;
    },
    closeRunner() {
      app.runner().onClose();
      state.view.rerender();
    },
    banner() {
      return findElements(state.view.tree, (n) => n.props?.className === 'cm-error mono').map(textOf).join(' | ');
    },
  };
  return app;
}

const RUN_ON_PROD = { kind: 'playbook', playbook: 'deploy.yml', server: 'prod', serverId: 'srv-prod', limit: 'prod-web', tags: ['release'], extraVars: { version: '1.2.3' }, become: true };

test('a re-run opens the dialog for the recorded playbook, with the recorded settings', () => {
  const app = shell(PROD);
  app.rerun(RUN_ON_PROD);
  app.openPlaybooks();
  const r = app.runner();
  assert.equal(r.open, true);
  assert.equal(r.pb.path, 'deploy.yml');
  assert.equal(r.seed.limit, 'prod-web');
  assert.equal(r.seed.become, true);
  assert.equal(app.banner(), '');
});

test('a re-run prefill is used once: close, leave, switch connection, come back', () => {
  const app = shell(PROD);
  app.rerun(RUN_ON_PROD);
  app.openPlaybooks();
  assert.equal(app.runner().open, true);
  assert.equal(app.state.consumed, 1, 'the view did not tell the shell the prefill was consumed');
  assert.equal(app.state.prefill, null, 'the shell still holds the prefill');

  app.closeRunner();
  assert.equal(app.runner().open, false);
  app.leave(); // to the Dashboard
  app.switchTo(STAGING); // which also has a deploy.yml
  app.openPlaybooks(); // back via the sidebar

  const r = app.runner();
  assert.equal(r.open, false, "prod's re-run reopened on staging");
  assert.equal(r.seed, null, "prod's limit, tags and extra vars are staged for a run on staging");
  assert.equal(app.banner(), '');
});

test('a stale prefill that reaches the view anyway is refused for the wrong connection', () => {
  // The same sequence with a shell that failed to drop the prefill: the
  // view must not depend on that. Staging has deploy.yml too, which is
  // exactly why the path check alone is not enough.
  const app = shell(PROD);
  app.rerun(RUN_ON_PROD);
  const stale = app.state.prefill;
  app.openPlaybooks();
  app.closeRunner();
  app.leave();
  app.state.active = STAGING; // connection changed, prefill NOT cleared
  app.openPlaybooks({ prefill: { ...stale, issuedAt: 99 } });

  const r = app.runner();
  assert.equal(r.open, false, "prod's re-run opened on staging");
  assert.equal(r.seed, null);
  assert.match(app.banner(), /Not re-running\. Recorded on connection "prod"/);
  assert.match(app.banner(), /active: "staging"/);
  assert.equal(app.state.consumed, 2, 'a refused prefill must be consumed too');
});

test('a prefill for a path this connection does not have is refused, not redirected', () => {
  const app = shell(PROD);
  app.rerun({ ...RUN_ON_PROD, playbook: 'staging/deploy.yml' });
  app.openPlaybooks();
  const r = app.runner();
  assert.equal(r.open, false);
  assert.equal(r.seed, null);
  // Whatever is selected, it was not given the other run's settings.
  assert.match(app.banner(), /Not re-running\. staging\/deploy\.yml is not in this connection's library/);
});

test('the prefill carries the connection the run was recorded on', () => {
  const { page } = shell(PROD);
  for (const build of [page.buildRerunPrefill, page.buildRetryPrefill]) {
    const prefill = build({ ...RUN_ON_PROD, log: [{ type: 'fail', host: 'web1' }] });
    assert.deepEqual([prefill.playbookPath, prefill.server, prefill.serverId], ['deploy.yml', 'prod', 'srv-prod']);
  }
  // Old records: empty, never undefined.
  const old = page.buildRerunPrefill({ playbook: 'deploy.yml' });
  assert.deepEqual([old.server, old.serverId], ['', '']);
});
