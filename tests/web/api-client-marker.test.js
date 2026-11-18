// web/data/api.js must send X-Ansbui-Request on every call. The server
// refuses an Origin-less GET to the routes that reach the control node
// unless it carries that header (withOriginGuard in internal/api/api.go),
// because such a GET is otherwise indistinguishable from one a page on
// another site fired through an <img> or a link. If the wrapper stopped
// sending it, inventory, playbooks, facts and vault would all 403.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, loadScript } from './browser-script.js';

const MARKER = 'X-Ansbui-Request';

// A page whose fetch records each call and answers with an empty object.
function recordingPage() {
  const calls = [];
  const fetch = async (path, options) => {
    calls.push({ path, options });
    return { ok: true, status: 200, json: async () => ({}) };
  };
  const page = createPage({ fetch });
  loadScript(page, 'data/api.js');
  return { page, calls };
}

test('every API call carries the client marker header', async () => {
  const { page, calls } = recordingPage();
  const api = page.AnsbuiAPI;

  // One of each shape: a bare GET, a GET that reaches the control node,
  // a POST with a body, a POST without one, and a DELETE.
  await api.authStatus();
  await api.getSettings();
  await api.login('pw');
  await api.activateServer('srv-1');
  await api.deleteServer('srv-1');
  // refreshData issues the reads the server guards: inventory,
  // playbooks, runs, settings.
  await api.refreshData();

  assert.ok(calls.length >= 9, `only ${calls.length} calls recorded`);
  const guarded = calls.map((c) => c.path).filter((p) => p === '/api/inventory' || p === '/api/playbooks');
  assert.equal(guarded.length, 2, 'refreshData did not fetch inventory and playbooks');
  for (const { path, options } of calls) {
    assert.equal(options?.headers?.[MARKER], '1', `${path} was sent without ${MARKER}`);
  }
});

test('a caller-supplied header does not displace the marker', async () => {
  const { page, calls } = recordingPage();
  // Every wrapper call that sets its own headers goes through the same
  // merge; exercise it through any method and check both survive.
  await page.AnsbuiAPI.setSettings({});
  const { headers } = calls[0].options;
  assert.equal(headers[MARKER], '1');
  assert.equal(headers['Content-Type'], 'application/json');
});
