// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Tests for how web/data/api.js derives a playbook card's title from the
// YAML. The helper is private to the script, so the tests go through the
// public path: stub `fetch`, call AnsbuiAPI.refreshData(), read the cards
// it publishes on globalThis.AnsibleData.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, loadScript, stringsOver } from './browser-script.js';

// The title pattern as it was before the rewrite (see the last test).
const OLD_TITLE_RE = /^-[ \t]+name:[ \t]+([^\n]+)$/gm;
const BLANK = /^[ \t]$/;

// Loads api.js into a page whose backend returns `playbooks`.
function pageWith(playbooks) {
  const bodies = {
    '/api/inventory': { groups: [], hosts: [] },
    '/api/playbooks': { playbooks },
    '/api/runs': { runs: [] },
    '/api/settings': {},
  };
  const fetch = async (path) => {
    assert.ok(path in bodies, `unexpected request: ${path}`);
    return { ok: true, status: 200, json: async () => bodies[path] };
  };
  const page = createPage({ fetch });
  loadScript(page, 'data/api.js');
  return page;
}

// Titles of the cards built from the given YAML documents, in order.
async function titlesFor(yamls) {
  const page = pageWith(yamls.map((yaml, i) => ({ id: `p${i}`, name: `file-${i}.yml`, yaml })));
  await page.AnsbuiAPI.refreshData();
  return Array.from(page.AnsibleData.PLAYBOOKS, (p) => p.title);
}

test('the title is the first play name, without quotes', async () => {
  assert.deepEqual(
    await titlesFor([
      '---\n- name: Deploy web\n  hosts: web\n',
      '- name: "Quoted \'title\'"\n  hosts: all\n',
      '-   name:\t  Spaced out\n',
      '- hosts: all\n  tasks: []\n- name: Second play\n',
    ]),
    ['Deploy web', 'Quoted title', 'Spaced out', 'Second play'],
  );
});

test('an explicit title wins, and no play name falls back to the file name', async () => {
  const page = pageWith([
    { id: 'a', name: 'a.yml', title: 'Given', yaml: '- name: From yaml\n' },
    { id: 'b', name: 'b.yml', yaml: '- hosts: all\n' },
    { id: 'c', name: 'c.yml' },
    // An indented `- name:` is a task, not a play.
    { id: 'd', name: 'd.yml', yaml: '- hosts: all\n  tasks:\n    - name: A task\n' },
  ]);
  await page.AnsbuiAPI.refreshData();
  assert.deepEqual(Array.from(page.AnsibleData.PLAYBOOKS, (p) => p.title), ['Given', 'b.yml', 'c.yml', 'd.yml']);
});

test('a play name that is only blanks is skipped', async () => {
  assert.deepEqual(
    await titlesFor([
      '- name:    \n  hosts: all\n',
      '- name: \t \n- name: Real name\n',
    ]),
    ['file-0.yml', 'Real name'],
  );
});

test('a hostile name line is handled quickly', async () => {
  const yaml = `- name:${' '.repeat(100_000)}\n${'- name:\n'.repeat(10_000)}`;
  const page = pageWith([{ id: 'p', name: 'p.yml', yaml }]);
  const started = performance.now();
  await page.AnsbuiAPI.refreshData();
  const ms = performance.now() - started;
  assert.ok(ms < 1500, `title scan took ${Math.round(ms)} ms`);
  assert.deepEqual(Array.from(page.AnsibleData.PLAYBOOKS, (p) => p.title), ['p.yml']);
});

test('the title matches the old pattern, except that blank names are skipped', async () => {
  // Expected result from the old pattern: its first match whose capture
  // is not a lone blank. (A lone blank was all the old pattern could
  // capture from a blank-only name, and only when there were two or more
  // blanks; with exactly one it already found no match on that line.)
  const expected = (yaml) => {
    for (const m of yaml.matchAll(OLD_TITLE_RE)) {
      if (!BLANK.test(m[1])) return m[1].replaceAll(/["']/g, '');
    }
    return null;
  };

  const yamls = [];
  for (const head of ['- name:', '-\tname:', 'x\n- name:', ' - name:']) {
    for (const tail of stringsOver([' ', '\t', 'x', '"', '\r', '\n'], 4)) {
      yamls.push(`${head}${tail}\n- name: later\n`);
      yamls.push(head + tail);
    }
  }
  assert.ok(yamls.length > 12_000, `only ${yamls.length} documents`);

  const titles = await titlesFor(yamls);
  yamls.forEach((yaml, i) => {
    assert.equal(titles[i], expected(yaml) ?? `file-${i}.yml`, JSON.stringify(yaml));
  });
});
