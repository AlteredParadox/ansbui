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

// The bootstrap form sends two ports: the one sshd answers on now and
// the one it is moved to. Both come from free-text fields, and
// Number.parseInt would read "22abc" as 22 and "4242 " + anything as
// 4242 — a typo that would move sshd somewhere the operator did not
// mean. parseTcpPort accepts digits only.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, loadScript } from './browser-script.js';

const page = createPage();
loadScript(page, 'views/Bootstrap.jsx');
const { parseTcpPort, parseBootstrapPorts } = page;

test('a TCP port is digits only, 1 to 65535', () => {
  for (const [text, want] of [['22', 22], ['4242', 4242], [' 2222 ', 2222], ['1', 1], ['65535', 65535]]) {
    assert.equal(parseTcpPort(text), want, JSON.stringify(text));
  }
});

test('anything else is refused', () => {
  for (const text of ['', ' ', '0', '65536', '99999', '123456', '-22', '22abc', '4242;reboot', '22.5', '2e3', '0x16', '２２']) {
    assert.equal(parseTcpPort(text), 0, JSON.stringify(text));
  }
});

test('a number is accepted as well as its text', () => {
  assert.equal(parseTcpPort(4242), 4242);
});

// The form's check, as start() runs it. Each field is refused on its
// own: the current port used to go through Number.parseInt, which
// let "22abc" and "22.5" through as 22.
test('both port fields of the form are checked strictly', () => {
  assert.deepEqual({ ...parseBootstrapPorts('22', '4242') }, { portNum: 22, newPortNum: 4242 });
  assert.deepEqual({ ...parseBootstrapPorts(' 2200 ', '2200') }, { portNum: 2200, newPortNum: 2200 });
  for (const bad of ['22abc', '22.5', '', '0', '70000']) {
    assert.match(parseBootstrapPorts(bad, '4242').error, /^Current SSH port/, `current=${JSON.stringify(bad)}`);
    assert.match(parseBootstrapPorts('22', bad).error, /^New SSH port/, `new=${JSON.stringify(bad)}`);
  }
});
