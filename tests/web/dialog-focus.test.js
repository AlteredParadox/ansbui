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

// Tests for where focus goes when a dialog opens (useDialog in
// web/components/Shell.jsx).
//
// showModal() focuses the first focusable element in the dialog, which is
// the close button in the header. A dialog that should open on a field
// marks it `data-autofocus`, and useDialog focuses it after showModal().
// React's `autoFocus` cannot do that for a field that is already present
// when the dialog opens, so the second test keeps it out of those places.

import assert from 'node:assert/strict';
import test from 'node:test';

import { traverse } from '@babel/core';

import { createPage, jsxFiles, loadScript, parseScript, reactStub } from './browser-script.js';

// Runs useDialog(open) once against a stand-in <dialog> and returns the
// calls it made, in order. `alreadyOpen` is the element's state before;
// `field` says whether the dialog holds a `data-autofocus` element.
function openDialog({ open, alreadyOpen = false, field = true }) {
  const calls = [];
  const el = {
    open: alreadyOpen,
    showModal() {
      calls.push('showModal');
      this.open = true;
    },
    close() {
      calls.push('close');
      this.open = false;
    },
    querySelector(selector) {
      calls.push(`querySelector ${selector}`);
      return field ? { focus: () => calls.push('focus') } : null;
    },
    addEventListener() {},
    removeEventListener() {},
  };
  const page = createPage({
    React: {
      ...reactStub(),
      useRef: () => ({ current: el }),
      // Run the effect body once, as on first render; cleanup is not run.
      useLayoutEffect: (effect) => void effect(),
      useEffect: (effect) => void effect(),
    },
  });
  loadScript(page, 'components/Shell.jsx');
  page.useDialog(open, () => {});
  return calls;
}

test('opening a dialog shows it, then focuses the marked field', () => {
  assert.deepEqual(openDialog({ open: true }), ['showModal', 'querySelector [data-autofocus]', 'focus']);
});

test('a dialog with no marked field is shown and focus is left to the browser', () => {
  assert.deepEqual(openDialog({ open: true, field: false }), ['showModal', 'querySelector [data-autofocus]']);
});

test('a dialog that is already open is not re-shown and focus is not moved', () => {
  assert.deepEqual(openDialog({ open: true, alreadyOpen: true }), []);
});

test('closing a dialog does not touch focus', () => {
  assert.deepEqual(openDialog({ open: false, alreadyOpen: true }), ['close']);
  assert.deepEqual(openDialog({ open: false }), []);
});

// ------------------------------------------------------------- autoFocus

// Where `autoFocus` is allowed: each of these mounts its field into a
// page or dialog that is already showing, which is the only case where
// React's autoFocus takes effect. Everything else must use
// `data-autofocus` (dialogs) or nothing.
const AUTOFOCUS_ALLOWED = {
  'views/Login.jsx': ['login-pw'],
  'views/Vault.jsx': ['ive-name', 'ive-pw'],
};

test('autoFocus appears only on the fields where it works', () => {
  const found = {};
  const marked = [];
  for (const file of jsxFiles()) {
    traverse(parseScript(file), {
      JSXAttribute(path) {
        const name = path.node.name.name;
        if (name !== 'autoFocus' && name !== 'data-autofocus') return;
        const id = path.parent.attributes.find((a) => a.type === 'JSXAttribute' && a.name.name === 'id')?.value?.value;
        if (name === 'autoFocus') (found[file] ??= []).push(id);
        else marked.push(`${file}#${id}`);
      },
    });
  }
  assert.deepEqual(found, AUTOFOCUS_ALLOWED);
  // The two dialogs that open on a field.
  assert.deepEqual(marked, ['views/Vault.jsx#vault-pw', 'views/Vault.jsx#vault-openpath']);
});
