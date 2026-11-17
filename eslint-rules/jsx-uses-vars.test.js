// Tests for the local jsx-uses-vars rule. Run with `npm test`.
//
// They lint snippets through the project's real eslint.config.js rather
// than a hand-built config, so they cover the wiring (parser, plugin
// registration, `no-unused-vars` options) as well as the rule itself.

import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { Linter } from 'eslint';

import config from '../eslint.config.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const linter = new Linter({ configType: 'flat', cwd: repoRoot });

// Returns the names `no-unused-vars` reports for a snippet linted as if
// it were a file under web/. Any other message fails the test, so a
// parse error or a misconfigured rule can't pass as "nothing reported".
function unusedVars(code) {
  const messages = linter.verify(code, config, { filename: path.join(repoRoot, 'web', 'probe.jsx') });
  const other = messages.filter((m) => m.ruleId !== 'no-unused-vars');
  assert.deepEqual(other, [], 'unexpected non-no-unused-vars messages');
  return messages.map((m) => /'([^']+)'/.exec(m.message)[1]).sort();
}

test('a component referenced only from JSX counts as used', () => {
  assert.deepEqual(
    unusedVars('function Comp() { return null; }\nwindow.App = function () { return <Comp />; };\n'),
    [],
  );
});

test('<ns.Component /> counts as a use of ns, whatever its case', () => {
  assert.deepEqual(
    unusedVars('const ns = { Component() { return null; } };\nwindow.App = function () { return <ns.Component />; };\n'),
    [],
  );
  assert.deepEqual(
    unusedVars('const a = { b: { C() { return null; } } };\nwindow.App = function () { return <a.b.C />; };\n'),
    [],
  );
});

test('an intrinsic tag is not a use of a same-named local', () => {
  assert.deepEqual(
    unusedVars('window.App = function () { const div = 1; return <div />; };\n'),
    ['div'],
  );
});

test('a namespaced tag is not a use of either name', () => {
  assert.deepEqual(
    unusedVars('window.App = function () { const svg = 1; const rect = 2; return <svg:rect />; };\n'),
    ['rect', 'svg'],
  );
});

test('a component that really is unused is still reported', () => {
  assert.deepEqual(
    unusedVars('function Unused() { return null; }\nwindow.App = function () { return <div />; };\n'),
    ['Unused'],
  );
});
