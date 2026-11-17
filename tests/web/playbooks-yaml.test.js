// Tests for the YAML line handling in web/views/Playbooks.jsx: the task
// outline (parseYamlTasks) and the syntax colouring (renderYamlLine).
//
// Three of its patterns used to take quadratic time on a hostile line.
// For each one this file checks (a) what the functions return on ordinary
// input, (b) that a 100,000-character hostile line is handled quickly,
// and (c) that the rewritten pattern gives the same result as the old one
// on every short string over a small alphabet.

import assert from 'node:assert/strict';
import test from 'node:test';

import { assertFast, createPage, evaluate, loadScript, plain, stringsOver } from './browser-script.js';

const page = createPage();
loadScript(page, 'views/Playbooks.jsx');
const { parseYamlTasks, renderYamlLine, colorizeValue } = page;

// A quadratic pattern needs roughly 10 s for this length on a laptop.
const HOSTILE = 100_000;

// The patterns as they were before the rewrite: the reference for (c).
const OLD_TASK_NAME_RE = /^[ \t]+- name:[ \t]+(.*)$/;
const OLD_DASH_RE = /^([ \t]*)-([ \t]+)(.*)$/;
const OLD_JINJA_RE = /\{\{.*\}\}/;

const groups = (m) => (m ? Array.from(m) : null);

// Alphabet for the old-versus-new comparisons: the two blanks the
// patterns name, an ordinary character, and the characters that separate
// the candidate rewrites from each other. Form feed is whitespace but not
// a blank (so `\S` would be the wrong shortcut); the last three are line
// terminators, which "." refuses to cross.
const BLANKS_AND_BREAKS = [' ', '\t', 'a', '\f', '\r', '\n', '\u2028'];

// ---------------------------------------------------------------- outline

test('parseYamlTasks lists named tasks with their section and module', () => {
  const yaml = [
    '- hosts: web',
    '  pre_tasks:',
    '    - name: "Warm up"',
    '      ansible.builtin.ping:',
    '  tasks:',
    "    - name: 'Install nginx'",
    '      ansible.builtin.apt:',
    '        name: nginx',
    '    - name: Restart',
    '      community.general.systemd:',
    '        name: nginx',
    '    - name:   ',
    '      debug:',
  ].join('\n');

  const tasks = plain(parseYamlTasks(yaml)).map(({ section, name, module, startLine }) => ({ section, name, module, startLine }));
  assert.deepEqual(tasks, [
    { section: 'pre_tasks', name: 'Warm up', module: 'ansible.builtin.ping', startLine: 2 },
    { section: 'tasks', name: 'Install nginx', module: 'ansible.builtin.apt', startLine: 5 },
    { section: 'tasks', name: 'Restart', module: 'community.general.systemd', startLine: 8 },
    // A name that is only blanks is still a task, with an empty name.
    { section: 'tasks', name: '', module: '', startLine: 11 },
  ]);
});

test('parseYamlTasks ignores a `- name:` line outside a task section', () => {
  assert.deepEqual(plain(parseYamlTasks('- name: play\n  hosts: all\n')), []);
});

test('parseYamlTasks handles a hostile task-name line quickly', () => {
  // Blanks after `name:` and then a carriage return: the line cannot
  // match, which is what made the old pattern retry once per blank.
  const line = `    - name:${' '.repeat(HOSTILE)}\r`;
  assertFast(assert, 'task name line', () => {
    assert.deepEqual(plain(parseYamlTasks(`  tasks:\n${line}\n`)), []);
  });
});

test('TASK_NAME_RE matches exactly what the old pattern matched', () => {
  const current = evaluate(page, 'TASK_NAME_RE');
  let checked = 0;
  for (const head of ['  - name:', '\t- name:', '- name:', '  - name']) {
    for (const tail of stringsOver(BLANKS_AND_BREAKS, 5)) {
      const line = head + tail;
      assert.deepEqual(groups(current.exec(line)), groups(OLD_TASK_NAME_RE.exec(line)), JSON.stringify(line));
      checked++;
    }
  }
  assert.ok(checked > 70_000, `only ${checked} strings compared`);
});

// --------------------------------------------------------------- colouring

// The class of the span colorizeValue picked for a value.
const valueClass = (rest) => colorizeValue(rest).props.className;

test('colorizeValue classifies numbers, booleans, strings, Jinja and the rest', () => {
  assert.equal(valueClass(' 42'), 'yml-n');
  assert.equal(valueClass(' 3.14'), 'yml-n');
  assert.equal(valueClass(' yes'), 'yml-b');
  assert.equal(valueClass(' "quoted"'), 'yml-s');
  assert.equal(valueClass(' {{ item }}'), 'yml-j');
  assert.equal(valueClass(' /etc/{{ name }}.conf'), 'yml-j');
  assert.equal(valueClass(' plain text'), 'yml-v');
  // Not Jinja: no opening pair, no closing pair, or the pairs reversed.
  assert.equal(valueClass(' { single }'), 'yml-v');
  assert.equal(valueClass(' {{ unclosed'), 'yml-v');
  assert.equal(valueClass(' }} backwards {{'), 'yml-v');
  // The closing pair must come after the opening one, not overlap it.
  assert.equal(valueClass(' {{}'), 'yml-v');
  assert.equal(valueClass(' {{}}'), 'yml-j');
});

test('colorizeValue handles a hostile run of braces quickly', () => {
  const value = ` ${'{'.repeat(HOSTILE)}`;
  assertFast(assert, 'brace run', () => {
    assert.equal(valueClass(value), 'yml-v');
  });
});

test('hasJinja agrees with the old pattern', () => {
  const hasJinja = evaluate(page, 'hasJinja');
  let checked = 0;
  for (const s of stringsOver(['{', '}', 'a', ' '], 8)) {
    assert.equal(hasJinja(s), OLD_JINJA_RE.test(s), JSON.stringify(s));
    checked++;
  }
  assert.ok(checked > 80_000, `only ${checked} strings compared`);
});

test('renderYamlLine splits a list item into indent, dash, gap and content', () => {
  const el = plain(renderYamlLine('  -   name: demo', 7));
  assert.equal(el.type, 'Fragment');
  const [indent, dash, gap, content] = el.children;
  assert.equal(indent, '  ');
  assert.deepEqual({ type: dash.type, cls: dash.props.className, text: dash.children }, { type: 'span', cls: 'yml-d', text: ['-'] });
  assert.equal(gap, '   ');
  // The content is coloured as key, colon, value.
  const [key, colon, value] = content.children;
  assert.deepEqual([key.props.className, key.children], ['yml-k', ['name']]);
  assert.deepEqual([colon.props.className, colon.children], ['yml-p', [':']]);
  assert.deepEqual([value.props.className, value.children], ['yml-v', [' demo']]);
});

test('renderYamlLine keeps comments and document markers whole', () => {
  assert.equal(plain(renderYamlLine('   # - not: a list', 0)).props.className, 'yml-c');
  assert.equal(plain(renderYamlLine('---', 0)).props.className, 'yml-c');
});

test('renderYamlLine handles a hostile list-item line quickly', () => {
  const line = `-${' '.repeat(HOSTILE)}\r`;
  assertFast(assert, 'dash line', () => {
    renderYamlLine(line, 0);
  });
});

test('DASH_RE matches exactly what the old pattern matched', () => {
  const current = evaluate(page, 'DASH_RE');
  let checked = 0;
  for (const line of stringsOver(['-', ...BLANKS_AND_BREAKS], 5)) {
    assert.deepEqual(groups(current.exec(line)), groups(OLD_DASH_RE.exec(line)), JSON.stringify(line));
    checked++;
  }
  assert.ok(checked > 30_000, `only ${checked} strings compared`);
});
