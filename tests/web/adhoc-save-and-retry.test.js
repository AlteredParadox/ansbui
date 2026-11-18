// Two places where the UI acts on text that came out of a run's output:
//
//   - "Save as playbook" writes the composer's target, module and
//     arguments into a YAML file that is later executed;
//   - "Retry failed" takes host names from "fatal: [name]" lines and
//     makes them the next run's target.
//
// A managed host can print such a line itself, so neither may trust
// the name: the first must not let it add YAML structure, the second
// must not let it widen the run.

import assert from 'node:assert/strict';
import test from 'node:test';

import { createPage, findElements, hookRuntime, loadScript, plain, textOf } from './browser-script.js';

const page = createPage();
loadScript(page, 'views/Adhoc.jsx');
loadScript(page, 'views/History.jsx');
const { yamlScalar, renderAdhocAsPlaybook, retryHosts, retryBlocked, buildAdhocRetryPrefill, buildRetryPrefill } = page;

// Characters a YAML parser treats as a line break, or strips.
const BREAKS = ['\n', '\r', '\u0085', '\u2028', '\u2029', '\ufeff'];

// decodeScalar reads back what yamlScalar wrote. A quoted result uses
// only the escapes JSON also has, so JSON.parse is the decoder; an
// unquoted one is the value itself.
function decodeScalar(text) {
  return text.startsWith('"') ? JSON.parse(text) : text;
}

const HOSTILE = [
  'web1\u2028  pre_tasks:\u2028    - ansible.builtin.debug: msg=INJECTED',
  'web2\r  become: true',
  'web3\n  become: true',
  'web4\u0085  become: true',
  'web5\u2029  become: true',
  'a: b',
  'all:',
  'x # comment',
  '{a: b}',
  '[a, b]',
  '- item',
  '*alias',
  '&anchor',
  '!tag',
  '@at',
  '%directive',
  '`tick`',
  '\'single\'',
  '"double"',
  'back\\slash',
  'trailing\\',
  'tab\there',
  'nul\u0000byte',
  'c1\u009bcontrol',
  '\ufeffbom',
  'emoji 🚀',
  ' leading space',
  'trailing space ',
  '2001:db8::1',
  '',
];

test('yamlScalar output decodes to its input and never contains a line break', () => {
  for (const value of HOSTILE) {
    const written = yamlScalar(value);
    assert.equal(decodeScalar(written), value, `round trip of ${JSON.stringify(value)}`);
    for (const br of BREAKS) {
      assert.ok(!written.includes(br), `${JSON.stringify(value)} was written with a raw U+${br.codePointAt(0).toString(16)}`);
    }
  }
});

test('yamlScalar quotes everything that is not a plain word', () => {
  for (const value of HOSTILE) {
    if (value === '') continue;
    assert.ok(yamlScalar(value).startsWith('"'), `${JSON.stringify(value)} was written unquoted`);
  }
  // Words YAML would read as a boolean, null or number stay strings.
  for (const word of ['true', 'False', 'null', 'yes', 'NO', 'on', 'off', '~', '42', '3.14']) {
    assert.equal(yamlScalar(word), `"${word}"`);
  }
  // Ordinary names are left readable.
  for (const word of ['all', 'web-1', 'db_servers', 'ansible.builtin.ping', 'plays/site.yml', 'user@host']) {
    assert.equal(yamlScalar(word), word);
  }
});

// playShape checks the generated document line by line: the fixed
// template, nothing added, and returns the decoded values.
function playShape(doc, { become, argCount }) {
  const lines = doc.split('\n');
  assert.equal(lines.pop(), '', 'document ends with a newline');
  const expected = 7 + (become ? 1 : 0) + argCount;
  assert.equal(lines.length, expected, `expected ${expected} lines, got:\n${doc}`);
  let i = 0;
  assert.equal(lines[i++], '---');
  const name = /^- name: (.+)$/.exec(lines[i++]);
  const hosts = /^ {2}hosts: (.+)$/.exec(lines[i++]);
  assert.ok(name && hosts, `name/hosts lines malformed:\n${doc}`);
  assert.equal(lines[i++], '  gather_facts: false');
  if (become) assert.equal(lines[i++], '  become: true');
  assert.equal(lines[i++], '  tasks:');
  const taskName = /^ {4}- name: (.+)$/.exec(lines[i++]);
  const moduleKey = /^ {6}(.+):$/.exec(lines[i++]);
  assert.ok(taskName && moduleKey, `task lines malformed:\n${doc}`);
  const args = lines.slice(i).map((line) => {
    // Key and value are each one scalar: quoted, or a plain word.
    const m = /^ {8}("(?:[^"\\]|\\.)*"|[^\s:"]+): (.+)$/.exec(line);
    assert.ok(m, `argument line malformed: ${JSON.stringify(line)}`);
    return [decodeScalar(m[1]), decodeScalar(m[2])];
  });
  return {
    name: decodeScalar(name[1]),
    hosts: decodeScalar(hosts[1]),
    taskName: decodeScalar(taskName[1]),
    module: decodeScalar(moduleKey[1]),
    args,
  };
}

test('a hostile target cannot add keys or tasks to the saved playbook', () => {
  for (const target of HOSTILE.filter(Boolean)) {
    const doc = renderAdhocAsPlaybook({
      target,
      module: 'ansible.builtin.command',
      args: { cmd: 'cat /etc/motd' },
      become: false,
    });
    const play = playShape(doc, { become: false, argCount: 1 });
    assert.equal(play.hosts, target);
    assert.equal(play.name, `ansible.builtin.command on ${target}`);
    assert.equal(play.module, 'ansible.builtin.command');
    assert.deepEqual(play.args, [['cmd', 'cat /etc/motd']]);
  }
});

test('module and argument names are quoted like values', () => {
  const module = 'x:\n  become: true\n  y';
  const args = { 'k: v\n        injected': 'value', plain_key: 'a: b' };
  const doc = renderAdhocAsPlaybook({ target: 'all', module, args, become: true });
  const play = playShape(doc, { become: true, argCount: 2 });
  assert.equal(play.module, module);
  assert.equal(play.taskName, `run ${module}`);
  assert.deepEqual(play.args, Object.entries(args));
});

test('an ordinary ad-hoc run renders as before, apart from the quoted names', () => {
  const doc = renderAdhocAsPlaybook({
    target: 'webservers',
    module: 'ansible.builtin.ping',
    args: { data: 'pong', empty: '' },
    become: false,
  });
  assert.equal(doc, [
    '---',
    '- name: "ansible.builtin.ping on webservers"',
    '  hosts: webservers',
    '  gather_facts: false',
    '  tasks:',
    '    - name: "run ansible.builtin.ping"',
    '      ansible.builtin.ping:',
    '        data: pong',
    '',
  ].join('\n'));
  assert.match(renderAdhocAsPlaybook({ target: '', module: 'm', args: {} }), /^ {2}hosts: all$/m);
});

// ---- Retry failed ----

const INVENTORY = {
  hosts: [
    { id: 'h1', name: 'web1', groups: ['web'] },
    { id: 'h2', name: 'web2', groups: ['web'] },
    { id: 'h3', name: 'db1', groups: ['db'] },
    { id: 'h4', name: 'cache1', groups: ['cache'] },
  ],
  groups: [
    { id: 'all', name: 'all', parent: null },
    { id: 'prod', name: 'prod', parent: 'all' },
    { id: 'web', name: 'web', parent: 'prod' },
    { id: 'db', name: 'db', parent: 'prod' },
    { id: 'cache', name: 'cache', parent: 'all' },
  ],
};

const fail = (host) => ({ type: 'fail', host, text: `fatal: [${host}]: FAILED!` });
const adhocRun = (target, hosts) => ({ kind: 'adhoc', status: 'err', target, module: 'ansible.builtin.command', args: { cmd: 'cat /etc/motd' }, log: hosts.map(fail) });
const playbookRun = (limit, hosts) => ({ kind: 'playbook', status: 'err', playbook: 'site.yml', limit, log: hosts.map(fail) });

test('retry keeps real failed hosts of the original target', () => {
  assert.deepEqual(plain(retryHosts(adhocRun('web', ['web2', 'web1']), INVENTORY)), ['web2', 'web1']);
  assert.deepEqual(plain(retryHosts(adhocRun('prod', ['db1']), INVENTORY)), ['db1']);
  assert.deepEqual(plain(retryHosts(adhocRun('web1,db1', ['db1']), INVENTORY)), ['db1']);
  assert.deepEqual(plain(retryHosts(adhocRun('all', ['cache1']), INVENTORY)), ['cache1']);
  assert.equal(retryBlocked(adhocRun('web', ['web1']), INVENTORY), '');
});

test('a group name, "all" or an unknown name in the output is never a retry target', () => {
  // One line of output from web1 used to turn the retry into a run on `all`.
  for (const injected of ['all', 'web', 'prod', 'db', 'all:!web1', 'web*', 'nosuchhost', '*']) {
    const run = adhocRun('web1', [injected]);
    assert.deepEqual(plain(retryHosts(run, INVENTORY)), [], injected);
    assert.match(retryBlocked(run, INVENTORY), /None of the failed hosts/, injected);
  }
});

test('a real host outside the original target is not added by its name appearing in output', () => {
  assert.deepEqual(plain(retryHosts(adhocRun('web1', ['db1', 'web1']), INVENTORY)), ['web1']);
  assert.deepEqual(plain(retryHosts(adhocRun('web', ['cache1']), INVENTORY)), []);
  // Playbook runs: the recorded --limit is the scope.
  assert.deepEqual(plain(retryHosts(playbookRun('web', ['web1', 'db1']), INVENTORY)), ['web1']);
  // No --limit recorded: any inventory host the output names, never a group.
  assert.deepEqual(plain(retryHosts(playbookRun('', ['db1', 'all', 'web']), INVENTORY)), ['db1']);
});

test('a scope with pattern operators falls back to the inventory check alone', () => {
  assert.deepEqual(plain(retryHosts(adhocRun('all:!db', ['web1', 'all']), INVENTORY)), ['web1']);
  assert.deepEqual(plain(retryHosts(playbookRun('web[1:2]', ['web2', 'prod']), INVENTORY)), ['web2']);
});

// An inventory host can be named by an IPv6 address. Its colons are
// part of the name, not pattern separators.
const V6 = '2001:db8::1';
const INVENTORY_V6 = {
  hosts: [...INVENTORY.hosts, { id: 'h6', name: V6, groups: ['web'] }, { id: 'h7', name: 'fd00::7', groups: ['db'] }],
  groups: INVENTORY.groups,
};

test('a host named by an IPv6 address stays in the retry scope', () => {
  // The recorded target IS the host: the retry must offer it, not drop it.
  assert.deepEqual(plain(retryHosts(adhocRun(V6, [V6]), INVENTORY_V6)), [V6]);
  assert.equal(retryBlocked(adhocRun(V6, [V6]), INVENTORY_V6), '');
  // In a comma-separated list, next to names and groups.
  assert.deepEqual(plain(retryHosts(adhocRun(`web1,${V6},db`, [V6, 'fd00::7', 'web1']), INVENTORY_V6)), [V6, 'fd00::7', 'web1']);
  // Reached through its group.
  assert.deepEqual(plain(retryHosts(adhocRun('web', [V6]), INVENTORY_V6)), [V6]);
  // A playbook run limited to it.
  assert.deepEqual(plain(retryHosts(playbookRun(V6, [V6, 'web1']), INVENTORY_V6)), [V6]);
  assert.equal(buildRetryPrefill(playbookRun(`${V6},web1`, [V6]), INVENTORY_V6).limit, V6);
  // Still scoped: another IPv6 host outside the target is not added.
  assert.deepEqual(plain(retryHosts(adhocRun(V6, ['fd00::7', V6]), INVENTORY_V6)), [V6]);
  assert.deepEqual(plain(retryHosts(adhocRun('db', [V6]), INVENTORY_V6)), []);
});

test('target resolution: commas first, whole piece as a host before splitting on colons', () => {
  const names = (target) => plain(page.AnsbuiResolveTargetHosts(target, INVENTORY_V6.hosts, INVENTORY_V6.groups).map((h) => h.name));
  assert.deepEqual(names(V6), [V6]);
  assert.deepEqual(names(`${V6},fd00::7`), [V6, 'fd00::7']);
  assert.deepEqual(names(`db1, ${V6}`), ['db1', V6]);
  // Colon-separated names and groups still work as before.
  assert.deepEqual(names('web1:db1'), ['web1', 'db1']);
  assert.deepEqual(names('db:cache'), ['db1', 'fd00::7', 'cache1']);
  assert.deepEqual(names('web1,db:cache1'), ['web1', 'db1', 'fd00::7', 'cache1']);
  assert.deepEqual(names('all').length, INVENTORY_V6.hosts.length);
  assert.deepEqual(names(''), []);
  assert.deepEqual(names('nosuch'), []);
});

test('the prefill carries only the hosts that passed', () => {
  const adhoc = buildAdhocRetryPrefill(adhocRun('web', ['all', 'web2', 'db1']), INVENTORY);
  assert.equal(adhoc.target, 'web2');
  assert.equal(adhoc.module, 'ansible.builtin.command');
  const pb = buildRetryPrefill(playbookRun('prod', ['web1', 'cache1', 'prod', 'db1']), INVENTORY);
  assert.equal(pb.limit, 'web1,db1');
});

test('a log with no failed host says so', () => {
  const run = { kind: 'adhoc', target: 'web', log: [{ type: 'line', text: 'hello' }] };
  assert.match(retryBlocked(run, INVENTORY), /names no failed host/);
  assert.match(retryBlocked(null, INVENTORY), /names no failed host/);
  assert.deepEqual(plain(retryHosts(run, null)), []);
});

// ---- the History view itself ----

// mountHistory renders HistoryView for one recorded run and returns
// its "Retry failed" button plus whatever the click handed to the
// ad-hoc composer.
async function mountHistory(detail) {
  const rt = hookRuntime();
  const opened = [];
  const view = createPage({
    React: rt.React,
    Icon: () => null,
    AnsibleData: {
      RUNS: [{ id: detail.id, kind: detail.kind, status: detail.status, target: detail.target, when: 'now' }],
      PLAYBOOKS: [],
      HOSTS: INVENTORY.hosts,
      GROUPS: INVENTORY.groups,
    },
    AnsbuiAPI: {
      refreshRuns: () => Promise.resolve(),
      getRun: () => Promise.resolve(detail),
    },
  });
  view.globalThis = view;
  loadScript(view, 'views/Adhoc.jsx');
  loadScript(view, 'views/History.jsx');
  const mounted = rt.mount(view.HistoryView, { onOpenAdhoc: (prefill) => opened.push(prefill), activeServer: { id: 'srv', name: 'prod' } });
  await new Promise((resolve) => setImmediate(resolve));
  mounted.rerender();
  const [button] = findElements(mounted.tree, (n) => n.type === 'button' && textOf(n).includes('Retry failed'));
  assert.ok(button, 'the Retry failed button is rendered for a failed ad-hoc run');
  return { button, opened };
}

test('History disables Retry failed, with the reason, when the output only names a group', async () => {
  const { button } = await mountHistory({ id: 'r1', ...adhocRun('web1', ['all']) });
  assert.equal(button.props.disabled, true);
  assert.match(button.props.title, /None of the failed hosts/);
});

test('History offers Retry failed for a real failed host and prefills only that host', async () => {
  const { button, opened } = await mountHistory({ id: 'r2', ...adhocRun('web', ['all', 'web2', 'db1']) });
  assert.equal(button.props.disabled, false);
  assert.match(button.props.title, /only the hosts that failed/);
  button.props.onClick();
  assert.equal(opened.length, 1);
  assert.equal(opened[0].target, 'web2');
});
