// Accessible names: what a screen reader announces for the graphics and
// the icon-only controls under web/.
//
// The first test reads every .jsx file as written and enforces two rules
// across the whole app. The rest run the chart and map components and
// check the names they produce.

import assert from 'node:assert/strict';
import test from 'node:test';

import { traverse } from '@babel/core';

import { createPage, jsxFiles, loadScript, parseScript, plain, reactStub } from './browser-script.js';

// ------------------------------------------------------------ static rules

const tagName = (el) => {
  const n = el.openingElement.name;
  return n.type === 'JSXIdentifier' ? n.name : '(member)';
};
const attributes = (el) =>
  new Map(el.openingElement.attributes.filter((a) => a.type === 'JSXAttribute').map((a) => [a.name.name, a.value]));
const hasName = (attrs) => attrs.has('aria-label') || attrs.has('aria-labelledby') || attrs.has('title');

// Could this node put text in front of the user? Deliberately generous:
// anything that is not plainly a drawing counts as text, so the rule
// below only fires on a control that certainly has none.
function rendersText(node) {
  switch (node.type) {
    case 'JSXText':
      return node.value.trim() !== '';
    case 'JSXFragment':
      return node.children.some(rendersText);
    case 'JSXElement': {
      const tag = tagName(node);
      if (tag === 'Icon' || tag === 'svg') return false;
      if (/^[a-z]/.test(tag)) return node.children.some(rendersText);
      return true; // some other component
    }
    case 'JSXExpressionContainer':
      return expressionRendersText(node.expression);
    default:
      return true;
  }
}

function expressionRendersText(e) {
  switch (e.type) {
    case 'JSXEmptyExpression':
      return false;
    case 'JSXElement':
    case 'JSXFragment':
      return rendersText(e);
    case 'LogicalExpression':
      return expressionRendersText(e.right);
    case 'ConditionalExpression':
      return expressionRendersText(e.consequent) || expressionRendersText(e.alternate);
    default:
      return true; // a variable, a call, a string
  }
}

// The problems in one file, as "file:line message" strings.
function problemsIn(relPath) {
  const problems = [];
  traverse(parseScript(relPath), {
    JSXElement(path) {
      const el = path.node;
      const tag = tagName(el);
      const attrs = attributes(el);
      const where = `${relPath}:${el.loc.start.line}`;

      const isControl = tag === 'button' || tag === 'a' || attrs.get('role')?.value === 'button';
      if (isControl && !hasName(attrs) && !el.children.some(rendersText)) {
        problems.push(`${where} <${tag}> shows no text and has no aria-label`);
      }

      if (tag === 'svg' && !hasName(attrs) && !attrs.has('aria-hidden')) {
        const hiddenAbove = path.findParent((p) => p.isJSXElement() && attributes(p.node).has('aria-hidden'));
        if (!hiddenAbove) problems.push(`${where} <svg> has neither a name nor aria-hidden`);
      }
    },
  });
  return problems;
}

test('every control has a name and every svg is named or hidden', () => {
  const files = jsxFiles();
  assert.ok(files.length >= 10, `only ${files.length} .jsx files found`);
  assert.deepEqual(files.flatMap(problemsIn), []);
});

// ------------------------------------------------------------------- icons

test('Icon is hidden from assistive technology', () => {
  const page = createPage();
  loadScript(page, 'components/Icon.jsx');
  for (const name of ['x', 'search', 'no-such-icon']) {
    const svg = plain(page.Icon({ name }));
    assert.equal(svg.type, 'svg');
    assert.equal(svg.props['aria-hidden'], 'true', name);
  }
});

// --------------------------------------------------------------- dashboard

const dashboard = createPage();
loadScript(dashboard, 'views/Dashboard.jsx');

test('the status donut is one image named with the three counts', () => {
  const svg = plain(dashboard.DonutStatus({ ok: 7, warn: 2, err: 1 }));
  assert.equal(svg.props.role, 'img');
  assert.equal(svg.props['aria-label'], 'Host status: 7 reachable, 2 degraded, 1 unreachable');
});

test('the sparkline is an image when labelled and hidden when not', () => {
  const labelled = plain(dashboard.Sparkline({ data: [1, 2, 3], label: 'Runs' }));
  assert.equal(labelled.props.role, 'img');
  assert.equal(labelled.props['aria-label'], 'Runs');
  assert.equal(labelled.props['aria-hidden'], undefined);

  const bare = plain(dashboard.Sparkline({ data: [1, 2, 3] }));
  assert.equal(bare.props.role, undefined);
  assert.equal(bare.props['aria-label'], undefined);
  assert.equal(bare.props['aria-hidden'], 'true');
});

test('activityLabel describes the run series in words', () => {
  const { activityLabel } = dashboard;
  assert.equal(activityLabel([]), '');
  assert.equal(activityLabel([0, 0, 0]), 'Runs per day over the last 3 days: none');
  assert.equal(activityLabel([4]), 'Runs per day over the last 1 day: 4 in total, 4 on the busiest day, 4 today');
  assert.equal(
    activityLabel([0, 5, 1, 2]),
    'Runs per day over the last 4 days: 8 in total, 5 on the busiest day, 2 today',
  );
});

// --------------------------------------------------------------- inventory

// InventoryGraph calls useMemo; computing the value directly is enough.
const inventory = createPage({ React: { ...reactStub(), useMemo: (compute) => compute() } });
loadScript(inventory, 'views/Inventory.jsx');

// All elements in a rendered tree, depth first. Children arrive nested
// (arrays from .map, null from conditions), so flatten as we go.
function* elements(node) {
  if (Array.isArray(node)) {
    for (const child of node) yield* elements(child);
  } else if (node && typeof node === 'object') {
    yield node;
    yield* elements(node.children);
  }
}
const withClass = (tree, cls) => [...elements(tree)].filter((el) => el.props?.className === cls);

const HOSTS = [
  { id: 'h1', name: 'web-1', status: 'ok', groups: ['web'], region: 'Hesse, DE' },
  { id: 'h2', name: 'web-2', status: 'warn', groups: ['web'], region: 'Bavaria, DE' },
  { id: 'h3', name: 'db-1', status: 'err', groups: ['db'], region: 'Uusimaa, FI' },
  { id: 'h4', name: 'lost-1', status: 'ok', groups: [], region: '' },
];
const GROUPS = [
  { id: 'all', name: 'all' },
  { id: 'prod', name: 'prod', parent: 'all' },
  { id: 'web', name: 'web', parent: 'prod' },
  { id: 'db', name: 'db', parent: 'prod' },
];

test('the inventory graph is a named group whose nodes are named buttons', () => {
  const tree = plain(inventory.InventoryGraph({ groups: GROUPS, hosts: HOSTS, onSelectGroup() {} }));
  const [svg] = [...elements(tree)].filter((el) => el.type === 'svg');
  // Not role="img": that would hide the buttons inside it.
  assert.equal(svg.props.role, 'group');
  assert.equal(svg.props['aria-label'], 'Inventory graph: groups and their hosts');

  const nodes = withClass(tree, 'graph-node');
  assert.deepEqual(
    nodes.map((n) => [n.props.role, n.props.tabIndex, n.props['aria-label']]),
    [
      ['button', 0, 'Group all, 0 hosts'],
      ['button', 0, 'Group prod, 0 hosts'],
      ['button', 0, 'Group web, 2 hosts'],
      ['button', 0, 'Group db, 1 host'],
    ],
  );

  // Host dots say their status in words, not only by colour.
  const titles = [...elements(tree)].filter((el) => el.type === 'title').map((el) => el.children.join(''));
  assert.deepEqual(titles, ['web-1 (reachable)', 'web-2 (degraded)', 'db-1 (unreachable)']);
});

test('each country on the map is one image with its counts in words', () => {
  const tree = plain(inventory.InventoryMap({ hosts: HOSTS }));
  const [svg] = [...elements(tree)].filter((el) => el.type === 'svg');
  assert.equal(svg.props.role, 'group');
  assert.equal(svg.props['aria-label'], 'Hosts by country');

  assert.deepEqual(
    withClass(tree, 'map-region').map((g) => [g.props.role, g.props['aria-label']]),
    [
      ['img', 'Germany: 2 hosts, 1 reachable, 1 degraded, 0 unreachable'],
      ['img', 'Finland: 1 host, 0 reachable, 0 degraded, 1 unreachable'],
    ],
  );

  // The dotted land masses are backdrop.
  const backdrop = svg.children.flat().find((el) => el?.type === 'g' && el.props.opacity === '0.35');
  assert.equal(backdrop.props['aria-hidden'], 'true');
});
