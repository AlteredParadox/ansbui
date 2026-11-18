// Loads the browser scripts under web/ into a Node `vm` context so their
// plain functions can be unit-tested (`npm test`).
//
// web/ has no bundler and no modules: index.html loads each file as a
// classic <script> (JSX through Babel in the browser) and the files talk
// through globals. This does the same thing: one context plays the page,
// each script runs in it in turn, and top-level functions end up on the
// context object, as they would on `window`.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

import { parseSync, transformSync } from '@babel/core';
import presetReact from '@babel/preset-react';

const webRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'web');

// A stand-in for React that records what would be rendered. Elements
// become plain `{ type, props, children }` objects a test can inspect.
// Hooks are deliberately absent: only functions that do not call them can
// be exercised this way. A test that needs a hook passes its own stand-in
// through `createPage({ React: { ...reactStub(), useMemo: (f) => f() } })`.
export function reactStub() {
  return {
    Fragment: 'Fragment',
    createElement(type, props, ...children) {
      return { type, props: props ?? {}, children };
    },
  };
}

// A hook runtime for running ONE function component: its body, its
// state and its effects. Children are recorded as elements (see
// reactStub) and not rendered, so this exercises a component's own
// logic — which state it ends up in, what it hands its children — and
// nothing below it.
//
//   const rt = hookRuntime();
//   const page = createPage({ React: rt.React });
//   loadScript(page, 'views/Some.jsx');
//   const view = rt.mount(page.SomeView, props);
//   view.tree            // the element tree of the settled render
//   view.update(props)   // new props, re-render until settled
//   view.rerender()      // after calling a handler that set state
//   view.unmount()       // run effect cleanups
//
// Effects run synchronously after each render pass, and a pass that
// sets state is followed by another, until nothing changes. Promises
// are not awaited: give the component data that needs no fetch.
export function hookRuntime() {
  let current = null;
  const same = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  const cell = (make) => {
    const inst = current;
    const k = inst.next++;
    if (!(k in inst.cells)) inst.cells[k] = make();
    return [inst, k, inst.cells[k]];
  };
  const React = {
    ...reactStub(),
    useState(initial) {
      const [inst, , c] = cell(() => ({ value: typeof initial === 'function' ? initial() : initial }));
      const set = (next) => {
        const value = typeof next === 'function' ? next(c.value) : next;
        if (!Object.is(value, c.value)) {
          c.value = value;
          inst.dirty = true;
        }
      };
      return [c.value, set];
    },
    useRef(initial) {
      return cell(() => ({ current: initial }))[2];
    },
    useMemo(compute, deps) {
      const [inst, k, c] = cell(() => ({ deps, value: compute() }));
      if (!same(c.deps, deps)) inst.cells[k] = { deps, value: compute() };
      return inst.cells[k].value;
    },
    useCallback(fn, deps) {
      return React.useMemo(() => fn, deps);
    },
    useEffect(effect, deps) {
      const [inst, k, c] = cell(() => ({ deps: null, cleanup: undefined, fresh: true }));
      if (!c.fresh && same(c.deps, deps)) return;
      inst.effects.push(() => {
        c.cleanup?.();
        const cleanup = effect();
        inst.cells[k] = { deps, cleanup: typeof cleanup === 'function' ? cleanup : undefined, fresh: false };
      });
    },
  };
  function mount(Component, props) {
    const inst = { cells: [], next: 0, effects: [], dirty: false, props, tree: null };
    const render = () => {
      for (let pass = 0; pass < 50; pass++) {
        inst.dirty = false;
        inst.next = 0;
        inst.effects = [];
        current = inst;
        try {
          inst.tree = Component(inst.props);
        } finally {
          current = null;
        }
        for (const run of inst.effects) run();
        if (!inst.dirty) return;
      }
      throw new Error('component did not settle after 50 render passes');
    };
    render();
    return {
      get tree() {
        return inst.tree;
      },
      update(next) {
        inst.props = { ...inst.props, ...next };
        render();
      },
      rerender: render,
      unmount() {
        for (const c of inst.cells) c?.cleanup?.();
      },
    };
  }
  return { React, mount };
}

// Every element in a recorded tree (see reactStub) for which `test`
// returns true, depth first.
export function findElements(tree, test) {
  const found = [];
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== 'object') return;
    if (test(node)) found.push(node);
    walk(node.children);
  };
  walk(tree);
  return found;
}

// The text inside a recorded element: its string and number children,
// joined.
export function textOf(node) {
  if (Array.isArray(node)) return node.map(textOf).join('');
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (!node || typeof node !== 'object') return '';
  return textOf(node.children);
}

// Returns a fresh page-like context. `globals` are added to it before any
// script runs (a `fetch` stub, for instance), and may replace `React`.
export function createPage(globals = {}) {
  return vm.createContext({ React: reactStub(), ...globals });
}

const babelOptions = (file) => ({
  filename: file,
  sourceType: 'script',
  babelrc: false,
  configFile: false,
  presets: [[presetReact, { runtime: 'classic' }]],
});

// Runs web/<relPath> in the page, compiling JSX first.
export function loadScript(page, relPath) {
  const file = path.join(webRoot, relPath);
  let code = fs.readFileSync(file, 'utf8');
  if (relPath.endsWith('.jsx')) code = transformSync(code, babelOptions(file)).code;
  vm.runInContext(code, page, { filename: file });
}

// Every .jsx file under web/ (the vendored libraries excluded), as paths
// relative to web/.
export function jsxFiles() {
  return fs
    .readdirSync(webRoot, { recursive: true })
    .map((p) => p.split(path.sep).join('/'))
    .filter((p) => p.endsWith('.jsx') && !p.startsWith('vendor/'))
    .sort();
}

// Parses web/<relPath> and returns its Babel AST, for tests that check
// the markup as written rather than run it.
export function parseScript(relPath) {
  const file = path.join(webRoot, relPath);
  return parseSync(fs.readFileSync(file, 'utf8'), babelOptions(file));
}

// Evaluates an expression in the page. Top-level `const`s of a script are
// not properties of the context object, but they are in scope here, the
// same way a later <script> can see them.
export function evaluate(page, expression) {
  return vm.runInContext(expression, page);
}

// Values created inside the page have that realm's prototypes, which
// `assert.deepStrictEqual` treats as different from ours. Copy to plain
// local data before comparing.
export function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

// Fails if `fn` takes longer than `limitMs`. Used with inputs sized so a
// linear algorithm finishes in a few milliseconds and a quadratic one
// needs many seconds; the limit sits far from both.
export function assertFast(assert, label, fn, limitMs = 1500) {
  const start = performance.now();
  fn();
  const ms = performance.now() - start;
  assert.ok(ms < limitMs, `${label}: took ${Math.round(ms)} ms, limit ${limitMs} ms`);
}

// Every string over `alphabet` up to `maxLength` characters, shortest
// first. Small alphabets only: the count is alphabet.length ** maxLength.
export function* stringsOver(alphabet, maxLength) {
  let layer = [''];
  yield '';
  for (let len = 1; len <= maxLength; len++) {
    const next = [];
    for (const prefix of layer) {
      for (const ch of alphabet) {
        const s = prefix + ch;
        next.push(s);
        yield s;
      }
    }
    layer = next;
  }
}
