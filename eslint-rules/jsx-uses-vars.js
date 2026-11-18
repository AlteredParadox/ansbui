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

// Counts a component tag as a use of the variable it names, so
// `no-unused-vars` does not report every component that is only
// referenced from JSX.
//
// This is the one rule we needed from eslint-plugin-react
// (`react/jsx-uses-vars`). It lives here because that plugin's latest
// release does not support ESLint 10, and a small rule is cheaper than
// a dependency we would be pinned behind. The cases mirror upstream:
//
//   <Component />     marks `Component`
//   <ns.Component />  marks `ns` (the root object, whatever its case)
//   <div />           marks nothing: a lowercase tag is an intrinsic
//                     element, not a reference to a binding, so a local
//                     that happens to be called `div` stays reportable
//   <svg:rect />      marks nothing: namespaced names are intrinsic too

const INTRINSIC_TAG = /^[a-z]/;

export default {
  meta: { type: 'problem', schema: [] },
  create(context) {
    return {
      JSXOpeningElement(node) {
        let name = node.name;
        if (name.type === 'JSXIdentifier') {
          if (INTRINSIC_TAG.test(name.name)) return;
        } else if (name.type === 'JSXMemberExpression') {
          while (name.type === 'JSXMemberExpression') name = name.object;
        } else {
          return;
        }
        if (name.type === 'JSXIdentifier') {
          context.sourceCode.markVariableAsUsed(name.name, node);
        }
      },
    };
  },
};
