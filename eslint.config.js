// Flat-config ESLint for ansbui's frontend.
//
// The frontend ships as plain <script> tags loaded by index.html and
// transformed in-browser by Babel — there is no bundler, no module
// graph, and a lot of cross-file globals (React, Icon, AnsbuiAPI,
// AnsbuiSettings, AnsibleData, useDialog, dialogBackdropHandlers,
// view-component constructors, etc.). With `no-undef` on, every JSX
// file would light up. We turn it off and rely on Sonar / runtime
// for "did you typo a global?" catches; ESLint here is for syntax,
// obvious bugs, and basic stylistic hygiene.

import babelParser from '@babel/eslint-parser';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactPlugin from 'eslint-plugin-react';

export default [
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      // Vendored third-party runtime (React/ReactDOM/Babel) served
      // from the embedded bundle — minified upstream artifacts, not
      // ours to lint.
      'web/vendor/**',
    ],
  },
  {
    files: ['web/**/*.{js,jsx}'],
    plugins: {
      'react-hooks': reactHooks,
      react: reactPlugin,
    },
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          presets: ['@babel/preset-env', '@babel/preset-react'],
        },
        ecmaVersion: 'latest',
        // Each file is a top-level <script>, not an ES module —
        // sourceType:script avoids "import/export only allowed in
        // module" false positives across the bundle.
        sourceType: 'script',
        ecmaFeatures: { jsx: true },
      },
      globals: {
        ...globals.browser,
        React: 'readonly',
        ReactDOM: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-undef': 'off',
      eqeqeq: ['error', 'smart'],
      'no-var': 'error',
      'prefer-const': 'warn',
      'no-debugger': 'warn',
      'no-dupe-keys': 'error',
      'no-dupe-args': 'error',
      'no-unreachable': 'error',
      'no-constant-condition': ['error', { checkLoops: false }],
      // React Hooks correctness — exhaustive-deps stays as a warn
      // because the existing codebase has eslint-disable comments
      // on a few legitimate "intentionally non-exhaustive" effects
      // (mount-only re-attach probes etc.). Promote to error if
      // those get cleaned up.
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      // Without jsx-uses-vars, every top-level component in a JSX
      // file lights up as "defined but never used" because eslint
      // doesn't see <Component/> tags as a use. The frontend ships
      // each .jsx as a top-level <script>, so component refs cross
      // files via globals — this rule suppresses the false-positive
      // unused-vars by counting JSX-tag references as usage.
      'react/jsx-uses-vars': 'error',
      'react/jsx-uses-react': 'error',
    },
  },
];
