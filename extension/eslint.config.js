// Just one rule: `curly`.
//
// This extension's code is written dense, several statements per line.
// An `if(cond)return;suite();` is correct today, but a statement
// added right after it will run outside the `if` with no signal
// saying so (SonarQube javascript:S2681). Braces close off that risk.
//
// No preset, no formatter: a global reformat over authority, masking
// and signature-verification code would make review impossible.
//
// detection-factory.js is regenerated from detection-factory.json by
// build-editions.js; fixing it here would be overwritten on the next build.
export default [
  {
    ignores: ['detection-factory.js', 'node_modules/**'],
  },
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
    },
    rules: {
      curly: ['error', 'all'],
    },
  },
];
