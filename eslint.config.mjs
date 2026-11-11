// The console is bundled browser JavaScript; no Node modules ship with the service.
export default [
  {
    files: ['src/http/docs.js', 'eslint.config.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        document: 'readonly',
        fetch: 'readonly',
        URLSearchParams: 'readonly',
        TextDecoder: 'readonly',
      },
    },
    rules: {
      eqeqeq: 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-undef': 'error',
      'no-unused-vars': 'error',
      'prefer-const': 'error',
    },
  },
];
