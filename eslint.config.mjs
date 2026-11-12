// The console is bundled browser JavaScript; no Node modules ship with the service.
export default [
  {
    files: ['src/http/docs.js', 'src/http/oauth-implicit.js', 'eslint.config.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        document: 'readonly',
        window: 'readonly',
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
