'use strict';
// Standalone typography preview: no Holochain backend, auth token or storage.
const theme = document.getElementById('preview-theme');
const allowed = new Set(['system', 'light', 'dark', 'amethyst-light', 'amethyst-night']);
theme.addEventListener('change', () => {
  const value = allowed.has(theme.value) ? theme.value : 'system';
  if (value === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', value);
});
