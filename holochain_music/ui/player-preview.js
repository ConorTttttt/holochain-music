'use strict';
// Static design preview only. No API requests, playback handlers or storage.
const theme = document.getElementById('preview-theme');
const modes = new Set(['system', 'light', 'dark', 'amethyst-light', 'amethyst-night']);
theme.addEventListener('change', () => {
  const mode = modes.has(theme.value) ? theme.value : 'system';
  if (mode === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', mode);
});
