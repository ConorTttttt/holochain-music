'use strict';
// Static design preview only. No API requests, playback handlers or storage.
const theme = document.getElementById('preview-theme');
const modes = new Set(['system', 'light', 'dark', 'amethyst-light', 'amethyst-night']);
theme.addEventListener('change', () => {
  const mode = modes.has(theme.value) ? theme.value : 'system';
  if (mode === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', mode);
});

// Preview only: local file selection creates a temporary object URL, no API calls.
const artworkInput = document.getElementById('preview-artwork-file');
const artworkImage = document.getElementById('now-art-image');
const artworkStatus = document.getElementById('preview-artwork-status');
let previewArtworkUrl = null;
artworkInput.addEventListener('change', () => {
  if (previewArtworkUrl) URL.revokeObjectURL(previewArtworkUrl);
  previewArtworkUrl = null;
  artworkImage.removeAttribute('src');
  artworkImage.hidden = true;
  const file = artworkInput.files && artworkInput.files[0];
  if (!file) {
    artworkStatus.textContent = 'Select a local PNG file to preview the artwork slot.';
  } else if (file.type !== 'image/png' || file.size > 768 * 1024) {
    artworkStatus.textContent = 'Choose a PNG cover below 768 KiB.';
  } else {
    previewArtworkUrl = URL.createObjectURL(file);
    artworkImage.src = previewArtworkUrl;
    artworkImage.hidden = false;
    artworkStatus.textContent = 'Your local cover is shown in the player sample. It has not been published.';
  }
});
window.addEventListener('pagehide', () => {
  if (previewArtworkUrl) URL.revokeObjectURL(previewArtworkUrl);
});
