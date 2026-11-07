'use strict';
// The token lives only in this browser tab's sessionStorage, never cookies or
// HTTP URLs, and the server will only accept authenticated loopback API calls.
const urlToken = new URLSearchParams(window.location.hash.slice(1)).get('token');
if (urlToken) { sessionStorage.setItem('s18_session_token', urlToken); history.replaceState(null, '', '/'); }
const token = sessionStorage.getItem('s18_session_token');
let tracks = [];
let state = null;
let sliderDragging = false;
const $ = id => document.getElementById(id);
const formatTime = secs => {
  const n = Math.max(0, Math.floor(secs || 0));
  return `${Math.floor(n / 60)}:${String(n % 60).padStart(2, '0')}`;
};
const notify = message => {
  const toast = $('toast'); toast.textContent = message; toast.hidden = false;
  setTimeout(() => { if (toast.textContent === message) toast.hidden = true; }, 5000);
};
async function api(path, method = 'GET', payload = null) {
  if (!token) throw new Error('Session token missing. Open the exact local URL printed in your terminal.');
  const options = { method, headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' };
  if (payload !== null) {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Local playback request failed');
  return data;
}
function findCurrent() { return tracks.find(t => state && t.id === state.track_id); }
function drawTracks() {
  const host = $('library-items'); host.replaceChildren();
  $('track-count').textContent = `${tracks.length} LOCAL ${tracks.length === 1 ? 'TRACK' : 'TRACKS'}`;
  tracks.forEach((track, i) => {
    const row = document.createElement('button'); row.type = 'button'; row.className = 'track';
    if (state && state.track_id === track.id) row.classList.add('active');
    const art = document.createElement('span'); art.className = 'track-icon'; art.textContent = ['♫', '◈', '♬'][i % 3];
    const title = document.createElement('span');
    const name = document.createElement('strong'); name.textContent = track.title;
    const artist = document.createElement('small'); artist.textContent = track.artist;
    title.append(name, artist);
    const album = document.createElement('span'); album.className = 'album'; album.textContent = track.album;
    const symbol = document.createElement('span'); symbol.className = 'track-play'; symbol.textContent = '▶';
    row.append(art, title, album, symbol);
    row.addEventListener('click', () => command('/api/play', { track_id: track.id }));
    host.append(row);
  });
  if (!tracks.length) { const e = document.createElement('p'); e.className = 'empty'; e.textContent = 'No imported tracks yet'; host.append(e); }
}
function render(newState) {
  const previousId = state && state.track_id;
  state = newState;
  const current = findCurrent();
  $('now-title').textContent = current ? current.title : 'Nothing selected';
  $('now-artist').textContent = current ? current.artist : 'Choose a track from your library';
  $('backend').textContent = `${(state.audio_backend || 'null').toUpperCase()} OUTPUT`;
  $('playback-state').textContent = state.state.toUpperCase();
  $('playback-state').style.color = state.state === 'error' ? '#ffaca6' : '#99f1b2';
  const active = ['playing', 'paused'].includes(state.state);
  $('playpause').textContent = state.state === 'playing' ? 'Ⅱ' : '▶';
  $('playpause').disabled = !current || state.state === 'loading';
  $('stop').disabled = !current || !['playing', 'paused', 'loading'].includes(state.state);
  const total = state.total_frames || 0;
  $('rewind').disabled = $('forward').disabled = $('seek').disabled = !total || state.state === 'loading';
  $('elapsed').textContent = formatTime(state.sample_rate ? state.position_frames / state.sample_rate : 0);
  $('duration').textContent = formatTime(state.sample_rate ? total / state.sample_rate : 0);
  if (!sliderDragging) $('seek').value = total ? Math.min(1000, Math.round(state.position_frames * 1000 / total)) : 0;
  if (current && current.id !== previousId) drawTracks();
  if (state.state === 'error' && state.error) notify(state.error);
}
async function command(path, data = {}) {
  try { render(await api(path, 'POST', data)); }
  catch (e) { notify(e.message); }
}
$('playpause').addEventListener('click', () => {
  if (!state || !state.track_id) return;
  if (state.state === 'playing') command('/api/pause');
  else if (state.state === 'paused') command('/api/resume');
  else command('/api/play', { track_id: state.track_id });
});
$('stop').addEventListener('click', () => command('/api/stop'));
const seekBy = delta => {
  if (!state || !state.total_frames || !state.sample_rate) return;
  const frame = Math.max(0, Math.min(state.total_frames - 1, state.position_frames + delta * state.sample_rate));
  command('/api/seek', { frame });
};
$('rewind').addEventListener('click', () => seekBy(-10));
$('forward').addEventListener('click', () => seekBy(10));
$('seek').addEventListener('pointerdown', () => { sliderDragging = true; });
$('seek').addEventListener('change', () => {
  sliderDragging = false;
  if (!state || !state.total_frames) return;
  command('/api/seek', { frame: Math.min(state.total_frames - 1, Math.floor(Number($('seek').value) * state.total_frames / 1000)) });
});
window.addEventListener('keydown', e => {
  if (e.code === 'Space' && !['INPUT', 'TEXTAREA', 'BUTTON'].includes(document.activeElement.tagName)) {
    e.preventDefault(); $('playpause').click();
  }
});
async function poll() {
  try { render(await api('/api/state')); }
  catch (e) { if (!state) notify(e.message); }
}
async function init() {
  try {
    const data = await api('/api/library');
    tracks = data.tracks;
    drawTracks();
    render(await api('/api/state'));
  } catch (e) { notify(e.message); }
  setInterval(poll, 300);
}
init();
