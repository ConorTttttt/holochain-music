'use strict';
// Loopback UI. The token lives only in this tab's sessionStorage and is sent
// in the Authorization header; it is removed from the visible URL at once.
// All remote/catalogue text is inserted with textContent, never as HTML.
const urlToken = new URLSearchParams(location.hash.slice(1)).get('token');
if (urlToken) { sessionStorage.setItem('hm_token', urlToken); history.replaceState(null, '', '/'); }
const token = sessionStorage.getItem('hm_token');

// UI-only preference: no key material, permissions, network config or audio state.
// Leaving data-theme unset makes CSS follow the OS, including live OS changes.
const APPEARANCE_KEY = 'holochain_music_appearance';
const APPEARANCE_MODES = new Set(['system', 'light', 'dark', 'amethyst-night', 'amethyst-light']);
function getAppearance() {
  try { const value = localStorage.getItem(APPEARANCE_KEY); return APPEARANCE_MODES.has(value) ? value : 'system'; }
  catch (_) { return 'system'; }
}
function setAppearance(value) {
  const mode = APPEARANCE_MODES.has(value) ? value : 'system';
  if (mode === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', mode);
  try { localStorage.setItem(APPEARANCE_KEY, mode); } catch (_) { /* private browsing or blocked storage */ }
  return mode;
}
setAppearance(getAppearance());

const $ = id => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids) if (kid !== null && kid !== undefined) n.append(kid);
  return n;
};
const fmt = ms => { const s = Math.max(0, Math.floor((ms || 0) / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };

let state = { player: null, online: false, agent: null, queue: [] };
let library = [];
let libraryById = new Map();
let view = 'browse';
let viewArg = null;
let dragging = false;

function toast(message, kind = 'error') {
  const t = $('toast'); t.textContent = message; t.className = `toast ${kind === 'info' ? 'info' : ''}`; t.hidden = false;
  clearTimeout(toast.timer); toast.timer = setTimeout(() => { t.hidden = true; }, 6000);
}

async function api(path, body) {
  if (!token) throw new Error('Session token missing. Open the exact private link printed by holochain-music.');
  const opts = { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${token}` }, cache: 'no-store' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
async function act(path, body = {}, okMessage) {
  try { const r = await api(path, body); if (okMessage) toast(okMessage, 'info'); await refreshLibrary(); return r; }
  catch (e) { toast(e.message); return null; }
}

// ---- status helpers --------------------------------------------------
function accessBadge(item) {
  if (!item) return el('span', { class: 'badge', text: 'Not in library' });
  if (item.download && ['downloading', 'retrying'].includes(item.download.state)) {
    const pct = Math.round(100 * item.download.available_chunks / Math.max(1, item.download.total_chunks));
    return el('span', { class: 'badge warn', text: `Downloading ${pct}%` });
  }
  if (item.download && item.download.state === 'unavailable') return el('span', { class: 'badge bad', text: 'Unavailable' });
  if (item.offline_ready) return el('span', { class: 'badge ok', text: 'Offline ready' });
  if (item.playable && item.grant_kind === 'perpetual-personal') return el('span', { class: 'badge ok', text: 'Licensed · streaming' });
  if (item.playable) return el('span', { class: 'badge ok', text: `Streaming access until ${new Date(item.grant_expires_at * 1000).toLocaleString()}` });
  if (item.grant_kind === 'stream') return el('span', { class: 'badge bad', text: 'Access expired' });
  if (item.requested && item.request_queued) return el('span', { class: 'badge warn', text: 'Request waiting for the artist to come online' });
  if (item.requested) return el('span', { class: 'badge warn', text: 'Access requested' });
  return el('span', { class: 'badge', text: 'No access' });
}

function trackActions(fileId, catalogueRow) {
  const item = libraryById.get(fileId);
  const box = el('div', { class: 'actions' });
  if (item && item.playable) {
    box.append(el('button', { class: 'btn primary', type: 'button', 'aria-label': `Play ${item.title}`, text: 'Play',
      onclick: () => act('/api/play', { file_id: fileId }) }));
    box.append(el('button', { class: 'btn', type: 'button', text: 'Queue', 'aria-label': `Add ${item.title} to queue`,
      onclick: () => act('/api/queue', { items: [...state.queue, fileId] }, 'Added to queue') }));
    if (!item.complete) box.append(el('button', { class: 'btn', type: 'button', text: 'Download',
      onclick: () => act('/api/download', { file_id: fileId }, 'Download started') }));
    if (item.offline_ready) box.append(el('button', { class: 'btn', type: 'button', text: 'Export WAV', onclick: () => exportWav(item) }));
    box.append(el('button', { class: 'btn', type: 'button', text: '+ Playlist', onclick: () => addToPlaylist(fileId) }));
  } else if (catalogueRow && catalogueRow.artist_agent !== state.agent) {
    const request = async kind => {
      const r = await act('/api/access/request', { track_key: catalogueRow.key, kind });
      if (r) toast(r.queued ? 'The artist is offline. Your private request will be delivered automatically when they are back (up to 7 days, while this app runs).' : 'Private request sent to the artist', 'info');
      render();
    };
    box.append(el('button', { class: 'btn', type: 'button', text: 'Request streaming', onclick: () => request('stream') }));
    box.append(el('button', { class: 'btn primary', type: 'button', text: 'Request licence', onclick: () => request('perpetual-personal') }));
  }
  return box;
}

function trackRow(t, fileId, catalogueRow) {
  const item = libraryById.get(fileId);
  const active = state.player && state.player.track_key === fileId;
  return el('div', { class: `row${active ? ' active' : ''}` },
    el('div', { class: 'title' }, el('strong', { text: t.title || 'Untitled' }),
      el('span', {}, catalogueRow ? el('a', { href: '#', text: t.artist_name || 'Unknown artist',
        onclick: e => { e.preventDefault(); show('artist', t.artist_agent); } }) : (t.artist_name || 'Unknown artist'))),
    el('div', { class: 'album' }, accessBadge(item)),
    el('div', { class: 'dur muted', text: fmt(t.duration_ms) }),
    trackActions(fileId, catalogueRow));
}

function list(rows, empty) {
  if (!rows.length) return el('p', { class: 'empty', text: empty });
  return el('div', { class: 'tracks' }, ...rows);
}

// ---- views -----------------------------------------------------------
const views = {
  async browse() {
    if (!state.online) return [el('h1', { text: 'Browse' }), el('p', { class: 'empty', text: 'Offline: the catalogue needs the Holochain network. Your downloaded music still plays from Your library.' })];
    const { tracks } = await api('/api/catalogue/browse', {});
    return [el('h1', { text: 'New music' }), el('p', { class: 'sub', text: 'Tracks published by artists on this Holochain network. Titles are artist claims, not verified rights.' }),
      list(tracks.map(t => trackRow(t, t.file_id, t)), 'No tracks found yet. New peers can take a few minutes to sync.')];
  },
  async search(q) {
    const { tracks } = await api('/api/catalogue/search', { query: q });
    return [el('h1', { text: `Results for “${q}”` }), list(tracks.map(t => trackRow(t, t.file_id, t)), 'No matching tracks.')];
  },
  async artists() {
    const { artists } = await api('/api/catalogue/artists', {});
    return [el('h1', { text: 'Artists' }), artists.length ? el('div', { class: 'grid' }, ...artists.map(a =>
      el('button', { class: 'tile', type: 'button', onclick: () => show('artist', a.agent) },
        el('strong', { text: a.display_name }), el('div', { class: 'muted', text: (a.biography || '').slice(0, 120) })))) :
      el('p', { class: 'empty', text: 'No artist profiles found yet.' })];
  },
  async artist(agent) {
    const { profile, albums, tracks } = await api('/api/catalogue/artist', { agent });
    const out = [el('h1', { text: profile ? profile.display_name : 'Artist' }),
      el('p', { class: 'sub', text: profile ? profile.biography : '' }), el('p', { class: 'mono muted', text: agent })];
    for (const album of albums) {
      out.push(el('h2', { text: `${album.title}${album.release_date ? ' · ' + album.release_date : ''}` }));
      out.push(list(tracks.filter(t => t.album_id === album.album_id).sort((a, b) => a.track_number - b.track_number)
        .map(t => trackRow(t, t.file_id, t)), 'No tracks on this album yet.'));
    }
    const singles = tracks.filter(t => !t.album_id || !albums.some(a => a.album_id === t.album_id));
    out.push(el('h2', { text: 'Tracks' }), list(singles.map(t => trackRow(t, t.file_id, t)), 'No other tracks.'));
    return out;
  },
  async library() {
    return [el('h1', { text: 'Your library' }), el('p', { class: 'sub', text: 'Encrypted on this computer. “Offline ready” tracks play with no network at all.' }),
      list(library.map(t => trackRow(t, t.file_id, null)), 'Nothing here yet. Browse the catalogue and request access from an artist.')];
  },
  async queue() {
    const rows = state.queue.map((id, i) => { const t = libraryById.get(id) || { title: id.slice(0, 12) };
      return el('div', { class: 'row' }, el('div', { class: 'title' }, el('strong', { text: `${i + 1}. ${t.title}` }), el('span', { text: t.artist_name || '' })),
        el('div'), el('div'), el('div', { class: 'actions' }, el('button', { class: 'btn', type: 'button', text: 'Remove',
          onclick: () => act('/api/queue', { items: state.queue.filter((_, j) => j !== i) }) }))); });
    return [el('h1', { text: 'Queue' }), list(rows, 'The queue is empty. Use “Queue” on a playable track.'),
      state.queue.length ? el('button', { class: 'btn', type: 'button', text: 'Clear queue', onclick: () => act('/api/queue', { items: [] }) }) : null];
  },
  async history() {
    const { history } = await api('/api/history');
    return [el('h1', { text: 'Recently played' }), list(history.map(h => trackRow({ ...h, ...(libraryById.get(h.key) || {}) }, h.key, null)), 'Nothing played yet.')];
  },
  async playlists() {
    const { playlists } = await api('/api/playlists');
    const name = el('input', { id: 'pl-name', maxlength: '120', placeholder: 'New playlist name' });
    const out = [el('h1', { text: 'Playlists' }),
      el('form', { class: 'stack', onsubmit: async e => { e.preventDefault(); if (!name.value.trim()) return;
        const id = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
        await act('/api/playlists', { playlists: [...playlists, { id, name: name.value.trim(), tracks: [] }] }, 'Playlist created'); render(); } },
        el('label', { for: 'pl-name', text: 'Create a playlist' }, name), el('button', { class: 'btn primary', type: 'submit', text: 'Create' }))];
    for (const p of playlists) {
      out.push(el('h2', { text: p.name }), el('div', { class: 'actions' },
        el('button', { class: 'btn primary', type: 'button', text: 'Play all', onclick: async () => {
          const ids = p.tracks.filter(id => (libraryById.get(id) || {}).playable); if (!ids.length) return toast('No playable tracks in this playlist');
          await act('/api/queue', { items: ids.slice(1) }); await act('/api/play', { file_id: ids[0] }); } }),
        el('button', { class: 'btn', type: 'button', text: 'Delete', onclick: async () => {
          await act('/api/playlists', { playlists: playlists.filter(x => x.id !== p.id) }); render(); } })),
        list(p.tracks.map(id => trackRow(libraryById.get(id) || { title: 'Unavailable track' }, id, null)), 'Empty playlist.'));
    }
    return out;
  },
  async publish() {
    const form = el('form', { class: 'stack' });
    const f = (label, input) => el('label', {}, label, input);
    const path = el('input', { required: true, placeholder: '/home/you/Music/song.wav', autocomplete: 'off' });
    const title = el('input', { required: true, maxlength: '200' });
    const rights = el('select', {}, el('option', { value: 'original_owner', text: 'I own the rights to this recording' }),
      el('option', { value: 'licensed_by_rights_holder', text: 'I am licensed by the rights holder' }));
    const name = el('input', { maxlength: '120', placeholder: 'Artist name shown to listeners' });
    const bio = el('textarea', { maxlength: '2048', rows: '3' });
    const profile = el('form', { class: 'stack', onsubmit: async e => { e.preventDefault();
      await act('/api/artist/profile', { display_name: name.value, biography: bio.value }, 'Artist profile published'); } },
      f('Artist name', name), f('Biography', bio), el('button', { class: 'btn', type: 'submit', text: 'Save profile' }));
    form.append(f('WAV file on this computer (16-bit PCM, mono/stereo)', path), f('Track title', title), f('Rights declaration', rights),
      el('p', { class: 'muted', text: 'The file is encrypted locally (AES-256-GCM). Only ciphertext is hosted; the content key never leaves this computer. Your declaration is not a copyright verification.' }),
      el('button', { class: 'btn primary', type: 'submit', text: 'Encrypt & publish' }));
    form.addEventListener('submit', async e => { e.preventDefault(); const b = form.querySelector('button[type=submit]'); b.disabled = true; b.textContent = 'Encrypting & publishing…';
      const r = await act('/api/artist/publish', { path: path.value, title: title.value, rights_basis: rights.value }, 'Track published and hosted');
      b.disabled = false; b.textContent = 'Encrypt & publish'; if (r) show('mytracks'); });
    return [el('h1', { text: 'Artist studio' }), el('h2', { text: '1. Your profile' }), el('div', { class: 'card' }, profile),
      el('h2', { text: '2. Publish a track' }), el('div', { class: 'card' }, form)];
  },
  async mytracks() {
    const { tracks } = await api('/api/artist/tracks', {});
    return [el('h1', { text: 'Your releases' }), el('p', { class: 'sub', text: 'Hosted by this computer over pinned MoQ/QUIC while the app is running.' }),
      list(tracks.map(t => el('div', { class: 'row' }, el('div', { class: 'title' }, el('strong', { text: t.title }), el('span', { class: 'mono', text: t.file_id })),
        el('div', { text: new Date(t.published_at * 1000).toLocaleDateString() }), el('div', { class: 'muted', text: fmt(t.duration_ms) }), el('div'))), 'You have not published anything yet.')];
  },
  async requests() {
    const { requests } = await api('/api/artist/requests', {});
    return [el('h1', { text: 'Access requests' }), el('p', { class: 'sub', text: 'Requests arrive privately on your own chain. Approving signs a grant for that listener only and delivers it privately. A licence allows permanent offline use and export and cannot be revoked.' }),
      list(requests.map(r => el('div', { class: 'row' },
        el('div', { class: 'title' }, el('strong', { text: r.track_title }), el('span', { class: 'mono', text: r.listener_agent })),
        el('div', {}, el('span', { class: 'badge', text: r.kind === 'stream' ? 'Wants streaming' : 'Wants licence' })),
        el('div', { class: 'muted', text: r.note || '' }),
        r.granted ? el('span', { class: 'badge ok', text: 'Granted' }) : el('div', { class: 'actions' },
          el('button', { class: 'btn', type: 'button', text: 'Grant 24 h streaming', onclick: () => approve(r, 'stream') }),
          el('button', { class: 'btn primary', type: 'button', text: 'Grant licence', onclick: () => approve(r, 'perpetual-personal') })))),
      'No requests yet.')];
  },
  async settings() {
    const id = await api('/api/identity');
    const s = id.settings;
    const appearance = el('select', { id: 'appearance', onchange: e => setAppearance(e.target.value) },
      el('option', { value: 'system', text: 'System (follow device)' }),
      el('option', { value: 'light', text: 'Light' }),
      el('option', { value: 'dark', text: 'Dark' }),
      el('option', { value: 'amethyst-night', text: 'Amethyst Night' }),
      el('option', { value: 'amethyst-light', text: 'Amethyst Light' }));
    appearance.value = getAppearance();
    const boot = el('input', { value: s.bootstrap_url }); const relay = el('input', { value: s.relay_url });
    const lan = el('input', { type: 'checkbox', checked: s.allow_lan }); const advertise = el('input', { value: s.host_advertise_ip || '', placeholder: 'e.g. 192.168.1.50 (empty = this computer only)' });
    const bind = el('input', { value: s.host_bind });
    const form = el('form', { class: 'stack', onsubmit: async e => { e.preventDefault();
      await act('/api/settings', { bootstrap_url: boot.value, relay_url: relay.value, allow_lan: lan.checked,
        host_advertise_ip: advertise.value || null, host_bind: bind.value }, 'Saved. Restart Holochain Music to apply network changes.'); } },
      el('label', {}, 'Bootstrap URL', boot), el('label', {}, 'Relay URL', relay),
      el('label', {}, el('span', {}, lan, ' Allow private-LAN (RFC1918) music hosts — experimental')),
      el('label', {}, 'Host bind address (use 0.0.0.0:PORT to serve a LAN)', bind), el('label', {}, 'Host advertised LAN IP', advertise),
      el('button', { class: 'btn primary', type: 'submit', text: 'Save' }));
    return [el('h1', { text: 'Identity & settings' }), el('div', { class: 'card' },
      el('p', {}, 'Holochain agent: ', el('code', { text: id.agent || 'not yet created' })),
      el('p', {}, 'Status: ', el('span', { text: id.status })),
      el('p', {}, 'Hosting: ', el('code', { text: id.host ? `${id.host.url} · ${id.host.fingerprint}` : 'not hosting' })),
      el('p', { class: 'muted', text: 'Back up your keys and library with: holochain-music backup export FILE (keep the passphrase safe; without the backup a lost computer means lost licences).' })),
      el('h2', { text: 'Appearance' }),
      el('div', { class: 'card' },
        el('div', { class: 'appearance-field' }, el('label', { for: 'appearance', text: 'Theme' }), appearance),
        el('p', { class: 'muted', text: 'Changes apply immediately. System follows your device, including future changes. Saved in this browser.' })),
      el('h2', { text: 'Network' }), el('div', { class: 'card' }, form)];
  },
};

async function approve(request, kind) {
  const r = await act('/api/artist/grant', { request_hash: request.request_hash, kind });
  if (r) toast(r.queued ? 'Signed. The listener is offline; it will be delivered automatically when they are back.' : 'Delivered privately to the listener', 'info');
  render();
}
async function exportWav(item) {
  const path = prompt('Save a playable WAV copy (personal use under your licence). Full path inside your home folder, ending in .wav:', '');
  if (path) await act('/api/export', { file_id: item.file_id, path }, 'Exported');
}
async function addToPlaylist(fileId) {
  const { playlists } = await api('/api/playlists');
  if (!playlists.length) return toast('Create a playlist first (Playlists).');
  const name = prompt(`Add to which playlist?\n${playlists.map(p => p.name).join('\n')}`, playlists[0].name);
  const p = playlists.find(x => x.name === name); if (!p) return;
  if (!p.tracks.includes(fileId)) p.tracks.push(fileId);
  await act('/api/playlists', { playlists }, `Added to ${p.name}`);
}

async function render() {
  document.querySelectorAll('.nav').forEach(b => {
    if (b.dataset.view === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  const host = $('view');
  try { host.replaceChildren(...(await views[view](viewArg)).filter(Boolean)); }
  catch (e) { host.replaceChildren(el('h1', { text: 'Something went wrong' }), el('p', { class: 'empty', text: e.message })); }
}
function show(name, arg = null) { view = name; viewArg = arg; render(); $('main').focus(); }

// ---- player bar ------------------------------------------------------
// ---- player state: ordered, with optimistic seeks ----------------------
// Every server status carries a monotonically increasing `seq`. Responses
// older than one already applied (e.g. a poll that was in flight when the
// user seeked) are dropped, so the timeline can never jump back to a stale
// position. While a seek is pending the UI shows its target.
let lastSeq = -1;
let pendingSeek = null;   // { frame, sentSeq }
let seekTimer = null;
function applyPlayer(p) {
  if (!p || typeof p.seq !== 'number' || p.seq < lastSeq) return false;
  lastSeq = p.seq;
  state.player = p;
  if (pendingSeek && pendingSeek.sentSeq !== undefined && p.seq > pendingSeek.sentSeq &&
      (p.output_active || ['paused', 'stopped', 'finished', 'error'].includes(p.state))) pendingSeek = null;
  return true;
}
function displayedFrame(p) { return pendingSeek ? pendingSeek.frame : p.position_frames; }
function requestSeek(frame) {
  const p = state.player; if (!p || !p.total_frames) return;
  pendingSeek = { frame: Math.max(0, Math.min(p.total_frames - 1, Math.floor(frame))) };
  renderPlayer();
  // Coalesce rapid slider/keyboard input: only the latest target is sent.
  clearTimeout(seekTimer);
  seekTimer = setTimeout(async () => {
    const target = pendingSeek.frame;
    try {
      const r = await api('/api/seek', { frame: target });
      if (pendingSeek && pendingSeek.frame === target) pendingSeek.sentSeq = r.seq;
      applyPlayer(r); renderPlayer();
    } catch (e) { pendingSeek = null; toast(e.message); }
  }, 120);
}

function renderPlayer() {
  const p = state.player; if (!p) return;
  const item = libraryById.get(p.track_key);
  $('now-title').textContent = item ? item.title : 'Nothing playing';
  $('now-artist').textContent = item ? item.artist_name : 'Choose a track';
  // "Playing" only once PCM for the current position has actually been written.
  const playingLabel = !p.output_active ? 'Starting…' : p.source === 'offline' ? 'Playing · offline copy' : 'Streaming';
  const labels = { idle: 'Idle', loading: 'Opening · verifying…', seeking: 'Seeking…', playing: playingLabel,
    buffering: 'Buffering…', paused: 'Paused', stopped: 'Stopped', finished: 'Finished', error: 'Error' };
  const badge = $('state-badge'); badge.textContent = pendingSeek && p.state !== 'error' ? 'Seeking…' : (labels[p.state] || p.state);
  badge.className = `badge ${p.state === 'error' ? 'bad' : p.state === 'buffering' ? 'warn' : ['playing', 'paused'].includes(p.state) ? 'ok' : ''}`;
  if (p.audio_output && p.audio_output.underruns > 0 && ['playing', 'paused', 'buffering'].includes(p.state)) {
    badge.textContent = `Audio interruptions · ${p.audio_output.underruns}`;
    badge.className = 'badge warn';
  }
  if (p.state === 'error' && p.error && renderPlayer.lastError !== p.error) toast(p.error);
  renderPlayer.lastError = p.error;
  const playing = ['playing', 'buffering', 'seeking'].includes(p.state);
  $('btn-play').querySelector('use').setAttribute('href', playing ? '#ph-pause-fill' : '#ph-play-fill');
  $('btn-play').setAttribute('aria-label', playing ? 'Pause' : 'Play');
  $('btn-play').disabled = !p.track_key || p.state === 'loading';
  $('btn-stop').disabled = !['playing', 'paused', 'buffering', 'loading', 'seeking'].includes(p.state);
  const ready = p.total_frames > 0 && p.sample_rate > 0 && p.state !== 'loading';
  $('btn-back').disabled = $('btn-fwd').disabled = $('seek').disabled = !ready;
  $('btn-next').disabled = !state.queue.length;
  const rate = p.sample_rate || 1;
  const shown = displayedFrame(p);
  $('elapsed').textContent = fmt(1000 * shown / rate); $('duration').textContent = fmt(1000 * p.total_frames / rate);
  if (!dragging) $('seek').value = p.total_frames ? Math.round(1000 * shown / p.total_frames) : 0;
  $('seek').setAttribute('aria-valuetext', `${$('elapsed').textContent} of ${$('duration').textContent}`);
  const qc = $('queue-count'); qc.hidden = !state.queue.length; qc.textContent = state.queue.length;
}
// ±10 s presses accumulate from the pending target, not the stale position.
const nudge = secs => { const p = state.player; if (p && p.total_frames) requestSeek(displayedFrame(p) + secs * p.sample_rate); };
$('btn-play').addEventListener('click', () => { const p = state.player; if (!p || !p.track_key) return;
  if (p.state === 'playing' || p.state === 'buffering') act('/api/pause'); else if (p.state === 'paused') act('/api/resume'); else act('/api/play', { file_id: p.track_key }); });
$('btn-stop').addEventListener('click', () => act('/api/stop'));
$('btn-back').addEventListener('click', () => nudge(-10));
$('btn-fwd').addEventListener('click', () => nudge(10));
$('btn-next').addEventListener('click', () => act('/api/next'));
$('btn-queue').addEventListener('click', () => show('queue'));
$('seek').addEventListener('pointerdown', () => { dragging = true; });
$('seek').addEventListener('change', () => { dragging = false; const p = state.player; if (p && p.total_frames) requestSeek($('seek').value * p.total_frames / 1000); });
let volTimer; $('volume').addEventListener('input', () => { clearTimeout(volTimer); volTimer = setTimeout(() => act('/api/volume', { volume: $('volume').value / 100 }), 120); });
document.querySelectorAll('.nav').forEach(b => b.addEventListener('click', () => show(b.dataset.view)));
$('search-form').addEventListener('submit', e => { e.preventDefault(); const q = $('search').value.trim(); if (q.length >= 2) show('search', q); });
window.addEventListener('keydown', e => {
  const typing = ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName);
  if (e.key === '/' && !typing) { e.preventDefault(); $('search').focus(); return; }
  if (typing || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.code === 'Space' && document.activeElement.tagName !== 'BUTTON') { e.preventDefault(); $('btn-play').click(); }
  else if (e.key === 'ArrowLeft') nudge(-10);
  else if (e.key === 'ArrowRight') nudge(10);
  else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') { const v = $('volume'); v.value = Math.max(0, Math.min(100, +v.value + (e.key === 'ArrowUp' ? 5 : -5))); v.dispatchEvent(new Event('input')); }
  else if (e.key.toLowerCase() === 'n') $('btn-next').click();
});

// ---- polling ---------------------------------------------------------
async function refreshLibrary() {
  try { library = (await api('/api/library')).tracks; libraryById = new Map(library.map(t => [t.file_id, t])); } catch (_) { /* shown elsewhere */ }
}
async function poll() {
  try {
    const s = await api('/api/state');
    const player = s.player; delete s.player;
    state = { ...state, ...s };
    applyPlayer(player);
    $('net-status').textContent = state.online ? 'Online · Holochain' : 'Offline';
    renderPlayer();
  } catch (e) { $('net-status').textContent = 'Not connected'; }
}
let ticks = 0;
async function slowPoll() {
  ticks += 1;
  if (state.online && ticks % 3 === 0) {
    try { const r = await api('/api/grants/sync', {}); if (r.new_grants) { toast(`${r.new_grants} new grant(s) received`, 'info'); await refreshLibrary(); if (view === 'library' || view === 'browse') render(); } } catch (_) {}
    try { const { requests } = await api('/api/artist/requests', {}); const open = requests.filter(r => !r.granted).length; const c = $('request-count'); c.hidden = !open; c.textContent = open; } catch (_) {}
  }
  const before = JSON.stringify(library.map(t => [t.file_id, t.download && t.download.available_chunks, t.playable, t.complete]));
  await refreshLibrary();
  if (view === 'library' && before !== JSON.stringify(library.map(t => [t.file_id, t.download && t.download.available_chunks, t.playable, t.complete]))) render();
}
(async () => {
  if (!token) { toast('Open the private link printed by holochain-music in your terminal.'); return; }
  await poll(); await refreshLibrary();
  show(state.online ? 'browse' : 'library');
  setInterval(poll, 500); setInterval(slowPoll, 5000);
})();
