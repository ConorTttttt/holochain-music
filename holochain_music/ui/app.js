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
  if (item.offline_ready) return el('span', { class: 'badge ok', text: 'Downloaded · verify offline' });
  if (item.playable && item.grant_kind === 'perpetual-personal') return el('span', { class: 'badge ok', text: 'Licensed · streaming' });
  if (item.playable) return el('span', { class: 'badge ok', text: `Streaming access until ${new Date(item.grant_expires_at * 1000).toLocaleString()}` });
  if (item.grant_kind === 'stream') return el('span', { class: 'badge bad', text: 'Access expired' });
  if (item.requested && item.request_queued) return el('span', { class: 'badge warn', text: 'Request waiting for the artist to come online' });
  if (item.requested) return el('span', { class: 'badge warn', text: 'Access requested' });
  return el('span', { class: 'badge', text: 'No access' });
}

// Local album cover images are token-authorised binary responses, then converted
// to short-lived blob: URLs. No bearer token is placed in an img src or query.
const albumArtwork = new Map();
const validAlbumId = id => typeof id === 'string' && /^[0-9a-f]{32}$/.test(id);
const validArtworkArtist = agent => typeof agent === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(agent);
async function albumArtworkUrl(albumId, artistAgent) {
  if (!token || !validAlbumId(albumId) || !validArtworkArtist(artistAgent)) return null;
  const key = `${artistAgent}:${albumId}`;
  if (albumArtwork.has(key)) return albumArtwork.get(key);
  const request = (async () => {
    try {
      // The backend queues no more than two MoQ cover fetches; a 202 means
      // the cover is being verified, not that arbitrary bytes are available.
      for (let attempt = 0; attempt < 36; attempt++) {
        const response = await fetch(`/api/artwork/${artistAgent}/${albumId}`, {
          headers: { Authorization: `Bearer ${token}` }, cache: 'no-store'
        });
        if (response.status === 202) {
          await new Promise(resolve => setTimeout(resolve, 1000));
          continue;
        }
        if (!response.ok || response.headers.get('Content-Type') !== 'image/png') return null;
        if (Number(response.headers.get('Content-Length')) > 768 * 1024) return null;
        const image = await response.blob();
        if (image.size > 768 * 1024 || image.type !== 'image/png') return null;
        return URL.createObjectURL(image);
      }
    } catch (_) { /* optional artwork never blocks listening */ }
    return null;
  })();
  albumArtwork.set(key, request);
  request.then(url => {
    if (!url) window.setTimeout(() => {
      if (albumArtwork.get(key) === request) albumArtwork.delete(key);
    }, 45_000);
  });
  return request;
}
window.addEventListener('pagehide', () => {
  for (const request of albumArtwork.values()) {
    Promise.resolve(request).then(url => { if (url) URL.revokeObjectURL(url); });
  }
});
function albumCoverThumb(albumId, artistAgent) {
  const thumb = el('span', { class: 'track-cover', 'aria-hidden': 'true' });
  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('class', 'icon');
  icon.setAttribute('viewBox', '0 0 256 256');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#ph-vinyl-record');
  icon.append(use);
  thumb.append(icon);
  if (validAlbumId(albumId) && validArtworkArtist(artistAgent)) albumArtworkUrl(albumId, artistAgent).then(url => {
    if (url) thumb.append(el('img', { src: url, alt: '' }));
  });
  return thumb;
}
let shownArtworkKey = undefined;
function showPlayerArtwork(item) {
  const albumId = item && validAlbumId(item.album_id) ? item.album_id : null;
  const artist = item && validArtworkArtist(item.artist_agent) ? item.artist_agent : null;
  const key = albumId && artist ? `${artist}:${albumId}` : null;
  const image = $('now-art-image');
  // A previously unavailable cover can be retried when its negative cache
  // expires; do not re-request an image already displayed successfully.
  if (key === shownArtworkKey && (!key || !image.hidden || albumArtwork.has(key))) return;
  shownArtworkKey = key;
  image.hidden = true;
  image.removeAttribute('src');
  if (!key) return;
  albumArtworkUrl(albumId, artist).then(url => {
    if (shownArtworkKey === key && url) {
      image.src = url;
      image.hidden = false;
    }
  });
}

function trackActions(fileId, catalogueRow) {
  const item = libraryById.get(fileId);
  const box = el('div', { class: 'actions' });
  if (item && item.playable) {
    box.append(el('button', { class: 'btn primary', type: 'button', 'aria-label': `Play ${item.title}`, text: 'Play',
      onclick: () => act('/api/play', { file_id: fileId }) }));
    box.append(el('button', { class: 'btn', type: 'button', text: 'Queue', 'aria-label': `Add ${item.title} to queue`,
      onclick: () => act('/api/queue', { items: [...state.queue, fileId] }, 'Added to queue') }));
    if (item.grant_kind === 'perpetual-personal' && !item.offline_ready) {
      const busy = item.download && ['downloading', 'retrying'].includes(item.download.state);
      box.append(el('button', { class: 'btn', type: 'button',
        text: busy ? 'Downloading…' : item.download && item.download.state === 'unavailable' ? 'Retry download' : 'Download for Offline',
        disabled: busy || !state.online,
        onclick: () => startOfflineDownload(fileId) }));
    }
    if (item.offline_ready && item.grant_kind === 'perpetual-personal')
      box.append(el('button', { class: 'btn', type: 'button', text: 'Export licensed WAV',
        onclick: () => exportWav(item) }));
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
    el('div', { class: 'track-info' }, albumCoverThumb(t.album_id, t.artist_agent),
      el('div', { class: 'title' }, el('strong', { text: t.title || 'Untitled' }),
        el('span', {}, catalogueRow ? el('a', { href: '#', text: t.artist_name || 'Unknown artist',
          onclick: e => { e.preventDefault(); show('artist', t.artist_agent); } }) : (t.artist_name || 'Unknown artist')))),
    el('div', { class: 'album' }, accessBadge(item)),
    el('div', { class: 'dur muted', text: fmt(t.duration_ms) }),
    trackActions(fileId, catalogueRow));
}

function list(rows, empty) {
  if (!rows.length) return el('p', { class: 'empty', text: empty });
  return el('div', { class: 'tracks' }, ...rows);
}

// Collection membership, rights and local availability remain independent.
// Filters use only fields the local backend actually reports; payment history,
// verified purchase records and subscription terms do not yet exist here.
const libraryFilters = { scope: 'all', query: '', sort: 'default' };
const libraryScopes = [
  ['all', 'All music'], ['songs', 'Songs'], ['albums', 'Albums'],
  ['licences', 'Permanent licences'], ['temporary', 'Temporary access'],
  ['offline', 'Offline'], ['requests', 'Access requests']
];
const libraryScopeNotes = {
  all: 'Your locally represented collection. Saved or requested does not mean purchased or playable.',
  songs: 'Songs represented in your local library, including currently unavailable items.',
  albums: 'Albums represented by local track metadata. Unavailable tracks remain listed.',
  licences: 'Permanent personal-use licences, including artist grants. This is not a verified purchase history.',
  temporary: 'Time-limited streaming access. Rental and subscription payments are not yet distinguished.',
  offline: 'App-managed downloads are separate from exported WAV files. Verify offline readiness explicitly; a stored Complete flag alone is not proof.',
  requests: 'Locally recorded access requests. Declined decisions are not yet synchronised into this view.'
};
function matchesLibraryScope(track, scope) {
  if (scope === 'licences') return track.grant_kind === 'perpetual-personal';
  if (scope === 'temporary') return track.grant_kind === 'stream';
  if (scope === 'offline') return track.offline_ready === true ||
    track.grant_kind === 'perpetual-personal' || Boolean(track.download);
  if (scope === 'requests') return Boolean(track.requested) && !track.playable;
  return true;
}
function renderLibraryView() {
  const scopes = el('div', { class: 'library-scopes', role: 'group', 'aria-label': 'Library collections' });
  const search = el('input', { type: 'search', class: 'library-search', 'aria-label': 'Search within your library',
    placeholder: 'Search titles, artists or albums' });
  search.value = libraryFilters.query;
  const sort = el('select', { class: 'library-sort', 'aria-label': 'Sort library songs' },
    el('option', { value: 'default', text: 'Library order' }),
    el('option', { value: 'title', text: 'Title (A–Z)' }),
    el('option', { value: 'artist', text: 'Artist (A–Z)' }));
  sort.value = libraryFilters.sort;
  const count = el('p', { class: 'library-count muted', role: 'status', 'aria-live': 'polite' });
  const note = el('p', { class: 'sub' });
  const results = el('section', { class: 'library-results', 'aria-label': 'Library results' });
  function update() {
    note.textContent = libraryScopeNotes[libraryFilters.scope];
    for (const button of scopes.querySelectorAll('button')) {
      button.setAttribute('aria-pressed', String(button.dataset.scope === libraryFilters.scope));
    }
    const q = libraryFilters.query.trim().toLocaleLowerCase();
    let rows = library.filter(t => matchesLibraryScope(t, libraryFilters.scope) &&
      (!q || [t.title, t.artist_name, t.album_title].some(v => String(v || '').toLocaleLowerCase().includes(q))));
    if (libraryFilters.sort === 'title') rows = [...rows].sort((a,b) =>
      String(a.title || '').localeCompare(String(b.title || '')));
    if (libraryFilters.sort === 'artist') rows = [...rows].sort((a,b) =>
      String(a.artist_name || '').localeCompare(String(b.artist_name || '')) ||
      String(a.title || '').localeCompare(String(b.title || '')));
    count.textContent = rows.length + (rows.length === 1 ? ' track' : ' tracks');
    if (libraryFilters.scope === 'offline') {
      results.replaceChildren(renderOfflineDashboard(rows));
      return;
    }
    if (libraryFilters.scope !== 'albums') {
      results.replaceChildren(list(rows.map(t => trackRow(t, t.file_id, null)),
        q ? 'No tracks match your library search or collection filter.' :
        'No tracks in this collection yet. Browse the catalogue to discover music.'));
      return;
    }
    const groups = new Map();
    for (const t of rows) {
      const key = t.album_id || (t.album_title ? 'title:' + t.album_title : 'singles');
      if (!groups.has(key)) groups.set(key, { title: t.album_title || 'Singles & ungrouped', tracks: [] });
      groups.get(key).tracks.push(t);
    }
    const children = [];
    for (const group of groups.values()) children.push(el('section', { class: 'library-album' },
      el('h2', { text: group.title + ' · ' + group.tracks.length + (group.tracks.length === 1 ? ' song' : ' songs') }),
      list(group.tracks.map(t => trackRow(t, t.file_id, null)), 'No tracks')));
    results.replaceChildren(...(children.length ? children : [
      el('p', { class: 'empty', text: q ? 'No albums match your search.' : 'No album information is available locally.' })]));
  }
  for (const [value, label] of libraryScopes) scopes.append(el('button', {
    type: 'button', class: 'btn library-scope', 'data-scope': value, 'aria-pressed': String(value === libraryFilters.scope),
    text: label, onclick: () => { libraryFilters.scope = value; update(); } }));
  search.addEventListener('input', () => { libraryFilters.query = search.value; update(); });
  sort.addEventListener('change', () => { libraryFilters.sort = sort.value; update(); });
  update();
  return [el('h1', { text: 'Your library' }), scopes,
    el('div', { class: 'library-toolbar' },
      el('label', { class: 'library-field' }, el('span', { text: 'Search your library' }), search),
      el('label', { class: 'library-field' }, el('span', { text: 'Sort by' }), sort)),
    note, count, results];
}

// Explicit on-demand crypto/integrity verification avoids expensive hashing on
// every library poll. The browser receives only an enumerated status, never keys.
const offlineChecks = new Map();
async function verifyOfflineTrack(fileId) {
  offlineChecks.set(fileId, { state: 'checking', message: 'Checking local encrypted data and licence…' });
  if (view === 'library' && libraryFilters.scope === 'offline') render();
  try {
    const result = await api('/api/offline/verify', { file_id: fileId });
    offlineChecks.set(fileId, { state: result.state, message: result.message,
      checkedAt: new Date().toLocaleTimeString() });
  } catch (e) {
    offlineChecks.set(fileId, { state: 'error', message: 'Verification could not finish: ' + e.message });
  }
  if (view === 'library' && libraryFilters.scope === 'offline') render();
}
async function startOfflineDownload(fileId) {
  try {
    const result = await api('/api/download', { file_id: fileId });
    if (result.state === 'complete') toast('Encrypted download present. Verify offline readiness before relying on it.', 'info');
    else toast('Download ' + (result.state || 'requested') + '. Progress will update in Offline.', 'info');
    await refreshLibrary();
    if (view === 'library') render();
  } catch (e) { toast('Download not started: ' + e.message); }
}
// Storage and deletion are explicit user actions; no auto-cleanup and no
// background /api/offline/storage polling during real-time playback.
let storageReport = null;
let storageBusy = false;
const readableBytes = bytes => {
  const value = Math.max(0, Number(bytes) || 0);
  if (value < 1024) return value + ' B';
  if (value < 1048576) return (value / 1024).toFixed(1) + ' KiB';
  if (value < 1073741824) return (value / 1048576).toFixed(1) + ' MiB';
  return (value / 1073741824).toFixed(2) + ' GiB';
};
async function inspectOfflineStorage() {
  if (storageBusy) return;
  storageBusy = true;
  storageReport = { state: 'checking' };
  if (view === 'library' && libraryFilters.scope === 'offline') render();
  try {
    storageReport = { state: 'complete', data: await api('/api/offline/storage') };
  } catch (e) {
    storageReport = { state: 'error', message: 'Storage could not be counted: ' + e.message };
  } finally {
    storageBusy = false;
    if (view === 'library' && libraryFilters.scope === 'offline') render();
  }
}
async function removeLocalDownload(item) {
  if (!item || !item.file_id) return;
  if (!confirm('Remove only the local app-managed encrypted copy of "' +
    (item.title || 'this track') + '"? Your licence, library entry, playlists and independently exported files will remain. Shared audio chunks are retained. Stop playback first.')) return;
  try {
    const result = await api('/api/offline/remove', { file_id: item.file_id });
    offlineChecks.delete(item.file_id);
    storageReport = null;
    toast('Removed ' + readableBytes(result.removed_bytes) + ' of exclusive encrypted audio. ' +
      result.shared_objects_preserved + ' shared objects kept. Rights and exported WAV files remain.', 'info');
    await refreshLibrary();
    if (view === 'library' && libraryFilters.scope === 'offline') render();
  } catch (e) { toast('Local copy was not removed: ' + e.message); }
}
function downloadStateText(item) {
  const transfer = item.download;
  if (transfer) {
    const found = Number(transfer.available_chunks);
    const total = Number(transfer.total_chunks);
    const progress = total > 0 && Number.isFinite(found) && Number.isFinite(total)
      ? ' · ' + Math.round(100 * found / total) + '% of authenticated chunks received' : '';
    if (transfer.state === 'unavailable') return 'Source unavailable — Retry when online.' + progress;
    if (transfer.state === 'retrying') return 'Retrying an authenticated source…' + progress;
    if (transfer.state === 'downloading') return 'Downloading encrypted audio…' + progress;
    if (transfer.state === 'paused') return 'Transfer paused or interrupted. Restart is available when supported.' + progress;
    if (transfer.state === 'complete') return 'Encrypted transfer complete; check offline licence and local keys.';
    return 'Transfer status: ' + String(transfer.state || 'unknown') + progress;
  }
  if (item.offline_ready) return 'Full encrypted download was recorded earlier. Verify before offline use.';
  if (item.grant_kind !== 'perpetual-personal')
    return 'This version supports streaming access only for this grant; no offline rental promise.';
  return 'Not downloaded for offline listening.';
}
function offlineTrackCard(item) {
  const check = offlineChecks.get(item.file_id);
  const card = el('article', { class: 'offline-track-card' },
    el('div', { class: 'offline-track-heading' },
      albumCoverThumb(item.album_id),
      el('div', {}, el('strong', { text: item.title || 'Untitled' }),
        el('p', { class: 'muted', text: item.artist_name || 'Unknown artist' }))),
    el('p', { class: 'muted', text: downloadStateText(item) }));
  if (item.download && Number(item.download.total_chunks) > 0) {
    const progress = el('progress', { max: String(item.download.total_chunks),
      value: String(Math.min(item.download.total_chunks, Math.max(0, item.download.available_chunks || 0))),
      'aria-label': 'Verified download chunks for ' + (item.title || 'track') });
    card.append(progress);
  }
  if (check) {
    const note = check.state === 'ready'
      ? 'Verified on this device at ' + check.checkedAt + ' · still checked when playing.'
      : check.message;
    card.append(el('p', { class: 'offline-check-result', role: 'status', text: note }));
  }
  const actions = el('div', { class: 'offline-actions' });
  if (item.grant_kind === 'perpetual-personal' && item.offline_ready) {
    actions.append(el('button', { class: 'btn', type: 'button',
      disabled: check && check.state === 'checking',
      text: check && check.state === 'ready' ? 'Verify again' : 'Verify offline readiness',
      onclick: () => verifyOfflineTrack(item.file_id) }));
    if (check && check.state === 'ready') {
      actions.append(el('button', { class: 'btn primary', type: 'button', text: 'Play verified copy',
        onclick: () => act('/api/play', { file_id: item.file_id }) }));
      actions.append(el('button', { class: 'btn', type: 'button', text: 'Export licensed WAV',
        onclick: () => exportWav(item) }));
    }
  } else if (item.grant_kind === 'perpetual-personal') {
    const transfer = item.download;
    const busy = transfer && ['downloading', 'retrying'].includes(transfer.state);
    actions.append(el('button', { class: 'btn', type: 'button',
      text: busy ? 'Downloading…' : transfer && transfer.state === 'unavailable' ? 'Retry download' : 'Download for Offline',
      disabled: !state.online || Boolean(busy),
      onclick: () => startOfflineDownload(item.file_id) }));
  }
  if (item.grant_kind === 'perpetual-personal' &&
      (item.offline_ready || Number(item.download?.available_chunks) > 0)) {
    actions.append(el('button', { class: 'btn offline-remove', type: 'button',
      text: 'Remove local copy',
      'aria-label': 'Remove local encrypted copy of ' + (item.title || 'track') + ' only',
      onclick: () => removeLocalDownload(item) }));
  }
  card.append(actions);
  return card;
}
function renderOfflineDashboard(rows) {
  const verified = rows.filter(t => offlineChecks.get(t.file_id)?.state === 'ready' && t.offline_ready);
  const pending = rows.filter(t => !verified.includes(t));
  const section = (heading, note, tracks, empty) => el('section', { class: 'offline-group' },
    el('h2', { text: heading }), el('p', { class: 'sub', text: note }),
    tracks.length ? el('div', { class: 'offline-track-list' }, ...tracks.map(offlineTrackCard)) :
      el('p', { class: 'empty', text: empty }));
  return el('div', { class: 'offline-dashboard' },
    section('Ready to listen',
      'Only tracks explicitly verified in this session appear here. Actual playback still checks audio and access.',
      verified, 'No tracks verified yet. Choose Verify offline readiness on a recorded complete download.'),
    section('Downloads',
      'Transfers show authenticated chunk progress when known. Temporary streaming access is not an offline rental licence.',
      pending, 'No downloads or offline-eligible music match your current filters.'),
    el('section', { class: 'offline-group' }, el('h2', { text: 'Independent licensed exports' }),
      el('p', { text: 'After verifying a permanent personal-use licence and local file, choose Export licensed WAV. The app can write a standard WAV under your home directory; export history and independent player testing are not tracked here.' }),
      el('p', { class: 'muted', text: 'An exported file is yours to retain under its personal-use licence. It is not a transfer of copyright or proof of a payment.' })),
    el('section', { class: 'offline-group' }, el('h2', { text: 'Storage and safety' }),
      el('p', { text: 'Encrypted app-managed downloads remain in your private music library. Select Remove local copy on a track to delete only exclusive encrypted objects after confirmation; shared chunks, licence and playlist references remain.' }),
      el('button', { class: 'btn', type: 'button',
        text: storageBusy ? 'Counting storage…' : 'Check local storage usage',
        disabled: storageBusy, onclick: inspectOfflineStorage }),
      storageReport && storageReport.state === 'complete'
        ? el('dl', { class: 'offline-storage-metrics' },
          el('dt', { text: 'Encrypted library audio objects' }),
          el('dd', { text: readableBytes(storageReport.data.encrypted_bytes) + ' · ' +
            storageReport.data.encrypted_objects + ' files' }),
          el('dt', { text: 'Library metadata and grants' }),
          el('dd', { text: readableBytes(storageReport.data.library_metadata_bytes) }),
          el('dt', { text: 'Total counted local library files' }),
          el('dd', { text: readableBytes(storageReport.data.accounted_bytes) }))
        : storageReport ? el('p', { role: 'status',
          text: storageReport.state === 'checking' ? 'Counting local library files…' : storageReport.message }) : null,
      el('p', { class: 'muted', text: 'Sizes count file bytes, not filesystem quota. Identity keys, Holochain host storage, temporary files, independently exported WAV files and backups are not included. Clear All, moving storage folders and deleting exports are intentionally unavailable.' })));
}

// Read the latest saved playlists before modifying them; never change the
// current playback session or queue for an ordinary library edit.
let playlistSaveBusy = false;
async function savePlaylistChange(transform, message, focusId = null) {
  if (playlistSaveBusy) return toast('Another playlist change is being saved.', 'info');
  playlistSaveBusy = true;
  try {
    const { playlists } = await api('/api/playlists');
    const updated = transform(playlists.map(p => ({ ...p, tracks: [...p.tracks] })));
    if (!updated) return false;
    await api('/api/playlists', { playlists: updated });
    toast(message, 'info');
    await render();
    const focusTarget = focusId ? $('playlist-' + focusId) : $('playlist-list-heading');
    if (focusTarget) focusTarget.focus();
    return true;
  } catch (e) { toast('Playlist not saved: ' + e.message); return false; }
  finally { playlistSaveBusy = false; }
}
function playablePlaylistTracks(playlist) {
  return playlist.tracks.filter(id => (libraryById.get(id) || {}).playable);
}
async function queueWholePlaylist(playlist) {
  const playable = playablePlaylistTracks(playlist);
  if (!playable.length) return toast('No playable tracks in this playlist.');
  // Queue append is explicit. Never replace the current session/priority queue.
  await act('/api/queue', { items: [...state.queue, ...playable] }, 'Added ' + playable.length + ' tracks to queue');
}
async function playWholePlaylist(playlist) {
  const playable = playablePlaylistTracks(playlist);
  if (!playable.length) return toast('No playable tracks in this playlist.');
  if (!confirm('Play "' + playlist.name + '" now? This replaces the current upcoming queue.')) return;
  try {
    // Start the selected track first. A failed access/source resolution must
    // not silently erase the listener's existing upcoming queue.
    await api('/api/play', { file_id: playable[0] });
    await api('/api/queue', { items: playable.slice(1) });
    toast('Playing playlist · upcoming queue replaced', 'info');
  } catch (e) { toast('Unable to play playlist: ' + e.message); }
}
function playlistItem(playlist, id, index) {
  const item = libraryById.get(id) || { title: 'Unavailable track' };
  const buttons = el('div', { class: 'playlist-edit-actions' },
    el('button', { class: 'btn', type: 'button', text: 'Move up', disabled: index === 0,
      'aria-label': 'Move ' + (item.title || 'track') + ' earlier in ' + playlist.name, onclick: () =>
        savePlaylistChange(rows => {
          const p = rows.find(x => x.id === playlist.id);
          if (!p || index < 1 || index >= p.tracks.length || p.tracks[index] !== id) {
            throw new Error('Playlist changed since it was displayed. Try again.');
          }
          [p.tracks[index - 1], p.tracks[index]] = [p.tracks[index], p.tracks[index - 1]];
          return rows;
        }, 'Track moved earlier', playlist.id) }),
    el('button', { class: 'btn', type: 'button', text: 'Move down', disabled: index === playlist.tracks.length - 1,
      'aria-label': 'Move ' + (item.title || 'track') + ' later in ' + playlist.name, onclick: () =>
        savePlaylistChange(rows => {
          const p = rows.find(x => x.id === playlist.id);
          if (!p || index < 0 || index >= p.tracks.length - 1 || p.tracks[index] !== id) {
            throw new Error('Playlist changed since it was displayed. Try again.');
          }
          [p.tracks[index], p.tracks[index + 1]] = [p.tracks[index + 1], p.tracks[index]];
          return rows;
        }, 'Track moved later', playlist.id) }),
    el('button', { class: 'btn', type: 'button', text: 'Remove',
      'aria-label': 'Remove ' + (item.title || 'track') + ' from ' + playlist.name, onclick: () =>
        savePlaylistChange(rows => {
          const p = rows.find(x => x.id === playlist.id);
          if (!p || index >= p.tracks.length || p.tracks[index] !== id) {
            throw new Error('Playlist changed since it was displayed. Try again.');
          }
          p.tracks.splice(index, 1);
          return rows;
        }, 'Removed from playlist only · music and licences unchanged', playlist.id) }));
  return el('li', { class: 'playlist-item' },
    trackRow(item, id, null), buttons);
}
function playlistSection(playlist) {
  return el('section', { class: 'playlist-section', 'aria-label': 'Playlist ' + playlist.name },
    el('h2', { id: 'playlist-' + playlist.id, tabindex: '-1',
      text: playlist.name + ' · ' + playlist.tracks.length + (playlist.tracks.length === 1 ? ' song' : ' songs') }),
    el('div', { class: 'playlist-top-actions' },
      el('button', { class: 'btn primary', type: 'button', text: 'Play now (replace queue)',
        onclick: () => playWholePlaylist(playlist) }),
      el('button', { class: 'btn', type: 'button', text: 'Add playlist to queue',
        onclick: () => queueWholePlaylist(playlist) }),
      el('button', { class: 'btn', type: 'button', text: 'Rename', onclick: () => {
        const next = prompt('Rename playlist', playlist.name);
        if (next === null || next.trim() === playlist.name) return;
        savePlaylistChange(rows => {
          const p = rows.find(x => x.id === playlist.id);
          if (!p) return null;
          p.name = next.trim(); return rows;
        }, 'Playlist renamed', playlist.id);
      } }),
      el('button', { class: 'btn', type: 'button', text: 'Delete playlist', onclick: () => {
        if (!confirm('Delete playlist "' + playlist.name + '"? This only deletes the playlist; your tracks, licences and downloads remain.')) return;
        savePlaylistChange(rows => rows.filter(x => x.id !== playlist.id),
          'Playlist deleted · music and licences unchanged');
      } })),
    playlist.tracks.length ?
      el('ol', { class: 'playlist-entries' }, ...playlist.tracks.map((id,i) => playlistItem(playlist,id,i))) :
      el('p', { class: 'empty', text: 'This playlist has no tracks. Use + Playlist on a song to add music.' }));
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
    return renderLibraryView();
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
    const name = el('input', { id: 'pl-name', required: true, maxlength: '120', placeholder: 'New playlist name' });
    const out = [el('h1', { id: 'playlist-list-heading', tabindex: '-1', text: 'Playlists' }),
      el('p', { class: 'sub', text: 'Playlists are local lists of tracks, not proof of ownership or permission to listen.' }),
      el('form', { class: 'stack playlist-create', onsubmit: async e => { e.preventDefault();
        if (!name.value.trim()) return;
        const id = Array.from(crypto.getRandomValues(new Uint8Array(8)), b => b.toString(16).padStart(2, '0')).join('');
        await savePlaylistChange(rows => [...rows, { id, name: name.value.trim(), tracks: [] }],
          'Playlist created', id);
      } },
        el('label', { for: 'pl-name', text: 'Create a playlist' }, name),
        el('button', { class: 'btn primary', type: 'submit', text: 'Create playlist' }))];
    for (const p of playlists) out.push(playlistSection(p));
    if (!playlists.length) out.push(el('p', { class: 'empty', text: 'No playlists yet. Create one to organise your music.' }));
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

    // The Holochain album record is public; its optional local cover is not
    // distributed to listeners until signed artwork transport is implemented.
    const albumName = el('input', { required: true, maxlength: '200', placeholder: 'Album or EP title' });
    const coverPath = el('input', { maxlength: '1024', placeholder: '/home/you/Pictures/cover.png', autocomplete: 'off' });
    const albumSelect = el('select', {}, el('option', { value: '', text: 'Single (no album)' }));
    try {
      const { albums } = await api('/api/artist/albums', {});
      for (const a of albums) if (validAlbumId(a.album_id)) {
        albumSelect.append(el('option', { value: a.album_id, text: a.title + (a.local_artwork ? ' · local cover' : '') }));
      }
    } catch (_) { /* New or offline artist: the selection can stay empty. */ }
    const albumForm = el('form', { class: 'stack', onsubmit: async e => {
      e.preventDefault();
      const submit = albumForm.querySelector('button[type=submit]');
      submit.disabled = true;
      const result = await act('/api/artist/album', { title: albumName.value,
        artwork_path: coverPath.value.trim() || null }, 'Album created');
      submit.disabled = false;
      if (result && validAlbumId(result.album_id)) {
        albumSelect.append(el('option', { value: result.album_id, text: albumName.value +
          (result.local_artwork ? ' · local cover' : '') }));
        albumSelect.value = result.album_id;
        albumName.value = ''; coverPath.value = '';
      }
    } },
      f('Album or EP title', albumName), f('Optional PNG cover file path on this computer (RGB/RGBA, up to 1200px and 768 KiB)', coverPath),
      el('p', { class: 'muted', text: 'Artwork is PUBLIC: the image is scrubbed of metadata, artist-signed, and made available to other listeners through authenticated Holochain/MoQ hosts. Music audio remains licensed separately.' }),
      el('button', { class: 'btn', type: 'submit', text: 'Create album' }));

    form.append(f('WAV file on this computer (16-bit PCM, mono/stereo)', path), f('Track title', title),
      f('Add track to album (optional)', albumSelect), f('Rights declaration', rights),
      el('p', { class: 'muted', text: 'The file is encrypted locally (AES-256-GCM). Only ciphertext is hosted; the content key never leaves this computer. Your declaration is not a copyright verification.' }),
      el('button', { class: 'btn primary', type: 'submit', text: 'Encrypt & publish' }));
    form.addEventListener('submit', async e => { e.preventDefault(); const b = form.querySelector('button[type=submit]'); b.disabled = true; b.textContent = 'Encrypting & publishing…';
      const r = await act('/api/artist/publish', { path: path.value, title: title.value,
        album_id: albumSelect.value || null, rights_basis: rights.value }, 'Track published and hosted');
      b.disabled = false; b.textContent = 'Encrypt & publish'; if (r) show('mytracks'); });
    return [el('h1', { text: 'Artist studio' }), el('h2', { text: '1. Your profile' }), el('div', { class: 'card' }, profile),
      el('h2', { text: '2. Create an album (optional)' }), el('div', { class: 'card' }, albumForm),
      el('h2', { text: '3. Publish a track' }), el('div', { class: 'card' }, form)];
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
  if (!item || item.grant_kind !== 'perpetual-personal' || !item.offline_ready)
    return toast('A complete local copy and permanent personal-use licence are needed for WAV export.');
  // A native OS file picker is not exposed by the current loopback browser API.
  // Never pretend to show a picker or claim file writes before the API confirms.
  const path = prompt('Export licensed WAV for independent use. Enter an absolute .wav filename inside your home folder. Existing files are never overwritten:', '');
  if (!path) return;
  try {
    const result = await api('/api/export', { file_id: item.file_id, path });
    if (!result.exported) throw new Error('No completed export path was returned.');
    toast('Export complete: WAV written to ' + result.exported +
      '. Independent playback in another player has not been verified.', 'info');
  } catch (e) { toast('Export failed: ' + e.message); }
}
async function addToPlaylist(fileId) {
  try {
    const { playlists } = await api('/api/playlists');
    if (!playlists.length) return toast('Create a playlist first (Playlists).');
    const choice = prompt('Add to which playlist? Enter its number:\n' +
      playlists.map((p,i) => (i + 1) + '. ' + p.name).join('\n'), '1');
    if (choice === null) return;
    const index = Number(choice) - 1;
    if (!Number.isInteger(index) || index < 0 || index >= playlists.length) return toast('Choose a valid playlist number.');
    const target = playlists[index];
    await savePlaylistChange(rows => {
      const p = rows.find(x => x.id === target.id);
      if (!p) return null;
      if (p.tracks.includes(fileId)) { toast('Already in ' + p.name, 'info'); return null; }
      p.tracks.push(fileId); return rows;
    }, 'Added to ' + target.name);
  } catch (e) { toast('Unable to add to playlist: ' + e.message); }
}

async function render() {
  const active = document.activeElement;
  const searchActive = active && active.classList.contains('library-search') && view === 'library';
  const selectionStart = searchActive ? active.selectionStart : null;
  const selectionEnd = searchActive ? active.selectionEnd : null;
  document.querySelectorAll('.nav').forEach(b => {
    if (b.dataset.view === view) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  const host = $('view');
  try { host.replaceChildren(...(await views[view](viewArg)).filter(Boolean)); }
  catch (e) { host.replaceChildren(el('h1', { text: 'Something went wrong' }), el('p', { class: 'empty', text: e.message })); }
  // Slow library metadata refreshes must not interrupt a listener typing
  // into the scoped search field or relocate their cursor.
  if (searchActive && view === 'library') {
    const replacement = host.querySelector('.library-search');
    if (replacement) {
      replacement.focus();
      if (selectionStart !== null && selectionEnd !== null) {
        replacement.setSelectionRange(selectionStart, selectionEnd);
      }
    }
  }
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

// Keep the custom track fill aligned with the same slider value used for seeks.
// This is presentation only: dragging still sends a seek at 'change', not 'input'.
function paintSeekProgress() {
  const slider = $('seek');
  const value = Math.max(0, Math.min(1000, Number(slider.value) || 0));
  slider.style.setProperty('--seek-progress', `${value / 10}%`);
}

function renderPlayer() {
  const p = state.player; if (!p) return;
  const item = libraryById.get(p.track_key);
  const title = item ? (item.title || 'Untitled') : 'Nothing playing';
  const artist = item ? (item.artist_name || 'Unknown artist') : 'Choose a track';
  $('now-title').textContent = title;
  $('now-artist').textContent = artist;
  $('now-title').title = title;
  $('now-artist').title = artist;
  showPlayerArtwork(item);
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
  badge.title = badge.textContent;
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
  paintSeekProgress();
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
$('seek').addEventListener('input', paintSeekProgress);
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
  const before = JSON.stringify(library.map(t => [t.file_id, t.download && t.download.state, t.download && t.download.available_chunks, t.playable, t.complete]));
  await refreshLibrary();
  if (view === 'library' && before !== JSON.stringify(library.map(t => [t.file_id, t.download && t.download.state, t.download && t.download.available_chunks, t.playable, t.complete]))) render();
}
(async () => {
  if (!token) { toast('Open the private link printed by holochain-music in your terminal.'); return; }
  await poll(); await refreshLibrary();
  show(state.online ? 'browse' : 'library');
  setInterval(poll, 500); setInterval(slowPoll, 5000);
})();
