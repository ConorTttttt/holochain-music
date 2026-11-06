'use strict';
// Loopback UI. The token lives only in this tab's sessionStorage and is sent
// in the Authorization header; it is removed from the visible URL at once.
// All remote/catalogue text is inserted with textContent, never as HTML.
const urlToken = new URLSearchParams(location.hash.slice(1)).get('token');
if (urlToken) { sessionStorage.setItem('hm_token', urlToken); history.replaceState(null, '', '/'); }
const token = sessionStorage.getItem('hm_token');

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
let requestFilters = { folder: 'all', kind: 'all', status: 'pending', search: '' };
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

// ---- public cover art and artist metadata ------------------------------
const coverCache = new Map();
function genresFromInput(value) {
  const tags = value.split(',').map(x => x.trim()).filter(Boolean);
  if (tags.length > 6 || new Set(tags.map(x => x.toLocaleLowerCase())).size !== tags.length
      || tags.some(x => new TextEncoder().encode(x).length > 32 || /[\\x00-\\x1f\\x7f]/.test(x))) {
    throw new Error('Use up to 6 unique genres, each no longer than 32 bytes.');
  }
  return tags;
}
function genreBadges(genres) {
  return (genres || []).map(g => el('span', { class: 'genre-tag', text: g }));
}
function coverThumb(agent, sha, alt = '', large = false) {
  const holder = el('span', { class: large ? 'cover-art large' : 'cover-art' });
  if (!agent || !sha) { holder.append(el('span', { text: '♫', 'aria-hidden': true })); return holder; }
  const img = el('img', { alt, loading: 'lazy' });
  holder.append(img);
  const key = agent + ':' + sha;
  if (!coverCache.has(key)) {
    coverCache.set(key, api('/api/catalogue/artwork', { artist: agent, sha256: sha }).then(({ mime_type, data_base64 }) => {
      const raw = atob(data_base64);
      const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
      return URL.createObjectURL(new Blob([bytes], { type: mime_type }));
    }).catch(e => { coverCache.delete(key); throw e; }));
  }
  coverCache.get(key).then(url => { img.src = url; }).catch(() => {
    holder.replaceChildren(el('span', { text: '♫', 'aria-hidden': true }));
  });
  return holder;
}
async function uploadCover(file) {
  if (!file) return null;
  if (!file.type.startsWith('image/') || file.size > 8 * 1024 * 1024) {
    throw new Error('Choose a JPEG, PNG or WebP image under 8 MB.');
  }
  const bitmap = await createImageBitmap(file);
  try {
    if (bitmap.width > 8192 || bitmap.height > 8192 || !bitmap.width || !bitmap.height) {
      throw new Error('Invalid or oversized artwork dimensions.');
    }
    for (const size of [512, 384, 320, 256, 192, 128]) {
      const canvas = document.createElement('canvas');
      canvas.width = canvas.height = size;
      const ctx = canvas.getContext('2d');
      const crop = Math.min(bitmap.width, bitmap.height);
      ctx.drawImage(bitmap, (bitmap.width - crop) / 2, (bitmap.height - crop) / 2, crop, crop,
        0, 0, size, size);
      for (const quality of [0.78, 0.6, 0.4]) {
        const blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/webp', quality));
        if (!blob || blob.type !== 'image/webp' || blob.size > 32768) continue;
        const bytes = new Uint8Array(await blob.arrayBuffer());
        let binary = '';
        for (let i = 0; i < bytes.length; i += 8192) {
          binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
        }
        const result = await api('/api/artist/artwork', {
          mime_type: 'image/webp', data_base64: btoa(binary),
        });
        return result.artwork_sha256;
      }
    }
  } finally { bitmap.close(); }
  throw new Error('Artwork could not be compressed under the 32 KB public-cover limit.');
}
function artistField(label, control) {
  return el('label', { class: 'artist-field' }, el('span', { text: label }), control);
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
    el('div', { class: 'title release-title' },
      coverThumb(t.artist_agent, t.artwork_sha256, '', false),
      el('div', {}, el('strong', { text: t.title || 'Untitled' }),
        el('span', {}, catalogueRow ? el('a', { href: '#', text: t.artist_name || 'Unknown artist',
          onclick: e => { e.preventDefault(); show('artist', t.artist_agent); } }) : (t.artist_name || 'Unknown artist')),
        el('div', { class: 'genre-tags' }, ...genreBadges(t.genres)))),
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
      out.push(el('div', { class: 'album-heading' },
        coverThumb(agent, album.artwork_sha256, album.title + ' cover', true),
        el('div', {}, el('h2', { text: `${album.title}${album.release_date ? ' · ' + album.release_date : ''}` }),
          el('div', { class: 'genre-tags' }, ...genreBadges(album.genres)))));
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
    const genres = el('input', { maxlength: '220', placeholder: 'e.g. Electronic, Ambient, Downtempo' });
    const artwork = el('input', { type: 'file', accept: 'image/jpeg,image/png,image/webp' });
    const trackNumber = el('input', { type: 'number', min: 1, max: 999, value: '1' });
    const { albums } = state.online ? await api('/api/catalogue/artist', { agent: state.agent }) : { albums: [] };
    const album = el('select', {}, el('option', { value: '', text: 'Release as a single' }),
      ...albums.map(a => el('option', { value: a.album_id, text: a.title })));
    const name = el('input', { maxlength: '120', placeholder: 'Artist name shown to listeners' });
    const bio = el('textarea', { maxlength: '2048', rows: '3' });
    const profile = el('form', { class: 'stack', onsubmit: async e => { e.preventDefault();
      await act('/api/artist/profile', { display_name: name.value, biography: bio.value }, 'Artist profile published'); } },
      f('Artist name', name), f('Biography', bio), el('button', { class: 'btn', type: 'submit', text: 'Save profile' }));
    form.append(f('WAV file on this computer (16-bit PCM, mono/stereo)', path), f('Track title', title), f('Rights declaration', rights),
      f('Genres (comma-separated, max 6)', genres), f('Cover artwork (optional; JPEG, PNG or WebP)', artwork),
      f('Album', album), f('Track number (if part of an album)', trackNumber),
      el('p', { class: 'muted', text: 'Audio is encrypted locally. Covers are public and resized before publication. Your declaration is not a copyright verification.' }),
      el('button', { class: 'btn primary', type: 'submit', text: 'Encrypt & publish' }));
    form.addEventListener('submit', async e => {
      e.preventDefault(); const b = form.querySelector('button[type=submit]'); b.disabled = true; b.textContent = 'Publishing…';
      try {
        const tags = genresFromInput(genres.value);
        const cover = await uploadCover(artwork.files[0]);
        const r = await api('/api/artist/publish', {
          path: path.value, title: title.value, rights_basis: rights.value,
          genres: tags, artwork_sha256: cover, album_id: album.value || null,
          track_number: Number(trackNumber.value),
        });
        if (r) { toast('Track published with its metadata', 'info'); await refreshLibrary(); show('mytracks'); }
      } catch (err) { toast(err.message); }
      finally { b.disabled = false; b.textContent = 'Encrypt & publish'; }
    });
    return [el('h1', { text: 'Artist studio' }), el('h2', { text: '1. Your profile' }), el('div', { class: 'card' }, profile),
      el('h2', { text: '2. Publish a track' }), el('div', { class: 'card' }, form),
      el('button', { class: 'btn', type: 'button', text: 'Create an album from existing songs',
        onclick: () => show('albums') })];
  },
  async mytracks() {
    const { tracks } = await api('/api/artist/tracks', {});
    return [el('h1', { text: 'Your releases' }), el('p', { class: 'sub', text: 'Hosted by this computer over pinned MoQ/QUIC while the app is running.' }),
      list(tracks.map(t => el('div', { class: 'row' }, el('div', { class: 'title' }, el('strong', { text: t.title }), el('span', { class: 'mono', text: t.file_id })),
        el('div', { text: new Date(t.published_at * 1000).toLocaleDateString() }), el('div', { class: 'muted', text: fmt(t.duration_ms) }), el('div'))), 'You have not published anything yet.')];
  },
  async requests() {
    const { requests } = await api('/api/artist/requests', {});
    const filters = requestFilters;
    let busy = false;
    const folders = new Map(requests.map(r => [r.file_id, r.track_title]));
    const select = (label, options, value, onChange) => {
      const field = el('label', { class: 'request-filter' }, el('span', { text: label }));
      const input = el('select', { 'aria-label': label }, ...options.map(([v, name]) =>
        el('option', { value: v, text: name })));
      input.value = value;
      input.addEventListener('change', () => onChange(input.value));
      field.append(input);
      return field;
    };
    const statusFilter = select('Status', [['pending', 'Pending'], ['approved', 'Approved'],
      ['declined', 'Declined'], ['all', 'All statuses']], filters.status, v => { filters.status = v; paint(); });
    const kindFilter = select('Request type', [['all', 'All types'], ['stream', '24-hour streaming'],
      ['perpetual-personal', 'Permanent personal licence']], filters.kind, v => { filters.kind = v; paint(); });
    const folderFilter = select('Track folder', [['all', 'All folders'], ...[...folders]
      .sort((a, b) => a[1].localeCompare(b[1])).map(([id, title]) => [id, title + ' · ' + id.slice(0, 8)])],
      filters.folder, v => { filters.folder = v; paint(); });
    const search = el('input', { type: 'search', maxlength: '120', value: filters.search,
      placeholder: 'Search title, listener or message', 'aria-label': 'Search access requests' });
    search.addEventListener('input', () => { filters.search = search.value; paint(); });
    const searchField = el('label', { class: 'request-filter' }, el('span', { text: 'Search' }), search);
    const summary = el('p', { class: 'sub', role: 'status' });
    const rowsHost = el('div', { class: 'tracks' });
    const progress = el('p', { class: 'muted', role: 'status', 'aria-live': 'polite' });
    const acceptAll = el('button', { class: 'btn primary', type: 'button', text: 'Accept all pending' });
    const acceptFiltered = el('button', { class: 'btn', type: 'button', text: 'Accept filtered' });
    const declineFiltered = el('button', { class: 'btn danger', type: 'button', text: 'Decline all filtered' });

    function matching() {
      const term = filters.search.trim().toLocaleLowerCase();
      return requests.filter(r => (filters.folder === 'all' || r.file_id === filters.folder)
        && (filters.status === 'all' || r.status === filters.status)
        && (filters.kind === 'all' || r.kind === filters.kind)
        && (!term || [r.track_title, r.listener_agent, r.note, r.file_id]
          .some(v => String(v || '').toLocaleLowerCase().includes(term))));
    }
    function paint() {
      const visible = matching();
      const pending = visible.filter(r => r.status === 'pending');
      const total = requests.filter(r => r.status === 'pending').length;
      summary.textContent = `${visible.length} shown · ${pending.length} pending in this view · ${total} pending overall`;
      acceptAll.disabled = busy || !total;
      acceptFiltered.disabled = declineFiltered.disabled = busy || !pending.length;
      acceptFiltered.textContent = filters.folder === 'all' ? 'Accept all filtered' : 'Accept all in this folder';
      const rows = visible.map(r => {
        const kind = r.kind === 'stream' ? '24-hour streaming' : 'Permanent personal licence';
        const badge = r.status === 'approved' ? 'badge ok' : r.status === 'declined' ? 'badge bad' : 'badge warn';
        return el('div', { class: 'row request-row' },
          el('div', { class: 'title' }, el('strong', { text: r.track_title }),
            el('span', { class: 'mono', text: r.listener_agent }),
            el('span', { class: 'muted', text: new Date(r.received_at * 1000).toLocaleString() })),
          el('div', {}, el('span', { class: 'badge', text: kind }),
            el('span', { class: badge, text: r.status[0].toUpperCase() + r.status.slice(1) })),
          el('div', { class: 'request-note', text: r.note || 'No message' }),
          r.status !== 'pending' ? el('div', { class: 'muted', text: 'Decision recorded' }) :
            el('div', { class: 'actions' },
              el('button', { class: 'btn primary', type: 'button', text: 'Accept',
                disabled: busy, onclick: () => decide('approve', [r], false) }),
              el('button', { class: 'btn danger', type: 'button', text: 'Decline',
                disabled: busy, onclick: () => decide('decline', [r], false) })));
      });
      rowsHost.replaceChildren(...(rows.length ? rows :
        [el('p', { class: 'empty', text: 'No requests match these filters.' })]));
    }
    async function decide(action, rows, bulk) {
      if (busy) return;
      const pending = rows.filter(r => r.status === 'pending');
      if (!pending.length) return;
      const permanent = pending.filter(r => r.kind === 'perpetual-personal').length;
      const verb = action === 'approve' ? 'accept' : 'decline';
      const irreversible = action === 'approve' && permanent
        ? ` This includes ${permanent} permanent licences that cannot be revoked.` : '';
      if ((bulk || irreversible) && !window.confirm(
        `Really ${verb} ${pending.length} request(s)?${irreversible}\nOnly the listed pending requests will be affected.`)) return;
      busy = true;
      paint();
      let succeeded = 0;
      let queued = 0;
      let failed = 0;
      try {
        for (let i = 0; i < pending.length; i += 25) {
          const slice = pending.slice(i, i + 25);
          progress.textContent = `Processing ${Math.min(i + 25, pending.length)} of ${pending.length}…`;
          const result = await api('/api/artist/requests/bulk', {
            action, request_hashes: slice.map(r => r.request_hash),
          });
          succeeded += result.succeeded;
          queued += result.results.filter(x => x.ok && x.queued).length;
          failed += result.results.filter(x => !x.ok).length;
          // Do not retry automatically: a delivery may have succeeded before the HTTP reply failed.
        }
        toast(`${succeeded} ${action === 'approve' ? 'accepted' : 'declined'}${queued ? ` (${queued} delivery queued)` : ''}${failed ? `; ${failed} failed` : ''}.`,
          failed ? 'error' : 'info');
      } catch (e) {
        toast(`Batch interrupted after ${succeeded} succeeded: ${e.message}. Refresh to see which remain.`);
      } finally {
        busy = false;
        progress.textContent = '';
        await render(); // refresh statuses from the artist's private ledger
      }
    }
    acceptAll.addEventListener('click', () => decide('approve', requests, true));
    acceptFiltered.addEventListener('click', () => decide('approve', matching(), true));
    declineFiltered.addEventListener('click', () => decide('decline', matching(), true));
    paint();
    return [el('h1', { text: 'Access requests' }),
      el('p', { class: 'sub', text: 'Accept or decline individual requests, or filter by track folder, type, status and listener. Accepting grants only the access requested. Permanent personal licences allow offline export and cannot be revoked. Declines are saved privately on this computer; listeners are not yet notified.' }),
      el('div', { class: 'request-filters' }, folderFilter, kindFilter, statusFilter, searchField),
      summary, el('div', { class: 'request-bulk actions' }, acceptAll, acceptFiltered, declineFiltered),
      progress, rowsHost];
  },
  async settings() {
    const id = await api('/api/identity');
    const s = id.settings;
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
      el('h2', { text: 'Network' }), el('div', { class: 'card' }, form)];
  },
};

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
  if (p.state === 'error' && p.error && renderPlayer.lastError !== p.error) toast(p.error);
  renderPlayer.lastError = p.error;
  const playing = ['playing', 'buffering', 'seeking'].includes(p.state);
  $('btn-play').textContent = playing ? '❚❚' : '▶'; $('btn-play').setAttribute('aria-label', playing ? 'Pause' : 'Play');
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
    try { const { requests } = await api('/api/artist/requests', {}); const open = requests.filter(r => r.status === 'pending').length; const c = $('request-count'); c.hidden = !open; c.textContent = open; } catch (_) {}
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
