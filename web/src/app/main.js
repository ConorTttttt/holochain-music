// Holochain Music — experimental browser client.
// All remote/catalogue text is inserted with textContent, never as HTML.

import { loadConfig } from '../config.js';
import { MusicHolochain, State, STATE_TEXT } from '../adapters/holochain/hwc.js';
import { Catalogue } from '../adapters/catalogue/catalogue.js';
import { MediaAdapterClient } from '../adapters/media/adapter-client.js';
import { GrantStore, RequestLog, RequestOutcome, requestAccess, syncInboxGrants } from '../adapters/grants/grants.js';
import { PlayerState, TrackPlayer } from '../player/track-player.js';
import { sha256Hex } from '../security/v1.js';

const $ = id => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined) n.append(kid);
  return n;
};
const fmt = ms => { const s = Math.max(0, Math.floor((ms || 0) / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };
const short = h => (h && h.length > 20 ? `${h.slice(0, 10)}…${h.slice(-6)}` : h || '');
const diagnostics = new URLSearchParams(location.search).has('diagnostics');

const app = {
  config: null, hc: null, catalogue: null, media: null, grants: new GrantStore(), requests: new RequestLog(), lastSync: null,
  trusted: new Map(), // track key -> resolve() result
  player: null, current: null, queue: [], view: ['browse'], chunkDigests: [],
};
// Read-only developer diagnostics (public values only; no keys, no grants).
window.hmWeb = {
  get state() { return app.hc?.state; },
  get detail() { return app.hc?.detail; },
  get agent() { return app.hc?.agent; },
  get cells() { return app.hc?.cells && Object.fromEntries(Object.entries(app.hc.cells).map(([r, c]) => [r, c.dna])); },
  get gateway() { return app.hc?.gateway; },
  get player() { return app.player && { state: app.player.state, error: app.player.error, stats: { ...app.player.stats }, position: app.player.positionFrames, frames: app.player.durationFrames, format: app.player.format }; },
  get chunkDigests() { return diagnostics ? [...app.chunkDigests] : null; },
  async recipientPublicKey() { return app.hc?.agent ? (await app.grants.recipientKey(app.hc.agent)).publicHex : null; },
  // Diagnostics only (?diagnostics=1): the stored grant exactly as signed
  // (wrapped key, no secrets) and the last inbox sync summary.
  async storedGrant(fileId) { return diagnostics && app.hc?.agent ? (await app.grants.get(app.hc.agent, fileId))?.grant ?? null : null; },
  get lastSync() { return diagnostics ? app.lastSync : null; },
  get trusted() { return [...app.trusted.entries()].map(([key, t]) => ({ key, digest: t.digest, file_id: t.manifestBody.file_id, artist_key_hex: t.artistKeyHex, hosts: t.hosts.map(h => ({ url: h.url, fingerprint: h.fingerprint, node_agent: h.node_agent })) })); },
};

function toast(text, kind = 'info') {
  const t = $('toast');
  t.textContent = text;
  t.className = `toast ${kind}`;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 6000);
}

// ---- connection --------------------------------------------------------------

function renderConnection() {
  const s = app.hc?.state ?? State.CHECKING;
  const banner = $('conn-banner');
  const ok = s === State.READY;
  $('net-status').textContent = ok ? 'Connected' : (STATE_TEXT[s] || s).split('.')[0];
  $('net-status').dataset.state = s;
  document.body.dataset.connection = s;
  banner.hidden = ok;
  banner.dataset.level = [State.EXTENSION_UNAVAILABLE, State.WRONG_DNA, State.ERROR].includes(s) ? 'bad' : 'warn';
  banner.replaceChildren(el('span', { text: STATE_TEXT[s] || s }), app.hc?.detail ? el('span', { class: 'muted', text: app.hc.detail }) : null,
    s === State.EXTENSION_UNAVAILABLE ? el('a', { href: '#', text: 'How to install', onclick: e => { e.preventDefault(); show('connection'); } }) : null,
    s !== State.CHECKING && s !== State.INSTALLING && !ok ? el('button', { class: 'btn', type: 'button', text: 'Connect', onclick: connect }) : null);
  if (app.view[0] === 'connection') render();
}

async function connect() {
  await app.hc.connect();
  if (app.hc.state === State.READY) render();
}

// ---- views ---------------------------------------------------------------------

function show(...view) { app.view = view; render(); $('main').focus(); }

async function render() {
  const [name, ...args] = app.view;
  for (const b of document.querySelectorAll('.nav')) b.toggleAttribute('aria-current', b.dataset.view === name);
  const view = $('view');
  const views = { browse, artists, artist, track, library, queue, connection: connectionView, search: searchView };
  if (name !== 'connection' && app.hc?.state !== State.READY) {
    view.replaceChildren(el('h1', { text: 'Holochain Music' }),
      el('p', { class: 'muted', text: 'Browse artists and play music published on Holochain. Connect your browser identity to begin.' }),
      el('button', { class: 'btn primary', type: 'button', text: 'Open connection details', onclick: () => show('connection') }));
    return;
  }
  view.replaceChildren(el('p', { class: 'muted', text: 'Loading…' }));
  try {
    view.replaceChildren(...[await views[name](...args)].flat());
  } catch (e) {
    view.replaceChildren(el('h1', { text: 'Could not load this page' }), el('p', { class: 'notice bad', text: e.message }),
      el('button', { class: 'btn', type: 'button', text: 'Retry', onclick: render }));
  }
}

function trackRow(t) {
  const playing = app.current?.key === t.key;
  return el('div', { class: `row${playing ? ' active' : ''}`, 'data-track': t.key },
    el('div', { class: 'title' }, el('strong', { text: t.title }),
      el('span', {}, el('a', { href: '#', text: t.artist_name, onclick: e => { e.preventDefault(); show('artist', t.artist_agent); } }))),
    el('div', { class: 'album muted', text: t.audio_format }),
    el('div', { class: 'dur muted', text: fmt(t.duration_ms) }),
    el('div', { class: 'actions' },
      el('button', { class: 'btn', type: 'button', text: 'Details', onclick: () => show('track', t.artist_agent, t.track_id) }),
      el('button', { class: 'btn primary', type: 'button', text: 'Play', 'aria-label': `Play ${t.title}`, onclick: () => play(t) })));
}

const list = (rows, empty) => rows.length ? el('div', { class: 'tracks' }, rows.map(trackRow)) : el('p', { class: 'empty', text: empty });

async function browse() {
  const tracks = await app.catalogue.browse(100);
  return [el('h1', { text: 'Browse' }), list(tracks, 'No tracks are visible yet. The network may still be synchronising — try again shortly.')];
}

async function searchView(q) {
  return [el('h1', { text: `Results for “${q}”` }), list(await app.catalogue.search(q, 50), 'No matching tracks.')];
}

async function artists() {
  const all = await app.catalogue.artists();
  return [el('h1', { text: 'Artists' }), all.length ? el('div', { class: 'grid' }, all.map(a =>
    el('button', { class: 'tile', type: 'button', onclick: () => show('artist', a.agent) }, el('strong', { text: a.display_name }),
      el('span', { class: 'muted', text: a.biography.slice(0, 140) })))) : el('p', { class: 'empty', text: 'No artists are visible yet.' })];
}

async function artist(agent) {
  const [profile, albums, tracks] = await Promise.all([app.catalogue.profile(agent), app.catalogue.albums(agent), app.catalogue.artistTracks(agent)]);
  return [el('h1', { text: profile?.display_name ?? 'Unknown artist' }),
    profile?.biography ? el('p', { text: profile.biography }) : null,
    el('p', { class: 'muted provenance', text: `Holochain identity ${agent}` }),
    albums.length ? [el('h2', { text: 'Albums' }), el('div', { class: 'grid' }, albums.map(a => el('div', { class: 'tile' },
      el('strong', { text: a.title }), el('span', { class: 'muted', text: a.release_date ?? 'Unreleased' }))))] : null,
    el('h2', { text: 'Tracks' }), list(tracks, 'This artist has not published tracks yet.')];
}

async function resolveTrusted(t) {
  const cached = app.trusted.get(t.key);
  if (cached) return cached;
  const trusted = await app.catalogue.resolve(t.artist_agent, t.track_id);
  app.trusted.set(t.key, trusted);
  return trusted;
}

async function track(agent, trackId) {
  const t = await app.catalogue.track(agent, trackId);
  if (!t) return [el('h1', { text: 'Track not found' }), el('p', { class: 'muted', text: 'It may not have reached this part of the network yet.' })];
  const stored = await app.grants.get(app.hc.agent, t.file_id);
  const verify = el('div', { class: 'card' }, el('h2', { text: 'Sources' }),
    el('button', { class: 'btn', type: 'button', id: 'verify-sources', text: 'Verify artist signature and hosts', onclick: async e => {
      e.target.disabled = true;
      try {
        const trusted = await resolveTrusted(t);
        e.target.replaceWith(el('div', { class: 'notice ok', id: 'sources-verified' },
          el('strong', { text: 'Verified. ' }),
          `Signed manifest matches the artist's Holochain pin and the artist's registered key; ${trusted.hosts.length} host(s) proved they hold the encrypted file.`,
          el('dl', { class: 'kv' }, el('dt', { text: 'Manifest SHA-256' }), el('dd', { text: trusted.digest }),
            el('dt', { text: 'Artist signing key' }), el('dd', { text: trusted.artistKeyHex }),
            el('dt', { text: 'Encrypted chunks' }), el('dd', { text: String(trusted.manifestBody.chunks.length) }),
            ...trusted.hosts.flatMap(h => [el('dt', { text: 'Host' }), el('dd', { text: `${h.url} · TLS pin ${short(h.fingerprint)} · host ${short(h.node_agent)}` })]))));
      } catch (err) {
        e.target.disabled = false;
        e.target.after(el('p', { class: 'notice bad', text: err.message }));
      }
    } }));
  const access = el('div', { class: 'card', id: 'access-card' }, el('h2', { text: 'Your access' }));
  access.append(accessStatus(t, stored));
  // A pending request: look for the artist's grant in this cell's private inbox.
  if (!stored && app.requests.get(app.hc.agent, t.file_id)) doSync(t, access, { quiet: true }).catch(() => {});
  const requestBox = el('div', { class: 'actions' },
    el('button', { class: 'btn', type: 'button', text: 'Request streaming', onclick: () => doRequest(t, 'stream', access) }),
    el('button', { class: 'btn primary', type: 'button', text: 'Request licence', onclick: () => doRequest(t, 'perpetual-personal', access) }),
    el('button', { class: 'btn', type: 'button', id: 'check-grants', text: 'Check for grants', onclick: () => doSync(t, access) }));
  access.append(requestBox, importBox(t, access));
  return [el('h1', { text: t.title }), el('p', {}, el('a', { href: '#', text: t.artist_name, onclick: ev => { ev.preventDefault(); show('artist', t.artist_agent); } })),
    el('div', { class: 'actions' }, el('button', { class: 'btn primary', type: 'button', text: 'Play', onclick: () => play(t) }),
      el('button', { class: 'btn', type: 'button', text: 'Add to queue', onclick: () => { app.queue.push(t); updateQueue(); toast('Added to queue'); } })),
    el('dl', { class: 'kv provenance' },
      el('dt', { text: 'Duration' }), el('dd', { text: fmt(t.duration_ms) }),
      el('dt', { text: 'Format' }), el('dd', { text: t.audio_format }),
      el('dt', { text: 'Rights' }), el('dd', { text: t.rights_basis.replaceAll('_', ' ') + ' (artist self-declaration)' }),
      el('dt', { text: 'Artist identity' }), el('dd', { text: t.artist_agent }),
      el('dt', { text: 'Catalogue record' }), el('dd', { text: t.action_hash }),
      el('dt', { text: 'Network (DNA)' }), el('dd', { text: app.config.roles.music_catalogue }),
      el('dt', { text: 'Manifest pin' }), el('dd', { text: t.manifest_sha256 })),
    verify, access];
}

function importBox(t, access) {
  const area = el('textarea', { class: 'grant', id: 'grant-json', 'aria-label': 'Artist-issued grant JSON', placeholder: 'Paste an artist-issued grant (JSON)' });
  return el('details', { class: 'diagnostic' }, el('summary', { text: 'Recovery: import a grant file received outside Holochain' }),
    el('p', { class: 'muted', text: 'Not needed normally: the artist’s approval arrives privately through Holochain (Check for grants). Use this only if an artist sent you a grant file another way. It is checked exactly like a delivered grant: artist signature, your identity, your key and this exact track. A grant for anyone else will not work.' }),
    area, el('button', { class: 'btn', type: 'button', id: 'grant-import', text: 'Verify and import', onclick: async () => {
      try {
        const trusted = await resolveTrusted(t);
        const r = await app.grants.accept(JSON.parse(area.value), { agent: app.hc.agent, trusted, via: 'imported' });
        area.value = '';
        access.querySelector('#access-status').replaceWith(status('granted', 'ok', `Grant verified (${r.kind === 'perpetual-personal' ? 'personal-use licence' : 'streaming'}). Playback authorised.`));
      } catch (e) {
        access.querySelector('#access-status').replaceWith(status('rejected', 'bad', `Grant rejected: ${e.message}`));
      }
    } }));
}

const status = (state, cls, ...kids) => el('div', { class: `notice ${cls}`, id: 'access-status', 'data-access-state': state }, ...kids);
const KIND_TEXT = { 'perpetual-personal': 'personal-use licence', stream: 'streaming access' };

/** The access state of one track, from verified local facts only. */
function accessStatus(t, stored) {
  if (stored) {
    const expired = stored.expires_at && stored.expires_at * 1000 <= Date.now();
    if (expired) return status('expired', 'bad', `Your streaming grant expired on ${new Date(stored.expires_at * 1000).toLocaleString()}. Request access again.`);
    return status('granted', 'ok', el('strong', { text: 'Access granted. ' }),
      stored.kind === 'perpetual-personal' ? 'You hold a personal-use licence from the artist. Playback authorised.'
        : `You hold streaming access until ${new Date(stored.expires_at * 1000).toLocaleString()}. Playback authorised.`);
  }
  const pending = app.requests.get(app.hc.agent, t.file_id);
  if (pending) {
    return status('awaiting', '', el('strong', { text: 'Awaiting the artist’s decision. ' }),
      `Your request for ${KIND_TEXT[pending.kind] ?? 'access'} was delivered privately on ${new Date(pending.sent_at * 1000).toLocaleString()}. The artist decides in their own Holochain Music app; use Check for grants to see whether access has arrived.`);
  }
  return status('none', 'muted', 'You need the artist’s permission to play this track. The artist decides in their own Holochain Music app.');
}

async function doRequest(t, kind, access) {
  const box = access.querySelector('#access-status');
  box.replaceWith(status('sending', '', 'Sending your request privately to the artist…'));
  const r = await requestAccess({ holochain: app.hc, store: app.grants, agent: app.hc.agent, track: t, kind });
  let next;
  if (r.outcome === RequestOutcome.SENT) {
    app.requests.record(app.hc.agent, t.file_id, kind);
    next = status('awaiting', 'ok', el('strong', { text: 'Request delivered privately to the artist. ' }),
      'Awaiting the artist’s decision. The artist decides in their own Holochain Music app; use Check for grants to see whether access has arrived.');
  } else if (r.outcome === RequestOutcome.TRANSPORT_UNSUPPORTED) {
    next = status('unsupported', '', el('strong', { text: 'Requests cannot be sent from this browser conductor. ' }),
      'Holochain Music delivers requests privately with an authenticated Holochain remote call, which this browser conductor does not support. Nothing was sent.');
  } else if (r.outcome === RequestOutcome.UNREACHABLE) {
    next = status('unavailable', 'bad', el('strong', { text: 'Access unavailable right now. ' }),
      'The artist’s Holochain node could not be reached, so nothing was delivered. Nothing has been approved or declined; try again later.');
  } else if (r.outcome === RequestOutcome.REFUSED) {
    next = status('unavailable', 'bad', el('strong', { text: 'The artist’s node did not accept the request. ' }),
      `${r.error.replace(/^.*recipient refused:?\s*/i, '').slice(0, 200)}. This is not a decision on your request.`);
  } else {
    next = status('failed', 'bad', `Request failed: ${r.error}`);
  }
  access.querySelector('#access-status').replaceWith(next);
}

async function doSync(t, access, { quiet = false } = {}) {
  if (!quiet) access.querySelector('#access-status').replaceWith(status('checking', '', 'Checking your private inbox…'));
  const results = await syncInboxGrants({ holochain: app.hc, store: app.grants, agent: app.hc.agent,
    resolveTrusted: async (owner, fileId) => {
      const track = (await app.catalogue.artistTracks(owner)).find(x => x.file_id === fileId);
      return track ? resolveTrusted(track) : null;
    } });
  app.lastSync = results.map(r => ({ file_id: r.file_id, kind: r.kind ?? null, duplicate: r.duplicate ?? null, error: r.error ?? null }));
  const stored = await app.grants.get(app.hc.agent, t.file_id);
  const mine = results.filter(r => r.file_id === t.file_id);
  let next = accessStatus(t, stored);
  if (!stored && mine.some(r => r.error)) {
    next = status('rejected', 'bad', `A grant arrived for this track but did not verify: ${mine.find(r => r.error).error}`);
  } else if (!stored && !quiet) {
    next.append(el('span', { class: 'muted', text: ' No verified grant for this track in your private inbox yet.' }));
  }
  const current = access.querySelector('#access-status');
  if (current) current.replaceWith(next);
}

async function library() {
  const grants = await app.grants.list(app.hc.agent);
  return [el('h1', { text: 'Your access' }),
    el('p', { class: 'muted', text: 'Grants are stored in this browser exactly as the artist signed them. They only work for this browser identity.' }),
    grants.length ? el('div', { class: 'tracks' }, grants.map(g => el('div', { class: 'row' },
      el('div', { class: 'title' }, el('strong', { text: short(g.file_id) }), el('span', { class: 'muted', text: `from ${short(g.owner_agent)}` })),
      el('div', { class: 'album', text: g.kind === 'perpetual-personal' ? 'Licence' : 'Streaming' }),
      el('div', { class: 'dur muted', text: g.expires_at ? `until ${new Date(g.expires_at * 1000).toLocaleString()}` : 'no expiry' }),
      el('div', { class: 'actions' })))) : el('p', { class: 'empty', text: 'You have no grants yet.' })];
}

function queue() {
  return [el('h1', { text: 'Queue' }), list(app.queue, 'Your queue is empty.'),
    app.queue.length ? el('button', { class: 'btn', type: 'button', text: 'Clear queue', onclick: () => { app.queue = []; updateQueue(); render(); } }) : null];
}

async function connectionView() {
  const s = app.hc.state;
  const checks = [
    ['Holo Web Conductor extension available', s !== State.EXTENSION_UNAVAILABLE && s !== State.CHECKING],
    ['This site authorised in Holo Web Conductor', Boolean(app.hc.agent)],
    ['Holochain Music installed with the expected DNAs', Boolean(app.hc.cells)],
    ['Authenticated gateway session', Boolean(app.hc.gateway?.authenticated && app.hc.gateway?.hasSession)],
    ['Network reachable through the gateway', s === State.READY],
  ];
  const key = app.hc.agent ? await app.grants.recipientKey(app.hc.agent) : null;
  const adapter = await app.media.health().catch(() => null);
  return [el('h1', { text: 'Identity & network' }),
    el('div', { class: 'card' }, el('p', { id: 'conn-state', 'data-state': s, text: STATE_TEXT[s] }), app.hc.detail ? el('p', { class: 'muted', text: app.hc.detail }) : null,
      el('ul', { class: 'checklist' }, checks.map(([label, ok]) => el('li', { 'data-ok': String(ok), text: label }))),
      el('button', { class: 'btn primary', type: 'button', text: s === State.READY ? 'Reconnect' : 'Connect', onclick: connect })),
    s === State.EXTENSION_UNAVAILABLE ? el('div', { class: 'card' }, el('h2', { text: 'Install Holo Web Conductor' }),
      el('p', { text: 'This experimental release needs the Holo Web Conductor extension in a Chromium-based browser. Your operator provides the verified extension build; load it, then reload this page.' })) : null,
    el('div', { class: 'card' }, el('h2', { text: 'Your browser identity' }),
      el('dl', { class: 'kv' },
        el('dt', { text: 'Holochain agent' }), el('dd', { id: 'agent-key', text: app.hc.agent ?? 'not connected' }),
        el('dt', { text: 'Recipient key (X25519, public)' }), el('dd', { id: 'recipient-key', text: key?.publicHex ?? '—' }),
        ...Object.entries(app.hc.cells ?? {}).flatMap(([role, c]) => [el('dt', { text: `Cell ${role}` }), el('dd', { text: c.dna })]),
        el('dt', { text: 'Gateway' }), el('dd', { text: app.config.gateway_url }),
        el('dt', { text: 'Media adapter' }), el('dd', { text: `${app.config.media_adapter_url} · ${adapter ? 'reachable' : 'unreachable'}` }),
        el('dt', { text: 'Release' }), el('dd', { text: app.config.release }))),
    el('p', { class: 'muted', text: 'Your Holochain keys stay inside the Holo Web Conductor extension. Your recipient key is held by this browser and cannot be exported.' })];
}

// ---- player ------------------------------------------------------------------------

function setBadge(state, error) {
  const b = $('state-badge');
  const label = { idle: 'Idle', loading: 'Verifying…', playing: 'Playing', paused: 'Paused', buffering: 'Buffering…', ended: 'Finished', stopped: 'Stopped', error: 'Error' }[state] ?? state;
  b.textContent = label;
  b.className = `badge ${state === 'error' ? 'bad' : state === 'buffering' || state === 'loading' ? 'warn' : state === 'playing' ? 'ok' : ''}`;
  b.dataset.state = state;
  $('btn-play').textContent = state === 'playing' || state === 'buffering' ? '❚❚' : '▶';
  $('btn-play').setAttribute('aria-label', state === 'playing' ? 'Pause' : 'Play');
  if (error) toast(error, 'bad');
}

async function play(t) {
  try {
    await app.player?.stop();
    app.player = null;
    app.current = t;
    app.chunkDigests = [];
    $('now-title').textContent = t.title;
    $('now-artist').textContent = t.artist_name;
    setBadge('loading');
    const trusted = await resolveTrusted(t);
    const contentKey = await app.grants.contentKey(app.hc.agent, trusted);
    const player = new TrackPlayer({ trusted, contentKey, media: app.media, workletUrl: '/src/player/pcm-worklet.js',
      onChunk: diagnostics ? async (i, plain) => { app.chunkDigests[i] = await sha256Hex(plain); } : null });
    app.player = player;
    player.addEventListener('state', e => {
      setBadge(e.detail.state, e.detail.error);
      if (e.detail.state === PlayerState.ENDED) next();
    });
    player.addEventListener('position', updateTimeline);
    player.setVolume(Number($('volume').value) / 100);
    await player.start(0);
    $('seek').disabled = false;
    mediaSession(t);
  } catch (e) {
    setBadge('error');
    toast(e.message, 'bad');
  }
}

function updateTimeline() {
  const p = app.player;
  if (!p?.format) return;
  const rate = p.format.sampleRate;
  $('elapsed').textContent = fmt(p.positionFrames / rate * 1000);
  $('duration').textContent = fmt(p.durationFrames / rate * 1000);
  if (!updateTimeline.dragging) $('seek').value = String(Math.round(1000 * p.positionFrames / Math.max(1, p.durationFrames)));
}

function next() {
  const t = app.queue.shift();
  updateQueue();
  if (t) play(t);
}

function updateQueue() {
  $('queue-count').hidden = !app.queue.length;
  $('queue-count').textContent = String(app.queue.length);
}

function mediaSession(t) {
  if (!('mediaSession' in navigator)) return;
  navigator.mediaSession.metadata = new MediaMetadata({ title: t.title, artist: t.artist_name, album: 'Holochain Music' });
  navigator.mediaSession.setActionHandler('play', () => app.player?.resume());
  navigator.mediaSession.setActionHandler('pause', () => app.player?.pause());
  navigator.mediaSession.setActionHandler('stop', () => app.player?.stop());
  navigator.mediaSession.setActionHandler('nexttrack', next);
}

function skip(seconds) {
  const p = app.player;
  if (p?.format) p.seek(p.positionFrames + seconds * p.format.sampleRate);
}

function wire() {
  for (const b of document.querySelectorAll('.nav')) b.addEventListener('click', () => show(b.dataset.view));
  $('search-form').addEventListener('submit', e => { e.preventDefault(); const q = $('search').value.trim(); if (q.length >= 2) show('search', q); });
  $('btn-play').addEventListener('click', () => {
    const p = app.player;
    if (!p) { if (app.queue.length) next(); return; }
    if (p.state === PlayerState.PLAYING || p.state === PlayerState.BUFFERING) p.pause();
    else if (p.state === PlayerState.PAUSED) p.resume();
    else if (app.current) play(app.current);
  });
  $('btn-stop').addEventListener('click', () => app.player?.stop());
  $('btn-back').addEventListener('click', () => skip(-10));
  $('btn-fwd').addEventListener('click', () => skip(10));
  $('btn-next').addEventListener('click', next);
  $('volume').addEventListener('input', e => app.player?.setVolume(Number(e.target.value) / 100));
  $('seek').addEventListener('pointerdown', () => { updateTimeline.dragging = true; });
  $('seek').addEventListener('change', e => {
    updateTimeline.dragging = false;
    const p = app.player;
    if (p?.format) p.seek(Number(e.target.value) / 1000 * p.durationFrames);
  });
  document.addEventListener('keydown', e => {
    if (e.target.closest('input, textarea, select')) return;
    if (e.key === '/') { e.preventDefault(); $('search').focus(); }
    else if (e.key === ' ') { e.preventDefault(); $('btn-play').click(); }
    else if (e.key === 'ArrowLeft') skip(-10);
    else if (e.key === 'ArrowRight') skip(10);
    else if (e.key.toLowerCase() === 'n') next();
  });
}

async function main() {
  wire();
  try {
    app.config = await loadConfig();
  } catch (e) {
    $('view').replaceChildren(el('h1', { text: 'Holochain Music is not configured' }), el('p', { class: 'notice bad', text: e.message }));
    return;
  }
  app.hc = new MusicHolochain(app.config);
  app.media = new MediaAdapterClient(app.config.media_adapter_url);
  app.catalogue = new Catalogue(app.hc, app.media, { allowLan: app.config.allow_lan_hosts });
  app.hc.addEventListener('state', () => { renderConnection(); if (app.hc.state === State.READY && app.view[0] !== 'connection') render(); });
  renderConnection();
  render();
  // A returning visitor reconnects automatically; a new one confirms in HWC's own window.
  await app.hc.connect();
}

main();
