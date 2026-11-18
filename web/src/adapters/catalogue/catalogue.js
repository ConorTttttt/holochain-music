// Music catalogue over the browser's own Holochain cells.
//
// Port of holochain_music/catalogue.py. Records come from the listener's own
// HWC cells running the unchanged Music coordinator zomes; `author` is the
// action author reported by that zome. Every record is re-validated here
// (track schema, author == claimed artist) and nothing in browsing authorises
// playback. Playback trust is established by resolve(), which follows the
// same chain as the desktop player:
//   track (artist-authored) -> unique owner key binding -> file commitment
//   -> host replica claims -> host key binding -> host MoQ endpoints
//   -> signed manifest (digest == track pin, artist signature)
//   -> host receipt (host signature, claim receipt digest).
// Known limit: HWC does not yet re-verify action signatures on records the
// gateway returns (see docs/web/security.md).

import { holoHashB64, holoHashBytes, toHex } from '../../security/bytes.js';
import * as v1 from '../../security/v1.js';

export const MAX_HOSTS_TRIED = 8;

export class ResolveError extends Error {}

function authored(row) {
  if (!row || typeof row.author !== 'string' || !row.body) return null;
  return { author: row.author, action_hash: holoHashB64(row.action_hash), body: row.body };
}

function cleanText(value, max) {
  return typeof value === 'string' ? value.slice(0, max) : '';
}

/** Canonical HTTPS IPv4:port, loopback or (opt-in) RFC1918 — moq_conductor._bound_local_url. */
export function boundHostUrl(value, allowLan) {
  if (typeof value !== 'string' || value.length > 80) return null;
  const m = /^https:\/\/((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})$/.exec(value);
  if (!m) return null;
  const port = Number(m[2]);
  if (port < 1 || port > 65535 || String(port) !== m[2]) return null;
  const octets = m[1].split('.');
  if (octets.some(o => (o.length > 1 && o.startsWith('0')) || Number(o) > 255)) return null;
  const [a, b] = octets.map(Number);
  if (m[1] === '127.0.0.1') return value;
  const lan = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  return allowLan && lan ? value : null;
}

export class Catalogue {
  constructor(holochain, media, { allowLan = false } = {}) {
    this.hc = holochain;
    this.media = media;
    this.allowLan = allowLan;
    this._profiles = new Map();
  }

  async _records(role, fn, payload) {
    const rows = await this.hc.call(role, fn, payload);
    return (Array.isArray(rows) ? rows : []).map(authored).filter(Boolean);
  }

  async _record(role, fn, payload) {
    const row = await this.hc.call(role, fn, payload);
    return row ? authored(row) : null;
  }

  _cleanTrack(r) {
    try {
      v1.validateTrack(r.body, r.author);
    } catch {
      return null;
    }
    const b = r.body;
    return {
      key: `${r.author}:${b.track_id}`, artist_agent: r.author, action_hash: r.action_hash, track_id: b.track_id,
      album_id: b.album_id, title: b.title, duration_ms: b.duration_ms, disc_number: b.disc_number,
      track_number: b.track_number, audio_format: b.audio_format, file_id: b.file_id,
      manifest_sha256: b.manifest_sha256, rights_basis: b.rights_basis, record: b,
    };
  }

  async profile(agent) {
    const cached = this._profiles.get(agent);
    if (cached && Date.now() - cached.at < 60000) return cached.value;
    const r = await this._record('music_catalogue', 'get_artist_profile', holoHashBytes(agent));
    let value = null;
    if (r && r.author === agent && r.body.artist_agent === agent && r.body.schema === v1.ARTIST_SCHEMA) {
      value = { agent, display_name: cleanText(r.body.display_name, 120), biography: cleanText(r.body.biography, 2048), action_hash: r.action_hash };
      this._profiles.set(agent, { at: Date.now(), value }); // never cache absence
    }
    return value;
  }

  async _decorate(tracks) {
    for (const t of tracks) {
      const p = await this.profile(t.artist_agent).catch(() => null);
      t.artist_name = p ? p.display_name : 'Unknown artist';
    }
    return tracks;
  }

  async artists() {
    const out = [];
    for (const r of await this._records('music_catalogue', 'list_artists', null)) {
      if (r.body.artist_agent === r.author && r.body.schema === v1.ARTIST_SCHEMA) {
        const value = { agent: r.author, display_name: cleanText(r.body.display_name, 120), biography: cleanText(r.body.biography, 2048), action_hash: r.action_hash };
        this._profiles.set(r.author, { at: Date.now(), value });
        out.push(value);
      }
    }
    return out;
  }

  async browse(limit = 100) {
    const rows = (await this._records('music_catalogue', 'browse_tracks', limit)).map(r => this._cleanTrack(r));
    return this._decorate(rows.filter(Boolean));
  }

  async search(query, limit = 50) {
    const q = String(query).trim();
    if (q.length < 2 || q.length > 80) return [];
    const rows = (await this._records('music_catalogue', 'search_tracks', { query: q, limit })).map(r => this._cleanTrack(r));
    return this._decorate(rows.filter(Boolean));
  }

  async artistTracks(agent) {
    const rows = (await this._records('music_catalogue', 'list_tracks', holoHashBytes(agent))).map(r => this._cleanTrack(r));
    return this._decorate(rows.filter(t => t && t.artist_agent === agent));
  }

  async albums(agent) {
    const out = [];
    for (const r of await this._records('music_catalogue', 'list_albums', holoHashBytes(agent))) {
      const b = r.body;
      if (r.author === agent && b.artist_agent === agent && b.schema === v1.ALBUM_SCHEMA && /^[0-9a-f]{32}$/.test(b.album_id)) {
        out.push({ album_id: b.album_id, title: cleanText(b.title, 200), release_date: b.release_date ?? null, artist_agent: agent });
      }
    }
    return out;
  }

  async albumTracks(agent, albumId) {
    const rows = (await this._records('music_catalogue', 'list_album_tracks', { artist: holoHashBytes(agent), album_id: albumId }))
      .map(r => this._cleanTrack(r));
    return this._decorate(rows.filter(t => t && t.artist_agent === agent && t.album_id === albumId));
  }

  async track(agent, trackId) {
    const r = await this._record('music_catalogue', 'get_track', { artist: holoHashBytes(agent), track_id: trackId });
    if (!r || r.author !== agent) return null;
    const t = this._cleanTrack(r);
    return t ? (await this._decorate([t]))[0] : null;
  }

  /** Owner-manifest key for an artist, exactly one binding (catalogue._unique_key). */
  async artistKey(agent) {
    const bindings = await this._records('music_storage', 'get_signing_keys', holoHashBytes(agent));
    return v1.uniqueKey(bindings, agent, v1.OWNER_PURPOSE);
  }

  /**
   * Establish playback trust for one track (catalogue.Catalogue.resolve).
   * Returns { track, artistKey, artistKeyHex, binding, commitment, manifest, manifestBody, digest, hosts[], provenance }.
   */
  async resolve(artistAgent, trackId, { signal } = {}) {
    const trackRecord = await this._record('music_catalogue', 'get_track', { artist: holoHashBytes(artistAgent), track_id: trackId });
    if (!trackRecord || trackRecord.author !== artistAgent) throw new ResolveError('track not found in the authenticated catalogue');
    v1.validateTrack(trackRecord.body, artistAgent);
    const track = trackRecord.body;
    let owner;
    try {
      owner = await this.artistKey(artistAgent);
    } catch (e) {
      throw new ResolveError(e.message);
    }
    const { file_id: fileId, manifest_sha256: digest } = track;
    const commitments = (await this._records('music_storage', 'get_file_commitments', holoHashBytes(artistAgent)))
      .filter(c => c.body.file_id === fileId && c.body.manifest_sha256 === digest);
    if (!commitments.length) throw new ResolveError('artist has not committed to this encrypted file');
    const commitment = commitments[0];
    const claims = await this._records('music_storage', 'get_replica_claims', { owner_agent: artistAgent, file_id: fileId });
    const errors = [];
    let trusted = null;
    let tried = 0;
    for (const claim of [...claims].reverse()) {
      const node = claim.author;
      if (claim.body.node_agent !== node || claim.body.manifest_sha256 !== digest) continue;
      if (tried >= MAX_HOSTS_TRIED) break;
      tried++;
      try {
        const nodeBindings = await this._records('music_storage', 'get_signing_keys', holoHashBytes(node));
        const nodeKey = v1.uniqueKey(nodeBindings, node, v1.HOST_PURPOSE);
        const endpoints = [];
        for (const e of [...await this._records('music_storage', 'get_moq_endpoints', holoHashBytes(node))].reverse()) {
          const b = e.body;
          if (e.author !== node || b.schema !== v1.MOQ_ENDPOINT_SCHEMA || b.node_agent !== node || b.owner_agent !== artistAgent
              || b.file_id !== fileId || b.manifest_sha256 !== digest || !/^[0-9a-f]{64}$/.test(b.cert_fingerprint_hex)) continue;
          const url = boundHostUrl(b.url, this.allowLan);
          if (url && !endpoints.some(x => x.url === url && x.fingerprint === b.cert_fingerprint_hex)) {
            endpoints.push({ node_agent: node, node_key_hex: toHex(nodeKey.key), url, fingerprint: b.cert_fingerprint_hex, endpoint_action: e.action_hash });
          }
        }
        for (const candidate of endpoints.slice(0, 3)) {
          try {
            let manifest = trusted?.manifest;
            let manifestBody = trusted?.manifestBody;
            if (!trusted) {
              manifest = await this.media.document(candidate, fileId, 'manifest', { signal });
              if (await v1.manifestDigest(manifest) !== digest) throw new ResolveError("host served a manifest that does not match the artist's pin");
              manifestBody = await v1.verifyTrackManifest(track, manifest, artistAgent, owner.key);
              await v1.verifyOwnedManifest(manifest, artistAgent, owner.record, commitment);
            }
            const receipt = await this.media.document(candidate, fileId, 'receipt', { signal });
            await v1.verifyReplicaClaim(receipt, manifest, artistAgent, node, owner.record, nodeKey.record, commitment, claim);
            if (!trusted) {
              trusted = {
                track, artistAgent, artistKey: owner.key, artistKeyHex: toHex(owner.key), binding: owner.record, commitment,
                manifest, manifestBody, digest, hosts: [],
                provenance: { track_action: trackRecord.action_hash, binding_action: owner.record.action_hash, commitment_action: commitment.action_hash },
              };
            }
            trusted.hosts.push({ ...candidate, claim_action: claim.action_hash });
            break;
          } catch (e) {
            errors.push(e.message);
          }
        }
      } catch (e) {
        errors.push(e.message);
      }
    }
    if (!trusted || !trusted.hosts.length) {
      throw new ResolveError(`track unavailable: ${errors.at(-1) ?? 'no host has published this track'}`.slice(0, 240));
    }
    return trusted;
  }
}
