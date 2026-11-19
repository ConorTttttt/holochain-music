// Holochain Music v1 verification and decryption, in the listener's browser.
//
// Byte-compatible with the native Python implementation:
//   holochain_storage/package.py         (signed S1 manifest, chunk AAD)
//   holochain_storage/holochain_identity.py (S2 key bindings, owner commitment, replica claim)
//   music_catalogue/contract.py          (track record validation)
//   music_catalogue/content_grants.py    (v1 grant + personal licence unwrap)
//
// Primitives come from the platform WebCrypto implementation only
// (Ed25519, X25519, HKDF-SHA-256, AES-256-GCM, SHA-256). No cryptographic
// algorithm is implemented here. Nothing in this module logs key material.

import { canonical } from './canonical.js';
import { concat, equalBytes, fromB64, fromHex, isHex, toHex, u64be } from './bytes.js';

const subtle = globalThis.crypto.subtle;
const utf8 = new TextEncoder();

export const PACKAGE_SCHEMA = 'holochain-storage/encrypted-package/v1';
export const RECEIPT_SCHEMA = 'holochain-storage/replica-receipt/v1';
export const KEY_SCHEMA = 'holochain-storage/key-binding/v1';
export const FILE_SCHEMA = 'holochain-storage/file-commitment/v1';
export const REPLICA_SCHEMA = 'holochain-storage/replica-claim/v1';
export const MOQ_ENDPOINT_SCHEMA = 'holochain-storage/moq-endpoint/v1';
export const TRACK_SCHEMA = 'holochain-music/track/v1';
export const ARTIST_SCHEMA = 'holochain-music/artist/v1';
export const ALBUM_SCHEMA = 'holochain-music/album/v1';
export const GRANT_SCHEMA = 'holochain-music/content-grant/v1';
export const LICENCE_SCHEMA = 'holochain-music/personal-licence/v1';
export const LICENCE_TERMS = 'perpetual-personal-use';
export const OWNER_PURPOSE = 'owner-manifest';
export const HOST_PURPOSE = 'host-receipt';

export const MAX_CHUNK_BYTES = 4 * 1024 * 1024;
export const MAX_CHUNKS = 16_384;
export const MAX_FILE_BYTES = 64 * 1024 ** 3;
export const MAX_MANIFEST_BYTES = 8 * 1024 * 1024;
export const MAX_RECEIPT_BYTES = 16 * 1024;
export const MAX_GRANT_BYTES = 4096;
export const MAX_LIFETIME_SECONDS = 86400;
export const CLOCK_SKEW_SECONDS = 120;

export class VerificationError extends Error {}
export class GrantError extends VerificationError {}

const fail = (message, Kind = VerificationError) => { throw new Kind(message); };
const isInt = v => Number.isSafeInteger(v);
const isPlain = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const sameKeys = (obj, keys) => isPlain(obj) && Object.keys(obj).length === keys.length && keys.every(k => Object.hasOwn(obj, k));

export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
}

/** sha256(canonical(signed_manifest)) — the value pinned in Track/FileCommitment. */
export async function manifestDigest(signedManifest) {
  return sha256Hex(canonical(signedManifest));
}

async function ed25519Verify(publicKey, signature, message) {
  const key = await subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
  return subtle.verify({ name: 'Ed25519' }, key, signature, message);
}

/** holochain_storage.package._verify_signed */
export async function verifySigned(payload, trustedSigner, kind) {
  if (!sameKeys(payload, ['body', 'signer', 'signature'])) fail(`invalid signed ${kind}`);
  let signer;
  try {
    signer = fromB64(payload.signer, 32);
  } catch {
    fail(`invalid signed ${kind}`);
  }
  if (!(trustedSigner instanceof Uint8Array) || trustedSigner.length !== 32 || !equalBytes(signer, trustedSigner)) {
    fail(`untrusted ${kind} signer`);
  }
  let body;
  try {
    body = canonical(payload.body);
  } catch {
    fail(`invalid ${kind} signature`);
  }
  if (body.length > MAX_MANIFEST_BYTES) fail(`${kind} exceeds size limit`);
  let ok = false;
  try {
    ok = await ed25519Verify(signer, fromB64(payload.signature, 64), body);
  } catch {
    ok = false;
  }
  if (!ok) fail(`invalid ${kind} signature`);
  if (!isPlain(payload.body)) fail(`invalid ${kind} body`);
  return payload.body;
}

/** holochain_storage.package._assert_manifest */
export function assertManifest(m) {
  if (!sameKeys(m, ['schema', 'file_id', 'cipher', 'chunk_size', 'total_plain_bytes', 'chunks'])
      || m.schema !== PACKAGE_SCHEMA || m.cipher !== 'AES-256-GCM') fail('invalid package schema');
  if (!isHex(m.file_id, 64)) fail('invalid sha256 digest');
  const { chunk_size: size, total_plain_bytes: total, chunks } = m;
  if (!isInt(size) || size < 1 || size > MAX_CHUNK_BYTES) fail('invalid chunk size');
  if (!isInt(total) || total < 0 || total > MAX_FILE_BYTES) fail('invalid package length');
  if (!Array.isArray(chunks) || chunks.length > MAX_CHUNKS || (chunks.length === 0 && total !== 0)) {
    fail('invalid number of package chunks');
  }
  let running = 0;
  const nonces = new Set();
  chunks.forEach((c, i) => {
    if (!sameKeys(c, ['index', 'sha256', 'cipher_bytes', 'plain_bytes', 'nonce'])) fail('invalid chunk structure');
    if (!isInt(c.index) || c.index !== i) fail('invalid chunk index');
    if (!isHex(c.sha256, 64)) fail('invalid sha256 digest');
    let nonce;
    try {
      nonce = fromB64(c.nonce, 12);
    } catch {
      fail('invalid chunk nonce');
    }
    const key = toHex(nonce);
    if (nonces.has(key)) fail('nonce reused in package');
    nonces.add(key);
    if (!isInt(c.plain_bytes) || c.plain_bytes < 1 || c.plain_bytes > size) fail('invalid plaintext chunk size');
    if (!isInt(c.cipher_bytes) || c.cipher_bytes !== c.plain_bytes + 16) fail('invalid ciphertext length');
    if (i < chunks.length - 1 && c.plain_bytes !== size) fail('short nonfinal chunk');
    running += c.plain_bytes;
  });
  if (running !== total) fail('manifest length mismatch');
}

/** music_catalogue.contract.validate_track — display AND playback gate. */
const PY_SPACE = new Set([...'\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0     　'].concat(
  Array.from({ length: 11 }, (_, i) => String.fromCharCode(0x2000 + i))));
const pyStripped = s => s.length > 0 && !PY_SPACE.has(s[0]) && !PY_SPACE.has(s[s.length - 1]);
const TRACK_KEYS = ['schema', 'artist_agent', 'track_id', 'album_id', 'title', 'duration_ms', 'disc_number',
  'track_number', 'audio_format', 'file_id', 'manifest_sha256', 'rights_basis'];
const FORMATS = new Set(['audio/mpeg', 'audio/flac', 'audio/ogg', 'audio/mp4', 'audio/wav']);
const RIGHTS = new Set(['original_owner', 'licensed_by_rights_holder']);

export function validateTrack(track, author) {
  if (!sameKeys(track, TRACK_KEYS)) fail('invalid track fields');
  if (typeof author !== 'string' || !author || track.artist_agent !== author) fail('track publisher does not match authenticated author');
  if (track.schema !== TRACK_SCHEMA || !isHex(track.track_id, 32)) fail('invalid track schema/id');
  if (track.album_id !== null && !isHex(track.album_id, 32)) fail('invalid album id');
  const t = track.title;
  if (typeof t !== 'string' || !t || !pyStripped(t) || utf8.encode(t).length > 200
      || [...t].some(c => c.codePointAt(0) < 32 || c.codePointAt(0) === 127)) fail('invalid title');
  for (const [k, lo, hi] of [['duration_ms', 1, 86_400_000], ['disc_number', 1, 99], ['track_number', 1, 999]]) {
    if (!isInt(track[k]) || track[k] < lo || track[k] > hi) fail(`invalid ${k}`);
  }
  if (!FORMATS.has(track.audio_format) || !RIGHTS.has(track.rights_basis)) fail('invalid audio format or rights declaration');
  for (const k of ['file_id', 'manifest_sha256']) if (!isHex(track[k], 64)) fail(`invalid ${k}`);
}

/** holochain_identity._verified_claim + key_for_agent */
function verifiedClaim(record, expectedAuthor, schema, fields) {
  if (!record || typeof expectedAuthor !== 'string' || !expectedAuthor) fail('missing authenticated Holochain record/agent');
  if (record.author !== expectedAuthor || typeof record.action_hash !== 'string' || !record.action_hash) fail('Holochain action author mismatch');
  if (!sameKeys(record.body, fields) || record.body.schema !== schema) fail('invalid Holochain storage record');
  return record.body;
}

export function keyForAgent(record, agent, purpose) {
  if (purpose !== OWNER_PURPOSE && purpose !== HOST_PURPOSE) fail('unsupported signing key purpose');
  const body = verifiedClaim(record, agent, KEY_SCHEMA, ['schema', 'agent', 'purpose', 'signing_key_hex']);
  if (body.agent !== agent || body.purpose !== purpose) fail('signing key not bound to expected agent/purpose');
  if (!isHex(body.signing_key_hex, 64)) fail('invalid 32-byte hex field');
  return fromHex(body.signing_key_hex, 32);
}

/** catalogue._unique_key: all bindings must agree on exactly one key. */
export function uniqueKey(records, agent, purpose) {
  const keys = new Map();
  for (const r of records) {
    try {
      const k = keyForAgent(r, agent, purpose);
      keys.set(toHex(k), { key: k, record: r });
    } catch {
      // Malformed or foreign records are ignored, as natively.
    }
  }
  if (keys.size !== 1) fail(`${keys.size === 0 ? 'no' : 'ambiguous'} ${purpose} key binding for agent`);
  return [...keys.values()][0];
}

/** holochain_identity.verify_owned_manifest */
export async function verifyOwnedManifest(pkg, ownerAgent, keyBinding, commitment) {
  const body = verifiedClaim(commitment, ownerAgent, FILE_SCHEMA, ['schema', 'owner_agent', 'file_id', 'manifest_sha256']);
  const ownerKey = keyForAgent(keyBinding, ownerAgent, OWNER_PURPOSE);
  const manifest = await verifySigned(pkg, ownerKey, 'manifest');
  assertManifest(manifest);
  if (body.owner_agent !== ownerAgent || body.file_id !== manifest.file_id || body.manifest_sha256 !== await manifestDigest(pkg)) {
    fail('owner commitment does not match signed manifest');
  }
  return manifest;
}

/** holochain_storage.package.verify_receipt */
export async function verifyReceipt(receipt, pkg, trustedNode, trustedArtist) {
  const body = await verifySigned(receipt, trustedNode, 'receipt');
  const manifestBody = await verifySigned(pkg, trustedArtist, 'manifest');
  assertManifest(manifestBody);
  if (!sameKeys(body, ['schema', 'file_id', 'manifest_sha256', 'chunk_count', 'received_at'])) fail('invalid receipt format');
  if (body.schema !== RECEIPT_SCHEMA || body.file_id !== manifestBody.file_id || body.manifest_sha256 !== await manifestDigest(pkg)) {
    fail('receipt references different package');
  }
  if (!isInt(body.chunk_count) || body.chunk_count !== manifestBody.chunks.length) fail('receipt chunk count mismatch');
  // Python: datetime.fromisoformat with a mandatory UTC offset.
  if (typeof body.received_at !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?([+-]\d{2}:\d{2}|Z)$/.test(body.received_at)
      || Number.isNaN(Date.parse(body.received_at))) fail('invalid receipt timestamp');
  return body;
}

/** holochain_identity.verify_replica_claim */
export async function verifyReplicaClaim(receipt, pkg, ownerAgent, nodeAgent, ownerKeyBinding, nodeKeyBinding, ownerCommitment, nodeClaim) {
  const manifest = await verifyOwnedManifest(pkg, ownerAgent, ownerKeyBinding, ownerCommitment);
  const nodeKey = keyForAgent(nodeKeyBinding, nodeAgent, HOST_PURPOSE);
  const ownerKey = keyForAgent(ownerKeyBinding, ownerAgent, OWNER_PURPOSE);
  const receiptBody = await verifyReceipt(receipt, pkg, nodeKey, ownerKey);
  const claim = verifiedClaim(nodeClaim, nodeAgent, REPLICA_SCHEMA,
    ['schema', 'node_agent', 'owner_agent', 'file_id', 'manifest_sha256', 'receipt_sha256']);
  if (claim.node_agent !== nodeAgent || claim.owner_agent !== ownerAgent || claim.file_id !== manifest.file_id
      || claim.manifest_sha256 !== await manifestDigest(pkg) || claim.receipt_sha256 !== await sha256Hex(canonical(receipt))) {
    fail('storage node claim does not match receipt/package');
  }
  return receiptBody;
}

/** music_catalogue.contract.verify_track_manifest */
export async function verifyTrackManifest(track, signedManifest, author, trustedSigner) {
  validateTrack(track, author);
  let body;
  let digest;
  try {
    body = await verifySigned(signedManifest, trustedSigner, 'manifest');
    assertManifest(body);
    digest = await manifestDigest(signedManifest);
  } catch (e) {
    fail(`signed encrypted manifest verification failed: ${e.message}`);
  }
  if (body.file_id !== track.file_id || digest !== track.manifest_sha256) fail('track references a different signed encrypted manifest');
  return body;
}

// ---- encrypted chunks ------------------------------------------------------

/** holochain_storage.package._aad */
export function chunkAad(fileId, index) {
  return concat(utf8.encode('holochain-storage/chunk/v1\x00'), fromHex(fileId, 32), u64be(index));
}

/** Length + SHA-256 against the signed manifest (what the host/adapter claims is irrelevant). */
export async function verifyChunk(chunk, data) {
  if (!(data instanceof Uint8Array) || data.length !== chunk.cipher_bytes || await sha256Hex(data) !== chunk.sha256) {
    fail(`ciphertext length/SHA-256 mismatch at chunk ${chunk.index}`);
  }
}

/** Verify ciphertext, then AES-GCM-decrypt with the file/index-bound AAD. */
export async function decryptChunk(contentKey, manifestBody, index, data) {
  if (!isInt(index) || index < 0 || index >= manifestBody.chunks.length) fail('chunk index outside signed manifest');
  const chunk = manifestBody.chunks[index];
  await verifyChunk(chunk, data);
  let plain;
  try {
    plain = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(chunk.nonce, 12), additionalData: chunkAad(manifestBody.file_id, index), tagLength: 128 },
      contentKey, data));
  } catch {
    fail('AES-GCM rejected content key or chunk');
  }
  if (plain.length !== chunk.plain_bytes) fail('invalid authenticated plaintext length');
  return plain;
}

// ---- grants and licences (music_catalogue/content_grants.py) ----------------

const GRANT_FIELDS = ['schema', 'owner_agent', 'listener_agent', 'file_id', 'manifest_sha256', 'recipient_key_hex',
  'ephemeral_key_hex', 'salt_b64', 'nonce_b64', 'wrapped_key_b64', 'issued_at', 'expires_at'];
const LICENCE_FIELDS = GRANT_FIELDS.filter(f => f !== 'expires_at').concat(['licence_id', 'terms']);

export function grantContext(body) {
  return concat(utf8.encode('holochain-music/content-grant/hkdf-aad/v1\x00'), canonical({
    schema: body.schema, owner_agent: body.owner_agent, listener_agent: body.listener_agent, file_id: body.file_id,
    manifest_sha256: body.manifest_sha256, recipient_key_hex: body.recipient_key_hex,
    issued_at: body.issued_at, expires_at: body.expires_at,
  }));
}

export function licenceContext(body) {
  return concat(utf8.encode('holochain-music/personal-licence/hkdf-aad/v1\x00'), canonical({
    schema: body.schema, owner_agent: body.owner_agent, listener_agent: body.listener_agent, file_id: body.file_id,
    manifest_sha256: body.manifest_sha256, recipient_key_hex: body.recipient_key_hex,
    issued_at: body.issued_at, licence_id: body.licence_id, terms: body.terms,
  }));
}

/** Public, *unauthenticated* classification for display/routing only. */
export function grantKind(grant) {
  const schema = isPlain(grant) && isPlain(grant.body) ? grant.body.schema : null;
  if (schema === LICENCE_SCHEMA) return 'perpetual-personal';
  if (schema === GRANT_SCHEMA) return 'stream';
  return fail('unknown grant schema', GrantError);
}

function identity(value, label) {
  if (typeof value !== 'string' || !value || value.length > 160 || value.includes('\0')) fail(`invalid ${label}`, GrantError);
  return value;
}

/**
 * content_grants.unwrap_content_grant.
 *
 * `trustedArtist` MUST come from the artist's validated S2 owner-manifest key
 * binding (via the listener's own Holochain cell), never from grant.signer.
 * `listenerAgent` MUST be this browser's own HWC agent key.
 * `recipientPrivate` is the listener's non-extractable X25519 CryptoKey.
 * Returns a non-extractable AES-GCM CryptoKey usable only for decrypt.
 */
export async function unwrapContentGrant(grant, { trustedArtist, ownerAgent, listenerAgent, recipientPrivate,
  recipientPublicHex, signedManifest, now = Math.floor(Date.now() / 1000) }) {
  identity(ownerAgent, 'owner agent');
  identity(listenerAgent, 'listener agent');
  if (!recipientPrivate || recipientPrivate.type !== 'private' || recipientPrivate.algorithm?.name !== 'X25519') {
    fail('reader X25519 private key required', GrantError);
  }
  if (!(trustedArtist instanceof Uint8Array) || trustedArtist.length !== 32) fail('trusted registered artist key required', GrantError);
  let manifestBody;
  try {
    manifestBody = await verifySigned(signedManifest, trustedArtist, 'manifest');
    assertManifest(manifestBody);
  } catch {
    fail('invalid signed S1 manifest', GrantError);
  }
  const fileId = manifestBody.file_id;
  const digest = await manifestDigest(signedManifest);
  if (!sameKeys(grant, ['body', 'signer', 'signature'])) fail('invalid grant envelope', GrantError);
  let grantBytes;
  try {
    grantBytes = canonical(grant);
  } catch {
    fail('invalid grant encoding or cryptographic field', GrantError);
  }
  if (grantBytes.length > MAX_GRANT_BYTES) fail('oversized grant', GrantError);
  let signer;
  let signature;
  try {
    signer = fromB64(grant.signer, 32);
    signature = fromB64(grant.signature, 64);
  } catch {
    fail('invalid grant encoding or cryptographic field', GrantError);
  }
  if (!equalBytes(signer, trustedArtist)) fail('grant not signed by registered artist', GrantError);
  const body = grant.body;
  const licence = isPlain(body) && body.schema === LICENCE_SCHEMA;
  if (!sameKeys(body, licence ? LICENCE_FIELDS : GRANT_FIELDS)) fail('invalid grant body', GrantError);
  let valid = false;
  try {
    valid = await ed25519Verify(trustedArtist, signature, canonical(body));
  } catch {
    valid = false;
  }
  if (!valid) fail('grant signature or key authentication failed', GrantError);
  if (body.schema !== (licence ? LICENCE_SCHEMA : GRANT_SCHEMA) || body.owner_agent !== ownerAgent
      || body.listener_agent !== listenerAgent || body.file_id !== fileId || body.manifest_sha256 !== digest) {
    fail('grant not valid for this listener/owner/file', GrantError);
  }
  if (!isHex(body.recipient_key_hex, 64)) fail('invalid recipient public key', GrantError);
  if (!isHex(body.ephemeral_key_hex, 64)) fail('invalid ephemeral public key', GrantError);
  if (licence) {
    if (!isInt(body.issued_at) || body.issued_at > now + CLOCK_SKEW_SECONDS || body.terms !== LICENCE_TERMS) {
      fail('invalid licence terms or issue time', GrantError);
    }
    if (!isHex(body.licence_id, 32)) fail('invalid licence ID', GrantError);
  } else {
    if (!isInt(body.issued_at) || !isInt(body.expires_at)) fail('invalid grant timestamps', GrantError);
    if (body.issued_at > now + CLOCK_SKEW_SECONDS || body.expires_at <= now
        || !(body.expires_at - body.issued_at >= 1 && body.expires_at - body.issued_at <= MAX_LIFETIME_SECONDS)) {
      fail('grant is expired or outside its validity window', GrantError);
    }
  }
  if (recipientPublicHex !== body.recipient_key_hex) fail('grant not addressed to this X25519 reader', GrantError);
  let salt;
  let nonce;
  let wrapped;
  try {
    salt = fromB64(body.salt_b64, 16);
    nonce = fromB64(body.nonce_b64, 12);
    wrapped = fromB64(body.wrapped_key_b64, 48);
  } catch {
    fail('invalid grant encoding or cryptographic field', GrantError);
  }
  const context = licence ? licenceContext(body) : grantContext(body);
  try {
    const ephemeral = await subtle.importKey('raw', fromHex(body.ephemeral_key_hex, 32), { name: 'X25519' }, false, []);
    const shared = await subtle.deriveBits({ name: 'X25519', public: ephemeral }, recipientPrivate, 256);
    const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const kek = await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: context }, hkdf,
      { name: 'AES-GCM', length: 256 }, false, ['unwrapKey']);
    // unwrapKey = AES-GCM decrypt + import; the raw content key never reaches JS.
    return await subtle.unwrapKey('raw', wrapped, kek,
      { name: 'AES-GCM', iv: nonce, additionalData: context, tagLength: 128 },
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  } catch {
    return fail('grant signature or key authentication failed', GrantError);
  }
}

// ---- listener recipient key -------------------------------------------------

/** Non-extractable X25519 key pair; only the public half can be exported. */
export async function generateRecipientKey() {
  const pair = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicHex = toHex(new Uint8Array(await subtle.exportKey('raw', pair.publicKey)));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicHex };
}
