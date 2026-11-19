// Browser v1 crypto vs the native Python implementation.
// Vectors: python3 web/tests/vectors/generate_vectors.py web/tests/vectors/.generated/v1.json
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { canonical } from '../src/security/canonical.js';
import { fromB64, fromHex, toHex } from '../src/security/bytes.js';
import * as v1 from '../src/security/v1.js';

const path = process.env.HM_WEB_VECTORS ?? new URL('./vectors/.generated/v1.json', import.meta.url);
const V = JSON.parse(readFileSync(path, 'utf8'));
const NOW = V.generated_at + 10;
const subtle = globalThis.crypto.subtle;

const importX = jwk => subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
const contentKey = () => subtle.importKey('raw', fromHex(V.keys.content_key_hex, 32), 'AES-GCM', false, ['decrypt']);
const rec = (author, body) => ({ author, action_hash: 'uhCkkHASH', body });

test('canonical JSON is byte-identical to Python json.dumps(sort_keys, compact, ensure_ascii=False)', async () => {
  for (const c of V.canonical) {
    assert.equal(Buffer.from(canonical(c.value)).toString('base64'), c.canonical_b64, JSON.stringify(c.value));
    assert.equal(await v1.sha256Hex(canonical(c.value)), c.sha256);
  }
});

test('canonical JSON fails closed on values Python would serialise differently', () => {
  for (const bad of [{ x: 1.5 }, { x: NaN }, { x: 2 ** 53 }, { x: '\ud800' }, { x: new Date() }, { x: undefined }]) {
    assert.throws(() => canonical(bad));
  }
});

test('manifest digest and signature match the native package', async () => {
  const { manifest, manifest_sha256: digest } = V.package;
  assert.equal(await v1.manifestDigest(manifest), digest);
  const body = await v1.verifySigned(manifest, fromHex(V.keys.artist_public_hex, 32), 'manifest');
  v1.assertManifest(body);
  await assert.rejects(v1.verifySigned(manifest, fromHex(V.keys.other_artist_public_hex, 32), 'manifest'), /untrusted manifest signer/);
  const tampered = structuredClone(manifest);
  tampered.body.chunks[0].sha256 = '0'.repeat(64);
  await assert.rejects(v1.verifySigned(tampered, fromHex(V.keys.artist_public_hex, 32), 'manifest'), /invalid manifest signature/);
});

test('manifest structure checks mirror _assert_manifest', () => {
  const good = V.package.manifest.body;
  v1.assertManifest(good);
  const mut = f => { const m = structuredClone(good); f(m); return m; };
  for (const [name, m] of [
    ['wrong index', mut(m => { m.chunks[1].index = 7; })],
    ['reused nonce', mut(m => { m.chunks[1].nonce = m.chunks[0].nonce; })],
    ['bad cipher length', mut(m => { m.chunks[0].cipher_bytes += 1; })],
    ['short nonfinal', mut(m => { m.chunks[0].plain_bytes -= 1; m.chunks[0].cipher_bytes -= 1; m.total_plain_bytes -= 1; })],
    ['length mismatch', mut(m => { m.total_plain_bytes += 1; })],
    ['extra field', mut(m => { m.extra = 1; })],
    ['uppercase file id', mut(m => { m.file_id = m.file_id.toUpperCase(); })],
  ]) assert.throws(() => v1.assertManifest(m), v1.VerificationError, name);
});

test('every encrypted chunk verifies and decrypts to the exact native plaintext', async () => {
  const body = V.package.manifest.body;
  const key = await contentKey();
  const parts = [];
  for (const [i, b64] of V.package.chunks_b64.entries()) parts.push(await v1.decryptChunk(key, body, i, fromB64(b64)));
  const plain = Buffer.concat(parts);
  assert.equal(plain.length, V.package.plaintext_bytes);
  assert.equal(await v1.sha256Hex(plain), V.package.plaintext_sha256);
});

test('corrupted, missing, reordered or wrongly keyed chunks are rejected', async () => {
  const body = V.package.manifest.body;
  const key = await contentKey();
  const chunk0 = fromB64(V.package.chunks_b64[0]);
  const corrupt = chunk0.slice(); corrupt[5] ^= 1;
  await assert.rejects(v1.decryptChunk(key, body, 0, corrupt), /SHA-256 mismatch/);
  await assert.rejects(v1.decryptChunk(key, body, 0, chunk0.slice(0, -1)), /SHA-256 mismatch/);
  await assert.rejects(v1.decryptChunk(key, body, 1, chunk0), /SHA-256 mismatch/, 'chunk 0 served as chunk 1');
  await assert.rejects(v1.decryptChunk(key, body, body.chunks.length, chunk0), /outside signed manifest/);
  const wrong = await subtle.importKey('raw', new Uint8Array(32).fill(7), 'AES-GCM', false, ['decrypt']);
  await assert.rejects(v1.decryptChunk(wrong, body, 0, chunk0), /AES-GCM rejected/);
  // Same ciphertext, but the AAD binds file_id + index: relabelled metadata must fail GCM.
  const relabelled = structuredClone(body);
  relabelled.chunks[1] = { ...relabelled.chunks[0], index: 1 };
  await assert.rejects(v1.decryptChunk(key, relabelled, 1, chunk0), /AES-GCM rejected/);
});

test('track validation matches music_catalogue.contract.validate_track', () => {
  for (const c of V.tracks) {
    let ok = true;
    try { v1.validateTrack(c.track, c.author); } catch { ok = false; }
    assert.equal(ok, c.valid, c.name);
  }
});

test('owner commitment, host receipt and replica claim verify like holochain_identity', async () => {
  const { manifest, receipt } = V.package;
  const { owner_binding: ob, node_binding: nb, commitment, claim } = V.records;
  const { owner, node } = V.agents;
  await v1.verifyReplicaClaim(receipt, manifest, owner, node, rec(owner, ob), rec(node, nb), rec(owner, commitment), rec(node, claim));
  await assert.rejects(v1.verifyReplicaClaim(receipt, manifest, owner, node, rec(node, ob), rec(node, nb), rec(owner, commitment), rec(node, claim)), /author mismatch/);
  await assert.rejects(v1.verifyReplicaClaim(receipt, manifest, owner, node, rec(owner, ob), rec(node, nb), rec(owner, { ...commitment, manifest_sha256: '0'.repeat(64) }), rec(node, claim)), /commitment does not match/);
  await assert.rejects(v1.verifyReplicaClaim(receipt, manifest, owner, node, rec(owner, ob), rec(node, nb), rec(owner, commitment), rec(node, { ...claim, receipt_sha256: '0'.repeat(64) })), /claim does not match/);
  const badReceipt = structuredClone(receipt); badReceipt.body.chunk_count += 1;
  await assert.rejects(v1.verifyReplicaClaim(badReceipt, manifest, owner, node, rec(owner, ob), rec(node, nb), rec(owner, commitment), rec(node, claim)), /receipt signature/);
  // Ambiguous key bindings are refused, a unique one is accepted.
  assert.equal(toHex(v1.uniqueKey([rec(owner, ob), rec(owner, ob)], owner, v1.OWNER_PURPOSE).key), ob.signing_key_hex);
  assert.throws(() => v1.uniqueKey([rec(owner, ob), rec(owner, { ...ob, signing_key_hex: 'a'.repeat(64) })], owner, v1.OWNER_PURPOSE), /ambiguous/);
  assert.throws(() => v1.uniqueKey([rec(node, ob)], owner, v1.OWNER_PURPOSE), /no owner-manifest key/);
});

test('grant verdicts and unwrapped keys match content_grants.unwrap_content_grant for every vector', async () => {
  const listener = await importX(V.keys.listener_x25519_jwk);
  const other = await importX(V.keys.other_x25519_jwk);
  const probe = fromB64(V.package.chunks_b64[0]);
  for (const c of V.grants) {
    const recipient = c.recipient === 'listener' ? listener : other;
    const recipientPublicHex = c.recipient === 'listener' ? V.keys.listener_x25519_public_hex : V.keys.other_x25519_public_hex;
    let key = null;
    let error = null;
    try {
      key = await v1.unwrapContentGrant(c.grant, {
        trustedArtist: fromHex(c.trusted_artist_hex, 32), ownerAgent: c.owner_agent, listenerAgent: c.listener_agent,
        recipientPrivate: recipient, recipientPublicHex,
        signedManifest: c.manifest === 'primary' ? V.package.manifest : V.package.other_manifest, now: NOW,
      });
    } catch (e) {
      error = e;
    }
    assert.equal(key !== null, c.python_valid, `${c.name}: browser=${error?.message ?? 'accepted'} python=${c.python_error ?? 'accepted'}`);
    if (error) assert.ok(error instanceof v1.GrantError, `${c.name} must fail with GrantError, got ${error}`);
    if (key) {
      // The unwrapped key is non-extractable; prove it equals Python's key by decrypting real audio.
      assert.equal(key.extractable, false);
      assert.deepEqual(key.usages, ['decrypt']);
      assert.equal(c.python_key_hex, V.keys.content_key_hex);
      const plain = await v1.decryptChunk(key, V.package.manifest.body, 0, probe);
      assert.equal(plain.length, V.package.manifest.body.chunks[0].plain_bytes);
    }
  }
});

test('expiry is evaluated against the browser clock exactly like Python', async () => {
  const listener = await importX(V.keys.listener_x25519_jwk);
  const stream = V.grants.find(c => c.name === 'stream-valid').grant;
  const opts = now => ({ trustedArtist: fromHex(V.keys.artist_public_hex, 32), ownerAgent: V.agents.owner,
    listenerAgent: V.agents.listener, recipientPrivate: listener, recipientPublicHex: V.keys.listener_x25519_public_hex,
    signedManifest: V.package.manifest, now });
  await v1.unwrapContentGrant(stream, opts(stream.body.expires_at - 1));
  await assert.rejects(v1.unwrapContentGrant(stream, opts(stream.body.expires_at)), /expired/);
  await assert.rejects(v1.unwrapContentGrant(stream, opts(stream.body.issued_at - 121)), /expired|validity/);
  const licence = V.grants.find(c => c.name === 'licence-valid').grant;
  await v1.unwrapContentGrant(licence, opts(licence.body.issued_at + 10 * 365 * 86400));
});

test('recipient keys are generated non-extractable and expose only the public half', async () => {
  const k = await v1.generateRecipientKey();
  assert.equal(k.privateKey.extractable, false);
  assert.match(k.publicHex, /^[0-9a-f]{64}$/);
  await assert.rejects(subtle.exportKey('pkcs8', k.privateKey));
});

test('grant kind classification is display-only', () => {
  assert.equal(v1.grantKind(V.grants[0].grant), 'stream');
  assert.equal(v1.grantKind(V.grants[1].grant), 'perpetual-personal');
  assert.throws(() => v1.grantKind({ body: { schema: 'x' } }), v1.GrantError);
});
