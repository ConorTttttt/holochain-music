#!/usr/bin/env node
// Run the native-Python compatibility vectors inside real Chromium (its own
// BoringSSL-backed WebCrypto), from a secure http://localhost origin.
//   node web/tests/chromium-crypto.mjs web/tests/vectors/.generated/v1.json
import { createReadStream, readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.HM_PLAYWRIGHT ?? 'playwright');
const web = resolve(fileURLToPath(import.meta.url), '..', '..');
const vectors = readFileSync(process.argv[2] ?? join(web, 'tests/vectors/.generated/v1.json'), 'utf8');

const server = createServer((req, res) => {
  const path = new URL(req.url, 'http://x').pathname;
  if (path === '/') { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>crypto</title>'); return; }
  if (path === '/vectors.json') { res.writeHead(200, { 'content-type': 'application/json' }); res.end(vectors); return; }
  const file = normalize(join(web, path));
  if (!file.startsWith(join(web, 'src'))) { res.writeHead(404).end(); return; }
  res.writeHead(200, { 'content-type': extname(file) === '.js' ? 'text/javascript' : 'application/octet-stream' });
  createReadStream(file).pipe(res);
}).listen(0, '127.0.0.1');
await new Promise(r => server.once('listening', r));
const origin = `http://localhost:${server.address().port}`;

const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(origin);
const result = await page.evaluate(async () => {
  const v1 = await import('/src/security/v1.js');
  const { canonical } = await import('/src/security/canonical.js');
  const { fromB64, fromHex } = await import('/src/security/bytes.js');
  const V = await (await fetch('/vectors.json')).json();
  const out = { userAgent: navigator.userAgent, canonical: 0, grants: [], chunks: 0, failures: [] };
  for (const c of V.canonical) {
    const b64 = btoa(String.fromCharCode(...canonical(c.value)));
    if (b64 === c.canonical_b64) out.canonical++; else out.failures.push(`canonical ${JSON.stringify(c.value)}`);
  }
  const imp = jwk => crypto.subtle.importKey('jwk', jwk, { name: 'X25519' }, false, ['deriveBits']);
  const keys = { listener: await imp(V.keys.listener_x25519_jwk), other: await imp(V.keys.other_x25519_jwk) };
  const pubs = { listener: V.keys.listener_x25519_public_hex, other: V.keys.other_x25519_public_hex };
  let unwrapped = null;
  for (const c of V.grants) {
    let ok = false;
    try {
      const k = await v1.unwrapContentGrant(c.grant, { trustedArtist: fromHex(c.trusted_artist_hex, 32), ownerAgent: c.owner_agent,
        listenerAgent: c.listener_agent, recipientPrivate: keys[c.recipient], recipientPublicHex: pubs[c.recipient],
        signedManifest: c.manifest === 'primary' ? V.package.manifest : V.package.other_manifest, now: V.generated_at + 10 });
      ok = true;
      unwrapped ??= k;
    } catch { ok = false; }
    out.grants.push({ name: c.name, browser: ok, python: c.python_valid });
    if (ok !== c.python_valid) out.failures.push(`grant ${c.name}`);
  }
  const parts = [];
  for (const [i, b64] of V.package.chunks_b64.entries()) { parts.push(await v1.decryptChunk(unwrapped, V.package.manifest.body, i, fromB64(b64))); out.chunks++; }
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  if (await v1.sha256Hex(all) !== V.package.plaintext_sha256) out.failures.push('plaintext digest');
  if (await v1.manifestDigest(V.package.manifest) !== V.package.manifest_sha256) out.failures.push('manifest digest');
  return out;
});
await browser.close();
server.close();
console.log(JSON.stringify({ ...result, grants: `${result.grants.filter(g => g.browser === g.python).length}/${result.grants.length} verdicts match Python` }, null, 1));
process.exit(result.failures.length ? 1 : 0);
