// Real Chromium + Holo Web Conductor listener for the Music interop test.
// Drives the actual web UI (no mocks). Every assertion is recorded in the
// evidence file with PASS/FAIL/BLOCKED; nothing private is written there.
//
// Env: HM_WEB_URL, HM_HWC_EXTENSION, HM_GATEWAY_URL, HM_GATEWAY_SECRET_FILE,
//      HM_ARTIST_STATUS, HM_EXPECTED_DIGESTS, HM_APPROVALS, HM_PROFILES, HM_EVIDENCE
//
// The primary grant workflow (checks E1-E5, then D2) uses only the web UI's
// normal controls, the operator's gateway admission and the native artist's
// explicit approval through MusicApp.artist.grant(). No grant file, key or
// browser storage is injected; the out-of-band import is exercised only as a
// negative/diagnostic path (D4, I2, X1 feed it grants that must be REJECTED).
import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.HM_PLAYWRIGHT ?? 'playwright');

const env = k => { const v = process.env[k]; if (!v) throw new Error(`missing ${k}`); return v; };
const WEB = env('HM_WEB_URL');
const EXT = env('HM_HWC_EXTENSION');
const GATEWAY = env('HM_GATEWAY_URL');
const SECRET = readFileSync(env('HM_GATEWAY_SECRET_FILE'), 'utf8').trim();
const artist = () => JSON.parse(readFileSync(env('HM_ARTIST_STATUS'), 'utf8'));
const expected = JSON.parse(readFileSync(env('HM_EXPECTED_DIGESTS'), 'utf8'));
const APPROVALS = env('HM_APPROVALS');
const PROFILES = env('HM_PROFILES');
const EVIDENCE = env('HM_EVIDENCE');
const TAMPER_WEB = process.env.HM_TAMPER_WEB_URL;
const TAMPER_STATE = process.env.HM_TAMPER_STATE;

const evidence = { started_at: new Date().toISOString(), checks: [], facts: {} };
let currentPage = null; // for failure screenshots (local debugging artefacts, not evidence)
const save = () => writeFileSync(EVIDENCE, JSON.stringify(evidence, null, 2));
async function check(id, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    evidence.checks.push({ id, result: 'PASS', ms: Date.now() - t0, detail: detail ?? null });
    console.log(`PASS ${id}`);
    return detail;
  } catch (e) {
    evidence.checks.push({ id, result: e.blocked ? 'BLOCKED' : 'FAIL', ms: Date.now() - t0, error: String(e.message).slice(0, 600) });
    await currentPage?.screenshot({ path: join(PROFILES, `failure-${id.split(' ')[0]}.png`) }).catch(() => {});
    console.log(`${e.blocked ? 'BLOCKED' : 'FAIL'} ${id}: ${e.message}`);
    save();
    if (!e.blocked && !e.soft) throw e;
    return null;
  } finally {
    save();
  }
}
async function until(fn, what, timeout = 120000, every = 1000) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try { const v = await fn(); if (v) return v; } catch (e) { last = e; }
    await delay(every);
  }
  throw new Error(`timed out: ${what}${last ? ` (${last.message})` : ''}`);
}
async function admin(method, agent, capabilities) {
  const res = await fetch(`${GATEWAY}/admin/agents`, { method, headers: { Authorization: `Bearer ${SECRET}`, 'content-type': 'application/json' },
    body: JSON.stringify({ agent_pubkey: agent, ...(capabilities ? { capabilities } : {}) }) });
  assert.equal(res.status, 204, `gateway admission ${method} returned ${res.status}`);
}

async function launch(name, web = WEB) {
  const ctx = await chromium.launchPersistentContext(join(PROFILES, name), {
    headless: false, viewport: { width: 1280, height: 860 },
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-first-run', '--autoplay-policy=no-user-gesture-required'],
  });
  // The genuine HWC approval window: the test clicks Approve as a user would.
  ctx.on('page', async p => {
    try {
      await p.waitForLoadState();
      if (p.url().includes('authorize.html')) { await p.click('#approve-btn', { timeout: 15000 }); evidence.facts[`${name}_approved_origin`] = true; }
    } catch { /* closed */ }
  });
  const page = await ctx.newPage();
  currentPage = page;
  page.on('pageerror', e => console.log(`[${name} pageerror] ${e.message}`));
  page.on('console', m => { if (m.type() === 'error') console.log(`[${name} console] ${m.text().slice(0, 300)}`); });
  await page.goto(`${web}/?diagnostics=1`);
  return { ctx, page };
}
const hm = (page, expr) => page.evaluate(expr);
const state = page => hm(page, () => window.hmWeb?.state);

// Operator admission for a Music listener: DHT access plus standard
// Holochain call_remote in both directions (request out, grant in).
const LISTENER_CAPS = ['dht_read', 'dht_write', 'k2', 'call_remote_send', 'call_remote_receive'];

async function connectAndAdmit(name, page, { admitFirst = true } = {}) {
  const agent = await until(() => hm(page, () => window.hmWeb.agent), `${name} agent`, 60000, 300);
  if (admitFirst) await admin('POST', agent, LISTENER_CAPS);
  return agent;
}

async function openTrack(page, key) {
  await until(async () => {
    await page.click('[data-view="browse"]');
    return page.waitForSelector(`[data-track="${key}"]`, { timeout: 5000 }).catch(() => null);
  }, `track ${key} in Browse`, 300000, 3000);
  await page.click(`[data-track="${key}"] button:has-text("Details")`);
  await page.waitForSelector('#access-card', { timeout: 30000 });
}
const accessState = page => page.getAttribute('#access-status', 'data-access-state').catch(() => null);

async function approve(name, requestHash, kind) {
  const result = join(APPROVALS, `${name}.result.json`);
  writeFileSync(join(APPROVALS, `${name}.approve.json`), JSON.stringify({ request_hash: requestHash, kind }));
  await until(() => existsSync(result), `artist decision ${name}`, 120000);
  return JSON.parse(readFileSync(result, 'utf8'));
}

async function waitReady(page, what, timeout = 240000) {
  return until(async () => {
    const s = await state(page);
    if (s === 'ready') return true;
    if (['admission-pending', 'gateway-disconnected', 'synchronising', 'error'].includes(s)) {
      await page.click('#conn-banner .btn').catch(() => {}); // the user-visible Connect/Reconnect button
    }
    return false;
  }, what, timeout, 2000);
}

async function main() {
  const a = artist();
  const trackTitle = a.track_key && 'Browser Interop Tone';
  evidence.facts.artist_agent = a.agent;
  evidence.facts.native_dnas = { music_catalogue: a.bridge_whoami.catalogue_dna, music_storage: a.bridge_whoami.storage_dna };

  // ---- Listener A: fresh profile ----------------------------------------------
  let { ctx, page } = await launch('listener-a');
  const agentA = await check('A1 browser identity created and origin authorised in HWC', async () => {
    const agent = await connectAndAdmit('listener-a', page);
    assert.match(agent, /^uhCAk[A-Za-z0-9_-]{48}$/);
    return { agent };
  });
  await check('A2 Music hApp installed in HWC with the exact native DNA hashes', async () => {
    const cells = await until(() => hm(page, () => window.hmWeb.cells), 'cells verified', 120000);
    assert.deepEqual(cells, evidence.facts.native_dnas);
    return cells;
  });
  await check('A3 authenticated H2HC gateway session and network round-trip (state ready)', async () => {
    await waitReady(page, 'listener A ready');
    const gw = await hm(page, () => window.hmWeb.gateway);
    assert.ok(gw.authenticated && gw.wsHealthy && gw.hasSession);
    return { gateway: gw.url, authenticated: gw.authenticated };
  });

  // ---- Discovery --------------------------------------------------------------
  await check('B1 browser discovers the native artist track via Holochain (Browse)', async () => {
    const row = await until(async () => {
      await page.click('[data-view="browse"]');
      return page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 5000 }).catch(() => null);
    }, 'track in Browse', 300000, 3000);
    const text = await row.textContent();
    assert.ok(text.includes(trackTitle) && text.includes('Native Test Artist'), text);
    return { track_key: a.track_key, row: text.slice(0, 120) };
  });
  await check('B2 search finds the track by title', async () => {
    await page.fill('#search', 'interop');
    await page.press('#search', 'Enter');
    await page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 30000 });
  });
  await check('B3 artist page lists the artist profile and track', async () => {
    // The artist page reads the profile and the artist's track links; both
    // converge over the DHT like Browse does, so retry from the search result.
    await until(async () => {
      if (!(await page.$(`[data-track="${a.track_key}"] .title a`))) {
        await page.fill('#search', 'interop');
        await page.press('#search', 'Enter');
        await page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 30000 });
      }
      await page.click(`[data-track="${a.track_key}"] .title a`);
      await page.waitForSelector(`h1:has-text("Native Test Artist")`, { timeout: 30000 });
      return page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 15000 }).catch(() => null);
    }, 'artist page with profile and track', 240000, 5000);
  });
  await check('C1 track detail shows artist-authored record and DNA provenance', async () => {
    await page.click(`[data-track="${a.track_key}"] button:has-text("Details")`);
    await page.waitForSelector('#verify-sources', { timeout: 30000 });
    const body = await page.textContent('#view');
    for (const s of [a.agent, a.manifest_sha256, evidence.facts.native_dnas.music_catalogue]) assert.ok(body.includes(s), `missing ${s}`);
  });
  await check('C2 genuine signed manifest + host receipt fetched via adapter and verified in-browser', async () => {
    // DHT records (key bindings, commitment, replica claim, endpoint) converge
    // over several minutes; retry like the native e2e test polls resolve().
    const attempts = [];
    await until(async () => {
      const button = await page.$('#verify-sources');
      if (!button) {
        await page.click('[data-view="browse"]');
        await page.click(`[data-track="${a.track_key}"] button:has-text("Details")`, { timeout: 30000 });
      }
      await page.click('#verify-sources');
      const outcome = await page.waitForSelector('#sources-verified, .card .notice.bad', { timeout: 120000 });
      if (await outcome.getAttribute('id') === 'sources-verified') return true;
      attempts.push((await outcome.textContent()).slice(0, 160));
      await outcome.evaluate(n => n.remove());
      return false;
    }, 'sources verified', 420000, 10000);
    evidence.facts.c2_retries = attempts;
    const trusted = (await hm(page, () => window.hmWeb.trusted)).find(t => t.key === a.track_key);
    assert.equal(trusted.digest, a.manifest_sha256);
    assert.equal(trusted.file_id, a.file_id);
    assert.equal(trusted.hosts[0].url, a.host.url);
    assert.equal(trusted.hosts[0].fingerprint, a.host.cert_fingerprint_hex);
    return trusted;
  });

  // ---- No grant: no audio -------------------------------------------------------
  await check('D0 unauthorised playback is refused (no grant, no audio)', async () => {
    await page.click('#view button:has-text("Play")');
    await page.waitForSelector('#state-badge[data-state="error"]', { timeout: 30000 });
    const p = await hm(page, () => window.hmWeb.player);
    assert.equal(p, null);
    assert.deepEqual(await hm(page, () => window.hmWeb.chunkDigests), []);
  });

  // ---- Private access request -> native approval -> private grant -----------
  // Checkpoint E: genuine Holochain call_remote both ways, private inbox entry.
  await check('E1 browser sends a private access request over Holochain call_remote (UI: Request licence)', async () => {
    await page.click('#access-card button:has-text("Request licence")');
    const handle = await page.waitForFunction(() => {
      const n = document.getElementById('access-status');
      const st = n?.dataset.accessState;
      return st && st !== 'sending' && { state: st, text: n.textContent };
    }, null, { timeout: 90000 });
    const r = await handle.jsonValue();
    evidence.facts.e1_ui = r;
    if (r.state === 'unsupported') { const err = new Error(`HWC cannot make call_remote: ${r.text}`); err.blocked = true; throw err; }
    assert.equal(r.state, 'awaiting', r.text);
    assert.match(r.text, /delivered privately/);
    assert.doesNotMatch(r.text, /approved|declined/i, 'no decision may be claimed');
    return r;
  });
  const request = await check('E2 native artist receives the browser request in MusicApp.artist.requests() with verified provenance', async () => {
    const r = await until(() => (artist().requests || []).find(x => x.listener_agent === agentA.agent && x.file_id === a.file_id),
      'request visible to the native artist', 120000, 2000);
    assert.equal(r.kind, 'perpetual-personal');
    assert.equal(r.granted, false);
    return r;
  });
  await check('E3 artist explicitly approves; the grant is DELIVERED to the browser by call_remote (not queued)', async () => {
    assert.ok(request?.request_hash, 'no request to approve');
    // The listener has not received anything before the artist decides.
    await page.click('#check-grants');
    await page.waitForFunction(() => !['checking', 'sending'].includes(document.getElementById('access-status')?.dataset.accessState), null, { timeout: 60000 });
    assert.equal(await accessState(page), 'awaiting', 'access must not appear before the artist decides');
    const outcome = await approve('listener-a', request.request_hash, 'perpetual-personal');
    evidence.facts.e3_artist_outcome = outcome;
    assert.equal(outcome.granted, true, outcome.error);
    assert.equal(outcome.delivered, true, `grant not delivered: ${JSON.stringify(outcome)}`);
    return outcome;
  });
  await check('E4 browser retrieves the private inbox entry, verifies the artist grant and stores it (UI: Check for grants)', async () => {
    await page.click('#check-grants');
    await page.waitForFunction(() => document.getElementById('access-status')?.dataset.accessState === 'granted', null, { timeout: 60000 });
    const sync = await hm(page, () => window.hmWeb.lastSync);
    const mine = sync.filter(r => r.file_id === a.file_id);
    assert.equal(mine.length, 1, JSON.stringify(sync));
    assert.equal(mine[0].error, null);
    assert.equal(mine[0].kind, 'perpetual-personal');
    const grant = await hm(page, `window.hmWeb.storedGrant(${JSON.stringify(a.file_id)})`);
    assert.equal(grant.body.listener_agent, agentA.agent);
    assert.equal(grant.body.owner_agent, a.agent);
    evidence.facts.e4_grant_schema = grant.body.schema;
    return { inbox_rows_for_track: mine.length, kind: mine[0].kind, ui: await page.textContent('#access-status') };
  });
  await check('E5 a second delivery for the same request is handled idempotently', async () => {
    // The artist approves the same request again: a second, freshly wrapped
    // grant arrives as a second private inbox entry.
    const outcome = await approve('listener-a-again', request.request_hash, 'perpetual-personal');
    assert.equal(outcome.delivered, true, JSON.stringify(outcome));
    const sync = async () => {
      await page.click('#check-grants');
      await page.waitForFunction(() => document.getElementById('access-status')?.dataset.accessState === 'granted', null, { timeout: 60000 });
      return (await hm(page, () => window.hmWeb.lastSync)).filter(r => r.file_id === a.file_id);
    };
    const first = await sync();
    assert.equal(first.length, 2, 'two private inbox entries');
    assert.ok(first.every(r => r.error === null), JSON.stringify(first));
    assert.equal(first.filter(r => r.superseded).length, 1, 'older delivery superseded');
    const again = await sync();
    assert.ok(again.some(r => r.duplicate === true), 're-sync recognises the stored grant');
    await page.click('[data-view="library"]');
    await page.waitForSelector('#view .row', { timeout: 30000 });
    assert.equal((await page.$$('#view .row')).length, 1, 'one stored grant');
    await openTrack(page, a.track_key);
  });
  const grantA = JSON.stringify(await hm(page, `window.hmWeb.storedGrant(${JSON.stringify(a.file_id)})`));
  await check('D2 browser verifies, decrypts and plays the genuine Music audio to the end', async () => {
    await page.click('#view button:has-text("Play")');
    await page.waitForSelector('#state-badge[data-state="playing"]', { timeout: 60000 });
    await page.waitForSelector('#state-badge[data-state="ended"]', { timeout: 120000 });
    const p = await hm(page, () => window.hmWeb.player);
    const digests = await hm(page, () => window.hmWeb.chunkDigests);
    assert.deepEqual(digests, expected.chunk_plain_sha256, 'decrypted chunks differ from the artist canonical WAV');
    assert.equal(p.format.sampleRate, 44100);
    assert.equal(p.position, p.frames, 'every frame rendered by the AudioWorklet');
    return { frames: p.frames, frames_played: p.position, stats: p.stats, format: p.format, chunks: digests.length };
  });
  await check('D3 pause, resume and seek during playback', async () => {
    await page.click('#view button:has-text("Play")');
    await page.waitForSelector('#state-badge[data-state="playing"]', { timeout: 60000 });
    await page.click('#btn-play');
    await page.waitForSelector('#state-badge[data-state="paused"]');
    const at = (await hm(page, () => window.hmWeb.player)).position;
    await delay(1500);
    assert.ok((await hm(page, () => window.hmWeb.player)).position - at < 2048, 'position advanced while paused');
    await page.click('#btn-play');
    await page.waitForSelector('#state-badge[data-state="playing"]');
    await page.evaluate(() => { const s = document.getElementById('seek'); s.value = '800'; s.dispatchEvent(new Event('change')); });
    await page.waitForSelector('#state-badge[data-state="ended"]', { timeout: 60000 });
    const p = await hm(page, () => window.hmWeb.player);
    assert.equal(p.stats.seeks, 1);
    assert.equal(p.position, p.frames);
    return { stats: p.stats };
  });
  await check('D4 tampered grant is rejected by the browser', async () => {
    const g = JSON.parse(grantA);
    g.body.listener_agent = g.body.owner_agent;
    await page.click('#access-card summary');
    await page.fill('#grant-json', JSON.stringify(g));
    await page.click('#grant-import');
    await page.waitForSelector('#access-status.bad', { timeout: 30000 });
  });

  // ---- Isolation between tracks ----------------------------------------------
  const b2 = a.second;
  if (b2) {
    await check('I1 track B has no access and is not playable with track A\'s grant', async () => {
      await openTrack(page, b2.track_key);
      assert.equal(await accessState(page), 'none');
      await page.click('#view button:has-text("Play")');
      await page.waitForSelector('#state-badge[data-state="error"]', { timeout: 60000 });
      assert.deepEqual(await hm(page, () => window.hmWeb.chunkDigests), []);
    });
    await check('I2 track A\'s grant is rejected for track B (wrong manifest/file)', async () => {
      await page.click('#access-card summary');
      await page.fill('#grant-json', grantA);
      await page.click('#grant-import');
      const text = await (await page.waitForSelector('#access-status.bad', { timeout: 60000 })).textContent();
      return { rejection: text };
    });
  }

  // ---- Browser restart: same identity, no reinstall, grant persists -------------
  await ctx.close();
  ({ ctx, page } = await launch('listener-a'));
  await check('R1 browser restart keeps the same identity, installation and grant', async () => {
    await waitReady(page, 'listener A ready after restart');
    assert.equal(await hm(page, () => window.hmWeb.agent), agentA.agent);
    await page.click('[data-view="library"]');
    await page.waitForSelector('#view .row', { timeout: 30000 });
    return { agent: agentA.agent };
  });
  if (b2) {
    await check('R2 after restart, track B is still refused', async () => {
      await openTrack(page, b2.track_key);
      assert.equal(await accessState(page), 'none');
      await page.click('#view button:has-text("Play")');
      await page.waitForSelector('#state-badge[data-state="error"]', { timeout: 60000 });
    });
  }
  await check('R3 after restart, returning to track A re-verifies the stored grant and plays the genuine audio', async () => {
    await openTrack(page, a.track_key);
    assert.equal(await accessState(page), 'granted');
    // Play re-resolves the signed manifest/hosts and re-verifies the stored grant.
    await until(async () => {
      await page.click('#view button:has-text("Play")');
      await page.waitForSelector('#state-badge:not([data-state="error"])', { timeout: 10000 }).catch(() => {});
      const b = await page.waitForSelector('#state-badge[data-state="ended"], #state-badge[data-state="error"]', { timeout: 180000 });
      return (await b.getAttribute('data-state')) === 'ended';
    }, 'playback after restart', 420000, 5000);
    assert.deepEqual(await hm(page, () => window.hmWeb.chunkDigests), expected.chunk_plain_sha256);
  });
  await ctx.close();

  // ---- Listener B: different identity --------------------------------------------
  ({ ctx, page } = await launch('listener-b'));
  const agentB = await until(() => hm(page, () => window.hmWeb.agent), 'agent B', 60000, 300);
  await check('G1 un-admitted identity is held at admission-pending (gateway rejection)', async () => {
    await until(async () => (await state(page)) === 'admission-pending', 'admission-pending', 90000);
  });
  await admin('POST', agentB, LISTENER_CAPS);
  await check('G2 second browser identity becomes ready after admission', async () => {
    assert.notEqual(agentB, agentA.agent);
    await waitReady(page, 'listener B ready');
  });
  await check('X1 listener B cannot use listener A grant (cross-listener reuse refused)', async () => {
    await until(async () => {
      await page.click('[data-view="browse"]');
      return page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 5000 }).catch(() => null);
    }, 'track for B', 240000, 3000);
    await page.click(`[data-track="${a.track_key}"] button:has-text("Details")`);
    await page.click('#access-card summary');
    await page.fill('#grant-json', grantA);
    await page.click('#grant-import');
    const text = await (await page.waitForSelector('#access-status.bad', { timeout: 60000 })).textContent();
    assert.match(text, /not valid for this listener|not addressed/);
    return { rejection: text };
  });
  await check('X2 listener B cannot play the encrypted track', async () => {
    await page.click('#view button:has-text("Play")');
    await page.waitForSelector('#state-badge[data-state="error"]', { timeout: 60000 });
    assert.deepEqual(await hm(page, () => window.hmWeb.chunkDigests), []);
  });
  await check('G3 revoked identity loses the authenticated gateway session', async () => {
    await admin('DELETE', agentB);
    await until(async () => (await state(page)) !== 'ready', 'B leaves ready after revocation', 90000);
    return { state: await state(page) };
  });
  await ctx.close();
  ({ ctx, page } = await launch('listener-b'));
  await check('G4 restarting a revoked browser profile does not reactivate its gateway session', async () => {
    assert.equal(await until(() => hm(page, () => window.hmWeb.agent), 'agent B after restart', 60000, 300), agentB);
    await delay(20000);
    const s = await state(page);
    assert.notEqual(s, 'ready');
    await until(async () => (await state(page)) === 'admission-pending', 'admission-pending after restart', 90000);
    return { state: await state(page) };
  });
  await ctx.close();

  // ---- Malicious gateway: forged records must never reach the UI -------------
  if (TAMPER_WEB) {
    ({ ctx, page } = await launch('listener-m', TAMPER_WEB));
    await check('M1 malicious gateway cannot forge catalogue records (HWC record verification)', async () => {
      const agentM = await until(() => hm(page, () => window.hmWeb.agent), 'agent M', 60000, 300);
      await admin('POST', agentM, ['dht_read', 'dht_write', 'k2']);  // M1 needs no call_remote
      await waitReady(page, 'listener M ready through the malicious gateway');
      const seen = [];
      const forged = await until(async () => {
        await page.click('[data-view="browse"]');
        await page.waitForSelector('#view h1', { timeout: 30000 });
        await delay(1500);
        const text = await page.textContent('#view');
        seen.push(text.slice(0, 120));
        assert.ok(!text.includes('FORGED!'), 'forged title reached the UI');
        const s = JSON.parse(readFileSync(TAMPER_STATE, 'utf8'));
        return s.forged_records >= 3 && s;
      }, 'malicious gateway to forge records', 240000, 4000);
      const finalText = await page.textContent('#view');
      assert.ok(!finalText.includes('FORGED!'), 'forged title reached the UI');
      return { proxy: forged, browse_view: finalText.slice(0, 160),
        genuine_track_listed: finalText.includes('Interop Tone') };
    });
    await ctx.close();
  }
  evidence.finished_at = new Date().toISOString();
  save();
}

main().catch(e => { console.error('FATAL', e); evidence.fatal = String(e.message); save(); process.exit(1); });
