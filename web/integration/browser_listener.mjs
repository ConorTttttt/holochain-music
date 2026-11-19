// Real Chromium + Holo Web Conductor listener for the Music interop test.
// Drives the actual web UI (no mocks). Every assertion is recorded in the
// evidence file with PASS/FAIL/BLOCKED; nothing private is written there.
//
// Env: HM_WEB_URL, HM_HWC_EXTENSION, HM_GATEWAY_URL, HM_GATEWAY_SECRET_FILE,
//      HM_ARTIST_STATUS, HM_EXPECTED_DIGESTS, HM_GRANT_DIR, HM_PROFILES, HM_EVIDENCE
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
const GRANTS = env('HM_GRANT_DIR');
const PROFILES = env('HM_PROFILES');
const EVIDENCE = env('HM_EVIDENCE');
const TAMPER_WEB = process.env.HM_TAMPER_WEB_URL;
const TAMPER_STATE = process.env.HM_TAMPER_STATE;

const evidence = { started_at: new Date().toISOString(), checks: [], facts: {} };
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
  page.on('pageerror', e => console.log(`[${name} pageerror] ${e.message}`));
  page.on('console', m => { if (m.type() === 'error') console.log(`[${name} console] ${m.text().slice(0, 300)}`); });
  await page.goto(`${web}/?diagnostics=1`);
  return { ctx, page };
}
const hm = (page, expr) => page.evaluate(expr);
const state = page => hm(page, () => window.hmWeb?.state);

async function connectAndAdmit(name, page, { admitFirst = true } = {}) {
  const agent = await until(() => hm(page, () => window.hmWeb.agent), `${name} agent`, 60000, 300);
  if (admitFirst) await admin('POST', agent, ['dht_read', 'dht_write', 'k2']);
  return agent;
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
    await page.click(`[data-track="${a.track_key}"] .title a`);
    await page.waitForSelector(`h1:has-text("Native Test Artist")`, { timeout: 30000 });
    await page.waitForSelector(`[data-track="${a.track_key}"]`, { timeout: 30000 });
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

  // ---- Private request (expected blocker) -------------------------------------
  await check('E1 private access request over Holochain from the browser', async () => {
    await page.click('#access-card button:has-text("Request licence")');
    const handle = await page.waitForFunction(() => {
      const t = document.getElementById('access-status')?.textContent ?? '';
      return /cannot be sent|delivered|Request failed/.test(t) && t;
    }, null, { timeout: 60000 });
    const text = await handle.jsonValue();
    evidence.facts.e1_ui_message = text;
    if (text.includes('cannot be sent from the browser')) {
      const err = new Error('HWC cannot make Holochain call_remote (send_access_request); gateway drops CallRemoteReq. Nothing was sent.');
      err.blocked = true;
      throw err;
    }
    assert.ok(text.includes('delivered'), text);
  });

  // ---- Operator-assisted, out-of-band artist grant ------------------------------
  const recipient = await hm(page, () => window.hmWeb.recipientPublicKey());
  await check('D1 artist issues a real v1 licence to this browser identity (OUT-OF-BAND, operator-assisted)', async () => {
    writeFileSync(join(GRANTS, 'listener-a.request.json'), JSON.stringify({ listener_agent: agentA.agent, recipient_public_hex: recipient, kind: 'perpetual-personal' }));
    const grantPath = join(GRANTS, 'listener-a.grant.json');
    await until(() => existsSync(grantPath), 'artist grant', 60000);
    const grant = readFileSync(grantPath, 'utf8');
    await page.click('#access-card summary');
    await page.fill('#grant-json', grant);
    await page.click('#grant-import');
    await page.waitForSelector('#access-status.ok', { timeout: 30000 });
    return { recipient_public_hex: recipient, grant_schema: JSON.parse(grant).body.schema, delivery: 'out-of-band file (not Holochain)' };
  });
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
    const g = JSON.parse(readFileSync(join(GRANTS, 'listener-a.grant.json'), 'utf8'));
    g.body.listener_agent = g.body.owner_agent;
    await page.fill('#grant-json', JSON.stringify(g));
    await page.click('#grant-import');
    await page.waitForSelector('#access-status.bad', { timeout: 30000 });
  });

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
  await ctx.close();

  // ---- Listener B: different identity --------------------------------------------
  ({ ctx, page } = await launch('listener-b'));
  const agentB = await until(() => hm(page, () => window.hmWeb.agent), 'agent B', 60000, 300);
  await check('G1 un-admitted identity is held at admission-pending (gateway rejection)', async () => {
    await until(async () => (await state(page)) === 'admission-pending', 'admission-pending', 90000);
  });
  await admin('POST', agentB, ['dht_read', 'dht_write', 'k2']);
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
    await page.fill('#grant-json', readFileSync(join(GRANTS, 'listener-a.grant.json'), 'utf8'));
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

  // ---- Malicious gateway: forged records must never reach the UI -------------
  if (TAMPER_WEB) {
    ({ ctx, page } = await launch('listener-m', TAMPER_WEB));
    await check('M1 malicious gateway cannot forge catalogue records (HWC record verification)', async () => {
      const agentM = await until(() => hm(page, () => window.hmWeb.agent), 'agent M', 60000, 300);
      await admin('POST', agentM, ['dht_read', 'dht_write', 'k2']);
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
