// Unit tests for browser modules that need no network or audio device.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { validateConfig, ConfigError } from '../src/config.js';
import { boundHostUrl } from '../src/adapters/catalogue/catalogue.js';
import { MediaAdapterClient, MediaUnavailable } from '../src/adapters/media/adapter-client.js';
import { parseWavHeader, pcm16ToPlanar, WavError } from '../src/player/wav.js';
import { holoHashB64, holoHashBytes, fromB64, fromHex } from '../src/security/bytes.js';

function wav({ rate = 44100, channels = 2, frames = 100, fmtLen = 16, bits = 16 } = {}) {
  const data = frames * channels * 2;
  const b = new Uint8Array(44 + data);
  const v = new DataView(b.buffer);
  const tag = (o, s) => [...s].forEach((c, i) => { b[o + i] = c.charCodeAt(0); });
  tag(0, 'RIFF'); v.setUint32(4, 36 + data, true); tag(8, 'WAVE'); tag(12, 'fmt ');
  v.setUint32(16, fmtLen, true); v.setUint16(20, 1, true); v.setUint16(22, channels, true); v.setUint32(24, rate, true);
  v.setUint32(28, rate * channels * 2, true); v.setUint16(32, channels * 2, true); v.setUint16(34, bits, true);
  tag(36, 'data'); v.setUint32(40, data, true);
  return b;
}

test('canonical WAV header accepted with the native rules, others refused', () => {
  const ok = wav();
  assert.deepEqual(parseWavHeader(ok, ok.length), { sampleRate: 44100, channels: 2, blockAlign: 4, dataBytes: 400, frames: 100 });
  assert.throws(() => parseWavHeader(ok, ok.length + 1), WavError, 'length must match signed manifest');
  for (const bad of [wav({ rate: 44101 }), wav({ channels: 3 }), wav({ bits: 24 }), wav({ fmtLen: 18 })]) {
    assert.throws(() => parseWavHeader(bad, bad.length), WavError);
  }
  assert.throws(() => parseWavHeader(ok.slice(0, 20), 20), WavError);
});

test('PCM16 conversion is exact and planar', () => {
  const pcm = new Uint8Array([0x00, 0x80, 0xff, 0x7f, 0x00, 0x00, 0x01, 0x00]); // L=-32768 R=32767 | L=0 R=1
  const [l, r] = pcm16ToPlanar(pcm, 2);
  assert.deepEqual([...l], [-1, 0]);
  assert.deepEqual([...r], [32767 / 32768, 1 / 32768]);
});

test('MoQ host URL policy matches moq_conductor._bound_local_url', () => {
  assert.equal(boundHostUrl('https://127.0.0.1:4433', false), 'https://127.0.0.1:4433');
  assert.equal(boundHostUrl('https://192.168.1.5:4433', false), null, 'LAN needs explicit opt-in');
  assert.equal(boundHostUrl('https://192.168.1.5:4433', true), 'https://192.168.1.5:4433');
  for (const bad of ['https://8.8.8.8:443', 'http://127.0.0.1:443', 'https://127.0.0.1:0', 'https://127.0.0.1:65536',
    'https://localhost:443', 'https://127.0.0.1:443/x', 'https://192.168.01.5:443', 'https://172.32.0.1:443', 'https://u@127.0.0.1:443']) {
    assert.equal(boundHostUrl(bad, true), null, bad);
  }
});

const goodConfig = {
  app_id: 'holochain-music-web', happ_url: '/holochain_music.happ', happ_sha256: 'a'.repeat(64),
  roles: { music_catalogue: 'uhC0k' + 'A'.repeat(48), music_storage: 'uhC0k' + 'B'.repeat(48) },
  gateway_url: 'https://gateway.example', media_adapter_url: 'https://media.example',
};

test('deployment config pins DNAs, digest and https origins', () => {
  const c = validateConfig(goodConfig, { pageOrigin: 'https://music.example' });
  assert.equal(c.allow_lan_hosts, false);
  assert.ok(Object.isFrozen(c) && Object.isFrozen(c.roles));
  const bad = [
    { ...goodConfig, roles: { music_catalogue: goodConfig.roles.music_catalogue } },
    { ...goodConfig, roles: { ...goodConfig.roles, extra: goodConfig.roles.music_storage } },
    { ...goodConfig, happ_sha256: 'A'.repeat(64) },
    { ...goodConfig, gateway_url: 'http://gateway.example' },
    { ...goodConfig, gateway_url: 'https://gateway.example/path' },
    { ...goodConfig, happ_url: 'https://cdn.example/x.happ' },
  ];
  for (const b of bad) assert.throws(() => validateConfig(b, { pageOrigin: 'https://music.example' }), ConfigError);
  // http is only acceptable when the page itself is a localhost development origin
  const dev = { ...goodConfig, gateway_url: 'http://127.0.0.1:8090', media_adapter_url: 'http://127.0.0.1:8787' };
  assert.throws(() => validateConfig(dev, { pageOrigin: 'https://music.example' }), ConfigError);
  assert.ok(validateConfig(dev, { pageOrigin: 'http://localhost:8080' }));
});

test('Holochain hash and strict field encodings round-trip', () => {
  const h = 'uhCAk' + 'x'.repeat(48);
  assert.equal(holoHashB64(holoHashBytes(h)), h);
  assert.equal(holoHashB64(Object.fromEntries([...holoHashBytes(h)].entries())), h, 'Chrome IPC object form');
  assert.throws(() => holoHashBytes('uhCAk' + 'x'.repeat(47)));
  assert.throws(() => fromHex('AB'));
  assert.throws(() => fromB64('QQ=', 1));
  assert.throws(() => fromB64('Q Q==', 1));
  assert.deepEqual([...fromB64('QQ==', 1)], [65]);
});

test('media adapter client retries transient failures and never retries refusals', async () => {
  const calls = [];
  const replies = [new Response('{"error":"busy"}', { status: 503 }), new Response(new Uint8Array([1, 2, 3]), { status: 200 })];
  const client = new MediaAdapterClient('http://127.0.0.1:1', { fetchImpl: async url => { calls.push(url); return replies.shift(); }, attempts: 3 });
  const host = { url: 'https://127.0.0.1:4433', fingerprint: 'f'.repeat(64) };
  assert.deepEqual([...await client.chunk(host, 'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), 7)], [1, 2, 3]);
  assert.equal(calls.length, 2);
  assert.match(calls[0], /\/v1\/files\/a{64}\/chunks\/7\?host=https%3A%2F%2F127\.0\.0\.1%3A4433&fp=f{64}/);
  const refusing = new MediaAdapterClient('http://127.0.0.1:1', { fetchImpl: async () => new Response('{"error":"host URL not permitted"}', { status: 403 }) });
  await assert.rejects(refusing.document(host, 'a'.repeat(64), 'manifest'), e => e instanceof MediaUnavailable && !e.retryable && /not permitted/.test(e.message));
  const huge = new MediaAdapterClient('http://127.0.0.1:1', { fetchImpl: async () => new Response(new Uint8Array(20000), { status: 200 }) });
  await assert.rejects(huge.document(host, 'a'.repeat(64), 'receipt'), /too large/);
});
