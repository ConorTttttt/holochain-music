/**
 * Malicious-gateway tests for record-verification.ts. Every record is built
 * with HWC's own Holochain 0.7 serialization and signed with real Ed25519
 * keys; the "gateway" then forges, relabels or substitutes data.
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import sodium from 'libsodium-wrappers';
import { normalizeByteArraysFromJson } from '../utils/bytes';
import { encode } from '@msgpack/msgpack';
import { blake2b256, computeAppEntryHash, HoloHashType, hashFrom32AndType } from '../hash';
import { buildCreateAction, buildCreateLinkAction, serializeAction, type SerializableAction } from '../types/holochain-serialization';
import {
  UnverifiedNetworkDataError, verifyDetails, verifyNetworkLink, verifyNetworkRecord, withRecordVerification,
} from './record-verification';
import type { NetworkLink, NetworkRecord, NetworkService } from './types';

let artist: sodium.KeyPair;
let attacker: sodium.KeyPair;
const agent = (kp: sodium.KeyPair) => hashFrom32AndType(kp.publicKey, HoloHashType.Agent);
const fakeHash = (type: HoloHashType, seed: number) => hashFrom32AndType(new Uint8Array(32).fill(seed), type);
const DNA = fakeHash(HoloHashType.Dna, 9);

beforeAll(async () => {
  await sodium.ready;
  artist = sodium.crypto_sign_keypair();
  attacker = sodium.crypto_sign_keypair();
});

function appEntry(value: unknown) {
  return { entry_type: 'App', entry: new Uint8Array(encode(value)) };
}

function signed(action: SerializableAction, kp: sodium.KeyPair, entry?: unknown): NetworkRecord {
  const bytes = serializeAction(action);
  const hash = hashFrom32AndType(blake2b256(bytes), HoloHashType.Action);
  return {
    signed_action: { hashed: { hash, content: action }, signature: sodium.crypto_sign_detached(bytes, kp.privateKey) } as never,
    entry: entry ? { Present: entry as never } : 'NA',
  };
}

function trackRecord(kp = artist, title = 'Genuine Track', author = agent(kp)) {
  const entry = appEntry({ schema: 'holochain-music/track/v1', title });
  const action = buildCreateAction({
    author, timestamp: 1_700_000_000_000_000, action_seq: 7, prev_action: fakeHash(HoloHashType.Action, 3),
    entry_type: { App: { entry_index: 2, zome_index: 0, visibility: 'Public' } } as never,
    entry_hash: computeAppEntryHash(entry.entry),
  });
  return { record: signed(action, kp, entry), entry };
}

const clone = <T>(v: T): T => structuredClone(v);
const reason = (fn: () => unknown) => { try { fn(); return 'accepted'; } catch (e) { expect(e).toBeInstanceOf(UnverifiedNetworkDataError); return (e as UnverifiedNetworkDataError).reason; } };

/** As ribosome-worker parseRecordResponse turns the gateway JSON into a NetworkRecord. */
function fromGatewayJson(text: string): NetworkRecord {
  const data = JSON.parse(text);
  const entry = data.entry?.Present ?? data.entry;
  return {
    signed_action: normalizeByteArraysFromJson(data.signed_action),
    entry: entry && typeof entry === 'object' ? { Present: normalizeByteArraysFromJson(entry) } : 'NA',
  } as NetworkRecord;
}

/** serde_json::Value round trip: every map comes back with sorted keys. */
function sortedKeysJson(value: unknown): string {
  const sort = (v: any): any => v instanceof Uint8Array ? Array.from(v)
    : Array.isArray(v) ? v.map(sort)
      : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
  return JSON.stringify(sort(value));
}

describe('genuine Holochain 0.7 record from the h2hc-linker gateway', () => {
  // Captured from the accepted gateway during the Music interop test: a
  // native artist's catalogue Track (Create, App entry), byte-for-byte.
  const fixture = readFileSync(new URL('./__fixtures__/gateway-record-create.json', import.meta.url), 'utf8');

  it('verifies exactly as the gateway sends it (sorted keys, JSON byte arrays)', () => {
    const record = fromGatewayJson(fixture);
    expect(reason(() => verifyNetworkRecord(record, record.signed_action.hashed.hash))).toBe('accepted');
  });

  it('rejects the same record with forged entry bytes', () => {
    const json = JSON.parse(fixture);
    const bytes: number[] = json.entry.Present.entry;
    const at = Buffer.from(bytes).indexOf(Buffer.from('Browser'));
    expect(at).toBeGreaterThan(0);
    Buffer.from('FORGED!').forEach((b, i) => { bytes[at + i] = b; });
    const record = fromGatewayJson(JSON.stringify(json));
    expect(reason(() => verifyNetworkRecord(record, record.signed_action.hashed.hash))).toMatch(/entry content/);
  });

  it('rejects the same record attributed to another author', () => {
    const json = JSON.parse(fixture);
    json.signed_action.hashed.content.header.author[10] ^= 1;
    const record = fromGatewayJson(JSON.stringify(json));
    expect(reason(() => verifyNetworkRecord(record))).toMatch(/action hash|signature/);
  });
});

describe('verifyNetworkRecord', () => {
  it('accepts records after a serde_json sorted-key round trip (AppEntryDef order)', () => {
    const { record } = trackRecord();
    const viaGateway = fromGatewayJson(sortedKeysJson(record));
    expect(reason(() => verifyNetworkRecord(viaGateway, record.signed_action.hashed.hash))).toBe('accepted');
  });

  it('accepts a genuine record requested by action hash or entry hash', () => {
    const { record } = trackRecord();
    expect(reason(() => verifyNetworkRecord(record, record.signed_action.hashed.hash))).toBe('accepted');
    const entryHash = (record.signed_action.hashed.content as any).data.entry_hash;
    expect(reason(() => verifyNetworkRecord(record, entryHash))).toBe('accepted');
  });

  it('accepts JSON-flattened byte arrays exactly as the gateway sends them', () => {
    const { record } = trackRecord();
    const wire = JSON.parse(JSON.stringify(record, (_k, v) => (v instanceof Uint8Array ? Array.from(v) : v)));
    expect(reason(() => verifyNetworkRecord(wire, record.signed_action.hashed.hash))).toBe('accepted');
  });

  it('rejects a record whose author is forged (signed by another key)', () => {
    const { record } = trackRecord(attacker, 'Forged', agent(artist));
    expect(reason(() => verifyNetworkRecord(record, record.signed_action.hashed.hash))).toMatch(/signature/);
  });

  it('rejects content altered after signing', () => {
    const { record } = trackRecord();
    const forged = clone(record);
    (forged.signed_action.hashed.content as any).header.action_seq = 8;
    expect(reason(() => verifyNetworkRecord(forged))).toMatch(/action hash/);
  });

  it('rejects a relabelled action hash even with recomputed hash field', () => {
    const { record } = trackRecord();
    const forged = clone(record);
    (forged.signed_action.hashed.content as any).header.timestamp += 1;
    const bytes = serializeAction(forged.signed_action.hashed.content as never);
    (forged.signed_action.hashed as any).hash = hashFrom32AndType(blake2b256(bytes), HoloHashType.Action);
    expect(reason(() => verifyNetworkRecord(forged))).toMatch(/signature/);
  });

  it('rejects a genuine record returned for a different requested action', () => {
    const { record } = trackRecord();
    const other = trackRecord(artist, 'Other');
    expect(reason(() => verifyNetworkRecord(record, other.record.signed_action.hashed.hash))).toMatch(/different action/);
  });

  it('rejects a genuine action returned for a different requested entry', () => {
    const { record } = trackRecord();
    expect(reason(() => verifyNetworkRecord(record, fakeHash(HoloHashType.Entry, 5)))).toMatch(/different entry/);
  });

  it('rejects substituted entry content', () => {
    const { record } = trackRecord();
    const forged = clone(record);
    (forged.entry as any).Present = appEntry({ schema: 'holochain-music/track/v1', title: 'Substituted' });
    expect(reason(() => verifyNetworkRecord(forged))).toMatch(/entry content/);
  });

  it('rejects truncated signatures and missing content', () => {
    const { record } = trackRecord();
    const short = clone(record);
    (short.signed_action as any).signature = (short.signed_action as any).signature.slice(0, 63);
    expect(reason(() => verifyNetworkRecord(short))).toMatch(/signature length/);
    expect(reason(() => verifyNetworkRecord({ signed_action: { hashed: {} } } as never))).toMatch(/missing action/);
  });
});

function signedLink(kp: sodium.KeyPair, base: Uint8Array, target: Uint8Array, linkType = 4, author = agent(kp)): NetworkLink {
  const params = {
    author, timestamp: 1_700_000_000_000_001, action_seq: 11, prev_action: fakeHash(HoloHashType.Action, 4),
    base_address: base, target_address: target, zome_index: 0, link_type: linkType, tag: new Uint8Array([1, 2]),
  };
  const bytes = serializeAction(buildCreateLinkAction(params as never));
  return {
    create_link_hash: fakeHash(HoloHashType.Action, 99), // as the pinned worker fabricates it
    base, target, zome_index: 0, link_type: linkType, tag: params.tag, timestamp: params.timestamp as never, author,
    prev_action: params.prev_action, action_seq: params.action_seq, signature: sodium.crypto_sign_detached(bytes, kp.privateKey),
  } as NetworkLink;
}

describe('verifyNetworkLink', () => {
  const base = fakeHash(HoloHashType.Entry, 1);
  const target = fakeHash(HoloHashType.Action, 2);

  it('authenticates a signed link and replaces the fabricated create_link_hash with the real hash', () => {
    const link = signedLink(artist, base, target);
    const out = verifyNetworkLink(link, base, 4, 0);
    const bytes = serializeAction(buildCreateLinkAction({ author: link.author, timestamp: link.timestamp, action_seq: 11,
      prev_action: link.prev_action!, base_address: base, target_address: target, zome_index: 0, link_type: 4, tag: link.tag } as never));
    expect(Array.from(out.create_link_hash)).toEqual(Array.from(hashFrom32AndType(blake2b256(bytes), HoloHashType.Action)));
  });

  it('rejects a link injected under another author', () => {
    expect(reason(() => verifyNetworkLink(signedLink(attacker, base, target, 4, agent(artist)), base))).toMatch(/signature/);
  });

  it('rejects a retargeted signed link', () => {
    const link = { ...signedLink(artist, base, target), target: fakeHash(HoloHashType.Action, 66) };
    expect(reason(() => verifyNetworkLink(link, base))).toMatch(/signature/);
  });

  it('rejects links for another base, type or zome, and partially signed links', () => {
    const link = signedLink(artist, base, target);
    expect(reason(() => verifyNetworkLink(link, fakeHash(HoloHashType.Entry, 7)))).toMatch(/base/);
    expect(reason(() => verifyNetworkLink(link, base, 5))).toMatch(/type/);
    expect(reason(() => verifyNetworkLink(link, base, 4, 1))).toMatch(/zome/);
    expect(reason(() => verifyNetworkLink({ ...link, signature: undefined }, base))).toMatch(/partially/);
  });

  it('passes unsigned gateway Links only when they match the query (authorship not verifiable)', () => {
    const { signature, prev_action, action_seq, ...unsigned } = signedLink(artist, base, target);
    expect(reason(() => verifyNetworkLink(unsigned as NetworkLink, base, 4, 0))).toBe('accepted');
    expect(reason(() => verifyNetworkLink(unsigned as NetworkLink, base, 3, 0))).toMatch(/type/);
  });
});

describe('withRecordVerification (malicious gateway)', () => {
  function gateway(overrides: Partial<NetworkService>): NetworkService {
    return {
      getRecordSync: () => null, getLinksSync: () => [], getDetailsSync: () => null, countLinksSync: () => 3,
      getAgentActivitySync: () => null, mustGetAgentActivitySync: () => null, isAvailable: () => true,
      getLinkerUrl: () => 'http://gateway.test', ...overrides,
    } as NetworkService;
  }

  it('turns forged records into not-found and reports each rejection', () => {
    const genuine = trackRecord();
    const forged = trackRecord(attacker, 'Forged', agent(artist));
    const onReject = vi.fn();
    const svc = withRecordVerification(gateway({ getRecordSync: (_d, h) => (h === genuine.record.signed_action.hashed.hash ? genuine.record : forged.record) }), onReject);
    expect(svc.getRecordSync(DNA, genuine.record.signed_action.hashed.hash)).toBe(genuine.record);
    expect(svc.getRecordSync(DNA, forged.record.signed_action.hashed.hash)).toBeNull();
    expect(onReject).toHaveBeenCalledWith('record', expect.stringMatching(/signature/));
  });

  it('drops injected and mismatched links but keeps genuine ones', () => {
    const base = fakeHash(HoloHashType.Entry, 1);
    const good = signedLink(artist, base, fakeHash(HoloHashType.Action, 2));
    const injected = signedLink(attacker, base, fakeHash(HoloHashType.Action, 3), 4, agent(artist));
    const otherBase = signedLink(artist, fakeHash(HoloHashType.Entry, 8), fakeHash(HoloHashType.Action, 2));
    const svc = withRecordVerification(gateway({ getLinksSync: () => [good, injected, otherBase] }));
    const out = svc.getLinksSync(DNA, base, 4, 0);
    expect(out).toHaveLength(1);
    expect(Array.from(out[0].target)).toEqual(Array.from(good.target));
  });

  it('verifies record details and rejects unknown detail shapes', () => {
    const { record } = trackRecord();
    const hash = record.signed_action.hashed.hash;
    const ok = { type: 'Record', content: { record, deletes: [], updates: [], validation_status: 'Valid' } };
    expect(reason(() => verifyDetails(ok, hash))).toBe('accepted');
    const svc = withRecordVerification(gateway({ getDetailsSync: () => ({ type: 'Surprise', content: {} }) }));
    expect(svc.getDetailsSync(DNA, hash)).toBeNull();
    const forgedUpdate = { ...ok, content: { ...ok.content, updates: [trackRecord(attacker, 'x', agent(artist)).record.signed_action] } };
    expect(reason(() => verifyDetails(forgedUpdate, hash))).toMatch(/signature/);
  });

  it('exposes only verified interface members', () => {
    const inner = Object.assign(gateway({}), { getRecord: async () => ({}) });
    const svc = withRecordVerification(inner as NetworkService) as Record<string, unknown>;
    expect(svc.getRecord).toBeUndefined();
    expect((svc as unknown as NetworkService).countLinksSync(DNA, new Uint8Array(39) as never)).toBe(3);
  });
});
