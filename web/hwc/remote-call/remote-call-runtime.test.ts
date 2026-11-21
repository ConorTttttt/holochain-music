/**
 * call_remote runtime against canonical Holochain 0.7 vectors: outgoing
 * signing, native ZomeCallResponse encodings, persistent nonce witnessing,
 * live capability grants from the source chain and incoming authorisation.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import sodium from 'libsodium-wrappers';
import { encode } from '@msgpack/msgpack';
import { readFileSync } from 'node:fs';
import { encodeZomeCallParams, sha512, type WitnessResult, type ZomeCallParams } from './remote-call-auth';
import {
  authorizeIncoming, decodeZomeCallResponse, encodeZomeCallResponse, liveCapGrants, signOutgoingCall,
  witnessWith, FRESH_NONCE_EXPIRES_US, type GrantStorage, type NonceWitnessStorage,
} from './remote-call-runtime';

const V = JSON.parse(readFileSync(new URL('./zome-call-vectors.json', import.meta.url), 'utf8'));
const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const R = (name: string) => hex(V.responses.find((r: any) => r.name === name).bytes);
const NOW = 1_800_000_000_000_000 - 60_000_000;
let caller: sodium.KeyPair;
let other: sodium.KeyPair;

beforeAll(async () => {
  await sodium.ready;
  caller = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(7));
  other = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(8));
});

const signer = (kp: () => sodium.KeyPair) => ({
  signSync: (raw: Uint8Array, data: Uint8Array) => {
    expect(toHex(raw)).toBe(toHex(kp().publicKey));
    return sodium.crypto_sign_detached(data, kp().privateKey);
  },
});

function vectorParams(c: any): ZomeCallParams {
  return {
    provenance: hex(c.provenance), cell_id: [hex(c.cell_dna), hex(c.cell_agent)], zome_name: c.zome_name, fn_name: c.fn_name,
    cap_secret: c.cap_secret ? hex(c.cap_secret) : null, payload: hex(c.payload), nonce: hex(c.nonce), expires_at: c.expires_at,
  };
}

/** A persistent table shared across "restarts" (new storage objects). */
class Table { rows = new Map<string, number>(); }

class FakeStorage implements GrantStorage, NonceWitnessStorage {
  actions: any[] = [];
  entries = new Map<string, Uint8Array>();
  constructor(private table: Table) {}
  queryActions() { return this.actions; }
  getEntry(h: Uint8Array) {
    const c = this.entries.get(toHex(h));
    return c ? { entryContent: c, entryType: 'CapGrant' } : null;
  }
  witnessRemoteCallNonce(agent: Uint8Array, nonce: Uint8Array, nowUs: number, expiresUs: number): WitnessResult {
    return witnessWith((a, n, exp) => {
      for (const [k, e] of this.table.rows) if (e <= nowUs) this.table.rows.delete(k);
      const key = `${a}:${n}`;
      if (this.table.rows.has(key)) return false;
      this.table.rows.set(key, exp);
      return true;
    }, agent, nonce, nowUs, expiresUs);
  }
  addGrant(seq: number, grant: unknown, type: 'Create' | 'Update' = 'Create') {
    const actionHash = new Uint8Array(39).fill(seq);
    const entryHash = new Uint8Array(39).fill(100 + seq);
    this.entries.set(toHex(entryHash), new Uint8Array(encode(grant)));
    this.actions.push({ actionType: type, entryType: 'CapGrant', actionHash, entryHash });
    return actionHash;
  }
}

const inboxGrant = { tag: 'inbox', access: 'Unrestricted', functions: { Listed: [['music_storage', 'receive_access_request'], ['music_storage', 'receive_grant']] } };

describe('outgoing call_remote signing (CallTarget::NetworkAgent)', () => {
  it('produces the native bytes and signature for the same params', () => {
    for (const c of V.cases) {
      const p = vectorParams(c);
      const out = signOutgoingCall(signer(() => caller), { dnaHash: p.cell_id[0], agent: p.provenance }, p.cell_id[1],
        p.zome_name, p.fn_name, p.cap_secret, p.payload, c.expires_at - FRESH_NONCE_EXPIRES_US, p.nonce);
      expect(toHex(out.bytes)).toBe(c.bytes);
      expect(toHex(out.signature)).toBe(c.signature);
      expect(out.params.expires_at).toBe(c.expires_at);
    }
  });

  it('always uses the calling cell as provenance, a fresh 32-byte nonce and a 5 minute expiry', () => {
    const c = V.cases[0];
    const p = vectorParams(c);
    const a = signOutgoingCall(signer(() => caller), { dnaHash: p.cell_id[0], agent: p.provenance }, p.cell_id[1], 'z', 'f', null, p.payload, NOW);
    const b = signOutgoingCall(signer(() => caller), { dnaHash: p.cell_id[0], agent: p.provenance }, p.cell_id[1], 'z', 'f', null, p.payload, NOW);
    expect(toHex(a.params.provenance)).toBe(c.provenance);
    expect(a.params.nonce.length).toBe(32);
    expect(toHex(a.params.nonce)).not.toBe(toHex(b.params.nonce));
    expect(a.params.expires_at).toBe(NOW + 5 * 60 * 1_000_000);
    expect(sodium.crypto_sign_verify_detached(a.signature, sha512(a.bytes), caller.publicKey)).toBe(true);
    expect(() => signOutgoingCall(signer(() => caller), { dnaHash: p.cell_id[0], agent: p.provenance }, new Uint8Array(32), 'z', 'f', null, p.payload, NOW)).toThrow();
    expect(() => signOutgoingCall(signer(() => caller), { dnaHash: p.cell_id[0], agent: p.provenance }, p.cell_id[1], 'z', 'f', new Uint8Array(3), p.payload, NOW)).toThrow();
  });
});

describe('ZomeCallResponse encoding equals holochain_serialized_bytes', () => {
  it('encodes Ok, Unauthorized and NetworkError exactly', () => {
    expect(toHex(encodeZomeCallResponse({ Ok: hex('81a16b01') }))).toBe(toHex(R('ok')));
    expect(toHex(encodeZomeCallResponse({ Unauthorized: ['BadCapGrant', null, 'music_storage', 'receive_grant'] })))
      .toBe(toHex(R('unauthorized-bad-cap-grant')));
    expect(toHex(encodeZomeCallResponse({ Unauthorized: [{ BadNonce: 'Duplicate' }, new Uint8Array(64).fill(5), 'music_storage', 'receive_access_request'] })))
      .toBe(toHex(R('unauthorized-bad-nonce-with-secret')));
    expect(toHex(encodeZomeCallResponse({ NetworkError: 'recipient unreachable' }))).toBe(toHex(R('network-error')));
  });

  it('decodes native responses and rejects anything else', () => {
    for (const r of V.responses) decodeZomeCallResponse(hex(r.bytes));
    expect(() => decodeZomeCallResponse(new Uint8Array(encode({ Ok: 1 })))).toThrow();
    expect(() => decodeZomeCallResponse(new Uint8Array(encode({ Bogus: 'x' })))).toThrow();
    expect(() => decodeZomeCallResponse(new Uint8Array([0xc0]))).toThrow();
  });
});

describe('live capability grants from the source chain', () => {
  it('ignores deleted, updated and malformed grants', () => {
    const s = new FakeStorage(new Table());
    const deleted = s.addGrant(1, { tag: 'a', access: 'Unrestricted', functions: 'All' });
    s.actions.push({ actionType: 'Delete', deletesActionHash: deleted });
    const updated = s.addGrant(2, { tag: 'b', access: 'Unrestricted', functions: 'All' });
    s.addGrant(3, { tag: 'b2', access: { Transferable: { secret: new Uint8Array(64).fill(1) } }, functions: 'All' }, 'Update');
    s.actions.push({ actionType: 'Update', originalActionHash: updated, entryType: 'CapGrant', actionHash: new Uint8Array(39).fill(9), entryHash: new Uint8Array(39).fill(200) });
    s.addGrant(4, { tag: 'bad', access: { Weird: 1 }, functions: 'All' });
    s.addGrant(5, inboxGrant);
    const tags = liveCapGrants(s, new Uint8Array(39), new Uint8Array(39)).map(g => g.tag).sort();
    expect(tags).toEqual(['b2', 'inbox']);
  });
});

describe('incoming call_remote authorisation (native order and outcomes)', () => {
  const cellOf = (c: any): [Uint8Array, Uint8Array] => [hex(c.cell_dna), hex(c.cell_agent)];

  it('executes a genuinely signed call for a granted inbox function with the caller provenance', () => {
    const s = new FakeStorage(new Table());
    s.addGrant(1, inboxGrant);
    const c = V.cases[0];
    const out = authorizeIncoming(s, cellOf(c), hex(c.bytes), hex(c.signature), NOW);
    expect(out.execute?.params.fn_name).toBe('receive_grant');
    expect(toHex(out.execute!.params.provenance)).toBe(c.provenance);
    expect(out.execute?.grant?.tag).toBe('inbox');
  });

  it('answers Unauthorized(BadCapGrant) byte-identically to native when no grant matches', () => {
    const s = new FakeStorage(new Table());
    const c = V.cases[0];
    const out = authorizeIncoming(s, cellOf(c), hex(c.bytes), hex(c.signature), NOW);
    expect(out.execute).toBeUndefined();
    expect(toHex(out.response!)).toBe(toHex(R('unauthorized-bad-cap-grant')));
  });

  it('replay is BadNonce(Duplicate) byte-identically, including after a restart', () => {
    const table = new Table();
    const c = V.cases[1];
    const grant = { tag: 't', access: { Transferable: { secret: hex(c.cap_secret) } }, functions: 'All' };
    const s1 = new FakeStorage(table); s1.addGrant(1, grant);
    expect(authorizeIncoming(s1, cellOf(c), hex(c.bytes), hex(c.signature), NOW).execute).toBeDefined();
    expect(toHex(authorizeIncoming(s1, cellOf(c), hex(c.bytes), hex(c.signature), NOW).response!))
      .toBe(toHex(R('unauthorized-bad-nonce-with-secret')));
    const s2 = new FakeStorage(table); s2.addGrant(1, grant); // "browser restart": same persistent table
    expect(toHex(authorizeIncoming(s2, cellOf(c), hex(c.bytes), hex(c.signature), NOW).response!))
      .toBe(toHex(R('unauthorized-bad-nonce-with-secret')));
  });

  it('concurrent duplicates: exactly one of two identical requests executes', async () => {
    const s = new FakeStorage(new Table());
    s.addGrant(1, inboxGrant);
    const c = V.cases[0];
    const results = await Promise.all([0, 1].map(async () =>
      authorizeIncoming(s, cellOf(c), hex(c.bytes), hex(c.signature), NOW)));
    expect(results.filter(r => r.execute).length).toBe(1);
  });

  it('forged signature, wrong cell, wrong DNA, expired and far-future calls are refused before the nonce is spent', () => {
    const table = new Table();
    const s = new FakeStorage(table);
    s.addGrant(1, inboxGrant);
    const c = V.cases[0];
    const p = vectorParams(c);
    const bytes = hex(c.bytes);
    const forged = sodium.crypto_sign_detached(sha512(bytes), other.privateKey);
    expect(authorizeIncoming(s, cellOf(c), bytes, forged, NOW).error).toMatch(/signature/);
    expect(table.rows.size).toBe(0);
    const [dna, agent] = cellOf(c);
    const wrongAgent = new Uint8Array(agent); wrongAgent[10] ^= 1;
    const wrongDna = new Uint8Array(dna); wrongDna[10] ^= 1;
    expect(authorizeIncoming(s, [dna, wrongAgent], bytes, hex(c.signature), NOW).error).toMatch(/different cell/);
    expect(authorizeIncoming(s, [wrongDna, agent], bytes, hex(c.signature), NOW).error).toMatch(/different cell/);
    expect(table.rows.size).toBe(0);
    const expired = authorizeIncoming(s, cellOf(c), bytes, hex(c.signature), c.expires_at);
    expect(decodeZomeCallResponse(expired.response!)).toEqual({ Unauthorized: [{ BadNonce: 'Expired' }, null, 'music_storage', 'receive_grant'] });
    const future = authorizeIncoming(s, cellOf(c), bytes, hex(c.signature), c.expires_at - 51 * 60 * 1_000_000);
    expect(decodeZomeCallResponse(future.response!)).toEqual({ Unauthorized: [{ BadNonce: 'Future' }, null, 'music_storage', 'receive_grant'] });
    // Impersonation: params claim the vector caller but are signed by another key.
    const fake = { ...p, payload: hex('c0') };
    const fb = encodeZomeCallParams(fake);
    expect(authorizeIncoming(s, cellOf(c), fb, sodium.crypto_sign_detached(sha512(fb), other.privateKey), NOW).error).toMatch(/signature/);
  });

  it('an ungranted function is refused even with a valid signature', () => {
    const s = new FakeStorage(new Table());
    s.addGrant(1, inboxGrant);
    const c = V.cases[0];
    const p = { ...vectorParams(c), fn_name: 'get_inbox_grants', nonce: new Uint8Array(32).fill(1) };
    const bytes = encodeZomeCallParams(p);
    const sig = sodium.crypto_sign_detached(sha512(bytes), caller.privateKey);
    const out = authorizeIncoming(s, cellOf(c), bytes, sig, NOW);
    expect(decodeZomeCallResponse(out.response!)).toEqual({ Unauthorized: ['BadCapGrant', null, 'music_storage', 'get_inbox_grants'] });
  });
});
