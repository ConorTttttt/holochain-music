/**
 * call_remote authorisation against canonical Holochain 0.7 vectors
 * (web/hwc/remote-call/vectors-rs, holochain_zome_types 0.7.0).
 */
import { beforeAll, describe, expect, it } from 'vitest';
import sodium from 'libsodium-wrappers';
import { readFileSync } from 'node:fs';
import { blake2b256 } from '../hash';
import {
  authorizeRemoteCall, capGrantIsValid, decodeZomeCallParams, encodeZomeCallParams, MemoryNonceWitness,
  RemoteCallDenied, sha512, verifyZomeCallSignature, WITNESSABLE_EXPIRY_US, type ZomeCallCapGrant, type ZomeCallParams,
} from './remote-call-auth';

const V = JSON.parse(readFileSync(new URL('./zome-call-vectors.json', import.meta.url), 'utf8'));
const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
let caller: sodium.KeyPair;
const NOW = 1_800_000_000_000_000 - 60_000_000; // one minute before the vectors expire
const inbox: ZomeCallCapGrant = { tag: 'inbox', access: 'Unrestricted', functions: { Listed: [['music_storage', 'receive_access_request'], ['music_storage', 'receive_grant']] } };

beforeAll(async () => {
  await sodium.ready;
  caller = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(7));
});

function vectorParams(c: any): ZomeCallParams {
  return {
    provenance: hex(c.provenance), cell_id: [hex(c.cell_dna), hex(c.cell_agent)], zome_name: c.zome_name, fn_name: c.fn_name,
    cap_secret: c.cap_secret ? hex(c.cap_secret) : null, payload: hex(c.payload), nonce: hex(c.nonce), expires_at: c.expires_at,
  };
}

function sign(params: ZomeCallParams, kp = caller) {
  const bytes = encodeZomeCallParams(params);
  return { bytes, signature: sodium.crypto_sign_detached(sha512(bytes), kp.privateKey) };
}

const denied = (fn: () => unknown) => { try { fn(); return 'authorised'; } catch (e) { expect(e).toBeInstanceOf(RemoteCallDenied); return (e as RemoteCallDenied).reason; } };

describe('byte compatibility with Holochain 0.7', () => {
  it('encodes ZomeCallParams exactly like holochain_serialized_bytes and verifies native signatures', () => {
    for (const c of V.cases) {
      const params = vectorParams(c);
      expect(Buffer.from(encodeZomeCallParams(params)).toString('hex')).toBe(c.bytes);
      expect(Buffer.from(sha512(hex(c.bytes))).toString('hex')).toBe(c.sha512);
      expect(() => verifyZomeCallSignature(hex(c.bytes), hex(c.signature), params.provenance)).not.toThrow();
      const decoded = decodeZomeCallParams(hex(c.bytes));
      expect(decoded.fn_name).toBe(c.fn_name);
    }
  });

  it('our signature equals the native signature for the same params (deterministic Ed25519)', () => {
    const c = V.cases[0];
    expect(Buffer.from(sign(vectorParams(c)).signature).toString('hex')).toBe(c.signature);
  });

  it('rejects the blake2b-256 digest HWC currently uses for remote signals', () => {
    const c = V.cases[0];
    const wrong = sodium.crypto_sign_detached(blake2b256(hex(c.bytes)), caller.privateKey);
    expect(denied(() => verifyZomeCallSignature(hex(c.bytes), wrong, hex(c.provenance)))).toMatch(/signature/);
  });
});

describe('authorizeRemoteCall (native is_authorized order)', () => {
  const c = () => V.cases[0];
  const input = (over: Partial<Parameters<typeof authorizeRemoteCall>[0]> = {}) => ({
    bytes: hex(c().bytes), signature: hex(c().signature), localCell: [hex(c().cell_dna), hex(c().cell_agent)] as [Uint8Array, Uint8Array],
    grants: [inbox], witness: new MemoryNonceWitness(), nowUs: NOW, ...over,
  });

  it('authorises a genuine inbox delivery once and refuses its replay', () => {
    const witness = new MemoryNonceWitness();
    expect(authorizeRemoteCall(input({ witness })).fn_name).toBe('receive_grant');
    expect(denied(() => authorizeRemoteCall(input({ witness })))).toBe('nonce duplicate');
  });

  it('does not witness the nonce when the signature is invalid', () => {
    const witness = new MemoryNonceWitness();
    const bad = hex(c().signature); bad[0] ^= 1;
    expect(denied(() => authorizeRemoteCall(input({ witness, signature: bad })))).toMatch(/signature/);
    expect(authorizeRemoteCall(input({ witness })).fn_name).toBe('receive_grant');
  });

  it('refuses tampered bytes, other cells, expired and far-future calls', () => {
    const tampered = hex(c().bytes); tampered[tampered.length - 20] ^= 1;
    expect(denied(() => authorizeRemoteCall(input({ bytes: tampered })))).toMatch(/signature|decod|shape|field|canonical/);
    expect(denied(() => authorizeRemoteCall(input({ localCell: [hex(c().cell_dna), hex(c().provenance)] })))).toMatch(/different cell/);
    expect(denied(() => authorizeRemoteCall(input({ nowUs: c().expires_at })))).toBe('nonce expired');
    expect(denied(() => authorizeRemoteCall(input({ nowUs: c().expires_at - WITNESSABLE_EXPIRY_US - 1 })))).toBe('nonce future');
  });

  it('requires a capability grant covering the exact function', () => {
    expect(denied(() => authorizeRemoteCall(input({ grants: [] })))).toMatch(/capability/);
    const other: ZomeCallCapGrant = { ...inbox, functions: { Listed: [['music_storage', 'receive_access_request']] } };
    expect(denied(() => authorizeRemoteCall(input({ grants: [other] })))).toMatch(/capability/);
  });

  it('a forged caller (signature by another key) is refused', () => {
    const mallory = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(66));
    const { bytes, signature } = sign(vectorParams(c()), mallory);
    expect(denied(() => authorizeRemoteCall(input({ bytes, signature })))).toMatch(/signature/);
  });
});

describe('capGrantIsValid (CapGrant::is_valid)', () => {
  const agent = new Uint8Array(39).fill(1);
  const other = new Uint8Array(39).fill(2);
  const secret = new Uint8Array(64).fill(3);
  it('Transferable needs the secret; Assigned needs secret and assignee', () => {
    const t: ZomeCallCapGrant = { tag: 't', access: { Transferable: { secret } }, functions: 'All' };
    expect(capGrantIsValid(t, 'z', 'f', agent, secret)).toBe(true);
    expect(capGrantIsValid(t, 'z', 'f', agent, null)).toBe(false);
    const a: ZomeCallCapGrant = { tag: 'a', access: { Assigned: { secret, assignees: [agent] } }, functions: 'All' };
    expect(capGrantIsValid(a, 'z', 'f', agent, secret)).toBe(true);
    expect(capGrantIsValid(a, 'z', 'f', other, secret)).toBe(false);
    expect(capGrantIsValid(a, 'z', 'f', agent, new Uint8Array(64))).toBe(false);
  });
});
