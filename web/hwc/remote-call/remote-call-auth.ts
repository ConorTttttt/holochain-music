/**
 * Authorisation of an incoming Holochain `call_remote` for a browser (HWC) cell.
 *
 * Reference semantics, Holochain 0.7.0:
 *  - `Cell::handle_call_remote` (holochain/src/conductor/cell.rs): decode
 *    `ZomeCallParams`, verify the provenance's Ed25519 signature over
 *    `sha2_512(bytes)` (`is_valid_signature`), then `call_zome`.
 *  - `ZomeCallInvocation::is_authorized` (holochain/src/core/ribosome.rs), in
 *    this order: witness the nonce (fresh), find a valid cap grant, check
 *    blocks. The nonce MUST only be written after the signature verified.
 *  - `witness_nonce` (holochain_data 0.7.0): Expired if `expires <= now`,
 *    Future if `expires > now + 50 min`, Duplicate if already witnessed for
 *    that agent, otherwise Fresh.
 *  - `CapGrant::is_valid` (holochain_integrity_types 0.7.0): the chain author
 *    is always authorised; otherwise the function must be granted, an
 *    Assigned grant must list the caller, and Transferable/Assigned grants
 *    need the matching secret (Unrestricted needs none).
 *
 * This module is transport-independent and has no side effects except the
 * nonce witness. The runtime wiring (persistent witness, live grants from the
 * source chain, dedicated execution entry point) is in remote-call-runtime.ts.
 */
import sodium from 'libsodium-wrappers';
import { decode, encode } from '@msgpack/msgpack';

export const WITNESSABLE_EXPIRY_US = 50 * 60 * 1_000_000;

export interface ZomeCallParams {
  provenance: Uint8Array;
  cell_id: [Uint8Array, Uint8Array];
  zome_name: string;
  fn_name: string;
  cap_secret: Uint8Array | null;
  payload: Uint8Array;
  nonce: Uint8Array;
  expires_at: number;
}

export type GrantedFunctions = 'All' | { Listed: Array<[string, string]> };
export type CapAccess =
  | 'Unrestricted'
  | { Transferable: { secret: Uint8Array } }
  | { Assigned: { secret: Uint8Array; assignees: Uint8Array[] } };
export interface ZomeCallCapGrant { tag: string; access: CapAccess; functions: GrantedFunctions }

/**
 * Which native outcome a denial corresponds to:
 *  - 'authentication': undecodable params or bad signature (native: error, ErrorRes)
 *  - 'cell': params addressed to another cell (native: no such cell, ErrorRes)
 *  - 'nonce': ZomeCallResponse::Unauthorized(BadNonce(..))
 *  - 'capability': ZomeCallResponse::Unauthorized(BadCapGrant)
 */
export type DenialKind = 'authentication' | 'cell' | 'nonce' | 'capability';

export class RemoteCallDenied extends Error {
  constructor(public readonly reason: string, public readonly kind: DenialKind = 'authentication',
              public readonly params?: ZomeCallParams) {
    super(`call_remote denied: ${reason}`);
    this.name = 'RemoteCallDenied';
  }
}

const deny = (reason: string, kind: DenialKind = 'authentication', params?: ZomeCallParams): never => {
  throw new RemoteCallDenied(reason, kind, params);
};

/** SHA-512 (holo_hash::sha2_512). */
export function sha512(bytes: Uint8Array): Uint8Array {
  const digest = sodium.crypto_hash(bytes);
  if (digest.length !== 64) throw new Error('crypto_hash is not SHA-512');
  return digest;
}

const isBytes = (v: unknown, len?: number): v is Uint8Array => v instanceof Uint8Array && (len === undefined || v.length === len);

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** holochain_serialized_bytes::encode(&ZomeCallParams): a msgpack map in field order. */
export function encodeZomeCallParams(p: ZomeCallParams): Uint8Array {
  return new Uint8Array(encode({
    provenance: p.provenance, cell_id: [p.cell_id[0], p.cell_id[1]], zome_name: p.zome_name, fn_name: p.fn_name,
    cap_secret: p.cap_secret, payload: p.payload, nonce: p.nonce, expires_at: p.expires_at,
  }, { useBigInt64: false }));
}

/** Strict decode: exact field set and types, canonical re-encoding. */
export function decodeZomeCallParams(bytes: Uint8Array): ZomeCallParams {
  let v: any;
  try {
    v = decode(bytes);
  } catch {
    return deny('undecodable zome call params');
  }
  const keys = ['provenance', 'cell_id', 'zome_name', 'fn_name', 'cap_secret', 'payload', 'nonce', 'expires_at'];
  if (!v || typeof v !== 'object' || Object.keys(v).join() !== keys.join()) deny('unexpected zome call params shape');
  if (!isBytes(v.provenance, 39) || !Array.isArray(v.cell_id) || v.cell_id.length !== 2
      || !isBytes(v.cell_id[0], 39) || !isBytes(v.cell_id[1], 39)
      || typeof v.zome_name !== 'string' || typeof v.fn_name !== 'string'
      || !(v.cap_secret === null || isBytes(v.cap_secret, 64)) || !isBytes(v.payload)
      || !isBytes(v.nonce, 32) || !Number.isSafeInteger(v.expires_at)) {
    deny('invalid zome call params field');
  }
  const params = v as ZomeCallParams;
  if (!eq(encodeZomeCallParams(params), bytes)) deny('non-canonical zome call params encoding');
  return params;
}

/** Ed25519 by `provenance` over sha2_512(bytes) (holochain is_valid_signature). */
export function verifyZomeCallSignature(bytes: Uint8Array, signature: Uint8Array, provenance: Uint8Array): void {
  if (!isBytes(signature, 64)) deny('signature length');
  // libsodium's crypto_hash is SHA-512 (the non-sumo build has no crypto_hash_sha512).
  // Computed outside the try so a missing primitive fails loudly, not as "bad signature".
  const digest = sha512(bytes);
  let ok = false;
  try {
    ok = sodium.crypto_sign_verify_detached(signature, digest, provenance.slice(3, 35));
  } catch {
    ok = false;
  }
  if (!ok) deny('zome call signature does not verify for provenance');
}

export type WitnessResult = 'Fresh' | 'Duplicate' | 'Expired' | 'Future';
export interface NonceWitness {
  /** Atomically record (agent, nonce) until `expiresUs`; must be persistent across restarts in production. */
  witness(agent: Uint8Array, nonce: Uint8Array, nowUs: number, expiresUs: number): WitnessResult;
}

/** Reference in-memory witness with the native rules (tests; production needs IndexedDB/OPFS). */
export class MemoryNonceWitness implements NonceWitness {
  private seen = new Map<string, number>();
  witness(agent: Uint8Array, nonce: Uint8Array, nowUs: number, expiresUs: number): WitnessResult {
    if (expiresUs <= nowUs) return 'Expired';
    if (expiresUs > nowUs + WITNESSABLE_EXPIRY_US) return 'Future';
    for (const [k, exp] of this.seen) if (exp <= nowUs) this.seen.delete(k);
    const key = `${sodium.to_hex(agent.slice(0, 36))}:${sodium.to_hex(nonce)}`;
    if (this.seen.has(key)) return 'Duplicate';
    this.seen.set(key, expiresUs);
    return 'Fresh';
  }
}

/** holochain_integrity_types CapGrant::is_valid for one grant (chain author handled by caller). */
export function capGrantIsValid(grant: ZomeCallCapGrant, zome: string, fn: string, agent: Uint8Array, secret: Uint8Array | null): boolean {
  const granted = grant.functions === 'All'
    || (typeof grant.functions === 'object' && grant.functions.Listed.some(([z, f]) => z === zome && f === fn));
  const access = grant.access;
  const agentOk = typeof access === 'object' && 'Assigned' in access ? access.Assigned.assignees.some(a => eq(a, agent)) : true;
  const secretOk = access === 'Unrestricted' ? true
    : 'Transferable' in access ? !!secret && eq(access.Transferable.secret, secret)
      : !!secret && eq(access.Assigned.secret, secret);
  return granted && agentOk && secretOk;
}

export interface AuthorizeInput {
  bytes: Uint8Array;
  signature: Uint8Array;
  /** This browser cell: [DnaHash, AgentPubKey] */
  localCell: [Uint8Array, Uint8Array];
  /** Live (committed, not deleted) cap grants on the local chain. */
  grants: ZomeCallCapGrant[];
  witness: NonceWitness;
  nowUs: number;
}

export interface AuthorizedRemoteCall {
  params: ZomeCallParams;
  /** The grant that authorised a non-author caller (null for the chain author). */
  grant: ZomeCallCapGrant | null;
  /** Native WitnessNonceResult of the accepted call (always Fresh). */
  nonce: 'Fresh';
}

/** Native order: decode → signature → target cell → nonce → grant. */
export function authorizeRemoteCallDetailed(input: AuthorizeInput): AuthorizedRemoteCall {
  const params = decodeZomeCallParams(input.bytes);
  verifyZomeCallSignature(input.bytes, input.signature, params.provenance);
  if (!eq(params.cell_id[0], input.localCell[0]) || !eq(params.cell_id[1], input.localCell[1])) {
    deny('call is for a different cell', 'cell', params);
  }
  const nonce = input.witness.witness(params.provenance, params.nonce, input.nowUs, params.expires_at);
  if (nonce !== 'Fresh') deny(`nonce ${nonce.toLowerCase()}`, 'nonce', params);
  if (eq(params.provenance, input.localCell[1])) return { params, grant: null, nonce: 'Fresh' };
  const grant = input.grants.find(g => capGrantIsValid(g, params.zome_name, params.fn_name, params.provenance, params.cap_secret));
  if (!grant) deny('no capability grant authorises this caller and function', 'capability', params);
  return { params, grant: grant!, nonce: 'Fresh' };
}

/** Returns the params to execute (see authorizeRemoteCallDetailed). */
export function authorizeRemoteCall(input: AuthorizeInput): ZomeCallParams {
  return authorizeRemoteCallDetailed(input).params;
}
