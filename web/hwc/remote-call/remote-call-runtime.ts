/**
 * Runtime support for standard Holochain `call_remote` in HWC.
 *
 * Browser-independent: used by the ribosome (Chromium offscreen worker and the
 * Firefox dedicated worker run the same ribosome-worker.ts). Transport is the
 * authenticated H2HC gateway (`POST /call_remote/{dna}` outgoing,
 * `call_remote_incoming` WebSocket frames incoming); see
 * holochain-music/docs/web/call-remote.md.
 *
 * Outgoing mirrors holochain 0.7 `host_fn/call.rs` (CallTarget::NetworkAgent):
 * provenance is ALWAYS the calling cell's own agent, nonce = 32 random bytes,
 * expires_at = now + 5 min (FRESH_NONCE_EXPIRES_AFTER), signature = Ed25519
 * over sha2_512(encode(params)) by the agent's Lair key. Network failures become
 * ZomeCallResponse::NetworkError, as natively.
 *
 * Incoming mirrors `Cell::handle_call_remote` + `ZomeCallInvocation::is_authorized`:
 * decode, verify signature, target cell, witness nonce (persistent), live cap
 * grant from the local source chain. HWC has no block list (block_agent was
 * removed from the 0.7 HDK and HWC has no admin API), so BlockedProvenance
 * cannot arise.
 */
import { decode, encode } from '@msgpack/msgpack';
import {
  authorizeRemoteCallDetailed, encodeZomeCallParams, sha512, RemoteCallDenied,
  type CapAccess, type GrantedFunctions, type NonceWitness, type WitnessResult,
  type ZomeCallCapGrant, type ZomeCallParams, WITNESSABLE_EXPIRY_US,
} from './remote-call-auth';

/** holochain_nonce FRESH_NONCE_EXPIRES_AFTER */
export const FRESH_NONCE_EXPIRES_US = 5 * 60 * 1_000_000;

/** Minimal storage surface (StorageProvider satisfies it). */
export interface GrantStorage {
  queryActions(dnaHash: Uint8Array, agentPubKey: Uint8Array, filter?: { actionType?: string }): any[];
  getEntry(entryHash: Uint8Array): { entryContent: Uint8Array; entryType: unknown } | null;
}

/** A persistent, atomic witness (SQLite table in the extension worker). */
export interface NonceWitnessStorage {
  witnessRemoteCallNonce(agent: Uint8Array, nonce: Uint8Array, nowUs: number, expiresUs: number): WitnessResult;
}

export function hasNonceWitness(storage: unknown): storage is NonceWitnessStorage {
  return typeof (storage as NonceWitnessStorage)?.witnessRemoteCallNonce === 'function';
}

/** The native witness rules applied on top of an atomic "insert if absent". */
export function witnessWith(
  insertIfAbsent: (agentKey: string, nonceKey: string, expiresUs: number) => boolean,
  agent: Uint8Array, nonce: Uint8Array, nowUs: number, expiresUs: number,
): WitnessResult {
  if (expiresUs <= nowUs) return 'Expired';
  if (expiresUs > nowUs + WITNESSABLE_EXPIRY_US) return 'Future';
  return insertIfAbsent(hex(agent.subarray(0, 36)), hex(nonce), expiresUs) ? 'Fresh' : 'Duplicate';
}

const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const bytes = (v: unknown): Uint8Array | null =>
  v instanceof Uint8Array ? v : Array.isArray(v) && v.every(x => Number.isInteger(x)) ? new Uint8Array(v) : null;

/*
 * Native serde (holochain_integrity_types 0.7 capability/grant.rs):
 *   CapAccess        #[serde(tag = "type", content = "value", rename_all = "snake_case")]
 *     {type:"unrestricted"} | {type:"transferable", value:{secret}} | {type:"assigned", value:{secret, assignees}}
 *   GrantedFunctions same tagging: {type:"all"} | {type:"listed", value:[[zome, fn], ...]}
 * Exactly these shapes are accepted (vectors: cap_grants in zome-call-vectors.json).
 */
function normalizeAccess(a: any): CapAccess | null {
  if (!a || typeof a !== 'object' || typeof a.type !== 'string') return null;
  if (a.type === 'unrestricted' && !('value' in a)) return 'Unrestricted';
  if (a.type === 'transferable') {
    const secret = bytes(a.value?.secret);
    return secret?.length === 64 ? { Transferable: { secret } } : null;
  }
  if (a.type === 'assigned') {
    const secret = bytes(a.value?.secret);
    const assignees = Array.isArray(a.value?.assignees) ? a.value.assignees.map(bytes) : null;
    return secret?.length === 64 && assignees && assignees.every((x: Uint8Array | null) => x?.length === 39)
      ? { Assigned: { secret, assignees } } : null;
  }
  return null;
}

function normalizeFunctions(f: any): GrantedFunctions | null {
  if (!f || typeof f !== 'object' || typeof f.type !== 'string') return null;
  if (f.type === 'all' && !('value' in f)) return 'All';
  if (f.type === 'listed' && Array.isArray(f.value)) {
    const listed = f.value.filter((p: unknown) => Array.isArray(p) && p.length === 2
      && typeof p[0] === 'string' && typeof p[1] === 'string');
    return listed.length === f.value.length ? { Listed: listed } : null;
  }
  return null;
}

/**
 * Live ZomeCallCapGrants of this cell: CapGrant entries created by the cell
 * whose action was neither deleted nor updated. Anything unparseable is
 * ignored (fails closed).
 */
export type LiveCapGrant = ZomeCallCapGrant & { /** native-serialised value, for call_info() */ raw: unknown };

export function liveCapGrants(storage: GrantStorage, dnaHash: Uint8Array, agent: Uint8Array): LiveCapGrant[] {
  const actions = storage.queryActions(dnaHash, agent) || [];
  const dead = new Set<string>();
  for (const a of actions) {
    if (a?.actionType === 'Delete' && a.deletesActionHash) dead.add(hex(bytes(a.deletesActionHash)!));
    if (a?.actionType === 'Update' && a.originalActionHash) dead.add(hex(bytes(a.originalActionHash)!));
  }
  const grants: LiveCapGrant[] = [];
  for (const a of actions) {
    if ((a?.actionType !== 'Create' && a?.actionType !== 'Update') || a.entryType !== 'CapGrant') continue;
    if (dead.has(hex(bytes(a.actionHash)!))) continue;
    const entry = storage.getEntry(a.entryHash);
    if (!entry) continue;
    let raw: any;
    try { raw = decode(entry.entryContent); } catch { continue; }
    const access = normalizeAccess(raw?.access);
    const functions = normalizeFunctions(raw?.functions);
    if (access && functions && typeof raw?.tag === 'string') grants.push({ tag: raw.tag, access, functions, raw });
  }
  return grants;
}

/** ZomeCallResponse as decoded from / encoded to msgpack (externally tagged). */
export type ZomeCallResponseValue =
  | { Ok: Uint8Array }
  | { Unauthorized: [unknown, Uint8Array | null, string, string] }
  | { NetworkError: string }
  | { AuthenticationFailed: [Uint8Array, Uint8Array] }
  | { CountersigningSession: string };

export function encodeZomeCallResponse(r: ZomeCallResponseValue): Uint8Array {
  return new Uint8Array(encode(r));
}

export function decodeZomeCallResponse(b: Uint8Array): ZomeCallResponseValue {
  const v: any = decode(b);
  if (!v || typeof v !== 'object' || Object.keys(v).length !== 1) throw new Error('invalid ZomeCallResponse');
  const k = Object.keys(v)[0];
  if (k === 'Ok' && v.Ok instanceof Uint8Array) return v;
  if (k === 'NetworkError' && typeof v.NetworkError === 'string') return v;
  if (k === 'CountersigningSession' && typeof v.CountersigningSession === 'string') return v;
  if (k === 'Unauthorized' && Array.isArray(v.Unauthorized) && v.Unauthorized.length === 4) return v;
  if (k === 'AuthenticationFailed' && Array.isArray(v.AuthenticationFailed)) return v;
  throw new Error('invalid ZomeCallResponse');
}

export interface IncomingOutcome {
  /** Execute with these params (provenance = verified caller). */
  execute?: { params: ZomeCallParams; grant: ZomeCallCapGrant | null };
  /** Native ZomeCallResponse to return without executing. */
  response?: Uint8Array;
  /** Error for ErrorRes (native returns an error for authentication / unknown cell). */
  error?: string;
}

/**
 * Authorise an incoming call against live local state. The nonce is consumed
 * only after the signature verified and only for this cell.
 */
export function authorizeIncoming(
  storage: GrantStorage & NonceWitnessStorage,
  localCell: [Uint8Array, Uint8Array],
  paramsBytes: Uint8Array,
  signature: Uint8Array,
  nowUs: number,
): IncomingOutcome {
  const witness: NonceWitness = {
    witness: (agent, nonce, now, exp) => storage.witnessRemoteCallNonce(agent, nonce, now, exp),
  };
  try {
    const grants = liveCapGrants(storage, localCell[0], localCell[1]);
    const ok = authorizeRemoteCallDetailed({ bytes: paramsBytes, signature, localCell, grants, witness, nowUs });
    return { execute: { params: ok.params, grant: ok.grant } };
  } catch (e) {
    if (!(e instanceof RemoteCallDenied)) throw e;
    const p = e.params;
    if (e.kind === 'nonce' && p) {
      const result = e.reason.replace(/^nonce /, '');
      const badNonce = { BadNonce: result.charAt(0).toUpperCase() + result.slice(1) };
      return { response: encodeZomeCallResponse({ Unauthorized: [badNonce, p.cap_secret, p.zome_name, p.fn_name] }) };
    }
    if (e.kind === 'capability' && p) {
      return { response: encodeZomeCallResponse({ Unauthorized: ['BadCapGrant', p.cap_secret, p.zome_name, p.fn_name] }) };
    }
    return { error: e.message };
  }
}

export interface Signer {
  /** Ed25519 by the agent's Lair key (raw 32-byte public key). */
  signSync(rawPubKey: Uint8Array, data: Uint8Array): Uint8Array;
}

/** Build and sign outgoing ZomeCallParams exactly as native NetworkAgent calls do. */
export function signOutgoingCall(
  signer: Signer,
  from: { dnaHash: Uint8Array; agent: Uint8Array },
  target: Uint8Array,
  zomeName: string,
  fnName: string,
  capSecret: Uint8Array | null,
  payload: Uint8Array,
  nowUs: number,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(32)),
): { params: ZomeCallParams; bytes: Uint8Array; signature: Uint8Array } {
  if (target.length !== 39 || from.agent.length !== 39 || from.dnaHash.length !== 39) throw new Error('invalid call_remote target');
  if (capSecret !== null && capSecret.length !== 64) throw new Error('invalid cap secret');
  const params: ZomeCallParams = {
    provenance: from.agent,
    cell_id: [from.dnaHash, target],
    zome_name: zomeName,
    fn_name: fnName,
    cap_secret: capSecret,
    payload,
    nonce,
    expires_at: nowUs + FRESH_NONCE_EXPIRES_US,
  };
  const bytes = encodeZomeCallParams(params);
  const signature = signer.signSync(from.agent.slice(3, 35), sha512(bytes));
  if (signature.length !== 64) throw new Error('signing failed');
  return { params, bytes, signature };
}

/** Transport for outgoing calls (implemented by the worker's network service). */
export interface CallRemoteTransport {
  callRemoteSync(dnaHash: Uint8Array, target: Uint8Array, paramsBytes: Uint8Array, signature: Uint8Array):
    { ok: true; response: Uint8Array } | { ok: false; error: string };
}

export function hasCallRemoteTransport(n: unknown): n is CallRemoteTransport {
  return typeof (n as CallRemoteTransport)?.callRemoteSync === 'function';
}

/*
 * The call_remote transport is registered separately from the DHT
 * NetworkService: that service is wrapped by record verification, which
 * deliberately exposes only verified DHT members. A call_remote reply is the
 * recipient's ZomeCallResponse, not DHT data (see docs/web/security.md for its
 * trust classification).
 */
let transport: CallRemoteTransport | null = null;
export function setCallRemoteTransport(t: CallRemoteTransport | null): void { transport = t; }
export function getCallRemoteTransport(): CallRemoteTransport | null { return transport; }
