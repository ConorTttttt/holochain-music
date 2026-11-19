/**
 * Verification of DHT data returned by an untrusted gateway (h2hc-linker).
 *
 * A zero-arc browser node reads the DHT through a gateway. Without these
 * checks the gateway could return records attributed to any author. Every
 * record is checked here before it can reach the cascade cache, validation
 * or zome WASM:
 *
 *  1. the action hash is recomputed from the exact msgpack bytes Holochain
 *     hashes and signs (`serializeAction` of the normalized wire action) and
 *     must equal `signed_action.hashed.hash`;
 *  2. the Ed25519 signature over those bytes must verify against the action
 *     signer (`actionSigner`, normally the author);
 *  3. the record must be the one asked for: the requested ActionHash equals
 *     the recomputed hash, or the requested EntryHash equals the action's
 *     `entry_hash`;
 *  4. a present entry must hash to the action's `entry_hash`.
 *
 * Links: links that carry their signed CreateLink fields (`signature`,
 * `prev_action`, `action_seq`) are reconstructed, hashed and signature
 * checked, and their `create_link_hash` is replaced by the recomputed hash.
 * Every link must match the requested base and type filter. Links without a
 * signature (the h2hc-linker `Vec<Link>` response) cannot be authenticated by
 * the client; their authorship stays gateway-trusted (see module README).
 *
 * Anything that fails is dropped (treated as not found): fail closed.
 */

import sodium from 'libsodium-wrappers';
import { blake2b256, computeAgentEntryHash, computeAppEntryHash, computeSystemEntryHash, HoloHashType, hashFrom32AndType } from '../hash';
import { serializeAction, buildCreateLinkAction } from '../types/holochain-serialization';
import { wireActionToSerializable } from '../recovery/chain-recovery';
import { actionSigner } from '../signing';
import { isActionHash, isEntryHash } from '../types/holochain-types';
import type { Action } from '../types/holochain-types';
import type { AnyDhtHash, DnaHash } from '@holochain/client';
import type { NetworkLink, NetworkRecord, NetworkService } from './types';
import { createLogger } from '@hwc/shared';

const log = createLogger('RecordVerification');

export class UnverifiedNetworkDataError extends Error {
  constructor(public readonly reason: string) {
    super(`unverified gateway data: ${reason}`);
    this.name = 'UnverifiedNetworkDataError';
  }
}

export type VerificationRejectHandler = (kind: 'record' | 'link' | 'details', reason: string) => void;

const fail = (reason: string): never => { throw new UnverifiedNetworkDataError(reason); };

function bytes(value: unknown, label: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (Array.isArray(value) && value.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) return Uint8Array.from(value);
  if (value && typeof value === 'object') {
    const values = Object.values(value as Record<string, unknown>);
    if (values.every(n => Number.isInteger(n) && (n as number) >= 0 && (n as number) <= 255)) return Uint8Array.from(values as number[]);
  }
  return fail(`${label} is not a byte array`);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

function verifySignedBytes(serialized: Uint8Array, signature: unknown, signer: unknown): void {
  const sig = bytes(signature, 'signature');
  const key = bytes(signer, 'signer');
  if (sig.length !== 64) fail('signature length');
  if (key.length !== 39) fail('signer key length');
  let ok = false;
  try {
    ok = sodium.crypto_sign_verify_detached(sig, serialized, key.slice(3, 35));
  } catch {
    ok = false;
  }
  if (!ok) fail('action signature does not verify against its author');
}

/** Recompute an entry's hash from its content; null for unsupported variants. */
export function computeNetworkEntryHash(entry: unknown): Uint8Array {
  const e = entry as { entry_type?: string; entry?: unknown };
  switch (e?.entry_type) {
    case 'App': return computeAppEntryHash(bytes(e.entry, 'app entry'));
    case 'Agent': return computeAgentEntryHash(bytes(e.entry, 'agent entry'));
    case 'CapClaim':
    case 'CapGrant': return computeSystemEntryHash(e.entry_type, e.entry as Record<string, unknown>);
    default: return fail(`unsupported entry type ${String(e?.entry_type)}`);
  }
}

/** Verify one signed action; returns its recomputed hash and flat fields. */
export function verifySignedAction(signedAction: unknown): { hash: Uint8Array; data: Record<string, unknown> } {
  const sa = signedAction as { hashed?: { hash?: unknown; content?: unknown }; signature?: unknown };
  const content = sa?.hashed?.content as Action | undefined;
  if (!content) fail('missing action content');
  let serializable;
  try {
    serializable = wireActionToSerializable(content as Action);
  } catch (e) {
    fail(`malformed action: ${(e as Error).message}`);
  }
  const serialized = serializeAction(serializable!);
  const hash = hashFrom32AndType(blake2b256(serialized), HoloHashType.Action);
  if (!sameBytes(hash, bytes(sa.hashed!.hash, 'action hash'))) fail('action hash does not match action content');
  let signer: unknown;
  try {
    signer = actionSigner(content as Action);
  } catch {
    fail('cannot determine action signer');
  }
  verifySignedBytes(serialized, sa.signature, signer);
  return { hash, data: (serializable as unknown as { data: Record<string, unknown> }).data };
}

/** Throws UnverifiedNetworkDataError unless `record` is authentic and is the one requested. */
export function verifyNetworkRecord(record: NetworkRecord, requested?: AnyDhtHash): void {
  if (!record || typeof record !== 'object') fail('missing record');
  const { hash, data } = verifySignedAction(record.signed_action);
  const entryHash = data.entry_hash ? bytes(data.entry_hash, 'entry hash') : null;
  if (requested) {
    const req = bytes(requested, 'requested hash');
    if (isActionHash(req)) {
      if (!sameBytes(req, hash)) fail('gateway returned a different action than requested');
    } else if (isEntryHash(req)) {
      if (!entryHash || !sameBytes(req, entryHash)) fail('gateway returned an action for a different entry');
    } else {
      fail('unsupported requested hash type');
    }
  }
  const entry = record.entry as unknown;
  if (entry && typeof entry === 'object' && 'Present' in (entry as object)) {
    if (!entryHash) fail('entry supplied for an action without an entry');
    if (!sameBytes(computeNetworkEntryHash((entry as { Present: unknown }).Present), entryHash!)) {
      fail('entry content does not match the signed entry hash');
    }
  }
}

/**
 * Check one link against the query; authenticate it when the gateway supplied
 * its signed CreateLink fields. Returns the link to use (with the real
 * create_link_hash) or throws.
 */
export function verifyNetworkLink(link: NetworkLink, base: AnyDhtHash, linkType?: number, zomeIndex?: number): NetworkLink {
  if (!sameBytes(bytes(link.base, 'link base'), bytes(base, 'requested base'))) fail('link base differs from query');
  if (linkType !== undefined && link.link_type !== linkType) fail('link type differs from query');
  if (zomeIndex !== undefined && link.zome_index !== zomeIndex) fail('link zome differs from query');
  if (link.signature === undefined && link.prev_action === undefined && link.action_seq === undefined) {
    return link; // unsigned gateway Link: authorship not client-verifiable (documented limit)
  }
  if (link.signature === undefined || link.prev_action === undefined || link.action_seq === undefined) {
    fail('partially signed link');
  }
  const action = buildCreateLinkAction({
    author: bytes(link.author, 'link author') as never, timestamp: Number(link.timestamp) as never,
    action_seq: link.action_seq!, prev_action: bytes(link.prev_action, 'prev_action') as never,
    base_address: bytes(link.base, 'link base') as never, target_address: bytes(link.target, 'link target') as never,
    zome_index: link.zome_index as never, link_type: link.link_type as never, tag: bytes(link.tag ?? new Uint8Array(0), 'link tag') as never,
  });
  const serialized = serializeAction(action);
  verifySignedBytes(serialized, link.signature, link.author);
  return { ...link, create_link_hash: hashFrom32AndType(blake2b256(serialized), HoloHashType.Action) as never };
}

/**
 * Wrap a gateway-facing NetworkService so that only verified data leaves it.
 * Records and details failing verification are treated as not found; failing
 * links are dropped. count_links and agent-activity responses pass through
 * unchanged (no signed material in those responses).
 */
export function withRecordVerification(inner: NetworkService, onReject?: VerificationRejectHandler): NetworkService {
  const reject = (kind: 'record' | 'link' | 'details', e: unknown) => {
    const reason = e instanceof UnverifiedNetworkDataError ? e.reason : String(e);
    log.warn(`Rejected ${kind} from gateway: ${reason}`);
    onReject?.(kind, reason);
  };
  const record = (r: NetworkRecord | null, requested: AnyDhtHash): NetworkRecord | null => {
    if (r === null) return null;
    try {
      verifyNetworkRecord(r, requested);
      return r;
    } catch (e) {
      reject('record', e);
      return null;
    }
  };
  const links = (ls: NetworkLink[], base: AnyDhtHash, linkType?: number, zomeIndex?: number): NetworkLink[] => {
    const out: NetworkLink[] = [];
    for (const l of ls) {
      try {
        out.push(verifyNetworkLink(l, base, linkType, zomeIndex));
      } catch (e) {
        reject('link', e);
      }
    }
    return out;
  };
  const details = (d: any, requested: AnyDhtHash): any => {
    if (d === null || d === undefined) return d;
    try {
      verifyDetails(d, requested);
      return d;
    } catch (e) {
      reject('details', e);
      return null;
    }
  };
  // Only interface members: nothing unverified can be reached through the wrapper.
  const service: NetworkService = {
    getRecordSync: (dna: DnaHash, hash: AnyDhtHash, options?: any) => record(inner.getRecordSync(dna, hash, options), hash),
    getLinksSync: (dna: DnaHash, base: AnyDhtHash, linkType?: number, zomeIndex?: number, options?: any) =>
      links(inner.getLinksSync(dna, base, linkType, zomeIndex, options), base, linkType, zomeIndex),
    getDetailsSync: (dna: DnaHash, hash: AnyDhtHash, options?: any) => details(inner.getDetailsSync(dna, hash, options), hash),
    countLinksSync: (...args: Parameters<NetworkService['countLinksSync']>) => inner.countLinksSync(...args),
    getAgentActivitySync: (...args: Parameters<NetworkService['getAgentActivitySync']>) => inner.getAgentActivitySync(...args),
    mustGetAgentActivitySync: (...args: Parameters<NetworkService['mustGetAgentActivitySync']>) => inner.mustGetAgentActivitySync(...args),
    isAvailable: () => inner.isAvailable(),
    getLinkerUrl: () => inner.getLinkerUrl(),
  };
  return service;
}

/**
 * get_details responses: every signed action they contain must verify, and
 * the primary record / entry must be the one requested. Unknown shapes are
 * rejected rather than passed through.
 */
export function verifyDetails(d: any, requested: AnyDhtHash): void {
  const type = d?.type;
  const content = d?.content;
  if (type === 'Record' && content?.record) {
    verifyNetworkRecord(content.record, requested);
    for (const list of [content.deletes, content.updates]) for (const sa of list ?? []) verifySignedAction(sa);
    return;
  }
  if (type === 'Entry' && content) {
    const req = bytes(requested, 'requested hash');
    if (!isEntryHash(req)) fail('entry details for a non-entry hash');
    if (content.entry && !sameBytes(computeNetworkEntryHash(content.entry), req)) fail('entry details content does not match the requested entry');
    for (const sa of [...(content.actions ?? []), ...(content.rejected_actions ?? [])]) {
      const { data } = verifySignedAction(sa);
      if (!data.entry_hash || !sameBytes(bytes(data.entry_hash, 'entry hash'), req)) fail('entry details action for a different entry');
    }
    for (const list of [content.deletes, content.updates]) for (const sa of list ?? []) verifySignedAction(sa);
    return;
  }
  fail('unrecognised details shape');
}
