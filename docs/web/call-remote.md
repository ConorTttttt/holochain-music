# `call_remote` for browser agents (HWC + h2hc-linker)

**Status: BLOCKED for Music private grants. Design and HWC-side foundation
ready; gateway and HWC runtime work not started.** Music's DNAs, request and
grant formats are not changed by any of this.

Music's private workflow is two `call_remote`s with capability-gated inbox
functions (`dna/coordinator/src/lib.rs`):

```
listener  send_access_request → call_remote(artist,   "receive_access_request", payload)
artist    send_grant          → call_remote(listener, "receive_grant",          payload)
```

The remote call's *provenance* authenticates the sender; the recipient's
`init` created an Unrestricted `inbox` grant listing exactly those two
functions; the recipient stores a private entry.

## Reference semantics (Holochain 0.7.0 sources)

| Step | Native implementation |
| --- | --- |
| Wire | `holochain_p2p` `WireMessage::CallRemoteReq { msg_id, to_agent, zome_call_params_serialized, signature }` → `CallRemoteRes { msg_id, response }` (request/response over kitsune2, same correlation as `GetReq/GetRes`) |
| Params | `ZomeCallParams { provenance, cell_id, zome_name, fn_name, cap_secret, payload, nonce: [u8;32], expires_at }`, bytes = `holochain_serialized_bytes::encode` |
| Signature | Ed25519 by `provenance` over **`sha2_512(bytes)`** (`ZomeCallParams::serialize_and_hash`, `is_valid_signature`) |
| Receive | `Cell::handle_call_remote`: decode, verify signature, then `call_zome` |
| Authorise | `ZomeCallInvocation::is_authorized`, in order: nonce witness (must be Fresh), cap grant, blocks. The nonce is written only after the signature verified. |
| Nonce | `witness_nonce` (holochain_data 0.7.0): Expired if `expires ≤ now`; Future if `expires > now + 50 min`; Duplicate if seen for that agent; else Fresh |
| Grant | `CapGrant::is_valid`: chain author always; else function granted, Assigned lists caller, Transferable/Assigned secret matches, Unrestricted needs none |

## What exists today

| Piece | State |
| --- | --- |
| HWC outgoing (`call` host fn, `CallTarget::NetworkAgent`) | refused: `[HostFn:call] No ConductorCell in target` (interop check E1) |
| HWC ZomeCallParams signing (used for remote signals) | **incompatible**: signs `blake2b256(bytes)` instead of `sha2_512(bytes)` |
| HWC incoming provenance | Imposter patch refuses any non-author provenance (correct until capability checks exist) |
| h2hc-linker outgoing | only `RemoteSignalEvt` fire-and-forget; no `CallRemoteReq`/response correlation |
| h2hc-linker incoming | forwards `RemoteSignalEvt` to the browser WebSocket; **drops `CallRemoteReq`** (the native caller times out: "recipient unreachable"; Music's outbox keeps the grant for retry — no false delivery) |
| Imposter role frames | domain `imposter.h2hc.private-role.v1`, capabilities `game_role_*`: not a carrier for Music |

## Foundation delivered in this round (HWC side, inert)

`web/hwc/remote-call/` (applied by `build-extension.sh`, not wired into the
runtime):

* `remote-call-auth.ts`: `encodeZomeCallParams` / strict `decodeZomeCallParams`
  (canonical re-encoding enforced), `verifyZomeCallSignature` (SHA-512),
  `MemoryNonceWitness` with the native rules, `capGrantIsValid`
  (`CapGrant::is_valid`), and `authorizeRemoteCall` in native order;
* `vectors-rs/`: a Rust generator using `holochain_zome_types 0.7.0`'s own
  `ZomeCallParams::serialize_and_hash` and Ed25519 → `zome-call-vectors.json`;
* tests (9): byte-identical encoding of native params, native signatures
  verify, our signature equals native, the HWC `blake2b256` scheme is
  rejected, replay refused, nonce not consumed by a bad signature, tampered
  bytes / other cell / expired / far-future / forged caller / ungranted
  function refused, Transferable and Assigned grant rules.

## Remaining work (separately reviewable, in dependency order)

1. **HWC — signing fix**: sign `sha2_512(encode(params))` (shared helper with
   the authoriser); keep remote signals behind Imposter's fail-closed gate.
2. **h2hc-linker — outgoing**: WebSocket frame `call_remote_request
   {dna, target_agent, params_bytes, signature, request_id}` for sessions with
   a new admission capability `call_remote_send`; the gateway verifies the
   signature and that `params.provenance` equals the session's authenticated
   agent (no impersonation), sends `CallRemoteReq`, correlates `CallRemoteRes`
   by `msg_id`, and returns `{request_id, response | error}` with a timeout.
3. **h2hc-linker — incoming**: for a registered browser agent with
   `call_remote_receive`, forward `CallRemoteReq` as `call_remote_incoming
   {request_id, params_bytes, signature}`; reply `CallRemoteRes` with the
   browser's `ZomeCallResponse` bytes, or `ErrorRes` on timeout/disconnect.
   Bound queue depth, size (Music grants ≤ 8 KiB) and rate per sender.
4. **HWC — incoming runtime**: on `call_remote_incoming`, run
   `authorizeRemoteCall` with a **persistent** nonce witness (IndexedDB/OPFS,
   survives restart), live cap grants read from the local chain, then execute
   with the verified provenance through a dedicated entry point (the general
   page path keeps refusing foreign provenance). Return `ZomeCallResponse::Ok`
   / `Unauthorized` in the native encoding.
5. **HWC — outgoing runtime**: `CallTarget::NetworkAgent` in `call` → sign →
   gateway frame → await response (the ribosome call is synchronous: needs the
   same sync-XHR/worker bridging HWC uses for DHT reads, with a timeout).
6. **Acceptance (Music interop harness)**: E1 becomes PASS; new checks: native
   artist sees the browser request in `MusicApp.artist.requests()`, approves
   with `MusicApp.artist.grant()`, the browser's "Check for grants" imports it
   from `get_inbox_grants`, verifies and plays; replayed/forged/expired/
   ungranted calls refused; revoked sessions cannot send or receive; Imposter
   role-delivery tests unchanged.

Steps 2–3 need the gateway source with Imposter's admission/session patches
(revision `9f5eb04b…`) and a Nix build; they are the critical path.
