# `call_remote` for browser agents (HWC + h2hc-linker)

**Status: implemented (experimental) in HWC and a candidate gateway; see
[integration-tests.md](integration-tests.md) for Checkpoint E/F evidence.**
Music's DNAs, request, grant and licence formats are unchanged.

Music's private workflow is two `call_remote`s with capability-gated inbox
functions (`dna/coordinator/src/lib.rs`):

```
listener  send_access_request → call_remote(artist,   "receive_access_request", payload)
artist    send_grant          → call_remote(listener, "receive_grant",          payload)
```

The remote call's *provenance* authenticates the sender; the recipient's
`init` created an Unrestricted `inbox` grant listing exactly those two
functions; the recipient stores a private entry.

## Reference semantics (Holochain 0.7.0 sources, verified)

| Step | Native implementation |
| --- | --- |
| Wire | `holochain_p2p` `WireMessage::CallRemoteReq { msg_id, to_agent, zome_call_params_serialized, signature }` → `CallRemoteRes { msg_id, response }` or `ErrorRes { msg_id, error }`, over kitsune2 `send_notify`, reply to the requesting peer URL |
| Params | `ZomeCallParams { provenance, cell_id, zome_name, fn_name, cap_secret, payload, nonce: [u8;32], expires_at }`, bytes = `holochain_serialized_bytes::encode` |
| Signature | Ed25519 by `provenance` over **`sha2_512(bytes)`** (`ZomeCallParams::serialize_and_hash`, `is_valid_signature`) |
| Outgoing | `host_fn/call.rs` `CallTarget::NetworkAgent`: provenance = the calling cell's agent, `fresh_nonce` (5 min), network failure → `ZomeCallResponse::NetworkError(e)` |
| Receive | `Cell::handle_call_remote`: decode, verify signature (failure → error/`ErrorRes`), then `call_zome`; a zome error is also an `ErrorRes` |
| Authorise | `ZomeCallInvocation::is_authorized`, in order: nonce witness (must be Fresh; else `Unauthorized(BadNonce("<Duplicate|Expired|Future>"))`), cap grant (else `Unauthorized(BadCapGrant)`), blocks |
| Nonce | `witness_nonce`: Expired if `expires ≤ now`; Future if `expires > now + 50 min`; Duplicate if seen for that agent; else Fresh |
| Grant | `CapGrant::is_valid`: chain author always; else function granted, Assigned lists caller, Transferable/Assigned secret matches, Unrestricted needs none |

## Implementation

```
 browser cell (HWC worker)                 H2HC gateway (candidate)                 native conductor
 call(NetworkAgent) ─ sign sha512 ─► POST /call_remote/{dna} ──► CallRemoteReq ───────► handle_call_remote
   (Lair, own agent)    (bearer,      provenance == session agent,                      ... ZomeCallResponse
                         call_remote_send)  sig, cell, expiry, bounds ◄── CallRemoteRes ◄┘
 ZomeCallResponse ◄────────── 200 {response} / 4xx-5xx {error} → NetworkError

 native send_grant ─► CallRemoteReq ──► gateway: sig, cell, expiry, recipient has call_remote_receive,
                                        current socket for (dna, agent), bounds ──► WS call_remote_incoming
 HWC: websocket-service (acknowledged registration, authenticated agent == to_agent)
      → offscreen (Chromium) / background (Firefox) → worker CALL_ZOME_REMOTE → callZomeRemote():
        decode → sha512 signature → cell → persistent nonce (SQLite) → live CapGrant from chain
        → execute with provenance = verified caller → ZomeCallResponse::Ok | Unauthorized | error
 ◄── WS call_remote_response (same agent, same socket) ── gateway ──► CallRemoteRes / ErrorRes
```

### HWC (`web/hwc/remote-call/`, applied by `build-extension.sh`)

* `remote-call-auth.ts` — strict canonical decode, SHA-512 signature check,
  native-order authorisation, `CapGrant::is_valid`, denial kinds.
* `remote-call-runtime.ts` — outgoing signing (`signOutgoingCall`),
  native `ZomeCallResponse` codec, live grants from the source chain (deleted
  or updated grants ignored), incoming outcomes, transport/witness interfaces.
* `runtime.patch` —
  * `host-fn/call.ts`: `CallTarget::NetworkAgent`; refused in validation and
    `init` contexts; the webpage cannot choose the provenance.
  * `ribosome/index.ts`: `callZomeRemote()` is the **only** path that may run
    a zome function with a non-author provenance. Authorisation is recorded in
    a module-private `WeakMap` keyed by the request object, so no caller can
    forge it by building a request; the page path keeps the Imposter
    restriction. Zome/fn/payload/provenance come only from the signed params.
    `call_info().cap_grant` reports `RemoteAgent(grant)` for remote callers.
  * `sqlite-schema.ts` + worker `witnessRemoteCallNonce`: table
    `remote_call_nonces(agent, nonce, expires_us, PRIMARY KEY(agent, nonce))`
    in the persistent OPFS SQLite database, `INSERT OR IGNORE` + `changes()`
    (atomic; the worker is single-threaded and calls are serialised), written
    before and outside the zome-call transaction, only after the signature
    verified. Survives worker and browser restarts.
  * `websocket-service.ts`: `call_remote_incoming` accepted only on an
    authenticated socket whose agent is the addressee and whose registration
    for that DNA the gateway acknowledged; otherwise answered with an error.
  * Chromium binding: `offscreen/index.ts` finds the enabled installed cell
    for exactly (DNA, agent), runs `CALL_ZOME_REMOTE`, publishes the records,
    answers on the same socket (never on a replaced one).
  * Worker transport: `ProxyNetworkService.callRemoteSync` (`POST /call_remote`,
    bearer added by the transport; Chromium through the offscreen sync XHR,
    Firefox directly from the worker).
* `firefox-binding.patch` — the same incoming path for Imposter's Firefox
  background executor; applies after Imposter's `firefox-desktop.patch`.
* Tests (`remote-call-*.test.ts`, 20): byte-identical native encodings of
  params, signatures **and `ZomeCallResponse` (Ok, Unauthorized BadCapGrant,
  Unauthorized BadNonce with secret, NetworkError)** from
  `vectors-rs` (`holochain_zome_types 0.7.0`); replay across a "restart";
  concurrent duplicates (exactly one executes); forged signature, wrong cell,
  wrong DNA, expired, far-future, impersonation, ungranted function; nonce not
  consumed by rejected calls; live-grant selection.

### Gateway (`web/gateway/`)

`build-candidate.sh` reproduces the accepted source from Imposter's recipe
(`293563649f…`) — source tree `46122443…` — and applies `call-remote.patch`:

* `POST /call_remote/{dna}` behind `call_remote_send` + DNA scope; provenance
  must be the session's authenticated agent; cell must be `(dna, target)`;
  signature verified; expiry witnessable; no self-calls; 32 KiB params;
  30 calls/min and 4 pending per agent, 256 pending total; 25 s timeout (below
  HWC's 30 s synchronous wait). Returns the recipient's exact
  `ZomeCallResponse` bytes or an error; nothing is reported as delivered
  because it was queued.
* Incoming `CallRemoteReq`: same signature/cell/expiry checks; recipient must
  currently hold `call_remote_receive` (checked at delivery time) and be
  registered on a live socket; 60 incoming calls/min per caller, 8 pending per
  recipient; 30 s timeout; answers bound to the request ID, the addressed
  agent **and** the same socket; answers must decode as `ZomeCallResponse`;
  socket close or revocation fails pending calls immediately (→ `ErrorRes`).
* Responses to the gateway's own outgoing calls are matched on `msg_id` **and**
  the peer URL the request was sent to.
* The gateway never signs zome calls and never executes zome functions.
  Without an auth store (development mode) incoming delivery fails closed and
  the HTTP route does not exist.
* Remote signals stay fail-closed; Imposter's role relay is unchanged.
* Rust tests (10 new, 207 total) cover native-signature acceptance and the
  raw-bytes scheme rejection, forged/tampered/short signatures, impersonation,
  wrong DNA/target/self, expiry, recipient isolation, answer binding to
  agent+socket, replayed answers, disconnect, invalid answers and peer-bound
  response routing.

## Known limits

* A browser→browser call between two agents served by the **same** Chromium
  extension would wait on the offscreen thread that is making the synchronous
  request; Music only uses browser↔native calls. Different browsers are fine.
* Incoming calls need the cell's signing key loaded (it is after any page
  zome call; Firefox preloads explicitly). If Lair is locked the call fails
  and the artist's outbox retries.
* HWC has no block list (the 0.7 HDK removed `block_agent`; HWC has no admin
  API), so `BlockedProvenance` cannot arise.
* Emitted signals from an incoming call are not forwarded to pages (Music's
  inbox functions emit none; the UI reads the inbox).
