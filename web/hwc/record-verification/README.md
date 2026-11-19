# HWC patch: verify DHT data returned by the gateway

**Scope:** Holo Web Conductor (`Holo-Host/holo-web-conductor@0c391226`) with
Imposter's browser-alpha patches. Generic, not Music-specific. Applied by
`apply.py` (anchored, refuses to run twice) from `web/hwc/build-extension.sh`.

## Problem

A zero-arc browser node reads the DHT through an h2hc-linker gateway. At the
pinned commit HWC accepts whatever the gateway returns for `get`,
`get_details` and `get_links`; `verifyActionSignature` is only applied to the
local chain and chain recovery. A malicious or compromised gateway could
therefore attribute arbitrary records to any author: for Music, forge
catalogue entries, S2 key bindings and host endpoints under a real artist's
identity.

## Fix

`packages/core/src/network/record-verification.ts` wraps the worker's
gateway `NetworkService` (`setNetworkService(withRecordVerification(...))`),
so nothing unverified reaches the cascade cache, validation or zome WASM:

| Data | Check | On failure |
| --- | --- | --- |
| Record (`get`, `must_get_*`) | action hash recomputed from the exact signed msgpack bytes; Ed25519 signature by the action signer; requested action hash, or requested entry hash = action `entry_hash`; present entry hashes to `entry_hash` | treated as not found |
| `get_details` | every contained signed action as above; primary record/entry is the one requested; unknown shapes refused | treated as not found |
| Link with signed `CreateLink` fields (`WireLinkOps` path) | action rebuilt, hashed and signature checked; the fabricated `create_link_hash` replaced by the real hash; base and type filter must match the query | link dropped |
| Link without signature (h2hc-linker `Vec<Link>`) | base and type filter must match the query | link dropped |

Also fixed while validating against real native records: the wire-action
normaliser kept the gateway's alphabetical key order for
`entry_type.App`. Msgpack map order is part of the signed bytes, so every
genuine `Create`/`Update` with an app entry failed. Rust's `AppEntryDef` order
(`entry_index, zome_index, visibility`) is restored. The same latent bug
affects HWC's existing chain-recovery signature check (not changed here).

## Tests

`record-verification.test.ts` (run in the build gate with the full HWC core
suite, including Imposter's `*.imposter.test.ts`):

* a **genuine Holochain 0.7 record captured from the accepted gateway**
  (`fixtures/gateway-record-create.json`, a native artist's Track) verifies
  exactly as the gateway sends it; the same record with forged entry bytes or
  another author is rejected;
* sorted-key (serde_json) round trips verify;
* forged author, altered content, recomputed-hash relabelling, substitution of
  another action or entry, substituted entry content, truncated signatures,
  injected and retargeted signed links, wrong base/type/zome, partially signed
  links, forged updates in details and unknown details shapes are rejected;
* the wrapper exposes only interface members (no unverified bypass).

End to end, `web/integration/run_interop.py` check **M1** puts a test-only
malicious gateway (`web/integration/tamper_proxy.mjs`) in front of the real
one; it rewrites the track title in record responses. The verifying build
never shows the forgery; a control run with an unpatched build shows it.

## Remaining limits

* **Link authorship** is not client-verifiable with the accepted gateway: it
  converts signed `WireLinkOps` into unsigned `Vec<Link>`. A gateway can omit
  links or add links whose targets are genuine records (the targets are still
  verified when fetched). Fix needs the gateway to return the signed
  `CreateLink` actions (or `WireLinkOps`) — h2hc-linker change.
* `count_links`, `get_agent_activity` and `must_get_agent_activity` pass
  through unchanged (no signed material in those responses as served).
* Validation status / warrants reported by the gateway are not independently
  checked (a gateway can still claim a valid record is rejected, i.e. deny
  service, but cannot forge one).
