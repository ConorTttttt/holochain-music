# Private request/grant security — source verification and independent review checklist

**Source baseline:** main bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637, examined 17 November 2026. **Status: IMPLEMENTATION PRESENT / INDEPENDENT SECURITY APPROVAL PENDING.** No penetration test, final-build conductor execution or physical LAN observation was performed by this documentation audit. Preserve existing permissions and entitlement semantics.

## Trust boundaries verified from source

| Concern | Observed implementation (source) | Required independent check / status |
|---|---|---|
| Caller provenance | dna/coordinator/src/lib.rs receives caller as call_info()?.provenance, ignoring claimed sender identities in input. docs/private-grant-security-review.md describes conductor-verified signed zome-call parameters/nonces. | Security reviewer verify current Holochain 0.7.0 remote signature, cell, nonce/expiry checking from exact bundled conductor source; execute spoof test. **REVIEW**. |
| Restricted remote-call scope | init() creates one CapAccess::Unrestricted grant with GrantedFunctions::Listed for receive_access_request and receive_grant only. get_inbox_* are separate local functions not in that list. | Enumerate effective grants at runtime and attempt arbitrary remote calls to get_inbox_* and admin/other functions. **REVIEW**. |
| Message contents | InboxAccessRequest and InboxGrant are private entry types (dna/integrity/src/lib.rs); recipient adds 16-byte nonce for request entries. Payload format, note and grant JSON limits in integrity validation. | Verify malformed/oversize refusal and no secret in action/DHT using two physical peers and/or real conductors. **PARTIAL**. |
| Grant verification | holochain_music/app.py sync_grants verifies artist-signed delivery and matching artist, recipient X25519, file ID and manifest; music_catalogue/content_grants.py authenticates wrapped keys. | Re-run forged, forwarded, expired and mismatched-target cases on exact candidate; verify zero output and zero export. **PARTIAL**. |
| Retry / failure classification | dna/coordinator/src/lib.rs distinguishes HM-REFUSED (permanent), HM-BUSY (retry), unreachable; holochain_music/outbox.py stores at most 200 messages for 7 days, retries at 30s while app runs; only BridgeError matching retry signatures requeues. | Force invalid/rate-limit/busy/offline/timeout for both operations, inspect queue and redacted logs; no dangerous retry amplification. **REVIEW**. |
| Resource bounds and spam | sender_check counts 20/sender/24h, 500/all senders/hour; queries existing private entries on chain. Other resource limits in docs/security-model.md. | Stress exact implementation, compare user-owned data growth, measure latency and boundedness after large history. **REVIEW — residual DoS**. |
| Transport | Private calls via Holochain kitsune2/iroh as documented; MoQ uses QUIC/TLS certificate fingerprint pinning; relay peers/timing remain visible, and plain HTTP relay framing may be visible. | Independently verify network encryption/pinning/relay settings, rejects modified certificate, avoid public-internet claims. **REVIEW**. |
| Source-chain privacy | Body of private entry not gossiped; authorship, action type/hash, sequence and timestamps remain visible to observers. Random 16-byte request nonce prevents straightforward guessed entry-hash testing. | Publish metadata disclosure/risk acceptance; test what a separate peer can observe, not only what UI displays. **BLOCKED — acceptance**. |
| Local permissions/host UI | Security model claims 0700/0600 on Linux and protected DACL on Windows, loopback admin/UI token/Origin protection, private-profile firewall rules. | Inspect final Windows ACLs including WAV working files, local library and MoQ TLS key (Agent 1 changes in PR #45 not on main); attack with second OS account where possible. **REVIEW**. |

**Finding register and approvals:** [release-review-approval-packet-20261117.md](release-review-approval-packet-20261117.md) gives SEC-01–09 severity, interim accountable owner, exact evidence and closure conditions; [release-independent-security-decision-record.md](release-independent-security-decision-record.md) is the **unsigned** candidate-bound reviewer form. A named independent specialist must sign; no source-level review is an independent sign-off.

## Important boundedness qualification

The cap is applied **separately** to request and grant inbox queries (receive_access_request queries InboxAccessRequest; receive_grant queries InboxGrant). Therefore 500/hour is a limit **per inbox type**, not necessarily a global cross-type cap. Both functions scan prior private entries to compute rate limits; source-chain growth and query cost can increase with lifetime history. Existing docs describe a 500/hour cap as if it were universal; the independent reviewer must assess whether this granularity and cost are acceptable. Do not reduce the cap or delete history without separately approved protocol changes.

Also, unauthenticated-to-the-application (though conductor-provenance-authenticated) remote grants can still be written as private inbox entries **before** signature checking occurs during client import. That is why receiver-side spam bounds and storage growth remain important; the later signature gate protects playback but does not erase those prior actions.

## Prior findings and remaining risks

- D17, D18 and D19: source has the documented fixes for lifetime inbox exhaustion, request nonce and refusal classification. tests/test_v1_e2e_grant_security.py contains historical spoof, forged/forwarded, duplicate, rate-limit and queued-delivery cases. **Not re-executed for this review.**
- D20: Rust app bridge concurrency and Python request-ID multiplexing are present. **Not independently stress-tested here.**
- D21: slow peer discovery remains observed in docs/v1-release-readiness.md even after mitigation. **Open for physical LAN.**
- D22: request can be queued using just a DHT track, with 30-second retries and seven-day age window. **Physical outage recovery pending.**
- Source-chain metadata, chosen-host file ID and requester IP, peer timing at relays, Sybil growth, unrotatable Ed25519/X25519 identities and local keystore compromise remain accepted-in-design only if owner/reviewer explicitly sign.
- Clock-controlled streaming-grant expiry is not DRM; perpetual personal licences and exported WAV cannot be revoked. **Do not change entitlement semantics in this review.**

## Adversarial acceptance protocol (capture raw evidence privately)

1. **Provenance/capability** — use three different real agents (artist, listener, attacker); forge claimed sender fields; try calls to get_inbox_* or unrelated zome functions over remote path. Record authenticated caller, target, selected function, refusal category and chain delta; never log content keys.
2. **Grant cryptography** — forward authentic grant to wrong listener, forge artist signature, substitute manifest/file ID/key, replay duplicate, replay expired streaming grant. Expect **zero newly playable content and no export**; verify no downgrade of permanent licence to streaming.
3. **Denial and retries** — submit invalid fields, rate limit 21st same-sender delivery, probe 500/hour cross-agent boundary in an isolated disposable installation; distinguish HM-REFUSED, HM-BUSY and offline, and ensure permanent refusal is not queued. Record queue counts before/after.
4. **Outage** — artist fully offline when listener requests; confirm request queued without artist host, then artist online; verify eventual delivery and no early playback. Stop host while un-downloaded track streams: explicit unavailable, no unauthenticated audio; completed licensed local copy may still play.
5. **Metadata/transport** — inspect observer's available public actions to confirm only aggregate type/time/count; capture traffic on trusted test LAN for plaintext leakage, actor/host exposure and TLS pin rejection; do not publish raw agent IDs, grant bodies or user identifiers.

For each test retain: reviewer/tester name, UTC timestamp, tested source SHA, hApp hash, conductor and bridge SHA-256, OS/versions, two/three agent roles, sanitized logs, operation counts and elapsed time, expected vs actual, result/issue ID, and independent reviewer signature. Archive under evidence/security/S01-S07/ in the future release evidence bundle.

## Approval decision — intentionally unfilled

Reviewer identity/role: ____; exact SHA and binary hashes: ____; severity rubric: ____; D17–D22 retest results: ____; metadata and relay acceptance: ____; Sybil/rate-limit decision: ____; key-rotation and user-data threat acceptance: ____; residual vulnerability owner and mitigation deadline: ____; **APPROVE / REJECT / CHANGES REQUIRED**: ____; signed UTC decision: ____.

Without this record, docs/private-grant-security-review.md is a **request for approval**, not an approval.
