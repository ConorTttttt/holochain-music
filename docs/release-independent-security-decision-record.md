# Independent private-grant security decision record (blank template)

**Status: NOT REVIEWED / NOT SIGNED.** This is an approval-ready form, not a certification. A contributor implementing the private-grant flow must **not** sign as their own independent assessor. Owner must identify a qualified independent reviewer and secure the actual signed evidence. Corresponding legal approval and release go/no-go are **separate** records.

Related: [source verification checklist](release-grant-security-verification.md), [severity-ranked issue register](release-review-approval-packet-20261117.md), [release gate matrix](release-gate-matrix.md), [licensing decision](release-licensing-decision-record.md).

## Reviewer and candidate identity — required

- Reviewer full legal name and organisation: **[UNASSIGNED]**
- Professional security qualification/experience and independence/conflicts declaration: **[UNPROVIDED]**
- Owner appointing reviewer and UTC appointment date: **[NOT RECORDED]**
- Scope: full v1 Holochain Music private-grant transport and release candidates, or explicitly bounded exception: **[NOT SET]**
- Candidate Git SHA / tag and byte-for-byte source provenance: **[NOT SET]**
- hApp and each DNA/Wasm SHA-256: **[NOT SET]**
- Linux and Windows package basename, byte size and SHA-256 (each): **[NOT SET]**
- Bundled conductor, bridge, MoQ host SHA-256 (each target): **[NOT SET]**
- Holochain, HDK/HDI, app, OS, Python and Rust version/feature details: **[NOT SET]**
- Test environment: three authenticated agents/conductors, machines, network, firewall and hardware test boundaries: **[NOT SET]**
- Private evidence archive with access controls and redacted-public summary reference: **[NOT SET]**
- Testing UTC start/end, reviewer presence and rerun instructions: **[NOT SET]**

## Required independent test evidence (status must be PASS / FAIL / BLOCKED / NOT RUN)

| Test | Expected safety/availability condition | Status | Evidence log/hash, actual observation, issue and severity |
|---|---|---|---|
| SEC-01a remote provenance spoof | Different physical/virtual authenticated agent cannot masquerade as listener/artist via claimed payload | **NOT RUN** | [ ] |
| SEC-01b unrestricted capability scope | Only `receive_access_request` and `receive_grant` remotely callable; inbox reads and other zome functions refused | **NOT RUN** | [ ] |
| SEC-01c signed nonce/expiry | Replayed/expired/mismatched raw zome-call signatures rejected by actual shipped conductor | **NOT RUN** | [ ] |
| SEC-02a grant forgery and forwarding | No forged, forwarded or wrong-listener grant adds playable PCM or WAV export rights | **NOT RUN** | [ ] |
| SEC-02b key/file/manifest binding | Incorrect X25519 recipient, artist Ed25519 key, file ID, signed manifest SHA or key-unwrapping tag refuses | **NOT RUN** | [ ] |
| SEC-02c expiry/non-downgrade | Expired stream never plays; perpetual personal licence is not downgraded or revoked by later stream grant | **NOT RUN** | [ ] |
| SEC-03a malformed and rate limit | Invalid payloads refused; 21st sender entry of a **single type** refused; no permanent refusal queued | **NOT RUN** | [ ] |
| SEC-03b cross-class quota | 20 request + 20 grant entries/sender and aggregate 500+500/hour attack capacity measured and explicitly accepted or fixed | **NOT RUN** | [ ] |
| SEC-03c lifetime-history/Sybil stress | Record CPU, peak memory, wall-time per delivery, private chain size after N=1k/10k/100k as feasible, malicious agent count; failure threshold preapproved | **NOT RUN** | [ ] |
| SEC-03d offline/outbox | Busy/offline retry; invalid/refused/unauthorized terminal; 200-queue bound; restart, age expiry and no unbounded retry amplification | **NOT RUN** | [ ] |
| SEC-04 metadata | Independent observer enumerates public agent activity action type/count/time/hash, but cannot read private bodies or infer specified file via guessed hash | **NOT RUN** | [ ] |
| SEC-05 LAN encryption/pinning | Traffic capture shows no plaintext grant/key; MoQ certificate mismatch rejects; chosen-host IP/file ID and plain relay metadata disclosed | **NOT RUN** | [ ] |
| SEC-06 keys and compromise | Simulate loss/recovery (without publishing keys); document artist/host/listener/lair identity continuity and failure mode | **NOT RUN** | [ ] |
| SEC-07 exact candidate CI | All required release CI checks pass on the **same integrated commit**, with test counts and individual skips; retests independently sampled | **NOT RUN** | [ ] |
| Local Windows ACL/loopback | Independent second-OS-user read and restricted LAN admin/API attempts; check WAV scratch, local keys, TLS key and log disclosure | **NOT RUN** | [ ] |

A documentation-only GitHub workflow cannot count as these dynamic tests. Holochain source-level observations are **review evidence**, not a runtime test pass. Any NOT RUN safety-critical test must produce a signed **REJECT** or **CHANGES REQUIRED**, unless owner records an explicitly scoped, reviewed exception and release remains correctly gated.

## Residual-risk decisions — one signed decision per row

| Finding | Initial proposed severity | Reviewer severity/reason, remediation or compensating control | Owner acceptance / date |
|---|---|---|---|
| R-S01 Cross-class inbox quotas (500/hour **per** class, not aggregate) | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S02 O(lifetime history) queries and Sybil private chain growth | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S03 Retried/refused ambiguity and persistent queue exposure | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S04 Public private-action timestamps, type/count and peer metadata | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S05 Relay plaintext framing, peer pairing, host-visible listener IP/file ID | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S06 No rotation of artist/host/listener identities; lair backup/key custody | P1 | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S07 Signed transport and capability-grant trust assumptions | P0 missing independent verification | **[OPEN]** | **[NOT ACCEPTED]** |
| R-S08 Unknown test failures, Windows ACL findings or integration skips | P0 until exact-baseline evidence exists | **[OPEN]** | **[NOT ACCEPTED]** |

A reviewer may change these *risk* severity labels only with evidence, not to bypass a gate. Sign the specific risk, compensating control, exposure population, residual likelihood/impact, owner and remediation deadline. An owner risk acceptance cannot itself replace an independent test of authentication or grant binding.

## Independent reviewer decision (required, intentionally blank)

- Findings satisfied (IDs): **[NONE]**
- Findings requiring change, issue links and priorities: **[NOT EVALUATED]**
- Objective evidence index: **[MISSING]**
- Exact software/hardware scope and exclusions: **[MISSING]**
- Exceptions/waivers (each independently reviewed and signed): **[NONE GRANTED]**
- Reviewed candidate SHA and binary hashes (repeat to prevent signature reuse): **[MISSING]**
- Outcome: **[CHOOSE ONE: APPROVE / REJECT / CHANGES REQUIRED — UNSET]**
- Reviewer name, professional role, UTC signature timestamp and unforgeable signature reference: **[MISSING]**

## Separate owner risk acceptance (required after independent review)

- Named owner (@ConorTttttt or formally delegated accountable officer): **[NOT SIGNED]**
- Exact independently reviewed report and tested candidate: **[MISSING]**
- Specific approved residual finding IDs with controls, expiry and re-review schedule: **[NONE ACCEPTED]**
- Outcome: **[CHOOSE ONE: ACCEPT / REJECT / CHANGES REQUIRED — UNSET]**
- Signed identity, UTC date/time and evidence location: **[MISSING]**

**Security sign-off here does not select any licence, establish CAL compliance, approve installed packages, prove physical speakers, or authorise public distribution.** Those require the separate qualified legal, CI/release, hardware and final owner decisions listed in the release gate matrix.
