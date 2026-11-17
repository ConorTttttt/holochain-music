# Agent 7 — Music / Media Core production-adoption readiness

Status: **comparison-only; not production-adopted** (17 November 2026).
Baseline: Music `feat/grant-anchor-v21` @ `b4173fc31317e8563f6f7bd18de73dbe5c47f014`;
Media Core `feat/grant-anchor-v21` @ `a74a8aec32da03962788ad92810c413103b2ffd3`.
The native comparison workflow pins the *exact* Media Core commit above.
Agent 6's access-grant/v2 implementation is a separate, unfinished dependency;
these checks must not mistake legacy CORE-005 policy verification for v2 issuance.

## 1. Decision

**Ready for further opt-in evaluation:** native CLI verification of Music v1
manifests, replica receipts, authenticated S2 identities, legacy grant policy
and integrity/audit/import of existing ciphertext objects. Music remains the
source of truth and the only holder of X25519 private keys and plaintext
content keys. No stored package, key wrap or licence is rewritten.

**NOT ready for default adoption:** Windows workflow evidence on this PR,
production wiring, CLI exit-1 I/O classification, schema-version negotiation
for S1 manifests, real crash mid-atomic-write fault injection, two-device
host failover, release signing and installation/supervision, verified v2
grant and key lifecycle/anchor integration, or a defined performance budget.
No source or manifest migration is needed for the existing v1 CAS.

## 2. Interface inventory (audit of current adapter)

| Adapter operation | CLI verb | Authenticated input | Returned decision | Missing Music wiring |
| --- | --- | --- | --- | --- |
| `verify_manifest` | `verify-manifest` | S1 signed manifest; independently pinned artist Ed25519 public key; optional exact manifest digest | S1 authenticity, content identity and chunk metadata | Shadow-compare on catalogue import, library admission and before download |
| `verify_receipt` | `verify-receipt` | S1 host receipt, S1 manifest, trusted artist/host public keys | Host acceptance at one instant, **not** continuing custody | Host selection/receipt check in storage-node and catalogue flows |
| `verify_replica_claim` | `verify-bindings` | Trusted conductor-bridge `AuthoredRecord` owner/host key bindings, commitment and claim | S2 owner/replica identity binding | Bridge retrieval, trusted conductor author, action provenance and lifecycle awareness at app call site |
| `check_access` | `check-access` | Wrapped owner-signed **v1** grant/licence, S1 manifest, conductor-authenticated owner records, listener agent + X25519 **public** key, requested right and clock | Policy check only (`stream`, `managed-offline`, `export`) | Application per-operation authorisation after policy decision; must independently invoke Music AES-GCM unwrap |
| `import_into_cas` | `import` | Signed manifest, trusted artist key, ciphertext-only source/destination directories | Verified chunk reuse/import/repair or named integrity failure with partial progress | Disposable download staging and controlled promotion into the listener library, supervision and cancellation |
| `audit_cas` | `audit` | Signed manifest, trusted artist key and CAS | Counts verified/missing/corrupt ciphertext; `offline_ready` | Compare with `Library.verify_complete` during offline readiness, host repair and startup |
| `binary` / `enabled` | n/a | `HOLOCHAIN_MEDIA_CORE_BIN` absolute existing executable path | CLI opt-in gating | Install discovery, secure signed release, process supervision, diagnostics and OS integration |

All paths are currently **unwired** from `holochain_music/app.py`,
`holochain_music/server.py`, `holochain_music/library.py`,
`music_catalogue/granted_audio.py`,
`music_catalogue/content_grants.py`, and
`holochain_storage/network_client.py`. They remain Music-owned.
Calling a verifier directly is **not** a production integration.

The CAS path convention is already shared:
`objects/sha256/<2 hex>/<64-hex SHA256>`.
Local ciphertext may be reused; Music's authenticated decryption and
playback logic must remain unchanged.

## 3. Compatibility and evidence matrix

Legend: **E** = existing code/tests on baseline; **A** = Agent 7 added
opt-in test; **G** = gated / no evidence in this branch; **B** = blocker.

| Scenario | Music/Python | Media Core/Rust | Evidence / decision |
| --- | --- | --- | --- |
| Manifest signature, digest, tamper, wrong signer | E | E | Existing `test_media_core_adapter` comparisons |
| Receipt pin, forged host and Holochain S2 binding | E | E | Existing comparisons; **A** host-switched receipts |
| Existing v1 streaming/managed-offline/export rights | E | E | Existing `test_media_core_entitlements` asserts *each* right |
| Wrong recipient, expired/replayed grant or licence | E | E | Existing adversarial comparisons |
| Signed but corrupted wrapped key | E: AES-GCM refuses | E: **policy can accept** | Existing intentional boundary test; never release plaintext on Rust-only decision |
| Verified ciphertext import, corrupt/truncated object, repair | E | E | Existing CAS tests; **A** multi-step recovery cases |
| Interrupted transfer, missing host A and restart from host B | E | A | New `test_media_core_resilience`: partial progress not ready, second source completes |
| Host-signature switch | E | A | Verify pinned host keys separately; swapped receipts fail |
| Local staging debris and same-length corruption | E | A | New tests: incomplete temp file ignored, damaged committed object repaired |
| Killed CLI process and a fresh process retry | E | A | Kill attempted; fast process may finish or be killed before first write. **Not proof of actual mid-write crash** |
| Unsupported v1 S1 *manifest schema* vs corrupt content | E | B | Rust returns `InvalidManifest` for both; cannot reliably separate |
| Unsupported legacy grant/entitlement schema | E | E/A | Rust emits entitlement `category=unsupported`; adapter raises `MediaCoreUnsupportedSchema` |
| CLI crash, timeout, invalid stdout/exit code | n/a | A | Always-on mocked subprocess contract tests |
| Linux native opt-in comparison | E historical | G on this PR | Matrix job added; must observe completed hosted run |
| Windows native opt-in comparison | E historical Rust CLI units | G on this PR | Matrix job added; must observe completed hosted run |
| Real MoQ host switch and conductor recovery | E in CORE-004 upstream | G | Existing CORE-004 acceptance is separate; rerun on pinned release candidate |
| Access-grant/v2 signed envelope after owner rotation | B | B | Agent 6 protocol not implemented at this pinned baseline |

Previous repository notes (`holochain-media-core/docs/current-state.md`)
report Linux tests on 14 Nov 2026, and explicitly state hosted CI was blocked
by account billing. **Those historical results are not an Agent 7 run.**
This branch has no observed Windows/Linux CI pass until the workflow completes.

## 4. Error taxonomy and safeguards

The adapter preserves current public exceptions and adds *backwards-compatible*
subclasses/fields. Never treat exit 1, timeout, or malformed stdout as a
cryptographic rejection.

| Category | Current mapping | Safe caller behaviour |
| --- | --- | --- |
| `invalid-content` | CLI exit 2 at S1/S2/integrity boundaries, or malformed/unauthenticated entitlement: `MediaCoreRejected.error_class` | Reject package or claim; quarantine bad ciphertext; do not retry same bytes without a new source |
| `access-denied` | CLI exit 2, entitlement `denied`/`validity`: `MediaCoreRejected.error_class` | Refuse operation, do not imply purchase/permission |
| `unsupported-schema` | CLI exit 2 entitlement `category=unsupported`: `MediaCoreUnsupportedSchema` | Refuse; initiate explicit version negotiation; never fall back to an older parser |
| `unavailable-service` | Missing CLI, launch error, timeout, unexpected exit, invalid/oversized stdout: `MediaCoreUnavailable` | Shadow mode: log degraded comparison; enforce mode: fail closed unless a separate *reviewed* fallback policy exists |
| `local-io` | Python input staging failure: `MediaCoreLocalIO` | Report filesystem error, avoid overwriting any verified copy |

**Outstanding interface defect:** CLI exit 1 exposes only
`boundary=usage-or-io` and an untyped string. Remote CLI file I/O,
invalid CLI flags and parse failures cannot yet be separated reliably.
Before enforcement, Media Core should return stable structured machine codes
(`kind=usage|local-io|unavailable-service`, `code`, `retryable`) and
distinct signed-schema errors *after* authenticity checks. No fragile
error-string matching is allowed. Also enforce a bounded subprocess
concurrency budget and public-only staging file permissions before rollout.

No caller may infer access from `offline_ready`, `verified`,
`decision=authorized`, manifest validity, receipt validity, or possession
of ciphertext. Music must authenticate the recipient private key and unwrap
the AES-GCM wrapped content key (and authenticate actual ciphertext on
decrypt) **for each permitted operation**.

## 5. Reproducible native builds and test commands

CI: `.github/workflows/media-core-comparison.yml`; native
`ubuntu-24.04` and `windows-2022`, Python 3.12, cryptography 46.0.4,
Rust 1.97.0, Media Core pinned commit, `Cargo.lock` enforced by
`--locked`. It prints each built executable's SHA256. The workflow is
separate from all existing Music CI and never sets the adapter as default.

Manually, in a checked-out Music tree beside a Media Core checkout at
`a74a8aec32da03962788ad92810c413103b2ffd3`:

```bash
cd ../holochain-media-core
cargo +1.97.0 build --release --locked -p holochain-content-cli
cargo +1.97.0 test --locked -p holochain-content-cli --all-targets
cd ../holochain-music
python -m pip install -e . cryptography==46.0.4

# With HOLOCHAIN_MEDIA_CORE_BIN unset, normal tests skip all real CLI tests.
python -m unittest -v tests.test_media_core_protocol tests.test_media_core_adapter \
    tests.test_media_core_entitlements tests.test_media_core_resilience

# Linux: set absolute path to the Rust target/release/holochain-media-core.
# Windows: use the absolute path to target/release/holochain-media-core.exe.
export HOLOCHAIN_MEDIA_CORE_BIN=/absolute/path/to/holochain-media-core
python -m unittest -v tests.test_media_core_protocol tests.test_media_core_adapter \
    tests.test_media_core_entitlements tests.test_media_core_resilience
python scripts/benchmark_media_core_comparison.py --rounds 5 --sizes-kib 128 4096
```

Windows PowerShell: `$env:HOLOCHAIN_MEDIA_CORE_BIN = 'C:\\absolute\\path\\holochain-media-core.exe'`;
use the same Python commands. No private key or plaintext content key is
an allowed CLI argument, stdin value or staged file. The tests inspect
every adapter CLI invocation, and the real Rust CLI rejects unknown flags.

## 6. Startup and transfer performance observations

**No new measurements are asserted**: this execution environment cannot
build Rust or fetch repositories via a shell. The opt-in benchmark captures:

- First CLI `verify-manifest` latency (includes process launch), median of
  repeated CLI verification, versus Music in-process S1 metadata verification.
- Full ciphertext audit (both) over the same generated payload.
- Full fresh-target transfer (Music `replicate_package` vs Media Core
  `import`), measuring wall-clock medians and individual samples.
- Host OS, Python version, payload KiB, chunk counts and samples.

Important difference: `replicate_package` signs a host receipt; `import`
does not. Results are **not** apples-to-apples end-to-end streaming or MoQ
throughput and need a separate whole-workflow benchmark before selection.
CI records output but imposes no arbitrary speed gate. Set thresholds only
after Linux and Windows baselines are reviewed (startup p50/p95, copy
throughput, extra per-chunk IO, peak resident memory, kill/restart impact).

## 7. Proposed production adoption and rollback

1. **Evidence gate (now, non-production):** run both native builds, all
   opt-in comparison and failure tests, baseline performance, reproducible
   binary provenance; fix schema and I/O taxonomy. Keep CLI opt-in.
2. **Shadow only:** propose new app config flag
   `MEDIA_CORE_VERIFY_MODE=off|shadow` (default `off`).
   Shadow verified metadata/receipt/grant checks with a timeout and metrics.
   Music Python determines *every* result; mismatches never affect users.
   Do not enable it in this Agent 7 branch.
3. **Read-only narrow adoption:** after zero security-relevant comparison
   mismatches across a defined release window, add an explicitly separate
   `MEDIA_CORE_MANIFEST_VERIFY=off|enforce` flag for manifest/receipt
   verification. Keep Music as the authoritative fallback only when the
   review explicitly allows it; untrusted content must always fail closed.
4. **CAS-only staged writes:** add `MEDIA_CORE_CAS_MODE=off|shadow|pilot`,
   using a dedicated staging directory and verifying Music's offline state
   before atomic promotion. Pilot on fresh downloads only; no migration or
   rewrite of existing packages. Maintain verified host repair/rollback.
5. **Grant policy shadow:** compare Rust CORE-005 legacy policy with Music
   `unwrap_content_grant` but **never** use Rust `authorized` to bypass
   Music unwrap, AES-GCM or the per-right application gate. Versioned
   `access-grant/v2` must receive a separate security review and rollout.
6. **Broader adoption decision:** only after real-conductor, MoQ, offline,
   two-device and Windows signed-packaging tests, plus observed user-visible
   error categories, service lifecycle and monitored performance.

Rollback: turn proposed flags to `off`, stop invoking the CLI and use
Music's unchanged Python read/write and licence paths. Already authenticated
CAS objects remain in the same layout; never downgrade an unsupported schema
or accept unsigned bytes during rollback. Stop the pilot on any false
positive, wrong-right grant, data loss, non-repeatable crash recovery,
unexpected public/private material crossing the CLI, or unclassified exit 1.

**Explicitly experimental:** new access-grant/v2, payment-backed policy,
rental/subscription enforcement, lifecycle-aware post-rotation licences,
trust-bound Holochain record acquisition inside the adapter, hostile
concurrent directory-swap protection, crash fault injection during atomic
publish, and signed native binary distribution.
