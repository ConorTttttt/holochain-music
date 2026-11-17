# Agent 4 — release gate and blocker matrix (17 November 2026)

**Status: BLOCKED / NOT AUTHORISED FOR PUBLIC DISTRIBUTION.** This is a documentation audit, not a legal opinion, independent penetration test, physical test, package build or release authorisation.

## Evidence baseline and interpretation

- Audited source: main at **bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637** (7 November 2026). This report must be revalidated if main or package contents change. Agent 4's documentation branch is not an application release baseline.
- The application declares **1.0.0rc3** in pyproject.toml; docs/v1-release-readiness.md and docs/hardware-test-plan.md are historically RC1-centred. Never attach an RC1 checksum to a newly built RC3 candidate.
- Main's latest observed workflow was **Storage protocol tests**, successful run 42410751678 (7 November, main bd7aabc). This is **not** evidence of a complete release suite.
- PR #45 (Windows OpenSSL/Perl) was open/unmerged, with successful run 43581953080 (14 November). PR #46 (isolated real-conductor matrix) was open/unmerged, with successful run 43574405481 (14 November). They test different branch heads; no combined-main pass is inferred.
- docs/rc1-checksums.md describes a 6 November package built from **958b23d**, NOT current main. docs/windows-wasapi-rc3-validation.md describes an earlier private candidate and explicitly leaves physical speakers pending. No GitHub releases were listed at audit time.
- Status vocabulary: **BLOCKED** = mandatory unsatisfied release condition; **REVIEW** = implementation reviewed but independent acceptance missing; **NOT RUN** = no valid physical result; **PARTIAL** = limited automated evidence; **PENDING** = owner decision or new build outstanding; **PASS** = only for a specifically identified executed check. No gate below is marked PASS by this audit.

**17 November follow-up verification:** PR #51's documentation head `d7e70a7c5235a19b57afbaea94c38e08db8c62cf` triggered successful storage and v1-application workflows, but Windows workflow [44071677628](https://github.com/ConorTttttt/holochain-music/actions/runs/44071677628) **failed** at the MSVC bridge OpenSSL build (`Locale/Maketext/Simple.pm` missing in Perl). All downstream Windows Python/security, installer and smoke jobs were skipped. The earlier separate PR #45 success is **not** an integrated success. This evidence does not alter any S/H/L/R gate to PASS. A severity-ranked finding/approval record and narrowly scoped proposed remediation PRs are in [release-review-approval-packet-20261117.md](release-review-approval-packet-20261117.md); the [independent security decision record](release-independent-security-decision-record.md) and [legal decision record](release-licensing-decision-record.md) remain **unsigned**. Interim accountability for every outstanding legal/security row is repository owner **@ConorTttttt**, who must delegate to named qualified specialists; that GitHub handle is **not** a legal or independent security signature.

## Release blocker matrix

| ID | Required gate / exact closure | Decision-maker or tester | Status on audited main | Evidence location / collection destination |
|---|---|---|---|---|
| L01 | Approve original-code licence and exact files/attribution scope; only then add a top-level LICENSE, NOTICE and crate metadata | **Project owner + legal reviewer** | **BLOCKED** — undecided; Apache-2.0 only proposed | docs/licensing-audit.md; docs/release-licensing-decision-record.md |
| L02 | Decide whether conductor is bundled; check CAL-1.0 corresponding source, notices, and user-data/key autonomy (including lair) for exact built binary | **Legal reviewer + release owner** | **BLOCKED** | docs/release-licensing-decision-record.md; packaging/proposed-notices/SOURCE-AVAILABILITY.md; future release evidence/legal/ |
| L03 | Resolve CAL-1.0 hdk/hdi, any applicable combined-work exception and licensing of compiled zomes/hApp | **Legal reviewer + release owner** | **BLOCKED** | dna/Cargo.lock, music-dna/Cargo.lock; docs/release-licensing-decision-record.md |
| L04 | Generate package-specific complete transitive dependency/attribution inventory, supply required notices, source for MPL/CDDL and other obligations, and matching SBOMs | **Release engineer + legal reviewer** | **BLOCKED** — proposals only, not packaged | docs/release-dependency-inventory.md; packaging/proposed-notices/; future release evidence/licenses/ |
| L05 | Verify Windows Microsoft Visual C++ redistribution, MinGW runtime and all upstream archive/wheel licence texts | **Legal reviewer + Windows packager** | **BLOCKED** — open questions | packaging/windows/THIRD-PARTY.txt; docs/release-licensing-decision-record.md |
| S01 | Independent sign-off of entire private-request/grant protocol, residual threat model, and documented exceptions | **Independent security reviewer + owner** | **REVIEW** — not approved | docs/private-grant-security-review.md; docs/release-grant-security-verification.md; future release evidence/security/ |
| S02 | Verify conductor-authenticated provenance, sender-only identity, recipient-side grant signature and audience/file/manifest binding against final hApp | **Security reviewer** | **PARTIAL** — source & historical e2e evidence; final build retest needed | dna/coordinator/src/lib.rs; holochain_music/app.py; tests/test_v1_e2e_grant_security.py; evidence/security/S02/ |
| S03 | Verify only two unrestricted capability functions, input bounds, Sybil/DoS limits, permanent-refusal vs retry distinction, and recovery | **Security reviewer** | **REVIEW** — bounded not Sybil-proof | dna/coordinator/src/lib.rs; holochain_music/outbox.py; evidence/security/S03/ |
| S04 | Explicitly accept or mitigate public source-chain action count/timing, relay peer-pair metadata and chosen-host file ID/IP visibility | **Security reviewer + owner** | **BLOCKED** — residual privacy decision | docs/security-model.md; docs/release-grant-security-verification.md; evidence/security/S04/ |
| S05 | Verify transport encryption and trusted-LAN default, endpoint/certificate pinning, plain HTTP relay framing and internet non-support | **Security reviewer + network tester** | **REVIEW** — physical LAN and relay test needed | docs/security-model.md; docs/hardware-acceptance-evidence-pack.md; evidence/security/S05/ |
| S06 | Accept key custody, lack of artist/listener/host key rotation and absence of OS keyring/DPAPI; decide response to compromise | **Security reviewer + owner** | **BLOCKED** — residual-risk decision | docs/private-grant-security-review.md §§5, 8; evidence/security/S06/ |
| S07 | Execute all grant-security real-conductor tests and security regression tests on exact candidate commit; archive workflow URLs/logs and failure triage | **CI/release engineer** | **PENDING** — historical test evidence, not final candidate | tests/test_v1_e2e_grant_security.py; docs/v1-release-readiness.md; evidence/ci/ |
| H01 | Human Ubuntu ALSA playback: audible stereo, pause/resume, volume, stop and seek | **Named Ubuntu human tester** | **NOT RUN** on audited build | docs/hardware-acceptance-evidence-pack.md / H01; evidence/hardware/H01/ |
| H02 | Acoustic + device seek latency with 10 timed observations and hardware benchmark; compare to predeclared limit | **Named Ubuntu human tester** | **NOT RUN** | docs/hardware-acceptance-evidence-pack.md / H02; evidence/hardware/H02/ |
| H03 | Two separate physical computers on trusted LAN: discovery, request, grant, encrypted MoQ streaming/seek | **Named A+B LAN testers** | **NOT RUN** | docs/hardware-acceptance-evidence-pack.md / H03; evidence/hardware/H03/ |
| H04 | Explicit grant denial and host-outage test: no ungranted playback, no stale authorisation, unavailability and recovery | **Named A+B LAN testers** | **NOT RUN** | docs/hardware-acceptance-evidence-pack.md / H04; evidence/hardware/H04/ |
| H05 | Unplug/disable networking and prove offline audio + perpetual-licence WAV export; streaming-only export forbidden | **Named offline human tester** | **NOT RUN** | docs/hardware-acceptance-evidence-pack.md / H05; evidence/hardware/H05/ |
| H06 | Clean Ubuntu install, launch, package smoke, remove, retained data without developer tools | **Named clean-install tester** | **NOT RUN** | docs/hardware-acceptance-evidence-pack.md / H06; evidence/hardware/H06/ |
| H07 | Physical Windows WASAPI Realtek speakers; crackling issue #26, same-WAV control, seek, stop and recovery | **Named Windows human tester + owner** | **BLOCKED** — issue #26 open | docs/windows-wasapi-rc3.md; docs/hardware-acceptance-evidence-pack.md / H07; evidence/hardware/H07/ |
| H08 | Windows→Ubuntu physical LAN direction if included in RC release claims | **Named cross-OS testers** | **NOT RUN** | docs/windows-lan-test-plan.md; evidence/hardware/H08/ |
| R01 | Integrate Agents 1 & 2 CI/Windows changes and obtain green exact-main/merged-candidate results including all real-conductor groups | **CI owner** | **BLOCKED** — PRs #45 and #46 not merged | GitHub PRs #45/#46; evidence/ci/ |
| R02 | Build Linux + Windows packages from exact approved commit; verify per-file hashes, correct notices/SBOM/source delivery and installer smoke | **Release engineer** | **BLOCKED** — historical hashes do not certify current source | docs/rc1-checksums.md; docs/windows-rc-checksums.md; evidence/packages/ |
| R03 | Owner confirms release identifier; align application, docs, notices, installers and checksum names | **Project owner + release engineer** | **PENDING** — 1.0.0rc3 source, RC1 legacy reports | pyproject.toml; holochain_music/__init__.py; docs/v1-release-readiness.md |
| R04 | Public release go/no-go after L01–L05, S01–S07, H01–H07, R01–R03 and any claimed H08 | **Project owner** | **BLOCKED** — no authorisation | A signed decision stored at evidence/approvals/release-go-no-go.md |

The evidence/ directories are **required destinations in the future candidate evidence archive**, not directories claimed to exist in this source tree. Each artifact must identify the tested Git SHA and SHA-256 of the *actual binary* used.

## Historical security finding reconciliation

| Finding | Audited source evidence | Status for release |
|---|---|---|
| D17 lifetime inbox lockout | Source uses 20 deliveries/sender/24h and 500/all/hour in dna/coordinator/src/lib.rs instead of a lifetime cap | **IMPLEMENTED; RETEST PENDING**. Sybil growth remains. |
| D18 guessable request entry hash | Recipient creates 16 random bytes in receive_access_request; private entries in dna/integrity/src/lib.rs | **IMPLEMENTED; RETEST PENDING**. Action metadata still visible. |
| D19 refusal wrongly retried as offline | Zome remote() distinguishes HM-REFUSED, HM-BUSY and unreachable; outbox.retryable limits to BridgeError signatures | **IMPLEMENTED; RETEST PENDING**. Malformed and busy error paths still need adverse-network validation. |
| D20 bridge serialized slow remote calls | music_app_bridge.rs spawns bounded concurrent requests; bridge.py dispatches replies by request ID | **IMPLEMENTED; RETEST PENDING**. |
| D21 long discovery delay | Historical 270s observation survives cited mitigation | **OPEN PERFORMANCE RISK; PHYSICAL LAN RETEST**. |
| D22 offline artist request cannot be queued | request_access uses DHT track record; Outbox can queue 7 days and retries 30s while process is running | **IMPLEMENTED; PHYSICAL RECOVERY RETEST**. |
| D23 host outage test silently skipped | Legacy report says assertion changed; test implementation and current execution must be verified for final SHA | **UNVERIFIED ON FINAL CANDIDATE**. |
| Windows audible crackle / issue #26 | RC3 model checks cannot establish speaker quality | **OPEN BLOCKER**. |

No security finding is described as independently closed merely because source or a prior test describes a fix. Risk acceptance must be explicit and signed, not inferred from a passing CI run.

## Sign-off and evidence contract

For every gate store: gate ID; owner/tester and reviewer name; UTC time; exact Git SHA; operating system and machine ID; package file basename, byte count and SHA-256; relevant upstream-binary/SBOM hashes; command or steps executed; expected vs observed outcomes; exit code; redacted raw logs and recordings where applicable; deviations; linked issue/PR; decision signature/date. Use **PASS**, **FAIL**, **BLOCKED**, **NOT RUN** only against the exact candidate; never migrate an old PASS automatically. Redact tokens, private grants, content keys, user home paths and unnecessary agent IDs before publishing evidence.

See docs/release-licensing-decision-record.md, docs/release-dependency-inventory.md, docs/release-grant-security-verification.md and docs/hardware-acceptance-evidence-pack.md.
