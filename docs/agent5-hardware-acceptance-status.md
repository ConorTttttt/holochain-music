# Agent 5 — physical acceptance evidence and platform disposition

**As of 2026-11-17 UTC. This is a non-release, documentation/preflight-only handoff.** Do not represent this page as a physical acceptance certificate.

## Source and candidate identity

- **Starting repository commit:** `main` = `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`, observed 17 November 2026.
- **Read but not modified:** PR #51 (`docs/agent4-release-gates-20261117`, head `d7e70a7c5235a19b57afbaea94c38e08db8c62cf` at review), `docs/hardware-acceptance-evidence-pack.md`, `docs/hardware-test-plan.md`, `docs/windows-wasapi-rc3.md`, `docs/windows-lan-test-plan.md`, `docs/windows-rc-checksums.md` and `docs/rc1-checksums.md`.
- **Adjacent release CI work:** #45/#46 and draft integration #49. A single approved package from Agent 3, with build commit, independent approval and per-artifact/per-component SHA-256, **was not available** to this agent. No candidate file was downloaded or hashed.
- **Historical only, NOT approved as the current candidate:** Linux rc1 from source `958b23d`, `.deb` SHA-256 `5462eacfba8af0300fd3cf50db24df6b092235c99e842b856badb87a204467eb`; Windows private rc3 installer SHA-256 `4593bf5e754227d01ffeb33779b5ada4aa2a7578c5dc35e94f09cb8d2d465644`. These are documentation records, not a freshly verified local binary.
- **Hardware access check:** agent container has no `/dev/snd` and no `/proc/asound/cards`; `aplay` and `speaker-test` not installed. No actual speakers, physical Ubuntu test device, physical second LAN host or Windows audio endpoint is exposed. The historically documented HP Pro Mini is **not** available to this agent for an actual sound test; its current human availability is unconfirmed. No hardware device make/driver/sample rate/network timings can responsibly be reported for this run.
- **Acceptance platform selection:** release owner has not signed final advertised platform scope in this run. Ubuntu 26.04 assumed as proposed primary target; Windows 11 x64 is conditional, and issue #26 remains open.

## Executed test inventory

| Check | Execution / outcome | Scope limitation |
|---|---|---|
| GitHub `main`, PR #51, PR #49, issue #26, historical docs and build script | **REVIEWED** via GitHub API on 2026-11-17 | Source/readiness audit, not application runtime |
| Presence of physical audio devices in execution container | **CHECKED: none exposed** (`/dev/snd`, `/proc/asound/cards` absent) | Cannot infer state of users' own machines |
| `python3 -m unittest discover -s packaging/acceptance -p 'test_*.py' -v` | **PASS 9/9** on local *synthetic fixture* | Only tests the new checksum preflight, not a real .deb/exe |
| `python3 -m py_compile packaging/acceptance/*.py` | **PASS** in local preparation | Python syntax only |
| Approved Agent 3 package hash / installed component checks | **BLOCKED: package + independent manifest absent** | No exact candidate/bundle hashes established |
| App Python/Rust/Node suite or real conductor CI rerun | **NOT RUN** by Agent 5 | Work owned by Agents 1–3; prior CI is not re-certified here |
| Physical Ubuntu ALSA and acoustic seeks | **NOT RUN** | No speaker/ALSA hardware |
| Two-physical-PC discovery, private grant, MoQ, download, outage | **NOT RUN** | No paired physical PCs and no candidate |
| Physical offline playback, WAV export, altered encrypted CAS | **NOT RUN** | No disposable physical test library |
| Clean Ubuntu install on independent host | **NOT RUN** | No clean test host or package |
| Physical Windows WASAPI/Realtek, 44.1/48 kHz, issue #26 | **NOT RUN** | No Windows speaker device or approved installer |

No human audio observation, device log, timing measurement, test-package SHA or diagnostic log from a live music app was produced. The existing docs' simulated PCM continuity, prior same-machine conductors and historical listening reports have **not** been recast as fresh physical passes.

## Gate ledger — actual status, not inferred success

| Gate | Required for | State on 17 Nov | Evidence needed to close |
|---|---|---|---|
| H01 audible Ubuntu ALSA + controls | Ubuntu | **BLOCKED / NOT RUN** | Named tester; real speaker output, stereo/control/shutdown logs and SHA |
| H02 acoustic seek | Ubuntu | **BLOCKED / NOT RUN** | 20 real-device bench seeks + 10 audible microphone intervals; predeclared criterion |
| H03 two physical PCs/LAN grants + streaming | Ubuntu LAN | **BLOCKED / NOT RUN** | Physical A/B, distinct identities, packet/host logs, no access before grant, live sound |
| H04 withheld-grant, host down/recovery | Ubuntu LAN | **BLOCKED / NOT RUN** | Refusal no PCM/export, offline host and request retry evidence; Deny UI gap tracked separately |
| H05 genuinely disconnected perpetual offline + WAV export | Ubuntu | **BLOCKED / NOT RUN** | Physical disconnection proof, licensed offline sound/export; streaming-only export refusal |
| H06 no-dev-tools Ubuntu install | Ubuntu | **BLOCKED / NOT RUN** | Clean install smoke, desktop, uninstall retention, licence/notice inspection |
| H07 physical Windows WASAPI acoustic quality | Windows if advertised | **CONDITIONAL — NOT RUN** | Issue #26 speaker/headphone sign-off on approved installer with Realtek comparison |
| H08 Windows host → Ubuntu listener | If advertised | **CONDITIONAL — NOT RUN** | Reverse-direction two-machine physical run |
| H09 corrupted encrypted CAS fail-closed/recovery | Ubuntu/negative security | **BLOCKED / NOT RUN** | Disposable-only tamper, no unauthenticated audio/export, restored/verified state |

Interactive **Deny** is not a verified v1 UI feature; withholding an access request does not count as a tested Deny action. Any decision to require Deny for RC1 belongs to the owner/security gate.

## Platform-specific disposition

**Ubuntu 26.04 x64: NO-GO for physical acceptance.** No candidate artifact with owner-authorised SHA and complete build trace; H01–H06/H09 remain unperformed. Historical RC1 null-output and package smoke checks are insufficient. Clean-install packaging legal notices and independent private-grant security review are separate outstanding release gates.

**Windows 11 x64: NO-GO if support is claimed.** Physical WASAPI/Realtek audible crackling/jitter regression from [issue #26](https://github.com/ConorTttttt/holochain-music/issues/26) remains unverified on the current source candidate. Windows automation or Linux scheduling models are not physical device evidence. If Windows is not advertised, document the owner-signed exclusion; H07/H08 can then be marked NOT APPLICABLE, **not PASS**.

**Security/fail-closed: UNPROVEN ON PHYSICAL CANDIDATE.** No negative test passed here; H04/H09 must run against genuine approved, isolated physical builds. Avoid claims that encrypted content or forged/withheld grants were freshly rejected.

## Next action and sign-off

Agent 3/release owner: supply exact candidate source SHA, trusted manifest SHA-256, private packages + sizes + SHA-256, bundle hApp/conductor/bridge/MoQ hashes, source/build transcript, release criteria and CI provenance. Owner: confirm supported platforms and physical testers. Named operator: execute `docs/agent5-physical-acceptance-runbook.md` alongside PR #51 on supported devices, archive signed evidence in private store, then update *each gate individually*. Independent reviewer: verify package identity, physical observation and fail-closed cases. **Do not merge or publish solely because this preparation exists.**

Human tester signature: **PENDING**. Independent reviewer: **PENDING**. Release owner/platform approval: **PENDING**.
