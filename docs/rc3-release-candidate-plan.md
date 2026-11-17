# RC3 packaging and acceptance plan — 2026-11-17

**DRAFT / internal evidence only. No public tag, GitHub release, package upload or distribution approval.**
This document supersedes the *current-status interpretation* of the historical
6 November entries in `docs/v1-release-readiness.md`, `docs/rc1-checksums.md`
and `docs/windows-rc-checksums.md`. It does not invalidate their historical
checksums or imply those bytes were rebuilt.

## Baseline and approved identifier

Audit reference: `main` = `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`
(17 November 2026). PR #45 (Windows OpenSSL/ACL/NSIS fixes) and PR #46
(isolated real-conductor test groups) were **open, not integrated** at audit.
The Agent 3 provenance draft is stacked on Agent 2's combined-CI branch
`ci/rc1-combined-ci-baseline-agent2` (PR #49) at
`b86ab9f6530075787338884497faf991c26349f9`. This review-only
integration dependency is **NOT an approved release baseline**. Rebase
and review this candidate against the accepted source SHA after the required
same-SHA CI gates pass; do not merge or package a public release on the
strength of the provenance unit tests alone.

Their earlier green CI evidence belongs to *different* commits, not a single release
commit. Recheck this section once Agents 1/2 integrate and choose an exact
tested final source commit. This audit SHA is **not** the selected RC source.

Source labels match: `pyproject.toml` and `holochain_music/__init__.py`
both say `1.0.0rc3`. **Owner confirmation is required to change the identifier.**

| Kind | Proposed filename/label | State |
|---|---|---|
| Python metadata and CLI | `1.0.0rc3` | Source verified; artefact not rebuilt |
| Debian amd64 | `holochain-music_1.0.0~rc3_amd64.deb` | Proposed, **NOT BUILT** |
| Windows NSIS x64 | `HolochainMusic-1.0.0-rc3-windows-x64.exe` | Proposed new build, **NOT BUILT** |
| Evidence | `<package>.sha256`, `<package>.provenance.json`, `*.contents.sha256` | Generated only after a real build |

Do not substitute or overwrite any November 6 RC1/RC2/RC3 package of the
same filename. Use a new empty output directory per candidate build;
the wrapper refuses to overwrite existing candidate packages.

## Builder audit and remaining repeatability gaps

**Linux:** `packaging/build-deb.sh` uses fixed `SOURCE_DATE_EPOCH`, sorted
source files, normalised mtimes, fixed root ownership and `dpkg-deb -Zxz`.
This establishes deterministic *assembly with identical compiled inputs*,
not reproducible Rust/DNA output across arbitrary toolchains.
It previously selected `holochain`, `hc` and
`kitsune2-bootstrap-srv` from unverified PATH and accepted
`--skip-build` with arbitrary stale native helpers/hApp. The strict
`packaging/rc-build.sh` path now rejects `--skip-build`, requires explicit
reviewed Holochain binary paths and an independent input checksum manifest. Every selected Linux
binary path and SHA-256 must now appear in that exact manifest; checking
unrelated files is insufficient. The wrapper rebuilds zomes, hApp, MoQ and bridge using lockfiles. The ordinary
developer builder is unchanged for non-RC use. Toolchain versions, compiler
feature flags and all upstream Linux binary hashes must still be reviewed.

**Windows:** `packaging/windows/inputs.sha256` pins Holochain 0.7.0
Windows executables, CPython 3.14.10 and four wheels. The installer
builder verifies these bytes. Rust-based MoQ/bridge helper binaries are
inputs supplied by the Windows CI job, so their build commit must be
checked against the selected source SHA; the wrapper records their input
SHA-256 and disallows externally supplied prebuilt launchers. NSIS,
MinGW, Rust/compiler tools, runner image and SOURCE_DATE_EPOCH must be
recorded; these **are not all cryptographically pinned** today. MSVC/native
helper compilation and Linux NSIS assembly are separate runner jobs.
The Windows version resource's numeric `VIProductVersion=1.0.0.0` is
not the prerelease display version; the NSIS display, ARP and strings
must all say `1.0.0-rc3` and the installed Python package `1.0.0rc3`.

Both builders now embed `SOURCE_COMMIT.txt` inside the installed package
(commit, package version and SOURCE_DATE_EPOCH). External provenance
contains SHA-256 of the package, checksum manifest, important bundled
binaries/hApp, dependency lockfiles and available builder tool versions.
The Linux installed source marker is checked as a complete triple of
commit, package version and epoch; checksum/provenance sidecars may not
be overwritten. Windows content checksums are from the staged files: **independent NSIS
extraction/installation verification is still required**, not inferred.

## Repeatable private build protocol

1. Merge/verify Agents 1/2, this PR and their tests; select the final
   **40-character tested commit SHA**. Check out that SHA with no tracked
   changes. Preserve the GitHub Actions run IDs and all relevant logs.
2. Record the exact builder OS image, Rust and Wasm target, compiler, Nix
   environment (if used), `hc`, Holochain, dpkg/fakeroot/NSIS versions and
   full third-party input hashes. Use separate clean output directories.
3. Linux: supply `HOLOCHAIN_BIN`, `HC_BIN`,
   `KITSUNE2_BOOTSTRAP_SRV_BIN` pointing at **reviewed** Ubuntu-compatible
   binaries, plus `HM_RC_LINUX_INPUTS_SHA256` pointing at their independently
   approved `sha256sum` manifest (with file paths accessible to the runner).
   Run `sh packaging/rc-build.sh linux <FULL_SHA> <EMPTY_OUTDIR>`.
   This rebuilds rather than using the unsafe `--skip-build` shortcut.
4. Windows: use the hApp and native MSVC MoQ/bridge binaries from the
   **same SHA's passing CI run**, along with the pinned upstream inputs.
   Set `HM_WIN_UPSTREAM`, `HM_WIN_PYTHON`, `HM_WIN_WHEELS`,
   `HM_WIN_MOQ` and `HM_WIN_BRIDGE`; run
   `sh packaging/rc-build.sh windows <FULL_SHA> <EMPTY_OUTDIR>` on the
   approved NSIS/MinGW builder. Do not mix CI runs or branch heads.
5. Inspect `<package>.provenance.json` and `<package>.sha256`; verify all
   hashes against the actual artefacts and preserve logs. Generate a second
   package using identical pinned inputs in a **different** output directory
   and compare SHA-256. A match proves only that specific environment/inputs.
6. On a disposable Ubuntu 26.04 test system, run
   `sudo apt install ./holochain-music_1.0.0~rc3_amd64.deb`, check
   `holochain-music --version`, inspect the embedded commit marker, execute
   `python3 /usr/share/doc/holochain-music/smoke-test.py /usr/bin/holochain-music`,
   and test removal/data retention. For Windows, run the `installer-smoke`
   job (install, version, status, two-instance real conductor/MoQ, uninstall
   and user-data retention); test `SOURCE_COMMIT.txt`, ACLs and firewall rules.
7. Attach only **actual execution evidence**: logs, runner URLs/SHAs,
   hashes and clean-machine results. The provenance generator never marks a
   test PASS or certifies signing/licensing/hardware.

### Acceptance checklist (no inferred passes)

| Gate | Kind | Result as at 17 Nov | Acceptance evidence |
|---|---|---|---|
| Python version labels equal `1.0.0rc3` | Static automated | **PASS** on main | Both source files |
| PR #45 Windows jobs | Automated, **pre-integration** | **PASS**, run `43581953080` | Four green jobs; cannot be promoted to integrated release pass |
| PR #46 four conductor groups | Automated, **pre-integration** | **PASS**, run `43574405481` | Four groups passed; cannot be promoted to integrated release pass |
| All checks on final merged release SHA | Automated | **NOT RUN** | SHA and green CI run IDs |
| Fresh Linux RC3 .deb + pinned native inputs | Build | **NOT RUN** | SHA-pinned sources, binary hashes, provenance |
| Fresh Windows RC3 installer + independent validation | Build | **NOT RUN** | Same-commit hApp/helpers, output SHA, provenance |
| Version/commit embedded, digest and reproducible assembly | Automated | **NOT RUN** | Installed marker, sidecars, repeat-build hashes |
| Clean Ubuntu apt install + package smoke | Installation | **NOT RUN** | stdout/stderr, installed commit and version |
| Windows install/launch/uninstall on final SHA | Installation | **NOT RUN** | Windows runner logs / firewall / data retention |
| Real Windows WASAPI speaker and repeated seek/recovery | Physical human | **BLOCKED** | Device, recordings/observations |
| Ubuntu↔Windows on two physical computers | Physical human | **BLOCKED** | Bidirectional grant, stream, seek/offline records |
| Real network unplugged offline playback | Physical human | **BLOCKED** | Hardware test result |
| Licensing/CAL-1.0 and third-party redistribution | Approval gate | **BLOCKED** | Legal/owner sign-off |
| Private-grant security and independent security review | Approval gate | **BLOCKED** | Owner/reviewer sign-off |
| Release identifier and distribution authorisation | Owner approval | **BLOCKED** | Explicit decision; never inferred from CI |

**Release conclusion: NO-GO for public distribution.** The old checksums
remain historical records, not evidence for a new candidate. No new SHA-256
values may be entered until the actual files exist and are hashed.
