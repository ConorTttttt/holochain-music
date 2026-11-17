# Agent 5 — physical release-acceptance operator runbook

**Prepared 17 November 2026. Status: PREPARED, NOT EXECUTED on physical hardware.**
This is the execution companion to [PR #51's hardware evidence pack](https://github.com/ConorTttttt/holochain-music/pull/51) and the existing [hardware test plan](hardware-test-plan.md), not a replacement or a claim of signed acceptance.

## 0. Hard preconditions and scope

1. Release owner selects the advertised platforms and numeric criteria **before** testing, appoints a named tester and independent reviewer, and expressly authorises **private** distribution of the test package. Public distribution remains held pending the licensing/security gates in PR #51.
2. Agent 3 supplies a complete, final package **from one exact source commit**, output hashes, per-installed-component hashes (especially hApp, conductor, bridge and MoQ), a build transcript and the approved manifest below. A *source SHA alone is not proof* of how a package was built.
3. Release owner supplies the full 40-character source commit and manifest SHA-256 through a trusted channel separate from the package transfer. An unsigned manifest plus a hash printed inside that same manifest is **not** independent approval.
4. Each tested machine compares its *actual received* file size and SHA-256 with the approved manifest **before installation**. Verify installed component hashes against Agent 3's bundle inventory as well. Mismatches, absent manifest/build, different candidate commits or unsigned changes after approval = **BLOCKED**.
5. Use **two separate physical PCs** for H03/H04/H05. This remote agent has no speaker, ALSA device, Windows endpoint or second physical PC; prior simulated/no-output and same-machine network results cannot be upgraded to hardware PASS.
6. Use new disposable test identities or backed-up devices. Never delete or alter a user's existing keys, licence, original CAS objects, profile or library to create negative tests. Do not expose a private UI URL: its fragment contains a bearer token. Keep unredacted logs private.

**Manifest schema** (JSON file sent out of band by Agent 3 and approved by release owner; fill with actual values, not example hashes):

```json
{
  "schema_version": 1,
  "approval_id": "owner-assigned-private-test-id",
  "source_sha": "FULL_40_CHARACTER_LOWERCASE_GIT_SHA",
  "artifacts": [
    {
      "platform": "ubuntu-26.04-amd64",
      "filename": "actual-candidate-filename.deb",
      "size_bytes": 123,
      "sha256": "ACTUAL_64_CHARACTER_LOWERCASE_SHA256"
    }
  ]
}
```

The deliberately invalid example above must **not** pass the checker. If Windows is claimed, Agent 3 adds its Windows installer as a second artifact entry. Build provenance, component-hash inventory and CI evidence remain separate mandatory attachments.

### Verify before install — Linux operator

On a machine with Python 3 (stdlib only), from the **same repo revision containing this runbook**:

```bash
set -eu
MANIFEST=/absolute/private/path/candidate-manifest.json
DEB=/absolute/private/path/actual-candidate.deb
MANIFEST_SHA=<64-hex-manifest-digest-from-owner-via-separate-channel>
SOURCE_SHA=<40-hex-build-commit-from-owner-via-separate-channel>
python3 packaging/acceptance/verify_candidate.py \
  --manifest "$MANIFEST" \
  --approved-manifest-sha256 "$MANIFEST_SHA" \
  --expected-source-sha "$SOURCE_SHA" \
  --artifact "$DEB" | tee verify-candidate-linux.json
sha256sum "$DEB"
stat -c '%n %s bytes' "$DEB"
dpkg-deb -f "$DEB" Package Version Architecture
```

Checker exit 0 means **HASH_VERIFIED_NOT_HARDWARE_ACCEPTANCE**, not an audit of the builder or physical acceptance. Any other exit blocks installation. On a clean machine without the checker, use `sha256sum` and `stat` and independently compare to the manifest. The old rc1 SHA in `docs/rc1-checksums.md` was for source `958b23d`, **not** for the current `main` or Agent 3's future output.

### Verify before install — Windows operator

On Windows 11 x64 PowerShell, no Python/Rust/build tools required:

```powershell
$Installer = "C:\private-test\actual-candidate.exe"
Get-FileHash -LiteralPath $Installer -Algorithm SHA256
(Get-Item -LiteralPath $Installer).Length
Get-ComputerInfo | Select-Object WindowsProductName,OsBuildNumber,OsArchitecture
Get-CimInstance Win32_SoundDevice | Select-Object Name,Manufacturer,Status
Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceClass -eq 'MEDIA' } |
  Select-Object DeviceName,DriverVersion,DriverDate,Manufacturer
Get-NetConnectionProfile | Select-Object Name,NetworkCategory
```

Compare filename, byte length, SHA-256 and release-owner source/bundle inventory **before running** the unsigned installer. Do not disable SmartScreen, Defender or firewall to make an untrusted build install. Never label the historic unsigned Windows rc3 package as an approved new candidate without independent explicit approval.

## 1. Evidence directory and baseline

Store originals in an access-restricted **private** folder outside Git. Suggested layout: `evidence/agent5/<approval-id>/H01/...H09/`, plus `candidate-manifest.json`, `owner-approval.txt`, `artifact-hashes.txt`, `installed-component-hashes.txt`, `CI-links.txt`, `execution-ledger.md` and `redaction-index.md`. Record source SHA, exact package SHA-256 on **every** device, UTC command timeline, human tester, acoustic observation, numeric threshold set in advance, logs and reviewer. Preserve source build log separately from test-run logs. Redact network/public IPs, MACs, names, private agents, request details, keys, tokens and URLs containing `#token=` before posting.

Baseline on **each physical Linux host** (keep output private):

```bash
date -u --iso-8601=seconds
cat /etc/os-release; uname -a
aplay -l; aplay -L
cat /proc/asound/cards
ip -br link; ip route
lsb_release -a 2>/dev/null || true
```

Identify host manufacturer/model, sound card/driver, output device, HDMI/USB/analogue path, actual stereo channels, speaker connection, current sample rate/format, NIC and physical router/switch. Save `~/.local/share/holochain-music/logs/{audio.log,conductor.log}` (or `$HOLOCHAIN_MUSIC_HOME/data/logs/` for a sandbox) and relevant bootstrap/host/bridge logs, redacted. Keep command stdout/stderr and exit codes; if logs are absent, report them absent, not clean.

For all private flows use two separate short-path sandbox roots, e.g. `HOLOCHAIN_MUSIC_HOME=/tmp/hm-a-acceptance` and `/tmp/hm-b-acceptance`, unique on each machine. Confirm these are new disposable directories **before running the app**. Persist each sandbox across H03–H05/H09; do not reset it between tests or claim stable identities. On a genuine clean-install test, verify the packaged launcher without any checkout or Rust dev tree.

## 2. Test execution order and gates

**H01 — Ubuntu ALSA acoustic player.** On supported Ubuntu physical speakers, follow `docs/hardware-test-plan.md` Test 1 with a **new generated 440/660 Hz licensed stereo test WAV**. First hear `speaker-test`; then independently hear through the installed app. Log actual play/pause/resume/stop/volume, keyboard and slider seeks, restart/position, UI badges, left/right, audible defects and shutdown. ALSA null/dummy, a virtual output or a PCM hash is not audible evidence.

**H02 — ALSA seek latency.** Follow Test 1b: from the **exact source commit** run 20 real ALSA `packaging/bench-seek.py` seeks, archive JSON (first *write* to ALSA, not sound at speaker), then record 10 actual keyboard-click-to-speaker-onset intervals using the alternating silence/tone WAV and microphone/phone; record individual values, median, p95 and worst, plus stale-status/timeline observations. The owner must approve a numeric acoustic threshold in advance (PR #51 suggests worst <=500 ms only as a proposed criterion). If mic recording cannot be made, leave acoustic timing **NOT RUN** even if the ALSA benchmark passes.

**H03 — two physical computers.** Follow Test 2 on trusted private LAN: A artist/bootstrap/MoQ host, B ungranted listener. Use actual private IP addresses, restricted firewall rules, timestamp publishing and first discovery, capture A+B conductor logs (especially if >60 s), and show B has no playback before grant. B requests a perpetual personal licence, A explicitly grants; record request-to-grant, first audible streamed PCM, mid-download seek, pause/resume, authenticated download completion and B's *independent real speakers*. Keep same identities and track IDs for H04/H05. Avoid uploading raw QUIC packets/keys; a visual ciphertext capture alone does not prove cryptographic correctness.

**H04 — withheld grants, missing host, recovery.** A explicit UI **Deny** action is currently **not implemented** on the audited v1 UI (see PR #51); withhold approval on a second ungranted test track and demonstrate B can neither play nor export/emit PCM. Do **not** report this as interactive denial. For outage, create a third uniquely named licensed track on A that B has **not yet fully downloaded**; stop A, confirm B's request/play shows unavailable without new PCM, restart A, confirm permitted recovery. Queue a permitted request while artist is offline; bring A back and measure whether it is delivered within the documented retry window. Repeat a new-track attempt with `allow_lan=false` to confirm refusal. A fully downloaded, valid perpetual licence correctly plays offline; this is not a host-outage bypass. Never delete someone's CAS objects to force the failure.

**H05 — physically disconnected licence and export.** On B, after H03 and a *fully authenticated downloaded* perpetual licence, shut down, unplug Ethernet and disable Wi-Fi/hotspot/tethering; collect `ip route`, `ip link`, failure to ping A, and `ss -tunap`. Start `holochain-music start --offline --audio alsa`; hear B's saved track, pause/seek, export WAV, hash the result, and hear exported WAV using `aplay` independently. Separately attempt to export a streaming-only granted test track: it **must be refused**. Record whether it ever emits new plaintext on a non-perpetual or ungranted path.

**H06 — clean Ubuntu install.** On fresh supported Ubuntu physical host **or clean VM for installation only**, with no checkout, Holochain, Rust, Cargo or prior app state, run `docs/hardware-test-plan.md` Test 4; check preflight SHA, install, `dpkg -s`, installed file list, launcher version, bundled hApp/native helpers, smoke test, desktop entry, uninstall without user-data deletion. Verify licensing/copyright/source notices as a **separate release gate**; current `main`'s `packaging/build-deb.sh` does not install complete copyright/notice/source documentation, so do not sign off package compliance on that build. A clean VM install is not H01 physical speaker evidence.

**H07 — Windows WASAPI on actual speakers, iff Windows is claimed.** Follow `docs/windows-wasapi-rc3.md`, `docs/windows-lan-test-plan.md` and [issue #26](https://github.com/ConorTttttt/holochain-music/issues/26). Record Windows build, sound card/device (especially Realtek), driver version, endpoint, shared/exclusive and mix format, source sample rates 44.1/48 kHz, and exact installer/installed binary hashes. Listen to five uninterrupted minutes of an authenticated offline WAV **in app** and the exported **same file** in an independent Windows player through the **same device/volume**, then actual authorised streaming. Perform >=20 seeks each direction, >=20 switches, 10 pause/resume and 10 stop/reopen, safe device disconnect/recovery, and timeline status. Timecode any crackles/jitter/dropouts and attach redacted `audio.log` native host-buffer, stream-start, `host_underflows`, `underruns`, `starved_frames`, `rebuffer_silence_frames` and callback timing counters. A Linux-simulated WASAPI pass **cannot** close issue #26.

**H08 — Windows host to Ubuntu listener, iff claimed.** Invert H03 roles and capture an entirely independent physical Windows-host/Ubuntu-listener discovery/request/grant/stream/offline run. Ubuntu-to-Windows evidence does not establish the opposite direction.

**H09 — tampered encrypted CAS fails closed (supplement to H04).** Use **only a new disposable B sandbox**, a uniquely generated licensed test track, no other user's encrypted objects, and a separate copy of its signed manifest. Confirm the track is completely downloaded; **quit B** and stop A's host so it cannot silently repair before the negative check. Locate a cipher object of this track beneath `$HOLOCHAIN_MUSIC_HOME/data/library/cas/objects/sha256` using the track's manifest (not a guess), and confirm the object is not shared by another test track. Back it up outside CAS, then flip one byte of the encrypted object only:

```bash
# Preconditions: app stopped; disposable test root; selected object unshared.
OBJ=/absolute/path/to/DISPOSABLE-CAS-OBJECT
test -f "$OBJ" && test ! -L "$OBJ" || exit 1
BACKUP=$(mktemp "${TMPDIR:-/tmp}/hm-agent5-cipher.XXXXXX")
chmod 600 "$BACKUP"
cp -p -- "$OBJ" "$BACKUP"
sha256sum "$OBJ" "$BACKUP" > before-corruption.sha256
python3 - "$OBJ" <<'PY'
import sys
from pathlib import Path
p = Path(sys.argv[1])
with p.open("r+b") as f:
    original = f.read(1)
    if not original:
        raise SystemExit("empty object; abort")
    f.seek(0)
    f.write(bytes([original[0] ^ 1]))
PY
sha256sum "$OBJ" > tampered-object.sha256
```

While A remains stopped, restart B offline and attempt to open/play the affected object, then try WAV export. **Expected:** an integrity/availability error; no unauthenticated PCM or completed export. Record app state, stderr, audio/bridge logs, exact object digest before/after. A mismatch-triggered *safe refusal* is acceptable; never claim the screen must display a particular text. Stop B, restore the original test object from the **external** backup with `cp -p -- "$BACKUP" "$OBJ"`, confirm `cmp -s "$BACKUP" "$OBJ"` succeeds and the restored object SHA-256 matches the recorded original, then remove the extra backup when the test is closed; restart and confirm authenticated local playback. Optionally repeat with the bad object and A online to confirm authenticated repair (no stale/unauthorised audio during repair); record repair separately. **Do not tamper artist manifests, private grants, keystores or any production data.** If a sandbox cannot be isolated, mark H09 **BLOCKED**, do not run a destructive test.

## 3. Required result reporting and go/no-go

Copy the evidence block in PR #51 into `evidence/<approval-id>/Hxx/acceptance.md` for **each** applicable gate; begin with `Result: NOT RUN`. State actual physical machine and tester, UTC stamps, commands and exit codes, SHA-256s of exact packages and installed hApp/helpers, network/device/driver/sample rate, all timing samples, audible judgment, negative-grant/outage/disconnect proof, logs and reviewer. Each gate must be `PASS`, `FAIL`, `BLOCKED`, `NOT RUN` or `NOT APPLICABLE (scope signed by owner)`; no implicit passing by omission. Store sensitive raw logs privately and publish only redacted evidence references. Record failed tests even if a later retry passes.

**Ubuntu go:** H01–H06 plus H09 PASS on the same approved candidate identities, signed human evidence, owner-agreed latency threshold, negative-case fail-closed, clean-install provenance and independent non-hardware release gates cleared. **Ubuntu no-go** if any required gate is failed, blocked, not run or unreviewed.

**Windows go (only if advertised):** H07 PASS on physical speaker hardware that actually addresses issue #26, plus appropriate LAN direction H03/H08, H04/H05 and approved package/security/legal gates for Windows. **Windows no-go** while issue #26 remains open for the claimed device/platform, until audible evidence demonstrates resolution. Do not infer general hardware compatibility from one device.

**This file was authored without hardware, package or network validation.** Only the synthetic stdlib verifier unit tests have been executed; see `docs/agent5-hardware-acceptance-status.md`. No release, merge, data migration, modified grant, ACL or cryptographic trust assumption is authorised by this document.
