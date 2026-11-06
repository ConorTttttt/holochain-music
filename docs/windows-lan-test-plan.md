# Windows ↔ Ubuntu LAN test plan (v1.0.0-rc1, Windows port)

These tests need two physical computers and a person listening. CI cannot
replace them. Record the evidence blocks in `v1-release-readiness.md` (§9).
Nothing here has been run yet.

| | Computer A | Computer B |
|---|---|---|
| Part 1 | **Ubuntu 26.04**: artist, MoQ host, bootstrap server | **Windows 11**: listener |
| Part 2 | **Windows 11**: artist, MoQ host, bootstrap server | **Ubuntu 26.04**: listener |

Example addresses: Ubuntu `192.168.1.50`, Windows `192.168.1.60`. Replace
them with the real ones (`ip -4 addr` / `ipconfig`). Both must be on the same
trusted private network, with the Windows network profile set to **Private**.

## 0. Preparation (both computers)

**Ubuntu:** install the RC `.deb` and check its SHA-256 against
`rc1-checksums.md`.

**Windows** (PowerShell):

```powershell
Get-FileHash .\HolochainMusic-1.0.0-rc-windows-x64.exe   # == value given by the builder
.\HolochainMusic-1.0.0-rc-windows-x64.exe                # install (see windows-installation.md)
$hm = "C:\Program Files\Holochain Music\holochain-music.exe"
& $hm --version                                          # 1.0.0rc1
Get-NetConnectionProfile | Select Name, NetworkCategory  # must be Private
Get-NetFirewallRule -DisplayName "Holochain Music*" | Select DisplayName, Enabled, Profile
& $hm audio-devices                                      # at least one WASAPI output
```

Test audio (30 s, 440 Hz left / 660 Hz right, licensed test material). On
Ubuntu, use `/tmp/hm-test-tone.wav` from `hardware-test-plan.md`, Test 1. On
Windows, use the bundled interpreter:

```powershell
& "C:\Program Files\Holochain Music\runtime\python.exe" -I -c "import math,struct,wave;w=wave.open(r'$env:USERPROFILE\Music\hm-test-tone.wav','wb');w.setnchannels(2);w.setsampwidth(2);w.setframerate(44100);w.writeframes(b''.join(struct.pack('<hh',int(6000*math.sin(2*math.pi*440*i/44100)),int(6000*math.sin(2*math.pi*660*i/44100))) for i in range(44100*30)));w.close()"
```

Start every app in this test with network diagnostics:

```bash
RUST_LOG="warn,kitsune2_core=debug,kitsune2_transport_iroh=debug,holochain_p2p=debug" holochain-music start --audio alsa
```
```powershell
$env:RUST_LOG = "warn,kitsune2_core=debug,kitsune2_transport_iroh=debug,holochain_p2p=debug"; & $hm start
```

## Part 1 — Ubuntu artist/host → Windows listener

### 1.1 Configure

Ubuntu (A):

```bash
holochain-music bootstrap-server --listen 192.168.1.50:47011        # own terminal, leave running
holochain-music config set bootstrap_url http://192.168.1.50:47011
holochain-music config set relay_url     http://192.168.1.50:47011
holochain-music config set run_local_bootstrap false
holochain-music config set host_bind 0.0.0.0:47100
holochain-music config set host_advertise_ip 192.168.1.50
sudo ufw allow from 192.168.1.60 to any port 47011 proto tcp
sudo ufw allow from 192.168.1.60 to any port 47011 proto udp
sudo ufw allow from 192.168.1.60 to any port 47100 proto udp
```

Windows (B):

```powershell
& $hm config set bootstrap_url http://192.168.1.50:47011
& $hm config set relay_url     http://192.168.1.50:47011
& $hm config set run_local_bootstrap false
& $hm config set allow_lan true
```

Start both apps (with diagnostics, as above).

### 1.2 Main flow (mission steps 1–13)

| # | Action | Pass when |
|---|---|---|
| 1 | A: **Publish a track** → `hm-test-tone.wav`, title "LAN tone" | A's *Identity & settings → Hosting* shows `https://192.168.1.50:47100 · <fingerprint>` |
| 2 | B: **Browse** until "LAN tone" appears; time it | appears (note seconds; target < 60 s) |
| 3 | B: before requesting, the track has **no Play** button | no Play / no audio possible |
| 4 | B: **Request licence** | A: **Access requests** lists B's agent |
| 5 | A: **Grant licence** | — |
| 6 | B: within ~15 s the grant arrives | track becomes playable |
| 7 | B: **Play** | badge **Streaming**, MoQ/QUIC from `192.168.1.50:47100` |
| 8 | B: listen | 440 Hz left, 660 Hz right through the Windows speakers/headphones; no clicks/gaps beyond start |
| 9 | B: seek to 0:20 while still downloading; then 0:05; pause/resume; volume 30 % | each seek audible in < 0.5 s; pause silences within ~0.2 s; volume changes |
| 10 | B: wait | badge **Offline ready** |
| 11 | B: *Quit*; Airplane mode on (or unplug) | `Test-NetConnection 192.168.1.50 -Port 47011` fails |
| 12 | B: `& $hm start --offline`; play "LAN tone" | plays fully, seeks work, no network |
| 13 | B: Library → **Export WAV** (or `& $hm export <file_id> "$env:USERPROFILE\Music\lan-export.wav"`) | file plays in Windows Media Player; `Get-FileHash` noted |

Optional encryption check on A while B streams:
`sudo tcpdump -ni any udp port 47100 -c 30 -X | head -60`. Payloads must look
random (QUIC); there must be no `RIFF`/`WAVE` text.

### 1.3 Negative tests (B = Windows listener)

Restore networking on B and restart both apps first.

| Test | How | Pass when |
|---|---|---|
| Missing grant | A publishes a second track "No grant"; B does **not** request it. B: `& $hm export <its file_id> x.wav` | no Play button; export fails ("no licence"); no audio |
| Unavailable host | A: Ctrl+C the app. B: play a granted track that is *not* downloaded (publish a third track, grant it, delete nothing, play before download completes, or quit B before download and restart) | ends in **Unavailable**; no sound from un-downloaded parts |
| Incorrect TLS certificate (impostor host on the right address) | A: quit the app (its published fingerprint stays in Holochain). Start an impostor with a **new** certificate on the same address, serving the same ciphertext: `/usr/lib/holochain-music/bin/holochain-music-moq serve --served-list ~/.local/share/holochain-music/host/state/served.json --store ~/.local/share/holochain-music/host/cas --cert-dir /tmp/impostor-cert --ready-file /tmp/impostor-ready.json --bind 0.0.0.0:47100 --allow-lan --advertise-ip 192.168.1.50`. B: play a granted, not-yet-downloaded track | B refuses the connection (fingerprint mismatch in the status/log); no audio; nothing written to B's library for that track. Stop the impostor; `rm -rf /tmp/impostor-cert` |
| Corrupted ciphertext | A: quit app. Flip one byte of one hosted object: `f=$(ls ~/.local/share/holochain-music/host/cas/*/* \| head -1); printf '\xff' \| dd of="$f" bs=1 seek=100 conv=notrunc`. Restart A. B: play a granted, not-yet-downloaded track using that object | B rejects that chunk (SHA-256/AES-GCM); state **Unavailable**/error; no audio from the bad chunk; B's library never stores it. Afterwards republish or restore A from backup |
| LAN not allowed | B: `& $hm config set allow_lan false`; restart; play a not-downloaded granted track | refused (no LAN host accepted). Set back to `true` |
| Queued request | A: quit. B: request a new track ("waiting for the artist…"). A: restart | delivered within ~30 s of A coming back |

Evidence (Part 1):

```
Part 1 — date: ____  A Ubuntu: model/IP ____  B Windows 11: model/build/IP ____
.deb sha256: ____  Windows installer sha256: ____  B audio device: ____
discovery s: ____  request->grant s: ____  streaming audio heard L/R correct Y/N
seek during download Y/N (latency by ear ____)  pause/resume Y/N  volume Y/N
offline ready Y/N  disconnected offline playback Y/N  exported WAV plays Y/N (sha256 ____)
tcpdump no plaintext Y/N/skipped
missing grant refused Y/N  host down -> Unavailable Y/N  impostor cert refused Y/N
corrupted chunk refused Y/N  allow_lan=false refuses Y/N  queued request delivered Y/N
logs attached (if discovery > 60 s or any failure): ____
notes: ____
```

## Part 2 — Windows artist/host → Ubuntu listener

### 2.1 Configure

Windows (A), PowerShell:

```powershell
& $hm bootstrap-server --listen 192.168.1.60:47011        # own PowerShell window, leave running
& $hm config set bootstrap_url http://192.168.1.60:47011
& $hm config set relay_url     http://192.168.1.60:47011
& $hm config set run_local_bootstrap false
& $hm config set host_bind 0.0.0.0:47100
& $hm config set host_advertise_ip 192.168.1.60
```

No manual firewall change is needed. The installer's Private-profile rules
cover `holochain-music-moq.exe` and `kitsune2-bootstrap-srv.exe`. If Windows
still shows a firewall prompt, the network is not Private: fix the profile,
don't allow on Public.

Ubuntu (B):

```bash
holochain-music config set bootstrap_url http://192.168.1.60:47011
holochain-music config set relay_url     http://192.168.1.60:47011
holochain-music config set run_local_bootstrap false
holochain-music config set allow_lan true
```

### 2.2 Flow and negative tests

Repeat the table in 1.2 with the roles swapped: Windows publishes from
`%USERPROFILE%\Music\hm-test-tone.wav`; Ubuntu requests, streams, seeks,
goes offline (`nmcli networking off`) and exports. Then run the negative tests
in 1.3 with the roles swapped. On Windows, use these for the host-side
manipulations:

```powershell
# Impostor host (after quitting the app from the Start menu):
& "C:\Program Files\Holochain Music\bin\holochain-music-moq.exe" serve `
  --served-list "$env:LOCALAPPDATA\HolochainMusic\data\host\state\served.json" `
  --store "$env:LOCALAPPDATA\HolochainMusic\data\host\cas" `
  --cert-dir "$env:TEMP\impostor-cert" --ready-file "$env:TEMP\impostor-ready.json" `
  --bind 0.0.0.0:47100 --allow-lan --advertise-ip 192.168.1.60
# Corrupt one hosted object (app stopped):
$f = Get-ChildItem "$env:LOCALAPPDATA\HolochainMusic\data\host\cas" -Recurse -File | Select-Object -First 1
$b = [IO.File]::ReadAllBytes($f.FullName); $b[100] = $b[100] -bxor 0xFF; [IO.File]::WriteAllBytes($f.FullName, $b)
```

Evidence (Part 2): same block as Part 1, with "A Windows / B Ubuntu".

## Part 3 — Windows installer lifecycle

| Test | Pass when |
|---|---|
| Fresh install as admin; start as a standard user | Start menu entry works; no console window; browser opens |
| Second start while running | reopens the page, no second instance |
| *Quit Holochain Music* | `Get-Process holochain, holochain-music-moq, music_app_bridge` shows none within 20 s |
| Kill `pythonw.exe` in Task Manager | `holochain.exe` etc. disappear too (Job Object) |
| Data ACL | `icacls "$env:LOCALAPPDATA\HolochainMusic\data\keys"` lists only you and SYSTEM, `(OI)(CI)(F)`, no inherited entries |
| Upgrade: re-run the same/newer installer while the app runs | app is asked to quit; afterwards same agent key (*Identity & settings*) and library |
| Uninstall | program folder, shortcuts, firewall rules gone (`Get-NetFirewallRule -DisplayName "Holochain Music*"` empty); `%LOCALAPPDATA%\HolochainMusic` still present |
| Reinstall after uninstall | same identity and library come back |

```
Part 3 — date: ____  Windows build: ____  installer sha256: ____
no console Y/N  reopen Y/N  clean quit Y/N  job kill Y/N  ACL user+SYSTEM only Y/N
upgrade keeps identity Y/N  uninstall keeps data Y/N  firewall rules removed Y/N  reinstall restores Y/N
```
