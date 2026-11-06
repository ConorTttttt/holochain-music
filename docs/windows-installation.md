# Holochain Music on Windows 11 (x64) — installation and use

> **Unsigned private test build.** `HolochainMusic-1.0.0-rc-windows-x64.exe`
> is for private hardware testing. It is not code-signed, and its licensing
> review is incomplete (see `licensing-audit.md`). Do not redistribute it.

## 1. Requirements

* Windows 11 x64 (Windows 10 x64 should work but is untested).
* An administrator account for the one-time installation (Program Files and
  firewall rules). Running the app needs no administrator rights.
* Nothing else: Python, Rust, Cargo and Git are **not** needed. The
  installer bundles its own Python runtime and the native helpers.

## 2. Install

1. Get the installer **and** its SHA-256 from the person who built it, over
   a different channel (for example, in person or by message).
2. Check the hash in PowerShell:

   ```powershell
   Get-FileHash .\HolochainMusic-1.0.0-rc-windows-x64.exe -Algorithm SHA256
   ```

   Do not continue if it differs.
3. Run the installer. Because it is unsigned, Windows SmartScreen may say
   *"Windows protected your PC"*. That warning is expected for this build.
   Proceed only for this verified file (**More info → Run anyway**). Do
   **not** turn SmartScreen, Microsoft Defender or the firewall off, now or
   later; the app does not need that.
4. Accept the test-build notice and the default folder
   (`C:\Program Files\Holochain Music`).

The installer adds:

| Item | Where |
|---|---|
| Application | `C:\Program Files\Holochain Music` (`runtime\` Python 3.14, `python\` app, `bin\` native helpers) |
| Start menu | *Holochain Music*, *Quit Holochain Music*, *Holochain Music guide*, *Uninstall* |
| Firewall | Inbound **allow** rules for `holochain.exe`, `holochain-music-moq.exe`, `kitsune2-bootstrap-srv.exe` on the **Private** profile only |
| Uninstall entry | *Settings → Apps → Installed apps* |

Silent install (for scripted test machines): `HolochainMusic-1.0.0-rc-windows-x64.exe /S`.

## 3. Start, open and quit

* **Start:** Start menu → *Holochain Music*. There is no console window. The
  player opens in your default browser at a private `http://127.0.0.1:…`
  link that contains a one-time token. Do not share that link.
* **Reopen the browser tab:** start *Holochain Music* again. A running
  instance is detected and its page reopens.
* **Quit:** Start menu → *Quit Holochain Music*. This shuts down the
  conductor, MoQ host and player cleanly.
* **Command line** (PowerShell):

  ```powershell
  $hm = "C:\Program Files\Holochain Music\holochain-music.exe"
  & $hm --version
  & $hm status
  & $hm start --no-browser      # prints the private link; Ctrl+C to stop
  ```

## 4. Your data

| What | Where |
|---|---|
| Keys, conductor (identity), library, hosted files, logs | `%LOCALAPPDATA%\HolochainMusic\data` |
| Settings | `%LOCALAPPDATA%\HolochainMusic\config\settings.json` |

* The `data` and `config` folders are created with a protected access-control
  list that grants access only to **your Windows account and SYSTEM**.
  Everything inside inherits it. The app refuses to use a key file that any
  other account can read. This is the Windows equivalent of the Linux 0700/0600
  permissions. It protects against other users of the PC, not against malware
  running as you. Use BitLocker for disk encryption.
* The conductor's lair keystore runs inside `holochain.exe` and listens on a
  Windows named pipe (on Linux, a Unix socket). Its passphrase is a random
  key file in `data\keys`.
* The data is per-machine (Local, not Roaming), because the Holochain agent
  identity is bound to this computer's conductor.
* **Upgrades** replace only the program folder. **Uninstalling** removes the
  program, shortcuts and firewall rules, and keeps your data. Make an
  encrypted backup before deleting data yourself:

  ```powershell
  & $hm backup export "$env:USERPROFILE\Documents\holochain-music-backup.hmb"
  ```

## 5. Windows Firewall and network profile

The installer's rules apply to the **Private** network profile only. On a
network marked *Public* (the Windows default for new Wi-Fi networks),
inbound connections stay blocked. Windows may then ask whether to allow
access. For a trusted home or office LAN, mark the network Private instead:

*Settings → Network & internet → (Wi-Fi or Ethernet) → your network →
Network profile type → Private network.*

Check from PowerShell:

```powershell
Get-NetConnectionProfile | Select-Object Name, NetworkCategory
Get-NetFirewallRule -DisplayName "Holochain Music*" | Select-Object DisplayName, Enabled, Profile, Action
```

What listens on the network:

| Process | Protocol | Port | When |
|---|---|---|---|
| `holochain.exe` | UDP/TCP (kitsune2 transport) | dynamic | always when online |
| `holochain-music-moq.exe` | UDP (QUIC, TLS 1.3, pinned certificate) | `host_bind`, e.g. 47100 | when hosting published tracks |
| `kitsune2-bootstrap-srv.exe` | TCP (HTTP bootstrap + relay) | e.g. 47011 | only if you run `bootstrap-server` |

The local player API listens on `127.0.0.1` only and needs no rule.

## 6. Private-LAN setup (Windows listener, Ubuntu artist)

Both computers must be on the same trusted private network. Example: Ubuntu
artist `192.168.1.50`, Windows listener `192.168.1.60`. The full procedure,
with checks and evidence, is in `windows-lan-test-plan.md`. In short:

On **Ubuntu** (artist and bootstrap):

```bash
holochain-music bootstrap-server --listen 192.168.1.50:47011     # own terminal
holochain-music config set bootstrap_url http://192.168.1.50:47011
holochain-music config set relay_url     http://192.168.1.50:47011
holochain-music config set run_local_bootstrap false
holochain-music config set host_bind 0.0.0.0:47100
holochain-music config set host_advertise_ip 192.168.1.50
sudo ufw allow from 192.168.1.60 to any port 47011 proto tcp
sudo ufw allow from 192.168.1.60 to any port 47011 proto udp
sudo ufw allow from 192.168.1.60 to any port 47100 proto udp
holochain-music start --audio alsa
```

On **Windows** (listener):

```powershell
& $hm config set bootstrap_url http://192.168.1.50:47011
& $hm config set relay_url     http://192.168.1.50:47011
& $hm config set run_local_bootstrap false
& $hm config set allow_lan true
```

Then start *Holochain Music* from the Start menu. LAN hosts are accepted only
at private (RFC 1918) addresses, and only with the TLS certificate
fingerprint the artist published in Holochain.

To **host** from Windows instead, set `host_bind` to `0.0.0.0:47100` and
`host_advertise_ip` to the Windows PC's LAN address (`ipconfig`). The
installer's firewall rule already allows `holochain-music-moq.exe` on Private
networks.

## 7. Audio output

Windows playback uses **WASAPI shared mode** (through PortAudio). The track's
sample rate is converted to the device mix format by Windows. Exclusive mode is
not used, so other apps keep their sound. The app keeps at most 200 ms of
audio queued, so pause, seek and stop take effect quickly.

```powershell
& $hm audio-devices                                   # list WASAPI outputs
& $hm config set audio_device "Headphones"            # any unique part of a name
& $hm config set audio_device default                 # follow the Windows default
```

Restart the app after changing the device. If WASAPI cannot open the device at
the track's rate, the app falls back to the MME host API. If a *named* device
is missing, playback fails with an error rather than switching to another
device. Volume is the in-app slider. It is applied after the authenticated
PCM check, so Windows' own volume mixer also applies.

## 8. Offline playback

A track whose badge says **Offline ready** (perpetual licence, fully
downloaded and verified) plays with no network at all:

1. Start menu → *Quit Holochain Music*.
2. Disconnect (Airplane mode, or unplug the cable).
3. PowerShell: `& $hm start --offline` (or simply start from the Start menu;
   the library plays without network either way).

Every chunk is still SHA-256-checked against the artist-signed manifest and
AES-GCM-authenticated before it reaches the speakers. Export a playable WAV
(perpetual licence only) from the Library, or:
`& $hm export <file_id> "$env:USERPROFILE\Music\track.wav"`.

## 9. Troubleshooting

| Symptom | Check |
|---|---|
| Nothing happens on start | `%LOCALAPPDATA%\HolochainMusic\data\logs\app.log`, `conductor.log`, `bridge.log` |
| "already running" but no page | Start *Holochain Music* again (reopens the page), or *Quit* then start |
| Status shows `offline: …` | `conductor.log`. Port in use? Another app instance under the same account? |
| Other computer never appears | Network profile Private? Same `bootstrap_url` on both? Ubuntu `ufw` rules for the Windows IP? Discovery can take up to a few minutes (see release notes). |
| Streaming "Unavailable" | Artist app running? `allow_lan` true on the listener? Artist's `host_advertise_ip` correct? Firewall rule for `holochain-music-moq.exe` on the host? |
| No sound | `& $hm audio-devices`; set `audio_device`; check the Windows volume mixer; Bluetooth devices may need to be connected before starting |
| SmartScreen blocks the installer | Expected for unsigned builds. Verify the SHA-256 first. Never disable SmartScreen. |
| Key file refused ("readable by other users") | Someone changed the folder's permissions. Restore from backup, or remove the extra access in *Properties → Security*. |

Verbose network logs for a test session:

```powershell
$env:RUST_LOG = "warn,kitsune2_core=debug,kitsune2_transport_iroh=debug,holochain_p2p=debug"
& $hm start
```

## 10. Known limitations (Windows test build)

* Unsigned, and not yet validated on physical Windows hardware: physical
  playback, two-machine LAN streaming and installer upgrade/uninstall need
  the hardware tests in `windows-lan-test-plan.md`.
* Stopping the conductor uses `TerminateProcess` (there is no SIGTERM on Windows).
  The Linux build's SIGTERM is equally abrupt for the conductor, which has no
  SIGTERM handler. Holochain's SQLite databases are designed to survive this.
* No Windows Credential Manager / DPAPI integration. Keys are files protected by
  the per-user ACL, as on Linux. No key rotation.
* WAV/PCM16 input only. LAN only (no public-internet hosting). Catalogue
  discovery between fresh peers can occasionally take minutes.
* `kitsune2-bootstrap-srv.exe` is the build shipped with the Holochain 0.7.0
  release. Ubuntu bundles 0.5.1. The LAN plan runs the bootstrap server on
  Ubuntu. A Windows-hosted bootstrap server is covered by the reverse test.

## 11. Compatibility between Windows and Linux

| Component | Linux .deb | Windows installer | Compatible |
|---|---|---|---|
| Holochain conductor | 0.7.0 (`cargo install`, default features) | 0.7.0 official release (default features) | same version and features |
| hApp / DNAs | `holochain_music.happ` | the same file | identical DNA hashes |
| MoQ/QUIC host | built from `crates/moq-music` | same source, Windows target | same protocol, same pinning rules |
| Grants, manifests, AES-GCM | Python, same code | Python, same code | identical |
| Audio | ALSA (`aplay`) | WASAPI shared (PortAudio) | output-only, after authentication |
| Data folder | `~/.local/share/holochain-music` | `%LOCALAPPDATA%\HolochainMusic\data` | same backup format; cross-OS restore not yet tested |
