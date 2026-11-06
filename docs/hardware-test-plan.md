# Hardware test plan — v1.0.0-rc1 (release candidate)

These four tests need a person and real hardware. Run them in order and paste
the filled-in evidence block for each into `docs/v1-release-readiness.md`.
Commands assume Ubuntu 26.04 and the RC package. `$DEB` is the package file;
the expected SHA-256 is in the readiness report.

```bash
DEB=holochain-music_1.0.0~rc1_amd64.deb
sha256sum "$DEB"              # must equal the checksum in the readiness report
```

---

## Test 1 — HP Pro Mini: graphical player and physical ALSA output

Purpose: a person hears authenticated audio through real speakers, driven by
the v1 UI.

```bash
# 0. Sound hardware works at all (should play a 1-second tone per channel)
aplay -l
speaker-test -c 2 -t sine -f 440 -l 1

# 1. Install (or run the extracted copy if you prefer not to install)
sudo apt install ./"$DEB"
holochain-music --version                 # 1.0.0rc1

# 2. A generated 30 s test WAV (440 Hz left, 660 Hz right; licensed test material)
python3 - <<'PY'
import math, struct, wave
with wave.open("/tmp/hm-test-tone.wav", "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(44100)
    w.writeframes(b"".join(struct.pack("<hh", int(6000*math.sin(2*math.pi*440*i/44100)),
                                       int(6000*math.sin(2*math.pi*660*i/44100))) for i in range(44100*30)))
PY

# 3. Start with real ALSA output (default device). The browser opens automatically.
holochain-music start --audio alsa
#    (use: holochain-music config set audio_device hw:0,0 to pick another device)
```

In the browser:

1. **Publish a track → Your profile**: name "Hardware Test", Save.
2. **Publish a track**: path `/tmp/hm-test-tone.wav`, title "Speaker test",
   rights "I own…", then **Encrypt & publish**. It should appear under **Your
   releases**, and in **Browse** with the badge **Offline ready**.
3. **Play**. Expect a steady tone: 440 Hz left, 660 Hz right. The player badge
   shows **Playing · offline copy**.
4. Check each control and note the result:
   - Pause / resume (Space).
   - ←/→ seeks 10 s with a short gap.
   - Drag the seek bar.
   - ↑/↓ and the volume slider change loudness.
   - Stop (■) silences immediately.
   - Play again restarts from 0.
   - Tab through the buttons: the focus ring is visible.
5. Quit with Ctrl+C in the terminal. The terminal prints "Shutting down…" and
   `pgrep -a holochain` shows no app processes left.

Evidence:

```
Test 1 — date/time: ____  machine: HP Pro Mini 400 G9  package sha256: ____
speaker-test audible: Y/N   tone audible in app: Y/N   L/R correct: Y/N
pause/resume Y/N  seek ±10s Y/N  seek bar Y/N  volume Y/N  stop Y/N  keyboard focus visible Y/N
clean shutdown Y/N   problems/notes: ____
```

---

## Test 2 — two physical computers on a private LAN

Machines: **A** = artist + host (example `192.168.1.50`), **B** = listener
(example `192.168.1.60`). Same trusted network, both with the package
installed. Replace the IPs with the real ones from `ip -4 addr`.

On **A**:

```bash
# A1. Bootstrap + relay for the LAN (leave running in its own terminal)
holochain-music bootstrap-server --listen 192.168.1.50:47011

# A2. Settings (second terminal), then start
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

On **B**:

```bash
holochain-music config set bootstrap_url http://192.168.1.50:47011
holochain-music config set relay_url     http://192.168.1.50:47011
holochain-music config set run_local_bootstrap false
holochain-music config set allow_lan true
holochain-music start --audio alsa
```

Steps:

1. A: publish `/tmp/hm-test-tone.wav` (create it on A as in Test 1). Check
   **Identity & settings → Hosting** shows `https://192.168.1.50:47100 · <fingerprint>`.
2. B: **Browse** until "Speaker test" appears. Write down the seconds taken;
   the target is under 60 s with the default 30 s bootstrap poll cap.
3. B: before requesting anything, there must be no **Play** button (no access).
4. B: **Request licence**. A: **Access requests** shows B's agent; click
   **Grant licence**. B: within about 15 s the track becomes playable.
5. B: **Play**. The badge shows **Streaming** and the tone plays on B's
   speakers. Seek forward 20 s while it is still downloading, then pause/resume.
6. B: wait for **Offline ready**.
7. Encryption check (optional, A or B): `sudo tcpdump -ni any udp port 47100 -c 30 -X | head -60`.
   Payloads must look random (QUIC). No RIFF/WAVE text.
8. Failure checks on B:
   - On A, quit the app. On B, play a track that is *not* yet downloaded (or
     delete `~/.local/share/holochain-music/library/cas` objects first): it
     must end in **Unavailable** with no sound.
   - On B: `holochain-music config set allow_lan false`, restart, try to play
     a new track from A: it must refuse (no LAN host accepted). Set it back.
   - With A offline, B's request shows "waiting for the artist to come online";
     restart A, and it should be delivered within about 30 s.

Evidence:

```
Test 2 — date: ____  A: model/IP ____  B: model/IP ____  package sha256: ____
discovery seconds: ____   request->grant seconds: ____   first audio (badge/streaming) Y/N
seek during download Y/N   offline ready Y/N   tcpdump shows no plaintext Y/N/skipped
host stopped -> Unavailable, no audio Y/N   allow_lan=false refuses Y/N   queued request delivered Y/N
notes: ____
```

---

## Test 3 — genuinely disconnected offline playback

Use B from Test 2 (a licensed, **Offline ready** track from another computer).
If Test 2 isn't possible, use A's own published track; that proves less,
because it never streamed.

```bash
# 1. Quit the app (Ctrl+C), then disconnect ALL networking
nmcli networking off            # and/or unplug the cable, switch off Wi-Fi
ip route                        # must show no default route
ping -c1 -W2 192.168.1.50 ; echo "ping exit $?"   # must fail (non-zero)

# 2. Start offline and play
holochain-music start --offline --audio alsa
#    Status says "Offline". Library -> the track shows "Offline ready" -> Play.
ss -tunap | grep -E 'holochain|python' # only 127.0.0.1 (the UI) may appear

# 3. Export a WAV (licence only) and play it with a normal player
#    Library -> Export WAV -> /home/<you>/Music/offline-test.wav
aplay ~/Music/offline-test.wav

# 4. Restore networking
nmcli networking on
```

Evidence:

```
Test 3 — date: ____  machine: ____  no default route Y/N  ping failed Y/N
offline playback audible Y/N  only loopback sockets Y/N  export plays in aplay Y/N  notes: ____
```

---

## Test 4 — clean Ubuntu `apt install`

On a freshly installed Ubuntu 26.04 machine or VM that has never had the
development tree, Rust, Holochain or this repository:

```bash
which holochain hc cargo || echo "clean: no dev tools on PATH"
sha256sum "$DEB"
sudo apt update && sudo apt install ./"$DEB"
dpkg -s holochain-music | grep -E 'Status|Version'
dpkg -L holochain-music | grep -E 'bin/|\.happ|\.desktop'
holochain-music --version
python3 /usr/share/doc/holochain-music/smoke-test.py /usr/bin/holochain-music   # must end with PASS
# Desktop: open "Holochain Music" from the applications menu; the browser shows the player.
sudo apt remove holochain-music
ls ~/.local/share/holochain-music 2>/dev/null && echo "user data kept (expected)"
```

Evidence:

```
Test 4 — date: ____  OS image: ____  clean (no dev tools) Y/N  install OK Y/N
smoke test PASS Y/N (paste last 10 lines)  desktop entry opens UI Y/N  remove keeps data Y/N  notes: ____
```
