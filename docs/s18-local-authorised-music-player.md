# S18 — Local browser controls for authorised encrypted WAV (draft)

S18 adds a **loopback-only, token-protected local player interface**. The player process, **not** the browser, opens ALSA and holds the listener's X25519 private key. It reads S1 signed encrypted CAS objects, verifies the artist's Ed25519 signature and listener's S10 grant, AES-GCM-authenticates chunks, then sends bounded PCM16 frames directly to the selected ALSA output. The browser receives *only* local library labels, playback state, progress and PCM digest metrics; never audio bytes, content keys, grants or raw private keys.

**Stage boundary:** S18 is a local listener interface for tracks **previously** discovered and authorised through the S2/S5/S9 conductor path. It does **not** yet discover live Holochain catalogues from the browser, buy licences, verify commercial rights, play FLAC/MP3, host a remote API, or support a multi-device media session. Local `title`/`album`/`artist` strings are friendly labels, not signed catalogue claims. S17 still needs separate-machine transport validation.

## 1. Run an entirely offline demo

On Ubuntu, with ALSA `aplay` available:

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
python -m pip install -e .
python -m music_catalogue.local_player --demo --backend alsa --open
```

If no desktop browser opens, copy the printed `http://127.0.0.1:<port>/#token=<secret>` into a browser on **this computer**. Click the **Local test tone** track, then try pause, resume, the timeline, back/forward 10 seconds and stop. Use `Ctrl+C` to stop the server. Generated input is 7-second, 16-kHz PCM WAV, locally encrypted into disposable AES-GCM CAS with a disposable signed test-only content grant. This is **not a Holochain licence**. Use `--backend null` instead of `alsa` to test without speakers. The URL token is a **local secret**; don't share screenshots including it.

## 2. Import an existing S10-authorised track (encrypted only)

Choose a signed manifest, matching local ciphertext CAS directory, artist **independently pinned** Ed25519 public signing key, owner-granted listener-specific S10 grant, and the listener's 32-byte X25519 private-key file. All must belong to the *same* already trusted S9/S10 Holochain identity/grant workflow. S18 does **not** query the conductor to establish the signer pin; a user-supplied dishonest artist pin can authenticate a dishonest fake artist. Example `s18-library.json`:

```json
{
  "tracks": [
    {
      "id": "track-01",
      "title": "Artist's Test Track",
      "artist": "Artist label (local)",
      "album": "Demo album",
      "manifest": "/absolute/local/path/signed-manifest.json",
      "ciphertext_store": "/absolute/local/path/listener-cas",
      "grant": "/absolute/local/path/listener-grant.json",
      "trusted_artist_hex": "<64 lowercase hex digits from the authenticated Holochain artist key binding>",
      "owner_agent": "<authenticated artist agent>",
      "listener_agent": "<authenticated local listener agent>",
      "recipient_private_file": "/absolute/private/path/listener-x25519-32bytes.bin"
    }
  ]
}
```

Set private key mode to `chmod 600` and keep the configuration/private key on your machine. **Do not commit or share them.** Once prepared, run:

```bash
python -m music_catalogue.local_player --library /path/to/s18-library.json --backend alsa --open
```

The player uses the S14 `VerifiedWavSeeker`: each new Play/Seek session prevalidates the **complete signed CAS**, the listener-specific grant and the 44-byte canonical WAV header; seek output is chunk-by-chunk hash and AES-GCM-verified again. Seeks stop the previous bounded PCM session and start a new one at the exact frame (a short acoustic gap is expected). Pause/resume use the existing S11 queue. Stop is intentionally incomplete and **must never** be recorded as successful playback. Changing tracks doesn't let a cancelled old worker finish a new session.

## 3. Security and honest limits

- HTTP binds **only `127.0.0.1`**, on a random port by default; the application does not listen on a LAN or expose a browser-readable plaintext media endpoint. No CORS is enabled.
- Every `/api/...` request requires a fresh 256-bit bearer token presented in the printed URL fragment, not in URL query strings. The browser retains it in **tab sessionStorage**, removes the fragment from the visible URL and sends it via `Authorization`. For state-changing requests, the server also restricts `Host` and `Origin`. Token theft, malware on the local machine, or another app with access to the same local user context are **not** mitigated.
- Static UI assets are local package files, with no third-party CSS/JS; a restrictive CSP and `no-store` headers are applied. All catalogue labels enter the DOM via `textContent`, not HTML injection.
- PCM stays in the local player/ALSA process and S11's **64 KiB** bounded queue. No web audio element, plaintext WAV export, content key storage, transcoding, commercial rights guarantee, authentication-based payments, lockscreen/mobile integration, playlists or real-time QoS guarantee.
- Local track configs can reference only explicitly listed local files and directories. Symlink final paths, duplicate IDs, invalid grants and corrupted CAS fail closed; corrupted audio never reaches the device. Publisher/receipt trust still originates in the existing Holochain/S4/S9/S10 workflow, not in local display names.

## 4. Tests

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s18_local_player.py -v
```

S18's Python suite tests real Ed25519/S1/AES-GCM/X25519 inputs and exact PCM hashes, UI library field isolation, wrong grants, tampered chunks, pause/resume/stop, frame-exact seek and replay, old-worker cancellation, bearer/origin/host/HTTP rejection, and an offline demo. It also runs in `.github/workflows/music-catalogue-ci.yml` without actual ALSA hardware. Manually confirm the audible demo on the Ubuntu host before marking **physical S18 UI playback** verified.
