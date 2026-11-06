# Installation, networking and testing

## Supported platform

Ubuntu 26.04 LTS, amd64. The bundled Holochain 0.7.0 binaries are built against
this release's glibc. Other distributions and releases are untested.
Windows 11 x64 (private test build): see `windows-installation.md`.

## Install the package

```bash
sudo apt install ./holochain-music_1.0.0~rc1_amd64.deb   # pulls python3, python3-cryptography, alsa-utils
holochain-music                                          # or the "Holochain Music" desktop entry
```

Data: `~/.local/share/holochain-music` (keys, conductor, library, host).
Settings: `~/.config/holochain-music/settings.json`. Override both with
`HOLOCHAIN_MUSIC_HOME=/short/path`.

Uninstall with `sudo apt remove holochain-music`. User data is kept; delete the
directories above yourself only after making a backup.

### Clean-machine acceptance test

On a fresh Ubuntu 26.04 machine, after installing the package:

```bash
python3 /usr/share/doc/holochain-music/smoke-test.py /usr/bin/holochain-music
```

(The script is also at `packaging/smoke-test.py` in the source.) It must print
`PASS`. It runs two throw-away instances on one machine with silent audio. Then
check real speakers: start `holochain-music`, publish a WAV from **Publish a
track** and play it.

## Two computers on a private LAN (experimental, not yet validated)

Computer A (artist/host, e.g. `192.168.1.50`) and computer B (listener), on the
same trusted private network.

1. On A, run a bootstrap + relay that both computers use:
   `holochain-music bootstrap-server --listen 192.168.1.50:47011`
2. On **both**, in **Identity & settings**: set Bootstrap URL and Relay URL to
   `http://192.168.1.50:47011`. On B, also tick **Allow private-LAN hosts**.
3. On A: set **Host bind address** to `0.0.0.0:47100` and **Host advertised LAN
   IP** to `192.168.1.50`. Allow UDP 47100 (and TCP 47011) from B only, e.g.
   `sudo ufw allow from 192.168.1.60 to any port 47100 proto udp`.
4. Restart the app on both. On A publish a track; on B wait for it in
   **Browse**, request a licence, approve it on A, then play, seek and download
   on B.
5. Negative checks on B: with A's app stopped, Play must report **Unavailable**
   (no audio); with the advertised IP changed to a wrong address, playback must
   fail.
6. Disconnect B from the network and run `holochain-music start --offline`.
   The downloaded track must play.

Record each result in `docs/v1-release-readiness.md`. Until this has passed on
two physical computers, LAN support is **experimental**.

## Offline independence, real disconnection

The automated test plays with all services stopped, in a process that cannot
open sockets or start helpers. To confirm on hardware: download a licensed
track, quit the app, unplug the network (or `nmcli networking off`), then run
`holochain-music start --offline` and play it.

## Developer setup and tests

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
(cd crates/moq-music && cargo build --release --locked)
(cd crates/storage-node && cargo build --locked)
(cd music-e2e && cargo build --locked --bin music_app_bridge)   # needs Holochain 0.7 toolchain
export HOLOCHAIN_MOQ_BIN=$PWD/crates/moq-music/target/release/holochain-music-moq
export HOLOCHAIN_STORAGE_NODE_BIN=$PWD/crates/storage-node/target/debug/holochain-storage-node
python -m unittest discover -s tests            # all unit + real-QUIC tests

# Real two-conductor application flow (~2–7 min):
HOLOCHAIN_MUSIC_E2E=1 HOLOCHAIN_MUSIC_E2E_DIR=/path/with/space \
HOLOCHAIN_MUSIC_BRIDGE_BIN=$PWD/music-e2e/target/debug/music_app_bridge \
HOLOCHAIN_MUSIC_HAPP=$PWD/integration/workdir/holochain_music.happ \
python -m unittest discover -s tests -p test_v1_e2e_flow.py

# Package:
packaging/build-deb.sh            # or --skip-build to reuse built artefacts
```

The zome crates pin `hdk_derive`, `holochain_integrity_types` and
`holochain_zome_types` to 0.7.0 in their lockfiles to match the 0.7.0
conductor. 0.7.1 changes the capability-grant wire format. Always build with
`--locked`.
