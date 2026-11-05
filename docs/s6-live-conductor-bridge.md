# S6 (draft) — Holochain 0.7 live conductor → encrypted ciphertext bridge

**State:** Initial read-only bridge and tests. Python IPC contract tests pass locally.
The Rust `holochain_client` WebSocket path needs to pass the two-conductor CI/
Ubuntu Sweettest before this is a verified *live* connection.

## Purpose

S5 and S2 share the same Holochain agent in the combined two-DNA hApp. S4
serves opaque signed encrypted packages. Prior Python `AuthoredRecord` fixtures
proved crypto/hash checks, but did not prove their Holochain origin. This stage
connects a listener to an **authenticated local** Holochain 0.7 conductor, gets
validated zome results, then runs the *existing* signed-manifest and receipt
checks before downloading any ciphertext.

```
Bob's trusted local conductor (admin/app WebSocket, localhost only)
          │
          ├── S5 get_track(Alice, track_id)
          └── S2 get_signing_keys(Alice / node)
                 get_file_commitments(Alice)
                 get_replica_claims(Alice, file_id)
          │
          ▼
music-e2e/src/bin/music_conductor_bridge.rs
  ├── authenticates to named installed app
  ├── requires pinned DNA hashes and same agent for both roles
  ├── uses authorised, signed app zome calls; observes action authors
  ├── rejects missing/ambiguous key or commitment/claim registrations
  └── prints one bounded JSON IPC response to local Python
          │
          ▼
music_catalogue/live_conductor.py
  └── fetch_verified_track(...) → S4 ReadOnlyStorageNodeClient
          │
          ▼
          SHA-256 verified AES-GCM ciphertext stored locally
```

## Safety boundaries

- **Admin WebSocket is privileged.** The executable refuses non-loopback admin
  addresses. Keep the conductor on localhost and restrict access to this
  executable / admin socket. Use it only with a trusted local conductor.
- **DNA pinning is mandatory:** provide independently known S5 and S2 DNA
  hashes (`uhC0k...`) for the *installed app*. The bridge checks role→DNA and
  the matching agent pubkey, and refuses a mismatch. It cannot establish that
  a **new, unreviewed** DNA is safe: review/pin the actual known zome bundle.
- **No key-selection shortcuts:** this proof-of-concept fails on two
  matching key bindings or file/receipt claims. Real deployment needs an
  explicit registration, revocation and key-rotation policy.
- **Holochain authorship** is anchored in the local validating conductor and
  installed, pinned zomes. JSON stdout is *local IPC*, **not** portable
  cryptographic proof that a remote client can verify independently.
- **Only a registered claim:** storage receipt/claim does not prove continued
  custody. Content keys, license grants, playback and MoQ transfer remain
  separate components. Nothing here authorises plaintext access.
- **One fetch at a time:** CLI issues app-interface and signing credentials
  via conductor admin APIs on every invocation. This is a development bridge,
  not a long-lived production daemon.

## Build and run the real-WebSocket Sweettest

From the repository root on this branch, use the **same** Holonix 0.7 shell
and already packed S5/S2 DNA files that passed PR #9:

```bash
cd /mnt/holochain/holochain-music
nix develop ./music-e2e
mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0

# The test needs these existing files:
ls -l music-dna/workdir/music_catalogue.dna dna/workdir/music_storage.dna

cd music-e2e
cargo test --test catalogue_storage_identity_sweettest -- --nocapture
```

The existing 2-conductor happy-path test now also spawns the **real** Rust
`music_conductor_bridge` binary against Bob's admin/app WebSockets, reads
Alice's track, matching owner commitment and Bob's host claim, and verifies
that an incorrect catalogue DNA pin fails. A single test invocation can take
multiple minutes because of real Holochain gossip/consistency.

To run the new Python IPC/verification tests:

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
python -m unittest discover -s tests -p test_live_conductor.py -v
python -m unittest discover -s tests -v
```

To build the CLI explicitly:

```bash
cd /mnt/holochain/holochain-music/music-e2e
cargo build --bin music_conductor_bridge
```

### Calling the Python bridge from an installed conductor

`fetch_from_live_conductor` (in `music_catalogue/live_conductor.py`) takes:

- The **absolute** binary path (typically `music-e2e/target/debug/music_conductor_bridge`)
  and trusted **local admin WebSocket port**.
- Installed app ID and **both trusted DNA hashes**; the expected **Bob agent**.
- Alice/artist agent key, chosen host/node agent key, track ID.
- An optional S1 signed encrypted manifest. If omitted, the manifest is fetched
  from S4 and authenticated against the Holochain digest and artist signature;
  an S4 `https://...` or localhost URL and target folder are required.

The function reads the conductor *before* it calls `ReadOnlyStorageNodeClient`;
all S1/S2/S4/S5 signature, digest, receipt and claim checks still apply.
There is no hardcoded network address, private signing key or content key.

Example *application* call (values must come from the actual installed app,
not be copied from an untrusted remote JSON blob):

```python
from pathlib import Path
from music_catalogue.live_conductor import fetch_from_live_conductor

fetch_from_live_conductor(
    bridge_binary=Path('/mnt/holochain/holochain-music/music-e2e/target/debug/music_conductor_bridge'),
    admin_port=9000, app_id='holochain_music',
    catalogue_dna=TRUSTED_CATALOGUE_DNA_HASH, storage_dna=TRUSTED_STORAGE_DNA_HASH,
    reader_agent=BOB_HOLOCHAIN_AGENT, artist_agent=ALICE_HOLOCHAIN_AGENT,
    node_agent=STORAGE_NODE_HOLOCHAIN_AGENT, track_id='a' * 32,
    storage_url='http://127.0.0.1:PORT',
    target_store=Path('/mnt/holochain/downloads'),
)
```

**Do not execute that illustrative call literally:** uppercase symbols and
`PORT` are placeholders, and the track must match an actual published track.

## Remaining gates

1. Confirm the new Rust websocket test passes under Holonix (plus CI).
2. Build an end-to-end fixture that starts a local conductor, S4 service, and
   publishes a *real* signed S1 package through both DNAs, then calls Python
   with no mocked conductor or storage node in **one combined test**.
3. Set up an operational long-running conductor launcher, app management,
   least-privilege capability credentials, key selection/revocation and TLS.
4. Integrate buyer grants and MoQ/QUIC transfer before playable downloads.
