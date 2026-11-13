# Opt-in Holochain Media Core adapter (comparison only)

Status: **opt-in, disabled by default, not used by any production path.**
Music's Python S1/S2 code remains the read/write implementation. The adapter
lets Music run Holochain Media Core's Rust verifier and `VerifiedCas`
(ConorTttttt/holochain-media-core, CORE-004) against the same packages, so
both implementations can be compared before any switch is considered.

## Why a subprocess CLI

Music already integrates its Rust components (`holochain-music-moq`,
`music_conductor_bridge`, `holochain-storage-node`) as supervised local
executables with JSON output, and packages Python with setuptools. A CLI adds
no Python build tooling (no pyo3/maturin wheel per Python version and
platform), no ABI coupling, and keeps a hard process boundary. An FFI binding
was not justified for a comparison path.

## What crosses the boundary

Only public material: signed manifest/receipt JSON, Ed25519 public keys,
conductor-bridge `AuthoredRecord`s and ciphertext directories. The CLI has no
option for content keys, grants, X25519 keys or private signing keys, and it
never decrypts. Exit codes: `0` accepted, `2` rejected at a named boundary
(`s1-manifest`, `s1-receipt`, `s2-binding`, `manifest-digest-pin`,
`ciphertext-integrity`), `1` usage/I/O failure — which the adapter raises as
`MediaCoreUnavailable`, never as a rejection.

Media Core's CAS uses Music's layout (`objects/sha256/<2>/<sha256>`), so
`verify_package`, `decrypt_package`, `play_granted_wav` and
`Library.verify_complete` work unchanged on a Media Core store.

## Run the comparison

```bash
# Build the CLI (Media Core repository, CORE-004 branch)
cargo build --release -p holochain-content-cli    # -> target/release/holochain-media-core

# In this repository
export HOLOCHAIN_MEDIA_CORE_BIN=/abs/path/to/holochain-media-core
python -m unittest -v tests.test_media_core_adapter
python -m unittest discover -s tests             # full regression, adapter enabled
```

Without `HOLOCHAIN_MEDIA_CORE_BIN` the comparison class is skipped and only
the two "disabled by default" checks run.

## Covered (both implementations must agree)

1. Existing S1 package accepted; identical manifest digest, file ID, chunk
   count and length.
2. Tampered body, re-signed by another key, and wrong trusted key rejected.
3. Receipt and S2 identity bindings: valid set accepted; owner key authored
   by another agent, wrong key purpose, claim for another receipt, commitment
   for another manifest and forged receipt rejected by both.
4. Ciphertext imported into a `Library` CAS; Music's `verify_complete` and
   Media Core's audit agree on offline readiness before, after, after
   same-length corruption and after verified repair.
5. Corrupt/truncated source chunk never imported.
6. Personal licence unwrap + `decrypt_package` from the Media Core store
   reproduce the original bytes.
7. `play_granted_wav` from the Media Core store emits the same PCM SHA-256 as
   from the Python store; ciphertext availability does not authorise a key.

Not covered: switching any production read/write path, MoQ transfer through
the adapter (exercised separately in Media Core's real-conductor CORE-004
acceptance suite), Windows execution of the CLI.
