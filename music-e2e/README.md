# S5: Two-real-conductor catalogue acceptance tests

This native Rust Sweettest crate is intentionally **separate** from the
`music-dna` Wasm workspace. It uses the actual Holochain 0.7 conductor and
**the packaged catalogue DNA**. No mocked author fields or in-memory DHT.

## Prerequisites

- Nix with flakes enabled, or a compatible Holochain 0.7 (`hc`, `holochain`,
  `lair-keystore`) and native Rust toolchain.
- Holochain 0.7 Holonix shell, as recommended in
  [Soushi888's Holochain skill](https://github.com/Soushi888/holochain-agent-skills/tree/main/skills/holochain).
- Storage for a native Holochain build (potentially multiple GB).

The repository pins `hdk = 0.7.0` and `hdi = 0.8.0` for its zomes. The test
crate pins native `holochain = 0.7.0` with the `sweettest` feature.

## Run from the repository root

```bash
nix develop ./music-e2e
cd music-dna
cargo build --release --target wasm32-unknown-unknown
hc dna pack workdir
cd ../music-e2e
cargo test --test catalogue_sweettest -- --nocapture
```

If already using a matching Holonix environment, omit the first command.
Both tests create their own independent temporary conductors and agents.
They wait for DHT consistency **before** cross-agent reads, and check:

1. Alice authors an artist profile, album and track; Bob discovers them by
   direct lookup, listing and public title search.
2. Bob receives the expected `file_id` and `manifest_sha256` metadata (not
   any media bytes or content keys).
3. An append-only track revision by Alice becomes visible to Bob.
4. Bob cannot publish a profile or album claiming Alice's identity, and
   malformed track metadata is rejected by an actual conductor.

These tests are **not** the encrypted-file node network, storage audits,
S2 artist signing-key registration or MoQ playback. They test the S5 catalogue
DHT/author-validation acceptance gate only.

### Troubleshooting

If `hc dna pack` fails, verify that both compiled Wasm files exist under
`music-dna/target/wasm32-unknown-unknown/release/` and that `hc --version`
is compatible with Holochain 0.7. Avoid `cargo ... --manifest-path ...` from
the repo root for Wasm compilation, because Cargo may miss
`music-dna/.cargo/config.toml` and fail in `getrandom`.

The local `music_catalogue.dna` is a **generated artifact**; do not commit
it or secret conductor keys. Run `git status` before committing changes.
