//! S8 one-shot encrypted-file transfer over real IETF MoQ/QUIC.
//!
//! Publisher reads ciphertext only from an S4 CAS replica; subscriber pins a
//! preverified S1 signed manifest and the publisher's TLS cert fingerprint.
//! Deliberately no agent private keys, content keys, plaintext, playback or
//! Holochain admin WebSocket are provided to the MoQ processes.
use anyhow::{anyhow, ensure, Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use holochain_moq_protocol::TransportIdentity;
use holochain_moq_realtime::{
    certs,
    transport::{Publication, PublishTransport, SubscribeTransport, Subscription},
    MoqPublishNode, MoqSubscribeNode,
};
use holochain_music_moq::{load_manifest, read_verified_chunk, store_verified_chunk};
use serde_json::json;
use std::{fs, io::Write, net::SocketAddr, path::PathBuf, time::Duration};
use url::Url;

#[derive(Parser)]
#[command(about = "S8: ciphertext objects over pinned MoQ/QUIC (local prototype)")]
struct Args { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    /// Serve one signed S1 package from an S4 node's ciphertext object store.
    Publish {
        #[arg(long)] manifest: PathBuf,
        #[arg(long)] store: PathBuf,
        #[arg(long)] trusted_artist_hex: String,
        #[arg(long)] expected_manifest_sha256: String,
        #[arg(long)] cert_dir: PathBuf,
        #[arg(long)] ready_file: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")] bind: SocketAddr,
        /// Test-only inter-object pacing to show playback/receive overlap.
        #[arg(long, default_value_t = 2)] chunk_delay_ms: u64,
    },
    /// Receive ciphertext into a separate listener-side CAS without a key.
    Receive {
        #[arg(long)] manifest: PathBuf,
        #[arg(long)] store: PathBuf,
        #[arg(long)] trusted_artist_hex: String,
        #[arg(long)] expected_manifest_sha256: String,
        #[arg(long)] url: Url,
        #[arg(long)] cert_fingerprint_hex: String,
        /// Opt-in per-verified-chunk progress JSONL (no secrets or plaintext).
        #[arg(long, default_value_t = false)] progress_jsonl: bool,
    },
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLISH_WAIT_FOR_DHT: Duration = Duration::from_secs(180);
const OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
fn namespace(file_id: &str) -> String { format!("holochain-music/file/{file_id}") }
const TRACK: &str = "ciphertext-chunks-v1";

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Publish { manifest, store, trusted_artist_hex, expected_manifest_sha256, cert_dir, ready_file, bind, chunk_delay_ms } => {
            publish(manifest, store, trusted_artist_hex, expected_manifest_sha256, cert_dir, ready_file, bind, chunk_delay_ms).await
        }
        Command::Receive { manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, progress_jsonl } => {
            receive(manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, progress_jsonl).await
        }
    }
}

async fn publish(
    manifest_path: PathBuf, store: PathBuf, artist: String, digest: String,
    cert_dir: PathBuf, ready_file: PathBuf, bind: SocketAddr, chunk_delay_ms: u64,
) -> Result<()> {
    ensure!(chunk_delay_ms <= 1000, "invalid per-chunk delay (max 1000 ms)");
    ensure!(bind.ip().is_loopback(), "publisher must bind to a loopback address (S8 local prototype)");
    let manifest = load_manifest(&manifest_path, &artist, &digest)?;
    ensure!(!manifest.body.chunks.is_empty(), "S8 stream requires at least one chunk");
    // Validate the S4 replica *before* accepting a remote subscriber. We
    // validate again immediately before each send against file mutations.
    for c in &manifest.body.chunks { read_verified_chunk(&store, c)?; }

    let (cert, key, identity) = certs::generate_localhost_cert_with_identity(&cert_dir)?;
    let mut publisher = MoqPublishNode::bind(bind, &cert, &key, &namespace(&manifest.body.file_id))?;
    let addr = publisher.local_addr();
    let readiness = json!({
        "url": format!("https://{addr}"),
        "cert_fingerprint_hex": hex::encode(identity.fingerprint),
        "namespace": namespace(&manifest.body.file_id),
        "track": TRACK,
        "manifest_sha256": manifest.digest,
        "file_id": manifest.body.file_id,
    });
    // Only the test orchestrator reads this file. The fingerprint is not
    // authenticated by its own presence in a local readiness JSON file.
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&ready_file)
        .context("creating unique MoQ readiness file")?;
    f.write_all(&serde_json::to_vec(&readiness)?)?;
    f.sync_all()?;

    tokio::time::timeout(PUBLISH_WAIT_FOR_DHT, publisher.connect()).await
        .context("timed out waiting for MoQ subscriber")??;
    let mut publication = publisher.publish(TRACK).await?;
    // The QUIC handshake finishes before SUBSCRIBE is processed. MoQ carries
    // ephemeral objects: this short delay is test choreography, NOT a replay
    // mechanism. Missing objects always make the receiver fail closed.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut sent = 0u64;
    for chunk in &manifest.body.chunks {
        let data = read_verified_chunk(&store, chunk)?;
        sent += data.len() as u64;
        publication.send(Bytes::from(data)).await.context("MoQ object send failed")?;
        // Keep this prototype's small ordered stream ahead of the QUIC reader
        // but below the existing MoQ receiver's 256-object / 32MiB queue.
        tokio::time::sleep(Duration::from_millis(chunk_delay_ms)).await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    drop(publication); // closes the track for this one-shot stream
    println!("{}", json!({"sent_chunks": manifest.body.chunks.len(), "cipher_bytes": sent}));
    Ok(())
}

async fn receive(
    manifest_path: PathBuf, store: PathBuf, artist: String, digest: String,
    url: Url, fingerprint_hex: String, progress_jsonl: bool,
) -> Result<()> {
    ensure!(url.scheme() == "https" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1")),
        "S8 receiver only supports localhost QUIC endpoints");
    let fingerprint = hex::decode(fingerprint_hex).context("invalid TLS certificate pin hex")?;
    let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| anyhow!("TLS pin must be SHA-256"))?;
    let manifest = load_manifest(&manifest_path, &artist, &digest)?;
    ensure!(!manifest.body.chunks.is_empty(), "S8 stream requires at least one chunk");
    let identity = TransportIdentity { fingerprint };
    let mut receiver = MoqSubscribeNode::new_with_pinned_identity(url, &namespace(&manifest.body.file_id), identity)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, receiver.connect()).await
        .context("MoQ/TLS connection timed out")??;
    let mut subscription = tokio::time::timeout(HANDSHAKE_TIMEOUT, receiver.subscribe(TRACK)).await
        .context("MoQ subscription timed out")??;
    let mut received = 0usize;
    let mut bytes = 0u64;
    // A finite signed S1 manifest commits to the exact ordered count/hashes.
    // Do not await an unreliable end-of-stream signal after all chunks arrive.
    for chunk in &manifest.body.chunks {
        let next = tokio::time::timeout(OBJECT_TIMEOUT, subscription.recv()).await
            .context("missing/truncated MoQ ciphertext stream")??;
        let payload = next.ok_or_else(|| anyhow!(
            "MoQ stream incomplete: received {received} of {} chunks", manifest.body.chunks.len()
        ))?;
        store_verified_chunk(&store, chunk, &payload)?;
        if progress_jsonl {
            // Emit progress ONLY AFTER atomic CAS persistence and full signed
            // manifest SHA-256 verification. Still no decryption or key.
            let event = json!({"kind": "chunk_verified", "index": chunk.index,
                "sha256": chunk.sha256, "cipher_bytes": chunk.cipher_bytes});
            println!("{event}");
            std::io::stdout().flush()?;
        }
        received += 1;
        bytes += payload.len() as u64;
    }
    drop(subscription);
    drop(receiver);
    // No plaintext is reconstructed here. The S1 decryptor requires a
    // separately provided 32-byte AES key and performs AES-GCM tag checks.
    let mut report = json!({"verified": true, "received_chunks": received,
        "cipher_bytes": bytes, "manifest_sha256": manifest.digest,
        "file_id": manifest.body.file_id});
    if progress_jsonl { report["kind"] = json!("transfer_complete"); }
    println!("{report}");
    std::io::stdout().flush()?;
    Ok(())
}
