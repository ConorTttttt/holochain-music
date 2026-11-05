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
use holochain_music_moq::{load_manifest, read_verified_chunk, repair_track, store_verified_chunk};
use serde_json::json;
use std::{fs, io::Write, net::{IpAddr, Ipv4Addr, SocketAddr}, path::PathBuf, time::Duration};
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
        /// S17 opt-in: permit a LAN interface (never enabled by default).
        #[arg(long, default_value_t = false)] allow_lan: bool,
        /// S17 advertised RFC1918 IPv4 host address; mandatory with --allow-lan.
        #[arg(long)] advertise_ip: Option<Ipv4Addr>,
        /// Test-only inter-object pacing to show playback/receive overlap.
        #[arg(long, default_value_t = 2)] chunk_delay_ms: u64,
        /// Test-only repeatable network jitter: after every N objects.
        #[arg(long, default_value_t = 0)] jitter_every: u64,
        /// Test-only extra milliseconds after each jittered object.
        #[arg(long, default_value_t = 0)] jitter_delay_ms: u64,
        /// S15 opt-in: after the normal stream, serve exactly one missing
        /// ciphertext index on a second QUIC/MoQ session at the same TLS pin.
        /// Host side must choose the index in advance (test choreography);
        /// arbitrary subscriber-driven requests are NOT supported yet.
        #[arg(long)] repair_index: Option<usize>,
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
        /// S17 opt-in: allow a certificate-pinned RFC1918 LAN endpoint.
        #[arg(long, default_value_t = false)] allow_lan: bool,
    },
    /// Fetch exactly one S1-manifest-pinned ciphertext CAS object via new MoQ session.
    RepairReceive {
        #[arg(long)] manifest: PathBuf,
        #[arg(long)] store: PathBuf,
        #[arg(long)] trusted_artist_hex: String,
        #[arg(long)] expected_manifest_sha256: String,
        #[arg(long)] url: Url,
        #[arg(long)] cert_fingerprint_hex: String,
        #[arg(long)] index: usize,
        /// S17 opt-in: allow a certificate-pinned RFC1918 LAN endpoint.
        #[arg(long, default_value_t = false)] allow_lan: bool,
    },
}

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLISH_WAIT_FOR_DHT: Duration = Duration::from_secs(180);
const OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
fn namespace(file_id: &str) -> String { format!("holochain-music/file/{file_id}") }
const TRACK: &str = "ciphertext-chunks-v1";

/// S17 deliberately permits only literal RFC1918 IPv4 for remote hosts: no
/// DNS rebinding, internet exposure, userinfo, URL paths or local-link hosts.
/// The TLS certificate is still verified against Bob's DHT-authenticated pin.
fn validate_endpoint(url: &Url, allow_lan: bool) -> Result<()> {
    ensure!(url.scheme() == "https" && url.username().is_empty()
        && url.password().is_none() && url.port().is_some()
        && url.port() != Some(0) && url.path() == "/"
        && url.query().is_none() && url.fragment().is_none(),
        "invalid MoQ HTTPS endpoint");
    let host = url.host_str().ok_or_else(|| anyhow!("MoQ URL has no host"))?;
    if matches!(host, "127.0.0.1" | "localhost" | "::1") { return Ok(()); }
    let ip: Ipv4Addr = host.parse().context("MoQ LAN host must be literal IPv4")?;
    ensure!(allow_lan && ip.is_private(),
        "non-loopback MoQ endpoint needs explicit --allow-lan and RFC1918 IPv4");
    Ok(())
}

fn advertised_host(bind: SocketAddr, allow_lan: bool, advertise_ip: Option<Ipv4Addr>) -> Result<IpAddr> {
    if !allow_lan {
        ensure!(advertise_ip.is_none() && bind.ip().is_loopback(),
            "default MoQ publisher must bind to loopback without --advertise-ip");
        return Ok(bind.ip());
    }
    let advertised = advertise_ip.context("--allow-lan requires --advertise-ip")?;
    ensure!(advertised.is_private(), "S17 advertise IP must be RFC1918 private IPv4");
    ensure!(bind.ip().is_unspecified() || bind.ip() == IpAddr::V4(advertised),
        "S17 bind must match --advertise-ip or be 0.0.0.0");
    Ok(IpAddr::V4(advertised))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Publish { manifest, store, trusted_artist_hex, expected_manifest_sha256, cert_dir, ready_file, bind, allow_lan, advertise_ip, chunk_delay_ms, jitter_every, jitter_delay_ms, repair_index } => {
            publish(manifest, store, trusted_artist_hex, expected_manifest_sha256, cert_dir, ready_file, bind, allow_lan, advertise_ip, chunk_delay_ms, jitter_every, jitter_delay_ms, repair_index).await
        }
        Command::Receive { manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, progress_jsonl, allow_lan } => {
            receive(manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, progress_jsonl, allow_lan).await
        }
        Command::RepairReceive { manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, index, allow_lan } => {
            repair_receive(manifest, store, trusted_artist_hex, expected_manifest_sha256, url, cert_fingerprint_hex, index, allow_lan).await
        }
    }
}

async fn publish(
    manifest_path: PathBuf, store: PathBuf, artist: String, digest: String,
    cert_dir: PathBuf, ready_file: PathBuf, bind: SocketAddr,
    allow_lan: bool, advertise_ip: Option<Ipv4Addr>, chunk_delay_ms: u64,
    jitter_every: u64, jitter_delay_ms: u64, repair_index: Option<usize>,
) -> Result<()> {
    ensure!(chunk_delay_ms <= 1000, "invalid per-chunk delay (max 1000 ms)");
    ensure!(jitter_delay_ms <= 2000, "invalid jitter delay (max 2000 ms)");
    ensure!((jitter_every == 0) == (jitter_delay_ms == 0),
        "jitter-every and jitter-delay-ms must both be zero or both nonzero");
    let endpoint_ip = advertised_host(bind, allow_lan, advertise_ip)?;
    let manifest = load_manifest(&manifest_path, &artist, &digest)?;
    ensure!(!manifest.body.chunks.is_empty(), "S8 stream requires at least one chunk");
    if let Some(index) = repair_index {
        ensure!(index < manifest.body.chunks.len(), "S15 repair index outside signed manifest");
    }
    // Validate the S4 replica *before* accepting a remote subscriber. We
    // validate again immediately before each send against file mutations.
    for c in &manifest.body.chunks { read_verified_chunk(&store, c)?; }

    let (cert, key, identity) = certs::generate_localhost_cert_with_identity(&cert_dir)?;
    let mut publisher = MoqPublishNode::bind(bind, &cert, &key, &namespace(&manifest.body.file_id))?;
    let addr = publisher.local_addr();
    let readiness = json!({
        "url": format!("https://{}", SocketAddr::new(endpoint_ip, addr.port())),
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
        let periodic_jitter = if jitter_every > 0 && (chunk.index as u64 + 1) % jitter_every == 0 {
            jitter_delay_ms
        } else { 0 };
        tokio::time::sleep(Duration::from_millis(chunk_delay_ms + periodic_jitter)).await;
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    drop(publication); // closes the primary MoQ track
    // S15 bounded proof of a selective ciphertext request using a new MoQ
    // SUBSCRIBE, NOT an S4 HTTP chunk read. This same bound server and TLS
    // certificate remains live, so Bob's validated DHT pin remains valid.
    // Host and test runner have preselected ONE repair index: this does NOT
    // implement arbitrary peer-driven repair requests, a relay or automatic
    // network-loss resumption. Each session serves only the selected object.
    if let Some(index) = repair_index {
        tokio::time::timeout(PUBLISH_WAIT_FOR_DHT, publisher.connect()).await
            .context("S15 selective MoQ repair subscriber did not connect")??;
        let mut repair = publisher.publish(&repair_track(index)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ciphertext = read_verified_chunk(&store, &manifest.body.chunks[index])?;
        let repair_bytes = ciphertext.len();
        repair.send(Bytes::from(ciphertext)).await.context("MoQ selective ciphertext repair send failed")?;
        tokio::time::sleep(Duration::from_millis(600)).await;
        drop(repair);
        println!("{}", json!({"sent_chunks": manifest.body.chunks.len(), "cipher_bytes": sent,
            "repair_index": index, "repair_cipher_bytes": repair_bytes,
            "repair_transport": "pinned-moq-quic-v1"}));
    } else {
        println!("{}", json!({"sent_chunks": manifest.body.chunks.len(), "cipher_bytes": sent}));
    }
    Ok(())
}

async fn receive(
    manifest_path: PathBuf, store: PathBuf, artist: String, digest: String,
    url: Url, fingerprint_hex: String, progress_jsonl: bool, allow_lan: bool,
) -> Result<()> {
    validate_endpoint(&url, allow_lan)?;
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

/// S15 single-index subscriber request over a separate pinned QUIC/MoQT
/// session. Bob must already know this URL and certificate fingerprint from
/// his authenticated local Holochain conductor, NOT a publisher ready file.
async fn repair_receive(
    manifest_path: PathBuf, store: PathBuf, artist: String, digest: String,
    url: Url, fingerprint_hex: String, index: usize, allow_lan: bool,
) -> Result<()> {
    validate_endpoint(&url, allow_lan)?;
    let fingerprint = hex::decode(fingerprint_hex).context("invalid pinned TLS fingerprint")?;
    let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| anyhow!("TLS pin must be SHA-256"))?;
    let manifest = load_manifest(&manifest_path, &artist, &digest)?;
    ensure!(index < manifest.body.chunks.len(), "repair index outside signed S1 manifest");
    let chunk = &manifest.body.chunks[index];
    let identity = TransportIdentity { fingerprint };
    let mut receiver = MoqSubscribeNode::new_with_pinned_identity(
        url, &namespace(&manifest.body.file_id), identity)?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, receiver.connect()).await
        .context("S15 pinned MoQ repair QUIC connection timeout")??;
    let mut subscription = tokio::time::timeout(HANDSHAKE_TIMEOUT,
        receiver.subscribe(&repair_track(index))).await
        .context("S15 repair subscription timed out")??;
    let next = tokio::time::timeout(OBJECT_TIMEOUT, subscription.recv()).await
        .context("S15 missing selective MoQ repair object")??;
    let payload = next.ok_or_else(|| anyhow!("S15 repair publisher sent no ciphertext"))?;
    // Reject oversized or mismatched objects before local filesystem write.
    store_verified_chunk(&store, chunk, &payload)?;
    // Consume exactly the requested object and then stop this subscription.
    // As in the main S8 receiver, do not wait for an unreliable clean MoQ
    // end-of-track event after the last verified object has arrived.
    // Unrequested objects are neither read nor persisted.
    drop(subscription);
    drop(receiver);
    println!("{}", json!({"repair_verified": true, "repair_index": index,
        "cipher_bytes": payload.len(), "manifest_sha256": manifest.digest,
        "file_id": manifest.body.file_id, "repair_transport": "pinned-moq-quic-v1"}));
    Ok(())
}


#[cfg(test)]
mod s17_lan_tests {
    use super::*;
    #[test]
    fn endpoint_requires_explicit_lan_and_exact_scheme() {
        let local = Url::parse("https://127.0.0.1:4567").unwrap();
        assert!(validate_endpoint(&local, false).is_ok());
        let private = Url::parse("https://192.168.5.20:4567").unwrap();
        assert!(validate_endpoint(&private, false).is_err());
        assert!(validate_endpoint(&private, true).is_ok());
        for rejected in ["https://8.8.8.8:4567", "http://192.168.1.2:4567",
                         "https://192.168.1.2:4567/secret", "https://u@192.168.1.2:4567",
                         "https://192.168.1.2:4567/?x=1", "https://127.0.0.1:0"] {
            assert!(validate_endpoint(&Url::parse(rejected).unwrap(), true).is_err(), "{rejected}");
        }
    }
    #[test]
    fn publisher_advertisement_must_be_private_and_explicit() {
        let localhost: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(advertised_host(localhost, false, None).is_ok());
        let all: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(advertised_host(all, false, None).is_err());
        assert!(advertised_host(all, true, None).is_err());
        let lan: Ipv4Addr = "192.168.5.20".parse().unwrap();
        assert_eq!(advertised_host(all, true, Some(lan)).unwrap(), IpAddr::V4(lan));
        assert!(advertised_host(localhost, true, Some(lan)).is_err());
        assert!(advertised_host(all, true, Some("8.8.8.8".parse().unwrap())).is_err());
    }
}
