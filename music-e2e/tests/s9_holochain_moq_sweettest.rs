//! S9: Holochain-authenticated host MoQ URL/certificate and real QUIC.
//! S7: one uninterrupted real S5 + S2 + S1 + S4 retrieval through Bob's
//! authenticated Holochain admin/app WebSocket and the Python listener.
//!
//! Unlike separate S6 and S4 contract tests, this test publishes *actual*
//! S1 manifest, Ed25519 key, receipt and replica commitments to the two DNAs,
//! then invokes the production read-only client with NO injected AuthoredRecord
//! or manifest. Bob retrieves encrypted chunks from a real Rust storage node.
//!
//! TEST ONLY: the Python fixture has the AES key to prove byte-for-byte
//! recovery. Neither the storage node nor the conductor receives that key.

use holo_hash::ActionHash;
use holochain::sweettest::*;
use serde::Serialize;
use serde_json::Value;
use std::{
    env, fs,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const APP: &str = "s9-holochain-moq-endpoint";
const MUSIC: &str = "music_catalogue";
const STORAGE: &str = "music_storage";
const ALICE: usize = 0;
const BOB: usize = 1;

#[derive(Debug, Serialize)]
struct ArtistProfile {
    schema: String,
    artist_agent: String,
    display_name: String,
    biography: String,
    artwork_manifest_sha256: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RightsBasis { OriginalOwner }

#[derive(Debug, Serialize)]
struct Track {
    schema: String,
    artist_agent: String,
    track_id: String,
    album_id: Option<String>,
    title: String,
    duration_ms: u32,
    disc_number: u16,
    track_number: u16,
    audio_format: String,
    file_id: String,
    manifest_sha256: String,
    rights_basis: RightsBasis,
}

#[derive(Debug, Serialize)]
struct SigningKeyBinding {
    schema: String,
    agent: String,
    purpose: String,
    signing_key_hex: String,
}

#[derive(Debug, Serialize)]
struct FileCommitment {
    schema: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
}

#[derive(Debug, Serialize)]
struct ReplicaClaim {
    schema: String,
    node_agent: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
    receipt_sha256: String,
}

#[derive(Debug, Serialize, Clone)]
struct MoqEndpoint {
    schema: String,
    node_agent: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
    url: String,
    cert_fingerprint_hex: String,
}

fn repo() -> PathBuf { Path::new(env!("CARGO_MANIFEST_DIR")).join("..") }
fn dna(relative: &str, override_name: &str) -> PathBuf {
    let path = env::var_os(override_name).map(PathBuf::from)
        .unwrap_or_else(|| repo().join(relative));
    assert!(path.is_file(), "DNA bundle missing: {}; compile wasm zomes and pack each DNA first", path.display());
    path
}
fn s(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing JSON fixture field {key}"))
        .to_owned()
}

struct TempWorkspace(PathBuf);
impl TempWorkspace {
    fn new() -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = env::temp_dir().join(format!("holochain-music-s7-{}-{nanos}", std::process::id()));
        fs::create_dir(&root).expect("create private S7 test workspace");
        Self(root)
    }
}
impl Drop for TempWorkspace {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

struct Node(Child);
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn python_stage(python: &Path, script: &Path, arguments: Vec<String>) -> Value {
    let python = python.to_owned();
    let script = script.to_owned();
    let root = repo();
    // External IO and the Python process must not block the Holochain runtime.
    let result = tokio::task::spawn_blocking(move || {
        Command::new(python).arg(script).args(arguments)
            .env("PYTHONPATH", &root)
            .output()
    }).await.expect("Python subprocess task").expect("start S7 Python test helper");
    assert!(result.status.success(),
        "S7 fixture/listener failed: stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    serde_json::from_slice(&result.stdout).expect("S7 fixture must print one JSON result")
}

async fn wait_for_node(address: SocketAddr, node: &mut Node) {
    for _ in 0..100 {
        assert!(node.0.try_wait().expect("inspect node process").is_none(),
            "S4 storage node exited before becoming available");
        if TcpStream::connect_timeout(&address, Duration::from_millis(150)).is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("S4 storage node did not start at {address}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bob_discovers_host_authored_moq_endpoint_and_receives_verified_quic() {
    let root = repo();
    let fixture_script = root.join("music-e2e/tests/helpers/s7_live_package.py");
    let python = env::var_os("HOLOCHAIN_MUSIC_PYTHON").map(PathBuf::from)
        .unwrap_or_else(|| {
            let venv = root.join(".venv/bin/python");
            if venv.is_file() { venv } else { PathBuf::from("python3") }
        });
    let moq_binary = env::var_os("HOLOCHAIN_MOQ_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("crates/moq-music/target/debug/holochain-music-moq"));
    assert!(moq_binary.is_file(), "S9 requires the real MoQ/QUIC executable at {}; build using `cargo build --manifest-path crates/moq-music/Cargo.toml`", moq_binary.display());
    let binary = env::var_os("HOLOCHAIN_STORAGE_NODE_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("crates/storage-node/target/debug/holochain-storage-node"));
    assert!(binary.is_file(), "S7 needs the real S4 node executable at {}; build with `cargo build --manifest-path crates/storage-node/Cargo.toml`", binary.display());
    let bridge = PathBuf::from(env!("CARGO_BIN_EXE_music_conductor_bridge"));
    assert!(bridge.is_absolute() && bridge.is_file(), "S6 Rust WebSocket bridge binary missing");
    let temp = TempWorkspace::new();
    let fixture_dir = temp.0.join("fixture");
    let node_dir = temp.0.join("node");
    let fixture_arg = fixture_dir.to_string_lossy().to_string();
    let fixture = python_stage(&python, &fixture_script,
        vec!["prepare".into(), "--root".into(), fixture_arg.clone()]).await;
    let file_id = s(&fixture, "file_id");
    let digest = s(&fixture, "manifest_sha256");
    let track_id = s(&fixture, "track_id");

    // Start the real S4 Rust node on localhost. Only the artist's Ed25519
    // *public* key is passed to it, never the artist private key or AES key.
    let reserved = TcpListener::bind("127.0.0.1:0").expect("allocate S4 listener port");
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let url = format!("http://{address}");
    let mut node = Node(Command::new(binary)
        .arg("--root").arg(&node_dir)
        .arg("--listen").arg(address.to_string())
        .arg("--artist-key").arg(s(&fixture, "artist_public_b64"))
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("start real S4 storage node"));
    wait_for_node(address, &mut node).await;
    let uploaded = python_stage(&python, &fixture_script, vec![
        "upload".into(), "--root".into(), fixture_arg.clone(),
        "--node-url".into(), url.clone(),
        "--node-root".into(), node_dir.to_string_lossy().to_string(),
    ]).await;
    assert_eq!(s(&uploaded, "file_id"), file_id);
    assert_eq!(s(&uploaded, "manifest_sha256"), digest);

    // Install both independently validated DNAs under ONE agent per hApp.
    let music = SweetDnaFile::from_bundle(&dna("music-dna/workdir/music_catalogue.dna", "MUSIC_CATALOGUE_DNA"))
        .await.expect("load S5 DNA");
    let storage = SweetDnaFile::from_bundle(&dna("dna/workdir/music_storage.dna", "MUSIC_STORAGE_DNA"))
        .await.expect("load S2 DNA");
    let mut conductors = SweetConductorBatch::standard(2).await;
    let apps = conductors.setup_app(APP, &[music, storage]).await.expect("install S5/S2 hApps");
    let mut music_cells = Vec::new();
    let mut storage_cells = Vec::new();
    for app in apps.into_inner() {
        let mut it = app.into_cells().into_iter();
        music_cells.push(it.next().expect("catalogue cell"));
        storage_cells.push(it.next().expect("storage cell"));
        assert!(it.next().is_none());
    }
    for i in [ALICE, BOB] {
        assert_eq!(music_cells[i].agent_pubkey(), storage_cells[i].agent_pubkey(),
            "catalogue and storage DNAs must share the same Holochain agent identity");
    }
    conductors.exchange_peer_info().await;
    let alice = music_cells[ALICE].agent_pubkey().to_string();
    let bob = music_cells[BOB].agent_pubkey().to_string();
    let music_alice = music_cells[ALICE].zome(MUSIC);
    let storage_alice = storage_cells[ALICE].zome(STORAGE);
    let storage_bob = storage_cells[BOB].zome(STORAGE);

    // Alice registers the REAL artist public key and signed S1 digest.
    let key = SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(),
        agent: alice.clone(), purpose: "owner-manifest".into(),
        signing_key_hex: s(&fixture, "artist_public_hex"),
    };
    let commitment = FileCommitment {
        schema: "holochain-storage/file-commitment/v1".into(),
        owner_agent: alice.clone(), file_id: file_id.clone(), manifest_sha256: digest.clone(),
    };
    let profile = ArtistProfile {
        schema: "holochain-music/artist/v1".into(),
        artist_agent: alice.clone(), display_name: "Alice (S7 fixture)".into(),
        biography: "A synthetic integration-test artist".into(), artwork_manifest_sha256: None,
    };
    let track = Track {
        schema: "holochain-music/track/v1".into(), artist_agent: alice.clone(),
        track_id: track_id.clone(), album_id: None, title: "S7 Verified Song".into(),
        duration_ms: 15_000, disc_number: 1, track_number: 1,
        audio_format: "audio/flac".into(), file_id: file_id.clone(),
        manifest_sha256: digest.clone(), rights_basis: RightsBasis::OriginalOwner,
    };
    conductors[ALICE].call::<_, ActionHash>(&storage_alice, "register_signing_key", &key).await;
    conductors[ALICE].call::<_, ActionHash>(&storage_alice, "publish_file_commitment", &commitment).await;
    conductors[ALICE].call::<_, ActionHash>(&music_alice, "publish_artist_profile", &profile).await;
    conductors[ALICE].call::<_, ActionHash>(&music_alice, "publish_track", &track).await;

    // Bob acts as the registered storage node host and signs the S2 host
    // declarations using his own Holochain agent. The receipt is from the
    // actual Rust S4 node and was checked against its real public key.
    let host_key = SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(),
        agent: bob.clone(), purpose: "host-receipt".into(),
        signing_key_hex: s(&uploaded, "node_public_hex"),
    };
    let claim = ReplicaClaim {
        schema: "holochain-storage/replica-claim/v1".into(),
        node_agent: bob.clone(), owner_agent: alice.clone(),
        file_id: file_id.clone(), manifest_sha256: digest.clone(),
        receipt_sha256: s(&uploaded, "receipt_sha256"),
    };
    conductors[BOB].call::<_, ActionHash>(&storage_bob, "register_signing_key", &host_key).await;
    conductors[BOB].call::<_, ActionHash>(&storage_bob, "publish_replica_claim", &claim).await;
    // Both cells must integrate both agents' writes before Bob queries S5/S2.
    await_consistency_s(90, music_cells.iter()).await.expect("catalogue DHT consistency");
    await_consistency_s(90, storage_cells.iter()).await.expect("storage DHT consistency");

    // The S4/QUIC publisher announces its address/cert in a local readiness
    // file which only the *host* uses to create a DHT record. Bob NEVER
    // reads this file: Bob receives the record from the validating conductor.
    let ready_path = temp.0.join("publisher-ready.json");
    let mut moq_publisher = Node(Command::new(&moq_binary)
        .arg("publish")
        .arg("--manifest").arg(fixture_dir.join("manifest.json"))
        .arg("--store").arg(&node_dir)
        .arg("--trusted-artist-hex").arg(s(&fixture, "artist_public_hex"))
        .arg("--expected-manifest-sha256").arg(&digest)
        .arg("--cert-dir").arg(temp.0.join("moq-cert"))
        .arg("--ready-file").arg(&ready_path)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().expect("start real IETF draft-14 MoQ publisher"));
    for _ in 0..150 {
        assert!(moq_publisher.0.try_wait().expect("inspect MoQ process").is_none(),
            "MoQ publisher terminated before making its QUIC endpoint ready");
        if ready_path.is_file() { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready_path.is_file(), "MoQ publisher did not announce its local UDP endpoint");
    let readiness: Value = serde_json::from_slice(&fs::read(&ready_path).unwrap())
        .expect("publisher readiness JSON");
    assert_eq!(s(&readiness, "file_id"), file_id);
    assert_eq!(s(&readiness, "manifest_sha256"), digest);
    let endpoint = MoqEndpoint {
        schema: "holochain-storage/moq-endpoint/v1".into(),
        node_agent: bob.clone(), owner_agent: alice.clone(),
        file_id: file_id.clone(), manifest_sha256: digest.clone(),
        url: s(&readiness, "url"),
        cert_fingerprint_hex: s(&readiness, "cert_fingerprint_hex"),
    };
    // Alice may not advertise a QUIC certificate claiming to be Bob.
    let forged = conductors[ALICE]
        .call_fallible::<_, ActionHash>(
            &storage_alice, "publish_moq_endpoint", &endpoint,
        ).await;
    assert!(forged.is_err(), "integrity zome accepted cross-agent MoQ endpoint forgery");
    conductors[BOB].call::<_, ActionHash>(
        &storage_bob, "publish_moq_endpoint", &endpoint,
    ).await;
    await_consistency_s(90, storage_cells.iter()).await
        .expect("MoQ host endpoint DHT consistency");

    let admin_port = conductors[BOB].get_arbitrary_admin_websocket_port().expect("Bob admin WebSocket");
    // Sweettest roles are DNA hashes, unlike named roles in the deployed hApp.
    let catalogue_role = music_cells[BOB].cell_id().dna_hash().to_string();
    let storage_role = storage_cells[BOB].cell_id().dna_hash().to_string();
    // Only passed trusted conductor parameters: NOT readiness.url or
    // readiness.cert_fingerprint_hex. The Python client MUST read those from
    // Bob's validated, pinned storage DNA via the S6 Rust WebSocket bridge.
    let s9_script = root.join("music-e2e/tests/helpers/s9_moq_receive.py");
    let result = python_stage(&python, &s9_script, vec![
        "--root".into(), fixture_arg,
        "--node-url".into(), url,
        "--bridge-binary".into(), bridge.to_string_lossy().to_string(),
        "--moq-binary".into(), moq_binary.to_string_lossy().to_string(),
        "--admin-port".into(), admin_port.to_string(),
        "--app-id".into(), APP.into(),
        "--catalogue-dna".into(), catalogue_role.clone(),
        "--storage-dna".into(), storage_role.clone(),
        "--catalogue-role".into(), catalogue_role,
        "--storage-role".into(), storage_role,
        "--reader-agent".into(), bob.clone(),
        "--artist-agent".into(), alice.clone(),
        "--node-agent".into(), bob,
        "--track-id".into(), track_id,
    ]).await;
    assert_eq!(result["verified"], Value::Bool(true));
    assert_eq!(s(&result, "file_id"), file_id);
    assert_eq!(s(&result, "sha256"), s(&fixture, "sample_sha256"));
    assert!(result["ciphertext_chunks"].as_u64().unwrap_or(0) > 0);
    // Publisher sent all ciphertext objects through genuine QUIC/MoQT.
    for _ in 0..100 {
        if let Some(status) = moq_publisher.0.try_wait().expect("publisher exit status") {
            assert!(status.success(), "MoQ publisher failed after QUIC transfer: {status}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("MoQ publisher failed to terminate after transferring its finite signed package");
}
