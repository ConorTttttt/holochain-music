//! Two distinct Holochain 0.7 DNAs on each of two real Sweettest conductors.
//! Validates shared agent identity and DHT gossip for S5 catalogue and S2
//! storage-signing identity. Cryptographic manifest/receipt and S4 ciphertext
//! exchange are covered by the Python verified-download suite separately.

use holo_hash::{ActionHash, AgentPubKey};
use holochain::sweettest::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const ALICE: usize = 0;
const BOB: usize = 1;
const CATALOGUE: &str = "music_catalogue";
const STORAGE: &str = "music_storage";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ArtistProfile {
    schema: String,
    artist_agent: String,
    display_name: String,
    biography: String,
    artwork_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RightsBasis {
    OriginalOwner,
    LicensedByRightsHolder,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct SigningKeyBinding {
    schema: String,
    agent: String,
    purpose: String,
    signing_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct FileCommitment {
    schema: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ReplicaClaim {
    schema: String,
    node_agent: String,
    owner_agent: String,
    file_id: String,
    manifest_sha256: String,
    receipt_sha256: String,
}

#[derive(Debug, Deserialize)]
struct AuthoredRecord<T> {
    author: String,
    action_hash: ActionHash,
    body: T,
}

#[derive(Debug, Serialize)]
struct TrackLookup {
    artist: AgentPubKey,
    track_id: String,
}

#[derive(Debug, Serialize)]
struct FileLookup {
    owner_agent: String,
    file_id: String,
}

fn bundle(relative: &str, override_key: &str) -> PathBuf {
    let path = std::env::var_os(override_key)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative));
    assert!(path.is_file(), "missing DNA bundle {}: build and `hc dna pack workdir` first", path.display());
    path
}

struct Network {
    conductors: SweetConductorBatch,
    catalogue_cells: Vec<SweetCell>,
    storage_cells: Vec<SweetCell>,
}

impl Network {
    fn agent(&self, i: usize) -> AgentPubKey {
        self.catalogue_cells[i].agent_pubkey().clone()
    }
    fn music(&self, i: usize) -> SweetZome { self.catalogue_cells[i].zome(CATALOGUE) }
    fn storage(&self, i: usize) -> SweetZome { self.storage_cells[i].zome(STORAGE) }
    async fn settle(&self) {
        await_consistency_s(90, self.catalogue_cells.iter()).await.unwrap();
        await_consistency_s(90, self.storage_cells.iter()).await.unwrap();
    }
}

async fn network() -> Network {
    let music = SweetDnaFile::from_bundle(&bundle("../music-dna/workdir/music_catalogue.dna", "MUSIC_CATALOGUE_DNA"))
        .await.unwrap();
    let storage = SweetDnaFile::from_bundle(&bundle("../dna/workdir/music_storage.dna", "MUSIC_STORAGE_DNA"))
        .await.unwrap();
    let mut conductors = SweetConductorBatch::standard(2).await;
    // One hApp with both DNA roles per agent. Installing independent hApps
    // could create different agent keys and invalidate identity checks.
    let apps = conductors.setup_app("catalogue-storage-integration", &[music, storage]).await.unwrap();
    let mut catalogue_cells = Vec::new();
    let mut storage_cells = Vec::new();
    for app in apps.into_inner() {
        let mut cells = app.into_cells().into_iter();
        catalogue_cells.push(cells.next().expect("catalogue role"));
        storage_cells.push(cells.next().expect("storage identity role"));
        assert!(cells.next().is_none(), "only two DNA roles expected");
    }
    for i in [ALICE, BOB] {
        assert_eq!(catalogue_cells[i].agent_pubkey(), storage_cells[i].agent_pubkey(),
            "both DNA roles must have one agent identity");
    }
    conductors.exchange_peer_info().await;
    Network { conductors, catalogue_cells, storage_cells }
}

#[tokio::test(flavor = "multi_thread")]
async fn bob_discovers_catalogue_and_matching_owner_storage_identity() {
    let net = network().await;
    let alice = net.agent(ALICE);
    let bob = net.agent(BOB);
    let owner = alice.to_string();
    let host = bob.to_string();
    let file_id = "a".repeat(64);
    let digest = "b".repeat(64);
    // Public key and hashes are deterministic metadata fixtures. The S1/S4
    // integration test, not this Holochain-only test, validates signatures.
    let profile = ArtistProfile {
        schema: "holochain-music/artist/v1".into(), artist_agent: owner.clone(),
        display_name: "Alice".into(), biography: String::new(), artwork_manifest_sha256: None,
    };
    let track = Track {
        schema: "holochain-music/track/v1".into(), artist_agent: owner.clone(),
        track_id: "c".repeat(32), album_id: None, title: "Network Song".into(),
        duration_ms: 120_000, disc_number: 1, track_number: 1,
        audio_format: "audio/flac".into(), file_id: file_id.clone(),
        manifest_sha256: digest.clone(), rights_basis: RightsBasis::OriginalOwner,
    };
    let key = SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(), agent: owner.clone(),
        purpose: "owner-manifest".into(), signing_key_hex: "1".repeat(64),
    };
    let commitment = FileCommitment {
        schema: "holochain-storage/file-commitment/v1".into(),
        owner_agent: owner.clone(), file_id: file_id.clone(), manifest_sha256: digest.clone(),
    };
    let key_hash: ActionHash = net.conductors[ALICE].call(&net.storage(ALICE), "register_signing_key", &key).await;
    let commitment_hash: ActionHash = net.conductors[ALICE].call(&net.storage(ALICE), "publish_file_commitment", &commitment).await;
    net.conductors[ALICE].call::<_, ActionHash>(&net.music(ALICE), "publish_artist_profile", &profile).await;
    net.conductors[ALICE].call::<_, ActionHash>(&net.music(ALICE), "publish_track", &track).await;

    // Bob independently publishes an S2 host public key and receipt claim.
    let node_key = SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(), agent: host.clone(),
        purpose: "host-receipt".into(), signing_key_hex: "2".repeat(64),
    };
    let node_claim = ReplicaClaim {
        schema: "holochain-storage/replica-claim/v1".into(),
        node_agent: host.clone(), owner_agent: owner.clone(),
        file_id: file_id.clone(), manifest_sha256: digest.clone(),
        receipt_sha256: "3".repeat(64),
    };
    net.conductors[BOB].call::<_, ActionHash>(&net.storage(BOB), "register_signing_key", &node_key).await;
    net.conductors[BOB].call::<_, ActionHash>(&net.storage(BOB), "publish_replica_claim", &node_claim).await;
    net.settle().await;

    let profiles: Vec<AuthoredRecord<ArtistProfile>> = net.conductors[BOB]
        .call(&net.music(BOB), "list_artists", ()).await;
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].author, owner);
    assert_eq!(profiles[0].body, profile);
    let fetched: Option<AuthoredRecord<Track>> = net.conductors[BOB]
        .call(&net.music(BOB), "get_track", TrackLookup { artist: alice.clone(), track_id: track.track_id.clone() }).await;
    let fetched = fetched.expect("Bob must discover Alice's catalogue track");
    assert_eq!(fetched.author, owner);
    assert_eq!(fetched.body, track);

    let bindings: Vec<AuthoredRecord<SigningKeyBinding>> = net.conductors[BOB]
        .call(&net.storage(BOB), "get_signing_keys", alice.clone()).await;
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].author, owner);
    assert_eq!(bindings[0].action_hash, key_hash);
    assert_eq!(bindings[0].body, key);
    let commitments: Vec<AuthoredRecord<FileCommitment>> = net.conductors[BOB]
        .call(&net.storage(BOB), "get_file_commitments", alice.clone()).await;
    assert_eq!(commitments.len(), 1);
    assert_eq!(commitments[0].action_hash, commitment_hash);
    assert_eq!(commitments[0].author, owner);
    assert_eq!(commitments[0].body, commitment);
    assert_eq!(fetched.body.file_id, commitments[0].body.file_id);
    assert_eq!(fetched.body.manifest_sha256, commitments[0].body.manifest_sha256);

    let nodes: Vec<AuthoredRecord<ReplicaClaim>> = net.conductors[ALICE]
        .call(&net.storage(ALICE), "get_replica_claims",
              FileLookup { owner_agent: owner.clone(), file_id: file_id.clone() }).await;
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].author, host);
    assert_eq!(nodes[0].body, node_claim);
    // S6: exercise the *real* Rust Holochain 0.7 admin/app WebSocket client,
    // not merely the SweetConductorHandle shortcut used by the rest of this test.
    // Sweettest's default role names are the DNA hashes; production hApps use
    // the role names declared in `integration/workdir/happ.yaml`.
    let port = net.conductors[BOB]
        .get_arbitrary_admin_websocket_port()
        .expect("Bob's admin WebSocket port");
    let music_role = net.catalogue_cells[BOB].cell_id().dna_hash().to_string();
    let storage_role = net.storage_cells[BOB].cell_id().dna_hash().to_string();
    let mut bridge_args = vec![
        "--admin".to_string(), format!("127.0.0.1:{port}"),
        "--app-id".into(), "catalogue-storage-integration".into(),
        "--catalogue-role".into(), music_role.clone(),
        "--storage-role".into(), storage_role.clone(),
        "--expect-catalogue-dna".into(), music_role.clone(),
        "--expect-storage-dna".into(), storage_role.clone(),
        "--artist".into(), alice.to_string(),
        "--node".into(), bob.to_string(),
        "--track-id".into(), track.track_id.clone(),
    ];
    let bridge_binary = env!("CARGO_BIN_EXE_music_conductor_bridge");
    let positive = tokio::task::spawn_blocking({
        let args = bridge_args.clone();
        move || std::process::Command::new(bridge_binary).args(&args).output().expect("start local bridge")
    }).await.unwrap();
    assert!(positive.status.success(), "bridge stderr: {}", String::from_utf8_lossy(&positive.stderr));
    let ipc: serde_json::Value = serde_json::from_slice(&positive.stdout).expect("typed bridge JSON");
    assert_eq!(ipc["schema"], "holochain-music/conductor-read/v1");
    assert_eq!(ipc["app_id"], "catalogue-storage-integration");
    assert_eq!(ipc["reader_agent"], bob.to_string());
    assert_eq!(ipc["catalogue_dna"], music_role);
    assert_eq!(ipc["storage_dna"], storage_role);
    assert_eq!(ipc["track"]["author"], alice.to_string());
    assert_eq!(ipc["track"]["body"]["file_id"], file_id);
    assert_eq!(ipc["owner_key_binding"]["author"], alice.to_string());
    assert_eq!(ipc["owner_commitment"]["body"]["manifest_sha256"], digest);
    assert_eq!(ipc["node_key_binding"]["author"], bob.to_string());
    assert_eq!(ipc["replica_claim"]["author"], bob.to_string());

    // A conductor returning the correct data for the wrong DNA MUST NOT
    // be accepted. This verifies that the trust boundary uses DNA pins.
    let pin_position = bridge_args.iter().position(|a| a == "--expect-catalogue-dna").unwrap() + 1;
    bridge_args[pin_position] = "incorrect-dna-hash".into();
    let negative = tokio::task::spawn_blocking(move ||
        std::process::Command::new(bridge_binary).args(&bridge_args).output().expect("start bridge with bad pin")
    ).await.unwrap();
    assert!(!negative.status.success(), "bridge accepted a non-matching catalogue DNA pin");
}

#[tokio::test(flavor = "multi_thread")]
async fn storage_identity_rejects_cross_agent_forgery_on_real_conductors() {
    let net = network().await;
    let alice = net.agent(ALICE);
    let bob = net.agent(BOB);
    let forged_key = SigningKeyBinding {
        schema: "holochain-storage/key-binding/v1".into(),
        agent: alice.to_string(), purpose: "owner-manifest".into(),
        signing_key_hex: "1".repeat(64),
    };
    let result: Result<ActionHash, _> = net.conductors[BOB]
        .call_fallible(&net.storage(BOB), "register_signing_key", &forged_key).await;
    assert!(result.is_err(), "Bob successfully registered a key pretending to be Alice");
    let forged_commitment = FileCommitment {
        schema: "holochain-storage/file-commitment/v1".into(),
        owner_agent: alice.to_string(), file_id: "a".repeat(64),
        manifest_sha256: "b".repeat(64),
    };
    let result: Result<ActionHash, _> = net.conductors[BOB]
        .call_fallible(&net.storage(BOB), "publish_file_commitment", &forged_commitment).await;
    assert!(result.is_err(), "Bob successfully forged Alice's file commitment");
    net.settle().await;
    let claimed: Vec<AuthoredRecord<FileCommitment>> = net.conductors[ALICE]
        .call(&net.storage(ALICE), "get_file_commitments", alice.clone()).await;
    assert!(claimed.is_empty());
    let keys: Vec<AuthoredRecord<SigningKeyBinding>> = net.conductors[ALICE]
        .call(&net.storage(ALICE), "get_signing_keys", bob).await;
    assert!(keys.is_empty());
}
