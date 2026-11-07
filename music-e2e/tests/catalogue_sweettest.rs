//! Real Holochain 0.7 conductor integration tests. No mocked DHT or fake
//! authorship: each cell is a distinct signed agent on an independent
//! SweetConductor, using the actual packed catalogue DNA.
//!
//! A native test crate intentionally avoids importing the Wasm zome crates.
//! Wire mirrors below must match the existing hdk/serde entry schemas.

use holo_hash::{ActionHash, AgentPubKey};
use holochain::sweettest::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const ZOME: &str = "music_catalogue";
const ARTIST_SCHEMA: &str = "holochain-music/artist/v1";
const ALBUM_SCHEMA: &str = "holochain-music/album/v1";
const TRACK_SCHEMA: &str = "holochain-music/track/v1";
const ALICE: usize = 0;
const BOB: usize = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ArtistProfile {
    schema: String,
    artist_agent: String,
    display_name: String,
    biography: String,
    artwork_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Album {
    schema: String,
    artist_agent: String,
    album_id: String,
    title: String,
    release_date: Option<String>,
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

#[derive(Debug, Deserialize)]
struct AuthoredRecord<T> {
    author: String,
    action_hash: ActionHash,
    body: T,
}

#[derive(Debug, Serialize)]
struct AlbumLookup {
    artist: AgentPubKey,
    album_id: String,
}

#[derive(Debug, Serialize)]
struct TrackLookup {
    artist: AgentPubKey,
    track_id: String,
}

#[derive(Debug, Serialize)]
struct SearchInput {
    query: String,
    limit: u8,
}

fn dna_path() -> PathBuf {
    let path = std::env::var_os("MUSIC_CATALOGUE_DNA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../music-dna/workdir/music_catalogue.dna")
        });
    assert!(
        path.is_file(),
        "missing packed DNA at {}: build the Wasm zomes and run `hc dna pack workdir` from music-dna first",
        path.display()
    );
    path
}

struct Network {
    conductors: SweetConductorBatch,
    cells: Vec<SweetCell>,
}

impl Network {
    fn agent(&self, i: usize) -> AgentPubKey {
        self.cells[i].agent_pubkey().clone()
    }

    fn zome(&self, i: usize) -> SweetZome {
        self.cells[i].zome(ZOME)
    }

    async fn settle(&self) {
        // Essential: do not mistake a missing gossip delay for a broken read.
        await_consistency_s(60, self.cells.iter()).await.unwrap();
    }
}

async fn network() -> Network {
    let dna = SweetDnaFile::from_bundle(&dna_path()).await.unwrap();
    let mut conductors = SweetConductorBatch::standard(2).await;
    let apps = conductors
        .setup_app("music-catalogue-e2e", &[dna])
        .await
        .unwrap();
    let cells = apps
        .into_inner()
        .into_iter()
        .map(|app| app.into_cells().into_iter().next().expect("one catalogue cell per agent"))
        .collect();
    conductors.exchange_peer_info().await;
    Network { conductors, cells }
}

fn profile(agent: &AgentPubKey) -> ArtistProfile {
    ArtistProfile {
        schema: ARTIST_SCHEMA.into(),
        artist_agent: agent.to_string(),
        display_name: "Alice Music".into(),
        biography: "Independent artist".into(),
        artwork_manifest_sha256: None,
    }
}

fn album(agent: &AgentPubKey) -> Album {
    Album {
        schema: ALBUM_SCHEMA.into(),
        artist_agent: agent.to_string(),
        album_id: "a".repeat(32),
        title: "Debut Album".into(),
        release_date: Some("2026-11-05".into()),
        artwork_manifest_sha256: None,
    }
}

fn track(agent: &AgentPubKey) -> Track {
    Track {
        schema: TRACK_SCHEMA.into(),
        artist_agent: agent.to_string(),
        track_id: "b".repeat(32),
        album_id: Some("a".repeat(32)),
        title: "First Single".into(),
        duration_ms: 185_000,
        disc_number: 1,
        track_number: 1,
        audio_format: "audio/flac".into(),
        file_id: "c".repeat(64),
        manifest_sha256: "d".repeat(64),
        rights_basis: RightsBasis::OriginalOwner,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn alice_publishes_bob_discovers_and_revision_reaches_bob() {
    let net = network().await;
    let alice = net.agent(ALICE);
    let p = profile(&alice);
    let a = album(&alice);
    let t = track(&alice);

    let profile_hash: ActionHash = net.conductors[ALICE]
        .call(&net.zome(ALICE), "publish_artist_profile", &p)
        .await;
    let album_hash: ActionHash = net.conductors[ALICE]
        .call(&net.zome(ALICE), "publish_album", &a)
        .await;
    let track_hash: ActionHash = net.conductors[ALICE]
        .call(&net.zome(ALICE), "publish_track", &t)
        .await;
    assert_ne!(profile_hash, album_hash);
    assert_ne!(album_hash, track_hash);
    net.settle().await;

    // All reads are on BOB's separate conductor, *not* Alice's own DHT.
    let found: Option<AuthoredRecord<ArtistProfile>> = net.conductors[BOB]
        .call(&net.zome(BOB), "get_artist_profile", alice.clone())
        .await;
    let found = found.expect("Bob discovers Alice's profile");
    assert_eq!(found.author, alice.to_string());
    assert_eq!(found.action_hash, profile_hash);
    assert_eq!(found.body, p);

    let artists: Vec<AuthoredRecord<ArtistProfile>> = net.conductors[BOB]
        .call(&net.zome(BOB), "list_artists", ())
        .await;
    assert_eq!(artists.len(), 1);
    assert_eq!(artists[0].body, p);

    let found_album: Option<AuthoredRecord<Album>> = net.conductors[BOB]
        .call(&net.zome(BOB), "get_album", AlbumLookup { artist: alice.clone(), album_id: a.album_id.clone() })
        .await;
    let found_album = found_album.expect("Bob discovers Alice's album");
    assert_eq!(found_album.author, alice.to_string());
    assert_eq!(found_album.action_hash, album_hash);
    assert_eq!(found_album.body, a);

    let albums: Vec<AuthoredRecord<Album>> = net.conductors[BOB]
        .call(&net.zome(BOB), "list_albums", alice.clone())
        .await;
    assert_eq!(albums.len(), 1);
    assert_eq!(albums[0].body, a);

    let found_track: Option<AuthoredRecord<Track>> = net.conductors[BOB]
        .call(&net.zome(BOB), "get_track", TrackLookup { artist: alice.clone(), track_id: t.track_id.clone() })
        .await;
    let found_track = found_track.expect("Bob discovers Alice's track");
    assert_eq!(found_track.author, alice.to_string());
    assert_eq!(found_track.action_hash, track_hash);
    assert_eq!(found_track.body, t);
    // Bob receives only an opaque S1 file identifier and signed-manifest hash.
    assert_eq!(found_track.body.file_id.len(), 64);
    assert_eq!(found_track.body.manifest_sha256.len(), 64);

    let tracks: Vec<AuthoredRecord<Track>> = net.conductors[BOB]
        .call(&net.zome(BOB), "list_album_tracks", AlbumLookup { artist: alice.clone(), album_id: a.album_id.clone() })
        .await;
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].body, t);

    let hits: Vec<AuthoredRecord<Track>> = net.conductors[BOB]
        .call(&net.zome(BOB), "search_tracks", SearchInput { query: "FIRST".into(), limit: 10 })
        .await;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].body, t);

    // An append-only metadata revision must replace the visible version for Bob.
    let mut revised = t.clone();
    revised.title = "First Single (Remastered)".into();
    net.conductors[ALICE]
        .call::<_, ActionHash>(&net.zome(ALICE), "publish_track", &revised)
        .await;
    net.settle().await;

    let newest: Option<AuthoredRecord<Track>> = net.conductors[BOB]
        .call(&net.zome(BOB), "get_track", TrackLookup { artist: alice, track_id: t.track_id.clone() })
        .await;
    assert_eq!(newest.expect("Bob sees the revision").body, revised);
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_authorship_and_malformed_entries_fail_on_real_conductor() {
    let net = network().await;
    let alice = net.agent(ALICE);
    let bob = net.agent(BOB);

    // Bob may NOT create entries that claim Alice's identity, even when the
    // request is otherwise structurally valid. These exercise Holochain's
    // signed action + integrity validation, not a local helper function.
    let forged_profile = profile(&alice);
    let profile_result: Result<ActionHash, _> = net.conductors[BOB]
        .call_fallible(&net.zome(BOB), "publish_artist_profile", &forged_profile)
        .await;
    assert!(profile_result.is_err(), "conductor accepted forged artist profile");

    let forged_album = album(&alice);
    let album_result: Result<ActionHash, _> = net.conductors[BOB]
        .call_fallible(&net.zome(BOB), "publish_album", &forged_album)
        .await;
    assert!(album_result.is_err(), "conductor accepted forged album");

    // A valid Bob-owned entry with an illegal format is also rejected by the
    // integrity callback, not merely by an application UI form.
    let mut malformed = track(&bob);
    malformed.album_id = None;
    malformed.manifest_sha256 = "NOT-A-SHA256".into();
    let malformed_result: Result<ActionHash, _> = net.conductors[BOB]
        .call_fallible(&net.zome(BOB), "publish_track", &malformed)
        .await;
    assert!(malformed_result.is_err(), "conductor accepted malformed track");

    net.settle().await;
    let artists: Vec<AuthoredRecord<ArtistProfile>> = net.conductors[ALICE]
        .call(&net.zome(ALICE), "list_artists", ())
        .await;
    assert!(artists.is_empty(), "forged artist entry became discoverable");
    let albums: Vec<AuthoredRecord<Album>> = net.conductors[ALICE]
        .call(&net.zome(ALICE), "list_albums", alice)
        .await;
    assert!(albums.is_empty(), "forged album became discoverable");
}
