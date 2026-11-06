//! Catalogue zome for artist-authored metadata only. Media bytes and private
//! keys never cross this API. Every entry is attributed to its Holochain
//! action author by the integrity zome, not by a caller-supplied field.

use hdk::prelude::*;
use music_catalogue_integrity::{Album, ArtistProfile, Artwork, EntryTypes, LinkTypes, Track};
use std::collections::HashSet;

const ARTISTS_PATH: &str = "catalogue.artists.v1";
const TRACKS_PATH: &str = "catalogue.tracks.v1";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoredRecord<T> {
    pub author: String,
    pub action_hash: ActionHash,
    pub body: T,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlbumLookup {
    pub artist: AgentPubKey,
    pub album_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TrackLookup {
    pub artist: AgentPubKey,
    pub track_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArtworkLookup {
    pub artist: AgentPubKey,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SearchInput {
    pub query: String,
    pub limit: u8,
}

fn typed_path(value: &str) -> ExternResult<TypedPath> {
    Path::from(value).typed(LinkTypes::Anchor)
}

fn lookup_links(base: impl Into<AnyLinkableHash>, lt: LinkTypes) -> ExternResult<Vec<Link>> {
    let mut links = get_links(LinkQuery::try_new(base, lt)?, GetStrategy::default())?;
    links.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(links)
}

fn linked_records<T>(base: impl Into<AnyLinkableHash>, lt: LinkTypes) -> ExternResult<Vec<AuthoredRecord<T>>>
where
    T: TryFrom<SerializedBytes, Error = SerializedBytesError>,
{
    let mut rows = Vec::new();
    for link in lookup_links(base, lt)? {
        let Some(hash) = link.target.into_action_hash() else { continue };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue };
        // Ignore wrong entry shapes rather than letting a malicious index poison
        // discovery. Holochain's validator still enforces allowed writes.
        let Ok(Some(body)) = record.entry().to_app_option::<T>() else { continue };
        rows.push(AuthoredRecord {
            author: record.action().author().to_string(),
            action_hash: hash,
            body,
        });
    }
    Ok(rows)
}

/// Profile revisions are append-only; newest authored version wins.
#[hdk_extern]
pub fn publish_artist_profile(profile: ArtistProfile) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    let all = typed_path(ARTISTS_PATH)?;
    all.ensure()?;
    let hash = create_entry(EntryTypes::ArtistProfile(profile))?;
    create_link(me, hash.clone(), LinkTypes::AgentToProfile, ())?;
    create_link(all.path_entry_hash()?, hash.clone(), LinkTypes::AllArtists, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_artist_profile(artist: AgentPubKey) -> ExternResult<Option<AuthoredRecord<ArtistProfile>>> {
    let expected = artist.to_string();
    Ok(linked_records::<ArtistProfile>(artist, LinkTypes::AgentToProfile)?
        .into_iter().find(|r| r.author == expected && r.body.artist_agent == expected))
}

/// Browse public artist profiles (a small-scale directory, not scalable search).
#[hdk_extern]
pub fn list_artists(_: ()) -> ExternResult<Vec<AuthoredRecord<ArtistProfile>>> {
    let base = typed_path(ARTISTS_PATH)?.path_entry_hash()?;
    let mut seen = HashSet::new();
    Ok(linked_records::<ArtistProfile>(base, LinkTypes::AllArtists)?
        .into_iter()
        .filter(|r| r.body.artist_agent == r.author && seen.insert(r.author.clone()))
        .collect())
}

/// Album IDs are stable per artist; later versions can correct metadata.
#[hdk_extern]
pub fn publish_album(album: Album) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::Album(album))?;
    create_link(me, hash.clone(), LinkTypes::AgentToAlbum, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn list_albums(artist: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<Album>>> {
    let expected = artist.to_string();
    let mut seen = HashSet::new();
    Ok(linked_records::<Album>(artist, LinkTypes::AgentToAlbum)?
        .into_iter()
        .filter(|r| r.author == expected && r.body.artist_agent == expected && seen.insert(r.body.album_id.clone()))
        .collect())
}

#[hdk_extern]
pub fn get_album(input: AlbumLookup) -> ExternResult<Option<AuthoredRecord<Album>>> {
    Ok(list_albums(input.artist)?.into_iter().find(|r| r.body.album_id == input.album_id))
}

/// Covers are small PUBLIC entries, separate from encrypted audio.
#[hdk_extern]
pub fn publish_artwork(artwork: Artwork) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    if artwork.artist_agent != me.to_string() {
        return Err(wasm_error!(WasmErrorInner::Guest("only an artist can publish their artwork".into())));
    }
    let hash = create_entry(EntryTypes::Artwork(artwork))?;
    create_link(me, hash.clone(), LinkTypes::AgentToArtwork, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_artwork(input: ArtworkLookup) -> ExternResult<Option<AuthoredRecord<Artwork>>> {
    let expected = input.artist.to_string();
    Ok(linked_records::<Artwork>(input.artist, LinkTypes::AgentToArtwork)?.into_iter()
        .find(|r| r.author == expected && r.body.artist_agent == expected && r.body.sha256 == input.sha256))
}

/// Tracks only reference a signed *encrypted package digest* and random file ID.
/// No plaintext or secret keys are included. The coordinator checks album
/// existence as a usability guard; this cross-entry check is not enforced
/// by the deterministic integrity validation and is not a legal rights check.
#[hdk_extern]
pub fn publish_track(track: Track) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    if track.artist_agent != me.to_string() {
        return Err(wasm_error!(WasmErrorInner::Guest("only the artist can publish tracks".into())));
    }
    if let Some(album_id) = track.album_id.as_ref() {
        if get_album(AlbumLookup { artist: me.clone(), album_id: album_id.clone() })?.is_none() {
            return Err(wasm_error!(WasmErrorInner::Guest("album must be published by the same artist first".into())));
        }
    }
    // Metadata revisions must never silently swap the encrypted file or audio
    // licence binding behind a stable track ID.
    if let Some(previous) = get_track(TrackLookup { artist: me.clone(), track_id: track.track_id.clone() })? {
        let old = previous.body;
        if old.file_id != track.file_id || old.manifest_sha256 != track.manifest_sha256
            || old.duration_ms != track.duration_ms || old.audio_format != track.audio_format
            || old.rights_basis != track.rights_basis {
            return Err(wasm_error!(WasmErrorInner::Guest("track audio/rights are immutable across metadata revisions".into())));
        }
    }
    let all = typed_path(TRACKS_PATH)?;
    all.ensure()?;
    let hash = create_entry(EntryTypes::Track(track))?;
    create_link(me, hash.clone(), LinkTypes::AgentToTrack, ())?;
    create_link(all.path_entry_hash()?, hash.clone(), LinkTypes::AllTracks, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn list_tracks(artist: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<Track>>> {
    let expected = artist.to_string();
    let mut seen = HashSet::new();
    Ok(linked_records::<Track>(artist, LinkTypes::AgentToTrack)?
        .into_iter()
        .filter(|r| r.author == expected && r.body.artist_agent == expected && seen.insert(r.body.track_id.clone()))
        .collect())
}

#[hdk_extern]
pub fn get_track(input: TrackLookup) -> ExternResult<Option<AuthoredRecord<Track>>> {
    Ok(list_tracks(input.artist)?.into_iter().find(|r| r.body.track_id == input.track_id))
}

#[hdk_extern]
pub fn list_album_tracks(input: AlbumLookup) -> ExternResult<Vec<AuthoredRecord<Track>>> {
    let id = input.album_id;
    Ok(list_tracks(input.artist)?.into_iter().filter(|r| r.body.album_id.as_deref() == Some(id.as_str())).collect())
}

/// MVP discovery: case-insensitive track-title search on the global public
/// index, with bounded output. Not suitable for a large-scale search service:
/// `get_links` still scans the full DHT index; indexing/sharding is future work.
#[hdk_extern]
pub fn search_tracks(input: SearchInput) -> ExternResult<Vec<AuthoredRecord<Track>>> {
    let needle = input.query.trim().to_lowercase();
    if needle.len() < 2 || needle.len() > 80 || input.limit == 0 || input.limit > 50 {
        return Err(wasm_error!(WasmErrorInner::Guest("invalid search query or limit".into())));
    }
    let base = typed_path(TRACKS_PATH)?.path_entry_hash()?;
    let mut seen = HashSet::new();
    Ok(linked_records::<Track>(base, LinkTypes::AllTracks)?
        .into_iter()
        .filter(|r| r.author == r.body.artist_agent
            && seen.insert((r.author.clone(), r.body.track_id.clone()))
            && (r.body.title.to_lowercase().contains(&needle)
                || r.body.genres.iter().any(|g| g.to_lowercase().contains(&needle))))
        .take(input.limit as usize)
        .collect())
}

/// Newest published tracks across all artists for the app's browse view.
/// Bounded output; the same small-scale index caveat as `search_tracks`.
#[hdk_extern]
pub fn browse_tracks(limit: u8) -> ExternResult<Vec<AuthoredRecord<Track>>> {
    if limit == 0 || limit > 100 {
        return Err(wasm_error!(WasmErrorInner::Guest("invalid browse limit".into())));
    }
    let base = typed_path(TRACKS_PATH)?.path_entry_hash()?;
    let mut seen = HashSet::new();
    Ok(linked_records::<Track>(base, LinkTypes::AllTracks)?
        .into_iter()
        .filter(|r| r.author == r.body.artist_agent
            && seen.insert((r.author.clone(), r.body.track_id.clone())))
        .take(limit as usize)
        .collect())
}
