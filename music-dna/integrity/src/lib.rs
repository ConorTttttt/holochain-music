//! Public music metadata, validated against the Holochain action author.
//! No file chunks, encryption keys, licences-as-secrets or full manifests.
//! Rights declarations are self-attestations, not copyright verification.

use hdi::prelude::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const ARTIST_SCHEMA: &str = "holochain-music/artist/v1";
pub const ALBUM_SCHEMA: &str = "holochain-music/album/v1";
pub const TRACK_SCHEMA: &str = "holochain-music/track/v1";
pub const ARTWORK_SCHEMA: &str = "holochain-music/artwork/v1";
const MAX_ARTWORK_BYTES: usize = 32 * 1024;

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtistProfile {
    pub schema: String,
    pub artist_agent: String,
    pub display_name: String,
    pub biography: String,
    pub artwork_manifest_sha256: Option<String>,
}

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Album {
    pub schema: String,
    pub artist_agent: String,
    /// 32 lowercase hex digits, stable across metadata revisions.
    pub album_id: String,
    pub title: String,
    /// ISO calendar date YYYY-MM-DD; optional for unreleased albums.
    pub release_date: Option<String>,
    pub artwork_manifest_sha256: Option<String>,
    #[serde(default)]
    pub artwork_sha256: Option<String>,
    #[serde(default)]
    pub genres: Vec<String>,
}

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Artwork {
    pub schema: String,
    pub artist_agent: String,
    pub mime_type: String,
    pub sha256: String,
    /// Small public cover; audio chunks and encryption keys remain off-DHT.
    pub data_base64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RightsBasis {
    OriginalOwner,
    LicensedByRightsHolder,
}

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Track {
    pub schema: String,
    pub artist_agent: String,
    /// 32 lowercase hex digits, stable across metadata revisions.
    pub track_id: String,
    pub album_id: Option<String>,
    pub title: String,
    pub duration_ms: u32,
    pub disc_number: u16,
    pub track_number: u16,
    pub audio_format: String,
    /// The random identifier in the S1 encrypted-package manifest.
    pub file_id: String,
    /// SHA-256 of the *complete signed S1 manifest*, not the audio plaintext.
    pub manifest_sha256: String,
    pub rights_basis: RightsBasis,
    #[serde(default)]
    pub artwork_sha256: Option<String>,
    #[serde(default)]
    pub genres: Vec<String>,
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    ArtistProfile(ArtistProfile),
    Album(Album),
    Track(Track),
    Artwork(Artwork),
}

#[hdk_link_types]
pub enum LinkTypes {
    AgentToProfile,
    AgentToAlbum,
    AgentToTrack,
    AllArtists,
    AllTracks,
    Anchor,
    AgentToArtwork,
}

#[hdk_extern]
pub fn genesis_self_check(_data: GenesisSelfCheckData) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

fn is_lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value.as_bytes().iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn short_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn biography_text(value: &str) -> bool {
    value.len() <= 2_048 && !value.chars().any(|c| c == '\0' || (c.is_control() && c != '\n'))
}

fn optional_manifest(value: &Option<String>) -> bool {
    value.as_ref().map_or(true, |v| is_lower_hex(v, 64))
}

fn valid_genres(genres: &[String]) -> bool {
    if genres.len() > 6 { return false; }
    let mut seen = HashSet::new();
    genres.iter().all(|g| short_text(g, 32) && seen.insert(g.to_lowercase()))
}

fn valid_artwork(a: &Artwork) -> bool {
    if a.schema != ARTWORK_SCHEMA || !is_lower_hex(&a.sha256, 64)
        || !matches!(a.mime_type.as_str(), "image/jpeg" | "image/png" | "image/webp")
        || a.data_base64.len() > ((MAX_ARTWORK_BYTES + 2) / 3) * 4 {
        return false;
    }
    let Ok(data) = STANDARD.decode(&a.data_base64) else { return false };
    if data.is_empty() || data.len() > MAX_ARTWORK_BYTES { return false; }
    let signature_ok = match a.mime_type.as_str() {
        "image/jpeg" => data.starts_with(&[0xff, 0xd8, 0xff]),
        "image/png" => data.starts_with(&[137, 80, 78, 71, 13, 10, 26, 10]),
        "image/webp" => data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP",
        _ => false,
    };
    signature_ok && format!("{:x}", Sha256::digest(&data)) == a.sha256
}

fn valid_date(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-'
        || !b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit()) {
        return false;
    }
    let (Ok(y), Ok(m), Ok(d)) = (value[..4].parse::<u32>(), value[5..7].parse::<u32>(), value[8..10].parse::<u32>())
    else { return false };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    y > 0 && d >= 1 && d <= days
}

/// Pure validation is used both by the integrity callback and by unit tests.
/// The actual `author` passed by the callback comes from the signed Holochain action.
pub fn validate_claim(author: &str, entry: &EntryTypes) -> Result<(), String> {
    match entry {
        EntryTypes::ArtistProfile(p) => {
            if p.artist_agent != author { return Err("artist profile author mismatch".into()) }
            if p.schema != ARTIST_SCHEMA || !short_text(&p.display_name, 120)
                || !biography_text(&p.biography) || !optional_manifest(&p.artwork_manifest_sha256) {
                return Err("invalid artist profile metadata".into())
            }
        }
        EntryTypes::Album(a) => {
            if a.artist_agent != author { return Err("album author mismatch".into()) }
            if a.schema != ALBUM_SCHEMA || !is_lower_hex(&a.album_id, 32)
                || !short_text(&a.title, 200) || !optional_manifest(&a.artwork_manifest_sha256)
                || !optional_manifest(&a.artwork_sha256) || !valid_genres(&a.genres)
                || !a.release_date.as_ref().map_or(true, |d| valid_date(d)) {
                return Err("invalid album metadata".into())
            }
        }
        EntryTypes::Track(t) => {
            if t.artist_agent != author { return Err("track author mismatch".into()) }
            if t.schema != TRACK_SCHEMA || !is_lower_hex(&t.track_id, 32)
                || !t.album_id.as_ref().map_or(true, |id| is_lower_hex(id, 32))
                || !short_text(&t.title, 200)
                || !(1..=86_400_000).contains(&t.duration_ms)
                || !(1..=99).contains(&t.disc_number) || !(1..=999).contains(&t.track_number)
                || !matches!(t.audio_format.as_str(), "audio/mpeg" | "audio/flac" | "audio/ogg" | "audio/mp4" | "audio/wav")
                || !is_lower_hex(&t.file_id, 64)
                || !is_lower_hex(&t.manifest_sha256, 64)
                || !optional_manifest(&t.artwork_sha256) || !valid_genres(&t.genres) {
                return Err("invalid track metadata".into())
            }
        }
        EntryTypes::Artwork(a) => {
            if a.artist_agent != author { return Err("artwork author mismatch".into()); }
            if !valid_artwork(a) { return Err("invalid public artwork".into()); }
        }
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> ValidateCallbackResult {
    ValidateCallbackResult::Invalid(reason.into())
}

/// Agent index: only the base agent can link to records they actually authored.
fn validate_agent_link(action: &TypedAction<CreateLinkData>) -> ExternResult<ValidateCallbackResult> {
    let Some(base) = action.base_address.clone().into_agent_pub_key() else {
        return Ok(invalid("agent index base must be AgentPubKey"));
    };
    if &base != action.author() {
        return Ok(invalid("cannot index a different agent's catalogue"));
    }
    validate_owned_target(action)
}

/// Public directories also require linking to an action authored by the linker.
/// The read API additionally checks the entry type and its claimed author.
fn validate_owned_target(action: &TypedAction<CreateLinkData>) -> ExternResult<ValidateCallbackResult> {
    let Some(target) = action.target_address.clone().into_action_hash() else {
        return Ok(invalid("catalogue link target must be ActionHash"));
    };
    let target_action = must_get_action(target)?;
    if target_action.action().author() != action.author() {
        return Ok(invalid("catalogue link target must belong to link author"));
    }
    Ok(ValidateCallbackResult::Valid)
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::CreateEntry(OpEntry::CreateEntry { app_entry, action }) => {
            Ok(match validate_claim(&action.author().to_string(), &app_entry) {
                Ok(()) => ValidateCallbackResult::Valid,
                Err(reason) => invalid(reason),
            })
        }
        FlatOp::CreateEntry(_) => Ok(ValidateCallbackResult::Valid),
        FlatOp::Link(OpLink::CreateLink { link_type, action }) => match link_type {
            LinkTypes::AgentToProfile | LinkTypes::AgentToAlbum | LinkTypes::AgentToTrack | LinkTypes::AgentToArtwork => {
                validate_agent_link(&action)
            }
            LinkTypes::AllArtists | LinkTypes::AllTracks => validate_owned_target(&action),
            LinkTypes::Anchor => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Link(OpLink::DeleteLink { .. }) => Ok(invalid("catalogue indexes are append-only")),
        FlatOp::Update(_) => Ok(invalid("catalogue updates must publish a new version")),
        FlatOp::Delete(_) => Ok(invalid("catalogue metadata cannot be deleted in v1")),
        FlatOp::CreateRecord(_) | FlatOp::AgentActivity(_) => Ok(ValidateCallbackResult::Valid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ArtistProfile {
        ArtistProfile { schema: ARTIST_SCHEMA.into(), artist_agent: "alice".into(), display_name: "Alice".into(), biography: String::new(), artwork_manifest_sha256: None }
    }
    fn album() -> Album {
        Album { schema: ALBUM_SCHEMA.into(), artist_agent: "alice".into(), album_id: "a".repeat(32), title: "Album".into(), release_date: Some("2024-02-29".into()), artwork_manifest_sha256: None, artwork_sha256: None, genres: vec![] }
    }
    fn track() -> Track {
        Track { schema: TRACK_SCHEMA.into(), artist_agent: "alice".into(), track_id: "a".repeat(32), album_id: Some("a".repeat(32)), title: "Song".into(), duration_ms: 120_000, disc_number: 1, track_number: 1, audio_format: "audio/flac".into(), file_id: "b".repeat(64), manifest_sha256: "c".repeat(64), rights_basis: RightsBasis::OriginalOwner, artwork_sha256: None, genres: vec![] }
    }
    #[test]
    fn valid_artist_album_and_track() {
        assert!(validate_claim("alice", &EntryTypes::ArtistProfile(profile())).is_ok());
        assert!(validate_claim("alice", &EntryTypes::Album(album())).is_ok());
        assert!(validate_claim("alice", &EntryTypes::Track(track())).is_ok());
    }
    #[test]
    fn rejects_cross_agent_publication() {
        assert!(validate_claim("bob", &EntryTypes::ArtistProfile(profile())).is_err());
        assert!(validate_claim("bob", &EntryTypes::Album(album())).is_err());
        assert!(validate_claim("bob", &EntryTypes::Track(track())).is_err());
    }
    #[test]
    fn bad_album_date_is_rejected() {
        let mut a = album(); a.release_date = Some("2025-02-29".into());
        assert!(validate_claim("alice", &EntryTypes::Album(a)).is_err());
        let mut a = album(); a.release_date = Some("2024-02-29".into());
        assert!(validate_claim("alice", &EntryTypes::Album(a)).is_ok());
    }
    #[test]
    fn malformed_track_hash_and_ids_fail() {
        let mut t = track(); t.file_id = "A".repeat(64);
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
        let mut t = track(); t.track_id = "wrong".into();
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
        let mut t = track(); t.album_id = Some("!".repeat(32));
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
    }
    #[test]
    fn malformed_profile_is_rejected() {
        let mut p = profile(); p.display_name = "  ".into();
        assert!(validate_claim("alice", &EntryTypes::ArtistProfile(p)).is_err());
        let mut p = profile(); p.biography = "a".repeat(2049);
        assert!(validate_claim("alice", &EntryTypes::ArtistProfile(p)).is_err());
    }
    #[test]
    fn rejects_invalid_genres_and_artwork_metadata() {
        let mut t = track();
        t.genres = vec!["Ambient".into(), "ambient".into()];
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
        let mut t = track();
        t.genres = vec!["Rock".into(), "Jazz".into()];
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_ok());
        let mut a = album(); a.artwork_sha256 = Some("bad".into());
        assert!(validate_claim("alice", &EntryTypes::Album(a)).is_err());
        let bytes = b"RIFF1234WEBPpublic-test";
        let art = Artwork { schema: ARTWORK_SCHEMA.into(), artist_agent: "alice".into(),
            mime_type: "image/webp".into(), sha256: format!("{:x}", Sha256::digest(bytes)),
            data_base64: STANDARD.encode(bytes) };
        assert!(validate_claim("alice", &EntryTypes::Artwork(art.clone())).is_ok());
        let mut bad = art.clone(); bad.data_base64 = STANDARD.encode(b"RIFF1234WEBPmutated");
        assert!(validate_claim("alice", &EntryTypes::Artwork(bad)).is_err());
        assert!(validate_claim("bob", &EntryTypes::Artwork(art)).is_err());
    }
    #[test]
    fn impossible_media_metadata_is_rejected() {
        let mut t = track(); t.duration_ms = 0;
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
        let mut t = track(); t.audio_format = "application/zip".into();
        assert!(validate_claim("alice", &EntryTypes::Track(t)).is_err());
    }
}
