//! S8 media transport contract. No DHT calls, secret content keys or plaintext.
//! A *trusted, signed S1 manifest* pins the order, lengths and SHA-256 of every
//! AES-GCM ciphertext chunk carried as one MoQ object. Real MoQ is in main.rs.
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, io::Read, path::{Path, PathBuf}};

pub const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHUNKS: usize = 16_384;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub index: usize,
    pub sha256: String,
    pub cipher_bytes: usize,
    pub plain_bytes: usize,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ManifestBody {
    pub schema: String,
    pub file_id: String,
    pub cipher: String,
    pub chunk_size: usize,
    pub total_plain_bytes: u64,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Clone)]
pub struct PinnedManifest {
    pub body: ManifestBody,
    pub digest: String,
}

fn sha256(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `trusted_artist_hex` and `expected_digest` are explicit independent pins,
/// NOT values learned from the untrusted manifest. The S6/S7 bridge should
/// eventually supply them from Bob's validated local conductor.
pub fn load_manifest(path: &Path, trusted_artist_hex: &str, expected_digest: &str) -> Result<PinnedManifest> {
    ensure!(valid_hash(trusted_artist_hex) && valid_hash(expected_digest), "invalid key/digest pin");
    let bytes = fs::read(path).with_context(|| format!("reading manifest {}", path.display()))?;
    ensure!(bytes.len() <= MAX_MANIFEST_BYTES, "manifest too large");
    let value: Value = serde_json::from_slice(&bytes).context("invalid signed manifest JSON")?;
    let outer = value.as_object().ok_or_else(|| anyhow!("signed manifest must be an object"))?;
    ensure!(outer.len() == 3 && outer.contains_key("body") && outer.contains_key("signer")
        && outer.contains_key("signature"), "unexpected signed-manifest fields");
    // serde_json::Map is sorted by key (no preserve_order feature), matching
    // the S1 Python canonical JSON for the current integer/string schema.
    let canonical = serde_json::to_vec(&value)?;
    ensure!(sha256(&canonical) == expected_digest, "manifest SHA-256 does not match Holochain pin");
    let signer = STANDARD.decode(outer["signer"].as_str().ok_or_else(|| anyhow!("missing signer"))?)?;
    let trusted = hex::decode(trusted_artist_hex)?;
    ensure!(signer == trusted, "manifest signer differs from trusted artist signing key");
    let key: [u8; 32] = signer.try_into().map_err(|_| anyhow!("invalid Ed25519 key length"))?;
    let verifier = VerifyingKey::from_bytes(&key)?;
    let sig = STANDARD.decode(outer["signature"].as_str().ok_or_else(|| anyhow!("missing signature"))?)?;
    let signature = Signature::from_slice(&sig)?;
    let body_value = &outer["body"];
    verifier.verify(&serde_json::to_vec(body_value)?, &signature)
        .context("invalid S1 artist signature")?;
    let body: ManifestBody = serde_json::from_value(body_value.clone())?;
    ensure!(body.schema == "holochain-storage/encrypted-package/v1" && body.cipher == "AES-256-GCM", "invalid package schema");
    ensure!(valid_hash(&body.file_id), "invalid file ID");
    ensure!((1..=MAX_CHUNK_BYTES).contains(&body.chunk_size), "invalid chunk size");
    ensure!(body.chunks.len() <= MAX_CHUNKS, "too many chunks");
    ensure!(body.total_plain_bytes <= 64 * 1024 * 1024 * 1024u64, "file too large");
    let mut total = 0u64;
    let mut nonces = HashSet::new();
    for (i, chunk) in body.chunks.iter().enumerate() {
        ensure!(chunk.index == i && valid_hash(&chunk.sha256), "invalid ciphertext chunk index/hash");
        ensure!(chunk.plain_bytes >= 1 && chunk.plain_bytes <= body.chunk_size
            && chunk.cipher_bytes == chunk.plain_bytes + 16, "invalid ciphertext chunk length");
        if i + 1 != body.chunks.len() { ensure!(chunk.plain_bytes == body.chunk_size, "nonfinal chunk too short"); }
        let nonce = STANDARD.decode(&chunk.nonce)?;
        ensure!(nonce.len() == 12 && nonces.insert(nonce), "invalid/reused AES-GCM nonce");
        total = total.checked_add(chunk.plain_bytes as u64).ok_or_else(|| anyhow!("size overflow"))?;
    }
    ensure!(total == body.total_plain_bytes, "manifest plaintext length mismatch");
    Ok(PinnedManifest { body, digest: expected_digest.to_owned() })
}

pub fn object_path(root: &Path, chunk: &Chunk) -> PathBuf {
    root.join("objects").join("sha256").join(&chunk.sha256[..2]).join(&chunk.sha256)
}

/// Read a ciphertext chunk from the S4 node's on-disk content-addressed store;
/// reject corruption before publishing it to the MoQ transport.
pub fn read_verified_chunk(store: &Path, chunk: &Chunk) -> Result<Vec<u8>> {
    let path = object_path(store, chunk);
    let meta = fs::symlink_metadata(&path).with_context(|| format!("missing object {}", chunk.index))?;
    ensure!(meta.is_file() && !meta.file_type().is_symlink()
        && meta.len() == chunk.cipher_bytes as u64, "invalid ciphertext object");
    let mut out = Vec::with_capacity(chunk.cipher_bytes);
    fs::File::open(&path)?.take(chunk.cipher_bytes as u64 + 1).read_to_end(&mut out)?;
    verify_chunk(chunk, &out)?;
    Ok(out)
}

pub fn verify_chunk(chunk: &Chunk, data: &[u8]) -> Result<()> {
    ensure!(data.len() == chunk.cipher_bytes && sha256(data) == chunk.sha256,
        "ciphertext length/SHA-256 mismatch at chunk {}", chunk.index);
    Ok(())
}

/// Persist a verified object to a local CAS destination. Never replace an
/// existing corrupt object; keep a partially received transfer unusable.
pub fn store_verified_chunk(store: &Path, chunk: &Chunk, data: &[u8]) -> Result<()> {
    verify_chunk(chunk, data)?;
    let dest = object_path(store, chunk);
    fs::create_dir_all(dest.parent().ok_or_else(|| anyhow!("missing parent"))?)?;
    match fs::symlink_metadata(&dest) {
        Ok(meta) => {
            ensure!(meta.is_file() && !meta.file_type().is_symlink(), "unsafe existing chunk path");
            let existing = read_verified_chunk(store, chunk)?;
            ensure!(existing == data, "existing chunk collision");
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    // create_new makes it impossible to replace an existing temporary file.
    let temp = dest.with_file_name(format!(".incoming-{}-{}-{}", std::process::id(),
        chunk.index, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
    let write: Result<()> = (|| {
        use std::io::Write;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&temp, &dest)?;
        Ok(())
    })();
    if write.is_err() { let _ = fs::remove_file(&temp); }
    write
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chunk_rejects_wrong_hash_and_length() {
        let chunk = Chunk { index: 0, sha256: sha256(b"hello"), cipher_bytes: 5,
            plain_bytes: 1, nonce: STANDARD.encode([0u8; 12]) };
        assert!(verify_chunk(&chunk, b"hello").is_ok());
        assert!(verify_chunk(&chunk, b"hell0").is_err());
        assert!(verify_chunk(&chunk, b"hello!").is_err());
    }
    #[test]
    fn hash_pin_requires_lowercase_hex() {
        assert!(valid_hash(&"a".repeat(64)));
        assert!(!valid_hash(&"A".repeat(64)));
        assert!(!valid_hash("a"));
    }
}

/// Domain-separated S15 one-object retry track; subscriber explicitly asks
/// for one manifest index on a fresh certificate-pinned MoQ session.
pub fn repair_track(index: usize) -> String {
    format!("ciphertext-repair-v1-{index}")
}

#[cfg(test)]
mod s15_tests {
    use super::*;
    #[test]
    fn repaired_track_name_is_deterministically_index_bound() {
        assert_eq!(repair_track(3), "ciphertext-repair-v1-3");
        assert_ne!(repair_track(3), repair_track(4));
    }
}
