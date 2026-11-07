//! v1 long-running ciphertext host: many files, many sessions, one stable
//! certificate. Subscribers choose what to receive by *track name*:
//!
//! * `file/<file_id>/from/<index>` — ordered objects `index..end` (initial
//!   streaming, seek-prioritised restart, resumption after interruption);
//! * `file/<file_id>/objects/<i>,<j>,…` — exactly the listed objects, in
//!   order, at most 64 per request (listener-driven repair);
//! * `file/<file_id>/manifest` and `file/<file_id>/receipt` — the public
//!   signed S1 manifest and this host's signed receipt, which the listener
//!   verifies against Holochain pins (so S4 HTTP need not be LAN-exposed).
//!
//! Every object is re-read and re-verified against the artist-signed S1
//! manifest immediately before it is sent. The host never has a content key,
//! listener key or plaintext. Requests are bounded per session, sessions are
//! bounded per host, and every unknown or malformed name is refused.
use crate::{load_manifest, read_verified_chunk, PinnedManifest};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use holochain_moq_realtime::{certs, fingerprint_of_der_cert};
use moq_native_ietf::{quic, tls};
use moq_transport::{
    coding::TrackNamespace,
    serve::{self, ServeError, Subgroup, TrackWriter},
    session::Publisher,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    fs,
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

pub const HOST_NAMESPACE: &str = "holochain-music/host/v1";
pub const MAX_SERVED_FILES: usize = 1_000;
pub const MAX_SESSIONS: usize = 64;
pub const MAX_REQUESTS_PER_SESSION: usize = 512;
pub const MAX_OBJECTS_PER_REQUEST: usize = 64;
const SESSION_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const LINGER: Duration = Duration::from_millis(600);

/// Track a subscriber asked for, after strict parsing.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TrackRequest {
    From { file_id: String, start: usize },
    Objects { file_id: String, indices: Vec<usize> },
    Document { file_id: String, kind: DocumentKind },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DocumentKind { Manifest, Receipt }

pub fn document_track(file_id: &str, kind: DocumentKind) -> String {
    format!("file/{file_id}/{}", match kind { DocumentKind::Manifest => "manifest", DocumentKind::Receipt => "receipt" })
}

pub fn stream_track(file_id: &str, start: usize) -> String { format!("file/{file_id}/from/{start}") }
pub fn objects_track(file_id: &str, indices: &[usize]) -> String {
    let list: Vec<String> = indices.iter().map(usize::to_string).collect();
    format!("file/{file_id}/objects/{}", list.join(","))
}

fn canonical_index(text: &str) -> Option<usize> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    text.parse().ok()
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse_track(name: &str) -> Option<TrackRequest> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() == 3 && parts[0] == "file" && is_hex64(parts[1]) {
        let kind = match parts[2] { "manifest" => DocumentKind::Manifest, "receipt" => DocumentKind::Receipt, _ => return None };
        return Some(TrackRequest::Document { file_id: parts[1].to_owned(), kind });
    }
    if parts.len() != 4 || parts[0] != "file" || !is_hex64(parts[1]) { return None; }
    let file_id = parts[1].to_owned();
    match parts[2] {
        "from" => Some(TrackRequest::From { file_id, start: canonical_index(parts[3])? }),
        "objects" => {
            let mut indices = Vec::new();
            for part in parts[3].split(',') {
                let index = canonical_index(part)?;
                if indices.contains(&index) { return None; }
                indices.push(index);
            }
            (indices.len() <= MAX_OBJECTS_PER_REQUEST).then_some(TrackRequest::Objects { file_id, indices })
        }
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServedEntry {
    manifest: PathBuf,
    trusted_artist_hex: String,
    manifest_sha256: String,
    #[serde(default)]
    receipt: Option<PathBuf>,
}

/// One verified package plus the public documents served alongside it.
pub struct Served {
    pub manifest: PinnedManifest,
    pub manifest_bytes: Bytes,
    pub receipt_bytes: Option<Bytes>,
}

pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServedList { files: Vec<ServedEntry> }

/// Load and fully verify every listed package before accepting any session.
pub fn load_catalogue(list: &Path, store: &Path) -> Result<HashMap<String, Served>> {
    let bytes = fs::read(list).with_context(|| format!("reading served list {}", list.display()))?;
    ensure!(bytes.len() <= 1024 * 1024, "served list too large");
    let parsed: ServedList = serde_json::from_slice(&bytes).context("invalid served list JSON")?;
    ensure!(parsed.files.len() <= MAX_SERVED_FILES, "too many served files");
    let mut out = HashMap::new();
    for entry in parsed.files {
        let manifest = load_manifest(&entry.manifest, &entry.trusted_artist_hex, &entry.manifest_sha256)?;
        ensure!(!manifest.body.chunks.is_empty(), "served package has no chunks");
        for chunk in &manifest.body.chunks { read_verified_chunk(store, chunk)?; }
        // Serve the exact bytes whose SHA-256 is the Holochain pin.
        let manifest_bytes = Bytes::from(serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(&fs::read(&entry.manifest)?)?)?);
        let receipt_bytes = match entry.receipt {
            Some(path) => {
                let data = fs::read(&path)?;
                ensure!(data.len() <= MAX_RECEIPT_BYTES, "receipt too large");
                serde_json::from_slice::<serde_json::Value>(&data).context("invalid receipt JSON")?;
                Some(Bytes::from(data))
            }
            None => None,
        };
        let id = manifest.body.file_id.clone();
        ensure!(out.insert(id, Served { manifest, manifest_bytes, receipt_bytes }).is_none(), "duplicate served file");
    }
    Ok(out)
}

/// PEM CERTIFICATE block -> DER, without a new parsing dependency.
fn pem_certificate_der(pem: &str) -> Result<Vec<u8>> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin).ok_or_else(|| anyhow!("no PEM certificate"))? + begin.len();
    let stop = pem[start..].find(end).ok_or_else(|| anyhow!("unterminated PEM certificate"))? + start;
    let body: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    Ok(STANDARD.decode(body).context("invalid PEM base64")?)
}

#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
#[cfg(not(unix))]
fn restrict(_: &Path, _: u32) -> Result<()> { Ok(()) }

/// Stable host identity: reuse `host.crt`/`host.key` so the fingerprint
/// published in Holochain stays valid across restarts. The directory is
/// 0700 and the key 0600 before any key material is written into it.
pub fn load_or_create_cert(dir: &Path) -> Result<(PathBuf, PathBuf, String)> {
    fs::create_dir_all(dir)?;
    restrict(dir, 0o700)?;
    let cert = dir.join("host.crt");
    let key = dir.join("host.key");
    if !(cert.is_file() && key.is_file()) {
        let staging = dir.join(format!(".new-{}", std::process::id()));
        fs::create_dir_all(&staging)?;
        restrict(&staging, 0o700)?;
        let (c, k, _) = certs::generate_localhost_cert_with_identity(&staging)?;
        restrict(&k, 0o600)?;
        fs::rename(&k, &key)?;
        fs::rename(&c, &cert)?;
        let _ = fs::remove_dir_all(&staging);
    }
    for path in [&cert, &key] {
        ensure!(!fs::symlink_metadata(path)?.file_type().is_symlink(), "refusing symlinked TLS file");
    }
    restrict(&key, 0o600)?;
    let der = pem_certificate_der(&fs::read_to_string(&cert)?)?;
    Ok((cert, key, hex::encode(fingerprint_of_der_cert(&der).fingerprint)))
}

/// Push objects into one ordered subgroup, paced to bound host memory.
async fn serve_track(track: TrackWriter, catalogue: Arc<HashMap<String, Served>>,
                     store: Arc<PathBuf>, bytes_per_second: u64) -> Result<()> {
    let name = track.name.to_string();
    let Some(request) = parse_track(&name) else {
        let _ = track.close(ServeError::not_found_ctx("malformed holochain-music track"));
        return Ok(());
    };
    let file_id = match &request {
        TrackRequest::From { file_id, .. } | TrackRequest::Objects { file_id, .. }
            | TrackRequest::Document { file_id, .. } => file_id,
    };
    let Some(served) = catalogue.get(file_id) else {
        let _ = track.close(ServeError::not_found_ctx("file not served by this host"));
        return Ok(());
    };
    let manifest = &served.manifest;
    let total = manifest.body.chunks.len();
    let order: Vec<usize> = match request {
        TrackRequest::From { start, .. } => (start..total).collect(),
        TrackRequest::Objects { indices, .. } => indices,
        TrackRequest::Document { kind, .. } => {
            let document = match kind {
                DocumentKind::Manifest => Some(served.manifest_bytes.clone()),
                DocumentKind::Receipt => served.receipt_bytes.clone(),
            };
            let Some(document) = document else {
                let _ = track.close(ServeError::not_found_ctx("document not available"));
                return Ok(());
            };
            let mut subgroups = track.subgroups().map_err(|e| anyhow!("track claimed: {e}"))?;
            let mut writer = subgroups.create(Subgroup { group_id: 0, subgroup_id: 0, priority: 0 })
                .map_err(|e| anyhow!("cannot open subgroup: {e}"))?;
            tokio::time::sleep(Duration::from_millis(200)).await;
            writer.write(document).map_err(|e| anyhow!("subscriber went away: {e}"))?;
            tokio::time::sleep(LINGER).await;
            return Ok(());
        }
    };
    if order.is_empty() || order.iter().any(|&i| i >= total) {
        let _ = track.close(ServeError::not_found_ctx("index outside signed manifest"));
        return Ok(());
    }
    let mut subgroups = track.subgroups().map_err(|e| anyhow!("track claimed: {e}"))?;
    let mut writer = subgroups.create(Subgroup { group_id: 0, subgroup_id: 0, priority: 0 })
        .map_err(|e| anyhow!("cannot open subgroup: {e}"))?;
    // SUBSCRIBE_OK precedes objects; give the subscriber a moment to attach.
    tokio::time::sleep(Duration::from_millis(200)).await;
    for index in order {
        let data = read_verified_chunk(&store, &manifest.body.chunks[index])?;
        let pause = Duration::from_micros(data.len() as u64 * 1_000_000 / bytes_per_second.max(1));
        writer.write(Bytes::from(data)).map_err(|e| anyhow!("subscriber went away: {e}"))?;
        tokio::time::sleep(pause).await;
    }
    tokio::time::sleep(LINGER).await;
    drop(writer);
    drop(subgroups);
    Ok(())
}

/// Answer subscriber-chosen tracks for one MoQT session until it closes.
async fn serve_requests(mut requests: serve::TracksRequest, catalogue: Arc<HashMap<String, Served>>,
                        store: Arc<PathBuf>, bytes_per_second: u64) -> Result<()> {
    let mut served = 0usize;
    while let Some(track) = requests.next().await {
        served += 1;
        if served > MAX_REQUESTS_PER_SESSION {
            let _ = track.close(ServeError::not_found_ctx("per-session request budget exhausted"));
            continue;
        }
        let (catalogue, store) = (catalogue.clone(), store.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_track(track, catalogue, store, bytes_per_second).await {
                tracing::warn!("track aborted: {e:#}");
            }
        });
    }
    Ok(())
}

pub struct ServeArgs {
    pub served_list: PathBuf,
    pub store: PathBuf,
    pub cert_dir: PathBuf,
    pub ready_file: PathBuf,
    pub bind: SocketAddr,
    pub advertised: IpAddr,
    pub max_sessions: usize,
    pub bytes_per_second: u64,
}

pub async fn serve(args: ServeArgs) -> Result<()> {
    ensure!((1..=MAX_SESSIONS).contains(&args.max_sessions), "invalid session limit");
    ensure!((64 * 1024..=1024 * 1024 * 1024).contains(&args.bytes_per_second), "invalid rate limit");
    let catalogue = Arc::new(load_catalogue(&args.served_list, &args.store)?);
    let store = Arc::new(args.store);
    let (cert, key, fingerprint) = load_or_create_cert(&args.cert_dir)?;
    let tls = tls::Args { cert: vec![cert], key: vec![key], ..Default::default() }
        .load().context("loading TLS server config")?;
    let endpoint = quic::Endpoint::new(quic::Config::new(args.bind, None, tls)?)?;
    let local = endpoint.client.local_addr()?;
    let mut server = endpoint.server.context("no server TLS config")?;
    let ready = json!({
        "url": format!("https://{}", SocketAddr::new(args.advertised, local.port())),
        "cert_fingerprint_hex": fingerprint,
        "namespace": HOST_NAMESPACE,
        "served_files": catalogue.len(),
    });
    // Replace atomically; only the local host app reads this file and then
    // publishes the URL and fingerprint as its own Holochain endpoint entry.
    let staging = args.ready_file.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).open(&staging)?;
        f.write_all(&serde_json::to_vec(&ready)?)?;
        f.sync_all()?;
    }
    fs::rename(&staging, &args.ready_file)?;
    let permits = Arc::new(Semaphore::new(args.max_sessions));
    while let Some((session, info)) = server.accept().await {
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            tracing::warn!("session limit reached; refusing {}", info.remote_address);
            drop(session);
            continue;
        };
        let (catalogue, store) = (catalogue.clone(), store.clone());
        let rate = args.bytes_per_second;
        tokio::spawn(async move {
            let _permit = permit;
            let run = async move {
                let (session, mut publisher) = Publisher::accept(session, info.transport).await
                    .context("MoQT publisher handshake failed")?;
                let (tracks_writer, requests, tracks_reader) = serve::Tracks {
                    namespace: TrackNamespace::from_utf8_path(HOST_NAMESPACE),
                }.produce();
                let _keep = tracks_writer;
                tokio::select! {
                    r = session.run() => r.context("session ended")?,
                    r = publisher.publish_namespace(tracks_reader) => r.context("namespace ended")?,
                    r = serve_requests(requests, catalogue, store, rate) => r?,
                }
                Ok::<(), anyhow::Error>(())
            };
            match tokio::time::timeout(SESSION_LIFETIME, run).await {
                Ok(Err(e)) => tracing::info!("session closed: {e:#}"),
                Err(_) => tracing::info!("session lifetime exceeded"),
                Ok(Ok(())) => {}
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn track_names_are_strict() {
        let id = "a".repeat(64);
        assert_eq!(parse_track(&stream_track(&id, 0)), Some(TrackRequest::From { file_id: id.clone(), start: 0 }));
        assert_eq!(parse_track(&objects_track(&id, &[17, 2])),
            Some(TrackRequest::Objects { file_id: id.clone(), indices: vec![17, 2] }));
        assert_eq!(parse_track(&document_track(&id, DocumentKind::Receipt)),
            Some(TrackRequest::Document { file_id: id.clone(), kind: DocumentKind::Receipt }));
        assert_eq!(parse_track(&format!("file/{id}/secret")), None);
        let too_many: Vec<usize> = (0..65).collect();
        for bad in [format!("file/{id}/from/01"), format!("file/{id}/from/-1"), format!("file/{id}/from/"),
                    format!("file/{id}/from/123456"), format!("file/{id}/object/1"),
                    format!("file/{id}/objects/1,1"), format!("file/{id}/objects/1,"),
                    objects_track(&id, &too_many),
                    format!("file/{}/from/1", "A".repeat(64)), format!("file/{id}/from/1/x"),
                    "ciphertext-chunks-v1".to_string(), format!("file/{}/from/1", "a".repeat(63))] {
            assert_eq!(parse_track(&bad), None, "{bad}");
        }
    }
    #[test]
    fn pem_certificate_round_trip_matches_rcgen_fingerprint() {
        let dir = std::env::temp_dir().join(format!("hm-cert-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (_, key, first) = load_or_create_cert(&dir).unwrap();
        let (_, _, again) = load_or_create_cert(&dir).unwrap();
        assert_eq!(first, again, "certificate must be stable across restarts");
        assert_eq!(first.len(), 64);
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        }
        let other = dir.join("rcgen");
        let (c, _, identity) = certs::generate_localhost_cert_with_identity(&other).unwrap();
        let der = pem_certificate_der(&fs::read_to_string(c).unwrap()).unwrap();
        assert_eq!(fingerprint_of_der_cert(&der), identity, "PEM parse must match rcgen DER fingerprint");
        let _ = fs::remove_dir_all(&dir);
    }
}
