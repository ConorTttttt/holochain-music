//! S4 prototype: a full encrypted-replica HTTP node, interoperable with S1 Python.
//! Only signed artist uploads are allowed. Downloads are public ciphertext and
//! must be checked against a pinned artist-signed manifest by the consumer.
//! Defaults to loopback HTTP; do NOT expose this to untrusted networks without TLS.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const SCHEMA: &str = "holochain-storage/encrypted-package/v1";
const RECEIPT_SCHEMA: &str = "holochain-storage/replica-receipt/v1";
const MAX_MANIFEST: usize = 8 * 1024 * 1024;
const MAX_CHUNK: usize = 4 * 1024 * 1024 + 16;
const MAX_CHUNKS: usize = 16_384;
const MAX_TOTAL: u64 = 64 * 1024 * 1024 * 1024;
const CLOCK_SKEW_SECONDS: i64 = 300;
const HTTP_MAX_BODY: usize = MAX_MANIFEST + 4096;

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    artist: VerifyingKey,
    signer: SigningKey,
    // One synchronous writer at a time; bounded chunks keep this acceptable
    // for the prototype. Replace with per-package locking before deployment.
    writer_lock: Arc<Mutex<()>>,
    // Replay protection during one process lifetime. Restart-safe persistence
    // is an explicit production gap; see the S4 security document.
    nonces: Arc<Mutex<HashMap<(String, String), i64>>>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error":self.message}))).into_response()
    }
}
type ApiResult<T> = Result<T, ApiError>;
fn error(status: StatusCode, message: impl Into<String>) -> ApiError {
    ApiError { status, message: message.into() }
}
fn invalid(message: impl Into<String>) -> ApiError {
    error(StatusCode::BAD_REQUEST, message)
}
fn forbidden(message: impl Into<String>) -> ApiError {
    error(StatusCode::FORBIDDEN, message)
}
fn internal(message: impl Into<String>) -> ApiError {
    error(StatusCode::INTERNAL_SERVER_ERROR, message)
}
fn sha256(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn is_hash(s: &str) -> bool { s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) }
fn b64_32(s: &str) -> ApiResult<[u8; 32]> {
    let v = B64.decode(s).map_err(|_| invalid("invalid base64 key"))?;
    v.try_into().map_err(|_| invalid("expected 32-byte key"))
}
fn canonical(value: &Value) -> ApiResult<Vec<u8>> {
    // serde_json::Value's map is sorted by key without preserve_order;
    // matches Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False).
    serde_json::to_vec(value).map_err(|_| invalid("invalid json"))
}
fn validate_file_id(s: &str) -> ApiResult<()> {
    if is_hash(s) { Ok(()) } else { Err(invalid("file_id must be lowercase sha256-shaped hex")) }
}
fn path_for_manifest(root: &Path, id: &str) -> PathBuf { root.join("packages").join(id).join("manifest.json") }
fn path_for_receipt(root: &Path, id: &str) -> PathBuf { root.join("packages").join(id).join("receipt.json") }
fn path_for_chunk(root: &Path, hash: &str) -> PathBuf { root.join("objects/sha256").join(&hash[..2]).join(hash) }

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct Chunk {
    index: usize,
    sha256: String,
    nonce: String,
    plain_bytes: usize,
    cipher_bytes: usize,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    schema: String,
    file_id: String,
    cipher: String,
    chunk_size: usize,
    total_plain_bytes: u64,
    chunks: Vec<Chunk>,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    body: ManifestBody,
    signer: String,
    signature: String,
}
fn verify_manifest(value: &Value, trusted: &VerifyingKey) -> ApiResult<ManifestBody> {
    let whole = canonical(value)?;
    if whole.len() > MAX_MANIFEST { return Err(invalid("manifest too large")); }
    let signed: SignedManifest = serde_json::from_value(value.clone()).map_err(|_| invalid("bad signed manifest"))?;
    if b64_32(&signed.signer)? != trusted.to_bytes() { return Err(forbidden("untrusted manifest signer")); }
    let raw_sig = B64.decode(&signed.signature).map_err(|_| invalid("bad manifest signature"))?;
    let sig = Signature::from_slice(&raw_sig).map_err(|_| invalid("bad signature length"))?;
    let body = value.get("body").ok_or_else(|| invalid("missing manifest body"))?;
    trusted.verify(&canonical(body)?, &sig).map_err(|_| forbidden("manifest signature invalid"))?;
    let m = signed.body;
    validate_file_id(&m.file_id)?;
    if m.schema != SCHEMA || m.cipher != "AES-256-GCM" { return Err(invalid("unsupported manifest schema/cipher")); }
    if m.chunk_size == 0 || m.chunk_size > 4 * 1024 * 1024 || m.total_plain_bytes > MAX_TOTAL || m.chunks.len() > MAX_CHUNKS { return Err(invalid("manifest limits exceeded")); }
    let mut total = 0u64;
    let mut nonces = HashSet::new();
    for (i, c) in m.chunks.iter().enumerate() {
        if c.index != i || !is_hash(&c.sha256) || c.plain_bytes == 0 || c.plain_bytes > m.chunk_size || c.cipher_bytes != c.plain_bytes + 16 { return Err(invalid("invalid chunk metadata")); }
        if i + 1 != m.chunks.len() && c.plain_bytes != m.chunk_size { return Err(invalid("nonfinal chunk has short length")); }
        let nonce = B64.decode(&c.nonce).map_err(|_| invalid("bad nonce"))?;
        if nonce.len() != 12 || !nonces.insert(nonce) { return Err(invalid("duplicate or malformed nonce")); }
        total += c.plain_bytes as u64;
    }
    if total != m.total_plain_bytes { return Err(invalid("manifest length mismatch")); }
    Ok(m)
}

fn header<'a>(headers: &'a HeaderMap, key: &str) -> ApiResult<&'a str> {
    headers.get(key).ok_or_else(|| forbidden(format!("missing header {key}")))?
        .to_str().map_err(|_| forbidden(format!("invalid header {key}")))
}
fn authorize(state: &AppState, headers: &HeaderMap, method: &str, path: &str, body: &[u8]) -> ApiResult<()> {
    let artist = header(headers, "x-hs-artist-key")?;
    if b64_32(artist)? != state.artist.to_bytes() { return Err(forbidden("artist not permitted")); }
    let stamp = header(headers, "x-hs-timestamp")?;
    let timestamp: i64 = stamp.parse().map_err(|_| forbidden("bad timestamp"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| internal("clock before epoch"))?.as_secs() as i64;
    if now.abs_diff(timestamp) > CLOCK_SKEW_SECONDS as u64 { return Err(forbidden("request outside time window")); }
    let nonce = header(headers, "x-hs-nonce")?;
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) { return Err(forbidden("bad nonce")); }
    let digest = sha256(body);
    if header(headers, "x-hs-body-sha256")? != digest { return Err(forbidden("body digest mismatch")); }
    let payload = format!("holochain-storage/http-auth/v1\n{method}\n{path}\n{stamp}\n{nonce}\n{digest}");
    let raw_sig = B64.decode(header(headers, "x-hs-signature")?).map_err(|_| forbidden("bad auth signature"))?;
    let signature = Signature::from_slice(&raw_sig).map_err(|_| forbidden("bad signature size"))?;
    state.artist.verify(payload.as_bytes(), &signature).map_err(|_| forbidden("invalid request signature"))?;
    let mut seen = state.nonces.lock().map_err(|_| internal("nonce state unavailable"))?;
    seen.retain(|_, when| now - *when <= CLOCK_SKEW_SECONDS * 2);
    if seen.len() > 100_000 { return Err(error(StatusCode::TOO_MANY_REQUESTS, "nonce cache full")); }
    if seen.insert((artist.to_owned(), nonce.to_owned()), now).is_some() { return Err(forbidden("replayed request")); }
    Ok(())
}

fn safe_read(path: &Path, limit: usize) -> ApiResult<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|_| error(StatusCode::NOT_FOUND, "object missing"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > limit as u64 { return Err(invalid("invalid stored object")); }
    let mut f = File::open(path).map_err(|_| internal("cannot read object"))?;
    let mut bytes = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| internal("read failed"))?;
    if bytes.len() > limit { return Err(invalid("stored object too large")); }
    Ok(bytes)
}
fn atomic_write(path: &Path, bytes: &[u8]) -> ApiResult<()> {
    let parent = path.parent().ok_or_else(|| internal("missing parent path"))?;
    fs::create_dir_all(parent).map_err(|_| internal("cannot create storage directory"))?;
    let temp = parent.join(format!(".incoming-{}", hex::encode(rand::random::<[u8; 16]>())));
    let result: ApiResult<()> = (|| {
        let mut f = OpenOptions::new().create_new(true).write(true).open(&temp).map_err(|_| internal("cannot stage object"))?;
        f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|_| internal("cannot sync object"))?;
        fs::rename(&temp, path).map_err(|_| internal("cannot commit object"))?;
        if let Ok(dir) = File::open(parent) { dir.sync_all().map_err(|_| internal("cannot sync directory"))?; }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result
}
fn read_manifest(state: &AppState, id: &str) -> ApiResult<(Value, ManifestBody)> {
    validate_file_id(id)?;
    let bytes = safe_read(&path_for_manifest(&state.root, id), MAX_MANIFEST)?;
    let json: Value = serde_json::from_slice(&bytes).map_err(|_| internal("malformed stored manifest"))?;
    let m = verify_manifest(&json, &state.artist)?;
    if m.file_id != id { return Err(invalid("manifest path mismatch")); }
    Ok((json, m))
}
fn committed(state: &AppState, id: &str) -> ApiResult<()> {
    let path = path_for_receipt(&state.root, id);
    if !path.exists() { return Err(error(StatusCode::NOT_FOUND, "package not committed")); }
    Ok(())
}
fn check_object(state: &AppState, chunk: &Chunk) -> ApiResult<Vec<u8>> {
    let bytes = safe_read(&path_for_chunk(&state.root, &chunk.sha256), chunk.cipher_bytes)?;
    if bytes.len() != chunk.cipher_bytes || sha256(&bytes) != chunk.sha256 { return Err(error(StatusCode::CONFLICT, "stored encrypted chunk damaged")); }
    Ok(bytes)
}

async fn health() -> &'static str { "ok" }
async fn init(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> ApiResult<(StatusCode, Json<Value>)> {
    authorize(&state, &headers, "POST", "/v1/packages/init", &body)?;
    if body.len() > MAX_MANIFEST { return Err(invalid("manifest upload too large")); }
    let request: Value = serde_json::from_slice(&body).map_err(|_| invalid("invalid init JSON"))?;
    let value = request.get("manifest").ok_or_else(|| invalid("manifest required"))?;
    if request.as_object().map(|m| m.len()) != Some(1) { return Err(invalid("init accepts only manifest")); }
    let manifest = verify_manifest(value, &state.artist)?;
    let path = path_for_manifest(&state.root, &manifest.file_id);
    let bytes = canonical(value)?;
    let _lock = state.writer_lock.lock().map_err(|_| internal("storage unavailable"))?;
    match safe_read(&path, MAX_MANIFEST) {
        Ok(existing) if existing != bytes => return Err(error(StatusCode::CONFLICT, "different manifest for file ID")),
        Ok(_) => {},
        Err(e) if e.status == StatusCode::NOT_FOUND => atomic_write(&path, &bytes)?,
        Err(e) => return Err(e),
    }
    Ok((StatusCode::CREATED, Json(json!({"file_id":manifest.file_id,"chunks":manifest.chunks.len()}))))
}
async fn upload(State(state): State<AppState>, AxumPath((id, index)): AxumPath<(String, usize)>, headers: HeaderMap, body: Bytes) -> ApiResult<StatusCode> {
    let path = format!("/v1/packages/{id}/chunks/{index}");
    authorize(&state, &headers, "PUT", &path, &body)?;
    if body.len() > MAX_CHUNK { return Err(invalid("ciphertext chunk too large")); }
    let _lock = state.writer_lock.lock().map_err(|_| internal("storage unavailable"))?;
    let (_value, manifest) = read_manifest(&state, &id)?;
    if path_for_receipt(&state.root, &id).exists() { return Err(error(StatusCode::CONFLICT, "package is committed")); }
    let chunk = manifest.chunks.get(index).ok_or_else(|| invalid("chunk index out of bounds"))?;
    if body.len() != chunk.cipher_bytes || sha256(&body) != chunk.sha256 { return Err(invalid("ciphertext differs from signed manifest")); }
    let dest = path_for_chunk(&state.root, &chunk.sha256);
    match safe_read(&dest, chunk.cipher_bytes) {
        Ok(existing) if existing.as_slice() != body.as_ref() => return Err(error(StatusCode::CONFLICT, "corrupt pre-existing object")),
        Ok(_) => {},
        Err(e) if e.status == StatusCode::NOT_FOUND => atomic_write(&dest, &body)?,
        Err(e) => return Err(e),
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn commit(State(state): State<AppState>, AxumPath(id): AxumPath<String>, headers: HeaderMap, body: Bytes) -> ApiResult<(StatusCode, Json<Value>)> {
    let path = format!("/v1/packages/{id}/commit");
    authorize(&state, &headers, "POST", &path, &body)?;
    if !body.is_empty() { return Err(invalid("commit body must be empty")); }
    let _lock = state.writer_lock.lock().map_err(|_| internal("storage unavailable"))?;
    let (value, manifest) = read_manifest(&state, &id)?;
    let receipt_path = path_for_receipt(&state.root, &id);
    if receipt_path.exists() {
        let bytes = safe_read(&receipt_path, 8192)?;
        let receipt: Value = serde_json::from_slice(&bytes).map_err(|_| internal("bad stored receipt"))?;
        return Ok((StatusCode::OK, Json(receipt)));
    }
    for chunk in &manifest.chunks { check_object(&state, chunk)?; }
    let receipt_body = json!({
        "schema":RECEIPT_SCHEMA,
        "file_id":id,
        "manifest_sha256":sha256(&canonical(&value)?),
        "chunk_count":manifest.chunks.len(),
        "received_at":Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
    });
    let sig = state.signer.sign(&canonical(&receipt_body)?);
    let receipt = json!({"body":receipt_body, "signer":B64.encode(state.signer.verifying_key().to_bytes()), "signature":B64.encode(sig.to_bytes())});
    atomic_write(&receipt_path, &canonical(&receipt)?)?;
    Ok((StatusCode::CREATED, Json(receipt)))
}
async fn manifest(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult<Json<Value>> {
    committed(&state, &id)?;
    Ok(Json(read_manifest(&state, &id)?.0))
}
async fn receipt(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> ApiResult<Json<Value>> {
    validate_file_id(&id)?;
    committed(&state, &id)?;
    let bytes = safe_read(&path_for_receipt(&state.root, &id), 8192)?;
    Ok(Json(serde_json::from_slice(&bytes).map_err(|_| internal("invalid receipt on disk"))?))
}
async fn download(State(state): State<AppState>, AxumPath((id, index)): AxumPath<(String, usize)>) -> ApiResult<Response> {
    committed(&state, &id)?;
    let (_, m) = read_manifest(&state, &id)?;
    let chunk = m.chunks.get(index).ok_or_else(|| error(StatusCode::NOT_FOUND, "unknown chunk"))?;
    let bytes = check_object(&state, chunk)?;
    Ok((StatusCode::OK, [("content-type", "application/octet-stream")], bytes).into_response())
}

fn load_or_generate_key(path: &Path) -> Result<SigningKey, String> {
    if path.exists() {
        if fs::symlink_metadata(path).map_err(|e| e.to_string())?.file_type().is_symlink() { return Err("refusing symlink node key".into()); }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let raw: [u8; 32] = bytes.try_into().map_err(|_| "invalid node key length")?;
        return Ok(SigningKey::from_bytes(&raw));
    }
    let key = SigningKey::generate(&mut OsRng);
    if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)] { options.mode(0o600); }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(&key.to_bytes()).and_then(|_| file.sync_all()).map_err(|e| e.to_string())?;
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut artist: Option<String> = None;
    let mut listen = "127.0.0.1:4780".to_string();
    let mut unsafe_remote = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(args.next().ok_or("missing --root value")?)),
            "--artist-key" => artist = Some(args.next().ok_or("missing --artist-key value")?),
            "--listen" => listen = args.next().ok_or("missing --listen value")?,
            "--allow-insecure-remote-http" => unsafe_remote = true,
            "--help" | "-h" => {
                println!("Usage: holochain-storage-node --root DIR --artist-key BASE64 [--listen 127.0.0.1:4780] [--allow-insecure-remote-http]\n\nWARNING: HTTP is plaintext. Default bind is loopback; use a secure tunnel for remote testing.");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let root = root.ok_or("missing --root")?;
    let artist_raw = b64_32(&artist.ok_or("missing --artist-key")?)?;
    let allowed = VerifyingKey::from_bytes(&artist_raw)?;
    let addr: SocketAddr = listen.parse()?;
    if !addr.ip().is_loopback() && !unsafe_remote { return Err("refusing non-loopback plaintext HTTP; use TLS termination or an SSH tunnel".into()); }
    fs::create_dir_all(&root)?;
    #[cfg(unix)] { fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?; }
    let signer = load_or_generate_key(&root.join("node.ed25519"))?;
    let state = AppState { root, artist: allowed, signer: signer.clone(), writer_lock: Arc::new(Mutex::new(())), nonces: Arc::new(Mutex::new(HashMap::new())) };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/packages/init", post(init))
        .route("/v1/packages/:id/chunks/:index", put(upload).get(download))
        .route("/v1/packages/:id/commit", post(commit))
        .route("/v1/packages/:id/manifest", get(manifest))
        .route("/v1/packages/:id/receipt", get(receipt))
        .layer(DefaultBodyLimit::max(HTTP_MAX_BODY))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("listening on http://{addr} (loopback recommended)");
    println!("node public Ed25519 key: {}", B64.encode(signer.verifying_key().to_bytes()));
    axum::serve(listener, app).await?;
    Ok(())
}
