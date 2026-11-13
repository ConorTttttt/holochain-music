//! Long-running local conductor bridge for the Holochain Music application.
//!
//! Speaks newline-delimited JSON on stdin/stdout with exactly one trusted
//! parent process (the Python app). One admin connection, one set of signing
//! credentials and ONE app interface are created per bridge lifetime, unlike
//! the one-shot `music_conductor_bridge` (which remains for S6–S17 tests).
//!
//! Only a fixed allow-list of zome functions can be called. Every record is
//! returned with its Holochain action author as reported by the validating
//! local conductor; callers still verify signatures and bindings themselves.
//! The admin interface is privileged: it MUST be loopback-only.

use holo_hash::{ActionHash, AgentPubKey};
use holochain_client::{
    AdminWebsocket, AllowedOrigins, AppWebsocket, AuthorizeSigningCredentialsPayload,
    CellInfo, ClientAgentSigner, DynAgentSigner, ExternIO, ZomeCallTarget,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, env, error::Error, io, net::SocketAddr};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const ORIGIN: &str = "holochain-music-app";
const CATALOGUE_ZOME: &str = "music_catalogue";
const STORAGE_ZOME: &str = "music_storage";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT: usize = 16;

fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

struct Options {
    admin: SocketAddr,
    app_id: String,
    catalogue_role: String,
    storage_role: String,
    catalogue_dna: Option<String>,
    storage_dna: Option<String>,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut flags = HashMap::<String, String>::new();
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if !matches!(flag.as_str(), "--admin" | "--app-id" | "--catalogue-role" | "--storage-role"
                | "--expect-catalogue-dna" | "--expect-storage-dna") {
                return Err(invalid(format!("unknown argument {flag}")));
            }
            let value = args.next().ok_or_else(|| invalid(format!("missing value for {flag}")))?;
            if value.is_empty() || flags.insert(flag.clone(), value).is_some() {
                return Err(invalid(format!("empty or duplicate option {flag}")));
            }
        }
        let admin: SocketAddr = flags.get("--admin").ok_or_else(|| invalid("missing --admin"))?.parse()?;
        if !admin.ip().is_loopback() || admin.port() == 0 {
            return Err(invalid("admin websocket MUST use loopback"));
        }
        Ok(Self {
            admin,
            app_id: flags.get("--app-id").cloned().ok_or_else(|| invalid("missing --app-id"))?,
            catalogue_role: flags.get("--catalogue-role").cloned().unwrap_or_else(|| "music_catalogue".into()),
            storage_role: flags.get("--storage-role").cloned().unwrap_or_else(|| "music_storage".into()),
            catalogue_dna: flags.get("--expect-catalogue-dna").cloned(),
            storage_dna: flags.get("--expect-storage-dna").cloned(),
        })
    }
}

#[derive(Debug, Deserialize)]
struct AuthoredRecord {
    author: String,
    action_hash: ActionHash,
    body: Value,
}

impl AuthoredRecord {
    fn out(self) -> Value {
        json!({"author": self.author, "action_hash": self.action_hash.to_string(), "body": self.body})
    }
}

#[derive(Debug, Serialize)]
struct TrackLookup { artist: AgentPubKey, track_id: String }
#[derive(Debug, Serialize)]
struct AlbumLookup { artist: AgentPubKey, album_id: String }
#[derive(Debug, Serialize)]
struct FileLookup { owner_agent: String, file_id: String }
#[derive(Debug, Serialize)]
struct SearchInput { query: String, limit: u8 }
#[derive(Debug, Serialize)]
struct SendAccessRequest { owner: AgentPubKey, request: Value }
#[derive(Debug, Serialize)]
struct SendGrant { listener: AgentPubKey, grant: Value }

#[derive(Debug, Deserialize)]
struct InboxRow {
    action_hash: ActionHash,
    received_at: holochain_client::Timestamp,
    body: Value,
}

struct Bridge {
    app: AppWebsocket,
    catalogue_role: String,
    storage_role: String,
    whoami: Value,
}

async fn connect(opts: Options) -> Result<Bridge> {
    let admin = AdminWebsocket::connect(opts.admin, Some(ORIGIN.into())).await?;
    let installed = admin.list_apps(None).await?
        .into_iter()
        .find(|a| a.installed_app_id == opts.app_id)
        .ok_or_else(|| invalid("installed app ID is not present on local conductor"))?;
    let one_cell = |role: &str| -> Result<_> {
        let cells = installed.cell_info.get(role).ok_or_else(|| invalid(format!("missing role {role}")))?;
        let mut entries = cells.iter().filter_map(|c| match c {
            CellInfo::Provisioned(p) => Some(p.cell_id.clone()),
            _ => None,
        });
        let cell = entries.next().ok_or_else(|| invalid(format!("no provisioned cell for {role}")))?;
        if entries.next().is_some() { return Err(invalid(format!("ambiguous cells for {role}"))); }
        Ok(cell)
    };
    let music = one_cell(&opts.catalogue_role)?;
    let storage = one_cell(&opts.storage_role)?;
    if music.dna_hash() == storage.dna_hash() {
        return Err(invalid("catalogue and storage roles must be different DNAs"));
    }
    for (pin, cell) in [(&opts.catalogue_dna, &music), (&opts.storage_dna, &storage)] {
        if let Some(expected) = pin {
            if &cell.dna_hash().to_string() != expected {
                return Err(invalid("installed DNA hash does not match the pinned value"));
            }
        }
    }
    if music.agent_pubkey() != storage.agent_pubkey() {
        return Err(invalid("catalogue and storage cells must share one agent"));
    }
    let signer = ClientAgentSigner::default();
    for cell in [&music, &storage] {
        let credentials = admin.authorize_signing_credentials(
            AuthorizeSigningCredentialsPayload { cell_id: cell.clone(), functions: None }
        ).await?;
        signer.add_credentials(cell.clone(), credentials);
    }
    // Reuse an existing interface restricted to our origin when one exists,
    // so restarting the app does not accumulate interfaces on the conductor.
    let existing = admin.list_app_interfaces().await?.into_iter().find(|i| {
        i.installed_app_id.as_deref() == Some(opts.app_id.as_str())
            && i.allowed_origins == AllowedOrigins::from(ORIGIN.to_string())
    });
    let app_port = match existing {
        Some(interface) => interface.port,
        None => admin.attach_app_interface(
            0, None, AllowedOrigins::from(ORIGIN.to_string()), Some(opts.app_id.clone())
        ).await?,
    };
    let token = admin.issue_app_auth_token(opts.app_id.clone().into()).await?.token;
    let dyn_signer: DynAgentSigner = signer.into();
    let app = AppWebsocket::connect(
        (std::net::Ipv4Addr::LOCALHOST, app_port), token, dyn_signer, Some(ORIGIN.into())
    ).await?;
    if &app.my_pub_key != music.agent_pubkey() {
        return Err(invalid("app socket agent differs from the app cells"));
    }
    let whoami = json!({
        "app_id": opts.app_id,
        "agent": music.agent_pubkey().to_string(),
        "catalogue_dna": music.dna_hash().to_string(),
        "storage_dna": storage.dna_hash().to_string(),
    });
    Ok(Bridge { app, catalogue_role: opts.catalogue_role, storage_role: opts.storage_role, whoami })
}

fn arg<'a>(args: &'a Value, key: &str) -> Result<&'a Value> {
    args.get(key).ok_or_else(|| invalid(format!("missing argument {key}")))
}
fn arg_str(args: &Value, key: &str) -> Result<String> {
    let value = arg(args, key)?.as_str().ok_or_else(|| invalid(format!("{key} must be a string")))?;
    if value.is_empty() || value.len() > 256 { return Err(invalid(format!("invalid {key}"))); }
    Ok(value.to_owned())
}
fn arg_agent(args: &Value, key: &str) -> Result<AgentPubKey> {
    Ok(AgentPubKey::try_from(arg_str(args, key)?.as_str())?)
}
fn arg_u8(args: &Value, key: &str) -> Result<u8> {
    let n = arg(args, key)?.as_u64().ok_or_else(|| invalid(format!("{key} must be an integer")))?;
    u8::try_from(n).map_err(|_| invalid(format!("{key} out of range")))
}
fn arg_entry(args: &Value) -> Result<Value> {
    arg_entry_named(args, "entry")
}
fn arg_entry_named(args: &Value, key: &str) -> Result<Value> {
    let entry = arg(args, key)?;
    if !entry.is_object() { return Err(invalid(format!("{key} must be an object"))); }
    Ok(entry.clone())
}

impl Bridge {
    async fn call<I: Serialize + std::fmt::Debug, O: DeserializeOwned + std::fmt::Debug>(
        &self, catalogue: bool, func: &str, payload: &I,
    ) -> Result<O> {
        let (role, zome) = if catalogue { (&self.catalogue_role, CATALOGUE_ZOME) } else { (&self.storage_role, STORAGE_ZOME) };
        let output = self.app.call_zome(
            ZomeCallTarget::RoleName(role.clone()), zome.into(), func.into(), ExternIO::encode(payload)?,
        ).await?;
        Ok(output.decode()?)
    }

    async fn records<I: Serialize + std::fmt::Debug>(&self, catalogue: bool, func: &str, payload: &I) -> Result<Value> {
        let rows: Vec<AuthoredRecord> = self.call(catalogue, func, payload).await?;
        Ok(Value::Array(rows.into_iter().map(AuthoredRecord::out).collect()))
    }

    async fn inbox(&self, func: &str) -> Result<Value> {
        let rows: Vec<InboxRow> = self.call(false, func, &()).await?;
        Ok(Value::Array(rows.into_iter().map(|r| json!({
            "action_hash": r.action_hash.to_string(),
            "received_at_us": r.received_at.as_micros(),
            "body": r.body,
        })).collect()))
    }

    async fn create(&self, catalogue: bool, func: &str, entry: Value) -> Result<Value> {
        let hash: ActionHash = self.call(catalogue, func, &entry).await?;
        Ok(json!({"action_hash": hash.to_string()}))
    }

    async fn dispatch(&self, op: &str, args: &Value) -> Result<Value> {
        match op {
            "whoami" => Ok(self.whoami.clone()),
            // Catalogue reads.
            "list_artists" => self.records(true, "list_artists", &()).await,
            "get_artist_profile" => {
                let row: Option<AuthoredRecord> = self.call(true, "get_artist_profile", &arg_agent(args, "artist")?).await?;
                Ok(row.map(AuthoredRecord::out).unwrap_or(Value::Null))
            }
            "list_albums" => self.records(true, "list_albums", &arg_agent(args, "artist")?).await,
            "list_tracks" => self.records(true, "list_tracks", &arg_agent(args, "artist")?).await,
            "list_album_tracks" => self.records(true, "list_album_tracks", &AlbumLookup {
                artist: arg_agent(args, "artist")?, album_id: arg_str(args, "album_id")?,
            }).await,
            "get_track" => {
                let row: Option<AuthoredRecord> = self.call(true, "get_track", &TrackLookup {
                    artist: arg_agent(args, "artist")?, track_id: arg_str(args, "track_id")?,
                }).await?;
                Ok(row.map(AuthoredRecord::out).unwrap_or(Value::Null))
            }
            "browse_tracks" => self.records(true, "browse_tracks", &arg_u8(args, "limit")?).await,
            "search_tracks" => self.records(true, "search_tracks", &SearchInput {
                query: arg_str(args, "query")?, limit: arg_u8(args, "limit")?,
            }).await,
            // Catalogue writes (author is always this agent; zomes validate).
            "publish_artist_profile" => self.create(true, "publish_artist_profile", arg_entry(args)?).await,
            "publish_album" => self.create(true, "publish_album", arg_entry(args)?).await,
            "publish_track" => self.create(true, "publish_track", arg_entry(args)?).await,
            // Storage reads.
            "get_signing_keys" => self.records(false, "get_signing_keys", &arg_agent(args, "agent")?).await,
            "get_file_commitments" => self.records(false, "get_file_commitments", &arg_agent(args, "agent")?).await,
            "get_replica_claims" => self.records(false, "get_replica_claims", &FileLookup {
                owner_agent: arg_str(args, "owner_agent")?, file_id: arg_str(args, "file_id")?,
            }).await,
            "get_moq_endpoints" => self.records(false, "get_moq_endpoints", &arg_agent(args, "host")?).await,
            // Private inbox (own source chain only; never DHT-linked).
            "get_inbox_access_requests" => self.inbox("get_inbox_access_requests").await,
            "get_inbox_grants" => self.inbox("get_inbox_grants").await,
            // Storage writes.
            "register_signing_key" => self.create(false, "register_signing_key", arg_entry(args)?).await,
            // S2 key-binding v2 (only present on the opt-in v2 storage DNA).
            // The entry carries a proof signed locally; no private key passes here.
            "key_binding_v2_context" => {
                let context: Value = self.call(false, "key_binding_v2_context", &()).await?;
                Ok(context)
            }
            "register_signing_key_v2" => self.create(false, "register_signing_key_v2", arg_entry(args)?).await,
            "get_signing_keys_v2" => self.records(false, "get_signing_keys_v2", &arg_agent(args, "agent")?).await,
            "publish_file_commitment" => self.create(false, "publish_file_commitment", arg_entry(args)?).await,
            "publish_replica_claim" => self.create(false, "publish_replica_claim", arg_entry(args)?).await,
            "publish_moq_endpoint" => self.create(false, "publish_moq_endpoint", arg_entry(args)?).await,
            "send_access_request" => {
                let _: () = self.call(false, "send_access_request", &SendAccessRequest {
                    owner: arg_agent(args, "owner")?, request: arg_entry_named(args, "request")?,
                }).await?;
                Ok(json!({"delivered": true}))
            }
            "send_grant" => {
                let _: () = self.call(false, "send_grant", &SendGrant {
                    listener: arg_agent(args, "listener")?, grant: arg_entry_named(args, "grant")?,
                }).await?;
                Ok(json!({"delivered": true}))
            }
            _ => Err(invalid("unknown bridge operation")),
        }
    }
}

/// Keep conductor error text short and single-line for the parent process.
fn short_error(error: &(dyn Error + Send + Sync)) -> String {
    let text = error.to_string().replace(['\n', '\r'], " ");
    text.chars().take(300).collect()
}

#[tokio::main]
async fn main() {
    let opts = match Options::parse() {
        Ok(o) => o,
        Err(e) => { eprintln!("music-app-bridge: {e}"); std::process::exit(2); }
    };
    let bridge = match connect(opts).await {
        Ok(b) => b,
        Err(e) => { eprintln!("music-app-bridge: {}", short_error(e.as_ref())); std::process::exit(1); }
    };
    let mut stdout = tokio::io::stdout();
    let ready = json!({"ready": true, "whoami": bridge.whoami});
    if stdout.write_all(format!("{ready}\n").as_bytes()).await.is_err() { return; }
    let _ = stdout.flush().await;
    // Requests run concurrently (bounded): a slow call_remote to an offline
    // peer must not stall catalogue reads. Replies carry the request id and
    // may arrive out of order; one writer task serialises stdout.
    let bridge = std::sync::Arc::new(bridge);
    let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(64);
    let writer = tokio::spawn(async move {
        while let Some(reply) = rx.recv().await {
            if stdout.write_all(format!("{reply}\n").as_bytes()).await.is_err() { break; }
            let _ = stdout.flush().await;
        }
    });
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if line.len() > MAX_REQUEST_BYTES {
            let _ = tx.send(json!({"id": Value::Null, "ok": false, "error": "request too large"})).await;
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            let _ = tx.send(json!({"id": Value::Null, "ok": false, "error": "invalid JSON request"})).await;
            continue;
        };
        let Ok(permit) = permits.clone().acquire_owned().await else { break };
        let (bridge, tx) = (bridge.clone(), tx.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            let op = request.get("op").and_then(Value::as_str).unwrap_or("");
            let args = request.get("args").cloned().unwrap_or_else(|| json!({}));
            let reply = match bridge.dispatch(op, &args).await {
                Ok(result) => json!({"id": id, "ok": true, "result": result}),
                Err(e) => json!({"id": id, "ok": false, "error": short_error(e.as_ref())}),
            };
            let _ = tx.send(reply).await;
        });
    }
    drop(tx);
    let _ = writer.await;
}
