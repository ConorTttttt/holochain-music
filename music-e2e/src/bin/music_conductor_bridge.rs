//! Read-only, authenticated S5+S2 conductor bridge for a music listener.
//!
//! This binary MUST be run on the same trusted machine as Bob's conductor.
//! It refuses non-loopback admin connections, authenticates to one installed
//! hApp, pins the two DNA hashes, uses the app's actual signed zome-call
//! channel, and outputs *only* validated action-backed coordinator records.
//!
//! The bridge has NO artist signing key, content key, payment or custody proof.
//! An admin interface is privileged: never expose it on a public network.

use holo_hash::{ActionHash, AgentPubKey};
use holochain_client::{
    AdminWebsocket, AllowedOrigins, AppWebsocket, AuthorizeSigningCredentialsPayload,
    CellInfo, ClientAgentSigner, DynAgentSigner, ExternIO, ZomeCallTarget,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, env, error::Error, io, net::SocketAddr};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

const ORIGIN: &str = "holochain-music-local-listener";
const CATALOGUE_ZOME: &str = "music_catalogue";
const STORAGE_ZOME: &str = "music_storage";
const RESPONSE_SCHEMA: &str = "holochain-music/conductor-read/v1";

fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

#[derive(Debug)]
struct Options {
    admin: SocketAddr,
    app_id: String,
    catalogue_role: String,
    storage_role: String,
    catalogue_dna: String,
    storage_dna: String,
    artist: AgentPubKey,
    node: AgentPubKey,
    track_id: String,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut flags = HashMap::<String, String>::new();
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if !flag.starts_with("--") {
                return Err(invalid(format!("unexpected argument {flag}")));
            }
            let value = args.next().ok_or_else(|| invalid(format!("missing value for {flag}")))?;
            if !matches!(flag.as_str(),
                "--admin" | "--app-id" | "--catalogue-role" | "--storage-role" |
                "--expect-catalogue-dna" | "--expect-storage-dna" |
                "--artist" | "--node" | "--track-id")
            {
                return Err(invalid(format!("unknown argument {flag}")));
            }
            if flags.insert(flag.clone(), value).is_some() {
                return Err(invalid(format!("duplicate option {flag}")));
            }
        }
        let required = |key: &str| -> Result<String> {
            let value = flags.get(key).ok_or_else(|| invalid(format!("missing {key}")))?;
            if value.is_empty() { return Err(invalid(format!("empty {key}"))); }
            Ok(value.to_owned())
        };
        let admin: SocketAddr = required("--admin")?.parse()?;
        if !admin.ip().is_loopback() || admin.port() == 0 {
            return Err(invalid("admin websocket MUST use loopback (127.0.0.1 or ::1)"));
        }
        let artist = AgentPubKey::try_from(required("--artist")?.as_str())?;
        let node = AgentPubKey::try_from(required("--node")?.as_str())?;
        let track_id = required("--track-id")?;
        if track_id.len() != 32 || !track_id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(invalid("track ID must be 32 lowercase hex digits"));
        }
        let catalogue_dna = required("--expect-catalogue-dna")?;
        let storage_dna = required("--expect-storage-dna")?;
        if catalogue_dna == storage_dna {
            return Err(invalid("catalogue and storage must have different DNA hashes"));
        }
        Ok(Self {
            admin,
            app_id: required("--app-id")?,
            catalogue_role: flags.get("--catalogue-role").cloned().unwrap_or_else(|| "music_catalogue".into()),
            storage_role: flags.get("--storage-role").cloned().unwrap_or_else(|| "music_storage".into()),
            catalogue_dna,
            storage_dna,
            artist,
            node,
            track_id,
        })
    }
}

#[derive(Debug, Deserialize)]
struct AuthoredRecord {
    author: String,
    action_hash: ActionHash,
    body: Value,
}

#[derive(Debug, Serialize)]
struct RecordOut {
    author: String,
    action_hash: String,
    body: Value,
}

impl AuthoredRecord {
    fn checked(self, expected_author: &str) -> Result<RecordOut> {
        if self.author != expected_author || !self.body.is_object() {
            return Err(invalid("unexpected author or malformed validated zome record"));
        }
        Ok(RecordOut {
            author: self.author,
            action_hash: self.action_hash.to_string(),
            body: self.body,
        })
    }
}

#[derive(Debug, Serialize)]
struct BridgeResult {
    schema: &'static str,
    app_id: String,
    reader_agent: String,
    catalogue_dna: String,
    storage_dna: String,
    track: RecordOut,
    owner_key_binding: RecordOut,
    owner_commitment: RecordOut,
    node_key_binding: RecordOut,
    replica_claim: RecordOut,
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

fn choose_unique(
    records: Vec<AuthoredRecord>,
    author: &str,
    predicate: impl Fn(&Value) -> bool,
    label: &str,
) -> Result<RecordOut> {
    let mut matches = records.into_iter().filter(|r| predicate(&r.body));
    let selected = matches.next().ok_or_else(|| invalid(format!("no {label} found")))?;
    if matches.next().is_some() {
        return Err(invalid(format!("ambiguous {label}: multiple matching entries; key/claim rotation policy is required")));
    }
    selected.checked(author)
}

async fn call<I: Serialize + std::fmt::Debug, O: DeserializeOwned>(
    app: &AppWebsocket,
    role: &str,
    zome: &str,
    func: &str,
    payload: &I,
) -> Result<O> {
    let input = ExternIO::encode(payload)?;
    let output = app
        .call_zome(ZomeCallTarget::RoleName(role.to_owned()), zome.into(), func.into(), input)
        .await?;
    Ok(output.decode()?)
}

async fn collect(opts: Options) -> Result<BridgeResult> {
    let admin = AdminWebsocket::connect(opts.admin, Some(ORIGIN.into())).await?;
    let installed = admin.list_apps(None).await?
        .into_iter()
        .find(|a| a.installed_app_id == opts.app_id)
        .ok_or_else(|| invalid("installed app ID is not present on local conductor"))?;
    let one_cell = |role: &str| -> Result<_> {
        let cells = installed.cell_info.get(role).ok_or_else(|| invalid(format!("missing role {role}")))?;
        let mut entries = cells.iter().filter_map(|c| match c {
            CellInfo::Provisioned(provisioned) => Some(provisioned.cell_id.clone()),
            _ => None,
        });
        let cell = entries.next().ok_or_else(|| invalid(format!("no provisioned cell for {role}")))?;
        if entries.next().is_some() { return Err(invalid(format!("ambiguous provisioned cells for {role}"))); }
        Ok(cell)
    };
    let music = one_cell(&opts.catalogue_role)?;
    let storage = one_cell(&opts.storage_role)?;
    if music.dna_hash().to_string() != opts.catalogue_dna || storage.dna_hash().to_string() != opts.storage_dna {
        return Err(invalid("installed app's DNA hashes do not match required trusted pins"));
    }
    if music.agent_pubkey() != storage.agent_pubkey() {
        return Err(invalid("catalogue and storage roles are not installed for the same agent"));
    }

    // Signing credentials authorise zome *reads*, not signing a manifest or
    // accessing either artist/node secret signing key.
    let signer = ClientAgentSigner::default();
    for cell in [&music, &storage] {
        let credentials = admin.authorize_signing_credentials(
            AuthorizeSigningCredentialsPayload { cell_id: cell.clone(), functions: None }
        ).await?;
        signer.add_credentials(cell.clone(), credentials);
    }
    let app_port = admin.attach_app_interface(
        0, None, AllowedOrigins::from(ORIGIN.to_string()), Some(opts.app_id.clone())
    ).await?;
    let token = admin.issue_app_auth_token(opts.app_id.clone().into()).await?.token;
    let dyn_signer: DynAgentSigner = signer.into();
    let app = AppWebsocket::connect(
        (std::net::Ipv4Addr::LOCALHOST, app_port), token, dyn_signer, Some(ORIGIN.into())
    ).await?;
    let reader_agent = music.agent_pubkey().to_string();
    if app.my_pub_key != *music.agent_pubkey() {
        return Err(invalid("app socket agent differs from the selected app cells"));
    }

    let artist = opts.artist.to_string();
    let node = opts.node.to_string();
    let track: Option<AuthoredRecord> = call(&app, &opts.catalogue_role, CATALOGUE_ZOME, "get_track", &TrackLookup {
        artist: opts.artist.clone(), track_id: opts.track_id.clone(),
    }).await?;
    let track = track.ok_or_else(|| invalid("track not found on authenticated catalogue"))?.checked(&artist)?;
    if track.body.get("artist_agent").and_then(Value::as_str) != Some(artist.as_str())
        || track.body.get("track_id").and_then(Value::as_str) != Some(opts.track_id.as_str()) {
        return Err(invalid("track entry identity mismatch"));
    }
    let file_id = track.body.get("file_id").and_then(Value::as_str)
        .ok_or_else(|| invalid("track lacks file ID"))?.to_string();
    let digest = track.body.get("manifest_sha256").and_then(Value::as_str)
        .ok_or_else(|| invalid("track lacks signed-manifest digest"))?.to_string();

    let owner_keys: Vec<AuthoredRecord> = call(&app, &opts.storage_role, STORAGE_ZOME, "get_signing_keys", &opts.artist).await?;
    let owner_key_binding = choose_unique(owner_keys, &artist, |b|
        b.get("purpose").and_then(Value::as_str) == Some("owner-manifest")
        && b.get("agent").and_then(Value::as_str) == Some(artist.as_str()), "owner signing-key binding")?;
    let file_rows: Vec<AuthoredRecord> = call(&app, &opts.storage_role, STORAGE_ZOME, "get_file_commitments", &opts.artist).await?;
    let owner_commitment = choose_unique(file_rows, &artist, |b|
        b.get("file_id").and_then(Value::as_str) == Some(file_id.as_str()), "owner file commitment")?;
    if owner_commitment.body.get("manifest_sha256").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(invalid("owner commitment does not match the catalogue manifest digest"));
    }

    let node_keys: Vec<AuthoredRecord> = call(&app, &opts.storage_role, STORAGE_ZOME, "get_signing_keys", &opts.node).await?;
    let node_key_binding = choose_unique(node_keys, &node, |b|
        b.get("purpose").and_then(Value::as_str) == Some("host-receipt")
        && b.get("agent").and_then(Value::as_str) == Some(node.as_str()), "storage-node signing-key binding")?;
    let node_rows: Vec<AuthoredRecord> = call(&app, &opts.storage_role, STORAGE_ZOME, "get_replica_claims", &FileLookup {
        owner_agent: artist.clone(), file_id: file_id.clone(),
    }).await?;
    let replica_claim = choose_unique(node_rows, &node, |b|
        b.get("node_agent").and_then(Value::as_str) == Some(node.as_str())
        && b.get("owner_agent").and_then(Value::as_str) == Some(artist.as_str())
        && b.get("file_id").and_then(Value::as_str) == Some(file_id.as_str()), "node replica claim")?;
    if replica_claim.body.get("manifest_sha256").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err(invalid("node replica claim does not match the catalogue manifest digest"));
    }

    Ok(BridgeResult {
        schema: RESPONSE_SCHEMA,
        app_id: opts.app_id,
        reader_agent,
        catalogue_dna: music.dna_hash().to_string(),
        storage_dna: storage.dna_hash().to_string(),
        track, owner_key_binding, owner_commitment, node_key_binding, replica_claim,
    })
}

#[tokio::main]
async fn main() {
    let result = async {
        let opts = Options::parse()?;
        let output = collect(opts).await?;
        println!("{}", serde_json::to_string(&output)?);
        Result::<()>::Ok(())
    }.await;
    if let Err(error) = result {
        eprintln!("music-conductor-bridge: {error}");
        std::process::exit(1);
    }
}
