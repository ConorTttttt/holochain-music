//! Storage metadata zome: key bindings, signed file commitments, signed host
//! claims. NO encrypted chunks or secret keys in entries or network calls.
//! An authenticated local Holochain conductor returns the action authors.

use hdk::prelude::*;
use music_storage_integrity::{
    EntryTypes, FileCommitment, InboxAccessRequest, InboxGrant, LinkTypes, MoqEndpoint,
    ReplicaClaim, SigningKeyBinding, UnitEntryTypes,
};
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoredRecord<T> {
    pub author: String,
    pub action_hash: ActionHash,
    pub body: T,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileLookup {
    pub owner_agent: String,
    pub file_id: String,
}

fn replica_path(owner: &str, file_id: &str) -> String {
    format!("file.{owner}.{file_id}")
}

fn typed_path(value: String) -> ExternResult<TypedPath> {
    Path::from(value).typed(LinkTypes::Anchor)
}

fn linked_records<T>(base: impl Into<AnyLinkableHash>, lt: LinkTypes) -> ExternResult<Vec<AuthoredRecord<T>>>
where
    T: TryFrom<SerializedBytes, Error = SerializedBytesError>,
{
    let mut rows = Vec::new();
    let mut links = get_links(LinkQuery::try_new(base, lt)?, GetStrategy::default())?;
    links.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    for link in links {
        let Some(hash) = link.target.clone().into_action_hash() else { continue };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue };
        let Some(body) = record.entry().to_app_option::<T>().map_err(|e|
            wasm_error!(WasmErrorInner::Guest(e.to_string())))? else { continue };
        rows.push(AuthoredRecord {
            author: record.action().author().to_string(),
            action_hash: hash,
            body,
        });
    }
    Ok(rows)
}

/// Any signed manifest must already have its key bound through this zome.
/// Agent identity is enforced by integrity validation, not by trusting caller inputs.
#[hdk_extern]
pub fn register_signing_key(entry: SigningKeyBinding) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::SigningKeyBinding(entry))?;
    create_link(agent, hash.clone(), LinkTypes::AgentToKey, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_signing_keys(agent: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<SigningKeyBinding>>> {
    let expected = agent.to_string();
    Ok(linked_records::<SigningKeyBinding>(agent, LinkTypes::AgentToKey)?
        .into_iter().filter(|r| r.author == expected && r.body.agent == expected).collect())
}

/// A public commitment identifies a signed ciphertext manifest without storing
/// the full manifest or secret content key on Holochain's DHT.
#[hdk_extern]
pub fn publish_file_commitment(entry: FileCommitment) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::FileCommitment(entry))?;
    create_link(me, hash.clone(), LinkTypes::AgentToFile, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_file_commitments(agent: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<FileCommitment>>> {
    let expected = agent.to_string();
    Ok(linked_records::<FileCommitment>(agent, LinkTypes::AgentToFile)?
        .into_iter().filter(|r| r.author == expected && r.body.owner_agent == expected).collect())
}

/// Host's append-only *claim*, not a proof of continued possession.
#[hdk_extern]
pub fn publish_replica_claim(entry: ReplicaClaim) -> ExternResult<ActionHash> {
    let index = typed_path(replica_path(&entry.owner_agent, &entry.file_id))?;
    index.ensure()?;
    let hash = create_entry(EntryTypes::ReplicaClaim(entry))?;
    create_link(index.path_entry_hash()?, hash.clone(), LinkTypes::FileToReplica, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_replica_claims(lookup: FileLookup) -> ExternResult<Vec<AuthoredRecord<ReplicaClaim>>> {
    let base = typed_path(replica_path(&lookup.owner_agent, &lookup.file_id))?.path_entry_hash()?;
    Ok(linked_records::<ReplicaClaim>(base, LinkTypes::FileToReplica)?
        .into_iter().filter(|r| r.author == r.body.node_agent
            && r.body.owner_agent == lookup.owner_agent
            && r.body.file_id == lookup.file_id).collect())
}

/// Host agent advertises QUIC endpoint and cert fingerprint for one encrypted
/// package; its author must equal `node_agent` (enforced in integrity zome).
#[hdk_extern]
pub fn publish_moq_endpoint(endpoint: MoqEndpoint) -> ExternResult<ActionHash> {
    let me = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::MoqEndpoint(endpoint))?;
    create_link(me, hash.clone(), LinkTypes::AgentToMoqEndpoint, ())?;
    Ok(hash)
}

/// Return action-authenticated host endpoint bindings. Readers MUST reject
/// missing/ambiguous bindings for their target file and manifest SHA-256.
#[hdk_extern]
pub fn get_moq_endpoints(host: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<MoqEndpoint>>> {
    let expected = host.to_string();
    Ok(linked_records::<MoqEndpoint>(host, LinkTypes::AgentToMoqEndpoint)?
        .into_iter().filter(|r| r.author == expected && r.body.node_agent == expected).collect())
}

// ---- private access-request / grant inbox (no DHT linkage) -------------
//
// Listener and artist exchange requests and grants by authenticated remote
// zome call. The recipient stores each message as a PRIVATE entry on its own
// chain; nothing linking a listener to a track is published to the DHT. Both
// peers must be online at the same time; the sender gets an explicit error
// otherwise and may retry.

const INBOX_TAG: &str = "holochain-music-private-inbox";
const MAX_INBOX: usize = 2000;
const MAX_PER_SENDER: usize = 50;

#[hdk_extern]
pub fn init(_: ()) -> ExternResult<InitCallbackResult> {
    let zome = zome_info()?.name;
    let mut functions = HashSet::new();
    functions.insert((zome.clone(), FunctionName::from("receive_access_request")));
    functions.insert((zome, FunctionName::from("receive_grant")));
    // Only these two inbox functions are remote-callable by any agent.
    create_cap_grant(ZomeCallCapGrant {
        tag: INBOX_TAG.into(),
        access: CapAccess::Unrestricted,
        functions: GrantedFunctions::Listed(functions),
    })?;
    Ok(InitCallbackResult::Pass)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessRequestPayload {
    pub file_id: String,
    pub manifest_sha256: String,
    pub x25519_public_hex: String,
    pub kind: String,
    pub note: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GrantPayload {
    pub file_id: String,
    pub manifest_sha256: String,
    pub kind: String,
    pub grant_json: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendAccessRequest {
    pub owner: AgentPubKey,
    pub request: AccessRequestPayload,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SendGrant {
    pub listener: AgentPubKey,
    pub grant: GrantPayload,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InboxRow<T> {
    pub action_hash: ActionHash,
    pub received_at: Timestamp,
    pub body: T,
}

fn guest(msg: impl Into<String>) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(msg.into()))
}

fn remote(agent: AgentPubKey, func: &str, payload: impl Serialize + std::fmt::Debug) -> ExternResult<()> {
    match call_remote(agent, zome_info()?.name, func.into(), None, payload)? {
        ZomeCallResponse::Ok(_) => Ok(()),
        ZomeCallResponse::NetworkError(e) => Err(guest(format!("recipient unreachable (offline?): {e}"))),
        ZomeCallResponse::Unauthorized(..) => Err(guest("recipient refused the delivery")),
        other => Err(guest(format!("delivery failed: {other:?}"))),
    }
}

fn inbox<T>(entry_type: UnitEntryTypes) -> ExternResult<Vec<InboxRow<T>>>
where
    T: TryFrom<SerializedBytes, Error = SerializedBytesError>,
{
    let filter = ChainQueryFilter::new().entry_type(entry_type.try_into()?).include_entries(true);
    let mut rows = Vec::new();
    for record in query(filter)? {
        if let Ok(Some(body)) = record.entry().to_app_option::<T>() {
            rows.push(InboxRow { action_hash: record.action_address().clone(),
                                 received_at: record.action().timestamp(), body });
        }
    }
    rows.reverse();
    Ok(rows)
}

fn sender_check(sender: &AgentPubKey, existing: impl Iterator<Item = String>) -> ExternResult<()> {
    let me = agent_info()?.agent_initial_pubkey;
    if sender == &me {
        return Err(guest("cannot deliver to yourself"));
    }
    let all: Vec<String> = existing.collect();
    let theirs = all.iter().filter(|a| a.as_str() == sender.to_string()).count();
    if all.len() >= MAX_INBOX || theirs >= MAX_PER_SENDER {
        return Err(guest("recipient inbox is full"));
    }
    Ok(())
}

/// Listener: deliver an access request privately to the artist's cell.
#[hdk_extern]
pub fn send_access_request(input: SendAccessRequest) -> ExternResult<()> {
    remote(input.owner, "receive_access_request", input.request)
}

/// Artist cell (remote-callable): store the request as a private entry.
#[hdk_extern]
pub fn receive_access_request(payload: AccessRequestPayload) -> ExternResult<ActionHash> {
    let sender = call_info()?.provenance;
    let existing = inbox::<InboxAccessRequest>(UnitEntryTypes::InboxAccessRequest)?;
    sender_check(&sender, existing.into_iter().map(|r| r.body.listener_agent))?;
    create_entry(EntryTypes::InboxAccessRequest(InboxAccessRequest {
        schema: music_storage_integrity::INBOX_REQUEST_SCHEMA.into(),
        listener_agent: sender.to_string(),
        file_id: payload.file_id, manifest_sha256: payload.manifest_sha256,
        x25519_public_hex: payload.x25519_public_hex, kind: payload.kind, note: payload.note,
    }))
}

#[hdk_extern]
pub fn get_inbox_access_requests(_: ()) -> ExternResult<Vec<InboxRow<InboxAccessRequest>>> {
    inbox(UnitEntryTypes::InboxAccessRequest)
}

/// Artist: deliver a signed grant privately to the listener's cell.
#[hdk_extern]
pub fn send_grant(input: SendGrant) -> ExternResult<()> {
    remote(input.listener, "receive_grant", input.grant)
}

/// Listener cell (remote-callable): store the grant as a private entry.
#[hdk_extern]
pub fn receive_grant(payload: GrantPayload) -> ExternResult<ActionHash> {
    let sender = call_info()?.provenance;
    let existing = inbox::<InboxGrant>(UnitEntryTypes::InboxGrant)?;
    sender_check(&sender, existing.into_iter().map(|r| r.body.owner_agent))?;
    create_entry(EntryTypes::InboxGrant(InboxGrant {
        schema: music_storage_integrity::INBOX_GRANT_SCHEMA.into(),
        owner_agent: sender.to_string(),
        file_id: payload.file_id, manifest_sha256: payload.manifest_sha256,
        kind: payload.kind, grant_json: payload.grant_json,
    }))
}

#[hdk_extern]
pub fn get_inbox_grants(_: ()) -> ExternResult<Vec<InboxRow<InboxGrant>>> {
    inbox(UnitEntryTypes::InboxGrant)
}
