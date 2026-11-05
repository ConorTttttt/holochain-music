//! Storage metadata zome: key bindings, signed file commitments, signed host
//! claims. NO encrypted chunks or secret keys in entries or network calls.
//! An authenticated local Holochain conductor returns the action authors.

use hdk::prelude::*;
use music_storage_integrity::{
    AccessRequest, EntryTypes, FileCommitment, GrantRecord, LinkTypes, ListenerKeyBinding,
    MoqEndpoint, ReplicaClaim, SigningKeyBinding,
};

/// Hard cap on rows returned from a link index anyone can write to.
const MAX_INDEX_ROWS: usize = 200;

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

/// Listener publishes the X25519 public key artists should wrap grants to.
#[hdk_extern]
pub fn register_listener_key(entry: ListenerKeyBinding) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::ListenerKeyBinding(entry))?;
    create_link(agent, hash.clone(), LinkTypes::AgentToListenerKey, ())?;
    Ok(hash)
}

#[hdk_extern]
pub fn get_listener_keys(agent: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<ListenerKeyBinding>>> {
    let expected = agent.to_string();
    Ok(linked_records::<ListenerKeyBinding>(agent, LinkTypes::AgentToListenerKey)?
        .into_iter().filter(|r| r.author == expected && r.body.agent == expected).collect())
}

/// Listener asks an artist for access. Carries only public data.
#[hdk_extern]
pub fn request_access(entry: AccessRequest) -> ExternResult<ActionHash> {
    let owner = AgentPubKey::try_from(entry.owner_agent.as_str())
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("invalid owner agent: {e}"))))?;
    let hash = create_entry(EntryTypes::AccessRequest(entry))?;
    create_link(owner, hash.clone(), LinkTypes::OwnerToAccessRequest, ())?;
    Ok(hash)
}

/// Requests addressed to the calling agent (artist). Newest first, bounded.
#[hdk_extern]
pub fn get_my_access_requests(_: ()) -> ExternResult<Vec<AuthoredRecord<AccessRequest>>> {
    let me = agent_info()?.agent_initial_pubkey;
    let expected = me.to_string();
    let mut rows: Vec<_> = linked_records::<AccessRequest>(me, LinkTypes::OwnerToAccessRequest)?
        .into_iter().filter(|r| r.author == r.body.listener_agent && r.body.owner_agent == expected)
        .collect();
    rows.reverse();
    rows.truncate(MAX_INDEX_ROWS);
    Ok(rows)
}

/// Artist delivers a signed grant to a listener through the DHT.
#[hdk_extern]
pub fn publish_grant(entry: GrantRecord) -> ExternResult<ActionHash> {
    let listener = AgentPubKey::try_from(entry.listener_agent.as_str())
        .map_err(|e| wasm_error!(WasmErrorInner::Guest(format!("invalid listener agent: {e}"))))?;
    let hash = create_entry(EntryTypes::GrantRecord(entry))?;
    create_link(listener, hash.clone(), LinkTypes::ListenerToGrant, ())?;
    Ok(hash)
}

/// Grant records addressed to the calling agent, newest first, bounded.
/// Callers must still verify every inner grant signature and binding.
#[hdk_extern]
pub fn get_my_grants(_: ()) -> ExternResult<Vec<AuthoredRecord<GrantRecord>>> {
    let me = agent_info()?.agent_initial_pubkey;
    let expected = me.to_string();
    let mut rows: Vec<_> = linked_records::<GrantRecord>(me, LinkTypes::ListenerToGrant)?
        .into_iter().filter(|r| r.author == r.body.owner_agent && r.body.listener_agent == expected)
        .collect();
    rows.reverse();
    rows.truncate(MAX_INDEX_ROWS);
    Ok(rows)
}
