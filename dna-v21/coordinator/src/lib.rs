//! S2 storage DNA **v2.1** coordinator zome.
//!
//! Compiles the UNCHANGED v1 coordinator source (`../../dna/coordinator`)
//! against the v2.1 integrity crate, and adds the key-lifecycle functions.
//! No private key is ever passed to these functions: the client signs proofs
//! and continuity signatures locally and submits only public data.
//!
//! The write functions are deliberately check-free: every accept/reject
//! decision is made by integrity validation (the trust boundary), so tests
//! through them exercise exactly those rules.

#[path = "../../../dna/coordinator/src/lib.rs"]
mod v1;
pub use v1::*;

use hdk::prelude::*;
use music_storage_integrity::{
    EntryTypes, KeyRevocationV21, KeyTransitionV21, LinkTypes, UnitEntryTypes,
    KEY_LIFECYCLE_SCHEMA_V21,
};

/// What a client must sign for the next transition of `purpose` on this cell,
/// computed from the agent's OWN local source chain. Convenience only: the
/// integrity zome re-derives and enforces all of it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyLifecycleV21Context {
    pub schema: String,
    pub dna_hash: String,
    pub agent: String,
    pub purpose: String,
    /// Generation the next transition must carry.
    pub next_generation: String,
    /// Empty when the next transition must be an inception.
    pub predecessor_action: String,
    pub predecessor_key_hex: String,
    pub predecessor_generation: String,
    /// True when the current key was revoked (only a recovery may follow).
    pub predecessor_revoked: bool,
}

/// A lifecycle record with its position on the author's chain. `body` is a
/// transition or a revocation (distinguished by its `schema`).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SequencedRecord<T> {
    pub author: String,
    pub action_hash: ActionHash,
    pub action_seq: u32,
    pub body: T,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum LifecycleBody {
    Transition(KeyTransitionV21),
    Revocation(KeyRevocationV21),
}

/// Position of any action on its author's chain (used to anchor historical
/// artifacts such as file commitments and replica claims before a revocation).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ActionPosition {
    pub author: String,
    pub action_hash: ActionHash,
    pub action_seq: u32,
}

fn own_lifecycle(purpose: &str) -> ExternResult<Vec<(ActionHash, u32, LifecycleBody)>> {
    let filter = ChainQueryFilter::new()
        .entry_type(EntryType::try_from(UnitEntryTypes::KeyTransitionV21)?)
        .entry_type(EntryType::try_from(UnitEntryTypes::KeyRevocationV21)?)
        .include_entries(true)
        .ascending();
    let mut rows = Vec::new();
    for record in query(filter)? {
        let hash = record.action_address().clone();
        let seq = record.action().action_seq();
        let decode = |e: SerializedBytesError| wasm_error!(WasmErrorInner::Guest(e.to_string()));
        if let Ok(Some(t)) = record.entry().to_app_option::<KeyTransitionV21>() {
            if t.schema == KEY_LIFECYCLE_SCHEMA_V21 && t.purpose == purpose {
                rows.push((hash, seq, LifecycleBody::Transition(t)));
            }
        } else if let Some(r) = record.entry().to_app_option::<KeyRevocationV21>().map_err(decode)? {
            if r.purpose == purpose {
                rows.push((hash, seq, LifecycleBody::Revocation(r)));
            }
        }
    }
    Ok(rows)
}

#[hdk_extern]
pub fn key_lifecycle_v21_context(purpose: String) -> ExternResult<KeyLifecycleV21Context> {
    let rows = own_lifecycle(&purpose)?;
    let last = rows.iter().rev().find_map(|(h, _, b)| match b {
        LifecycleBody::Transition(t) => Some((h.clone(), t.clone())),
        LifecycleBody::Revocation(_) => None,
    });
    let (next_generation, predecessor_action, predecessor_key_hex, predecessor_generation, revoked) =
        match last {
            None => ("1".to_string(), String::new(), String::new(), String::new(), false),
            Some((hash, t)) => {
                let generation: u32 = t.generation.parse().unwrap_or(0);
                let revoked = rows.iter().any(|(_, _, b)| matches!(b,
                    LifecycleBody::Revocation(r) if r.target_action == hash.to_string()));
                ((generation + 1).to_string(), hash.to_string(), t.signing_key_hex, t.generation, revoked)
            }
        };
    Ok(KeyLifecycleV21Context {
        schema: KEY_LIFECYCLE_SCHEMA_V21.into(),
        dna_hash: dna_info()?.hash.to_string(),
        agent: agent_info()?.agent_initial_pubkey.to_string(),
        purpose,
        next_generation,
        predecessor_action,
        predecessor_key_hex,
        predecessor_generation,
        predecessor_revoked: revoked,
    })
}

/// Publish a transition (inception, rotation or recovery). No checks here.
#[hdk_extern]
pub fn publish_key_transition_v21(entry: KeyTransitionV21) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::KeyTransitionV21(entry))?;
    create_link(agent, hash.clone(), LinkTypes::AgentToKeyLifecycleV21, ())?;
    Ok(hash)
}

/// Publish a revocation. No checks here.
#[hdk_extern]
pub fn publish_key_revocation_v21(entry: KeyRevocationV21) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::KeyRevocationV21(entry))?;
    create_link(agent, hash.clone(), LinkTypes::AgentToKeyLifecycleV21, ())?;
    Ok(hash)
}

/// Validated lifecycle records authored by `agent`, with their chain
/// positions, in chain order. Readers verify every record themselves and
/// resolve the lifecycle by predecessor references, never by timestamp.
#[hdk_extern]
pub fn get_key_lifecycle_v21(agent: AgentPubKey) -> ExternResult<Vec<SequencedRecord<LifecycleBody>>> {
    let expected = agent.to_string();
    let links = get_links(LinkQuery::try_new(agent, LinkTypes::AgentToKeyLifecycleV21)?, GetStrategy::default())?;
    let mut rows = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for link in links {
        let Some(hash) = link.target.clone().into_action_hash() else { continue };
        if !seen.insert(hash.clone()) {
            continue;
        }
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue };
        let author = record.action().author().to_string();
        if author != expected {
            continue;
        }
        let decode = |e: SerializedBytesError| wasm_error!(WasmErrorInner::Guest(e.to_string()));
        let body = if let Ok(Some(t)) = record.entry().to_app_option::<KeyTransitionV21>() {
            LifecycleBody::Transition(t)
        } else if let Some(r) = record.entry().to_app_option::<KeyRevocationV21>().map_err(decode)? {
            LifecycleBody::Revocation(r)
        } else {
            continue;
        };
        rows.push(SequencedRecord { author, action_hash: hash, action_seq: record.action().action_seq(), body });
    }
    rows.sort_by_key(|r| r.action_seq);
    Ok(rows)
}

/// Chain position of a validated action (any type), for historical anchoring.
#[hdk_extern]
pub fn get_action_position_v21(action_hash: ActionHash) -> ExternResult<Option<ActionPosition>> {
    Ok(get(action_hash.clone(), GetOptions::default())?.map(|record| ActionPosition {
        author: record.action().author().to_string(),
        action_hash,
        action_seq: record.action().action_seq(),
    }))
}
