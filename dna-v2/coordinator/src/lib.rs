//! S2 storage DNA **v2** coordinator zome.
//!
//! Compiles the UNCHANGED v1 coordinator source (`../../dna/coordinator`)
//! against the v2 integrity crate, and adds the key-binding v2 functions.
//! No private key is ever passed to these functions: the caller signs the
//! proof of possession locally.

#[path = "../../../dna/coordinator/src/lib.rs"]
mod v1;
pub use v1::*;

use hdk::prelude::*;
use music_storage_integrity::{EntryTypes, LinkTypes, SigningKeyBindingV2};

/// What a key holder must sign for a v2 binding on this cell. Returned by the
/// local conductor, so the client signs for the DNA and agent it runs as.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyBindingV2Context {
    pub schema: String,
    pub dna_hash: String,
    pub agent: String,
    pub generation: String,
}

#[hdk_extern]
pub fn key_binding_v2_context(_: ()) -> ExternResult<KeyBindingV2Context> {
    Ok(KeyBindingV2Context {
        schema: music_storage_integrity::KEY_SCHEMA_V2.into(),
        dna_hash: dna_info()?.hash.to_string(),
        agent: agent_info()?.agent_initial_pubkey.to_string(),
        generation: music_storage_integrity::KEY_GENERATION_V2.into(),
    })
}

/// Deliberately thin: it performs NO checks of its own, so every accept or
/// reject decision for a v2 binding is made by the integrity zome's
/// validation (the trust boundary), and tests through this function exercise
/// exactly those rules.
#[hdk_extern]
pub fn register_signing_key_v2(entry: SigningKeyBindingV2) -> ExternResult<ActionHash> {
    let agent = agent_info()?.agent_initial_pubkey;
    let hash = create_entry(EntryTypes::SigningKeyBindingV2(entry))?;
    create_link(agent, hash.clone(), LinkTypes::AgentToKeyV2, ())?;
    Ok(hash)
}

/// Validated v2 bindings authored by `agent` (author == body agent). Readers
/// still verify the proof themselves and apply an explicit uniqueness policy.
#[hdk_extern]
pub fn get_signing_keys_v2(agent: AgentPubKey) -> ExternResult<Vec<AuthoredRecord<SigningKeyBindingV2>>> {
    let expected = agent.to_string();
    let mut rows = Vec::new();
    let mut links = get_links(LinkQuery::try_new(agent, LinkTypes::AgentToKeyV2)?, GetStrategy::default())?;
    links.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    for link in links {
        let Some(hash) = link.target.clone().into_action_hash() else { continue };
        let Some(record) = get(hash.clone(), GetOptions::default())? else { continue };
        let Some(body) = record.entry().to_app_option::<SigningKeyBindingV2>().map_err(|e|
            wasm_error!(WasmErrorInner::Guest(e.to_string())))? else { continue };
        let author = record.action().author().to_string();
        if author == expected && body.agent == expected {
            rows.push(AuthoredRecord { author, action_hash: hash, body });
        }
    }
    Ok(rows)
}
