//! S2 authenticated metadata only. No file payload, ciphertext chunk, or key secret.
//! Holochain action authorship binds a claimed agent to a public Ed25519 key,
//! an encrypted file commitment, or a node's claim to hold a replica.
//! Receipts and manifest signatures are verified by the client, not the DHT.

use hdi::prelude::*;

pub const KEY_SCHEMA: &str = "holochain-storage/key-binding/v1";
pub const FILE_SCHEMA: &str = "holochain-storage/file-commitment/v1";
pub const REPLICA_SCHEMA: &str = "holochain-storage/replica-claim/v1";
pub const MOQ_SCHEMA: &str = "holochain-storage/moq-endpoint/v1";

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyBinding {
    pub schema: String,
    pub agent: String,
    pub purpose: String, // owner-manifest or host-receipt
    pub signing_key_hex: String, // public Ed25519 key only; 32 bytes, hex
}

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FileCommitment {
    pub schema: String,
    pub owner_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
}

#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReplicaClaim {
    pub schema: String,
    pub node_agent: String,
    pub owner_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
    pub receipt_sha256: String,
}

/// Host-authored binding from a particular S1 file to one QUIC/TLS server.
/// Never includes an artist secret, storage signing secret, or AES content key.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MoqEndpoint {
    pub schema: String,
    pub node_agent: String,
    pub owner_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
    pub url: String,
    pub cert_fingerprint_hex: String,
}

/// S9 local-only test network. Internet address / port policy is a separate
/// release gate; this MVP only registers loopback HTTPS/QUIC endpoints.
pub fn valid_moq_url(url: &str) -> bool {
    let Some(port) = url.strip_prefix("https://127.0.0.1:") else { return false; };
    !port.is_empty() && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|n| n != 0)
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    SigningKeyBinding(SigningKeyBinding),
    FileCommitment(FileCommitment),
    ReplicaClaim(ReplicaClaim),
    MoqEndpoint(MoqEndpoint),
}

#[hdk_link_types]
pub enum LinkTypes {
    AgentToKey,
    AgentToFile,
    FileToReplica,
    Anchor,
    AgentToMoqEndpoint,
}

#[hdk_extern]
pub fn genesis_self_check(_data: GenesisSelfCheckData) -> ExternResult<ValidateCallbackResult> {
    Ok(ValidateCallbackResult::Valid)
}

pub fn is_hex32(s: &str) -> bool {
    s.len() == 64 && s.as_bytes().iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

fn invalid(msg: impl Into<String>) -> ValidateCallbackResult {
    ValidateCallbackResult::Invalid(msg.into())
}

fn check_author(author: &AgentPubKey, claimed: &str) -> Result<(), String> {
    if author.to_string() == claimed {
        Ok(())
    } else {
        Err(format!("entry claims {claimed}, actual Holochain action author is {author}"))
    }
}

/// Deterministic, local checks only. Do not attempt network reads in validation.
fn validate_app_entry(author: &AgentPubKey, entry: &EntryTypes) -> ValidateCallbackResult {
    let result: Result<(), String> = match entry {
        EntryTypes::SigningKeyBinding(k) => {
            check_author(author, &k.agent).and_then(|_| {
                if k.schema != KEY_SCHEMA
                    || (k.purpose != "owner-manifest" && k.purpose != "host-receipt")
                    || !is_hex32(&k.signing_key_hex) {
                    Err("invalid signer key schema, purpose, or public key".into())
                } else { Ok(()) }
            })
        }
        EntryTypes::FileCommitment(f) => {
            check_author(author, &f.owner_agent).and_then(|_| {
                if f.schema != FILE_SCHEMA || !is_hex32(&f.file_id) || !is_hex32(&f.manifest_sha256) {
                    Err("invalid file commitment metadata".into())
                } else { Ok(()) }
            })
        }
        EntryTypes::ReplicaClaim(r) => {
            check_author(author, &r.node_agent).and_then(|_| {
                if r.schema != REPLICA_SCHEMA || r.owner_agent.is_empty() || r.owner_agent.len() > 160
                    || !is_hex32(&r.file_id) || !is_hex32(&r.manifest_sha256) || !is_hex32(&r.receipt_sha256) {
                    Err("invalid replica claim metadata".into())
                } else { Ok(()) }
            })
        }
        EntryTypes::MoqEndpoint(endpoint) => {
            check_author(author, &endpoint.node_agent).and_then(|_| {
                if endpoint.schema != MOQ_SCHEMA
                    || endpoint.owner_agent.is_empty() || endpoint.owner_agent.len() > 160
                    || !is_hex32(&endpoint.file_id)
                    || !is_hex32(&endpoint.manifest_sha256)
                    || !is_hex32(&endpoint.cert_fingerprint_hex)
                    || !valid_moq_url(&endpoint.url)
                {
                    Err("invalid host-authored MoQ endpoint metadata".into())
                } else { Ok(()) }
            })
        }
    };
    match result { Ok(()) => ValidateCallbackResult::Valid, Err(reason) => invalid(reason) }
}

/// Author may only link their own key/commitment entries from their agent key.
fn validate_agent_link(action: &TypedAction<CreateLinkData>) -> ExternResult<ValidateCallbackResult> {
    let Some(base_agent) = action.base_address.clone().into_agent_pub_key() else {
        return Ok(invalid("agent index must use AgentPubKey base"));
    };
    if &base_agent != action.author() {
        return Ok(invalid("only the owning agent may create agent index links"));
    }
    validate_owned_target(action)
}

/// A storage node can only index an entry *it authored* as its own claim.
fn validate_owned_target(action: &TypedAction<CreateLinkData>) -> ExternResult<ValidateCallbackResult> {
    let Some(target) = action.target_address.clone().into_action_hash() else {
        return Ok(invalid("index target must be an ActionHash"));
    };
    let target_action = must_get_action(target)?;
    if target_action.action().author() != action.author() {
        return Ok(invalid("index target must be authored by the index writer"));
    }
    Ok(ValidateCallbackResult::Valid)
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    match op.flattened::<EntryTypes, LinkTypes>()? {
        FlatOp::CreateEntry(OpEntry::CreateEntry { app_entry, action }) =>
            Ok(validate_app_entry(action.author(), &app_entry)),
        FlatOp::CreateEntry(_) => Ok(ValidateCallbackResult::Valid),
        FlatOp::Link(OpLink::CreateLink { link_type, action }) => match link_type {
            LinkTypes::AgentToKey | LinkTypes::AgentToFile | LinkTypes::AgentToMoqEndpoint => validate_agent_link(&action),
            LinkTypes::FileToReplica => validate_owned_target(&action),
            LinkTypes::Anchor => Ok(ValidateCallbackResult::Valid),
        },
        FlatOp::Link(OpLink::DeleteLink { .. }) => Ok(invalid("index links are append-only")),
        FlatOp::Update(_) => Ok(invalid("metadata entries are append-only")),
        FlatOp::Delete(_) => Ok(invalid("metadata entries cannot be deleted")),
        FlatOp::CreateRecord(_) | FlatOp::AgentActivity(_) => Ok(ValidateCallbackResult::Valid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_lowercase_sha_256_and_key_hex() {
        assert!(is_hex32(&"a".repeat(64)));
        assert!(is_hex32(&"0".repeat(64)));
        assert!(!is_hex32(&"A".repeat(64)));
        assert!(!is_hex32("123"));
        assert!(!is_hex32(&"g".repeat(64)));
    }
    #[test]
    fn endpoint_urls_are_loopback_only_and_port_validated() {
        assert!(valid_moq_url("https://127.0.0.1:443"));
        assert!(valid_moq_url("https://127.0.0.1:65535"));
        assert!(!valid_moq_url("https://127.0.0.1:0"));
        assert!(!valid_moq_url("https://127.0.0.1:65536"));
        assert!(!valid_moq_url("https://example.org:443"));
        assert!(!valid_moq_url("https://127.0.0.1:443/bad"));
    }
}
