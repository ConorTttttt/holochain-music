//! S2 authenticated metadata only. No file payload, ciphertext chunk, or key secret.
//! Holochain action authorship binds a claimed agent to a public Ed25519 key,
//! an encrypted file commitment, or a node's claim to hold a replica.
//! Receipts and manifest signatures are verified by the client, not the DHT.

use hdi::prelude::*;

pub const KEY_SCHEMA: &str = "holochain-storage/key-binding/v1";
pub const FILE_SCHEMA: &str = "holochain-storage/file-commitment/v1";
pub const REPLICA_SCHEMA: &str = "holochain-storage/replica-claim/v1";
pub const MOQ_SCHEMA: &str = "holochain-storage/moq-endpoint/v1";
pub const INBOX_REQUEST_SCHEMA: &str = "holochain-music/inbox-access-request/v1";
pub const INBOX_GRANT_SCHEMA: &str = "holochain-music/inbox-grant/v1";
pub const INBOX_DECISION_SCHEMA: &str = "holochain-music/inbox-decision/v1";
/// Signed grant JSON envelopes are small (S10 grants are capped at 4 KiB).
pub const MAX_GRANT_JSON_BYTES: usize = 8192;
pub const GRANT_KINDS: [&str; 2] = ["stream", "perpetual-personal"];

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

/// PRIVATE entry on the *artist's* source chain: an access request received
/// through an authenticated remote call. `listener_agent` is the remote call's
/// provenance as verified by the artist's conductor, never a caller field.
/// Private entries are not published to the DHT; only the action (type,
/// entry hash, time) appears in the author's agent activity.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InboxAccessRequest {
    pub schema: String,
    /// 16 random bytes (hex) chosen by the recipient; hides the entry hash.
    pub nonce: String,
    pub listener_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
    pub x25519_public_hex: String,
    pub kind: String,
    pub note: String,
    /// Listener-generated correlation ID. Optional for pre-upgrade requests.
    #[serde(default)]
    pub request_id: Option<String>,
}

/// PRIVATE entry on the *listener's* source chain: an artist-signed grant
/// delivered by remote call. `owner_agent` is the call provenance. The grant's
/// own Ed25519 signature is still verified by the client before use.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InboxGrant {
    pub schema: String,
    pub owner_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
    pub kind: String,
    pub grant_json: String,
}

/// PRIVATE listener-source-chain status. Provenance is established by the
/// receiver's conductor and checked against the locally requested artist.
/// A decline is never a licence or a revocation of an existing grant.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InboxDecision {
    pub schema: String,
    pub owner_agent: String,
    pub file_id: String,
    pub manifest_sha256: String,
    pub kind: String,
    pub request_id: Option<String>,
    pub decision: String,
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.len() <= 5
        && port.bytes().all(|c| c.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|n| n != 0)
}

/// Literal RFC1918 IPv4 only: no DNS names, public, link-local or IPv6 hosts.
fn rfc1918(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty() || p.len() > 3
        || !p.bytes().all(|c| c.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0'))) {
        return false;
    }
    let Ok(o) = parts.iter().map(|p| p.parse::<u8>()).collect::<Result<Vec<u8>, _>>() else { return false };
    o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Loopback or private-LAN QUIC endpoint. Whether a *listener* accepts a LAN
/// endpoint remains an explicit client-side opt-in (S17); the DNA only stops
/// hosts advertising DNS names or public addresses. Internet endpoints are a
/// separate, unreviewed release gate.
pub fn valid_moq_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false; };
    let Some((host, port)) = rest.rsplit_once(':') else { return false; };
    valid_port(port) && (host == "127.0.0.1" || rfc1918(host))
}

fn is_hex16(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_note(note: &str) -> bool {
    note.len() <= 500 && !note.chars().any(|c| c == '\0' || (c.is_control() && c != '\n'))
}

fn valid_agent_text(agent: &str) -> bool {
    !agent.is_empty() && agent.len() <= 160
}

#[hdk_entry_types]
#[unit_enum(UnitEntryTypes)]
pub enum EntryTypes {
    SigningKeyBinding(SigningKeyBinding),
    FileCommitment(FileCommitment),
    ReplicaClaim(ReplicaClaim),
    MoqEndpoint(MoqEndpoint),
    #[entry_type(visibility = "private")]
    InboxAccessRequest(InboxAccessRequest),
    #[entry_type(visibility = "private")]
    InboxGrant(InboxGrant),
    #[entry_type(visibility = "private")]
    InboxDecision(InboxDecision),
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
        // Private inbox entries: only the author (recipient) ever validates
        // them, so these checks are format hygiene, not a trust boundary.
        EntryTypes::InboxAccessRequest(r) => {
            if r.schema != INBOX_REQUEST_SCHEMA || !valid_agent_text(&r.listener_agent)
                || r.nonce.len() != 32 || !r.nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || r.listener_agent == author.to_string()
                || !is_hex32(&r.file_id) || !is_hex32(&r.manifest_sha256) || !is_hex32(&r.x25519_public_hex)
                || !GRANT_KINDS.contains(&r.kind.as_str()) || !valid_note(&r.note)
                || !r.request_id.as_ref().map_or(true, |id| is_hex16(id)) {
                Err("invalid inbox access request".into())
            } else { Ok(()) }
        }
        EntryTypes::InboxDecision(d) => {
            if d.schema != INBOX_DECISION_SCHEMA || !valid_agent_text(&d.owner_agent)
                || d.owner_agent == author.to_string()
                || !is_hex32(&d.file_id) || !is_hex32(&d.manifest_sha256)
                || !GRANT_KINDS.contains(&d.kind.as_str())
                || !d.request_id.as_ref().map_or(true, |id| is_hex16(id))
                || d.decision != "declined" {
                Err("invalid inbox decision".into())
            } else { Ok(()) }
        }
        EntryTypes::InboxGrant(g) => {
            if g.schema != INBOX_GRANT_SCHEMA || !valid_agent_text(&g.owner_agent)
                || g.owner_agent == author.to_string()
                || !is_hex32(&g.file_id) || !is_hex32(&g.manifest_sha256)
                || !GRANT_KINDS.contains(&g.kind.as_str())
                || g.grant_json.is_empty() || g.grant_json.len() > MAX_GRANT_JSON_BYTES {
                Err("invalid inbox grant".into())
            } else { Ok(()) }
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
    fn endpoint_urls_are_loopback_or_rfc1918_and_port_validated() {
        assert!(valid_moq_url("https://127.0.0.1:443"));
        assert!(valid_moq_url("https://127.0.0.1:65535"));
        assert!(!valid_moq_url("https://127.0.0.1:0"));
        assert!(!valid_moq_url("https://127.0.0.1:65536"));
        assert!(!valid_moq_url("https://example.org:443"));
        assert!(!valid_moq_url("https://127.0.0.1:443/bad"));
        // S17/v1: literal private-LAN IPv4 hosts only.
        for ok in ["https://192.168.1.50:4443", "https://10.0.0.7:1", "https://172.16.0.1:9000", "https://172.31.255.255:9000"] {
            assert!(valid_moq_url(ok), "{ok}");
        }
        for bad in ["https://8.8.8.8:443", "https://172.32.0.1:443", "https://169.254.1.1:443",
                    "https://192.168.1.050:443", "https://192.168.1:443", "https://[fd00::1]:443",
                    "http://192.168.1.5:443", "https://u@192.168.1.5:443", "https://192.168.1.5:443/x",
                    "https://192.168.1.5", "https://localhost:443", "https://192.168.1.5:0"] {
            assert!(!valid_moq_url(bad), "{bad}");
        }
    }
    #[test]
    fn grant_notes_reject_control_characters() {
        assert!(valid_note("please\nthanks"));
        assert!(!valid_note("bad\0"));
        assert!(!valid_note(&"x".repeat(501)));
    }
}
