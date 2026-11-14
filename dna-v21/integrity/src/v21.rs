//! S2 key lifecycle v2.1: rotation, recovery and revocation of the media
//! signing keys bound to a Holochain agent, for the separately versioned v2.1
//! storage DNA. See docs/s2-key-lifecycle-v21.md (Music) and
//! docs/S2-KEY-LIFECYCLE-V21.md (Media Core).
//!
//! Authority model
//! * The Holochain agent (the action author, signing with its Lair agent key)
//!   is the ONLY authority for every lifecycle step. A media signing key never
//!   authorises anything on its own: possession of an Ed25519 media key cannot
//!   author an action as another agent.
//! * Each new key proves possession by signing the complete transition.
//! * A normal rotation additionally carries a continuity signature by the
//!   predecessor key over the same complete transition.
//! * A recovery (lost or compromised predecessor) has no continuity signature
//!   and is labelled as such; readers decide whether to accept it.
//!
//! Ordering is the author's own source chain (validated agent activity read
//! with `must_get_agent_activity`), never a timestamp: for each purpose the
//! "current" generation is the last transition before this action. That makes
//! skipped generations, forks of the lifecycle, reactivated keys and
//! cross-purpose predecessors invalid at the DNA level.

use super::*;

/// Integrity verdict for a v1 binding on the v2.1 DNA.
pub const V1_REJECTED_V21: &str =
    "key-binding/v1 is not accepted by the v2.1 storage DNA; publish a key-lifecycle/v2.1 inception";
/// Integrity verdict for a v2 binding on the v2.1 DNA.
pub const V2_REJECTED_V21: &str =
    "key-binding/v2 is not accepted by the v2.1 storage DNA; publish a key-lifecycle/v2.1 inception";

/// Schema of a lifecycle transition (inception, rotation, recovery).
pub const KEY_LIFECYCLE_SCHEMA_V21: &str = "holochain-storage/key-lifecycle/v2.1";
/// Schema of a revocation.
pub const KEY_REVOCATION_SCHEMA_V21: &str = "holochain-storage/key-revocation/v2.1";
/// Signing domain of every lifecycle signature (NUL-terminated). Distinct
/// from the v2 proof domain, S1 canonical JSON and S10 HKDF contexts.
pub const KEY_LIFECYCLE_DOMAIN_V21: &[u8] = b"holochain-storage/key-lifecycle/v2.1\0";
/// Role of the new key's proof of possession.
pub const ROLE_SUCCESSOR: &str = "successor-possession";
/// Role of the predecessor key's continuity signature.
pub const ROLE_PREDECESSOR: &str = "predecessor-continuity";
/// First generation of a purpose.
pub const KIND_INCEPTION: &str = "inception";
/// Normal rotation: old and new key both sign.
pub const KIND_ROTATION: &str = "rotation";
/// Recovery: agent-authorised, no continuity signature.
pub const KIND_RECOVERY: &str = "recovery";
/// The only revocation authority defined by v2.1: the Holochain agent.
pub const REVOCATION_AUTHORITY_AGENT: &str = "holochain-agent";
/// Revoked for new operations; historical signatures stay verifiable.
pub const SCOPE_NEW_OPERATIONS: &str = "new-operations";
/// Revoked as compromised: no new operations; historical signatures only
/// when anchored on the agent's chain before the revocation.
pub const SCOPE_COMPROMISED: &str = "compromised";
/// Upper bound on a generation number (bounded parsing; no overflow).
pub const MAX_GENERATION: u32 = 1_000_000;
const MAX_TEXT_V21: usize = 160;

/// One step of an agent's signing-key lifecycle for one purpose.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyTransitionV21 {
    /// `holochain-storage/key-lifecycle/v2.1`.
    pub schema: String,
    /// DNA hash (`uhC0k…`) of the network this transition is made for.
    pub dna_hash: String,
    /// The Holochain agent; must equal the action author.
    pub agent: String,
    /// `owner-manifest` or `host-receipt`.
    pub purpose: String,
    /// Canonical decimal, `"1"` for an inception, predecessor + 1 otherwise.
    pub generation: String,
    /// `inception`, `rotation` or `recovery`.
    pub kind: String,
    /// The new public Ed25519 key, 64 lowercase hex.
    pub signing_key_hex: String,
    /// Action hash (`uhCkk…`) of the predecessor transition; empty for inception.
    pub predecessor_action: String,
    /// The predecessor's public key; empty for inception.
    pub predecessor_key_hex: String,
    /// New key's signature over the transition message (role successor).
    pub proof_signature_hex: String,
    /// Predecessor key's signature over the transition message (role
    /// predecessor); required for rotation, empty for inception and recovery.
    pub continuity_signature_hex: String,
}

/// Revocation of one generation of one purpose, by the agent.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyRevocationV21 {
    /// `holochain-storage/key-revocation/v2.1`.
    pub schema: String,
    /// DNA hash of the network.
    pub dna_hash: String,
    /// The Holochain agent; must equal the action author.
    pub agent: String,
    /// Purpose of the revoked key.
    pub purpose: String,
    /// Generation of the revoked key.
    pub generation: String,
    /// The revoked public key.
    pub signing_key_hex: String,
    /// Action hash of the exact transition that introduced the key.
    pub target_action: String,
    /// `holochain-agent`.
    pub authority: String,
    /// `new-operations` or `compromised`.
    pub scope: String,
}

/// Exact bytes signed by lifecycle signatures:
/// `KEY_LIFECYCLE_DOMAIN_V21 || for f in [role, schema, dna_hash, agent,
/// purpose, generation, kind, signing_key_hex, predecessor_action,
/// predecessor_key_hex]: u32_be(len(f)) || utf8(f)`.
#[allow(clippy::too_many_arguments)]
pub fn key_transition_v21_message(
    role: &str, dna_hash: &str, agent: &str, purpose: &str, generation: &str, kind: &str,
    signing_key_hex: &str, predecessor_action: &str, predecessor_key_hex: &str,
) -> Vec<u8> {
    let mut out = KEY_LIFECYCLE_DOMAIN_V21.to_vec();
    for field in [
        role, KEY_LIFECYCLE_SCHEMA_V21, dna_hash, agent, purpose, generation, kind,
        signing_key_hex, predecessor_action, predecessor_key_hex,
    ] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

/// The message a transition's `role` signature covers.
pub fn transition_message(t: &KeyTransitionV21, role: &str) -> Vec<u8> {
    key_transition_v21_message(
        role, &t.dna_hash, &t.agent, &t.purpose, &t.generation, &t.kind,
        &t.signing_key_hex, &t.predecessor_action, &t.predecessor_key_hex,
    )
}

/// Canonical decimal generation in `1..=MAX_GENERATION` (no sign, no leading zero).
pub fn parse_generation(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 7 || !text.bytes().all(|b| b.is_ascii_digit())
        || text.starts_with('0') {
        return None;
    }
    text.parse::<u32>().ok().filter(|g| (1..=MAX_GENERATION).contains(g))
}

fn hex_n<const N: usize>(text: &str) -> Option<[u8; N]> {
    let raw = text.as_bytes();
    if raw.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, pair) in raw.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

fn valid_purpose(purpose: &str) -> bool {
    purpose == "owner-manifest" || purpose == "host-receipt"
}

fn check_scope(agent: &str, author: &str, dna: &str, entry_dna: &str) -> Result<(), String> {
    if agent != author {
        return Err(format!("entry claims {agent}, actual Holochain action author is {author}"));
    }
    if entry_dna.is_empty() || entry_dna.len() > MAX_TEXT_V21 || entry_dna != dna {
        return Err("key lifecycle entry is for a different DNA".into());
    }
    Ok(())
}

/// The author's earlier lifecycle entries for ONE purpose, in chain order,
/// each with its action hash.
#[derive(Clone, Debug, Default)]
pub struct PurposeHistory {
    /// Transitions, oldest first.
    pub transitions: Vec<(String, KeyTransitionV21)>,
    /// Revocations, oldest first.
    pub revocations: Vec<(String, KeyRevocationV21)>,
}

/// One Ed25519 check to perform: (public key, signature, message).
pub type SignatureCheck = ([u8; 32], [u8; 64], Vec<u8>);

/// Structural rules of a transition that need no chain history.
/// Returns the parsed generation, new key and proof signature.
pub fn check_transition_structure_v21(
    t: &KeyTransitionV21, author: &str, dna: &str,
) -> Result<(u32, [u8; 32], [u8; 64]), String> {
    check_scope(&t.agent, author, dna, &t.dna_hash)?;
    if t.schema != KEY_LIFECYCLE_SCHEMA_V21 {
        return Err("unsupported key lifecycle schema".into());
    }
    if !valid_purpose(&t.purpose) {
        return Err("unsupported signing key purpose".into());
    }
    let generation = parse_generation(&t.generation).ok_or("invalid key generation")?;
    if ![KIND_INCEPTION, KIND_ROTATION, KIND_RECOVERY].contains(&t.kind.as_str()) {
        return Err("unsupported key transition kind".into());
    }
    let key = hex_n::<32>(&t.signing_key_hex).ok_or("invalid public key encoding")?;
    let proof = hex_n::<64>(&t.proof_signature_hex).ok_or("invalid proof signature encoding")?;
    Ok((generation, key, proof))
}

/// Deterministic structural and chain-order rules for a transition (all but
/// the signature verification itself). Returns the signature checks.
pub fn check_transition_v21(
    t: &KeyTransitionV21, author: &str, dna: &str, history: &PurposeHistory,
) -> Result<Vec<SignatureCheck>, String> {
    let (generation, key, proof) = check_transition_structure_v21(t, author, dna)?;
    let mut checks = vec![(key, proof, transition_message(t, ROLE_SUCCESSOR))];
    match t.kind.as_str() {
        KIND_INCEPTION => {
            if generation != 1 {
                return Err("an inception must be generation 1".into());
            }
            if !t.predecessor_action.is_empty() || !t.predecessor_key_hex.is_empty()
                || !t.continuity_signature_hex.is_empty() {
                return Err("an inception must not name a predecessor".into());
            }
            if !history.transitions.is_empty() {
                return Err("purpose already has a key lifecycle; rotate or recover instead".into());
            }
        }
        KIND_ROTATION | KIND_RECOVERY => {
            let Some((last_action, last)) = history.transitions.last() else {
                return Err("no predecessor key for this purpose".into());
            };
            if &t.predecessor_action != last_action {
                return Err("predecessor is not the author's current key for this purpose".into());
            }
            // History entries were validated, so their generation parses.
            let last_generation = parse_generation(&last.generation).unwrap_or(0);
            if generation != last_generation + 1 {
                return Err("generation must increase by exactly one".into());
            }
            if t.predecessor_key_hex != last.signing_key_hex {
                return Err("predecessor key does not match the predecessor transition".into());
            }
            if history.transitions.iter().any(|(_, p)| p.signing_key_hex == t.signing_key_hex) {
                return Err("signing key was already used in this lifecycle (no reactivation)".into());
            }
            if t.kind == KIND_ROTATION {
                if history.revocations.iter().any(|(_, r)| &r.target_action == last_action) {
                    return Err("predecessor key is revoked; only a recovery may follow it".into());
                }
                let predecessor = hex_n::<32>(&t.predecessor_key_hex)
                    .ok_or("predecessor key does not match the predecessor transition")?;
                let continuity = hex_n::<64>(&t.continuity_signature_hex)
                    .ok_or("invalid continuity signature encoding")?;
                checks.push((predecessor, continuity, transition_message(t, ROLE_PREDECESSOR)));
            } else if !t.continuity_signature_hex.is_empty() {
                return Err("a recovery carries no continuity signature".into());
            }
        }
        _ => return Err("unsupported key transition kind".into()),
    }
    Ok(checks)
}

/// Deterministic rules for a revocation.
pub fn check_revocation_v21(
    r: &KeyRevocationV21, author: &str, dna: &str, history: &PurposeHistory,
) -> Result<(), String> {
    check_scope(&r.agent, author, dna, &r.dna_hash)?;
    if r.schema != KEY_REVOCATION_SCHEMA_V21 {
        return Err("unsupported key revocation schema".into());
    }
    if !valid_purpose(&r.purpose) {
        return Err("unsupported signing key purpose".into());
    }
    parse_generation(&r.generation).ok_or("invalid key generation")?;
    hex_n::<32>(&r.signing_key_hex).ok_or("invalid public key encoding")?;
    if r.authority != REVOCATION_AUTHORITY_AGENT {
        return Err("unsupported revocation authority".into());
    }
    if r.scope != SCOPE_NEW_OPERATIONS && r.scope != SCOPE_COMPROMISED {
        return Err("unsupported revocation scope".into());
    }
    let Some((_, target)) = history.transitions.iter().find(|(h, _)| h == &r.target_action) else {
        return Err("revocation target is not a key transition of this agent and purpose".into());
    };
    if target.generation != r.generation || target.signing_key_hex != r.signing_key_hex {
        return Err("revocation does not match the target transition".into());
    }
    let earlier: Vec<&KeyRevocationV21> = history.revocations.iter()
        .filter(|(_, e)| e.target_action == r.target_action).map(|(_, e)| e).collect();
    // `compromised` is terminal; any scope may otherwise be recorded once.
    if earlier.iter().any(|e| e.scope == SCOPE_COMPROMISED) {
        return Err("key is already revoked as compromised".into());
    }
    if earlier.iter().any(|e| e.scope == r.scope) {
        return Err("key is already revoked with this scope".into());
    }
    Ok(())
}

/// Read the author's lifecycle entries for `purpose` strictly before the
/// action whose `prev_action` is `prev`, in chain order. Deterministic:
/// `must_get_agent_activity` over the hash-linked chain from `prev` to
/// genesis, then `must_get_valid_record` for lifecycle actions only.
fn purpose_history(author: &AgentPubKey, prev: &ActionHash, purpose: &str) -> ExternResult<PurposeHistory> {
    let transition_def = ScopedEntryDefIndex::try_from(UnitEntryTypes::KeyTransitionV21)?;
    let revocation_def = ScopedEntryDefIndex::try_from(UnitEntryTypes::KeyRevocationV21)?;
    let mut activity = must_get_agent_activity(author.clone(), ChainFilter::new(prev.clone()))?;
    activity.sort_by_key(|a| a.action.hashed.content.action_seq());
    let mut history = PurposeHistory::default();
    for item in activity {
        let action = &item.action.hashed.content;
        let Some(EntryType::App(def)) = action.entry_type() else { continue };
        if def.zome_index != transition_def.zome_index {
            continue;
        }
        let is_transition = def.entry_index == transition_def.zome_type;
        let is_revocation = def.entry_index == revocation_def.zome_type;
        if !is_transition && !is_revocation {
            continue;
        }
        let hash = item.action.hashed.hash.clone();
        let record = must_get_valid_record(hash.clone())?;
        let decode = |e: SerializedBytesError| wasm_error!(WasmErrorInner::Guest(e.to_string()));
        if is_transition {
            if let Some(t) = record.entry().to_app_option::<KeyTransitionV21>().map_err(decode)? {
                if t.purpose == purpose && t.agent == author.to_string() {
                    history.transitions.push((hash.to_string(), t));
                }
            }
        } else if let Some(r) = record.entry().to_app_option::<KeyRevocationV21>().map_err(decode)? {
            if r.purpose == purpose && r.agent == author.to_string() {
                history.revocations.push((hash.to_string(), r));
            }
        }
    }
    Ok(history)
}

fn verify_all(checks: Vec<SignatureCheck>, failure: &str) -> Result<(), String> {
    for (key, signature, message) in checks {
        let signer = AgentPubKey::from_raw_32(key.to_vec());
        match verify_signature_raw(signer, Signature(signature), message) {
            Ok(true) => {}
            _ => return Err(failure.into()),
        }
    }
    Ok(())
}

fn dna_text() -> ExternResult<String> {
    Ok(dna_info()?.hash.to_string())
}

/// Full transition rule. `Err` (outer) propagates unresolved dependencies
/// from `must_get_*` so the host can retry; `Ok(Err)` is an invalid verdict.
pub(crate) fn validate_transition_v21(action: &TypedAction<CreateData>, t: &KeyTransitionV21) -> ExternResult<Result<(), String>> {
    let author = action.author().to_string();
    let dna = dna_text()?;
    // Structural rules first: no chain reads for malformed entries.
    if let Err(e) = check_transition_structure_v21(t, &author, &dna) {
        return Ok(Err(e));
    }
    let Some(prev) = action.prev_action() else {
        return Ok(Err("a lifecycle entry needs a source-chain position".into()));
    };
    let history = purpose_history(action.author(), prev, &t.purpose)?;
    let checks = match check_transition_v21(t, &author, &dna, &history) {
        Ok(c) => c,
        Err(e) => return Ok(Err(e)),
    };
    let first = if t.kind == KIND_ROTATION {
        "proof of possession or continuity signature does not verify for this transition"
    } else {
        "proof of possession does not verify for this transition"
    };
    Ok(verify_all(checks, first))
}

/// Full revocation rule (see [`validate_transition_v21`] for the result shape).
pub(crate) fn validate_revocation_v21(action: &TypedAction<CreateData>, r: &KeyRevocationV21) -> ExternResult<Result<(), String>> {
    let author = action.author().to_string();
    let dna = dna_text()?;
    // Structural rules need no chain reads; a full check follows.
    if let Err(e) = check_revocation_v21(r, &author, &dna, &PurposeHistory::default()) {
        if !e.starts_with("revocation target is not") {
            return Ok(Err(e));
        }
    }
    let Some(prev) = action.prev_action() else {
        return Ok(Err("a lifecycle entry needs a source-chain position".into()));
    };
    let history = purpose_history(action.author(), prev, &r.purpose)?;
    Ok(check_revocation_v21(r, &author, &dna, &history))
}

/// Map a lifecycle rule result to the validation callback result.
pub(crate) fn lifecycle_verdict(result: ExternResult<Result<(), String>>) -> ExternResult<ValidateCallbackResult> {
    match result? {
        Ok(()) => Ok(ValidateCallbackResult::Valid),
        Err(reason) => Ok(ValidateCallbackResult::Invalid(reason)),
    }
}

#[cfg(test)]
mod v21_tests {
    use super::*;

    const DNA: &str = "uhC0kDnaForTests";
    const ALICE: &str = "uhCAkAlice";

    fn inception(key: &str) -> KeyTransitionV21 {
        KeyTransitionV21 {
            schema: KEY_LIFECYCLE_SCHEMA_V21.into(),
            dna_hash: DNA.into(),
            agent: ALICE.into(),
            purpose: "owner-manifest".into(),
            generation: "1".into(),
            kind: KIND_INCEPTION.into(),
            signing_key_hex: key.repeat(32),
            predecessor_action: String::new(),
            predecessor_key_hex: String::new(),
            proof_signature_hex: "cd".repeat(64),
            continuity_signature_hex: String::new(),
        }
    }

    fn successor(kind: &str, generation: &str, key: &str, pred: (&str, &KeyTransitionV21)) -> KeyTransitionV21 {
        KeyTransitionV21 {
            generation: generation.into(),
            kind: kind.into(),
            signing_key_hex: key.repeat(32),
            predecessor_action: pred.0.into(),
            predecessor_key_hex: pred.1.signing_key_hex.clone(),
            continuity_signature_hex: if kind == KIND_ROTATION { "ef".repeat(64) } else { String::new() },
            ..inception(key)
        }
    }

    fn revocation(target: (&str, &KeyTransitionV21), scope: &str) -> KeyRevocationV21 {
        KeyRevocationV21 {
            schema: KEY_REVOCATION_SCHEMA_V21.into(),
            dna_hash: DNA.into(),
            agent: ALICE.into(),
            purpose: target.1.purpose.clone(),
            generation: target.1.generation.clone(),
            signing_key_hex: target.1.signing_key_hex.clone(),
            target_action: target.0.into(),
            authority: REVOCATION_AUTHORITY_AGENT.into(),
            scope: scope.into(),
        }
    }

    fn history(t: &[(&str, &KeyTransitionV21)], r: &[(&str, &KeyRevocationV21)]) -> PurposeHistory {
        PurposeHistory {
            transitions: t.iter().map(|(h, x)| (h.to_string(), (*x).clone())).collect(),
            revocations: r.iter().map(|(h, x)| (h.to_string(), (*x).clone())).collect(),
        }
    }

    fn err(r: Result<Vec<SignatureCheck>, String>) -> String {
        r.expect_err("must be rejected")
    }

    #[test]
    fn message_is_domain_separated_role_bound_and_length_prefixed() {
        let m = key_transition_v21_message(ROLE_SUCCESSOR, "D", "A", "owner-manifest", "2", "rotation", "K", "P", "Q");
        let mut expected = b"holochain-storage/key-lifecycle/v2.1\0".to_vec();
        for f in [ROLE_SUCCESSOR, KEY_LIFECYCLE_SCHEMA_V21, "D", "A", "owner-manifest", "2", "rotation", "K", "P", "Q"] {
            expected.extend((f.len() as u32).to_be_bytes());
            expected.extend(f.as_bytes());
        }
        assert_eq!(m, expected);
        assert_ne!(m, key_transition_v21_message(ROLE_PREDECESSOR, "D", "A", "owner-manifest", "2", "rotation", "K", "P", "Q"));
        assert_ne!(key_transition_v21_message(ROLE_SUCCESSOR, "DA", "", "p", "1", "k", "K", "", ""),
                   key_transition_v21_message(ROLE_SUCCESSOR, "D", "A", "p", "1", "k", "K", "", ""));
        // Never a valid v2 proof-of-possession message.
        assert!(!m.starts_with(b"holochain-storage/key-binding-pop/v2\0"));
    }

    #[test]
    fn generations_are_canonical_and_bounded() {
        for ok in ["1", "2", "10", "1000000"] {
            assert!(parse_generation(ok).is_some(), "{ok}");
        }
        for bad in ["", "0", "01", "+1", "-1", " 1", "1000001", "99999999", "1.0", "x"] {
            assert!(parse_generation(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn inception_rules() {
        let g1 = inception("aa");
        let checks = check_transition_v21(&g1, ALICE, DNA, &PurposeHistory::default()).unwrap();
        assert_eq!(checks.len(), 1, "inception: proof of possession only");
        assert!(err(check_transition_v21(&g1, "uhCAkMallory", DNA, &PurposeHistory::default()))
            .contains("actual Holochain action author"));
        assert!(err(check_transition_v21(&g1, ALICE, "uhC0kOther", &PurposeHistory::default()))
            .contains("different DNA"));
        // A second inception for the same purpose would fork the lifecycle.
        assert!(err(check_transition_v21(&inception("bb"), ALICE, DNA, &history(&[("h1", &g1)], &[])))
            .contains("already has a key lifecycle"));
        let mut g2 = g1.clone();
        g2.generation = "2".into();
        assert!(err(check_transition_v21(&g2, ALICE, DNA, &PurposeHistory::default())).contains("generation 1"));
        let mut named = g1.clone();
        named.predecessor_action = "uhCkkX".into();
        assert!(err(check_transition_v21(&named, ALICE, DNA, &PurposeHistory::default())).contains("must not name"));
    }

    #[test]
    fn rotation_and_recovery_follow_the_current_generation_only() {
        let g1 = inception("aa");
        let h = history(&[("h1", &g1)], &[]);
        let g2 = successor(KIND_ROTATION, "2", "bb", ("h1", &g1));
        assert_eq!(check_transition_v21(&g2, ALICE, DNA, &h).unwrap().len(), 2, "rotation: proof + continuity");
        let rec = successor(KIND_RECOVERY, "2", "bb", ("h1", &g1));
        assert_eq!(check_transition_v21(&rec, ALICE, DNA, &h).unwrap().len(), 1, "recovery: proof only");

        // Skipped generation.
        let skip = successor(KIND_ROTATION, "3", "bb", ("h1", &g1));
        assert!(err(check_transition_v21(&skip, ALICE, DNA, &h)).contains("exactly one"));
        // Wrong predecessor reference (unknown, or not the current one).
        let mut unknown = g2.clone();
        unknown.predecessor_action = "uhCkkNope".into();
        assert!(err(check_transition_v21(&unknown, ALICE, DNA, &h)).contains("not the author's current key"));
        let h2 = history(&[("h1", &g1), ("h2", &g2)], &[]);
        // Competing successor of h1 after h2 exists (a fork), or a replay of g2.
        let fork = successor(KIND_ROTATION, "2", "cc", ("h1", &g1));
        assert!(err(check_transition_v21(&fork, ALICE, DNA, &h2)).contains("not the author's current key"));
        assert!(err(check_transition_v21(&g2, ALICE, DNA, &h2)).contains("not the author's current key"));
        // Reactivating the generation-1 key as generation 3.
        let back = successor(KIND_ROTATION, "3", "aa", ("h2", &g2));
        assert!(err(check_transition_v21(&back, ALICE, DNA, &h2)).contains("no reactivation"));
        let same = successor(KIND_ROTATION, "2", "aa", ("h1", &g1));
        assert!(err(check_transition_v21(&same, ALICE, DNA, &h)).contains("no reactivation"));
        // Predecessor key must be the predecessor transition's key.
        let mut lie = g2.clone();
        lie.predecessor_key_hex = "dd".repeat(32);
        assert!(err(check_transition_v21(&lie, ALICE, DNA, &h)).contains("predecessor key does not match"));
        // Rotation without continuity, recovery with continuity.
        let mut bare = g2.clone();
        bare.continuity_signature_hex = String::new();
        assert!(err(check_transition_v21(&bare, ALICE, DNA, &h)).contains("continuity signature encoding"));
        let mut rec_c = rec.clone();
        rec_c.continuity_signature_hex = "ef".repeat(64);
        assert!(err(check_transition_v21(&rec_c, ALICE, DNA, &h)).contains("no continuity"));
        // No predecessor at all.
        assert!(err(check_transition_v21(&g2, ALICE, DNA, &PurposeHistory::default())).contains("no predecessor"));
        // Unknown kind.
        let mut odd = g2.clone();
        odd.kind = "reset".into();
        assert!(err(check_transition_v21(&odd, ALICE, DNA, &h)).contains("unsupported key transition kind"));
    }

    #[test]
    fn a_revoked_predecessor_can_only_be_followed_by_recovery() {
        let g1 = inception("aa");
        let r = revocation(("h1", &g1), SCOPE_COMPROMISED);
        let h = history(&[("h1", &g1)], &[("r1", &r)]);
        let g2 = successor(KIND_ROTATION, "2", "bb", ("h1", &g1));
        assert!(err(check_transition_v21(&g2, ALICE, DNA, &h)).contains("only a recovery"));
        let rec = successor(KIND_RECOVERY, "2", "bb", ("h1", &g1));
        assert!(check_transition_v21(&rec, ALICE, DNA, &h).is_ok());
    }

    #[test]
    fn revocation_rules() {
        let g1 = inception("aa");
        let g2 = successor(KIND_ROTATION, "2", "bb", ("h1", &g1));
        let h = history(&[("h1", &g1), ("h2", &g2)], &[]);
        let ok = revocation(("h1", &g1), SCOPE_NEW_OPERATIONS);
        assert!(check_revocation_v21(&ok, ALICE, DNA, &h).is_ok());
        assert!(check_revocation_v21(&ok, "uhCAkMallory", DNA, &h).unwrap_err().contains("actual Holochain action author"));
        assert!(check_revocation_v21(&ok, ALICE, "uhC0kOther", &h).unwrap_err().contains("different DNA"));
        let mut missing = ok.clone();
        missing.target_action = "uhCkkNope".into();
        assert!(check_revocation_v21(&missing, ALICE, DNA, &h).unwrap_err().contains("not a key transition"));
        let mut wrong_key = ok.clone();
        wrong_key.signing_key_hex = g2.signing_key_hex.clone();
        assert!(check_revocation_v21(&wrong_key, ALICE, DNA, &h).unwrap_err().contains("does not match"));
        let mut bad_scope = ok.clone();
        bad_scope.scope = "everything".into();
        assert!(check_revocation_v21(&bad_scope, ALICE, DNA, &h).unwrap_err().contains("scope"));
        let mut bad_authority = ok.clone();
        bad_authority.authority = "media-key".into();
        assert!(check_revocation_v21(&bad_authority, ALICE, DNA, &h).unwrap_err().contains("authority"));
        // Duplicate scope is a replay; escalation to compromised is allowed;
        // nothing follows compromised.
        let h_r = history(&[("h1", &g1), ("h2", &g2)], &[("r1", &ok)]);
        assert!(check_revocation_v21(&ok, ALICE, DNA, &h_r).unwrap_err().contains("already revoked with this scope"));
        let worse = revocation(("h1", &g1), SCOPE_COMPROMISED);
        assert!(check_revocation_v21(&worse, ALICE, DNA, &h_r).is_ok());
        let h_c = history(&[("h1", &g1), ("h2", &g2)], &[("r1", &ok), ("r2", &worse)]);
        assert!(check_revocation_v21(&ok, ALICE, DNA, &h_c).unwrap_err().contains("compromised"));
    }
}
