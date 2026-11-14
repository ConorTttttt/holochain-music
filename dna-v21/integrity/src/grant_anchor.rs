//! `holochain-storage/grant-anchor/v2`: a minimal public record, authored by
//! the content owner, that anchors one access grant (Media Core
//! docs/ACCESS-GRANT-V2.md §3.5, §4) on the owner's own source chain.
//!
//! The anchor carries no recipient, content identifier, rights, terms or key
//! material: only the network, the grant's random id, a domain-separated
//! commitment to the complete signed grant, and the lifecycle transition
//! whose key signs it. The issuer is the action author.
//!
//! Conductor-enforced here (deterministic, chain-ordered):
//! 1. exact fields and encodings;
//! 2. `dna_hash` is this DNA;
//! 3. `issuer_key_action` is the author's CURRENT `owner-manifest`
//!    transition at this chain position, and it is not revoked;
//! 4. `grant_id` is unique among the author's earlier anchors;
//! 5. append-only (existing rule).
//!
//! Not enforceable here (verifiers must check): that a grant matches the
//! anchor (the grant is private), its signature, that the author owns the
//! granted content, the recovered-issuer policy and lifecycle completeness.

use super::*;

/// Schema of a grant anchor.
pub const GRANT_ANCHOR_SCHEMA_V2: &str = "holochain-storage/grant-anchor/v2";
/// Domain of the commitment: SHA-256(domain || grant_message).
pub const GRANT_ANCHOR_COMMITMENT_DOMAIN_V2: &[u8] = b"holochain-storage/grant-anchor-commitment/v2\0";

/// A public grant anchor. All fields are strings.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantAnchorV2 {
    /// `holochain-storage/grant-anchor/v2`.
    pub schema: String,
    /// DNA hash of this network.
    pub dna_hash: String,
    /// The grant's random 128-bit id, 32 lowercase hex.
    pub grant_id: String,
    /// SHA-256 of the commitment domain and the grant's signed message,
    /// 64 lowercase hex.
    pub grant_commitment: String,
    /// Action hash of the author's `owner-manifest` lifecycle transition
    /// whose key signs the grant.
    pub issuer_key_action: String,
}

fn lower_hex(text: &str, chars: usize) -> bool {
    text.len() == chars && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Rules 1 and 2: structure and network.
pub fn check_grant_anchor_structure_v2(a: &GrantAnchorV2, dna: &str) -> Result<(), String> {
    if a.schema != GRANT_ANCHOR_SCHEMA_V2 {
        return Err("unsupported grant anchor schema".into());
    }
    if a.dna_hash.is_empty() || a.dna_hash.len() > 160 || a.dna_hash != dna {
        return Err("grant anchor is for a different DNA".into());
    }
    if !lower_hex(&a.grant_id, 32) {
        return Err("invalid grant id encoding".into());
    }
    if !lower_hex(&a.grant_commitment, 64) {
        return Err("invalid grant commitment encoding".into());
    }
    if a.issuer_key_action.is_empty() || a.issuer_key_action.len() > 160 {
        return Err("invalid issuer key action".into());
    }
    Ok(())
}

/// Rules 1-4 against the author's `owner-manifest` history before this action.
pub fn check_grant_anchor_v2(a: &GrantAnchorV2, dna: &str, history: &PurposeHistory) -> Result<(), String> {
    check_grant_anchor_structure_v2(a, dna)?;
    let Some((current, _)) = history.transitions.last() else {
        return Err("author has no owner-manifest signing key to issue grants".into());
    };
    if current != &a.issuer_key_action {
        return Err("issuer key is not the author's current owner-manifest key".into());
    }
    if history.revocations.iter().any(|(_, r)| &r.target_action == current) {
        return Err("issuer key is revoked; it cannot authorise new grants".into());
    }
    if history.anchor_grant_ids.iter().any(|id| id == &a.grant_id) {
        return Err("grant id was already anchored by this author".into());
    }
    Ok(())
}

/// Full rule (see `validate_transition_v21` for the result shape).
pub(crate) fn validate_grant_anchor_v2(action: &TypedAction<CreateData>, a: &GrantAnchorV2) -> ExternResult<Result<(), String>> {
    let dna = dna_info()?.hash.to_string();
    if let Err(e) = check_grant_anchor_structure_v2(a, &dna) {
        return Ok(Err(e));
    }
    let Some(prev) = action.prev_action() else {
        return Ok(Err("a grant anchor needs a source-chain position".into()));
    };
    let history = purpose_history(action.author(), prev, "owner-manifest")?;
    Ok(check_grant_anchor_v2(a, &dna, &history))
}

#[cfg(test)]
mod grant_anchor_tests {
    use super::*;

    const DNA: &str = "uhC0kDnaForTests";

    fn anchor() -> GrantAnchorV2 {
        GrantAnchorV2 {
            schema: GRANT_ANCHOR_SCHEMA_V2.into(),
            dna_hash: DNA.into(),
            grant_id: "ab".repeat(16),
            grant_commitment: "cd".repeat(32),
            issuer_key_action: "uhCkkG2".into(),
        }
    }

    fn transition(generation: &str) -> KeyTransitionV21 {
        KeyTransitionV21 {
            schema: KEY_LIFECYCLE_SCHEMA_V21.into(),
            dna_hash: DNA.into(),
            agent: "uhCAkAlice".into(),
            purpose: "owner-manifest".into(),
            generation: generation.into(),
            kind: if generation == "1" { KIND_INCEPTION } else { KIND_ROTATION }.into(),
            signing_key_hex: "aa".repeat(32),
            predecessor_action: String::new(),
            predecessor_key_hex: String::new(),
            proof_signature_hex: "cd".repeat(64),
            continuity_signature_hex: String::new(),
        }
    }

    fn revocation(target: &str) -> KeyRevocationV21 {
        KeyRevocationV21 {
            schema: KEY_REVOCATION_SCHEMA_V21.into(),
            dna_hash: DNA.into(),
            agent: "uhCAkAlice".into(),
            purpose: "owner-manifest".into(),
            generation: "2".into(),
            signing_key_hex: "aa".repeat(32),
            target_action: target.into(),
            authority: REVOCATION_AUTHORITY_AGENT.into(),
            scope: SCOPE_NEW_OPERATIONS.into(),
        }
    }

    fn rotated() -> PurposeHistory {
        PurposeHistory {
            transitions: vec![("uhCkkG1".into(), transition("1")), ("uhCkkG2".into(), transition("2"))],
            revocations: Vec::new(),
            anchor_grant_ids: Vec::new(),
        }
    }

    #[test]
    fn current_key_anchors() {
        assert!(check_grant_anchor_v2(&anchor(), DNA, &rotated()).is_ok());
    }

    #[test]
    fn structure_and_network() {
        let cases: Vec<(fn(&mut GrantAnchorV2), &str)> = vec![
            (|a| a.schema = "holochain-storage/grant-anchor/v1".into(), "schema"),
            (|a| a.dna_hash = "uhC0kOther".into(), "different DNA"),
            (|a| a.dna_hash = "x".repeat(200), "different DNA"),
            (|a| a.grant_id = "AB".repeat(16), "grant id"),
            (|a| a.grant_id = "ab".repeat(15), "grant id"),
            (|a| a.grant_commitment = "cd".repeat(31), "commitment"),
            (|a| a.grant_commitment = "zz".repeat(32), "commitment"),
            (|a| a.issuer_key_action = String::new(), "issuer key action"),
            (|a| a.issuer_key_action = "x".repeat(161), "issuer key action"),
        ];
        for (mutate, needle) in cases {
            let mut a = anchor();
            mutate(&mut a);
            let e = check_grant_anchor_v2(&a, DNA, &rotated()).unwrap_err();
            assert!(e.contains(needle), "{needle}: {e}");
        }
    }

    #[test]
    fn rotated_revoked_or_missing_keys_cannot_anchor() {
        let mut stale = anchor();
        stale.issuer_key_action = "uhCkkG1".into();
        assert!(check_grant_anchor_v2(&stale, DNA, &rotated()).unwrap_err().contains("not the author's current"));
        let mut foreign = anchor();
        foreign.issuer_key_action = "uhCkkSomeoneElse".into();
        assert!(check_grant_anchor_v2(&foreign, DNA, &rotated()).unwrap_err().contains("not the author's current"));
        let mut revoked = rotated();
        revoked.revocations.push(("uhCkkR".into(), revocation("uhCkkG2")));
        assert!(check_grant_anchor_v2(&anchor(), DNA, &revoked).unwrap_err().contains("revoked"));
        assert!(check_grant_anchor_v2(&anchor(), DNA, &PurposeHistory::default()).unwrap_err().contains("no owner-manifest"));
    }

    #[test]
    fn grant_ids_are_unique_per_author() {
        let mut used = rotated();
        used.anchor_grant_ids.push("ab".repeat(16));
        assert!(check_grant_anchor_v2(&anchor(), DNA, &used).unwrap_err().contains("already anchored"));
        let mut other = anchor();
        other.grant_id = "ef".repeat(16);
        assert!(check_grant_anchor_v2(&other, DNA, &used).is_ok());
    }
}
