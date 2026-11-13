//! S2 key-binding v2 for the separately versioned v2 storage DNA.
//! See docs/s2-key-binding-v2.md (Music) and docs/S2-KEY-BINDING-V2.md (Media Core).

use super::*;

/// Integrity verdict for a v1 binding in the v2 DNA.
pub const V1_REJECTED: &str =
    "key-binding/v1 is not accepted by the v2 storage DNA; register key-binding/v2";

/// S2 key binding v2: the author proves possession of the Ed25519 signing key.
///
/// Only in the separately versioned v2 storage DNA; the v1 DNA is unchanged.
/// All fields are strings so readers can treat the entry exactly like the
/// other S2 records.
#[hdk_entry_helper]
#[derive(Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyBindingV2 {
    /// `holochain-storage/key-binding/v2`.
    pub schema: String,
    /// The DNA hash (`uhC0k…`) of the network this binding is made for.
    pub dna_hash: String,
    /// The Holochain agent (`uhCAk…`); must equal the action author.
    pub agent: String,
    /// `owner-manifest` or `host-receipt`.
    pub purpose: String,
    /// Public Ed25519 key, 64 lowercase hex characters.
    pub signing_key_hex: String,
    /// Key generation; only `"1"` is defined (rotation is not part of v2.0).
    pub generation: String,
    /// Ed25519 signature by `signing_key_hex` over [`key_binding_v2_message`],
    /// 128 lowercase hex characters.
    pub proof_signature_hex: String,
}

/// Schema of a v2 binding.
pub const KEY_SCHEMA_V2: &str = "holochain-storage/key-binding/v2";
/// Proof-of-possession signing domain. Distinct from every S1/S10 domain
/// (manifests and receipts sign bare canonical JSON; grants use
/// `holochain-music/...` HKDF contexts), and NUL-terminated.
pub const KEY_POP_DOMAIN_V2: &[u8] = b"holochain-storage/key-binding-pop/v2\0";
/// The only generation defined by v2.0.
pub const KEY_GENERATION_V2: &str = "1";
const MAX_DNA_HASH_TEXT: usize = 160;

/// The exact bytes signed by the proof of possession:
/// `domain || for f in [schema, dna_hash, agent, purpose, signing_key_hex,
/// generation]: u32_be(len(f)) || utf8(f)`. Length prefixes make the
/// encoding injective; field order is fixed.
pub fn key_binding_v2_message(
    dna_hash: &str, agent: &str, purpose: &str, signing_key_hex: &str, generation: &str,
) -> Vec<u8> {
    let mut out = KEY_POP_DOMAIN_V2.to_vec();
    for field in [KEY_SCHEMA_V2, dna_hash, agent, purpose, signing_key_hex, generation] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
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

/// Deterministic structural checks of a v2 binding (everything except the
/// signature itself). Returns the public key, signature and signed message.
pub fn check_key_binding_v2(
    k: &SigningKeyBindingV2, author: &str, dna_hash: &str,
) -> Result<([u8; 32], [u8; 64], Vec<u8>), String> {
    if k.agent != author {
        return Err(format!("entry claims {}, actual Holochain action author is {author}", k.agent));
    }
    if k.schema != KEY_SCHEMA_V2 {
        return Err("unsupported key binding schema".into());
    }
    if k.dna_hash.is_empty() || k.dna_hash.len() > MAX_DNA_HASH_TEXT || k.dna_hash != dna_hash {
        return Err("key binding is for a different DNA".into());
    }
    if k.purpose != "owner-manifest" && k.purpose != "host-receipt" {
        return Err("unsupported signing key purpose".into());
    }
    if k.generation != KEY_GENERATION_V2 {
        return Err("unsupported key generation (rotation is not defined in v2.0)".into());
    }
    let key = hex_bytes::<32>(&k.signing_key_hex).ok_or("invalid public key encoding")?;
    let signature = hex_bytes::<64>(&k.proof_signature_hex).ok_or("invalid proof signature encoding")?;
    let message = key_binding_v2_message(&k.dna_hash, &k.agent, &k.purpose, &k.signing_key_hex, &k.generation);
    Ok((key, signature, message))
}

/// Full v2 rule: structure, then Ed25519 proof of possession verified by the
/// conductor (Lair `verify_detached`). Uses only `dna_info` and signature
/// verification: no network reads, no clock.
pub(crate) fn validate_key_binding_v2(author: &AgentPubKey, k: &SigningKeyBindingV2) -> Result<(), String> {
    let dna = dna_info().map_err(|e| format!("dna_info unavailable: {e:?}"))?.hash.to_string();
    let (key, signature, message) = check_key_binding_v2(k, &author.to_string(), &dna)?;
    let signer = AgentPubKey::from_raw_32(key.to_vec());
    match verify_signature_raw(signer, Signature(signature), message) {
        Ok(true) => Ok(()),
        _ => Err("proof of possession does not verify for this agent, purpose, key and DNA".into()),
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    fn binding() -> SigningKeyBindingV2 {
        SigningKeyBindingV2 {
            schema: KEY_SCHEMA_V2.into(),
            dna_hash: "uhC0kDnaForTests".into(),
            agent: "uhCAkAlice".into(),
            purpose: "owner-manifest".into(),
            signing_key_hex: "ab".repeat(32),
            generation: "1".into(),
            proof_signature_hex: "cd".repeat(64),
        }
    }

    #[test]
    fn message_is_domain_separated_and_length_prefixed() {
        let m = key_binding_v2_message("D", "A", "owner-manifest", "K", "1");
        let mut expected = b"holochain-storage/key-binding-pop/v2\0".to_vec();
        for f in ["holochain-storage/key-binding/v2", "D", "A", "owner-manifest", "K", "1"] {
            expected.extend((f.len() as u32).to_be_bytes());
            expected.extend(f.as_bytes());
        }
        assert_eq!(m, expected);
        // Moving a byte between adjacent fields changes the message.
        assert_ne!(key_binding_v2_message("DA", "", "p", "K", "1"),
                   key_binding_v2_message("D", "A", "p", "K", "1"));
    }

    #[test]
    fn structural_rules() {
        let ok = binding();
        assert!(check_key_binding_v2(&ok, "uhCAkAlice", "uhC0kDnaForTests").is_ok());
        let author = check_key_binding_v2(&ok, "uhCAkMallory", "uhC0kDnaForTests").unwrap_err();
        assert!(author.contains("actual Holochain action author"));
        assert!(check_key_binding_v2(&ok, "uhCAkAlice", "uhC0kOtherDna").is_err());
        let cases: Vec<fn(&mut SigningKeyBindingV2)> = vec![
            |b| b.schema = "holochain-storage/key-binding/v1".into(),
            |b| b.purpose = "grant-issuer".into(),
            |b| b.generation = "2".into(),
            |b| b.generation = "01".into(),
            |b| b.signing_key_hex = "AB".repeat(32),
            |b| b.signing_key_hex = "ab".repeat(31),
            |b| b.proof_signature_hex = "cd".repeat(63),
            |b| b.proof_signature_hex = String::new(),
            |b| b.proof_signature_hex = "zz".repeat(64),
            |b| b.dna_hash = "x".repeat(200),
        ];
        for (i, mutate) in cases.into_iter().enumerate() {
            let mut b = binding();
            mutate(&mut b);
            let dna = b.dna_hash.clone();
            assert!(check_key_binding_v2(&b, "uhCAkAlice", &dna).is_err(), "case {i}");
        }
    }
}

