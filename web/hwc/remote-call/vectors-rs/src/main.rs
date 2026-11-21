//! Canonical vectors: bytes = holochain_serialized_bytes::encode(&ZomeCallParams),
//! signature = Ed25519(provenance, sha2_512(bytes)) — exactly what
//! holochain 0.7 `Cell::handle_call_remote` verifies (is_valid_signature).
use ed25519_dalek::{Signer, SigningKey};
use holo_hash::{sha2_512, AgentPubKey, DnaHash};
use holochain_zome_types::prelude::*;
use holochain_nonce::Nonce256Bits;
use serde_json::json;

fn agent(seed: u8) -> (SigningKey, AgentPubKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let pk = AgentPubKey::from_raw_32(key.verifying_key().to_bytes().to_vec());
    (key, pk)
}

fn main() {
    let (caller_key, caller) = agent(7);
    let (_, target) = agent(9);
    let dna = DnaHash::from_raw_32(vec![3; 32]);
    let mut cases = Vec::new();
    for (name, zome, func, secret, payload) in [
        ("inbox-receive-grant", "music_storage", "receive_grant", None, vec![0x81, 0xa1, b'k', 0x01]),
        ("with-cap-secret", "music_storage", "receive_access_request", Some([5u8; 64]), vec![0xc0]),
    ] {
        let params = ZomeCallParams {
            provenance: caller.clone(),
            cell_id: CellId::new(dna.clone(), target.clone()),
            zome_name: zome.into(),
            fn_name: func.into(),
            cap_secret: secret.map(CapSecret::from),
            payload: ExternIO(payload),
            nonce: Nonce256Bits::from([11u8; 32]),
            expires_at: Timestamp::from_micros(1_800_000_000_000_000),
        };
        let (bytes, hash) = params.serialize_and_hash().unwrap();
        assert_eq!(hash, sha2_512(&bytes));
        let sig = caller_key.sign(&hash);
        cases.push(json!({
            "name": name,
            "provenance": hex::encode(caller.get_raw_39()),
            "cell_dna": hex::encode(dna.get_raw_39()),
            "cell_agent": hex::encode(target.get_raw_39()),
            "zome_name": zome, "fn_name": func,
            "cap_secret": secret.map(|s| hex::encode(s)),
            "payload": hex::encode(&params.payload.0),
            "nonce": hex::encode([11u8; 32]),
            "expires_at": 1_800_000_000_000_000i64,
            "bytes": hex::encode(&bytes),
            "sha512": hex::encode(&hash),
            "signature": hex::encode(sig.to_bytes()),
        }));
    }
    // ZomeCallResponse encodings (what CallRemoteRes carries back to the caller).
    let responses: Vec<_> = [
        ("ok", ZomeCallResponse::Ok(ExternIO(vec![0x81, 0xa1, b'k', 0x01]))),
        ("unauthorized-bad-cap-grant", ZomeCallResponse::Unauthorized(
            ZomeCallAuthorization::BadCapGrant, None, "music_storage".into(), "receive_grant".into())),
        ("unauthorized-bad-nonce-with-secret", ZomeCallResponse::Unauthorized(
            ZomeCallAuthorization::BadNonce("Duplicate".into()), Some(CapSecret::from([5u8; 64])),
            "music_storage".into(), "receive_access_request".into())),
        ("network-error", ZomeCallResponse::NetworkError("recipient unreachable".into())),
    ]
    .into_iter()
    .map(|(name, r)| json!({
        "name": name,
        "bytes": hex::encode(holochain_serialized_bytes::encode(&r).unwrap()),
    }))
    .collect();
    println!("{}", serde_json::to_string_pretty(&json!({
        "generator": "web/hwc/remote-call/vectors-rs (holochain_zome_types 0.7.0)",
        "warning": "TEST-ONLY fixed keys (seed bytes 7 and 9)",
        "cases": cases,
        "responses": responses,
    })).unwrap());
}
