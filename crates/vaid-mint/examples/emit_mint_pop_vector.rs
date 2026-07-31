//! Generator for the frozen cross-language mint proof-of-possession vector
//! (`mint_pop_v1.json`).
//!
//! Run with `cargo run -p vaid-mint --example emit_mint_pop_vector` to print the
//! vector JSON. It builds a fully-specified, deterministic [`MintPopPayload`] —
//! the payload a holder signs to prove it controls the BYO key it registers at
//! mint — computes its canonical signing digest through the shared `vaid-pop`
//! primitive, and signs that digest with the holder's key.
//!
//! ## Why this vector exists
//!
//! `MintPopPayload` was the one signed structure in VAID with no frozen vector.
//! The three reference implementations agreed on it *by construction* (they share
//! the `vaid-pop` primitive and were written against each other) rather than
//! because an artifact held them to it — see `docs/spec/encoding.md` E.11. A fourth
//! implementation could have got it wrong, passed every conformance gate in the
//! repo, and failed only later as an unexplained proof-of-possession rejection.
//!
//! ## Two things this vector pins that no other one does
//!
//! 1. **A JSON `null` inside signed bytes.** This is the ROOT mint case, so
//!    `parentVaid` is `null`. No other frozen vector contains a null at all —
//!    `mint_v1`'s `parent_vaid` carries a UUID — so until now nothing held
//!    implementations to `docs/spec/encoding.md` E.7 (an absent value is `null`
//!    with its key retained, never an omitted key). An implementation that drops
//!    the key produces a different key set and a different digest.
//! 2. **The registered key is the signing key.** Unlike `mint_v1`, where
//!    `public_key_der` is arbitrary fixed bytes and the kernel key is a separate
//!    thing, here `publicKeyDer` IS the public half of the seed that signs. That
//!    is the entire semantic content of proof-of-possession: the signature must
//!    verify against the key being registered. A conforming implementation can
//!    therefore check this vector end-to-end through `verify_signed_payload`,
//!    exactly as `MintService::verify_pop_at_mint` does.
//!
//! The seed is the same RFC 8032 test seed used by `operator_pop_v1.json`, so the
//! registered public key is already a known value in the repo.

use ring::signature::{Ed25519KeyPair, KeyPair};

use vaid_mint::mint_types::VaidSeed;
use vaid_pop::vaid_pop::{canonical_request_signing_bytes, sign_payload};

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    // ── Fixed inputs (deterministic) ──
    const HOLDER_SEED_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let nonce = "0123456789abcdef0123456789abcdef";
    let issued_at_str = "2026-06-04T12:00:00Z";
    let issued_at = chrono::DateTime::parse_from_rfc3339(issued_at_str)
        .unwrap()
        .with_timezone(&chrono::Utc);

    // The holder's keypair. The REGISTERED key is this key's public half — that
    // binding is what the proof-of-possession proves.
    let holder_kp = Ed25519KeyPair::from_seed_unchecked(&unhex(HOLDER_SEED_HEX)).unwrap();
    let registered_key = holder_kp.public_key().as_ref().to_vec();

    // A root BYO-key mint: no parent, so `parentVaid` serializes to JSON null.
    let seed = VaidSeed {
        agent_class: "runner".into(),
        version: "1.0.0".into(),
        tenant_id: "aifactory".into(),
        parent_vaid: None,
        scope_boundary: vec!["data.aifactory".to_string()],
        capability_set: vec!["read".to_string()],
        public_key_der: Some(registered_key.clone()),
    };

    // Build the payload through the SINGLE constructor both holder and mint use,
    // so the vector cannot encode a shape the mint would not reconstruct.
    let payload = seed.pop_payload(registered_key.clone(), nonce.to_string(), issued_at);

    let digest = canonical_request_signing_bytes(&payload);
    let signature = sign_payload(&payload, &holder_kp);

    // The `input` is the real camelCase MintPopPayload, serialized by serde.
    let input = serde_json::to_value(&payload).unwrap();
    // Guard the two properties the doc comment claims, so a future edit to
    // VaidSeed/MintPopPayload cannot silently emit a vector that no longer pins
    // what this generator says it pins.
    assert!(
        input.get("parentVaid") == Some(&serde_json::Value::Null),
        "this vector must carry parentVaid as JSON null — that is half its purpose"
    );
    assert_eq!(
        input.get("publicKeyDer").unwrap(),
        &serde_json::json!(registered_key),
        "the registered key must be the signing key's public half"
    );

    let vector = serde_json::json!({
        "_comment": "Mint proof-of-possession conformance vector (v1). Load-bearing. `input` is a \
                     real MintPopPayload (#[serde(rename_all=camelCase)]) — the payload a holder \
                     signs to prove it controls the BYO public key it registers at mint. A \
                     conforming implementation MUST produce `digest_sha256_hex` from `input` via \
                     JCS (RFC 8785) -> SHA-256, and (given `ed25519.private_key_seed_hex`) \
                     reproduce `ed25519.signature_hex` byte-for-byte. TWO THINGS THIS VECTOR PINS \
                     THAT NO OTHER DOES: (1) it is the ROOT case, so `parentVaid` is JSON **null** \
                     — the only null in any frozen vector, pinning docs/spec/encoding.md E.7 (an \
                     absent value is null with its key retained, NEVER an omitted key); (2) \
                     `publicKeyDer` IS the public half of the signing seed, so the signature \
                     verifies against the key being registered — the whole semantic content of \
                     proof-of-possession, checkable end-to-end via verify_signed_payload. Before \
                     this vector existed, MintPopPayload was the one signed structure with no \
                     frozen artifact (encoding.md E.11): the implementations agreed by \
                     construction, not by proof.",
        "scheme": "JCS(RFC8785) over the camelCase MintPopPayload -> SHA-256 -> pure Ed25519 over \
                   the 32-byte digest as raw message; raw 64-byte signature; raw 32-byte Ed25519 \
                   public key. Byte-valued fields (publicKeyDer) are arrays of numbers, per \
                   docs/spec/encoding.md E.4.",
        "input": input,
        "digest_sha256_hex": to_hex(&digest),
        "ed25519": {
            "_comment": "Deterministic holder key (same RFC 8032 seed as operator_pop_v1.json). \
                         NOTE the difference from mint_v1.json: here the public key is not an \
                         independent value but exactly `input.publicKeyDer`, because a \
                         proof-of-possession signs FOR the key it registers.",
            "private_key_seed_hex": HOLDER_SEED_HEX,
            "public_key_hex": to_hex(&registered_key),
            "signature_hex": to_hex(&signature),
        }
    });

    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
