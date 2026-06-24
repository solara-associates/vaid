//! Proof-of-possession request signing primitive.
//!
//! A holder proves it controls a private key by signing the RFC 8785 (JCS)
//! canonical SHA-256 digest of a request payload with that key; a verifier checks
//! the signature against the *public* half it was handed. The verifier never sees
//! the private key.
//!
//! The signed payload carries **no embedded signature field** — the signature
//! travels alongside the payload — so there is nothing to null before
//! canonicalizing.
//!
//! This is the **single home** of the primitive: one canonicalization
//! implementation, so a signer and a conforming verifier agree byte-for-byte.

use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Compute the canonical 32-byte SHA-256 signing digest of any serializable
/// request payload, via RFC 8785 (JSON Canonicalization Scheme). This is the
/// exact byte string a holder signs and a verifier checks — both sides MUST
/// derive it the same way, which is why it lives in one place.
pub fn canonical_request_signing_bytes<T: Serialize>(payload: &T) -> Vec<u8> {
    let value =
        serde_json::to_value(payload).expect("request payload must be serde-serializable");
    let canonical = serde_jcs::to_vec(&value)
        .expect("RFC 8785 canonicalization of a valid Value cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    hasher.finalize().to_vec()
}

/// Sign a request payload with an Ed25519 key pair — the holder side of
/// proof-of-possession. Returns the detached signature bytes. Used by any holder
/// (the client SDK, or an in-process caller) to produce a valid PoP.
pub fn sign_payload<T: Serialize>(payload: &T, key_pair: &Ed25519KeyPair) -> Vec<u8> {
    let digest = canonical_request_signing_bytes(payload);
    key_pair.sign(&digest).as_ref().to_vec()
}

/// Verify an Ed25519 proof-of-possession signature over a request payload
/// against the supplied public key. Returns `true` iff the signature is valid
/// for `public_key_der`.
///
/// No error surface: a bad/forged signature, a malformed key, or a
/// wrong-length signature are all simply a verification result (`false`),
/// never a fault.
pub fn verify_signed_payload<T: Serialize>(
    payload: &T,
    public_key_der: &[u8],
    signature: &[u8],
) -> bool {
    let digest = canonical_request_signing_bytes(payload);
    let public_key = UnparsedPublicKey::new(&ED25519, public_key_der);
    public_key.verify(&digest, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use serde::Deserialize;

    fn fresh_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    #[derive(Serialize, Deserialize)]
    struct DummyPayload {
        a: String,
        b: u64,
        c: Vec<u8>,
    }

    fn dummy() -> DummyPayload {
        DummyPayload { a: "x".into(), b: 7, c: vec![1, 2, 3] }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let kp = fresh_keypair();
        let pk = {
            use ring::signature::KeyPair;
            kp.public_key().as_ref().to_vec()
        };
        let payload = dummy();
        let sig = sign_payload(&payload, &kp);
        assert!(verify_signed_payload(&payload, &pk, &sig));
    }

    #[test]
    fn verify_fails_against_a_different_key() {
        // The core PoP attack: a signature made with key A must not verify
        // against key B's public half.
        use ring::signature::KeyPair;
        let signer = fresh_keypair();
        let attacker_pub = fresh_keypair().public_key().as_ref().to_vec();
        let payload = dummy();
        let sig = sign_payload(&payload, &signer);
        assert!(
            !verify_signed_payload(&payload, &attacker_pub, &sig),
            "a signature over key A must not verify against key B"
        );
    }

    #[test]
    fn verify_fails_when_payload_tampered() {
        use ring::signature::KeyPair;
        let kp = fresh_keypair();
        let pk = kp.public_key().as_ref().to_vec();
        let sig = sign_payload(&dummy(), &kp);
        let tampered = DummyPayload { a: "x".into(), b: 8, c: vec![1, 2, 3] };
        assert!(!verify_signed_payload(&tampered, &pk, &sig));
    }

    #[test]
    fn verify_fails_on_garbage_signature() {
        use ring::signature::KeyPair;
        let kp = fresh_keypair();
        let pk = kp.public_key().as_ref().to_vec();
        assert!(!verify_signed_payload(&dummy(), &pk, &[0u8; 64]));
        assert!(!verify_signed_payload(&dummy(), &pk, &[0u8; 3]));
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_32_bytes() {
        let d1 = canonical_request_signing_bytes(&dummy());
        let d2 = canonical_request_signing_bytes(&dummy());
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }
}
