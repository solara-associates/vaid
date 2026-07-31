//! The two v3 issuer-identity values: the trust domain and the kernel key
//! thumbprint (ADR-0004).
//!
//! Both live inside the signed VAID document, so both are inside the canonical
//! bytes and neither may be normalized at verification — a verifier that
//! "corrects" a value recomputes different bytes from the ones the signer
//! covered, which is the `docs/spec/encoding.md` E.6 timestamp failure in a new
//! place. Producers emit the conforming form; non-conforming input is rejected,
//! never repaired.
//!
//! # What each one answers
//!
//! - [`kernel_key_thumbprint`] answers *which key signed this*. It is a
//!   commitment: given a document and a candidate key, correspondence is
//!   decidable offline by one hash, with no network and no issuer.
//! - [`is_valid_trust_domain`] constrains *who claims to have issued it*, so a
//!   verifier has something to look the thumbprint up **under**. A thumbprint
//!   alone gives selection with nothing to select within.
//!
//! Neither establishes attribution. A self-signed document whose thumbprint
//! matches its own key is internally consistent and entirely unauthorized. The
//! binding from a trust domain to an authorized key set is out-of-band, static,
//! and cached — see ADR-0004.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};

/// The RFC 9278 JWK Thumbprint URI prefix. SHA-256 is mandatory-to-implement
/// there and is the only algorithm this version emits; the prefix carries the
/// algorithm so a later move off SHA-256 needs no new field.
pub const THUMBPRINT_URI_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// Maximum total length of a trust domain, in bytes (the DNS name limit).
pub const TRUST_DOMAIN_MAX_LEN: usize = 253;
/// Maximum length of a single label, in bytes.
pub const TRUST_DOMAIN_MAX_LABEL_LEN: usize = 63;

/// Compute the RFC 9278 thumbprint URI of a raw 32-byte Ed25519 public key,
/// over the RFC 7638 JWK thumbprint.
///
/// # Why this is not hand-rolled
///
/// RFC 7638's substance is the canonicalization: take **only** the required
/// members, order them lexicographically, emit no whitespace. For an OKP key the
/// required members are exactly `crv`, `kty`, `x` (RFC 8037 §2). That is
/// precisely what RFC 8785 (JCS) produces for the same object — JCS sorts keys
/// by UTF-16 code unit, and `crv` < `kty` < `x` under every ordering — so this
/// delegates the risky half to `serde_jcs`, the same JCS implementation the
/// signing path already uses and the frozen vectors already prove. Only the
/// three-member JWK is written here.
///
/// Adding a JOSE library to each of three languages for this would mean three
/// new supply-chain dependencies in a security standard, to do what a
/// vector-proven dependency already does.
///
/// Correctness is pinned against the published RFC 8037 Appendix A.3 thumbprint
/// vector in the tests below, so this is checked against the standard rather
/// than only against itself.
pub fn kernel_key_thumbprint(public_key: &[u8]) -> String {
    let x = URL_SAFE_NO_PAD.encode(public_key);
    let jwk = json!({ "crv": "Ed25519", "kty": "OKP", "x": x });
    let canonical =
        serde_jcs::to_vec(&jwk).expect("RFC 8785 canonicalization of a fixed 3-member object");
    let digest = Sha256::digest(&canonical);
    format!("{THUMBPRINT_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(digest))
}

/// Is `s` a well-formed trust domain (ADR-0004)?
///
/// Lowercase ASCII letters, digits, `-` and `.`; at least two labels; each label
/// 1–63 bytes with no leading or trailing `-`; no empty label and no trailing
/// dot; 1–253 bytes total; and a final label that is not all-numeric.
///
/// Two deliberate divergences from SPIFFE's trust-domain grammar, each with a
/// reason:
///
/// - **No underscore.** SPIFFE permits it. An underscore cannot appear in a
///   hostname, so such a name cannot be bound by the WebPKI or DNS anchor this
///   identifier exists to be bound by.
/// - **No case-insensitive comparison.** SPIFFE normalizes case when comparing.
///   This cannot: the value is inside signed bytes, so comparison is byte
///   equality and an uppercase producer is non-conforming rather than corrected.
///
/// The all-numeric final label rule excludes dotted-quad IP literals. SPIFFE
/// deliberately permits IPs; this does not, because an IP has no controller to
/// bind to.
///
/// Special-use names (RFC 2606 / RFC 6761 — `example`, `invalid`, `localhost`,
/// `test`, `local`, `internal`) are **permitted by this grammar**: the frozen
/// conformance vector needs one, and `vaid.example` is what it uses. Policy, not
/// grammar, forbids them in production — a verifier SHOULD refuse to bind a
/// trust bundle to a special-use name. See [`is_special_use_trust_domain`].
pub fn is_valid_trust_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > TRUST_DOMAIN_MAX_LEN {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for label in &labels {
        if label.is_empty() || label.len() > TRUST_DOMAIN_MAX_LABEL_LEN {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return false;
        }
    }
    // Final label all-numeric would admit `192.0.2.1`.
    !labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit())
}

/// Is `s` a special-use name reserved by RFC 2606 / RFC 6761?
///
/// Advisory, not a conformance rule. A verifier SHOULD refuse to hold a trust
/// bundle for one of these, which is what makes the frozen vector's issuer
/// (`vaid.example`) unbindable by rule rather than by convention — the vector
/// publishes its own kernel private seed, so anyone can sign documents under it.
pub fn is_special_use_trust_domain(s: &str) -> bool {
    const RESERVED_TLDS: [&str; 6] = [
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "internal",
    ];
    match s.rsplit('.').next() {
        Some(tld) => RESERVED_TLDS.contains(&tld),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published RFC 8037 Appendix A.3 JWK Thumbprint vector. This is the
    /// test that matters: it checks the implementation against the STANDARD,
    /// not against itself. Every other test here is self-consistency.
    #[test]
    fn matches_the_published_rfc_8037_thumbprint_vector() {
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let key = URL_SAFE_NO_PAD.decode(x).expect("RFC 8037 test key");
        assert_eq!(
            kernel_key_thumbprint(&key),
            format!("{THUMBPRINT_URI_PREFIX}kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
        );
    }

    #[test]
    fn thumbprint_is_deterministic_and_key_bound() {
        let a = [7u8; 32];
        let b = [8u8; 32];
        assert_eq!(kernel_key_thumbprint(&a), kernel_key_thumbprint(&a));
        assert_ne!(kernel_key_thumbprint(&a), kernel_key_thumbprint(&b));
        assert!(kernel_key_thumbprint(&a).starts_with(THUMBPRINT_URI_PREFIX));
    }

    #[test]
    fn accepts_conforming_trust_domains() {
        for s in [
            "vaid.example",
            "synthera.solara.associates",
            "a.bc",
            "x-1.example",
            "deep.ly.nested.name.example",
        ] {
            assert!(is_valid_trust_domain(s), "should accept {s}");
        }
    }

    #[test]
    fn rejects_non_conforming_trust_domains() {
        for s in [
            "",                    // empty
            "single",              // one label
            "Solara.Associates",   // uppercase — non-conforming, never normalized
            "solara.associates.",  // trailing dot
            "solara..associates",  // empty label
            "-lead.example",       // leading hyphen
            "trail-.example",      // trailing hyphen
            "under_score.example", // underscore: diverges from SPIFFE, deliberately
            "192.0.2.1",           // IP literal — all-numeric final label
            "sp ace.example",      // whitespace
            "sοlara.associates",   // Greek omicron — homograph
        ] {
            assert!(!is_valid_trust_domain(s), "should reject {s:?}");
        }
    }

    #[test]
    fn label_and_total_length_bounds_are_enforced() {
        let long_label = "a".repeat(64);
        assert!(!is_valid_trust_domain(&format!("{long_label}.example")));
        let ok_label = "a".repeat(63);
        assert!(is_valid_trust_domain(&format!("{ok_label}.example")));

        // Exactly 253 bytes conforms; 254 does not. 63+1+63+1+63+1+61 = 253.
        let at_limit = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(61)
        );
        assert_eq!(at_limit.len(), TRUST_DOMAIN_MAX_LEN);
        assert!(is_valid_trust_domain(&at_limit));

        let over_limit = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(63),
            "a".repeat(62)
        );
        assert_eq!(over_limit.len(), TRUST_DOMAIN_MAX_LEN + 1);
        assert!(!is_valid_trust_domain(&over_limit));
    }

    #[test]
    fn special_use_names_are_grammatical_but_flagged() {
        assert!(is_valid_trust_domain("vaid.example"));
        assert!(is_special_use_trust_domain("vaid.example"));
        assert!(is_special_use_trust_domain("foo.internal"));
        assert!(!is_special_use_trust_domain("synthera.solara.associates"));
    }
}
