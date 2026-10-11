//! Packaged cross-language mint conformance check — the firewall, shipped in the crate.
//!
//! Rust counterpart of `vaid_mint.conformance` (Python) and
//! `vaid-mint/src/bin/conformance.ts` (TypeScript), and the sibling of
//! `vaid-pop-conformance`. Those ship an executable so a consumer with only
//! `pip install` / `npm install` can prove the mint they installed reproduces the
//! frozen vectors byte-for-byte. `vaid-mint` had no equivalent: its gates were
//! `#[test]`s under `tests/`, and `cargo test` needs a checkout, so the only Rust
//! answer was "clone our repository and trust that it is the source your crate was
//! built from" — a strictly weaker claim than the other two languages make.
//!
//! ```console
//! $ cargo install vaid-mint          # builds the binary from the crate you fetched
//! $ vaid-mint-conformance            # exit 0 = PASS, 1 = BLOCKER
//! ```
//!
//! Because `cargo install` compiles from that tarball, the bytes checked here are the
//! bytes you received from crates.io — not a copy in our repository, and not this
//! comment. A firewall is only real if it runs against the artifact in your hands.
//!
//! # It enumerates; it does not name a fixed set
//!
//! The vectors are embedded by `build.rs`, which scans `tests/vectors/` **at build
//! time** and emits one `include_str!` per file. That is the closest Rust gets to
//! what Python and TypeScript do at runtime, and it matters for a reason with
//! history: `vaid-mint` 0.4.0 shipped `chain_v1` and `attestation_v1`, its firewall
//! named a fixed set of two, and it printed PASS having checked neither of the
//! vectors that release existed for.
//!
//! So this fails in **both** directions:
//!
//! - a vector embedded in the crate with no entry in [`VECTOR_CHECKS`] is a BLOCKER —
//!   the defect above;
//! - an entry in [`VECTOR_CHECKS`] whose vector is not embedded is a BLOCKER — a
//!   checker that quietly checks nothing is the same defect wearing the other hat;
//! - and no embedded vectors at all is a BLOCKER, because a firewall that checked
//!   nothing must never report PASS.
//!
//! It cannot verify a vector nobody has written a checker for; nothing can. What it
//! guarantees is that such a vector cannot ship *quietly*.

use std::collections::BTreeSet;
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};

use vaid_mint::attestation::{
    canonical_attestation_signing_bytes, verify_attestation_authenticity, AttestationBundle,
    ConsentAttestation,
};
use vaid_mint::chain::{verify_chain_at, ChainVerification, PresentedBundle, SingleKernelKey};
use vaid_mint::document::{
    boundary_is_evaluable, canonical_vaid_signing_bytes, compute_lineage_hash,
    entry_claimed_resource, scope_contains, ScopeBoundaryEntry, Vaid, RECOGNISED_SCOPE_KINDS,
    SCOPE_SEPARATORS,
};
use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::mint::{
    expiry_attenuates_within, scope_attenuates_within, scope_attenuation_reason, AttenuationReason,
};
use vaid_mint::revocation::RevocationStatus;
use vaid_mint::verify::{verify_vaid_authenticity, verify_vaid_standing_from_json, VaidVerdict};

include!(concat!(env!("OUT_DIR"), "/embedded_vectors.rs"));

/// A cross-language byte-identity divergence — a hard BLOCKER, never ship-anyway.
#[derive(Debug)]
struct ConformanceError(String);

impl std::fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

type Check = Result<(), ConformanceError>;

/// One vector's filename paired with the function that says what it means.
type VectorCheck = (&'static str, fn(&Value) -> Check);

fn err<T>(message: impl Into<String>) -> Result<T, ConformanceError> {
    Err(ConformanceError(message.into()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn assert_hex(label: &str, got: &str, want: &str) -> Check {
    if got != want {
        return err(format!(
            "{label} diverged from the frozen vector\n  got    = {got}\n  vector = {want}"
        ));
    }
    Ok(())
}

fn doc_from(value: &Value) -> Result<Vaid, ConformanceError> {
    serde_json::from_value(value.clone())
        .map_err(|e| ConformanceError(format!("vector document is not a valid VAID: {e}")))
}

// ── per-vector checks ─────────────────────────────────────────────────────────

/// `mint_v1.json` — the signed VAID document: canonical digest, deterministic
/// kernel signature, lineage-hash derivation, the `vaid_id == agent_id` invariant,
/// and public-key-only verification.
fn check_mint(v: &Value) -> Check {
    let unsigned = doc_from(&v["input"])?;
    assert_hex(
        "Rust document digest",
        &to_hex(&canonical_vaid_signing_bytes(&unsigned)),
        v["digest_sha256_hex"].as_str().unwrap_or_default(),
    )?;

    let seed = unhex(
        v["ed25519"]["kernel_private_key_seed_hex"]
            .as_str()
            .unwrap_or_default(),
    );
    let kp = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(kp) => kp,
        Err(e) => {
            return err(format!(
                "vector kernel seed is not a valid Ed25519 seed: {e}"
            ))
        }
    };
    assert_hex(
        "Rust kernel public key",
        &to_hex(kp.public_key().as_ref()),
        v["ed25519"]["kernel_public_key_hex"]
            .as_str()
            .unwrap_or_default(),
    )?;
    assert_hex(
        "Rust kernel signature",
        &to_hex(kp.sign(&canonical_vaid_signing_bytes(&unsigned)).as_ref()),
        v["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
    )?;

    assert_hex(
        "Rust lineage_hash",
        &compute_lineage_hash(unsigned.parent_vaid(), &unsigned.agent_id()),
        unsigned.lineage_hash(),
    )?;
    if unsigned.vaid_id().to_string() != unsigned.agent_id().to_string() {
        return err("vaid_id MUST equal agent_id");
    }

    // The property a third party actually exercises: public key only, no issuer.
    let signed = unsigned.with_kernel_signature(unhex(
        v["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
    ));
    if !verify_vaid_authenticity(kp.public_key().as_ref(), &signed) {
        return err("the frozen document must verify under the frozen kernel public key");
    }
    Ok(())
}

/// `mint_pop_v1.json` — the `MintPopPayload` a holder signs. Checked here as frozen
/// bytes: the payload constructor is exercised by `tests/mint_pop_conformance.rs`,
/// which has the seed type it needs; duplicating that here would not add coverage.
fn check_mint_pop(v: &Value) -> Check {
    let seed = unhex(
        v["ed25519"]["private_key_seed_hex"]
            .as_str()
            .unwrap_or_default(),
    );
    let kp = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(kp) => kp,
        Err(e) => return err(format!("vector PoP seed is not a valid Ed25519 seed: {e}")),
    };
    assert_hex(
        "Rust mint-PoP public key",
        &to_hex(kp.public_key().as_ref()),
        v["ed25519"]["public_key_hex"].as_str().unwrap_or_default(),
    )?;
    assert_hex(
        "Rust mint-PoP signature",
        &to_hex(
            kp.sign(&unhex(v["digest_sha256_hex"].as_str().unwrap_or_default()))
                .as_ref(),
        ),
        v["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
    )?;
    // E.7: a present JSON null, not an omitted key.
    if v["input"].get("parentVaid") != Some(&Value::Null) {
        return err("parentVaid must be a PRESENT JSON null in this vector — encoding.md E.7");
    }
    Ok(())
}

/// `chain_v1.json` — THE WALK. Per-hop digests and signatures, the contract digest
/// over the whole frozen chain, and the verdict a third party reaches.
fn check_chain(v: &Value) -> Check {
    let seed = unhex(
        v["ed25519"]["kernel_private_key_seed_hex"]
            .as_str()
            .unwrap_or_default(),
    );
    let kp = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(kp) => kp,
        Err(e) => {
            return err(format!(
                "chain vector seed is not a valid Ed25519 seed: {e}"
            ))
        }
    };

    let entries = match v["chain"].as_array() {
        Some(e) => e,
        None => return err("chain vector has no `chain` array"),
    };

    let mut docs: Vec<Vaid> = Vec::with_capacity(entries.len());
    for entry in entries {
        let role = entry["_role"].as_str().unwrap_or("?");
        let unsigned = doc_from(&entry["document"])?;
        let digest = canonical_vaid_signing_bytes(&unsigned);
        assert_hex(
            &format!("chain hop {role} digest"),
            &to_hex(&digest),
            entry["digest_sha256_hex"].as_str().unwrap_or_default(),
        )?;
        assert_hex(
            &format!("chain hop {role} signature"),
            &to_hex(kp.sign(&digest).as_ref()),
            entry["signature_hex"].as_str().unwrap_or_default(),
        )?;
        docs.push(
            unsigned
                .with_kernel_signature(unhex(entry["signature_hex"].as_str().unwrap_or_default())),
        );
    }

    // The contract digest: one value that moves if any part of the frozen chain or
    // its expected outcome moves. The prose `_comment` is documentation, not
    // contract, and is excluded.
    let mut expected = v["expected"].clone();
    if let Some(map) = expected.as_object_mut() {
        map.remove("_comment");
    }
    let contract = serde_json::json!({ "chain": v["chain"], "expected": expected });
    let canonical = match serde_jcs::to_vec(&contract) {
        Ok(c) => c,
        Err(e) => return err(format!("chain contract does not canonicalize: {e}")),
    };
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    assert_hex(
        "chain contract digest",
        &to_hex(&hasher.finalize()),
        v["digest_sha256_hex"].as_str().unwrap_or_default(),
    )?;

    // The assertion the chain vector exists for: not the bytes, the VERDICT.
    let leaf = match docs.last() {
        Some(l) => l.clone(),
        None => return err("chain vector is empty"),
    };
    // AT the instant the vector states, never at this machine's clock. Every
    // document in chain_v1 expired on 2026-06-05; verified against a wall clock,
    // this assertion silently changed meaning on that date and went on passing
    // because nothing consulted expiry (vaid#79).
    let instant = match instant_of(&v["expected"]["verification_instant"]) {
        Some(i) => i,
        None => return err("chain vector states no verification_instant".to_string()),
    };
    let verdict = verify_chain_at(
        &SingleKernelKey::new(kp.public_key().as_ref()),
        &leaf,
        &PresentedBundle::new(docs),
        &AttestationBundle::default(),
        instant,
    );
    let actual = verdict_name(verdict);
    let want = v["expected"]["verification"].as_str().unwrap_or_default();
    if actual != want {
        return err(format!(
            "chain verdict '{actual}' != frozen '{want}' — the installed verifier \
             disagrees with the frozen walk"
        ));
    }
    Ok(())
}

/// The wire spelling of a chain verdict. One mapping, used by every chain check, so
/// two checks cannot name the same verdict differently.
fn verdict_name(verdict: ChainVerification) -> &'static str {
    match verdict {
        ChainVerification::Attenuated => "attenuated",
        ChainVerification::Inauthentic => "inauthentic",
        ChainVerification::Unverifiable => "unverifiable",
        ChainVerification::NotAttenuated => "not_attenuated",
        ChainVerification::Expired => "expired",
        ChainVerification::ConsentExpired => "consent_expired",
    }
}

/// A vector-stated verification instant, parsed. `None` if absent or unreadable —
/// which is a failure at the call site, never a silent fall back to the clock.
fn instant_of(value: &Value) -> Option<DateTime<Utc>> {
    let text = value.as_str()?;
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// `chain_expiry_v1.json` — the expiry invariant (vaid#79), on both surfaces.
///
/// A predicate vector: it carries no digest of its own, so the assertion IS the
/// verdict. Every document is still re-derived from the vector's kernel seed first,
/// because a verdict over bytes nobody checked is a verdict about nothing.
fn check_chain_expiry(v: &Value) -> Check {
    for case in v["expiry_containment"].as_array().unwrap_or(&Vec::new()) {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let parent = case["parent_expires_at"].as_str().unwrap_or("");
        let child = case["child_expires_at"].as_str();
        let permitted = expiry_attenuates_within(parent, child);
        let want = case["expected"].as_str().unwrap_or_default() == "permitted";
        if permitted != want {
            return err(format!(
                "expiry containment '{name}': expected {}, got {}",
                case["expected"].as_str().unwrap_or_default(),
                if permitted { "permitted" } else { "refused" }
            ));
        }
    }

    let empty = Vec::new();
    let cases = v["cases"].as_array().unwrap_or(&empty);
    if cases.is_empty() {
        return err("chain_expiry vector has no cases".to_string());
    }

    let mut saw_positive_chain = false;
    let mut saw_positive_containment = false;
    for case in v["expiry_containment"].as_array().unwrap_or(&empty) {
        if case["expected"].as_str() == Some("permitted") {
            saw_positive_containment = true;
        }
    }

    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>").to_string();
        let seed = unhex(
            v["ed25519"]["kernel_private_key_seed_hex"]
                .as_str()
                .unwrap_or_default(),
        );
        let kp = match Ed25519KeyPair::from_seed_unchecked(&seed) {
            Ok(k) => k,
            Err(e) => return err(format!("vector seed is not a usable Ed25519 seed: {e:?}")),
        };

        let mut docs: Vec<Vaid> = Vec::new();
        for entry in case["chain"].as_array().unwrap_or(&empty) {
            let role = entry["_role"].as_str().unwrap_or("?");
            let unsigned: Vaid = match serde_json::from_value(entry["document"].clone()) {
                Ok(d) => d,
                Err(e) => return err(format!("{name} / {role}: does not deserialize: {e}")),
            };
            let digest = canonical_vaid_signing_bytes(&unsigned);
            assert_hex(
                &format!("{name} / {role} digest"),
                &to_hex(&digest),
                entry["digest_sha256_hex"].as_str().unwrap_or_default(),
            )?;
            assert_hex(
                &format!("{name} / {role} signature"),
                &to_hex(kp.sign(&digest).as_ref()),
                entry["signature_hex"].as_str().unwrap_or_default(),
            )?;
            docs.push(
                unsigned.with_kernel_signature(unhex(
                    entry["signature_hex"].as_str().unwrap_or_default(),
                )),
            );
        }

        let leaf = match docs.last() {
            Some(l) => l.clone(),
            None => return err(format!("{name}: empty chain")),
        };
        let instant = match instant_of(&case["verification_instant"]) {
            Some(i) => i,
            None => return err(format!("{name}: no verification_instant")),
        };
        let actual = verdict_name(verify_chain_at(
            &SingleKernelKey::new(kp.public_key().as_ref()),
            &leaf,
            &PresentedBundle::new(docs),
            &AttestationBundle::default(),
            instant,
        ));
        let want = case["expected_verification"].as_str().unwrap_or_default();
        if actual != want {
            return err(format!(
                "chain verdict '{actual}' != frozen '{want}' for '{name}' — the \
                 installed verifier disagrees with the frozen expiry rule"
            ));
        }
        if want == "attenuated" {
            saw_positive_chain = true;
        }
    }

    // The controls are load-bearing: an implementation that refuses everything
    // satisfies every negative case above and nothing here.
    if !saw_positive_chain {
        return err("chain_expiry_v1 carries no positive control".to_string());
    }
    if !saw_positive_containment {
        return err("chain_expiry_v1 carries no positive containment control".to_string());
    }
    Ok(())
}

/// `attestation_v1.json` — the consent attestation: canonicalization, signature, and
/// that the frozen signature verifies as authentic.
fn check_attestation(v: &Value) -> Check {
    let unsigned: ConsentAttestation = match serde_json::from_value(v["attestation"].clone()) {
        Ok(a) => a,
        Err(e) => return err(format!("vector attestation does not deserialize: {e}")),
    };
    let digest = canonical_attestation_signing_bytes(&unsigned);
    assert_hex(
        "Rust attestation digest",
        &to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap_or_default(),
    )?;

    let seed = unhex(
        v["ed25519"]["kernel_private_key_seed_hex"]
            .as_str()
            .unwrap_or_default(),
    );
    let kp = match Ed25519KeyPair::from_seed_unchecked(&seed) {
        Ok(kp) => kp,
        Err(e) => return err(format!("attestation seed is not a valid Ed25519 seed: {e}")),
    };
    assert_hex(
        "Rust attestation signature",
        &to_hex(kp.sign(&digest).as_ref()),
        v["signature_hex"].as_str().unwrap_or_default(),
    )?;

    // The attesting key must be the one the attestation commits to.
    assert_hex(
        "attestation kernel_key_thumbprint",
        &kernel_key_thumbprint(kp.public_key().as_ref()),
        &unsigned.kernel_key_thumbprint,
    )?;

    let signed = unsigned.with_signature(unhex(v["signature_hex"].as_str().unwrap_or_default()));
    if !verify_attestation_authenticity(kp.public_key().as_ref(), &signed) {
        return err("the frozen attestation must verify as authentic under the frozen key");
    }
    Ok(())
}

/// Parse a typed `scope_boundary` (spec S.8) out of a vector case.
///
/// Goes through `ScopeBoundaryEntry`'s own `Deserialize` rather than reading
/// `kind`/`value` by hand, so the firewall exercises the SHIPPED shape gate. A
/// hand-rolled reader here would accept entries the library refuses and report a
/// pass for a build that cannot parse its own vector.
fn boundary_of(v: &Value) -> Result<Vec<ScopeBoundaryEntry>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| "scope_boundary is not an array".to_string())?;
    arr.iter()
        .map(|e| {
            serde_json::from_value::<ScopeBoundaryEntry>(e.clone())
                .map_err(|err| format!("scope_boundary entry {e}: {err}"))
        })
        .collect()
}

/// `scope_v1.json` — scope containment (spec S.3, ADR-0005).
///
/// The only check here that verifies a PREDICATE rather than bytes. Containment is
/// computed over a document and never appears inside one, so there is no digest to
/// reproduce and no signature to re-derive; what must agree across languages is the
/// verdict on every case.
///
/// It also asserts the vector still disagrees with bare prefix matching in at least
/// five places. Without that, a future edit could quietly reduce the vector to cases
/// both rules accept, leaving a green firewall that no longer covers the
/// sibling-capture bug the vector exists for.
fn check_scope(v: &Value) -> Check {
    let cases = match v["cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("scope vector carries no cases"),
    };

    let mut positives = 0usize;
    let mut negatives = 0usize;
    let mut disagreements = 0usize;

    for case in cases {
        let boundary = match boundary_of(&case["boundary"]) {
            Ok(b) => b,
            Err(e) => return err(format!("scope case boundary is not well formed: {e}")),
        };
        let resource = case["resource"].as_str().unwrap_or_default();
        let expected = match case["expected"].as_bool() {
            Some(b) => b,
            None => return err("scope case has no boolean `expected`"),
        };
        let why = case["why"].as_str().unwrap_or_default();

        let got = scope_contains(&boundary, resource);
        if got != expected {
            return err(format!(
                "scope containment mismatch: boundary={boundary:?} resource={resource:?} \
                 expected={expected} got={got} — {why}"
            ));
        }
        if expected {
            positives += 1;
        } else {
            negatives += 1;
        }
        if !boundary.is_empty() {
            let old = boundary
                .iter()
                .any(|e| entry_claimed_resource(e).is_some_and(|p| resource.starts_with(p)));
            if old != expected {
                disagreements += 1;
            }
        }
    }

    if positives == 0 || negatives == 0 {
        return err("scope vector must exercise both outcomes");
    }
    if disagreements < 5 {
        return err(format!(
            "scope vector must pin the sibling-capture regression class; only \
             {disagreements} case(s) disagree with bare prefix matching"
        ));
    }

    let declared: Vec<String> = SCOPE_SEPARATORS.iter().map(|c| c.to_string()).collect();
    let frozen: Vec<String> = v["rule"]["separators"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    if declared != frozen {
        return err(format!(
            "separator set mismatch: implementation {declared:?} != vector {frozen:?}"
        ));
    }
    Ok(())
}

/// `roundtrip_v1.json` -- round-trip verification (ADR-0006).
///
/// Verify-only: it pins a VERDICT OVER GIVEN BYTES rather than bytes over a given
/// input, the only shape that catches cross-implementation disagreement. It also
/// asserts the vector still DISCRIMINATES -- a dropping implementation must fail
/// it in BOTH directions -- so it cannot decay into cases every implementation
/// passes regardless of behaviour.
fn check_roundtrip(v: &Value) -> Check {
    use ring::signature::{UnparsedPublicKey, ED25519};
    let cases = match v["cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("roundtrip vector carries no cases"),
    };
    let pk_bytes = unhex(
        v["ed25519"]["kernel_public_key_hex"]
            .as_str()
            .unwrap_or_default(),
    );

    let sig_of = |doc: &Value| -> Vec<u8> {
        doc["kernel_signature"]
            .as_array()
            .map(|a| a.iter().map(|n| n.as_u64().unwrap_or(0) as u8).collect())
            .unwrap_or_default()
    };

    for case in cases {
        let doc = &case["document"];
        let expected = match case["expected_valid"].as_bool() {
            Some(b) => b,
            None => return err("roundtrip case has no boolean `expected_valid`"),
        };
        let parsed: Vaid = match serde_json::from_value(doc.clone()) {
            Ok(d) => d,
            Err(e) => return err(format!("roundtrip case document does not deserialize: {e}")),
        };
        // Canonicalization must be a function of the input: re-serializing MUST
        // reproduce what was presented, or the verdict below is about other bytes.
        if serde_json::to_value(&parsed).unwrap_or(Value::Null) != *doc {
            return err(format!(
                "roundtrip case {:?} did not round-trip byte-exactly -- this \
                 implementation is re-projecting the document (ADR-0006)",
                case["name"].as_str().unwrap_or_default()
            ));
        }
        let got = UnparsedPublicKey::new(&ED25519, &pk_bytes)
            .verify(&canonical_vaid_signing_bytes(&parsed), &sig_of(doc))
            .is_ok();
        if got != expected {
            return err(format!(
                "roundtrip case {:?}: got {got}, expected {expected} -- {}",
                case["name"].as_str().unwrap_or_default(),
                case["why"].as_str().unwrap_or_default()
            ));
        }
    }

    let (mut false_negative, mut false_accept) = (false, false);
    for case in cases {
        let doc = &case["document"];
        let expected = case["expected_valid"].as_bool().unwrap_or(false);
        let mut dropped = doc.clone();
        if let Value::Object(m) = &mut dropped {
            m.retain(|k, _| !k.starts_with("x_"));
            m.insert("kernel_signature".into(), Value::Null);
        }
        let digest = {
            let c = match serde_jcs::to_vec(&dropped) {
                Ok(c) => c,
                Err(e) => return err(format!("jcs failed: {e}")),
            };
            let mut h = Sha256::new();
            h.update(&c);
            h.finalize().to_vec()
        };
        let got = UnparsedPublicKey::new(&ED25519, &pk_bytes)
            .verify(&digest, &sig_of(doc))
            .is_ok();
        if got != expected {
            if expected {
                false_negative = true;
            } else {
                false_accept = true;
            }
        }
    }
    if !false_negative || !false_accept {
        return err(
            "the roundtrip vector no longer catches a dropping implementation in both \
             directions -- its discriminating power has been weakened",
        );
    }
    Ok(())
}

/// `verdict_v1.json` — the negative path (graded verdicts).
///
/// The other checks in this file ask "does the installed mint produce the same
/// bytes as everyone else". This one asks "does it REFUSE the same way, and say
/// the same thing about why". The happy-path vectors cannot answer that: they only
/// ever exercise documents that work.
///
/// It asserts the REASON, not just the boolean. Three implementations that reject
/// the same document for three different reasons agree on every boolean and
/// disagree about what happened — and a `cargo install` consumer whose build
/// disagrees with the vector on a reason has a mint that will log, alert and retry
/// differently from every other deployment.
///
/// It also refuses to pass a vector that has lost its teeth: no positive control
/// on either surface, a single refusal reason across every negative case, or a
/// vocabulary that has drifted from [`VaidVerdict::ALL`] are all BLOCKERs. A green
/// firewall over a vector that asserts nothing is the masked-green defect this
/// crate keeps finding.
fn check_verdict(v: &Value) -> Check {
    let cases = match v["cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("verdict vector carries no cases"),
    };
    let pk = unhex(
        v["ed25519"]["kernel_public_key_hex"]
            .as_str()
            .unwrap_or_default(),
    );

    let mut positives = (0usize, 0usize); // (standing, attenuation)
    let mut negatives = (0usize, 0usize);
    let mut refusal_reasons: BTreeSet<String> = BTreeSet::new();
    let mut exercised: BTreeSet<String> = BTreeSet::new();

    for case in cases {
        let name = case["name"].as_str().unwrap_or_default();
        let why = case["why"].as_str().unwrap_or_default();
        let expected_reason = match case["expected_reason"].as_str() {
            Some(r) => r,
            None => return err(format!("verdict case {name:?} has no expected_reason")),
        };
        let expected_valid = match case["expected_valid"].as_bool() {
            Some(b) => b,
            None => {
                return err(format!(
                    "verdict case {name:?} has no boolean expected_valid"
                ))
            }
        };

        let (reason, valid) = match case["surface"].as_str() {
            Some("standing") => {
                let text = match case["document_json"].as_str() {
                    Some(t) => t,
                    None => return err(format!("standing case {name:?} has no document_json")),
                };
                let rev = match case["revocation"].as_str() {
                    Some("not_revoked") => RevocationStatus::NotRevoked,
                    Some("revoked") => RevocationStatus::Revoked,
                    Some("unavailable") => RevocationStatus::Unavailable,
                    other => {
                        return err(format!(
                            "standing case {name:?} names unknown revocation state {other:?}"
                        ))
                    }
                };
                let verdict = verify_vaid_standing_from_json(&pk, text, rev);
                (verdict.code().to_string(), verdict.is_valid())
            }
            Some("attenuation") => {
                let parent = match boundary_of(&case["parent_scope"]) {
                    Ok(b) => b,
                    Err(e) => return err(format!("attenuation case {name:?} parent: {e}")),
                };
                let child = match boundary_of(&case["child_scope"]) {
                    Ok(b) => b,
                    Err(e) => return err(format!("attenuation case {name:?} child: {e}")),
                };
                let reason = scope_attenuation_reason(&parent, &child);
                // The bool is DERIVED from the reason in the library; asserted
                // here so a build whose two answers disagree cannot pass.
                let ok = scope_attenuates_within(&parent, &child);
                if ok != (reason == AttenuationReason::Attenuated) {
                    return err(format!(
                        "attenuation case {name:?}: the boolean and the reason disagree"
                    ));
                }
                (attenuation_code(reason).to_string(), ok)
            }
            other => {
                return err(format!(
                    "verdict case {name:?} names unknown surface {other:?}"
                ))
            }
        };

        if reason != expected_reason {
            return err(format!(
                "verdict case {name:?}: reason {reason:?} != frozen {expected_reason:?} — {why}\n  \
                 A reason mismatch is a divergence even where the boolean agrees: this \
                 build and the vector disagree about WHAT HAPPENED."
            ));
        }
        if valid != expected_valid {
            return err(format!(
                "verdict case {name:?}: valid={valid}, frozen {expected_valid} — {why}"
            ));
        }

        let is_standing = case["surface"] == "standing";
        if expected_valid {
            if is_standing {
                positives.0 += 1;
            } else {
                positives.1 += 1;
            }
        } else {
            if is_standing {
                negatives.0 += 1;
            } else {
                negatives.1 += 1;
            }
            refusal_reasons.insert(reason.clone());
        }
        exercised.insert(expected_reason.to_string());
    }

    // The vector must still have teeth. Each of these is a way it could be edited
    // into something that passes for every implementation regardless of behaviour.
    if positives.0 == 0 || positives.1 == 0 {
        return err(
            "the verdict vector has lost a positive control (standing and attenuation \
             each need one) — an implementation that refused every input would pass it",
        );
    }
    if negatives.0 == 0 || negatives.1 == 0 {
        return err(
            "the verdict vector has lost a negative case on one of its surfaces — an \
             implementation that accepted every input would pass it",
        );
    }
    if refusal_reasons.len() < 2 {
        return err(format!(
            "every refusing case expects the same reason ({refusal_reasons:?}) — a \
             boolean-only implementation would pass this vector, so the reason \
             assertions would be checking nothing"
        ));
    }

    // Vocabulary agreement, both directions: a reason the vector declares that this
    // build cannot return means the vector was written against a different
    // implementation; a verdict this build can return that the vector never names
    // is a state shipping unchecked.
    let declared: BTreeSet<String> = v["reasons"]["standing"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default();
    let implemented: BTreeSet<String> = VaidVerdict::ALL
        .iter()
        .map(|r| r.code().to_string())
        .collect();
    if declared != implemented {
        return err(format!(
            "the verdict vector's standing vocabulary and this build's VaidVerdict \
             disagree\n  only in the vector:         {:?}\n  only in the implementation: {:?}",
            declared.difference(&implemented).collect::<Vec<_>>(),
            implemented.difference(&declared).collect::<Vec<_>>(),
        ));
    }
    let all_declared: BTreeSet<String> = declared
        .iter()
        .cloned()
        .chain(
            v["reasons"]["attenuation"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|s| s.as_str().unwrap_or_default().to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .collect();
    let unexercised: Vec<_> = all_declared.difference(&exercised).collect();
    if !unexercised.is_empty() {
        return err(format!(
            "reason(s) declared by the vector but exercised by no case: {unexercised:?} \
             — a state with no case behind it is a claim with no evidence"
        ));
    }
    Ok(())
}

/// The wire string for an attenuation reason. The vocabulary
/// `verdict_v1.json` and `scope_kinds_v1.json` are written in, and the thing
/// three implementations must spell the same way.
fn attenuation_code(reason: AttenuationReason) -> &'static str {
    match reason {
        AttenuationReason::Attenuated => "attenuated",
        AttenuationReason::ScopeEscalation => "scope_escalation",
        AttenuationReason::UnknownScopeKind => "unknown_scope_kind",
    }
}

/// `scope_kinds_v1.json` — the typed boundary (spec S.8 to S.12, ADR-0009).
///
/// Three surfaces in one file, because they share ONE recognised-kind registry
/// and splitting them is how the registry acquires two readers that disagree:
/// containment over a typed boundary, attenuation over two of them, and
/// parse-level acceptance of boundary bytes.
///
/// The declared `rule.kinds` is checked against [`RECOGNISED_SCOPE_KINDS`]
/// directly, so a kind added to the code without being added to the
/// specification fails here, and so does the reverse.
fn check_scope_kinds(v: &Value) -> Check {
    // The registry, both directions.
    let declared: BTreeSet<&str> = match v["rule"]["kinds"].as_array() {
        Some(a) => a.iter().filter_map(|k| k.as_str()).collect(),
        None => return err("scope-kinds vector declares no `rule.kinds`"),
    };
    let built: BTreeSet<&str> = RECOGNISED_SCOPE_KINDS.iter().copied().collect();
    if declared != built {
        return err(format!(
            "recognised scope kinds disagree: vector declares {declared:?}, this build              recognises {built:?} — a kind in one and not the other is a fail-closed              rule that fails open in whichever direction the gap runs"
        ));
    }

    // Surface A: containment.
    let cases = match v["containment_cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("scope-kinds vector carries no containment_cases"),
    };
    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let boundary = match boundary_of(&case["boundary"]) {
            Ok(b) => b,
            Err(e) => return err(format!("containment case {name:?}: {e}")),
        };
        let resource = case["resource"].as_str().unwrap_or_default();
        let expected = match case["expected"].as_bool() {
            Some(b) => b,
            None => return err(format!("containment case {name:?} has no `expected`")),
        };
        let got = scope_contains(&boundary, resource);
        if got != expected {
            return err(format!(
                "containment case {name:?}: expected {expected}, got {got}"
            ));
        }
        // The reason must agree too, not merely the boolean.
        let expected_reason = case["expected_reason"].as_str().unwrap_or_default();
        let got_reason = if !boundary_is_evaluable(&boundary) {
            "unknown_scope_kind"
        } else if got {
            "contained"
        } else {
            "not_contained"
        };
        if got_reason != expected_reason {
            return err(format!(
                "containment case {name:?}: reason {got_reason:?} != frozen                  {expected_reason:?} — a refusal and an inability to evaluate are                  different accusations and agree on every boolean"
            ));
        }
    }

    // Surface B: attenuation.
    let cases = match v["attenuation_cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("scope-kinds vector carries no attenuation_cases"),
    };
    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let parent = match boundary_of(&case["parent_scope"]) {
            Ok(b) => b,
            Err(e) => return err(format!("attenuation case {name:?} parent: {e}")),
        };
        let child = match boundary_of(&case["child_scope"]) {
            Ok(b) => b,
            Err(e) => return err(format!("attenuation case {name:?} child: {e}")),
        };
        let reason = scope_attenuation_reason(&parent, &child);
        let ok = scope_attenuates_within(&parent, &child);
        if ok != (reason == AttenuationReason::Attenuated) {
            return err(format!(
                "attenuation case {name:?}: the boolean and the reason disagree"
            ));
        }
        let expected_valid = case["expected_valid"].as_bool().unwrap_or(false);
        let expected_reason = case["expected_reason"].as_str().unwrap_or_default();
        if ok != expected_valid || attenuation_code(reason) != expected_reason {
            return err(format!(
                "attenuation case {name:?}: got ({ok}, {:?}), frozen                  ({expected_valid}, {expected_reason:?})",
                attenuation_code(reason)
            ));
        }
    }

    // Surface C: the shape gate, over TEXT, so the malformed cases travel the
    // same code path as the well-formed ones.
    let cases = match v["shape_cases"].as_array() {
        Some(c) if !c.is_empty() => c,
        _ => return err("scope-kinds vector carries no shape_cases"),
    };
    let mut parsed_controls = 0usize;
    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let text = match case["boundary_json"].as_str() {
            Some(t) => t,
            None => return err(format!("shape case {name:?} has no boundary_json")),
        };
        // Every case's bytes are themselves well-formed JSON, so what is being
        // exercised is the SHAPE gate and never the JSON parser.
        let value: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                return err(format!(
                    "shape case {name:?} is not valid JSON ({e}) — it would test the                      parser rather than the shape gate"
                ))
            }
        };
        let got_reason = match boundary_of(&value) {
            Ok(_) => "parsed",
            Err(_) => "unparseable",
        };
        let expected_reason = case["expected_reason"].as_str().unwrap_or_default();
        if got_reason != expected_reason {
            return err(format!(
                "shape case {name:?}: {got_reason:?} != frozen {expected_reason:?}"
            ));
        }
        if got_reason == "parsed" {
            parsed_controls += 1;
        }
    }
    if parsed_controls < 2 {
        return err(
            "the shape surface needs at least two positive controls, one of them an              unrecognised kind — without them, refusing every boundary passes every case",
        );
    }
    Ok(())
}

/// Every vector this firewall knows how to check, by filename.
///
/// The embedded set is enumerated by `build.rs`; this table says what each one
/// means. A vector in one and not the other is a BLOCKER, both ways — see [`run`].
const VECTOR_CHECKS: &[VectorCheck] = &[
    ("mint_v1.json", check_mint),
    ("mint_pop_v1.json", check_mint_pop),
    ("chain_v1.json", check_chain),
    ("chain_expiry_v1.json", check_chain_expiry),
    ("attestation_v1.json", check_attestation),
    ("scope_v1.json", check_scope),
    ("roundtrip_v1.json", check_roundtrip),
    ("verdict_v1.json", check_verdict),
    ("scope_kinds_v1.json", check_scope_kinds),
];

/// Run every check against every embedded vector, returning `(name, digest)` pairs.
fn run() -> Result<Vec<(String, String)>, ConformanceError> {
    let embedded: BTreeSet<&str> = EMBEDDED_VECTORS.iter().map(|(n, _)| *n).collect();
    let known: BTreeSet<&str> = VECTOR_CHECKS.iter().map(|(n, _)| *n).collect();

    // A firewall that checked nothing must never report PASS.
    if embedded.is_empty() {
        return err(
            "no conformance vectors are embedded in this build — the crate was built \
             without tests/vectors/, so this binary can vouch for nothing",
        );
    }

    let unchecked: Vec<&str> = embedded.difference(&known).copied().collect();
    if !unchecked.is_empty() {
        return err(format!(
            "vector(s) ship in this crate but no firewall check covers them: {} — add a \
             checker to VECTOR_CHECKS. A shipped-but-unchecked vector makes a PASS mean \
             less than it appears to.",
            unchecked.join(", ")
        ));
    }

    let missing: Vec<&str> = known.difference(&embedded).copied().collect();
    if !missing.is_empty() {
        return err(format!(
            "firewall expects vector(s) that are not in this crate: {} — the packaging \
             dropped them, or the check is stale.",
            missing.join(", ")
        ));
    }

    let mut checked = Vec::new();
    for (name, json) in EMBEDDED_VECTORS {
        let value: Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => return err(format!("{name} is not valid JSON: {e}")),
        };
        let check = VECTOR_CHECKS
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, f)| f)
            .expect("membership proved above");
        check(&value)?;
        checked.push((
            (*name).to_string(),
            // A predicate vector pins verdicts, not bytes, so it has no digest to
            // report. Say what it DID check rather than printing a blank, so the
            // output still evidences that this vector was looked at.
            value["digest_sha256_hex"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| {
                    // `cases` for most predicate vectors; a vector with several
                    // named surfaces carries none, so count across all of them
                    // rather than print a blank for the one file whose shape is
                    // different.
                    let counted: usize = [
                        "cases",
                        "containment_cases",
                        "attenuation_cases",
                        "shape_cases",
                    ]
                    .iter()
                    .filter_map(|k| value[*k].as_array())
                    .map(|a| a.len())
                    .sum();
                    if counted > 0 {
                        format!("{counted} case(s) — predicate vector, no digest")
                    } else {
                        "(no digest)".to_string()
                    }
                }),
        ));
    }
    checked.sort();
    Ok(checked)
}

fn main() -> ExitCode {
    match run() {
        Err(e) => {
            eprintln!("CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n{e}");
            ExitCode::FAILURE
        }
        Ok(checked) => {
            println!(
                "CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == {} frozen vector(s), \
                 byte-for-byte",
                checked.len()
            );
            // Every vector named with its digest. The COUNT is the point: a release
            // that adds a vector visibly adds a line here, so "did the firewall look
            // at the thing this release was about" is answerable from the output.
            for (name, digest) in &checked {
                println!("  {name:22} {digest}");
            }
            ExitCode::SUCCESS
        }
    }
}
