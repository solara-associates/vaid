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

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;
use sha2::{Digest, Sha256};

use vaid_mint::attestation::{
    canonical_attestation_signing_bytes, verify_attestation_authenticity, ConsentAttestation,
};
use vaid_mint::chain::{verify_chain, ChainVerification, PresentedBundle};
use vaid_mint::document::{
    canonical_vaid_signing_bytes, compute_lineage_hash, scope_contains, Vaid, SCOPE_SEPARATORS,
};
use vaid_mint::issuer_identity::kernel_key_thumbprint;
use vaid_mint::verify::verify_vaid_authenticity;

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
    let verdict = verify_chain(kp.public_key().as_ref(), &leaf, &PresentedBundle::new(docs));
    let actual = match verdict {
        ChainVerification::Attenuated => "attenuated",
        ChainVerification::Inauthentic => "inauthentic",
        ChainVerification::Unverifiable => "unverifiable",
        ChainVerification::NotAttenuated => "not_attenuated",
        ChainVerification::ConsentExpired => "consent_expired",
    };
    let want = v["expected"]["verification"].as_str().unwrap_or_default();
    if actual != want {
        return err(format!(
            "chain verdict '{actual}' != frozen '{want}' — the installed verifier \
             disagrees with the frozen walk"
        ));
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
        let boundary: Vec<String> = case["boundary"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|s| s.as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default();
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
            let old = boundary.iter().any(|s| resource.starts_with(s));
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

/// Every vector this firewall knows how to check, by filename.
///
/// The embedded set is enumerated by `build.rs`; this table says what each one
/// means. A vector in one and not the other is a BLOCKER, both ways — see [`run`].
const VECTOR_CHECKS: &[VectorCheck] = &[
    ("mint_v1.json", check_mint),
    ("mint_pop_v1.json", check_mint_pop),
    ("chain_v1.json", check_chain),
    ("attestation_v1.json", check_attestation),
    ("scope_v1.json", check_scope),
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
                .unwrap_or_else(|| match value["cases"].as_array() {
                    Some(c) => format!("{} case(s) — predicate vector, no digest", c.len()),
                    None => "(no digest)".to_string(),
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
