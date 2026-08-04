//! Packaged cross-language PoP conformance check — the firewall, shipped in the crate.
//!
//! Rust counterpart of `vaid_pop.conformance` (Python) and
//! `vaid-pop/src/bin/conformance.ts` (TypeScript). Those two ship an executable so a
//! consumer with only `pip install vaid-pop` / `npm install vaid-pop` can prove the
//! primitive they installed reproduces the frozen vectors byte-for-byte. Rust had no
//! equivalent: its gates were `#[test]`s under `tests/`, and `cargo test` needs a
//! checkout, so the only Rust answer was "clone our repository and trust that it is
//! the source your crate was built from". That is a strictly weaker claim than the
//! other two languages make, and this binary closes it:
//!
//! ```console
//! $ cargo install vaid-pop            # builds the binary from the crate you fetched
//! $ vaid-pop-conformance              # exit 0 = PASS, 1 = BLOCKER
//! ```
//!
//! The vectors ship inside the published `.crate` tarball. Because `cargo install`
//! compiles from that tarball, the bytes checked here are the bytes you received
//! from crates.io — not a copy in our repository, and not this comment. That is the
//! whole point of a firewall: it is only real if it runs against the artifact in
//! your hands.
//!
//! # It enumerates; it does not name a fixed set
//!
//! The vectors are embedded by `build.rs`, which scans `tests/vectors/` **at build
//! time** and emits one `include_str!` per file. This binary previously named two
//! literal paths, which is the same shape that let `chain_v1` and `attestation_v1`
//! ship unchecked in `vaid-mint` 0.4.0 — its firewall printed PASS having verified
//! neither of the vectors that release existed for. A third vector added here would
//! have gone the same way.
//!
//! So this fails in **both** directions:
//!
//! - a vector embedded in the crate with no entry in [`VECTOR_CHECKS`] is a BLOCKER;
//! - an entry in [`VECTOR_CHECKS`] whose vector is not embedded is a BLOCKER — a
//!   checker that quietly checks nothing is the same defect wearing the other hat;
//! - and no embedded vectors at all is a BLOCKER, because a firewall that checked
//!   nothing must never report PASS.
//!
//! It cannot verify a vector nobody has written a checker for; nothing can. What it
//! guarantees is that such a vector cannot ship *quietly*.
//!
//! WHAT IS AND IS NOT COVERED HERE. This crate is the signing *primitive*; the
//! request *signer* lives in `vaid-client`, which depends on this crate, so checking
//! the signer from here would invert the dependency. This binary therefore asserts
//! the primitive's contract — canonical digest, deterministic Ed25519 signature,
//! derived public key, and the completion-record vector including the `AssuranceTier`
//! enum-string drift guard. The signer path is asserted by
//! `cargo test -p vaid-client --test conformance`. Python's firewall covers both
//! because its signer ships in the same package; that is a packaging difference, not
//! a coverage gap in the standard.

use std::collections::BTreeSet;
use std::process::ExitCode;

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::request_completion::{AssuranceTier, CompletionRecord};
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

// Vendored copies, byte-identical to every other language's (a CI `cmp` enforces
// that). They ship in the crate so this runs with no checkout and no network, and
// are enumerated at build time rather than named here — see the module docs.
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

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("vector hex is well-formed"))
        .collect()
}

fn assert_hex(label: &str, got: &str, want: &str) -> Check {
    if got != want {
        return Err(ConformanceError(format!(
            "{label} diverged from the frozen vector — BLOCKER\n  got    = {got}\n  vector = {want}"
        )));
    }
    Ok(())
}

fn parse(label: &str, json: &str) -> Result<Value, ConformanceError> {
    serde_json::from_str(json)
        .map_err(|e| ConformanceError(format!("{label} vector does not parse — BLOCKER: {e}")))
}

fn seed_keypair(v: &Value) -> Result<Ed25519KeyPair, ConformanceError> {
    let seed = unhex(
        v["ed25519"]["private_key_seed_hex"]
            .as_str()
            .ok_or_else(|| ConformanceError("vector missing ed25519 seed — BLOCKER".into()))?,
    );
    Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| ConformanceError(format!("frozen seed is not a valid key — BLOCKER: {e}")))
}

/// JCS + SHA-256 over the REAL camelCase `RequestAuthPayload` reproduces the frozen
/// digest. Deserializing into the actual struct (rather than hashing the raw JSON)
/// is deliberate: it proves the field names and encodings this crate serializes are
/// the ones the vector froze, which is where cross-language drift actually happens.
fn check_operator_digest(v: &Value) -> Check {
    let payload: RequestAuthPayload = serde_json::from_value(v["input"].clone()).map_err(|e| {
        ConformanceError(format!(
            "vector input does not deserialize into a real RequestAuthPayload — BLOCKER: {e}"
        ))
    })?;
    let digest = canonical_request_signing_bytes(&payload);
    if digest.len() != 32 {
        return Err(ConformanceError(format!(
            "digest is {} bytes, expected 32 — BLOCKER",
            digest.len()
        )));
    }
    assert_hex(
        "operator canonical digest",
        &to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap_or_default(),
    )
}

/// From the frozen seed, derive the same public key and the same deterministic
/// signature, then verify it. Ed25519 is deterministic (RFC 8032), so a divergence
/// here is a real contract break and never flakiness.
fn check_operator_signature(v: &Value) -> Check {
    let kp = seed_keypair(v)?;
    assert_hex(
        "operator public key",
        &to_hex(kp.public_key().as_ref()),
        v["ed25519"]["public_key_hex"].as_str().unwrap_or_default(),
    )?;
    let payload: RequestAuthPayload = serde_json::from_value(v["input"].clone())
        .map_err(|e| ConformanceError(format!("vector input invalid — BLOCKER: {e}")))?;
    let digest = canonical_request_signing_bytes(&payload);
    let sig = kp.sign(&digest);
    assert_hex(
        "operator signature",
        &to_hex(sig.as_ref()),
        v["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
    )
}

/// The completion-record vector: same digest/signature discipline over a real
/// `CompletionRecord`.
fn check_completion(v: &Value) -> Check {
    let rec: CompletionRecord = serde_json::from_value(v["input"].clone()).map_err(|e| {
        ConformanceError(format!(
            "vector input does not deserialize into a real CompletionRecord — BLOCKER: {e}"
        ))
    })?;
    let digest = canonical_request_signing_bytes(&rec);
    assert_hex(
        "completion digest",
        &to_hex(&digest),
        v["digest_sha256_hex"].as_str().unwrap_or_default(),
    )?;
    let kp = seed_keypair(v)?;
    let sig = kp.sign(&digest);
    assert_hex(
        "completion signature",
        &to_hex(sig.as_ref()),
        v["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
    )
}

/// THE ENUM DRIFT GUARD: every `AssuranceTier` must serialize to exactly the frozen
/// string, in order. Enum strings travel inside signed bytes, so a rename that looks
/// cosmetic in one language silently breaks byte-identity with the other two.
fn check_assurance_tiers(v: &Value) -> Check {
    let frozen: Vec<String> = v["assurance_tier_strings"]
        .as_array()
        .ok_or_else(|| ConformanceError("vector missing assurance_tier_strings — BLOCKER".into()))?
        .iter()
        .map(|s| s.as_str().unwrap_or_default().to_string())
        .collect();
    let serialized: Vec<String> = [
        AssuranceTier::SelfReported,
        AssuranceTier::CounterSigned,
        AssuranceTier::ThirdPartyAttested,
    ]
    .iter()
    .map(|t| {
        serde_json::to_value(t)
            .ok()
            .and_then(|x| x.as_str().map(str::to_string))
            .unwrap_or_default()
    })
    .collect();
    if serialized != frozen {
        return Err(ConformanceError(format!(
            "AssuranceTier strings diverged from the frozen vector — BLOCKER\n  got    = {serialized:?}\n  vector = {frozen:?}"
        )));
    }
    Ok(())
}

/// One vector's filename paired with the checks that say what it means.
type VectorCheck = (&'static str, &'static [fn(&Value) -> Check]);

/// Every vector this firewall knows how to check, by filename.
///
/// The embedded set is enumerated by `build.rs`; this table says what each one
/// means. A vector in one and not the other is a BLOCKER, both ways — see [`run`].
const VECTOR_CHECKS: &[VectorCheck] = &[
    (
        "operator_pop_v1.json",
        &[check_operator_digest, check_operator_signature],
    ),
    (
        "completion_v1.json",
        &[check_completion, check_assurance_tiers],
    ),
];

/// Run every check against every embedded vector, returning `(name, digest)` pairs.
fn run() -> Result<Vec<(String, String)>, ConformanceError> {
    let embedded: BTreeSet<&str> = EMBEDDED_VECTORS.iter().map(|(n, _)| *n).collect();
    let known: BTreeSet<&str> = VECTOR_CHECKS.iter().map(|(n, _)| *n).collect();

    // A firewall that checked nothing must never report PASS.
    if embedded.is_empty() {
        return Err(ConformanceError(
            "no conformance vectors are embedded in this build — the crate was built \
             without tests/vectors/, so this binary can vouch for nothing"
                .into(),
        ));
    }

    let unchecked: Vec<&str> = embedded.difference(&known).copied().collect();
    if !unchecked.is_empty() {
        return Err(ConformanceError(format!(
            "vector(s) ship in this crate but no firewall check covers them: {} — add a \
             checker to VECTOR_CHECKS. A shipped-but-unchecked vector makes a PASS mean \
             less than it appears to.",
            unchecked.join(", ")
        )));
    }

    let missing: Vec<&str> = known.difference(&embedded).copied().collect();
    if !missing.is_empty() {
        return Err(ConformanceError(format!(
            "firewall expects vector(s) that are not in this crate: {} — the packaging \
             dropped them, or the check is stale.",
            missing.join(", ")
        )));
    }

    let mut checked = Vec::new();
    for (name, json) in EMBEDDED_VECTORS {
        let value = parse(name, json)?;
        let checks = VECTOR_CHECKS
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, c)| *c)
            .expect("membership proved above");
        for check in checks {
            check(&value)?;
        }
        checked.push((
            (*name).to_string(),
            value["digest_sha256_hex"]
                .as_str()
                .unwrap_or("(no digest)")
                .to_string(),
        ));
    }
    checked.sort();
    Ok(checked)
}

fn main() -> ExitCode {
    match run() {
        Err(e) => {
            // Report on stderr so a mismatch is visible even when stdout is piped,
            // and exit non-zero so CI and `set -e` scripts stop.
            eprintln!("CROSS-LANGUAGE PoP FIREWALL: MISMATCH — BLOCKER\n{e}");
            ExitCode::FAILURE
        }
        Ok(checked) => {
            println!(
                "CROSS-LANGUAGE PoP FIREWALL: PASS — installed signer == {} frozen \
                 vector(s), byte-for-byte",
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
