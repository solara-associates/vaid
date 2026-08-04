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
//! The vectors are `include_str!`d from `tests/vectors/`, which ships inside the
//! published `.crate` tarball. Because `cargo install` compiles from that tarball,
//! the bytes checked here are the bytes you received from crates.io — not a copy in
//! our repository, and not this comment. That is the whole point of a firewall: it
//! is only real if it runs against the artifact in your hands.
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

use std::process::ExitCode;

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::request_completion::{AssuranceTier, CompletionRecord};
use vaid_pop::vaid_pop::canonical_request_signing_bytes;

// Vendored copies, byte-identical to every other language's (a CI `cmp` enforces
// that). They ship in the crate so this runs with no checkout and no network.
const OPERATOR_VECTOR_JSON: &str = include_str!("../../tests/vectors/operator_pop_v1.json");
const COMPLETION_VECTOR_JSON: &str = include_str!("../../tests/vectors/completion_v1.json");

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

fn run() -> Result<(Value, Value), ConformanceError> {
    let operator = parse("operator_pop_v1", OPERATOR_VECTOR_JSON)?;
    let completion = parse("completion_v1", COMPLETION_VECTOR_JSON)?;
    check_operator_digest(&operator)?;
    check_operator_signature(&operator)?;
    check_completion(&completion)?;
    check_assurance_tiers(&completion)?;
    Ok((operator, completion))
}

fn main() -> ExitCode {
    match run() {
        Err(e) => {
            // Report on stderr so a mismatch is visible even when stdout is piped,
            // and exit non-zero so CI and `set -e` scripts stop.
            eprintln!("CROSS-LANGUAGE PoP FIREWALL: MISMATCH — BLOCKER\n{e}");
            ExitCode::FAILURE
        }
        Ok((o, c)) => {
            println!(
                "CROSS-LANGUAGE PoP FIREWALL: PASS — installed signer == frozen vectors, \
                 byte-for-byte\n  \
                 operator   digest    = {}\n  \
                 operator   signature = {}\n  \
                 completion digest    = {}\n  \
                 completion signature = {}",
                o["digest_sha256_hex"].as_str().unwrap_or_default(),
                o["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
                c["digest_sha256_hex"].as_str().unwrap_or_default(),
                c["ed25519"]["signature_hex"].as_str().unwrap_or_default(),
            );
            ExitCode::SUCCESS
        }
    }
}
