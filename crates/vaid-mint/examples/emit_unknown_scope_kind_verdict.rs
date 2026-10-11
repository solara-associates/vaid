//! The verdicts this implementation returns for an UNRECOGNISED scope-boundary
//! kind, as JSON, for cross-language comparison (spec S.10, ADR-0009).
//!
//! Run with `cargo run -p vaid-mint --example emit_unknown_scope_kind_verdict`.
//! `scripts/unknown_scope_kind_agreement.sh` runs this and its Python and
//! TypeScript twins and diffs the output.
//!
//! # Why this is a script and not only a vector assertion
//!
//! Each language's conformance test already checks its own verdict against the
//! vector, so all three agreeing WITH THE VECTOR implies they agree with each
//! other. That implication is only as good as the three test harnesses being
//! equivalent, and the fail-closed rule of S.10 is exactly where they are most
//! likely not to be: Rust gets its shape gate from `serde`, Python and TypeScript
//! hand-roll theirs, and the whole point of S.10 is a document that PARSES in all
//! three and is then refused by a verdict. A single artifact, diffed, is a direct
//! reading of that rather than three indirect ones.
//!
//! The inputs are taken from the frozen vectors rather than constructed here, so
//! the three implementations are provably answering about the SAME bytes: CI
//! `cmp`s the three copies of each vector, so "read it from your own copy" and
//! "read it from one shared copy" are the same thing.

use serde_json::{json, Value};

use vaid_mint::mint::{scope_attenuation_reason, AttenuationReason};
use vaid_mint::revocation::RevocationStatus;
use vaid_mint::verify::verify_vaid_standing_from_json;
use vaid_mint::ScopeBoundaryEntry;

const VERDICT_VECTOR: &str = include_str!("../tests/vectors/verdict_v1.json");
const SCOPE_KINDS_VECTOR: &str = include_str!("../tests/vectors/scope_kinds_v1.json");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn attenuation_code(reason: AttenuationReason) -> &'static str {
    match reason {
        AttenuationReason::Attenuated => "attenuated",
        AttenuationReason::ScopeEscalation => "scope_escalation",
        AttenuationReason::UnknownScopeKind => "unknown_scope_kind",
    }
}

fn main() {
    let verdict: Value = serde_json::from_str(VERDICT_VECTOR).expect("verdict_v1 parses");
    let kinds: Value = serde_json::from_str(SCOPE_KINDS_VECTOR).expect("scope_kinds_v1 parses");
    let kernel_pk = unhex(
        verdict["ed25519"]["kernel_public_key_hex"]
            .as_str()
            .expect("the vector carries a kernel public key"),
    );

    // The STANDING surface: an authentic, unexpired, unrevoked document whose
    // boundary names a kind no v4 verifier recognises.
    let mut standing = Vec::new();
    for case in verdict["cases"].as_array().expect("cases") {
        if case["expected_reason"] != "unknown_scope_kind" {
            continue;
        }
        let Some(text) = case["document_json"].as_str() else {
            continue;
        };
        let got = verify_vaid_standing_from_json(&kernel_pk, text, RevocationStatus::NotRevoked);
        standing.push(json!({
            "case": case["name"],
            "reason": got.code(),
            "valid": got.is_valid(),
        }));
    }

    // The ATTENUATION surface: an unreadable kind on either side of a hop.
    let mut attenuation = Vec::new();
    for case in kinds["attenuation_cases"].as_array().expect("cases") {
        if case["expected_reason"] != "unknown_scope_kind" {
            continue;
        }
        let parse = |k: &str| -> Vec<ScopeBoundaryEntry> {
            case[k]
                .as_array()
                .expect("a boundary")
                .iter()
                .map(|e| serde_json::from_value(e.clone()).expect("a well-formed entry"))
                .collect()
        };
        let reason = scope_attenuation_reason(&parse("parent_scope"), &parse("child_scope"));
        attenuation.push(json!({
            "case": case["name"],
            "reason": attenuation_code(reason),
        }));
    }

    // A refusal over zero inputs is not a reading. Asserted here rather than only
    // in the shell script, so an emitter that silently found nothing cannot be
    // diffed against another that also found nothing and report agreement.
    assert!(
        !standing.is_empty(),
        "verdict_v1.json carries no unknown_scope_kind standing case — nothing was measured"
    );
    assert!(
        !attenuation.is_empty(),
        "scope_kinds_v1.json carries no unknown_scope_kind attenuation case — nothing was measured"
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "surface": "unknown scope kind (spec S.10, ADR-0009)",
            "standing": standing,
            "attenuation": attenuation,
        }))
        .unwrap()
    );
}
