//! Negative-path conformance (`verdict_v1.json`) — the suite proves failures fail
//! IDENTICALLY, and for the SAME REASON.
//!
//! The frozen happy-path vectors prove three implementations MINT the same bytes.
//! None of them proves they REFUSE the same way. A verifier that accepts an
//! expired VAID in one language and rejects it in another is a worse defect than
//! a mint mismatch, and until this vector existed nothing in the suite would have
//! caught it.
//!
//! # The assertion is the REASON, not the boolean
//!
//! Three implementations that reject the same document for three different
//! reasons agree on every boolean and disagree about what happened. `false`
//! collapses "this is forged" into "I could not reach a revocation list"; a suite
//! that only pins `false` cannot tell those apart and therefore cannot notice when
//! two implementations stop agreeing about which one they got.
//!
//! # What stops this decaying into a vector that asserts nothing
//!
//! Four things, each of which has a test below:
//!
//! - **Positive controls.** An implementation that refuses every input passes
//!   every negative case in the file. [`positive_controls_exist_on_both_surfaces`]
//!   requires cases that must SUCCEED.
//! - **Reason coverage, both directions.** A declared reason with no case is an
//!   unchecked state; a case naming an undeclared reason is a vector written
//!   against something else.
//! - **Enum agreement, both directions.** The vector's vocabulary and
//!   [`VaidVerdict::ALL`] must be the same set.
//! - **Discriminating power.** [`the_vector_catches_a_collapsed_indeterminate`] and
//!   [`reasons_are_load_bearing`] reconstruct the defects this exists to catch and
//!   require the vector to fail them.

use std::collections::BTreeSet;

use serde::Deserialize;
use vaid_mint::{
    scope_attenuates_within, verify_vaid_standing_from_json, RevocationStatus, VaidVerdict,
};

const VECTOR_JSON: &str = include_str!("vectors/verdict_v1.json");

#[derive(Deserialize)]
struct Vector {
    reasons: Reasons,
    ed25519: Keys,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Reasons {
    standing: Vec<String>,
    attenuation: Vec<String>,
}
#[derive(Deserialize)]
struct Keys {
    kernel_public_key_hex: String,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    why: String,
    surface: String,
    #[serde(default)]
    document_json: Option<String>,
    #[serde(default)]
    revocation: Option<String>,
    #[serde(default)]
    parent_scope: Option<Vec<String>>,
    #[serde(default)]
    child_scope: Option<Vec<String>>,
    expected_valid: bool,
    expected_reason: String,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vector() -> Vector {
    serde_json::from_str(VECTOR_JSON).expect("verdict_v1.json parses")
}

fn revocation(name: &str) -> RevocationStatus {
    match name {
        "not_revoked" => RevocationStatus::NotRevoked,
        "revoked" => RevocationStatus::Revoked,
        "unavailable" => RevocationStatus::Unavailable,
        other => panic!("verdict_v1.json names an unknown revocation state {other:?}"),
    }
}

/// Evaluate one case the way the vector says it must be evaluated, returning
/// `(reason, valid)`.
fn evaluate(case: &Case, kernel_pk: &[u8]) -> (String, bool) {
    match case.surface.as_str() {
        "standing" => {
            let text = case
                .document_json
                .as_deref()
                .expect("a standing case carries document_json");
            let rev = revocation(
                case.revocation
                    .as_deref()
                    .expect("a standing case carries a revocation state"),
            );
            let verdict = verify_vaid_standing_from_json(kernel_pk, text, rev);
            (verdict.code().to_string(), verdict.is_valid())
        }
        "attenuation" => {
            let parent = case
                .parent_scope
                .as_ref()
                .expect("an attenuation case carries parent_scope");
            let child = case
                .child_scope
                .as_ref()
                .expect("an attenuation case carries child_scope");
            let ok = scope_attenuates_within(parent, child);
            (
                if ok { "attenuated" } else { "scope_escalation" }.to_string(),
                ok,
            )
        }
        other => panic!("verdict_v1.json names an unknown surface {other:?}"),
    }
}

/// THE ASSERTION. Every case returns the frozen verdict AND the frozen reason.
#[test]
fn every_case_returns_the_frozen_verdict_and_reason() {
    let v = vector();
    let pk = unhex(&v.ed25519.kernel_public_key_hex);
    for case in &v.cases {
        let (reason, valid) = evaluate(case, &pk);
        assert_eq!(
            reason, case.expected_reason,
            "verdict_v1 case '{}' gave reason '{}', expected '{}' — {}\n  \
             A reason mismatch is a defect even when the boolean agrees: it means \
             this implementation and the vector disagree about WHAT HAPPENED.",
            case.name, reason, case.expected_reason, case.why
        );
        assert_eq!(
            valid, case.expected_valid,
            "verdict_v1 case '{}' returned valid={}, expected {} — {}",
            case.name, valid, case.expected_valid, case.why
        );
    }
}

/// A refusal is never a panic. Malformed, truncated and empty input must reach a
/// verdict, because a verifier that panics on hostile bytes is a denial of service
/// wearing a safety property's clothes.
#[test]
fn no_case_panics() {
    let v = vector();
    let pk = unhex(&v.ed25519.kernel_public_key_hex);
    for case in &v.cases {
        let _ = evaluate(case, &pk); // a panic here fails the test by construction
    }
}

/// THE CONTROL. An implementation that refuses everything passes every negative
/// case in this file; only a case that must SUCCEED catches it. Both surfaces need
/// one, because they are evaluated by different code.
#[test]
fn positive_controls_exist_on_both_surfaces() {
    let v = vector();
    for surface in ["standing", "attenuation"] {
        let positives = v
            .cases
            .iter()
            .filter(|c| c.surface == surface && c.expected_valid)
            .count();
        let negatives = v
            .cases
            .iter()
            .filter(|c| c.surface == surface && !c.expected_valid)
            .count();
        assert!(
            positives > 0,
            "the {surface} surface has no positive control — an implementation that \
             rejected every input would pass every case on it"
        );
        assert!(
            negatives > 0,
            "the {surface} surface has no negative case — an implementation that \
             accepted every input would pass every case on it"
        );
    }
}

/// Reason coverage, BOTH directions: a declared reason with no case is a state
/// that ships unchecked; a case naming an undeclared reason is a vector written
/// against a vocabulary this file does not define.
#[test]
fn declared_reasons_and_exercised_reasons_are_the_same_set() {
    let v = vector();
    let declared: BTreeSet<&str> = v
        .reasons
        .standing
        .iter()
        .chain(v.reasons.attenuation.iter())
        .map(String::as_str)
        .collect();
    let exercised: BTreeSet<&str> = v.cases.iter().map(|c| c.expected_reason.as_str()).collect();

    let unexercised: Vec<_> = declared.difference(&exercised).collect();
    assert!(
        unexercised.is_empty(),
        "reason(s) declared but exercised by no case: {unexercised:?} — a state with \
         no case behind it is a claim with no evidence"
    );
    let undeclared: Vec<_> = exercised.difference(&declared).collect();
    assert!(
        undeclared.is_empty(),
        "case(s) name reason(s) the vector does not declare: {undeclared:?}"
    );
}

/// Enum agreement, BOTH directions. The vector's standing vocabulary and
/// [`VaidVerdict::ALL`] must be the same set — a reason the vector declares that
/// this build cannot return means the vector was written against a different
/// implementation, and a verdict this build can return that the vector never names
/// is a state shipping without a case.
#[test]
fn the_vector_vocabulary_and_the_enum_are_the_same_set() {
    let v = vector();
    let declared: BTreeSet<&str> = v.reasons.standing.iter().map(String::as_str).collect();
    let implemented: BTreeSet<&str> = VaidVerdict::ALL.iter().map(|r| r.code()).collect();

    assert_eq!(
        declared,
        implemented,
        "verdict_v1.json's standing vocabulary and VaidVerdict::ALL disagree.\n  \
         only in the vector:      {:?}\n  only in the implementation: {:?}",
        declared.difference(&implemented).collect::<Vec<_>>(),
        implemented.difference(&declared).collect::<Vec<_>>(),
    );

    // And every declared reason must round-trip through the parser, so a typo in
    // the vector cannot pass as a state.
    for reason in &declared {
        assert!(
            VaidVerdict::from_code(reason).is_some(),
            "the vector declares reason {reason:?}, which VaidVerdict::from_code \
             does not recognise"
        );
    }
}

/// DISCRIMINATING POWER, part one. Reconstruct the two ways an implementation can
/// collapse the third state, and require the vector to catch BOTH.
///
/// This is the check that stops the fail-closed rule becoming decoration. A vector
/// full of indeterminate cases proves nothing if an implementation that maps
/// Unavailable straight to "clean" still passes it.
#[test]
fn the_vector_catches_a_collapsed_indeterminate() {
    let v = vector();
    let pk = unhex(&v.ed25519.kernel_public_key_hex);

    let mut caught_fail_open = false; // Unavailable read as NotRevoked
    let mut caught_false_accusation = false; // Unavailable read as Revoked

    for case in &v.cases {
        if case.surface != "standing" {
            continue;
        }
        let rev_name = case.revocation.as_deref().expect("revocation state");
        if rev_name != "unavailable" {
            continue;
        }
        let text = case.document_json.as_deref().expect("document_json");

        let as_clean = verify_vaid_standing_from_json(&pk, text, RevocationStatus::NotRevoked);
        if as_clean.code() != case.expected_reason {
            caught_fail_open = true;
        }
        let as_revoked = verify_vaid_standing_from_json(&pk, text, RevocationStatus::Revoked);
        if as_revoked.code() != case.expected_reason {
            caught_false_accusation = true;
        }
    }

    assert!(
        caught_fail_open,
        "the vector no longer catches an implementation that reads Unavailable as \
         'not revoked' — that is a FAIL-OPEN, and it is the more dangerous of the two"
    );
    assert!(
        caught_false_accusation,
        "the vector no longer catches an implementation that reads Unavailable as \
         'revoked' — accusing a holder because a store was unreachable is a false \
         accusation, not a safe default"
    );
}

/// DISCRIMINATING POWER, part two. The reasons must be LOAD-BEARING.
///
/// If every case with the same boolean also had the same reason, a boolean-only
/// implementation would pass this vector and the whole premise of the file would
/// be decorative. So: there must exist cases that agree on `expected_valid` and
/// disagree on `expected_reason`, and enough of them to cover the ordering rules.
#[test]
fn reasons_are_load_bearing() {
    let v = vector();
    let refusal_reasons: BTreeSet<&str> = v
        .cases
        .iter()
        .filter(|c| !c.expected_valid)
        .map(|c| c.expected_reason.as_str())
        .collect();

    assert!(
        refusal_reasons.len() > 1,
        "every refusing case in this vector expects the same reason ({refusal_reasons:?}), \
         so a boolean-only implementation would pass it and the reason assertions \
         would be checking nothing"
    );

    // The ordering cases specifically: a document with two faults pins WHICH fault
    // is reported. Without them, an implementation could reorder its checks freely.
    let ordering_cases = v
        .cases
        .iter()
        .filter(|c| c.name.starts_with("order:"))
        .count();
    assert!(
        ordering_cases >= 3,
        "only {ordering_cases} ordering case(s) — these are what pin the ORDER of the \
         checks, and the order is the part that changes reason codes while leaving \
         every boolean identical"
    );
}
