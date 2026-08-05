//! Scope-containment conformance (spec `docs/spec/scope.md` S.3, ADR-0005).
//!
//! The vendored vector `tests/vectors/scope_v1.json` is byte-identical to the
//! Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies; CI `cmp`s all
//! three, so "the vectors are the same bytes" gives Rust == Python == TypeScript
//! on the scope matcher.
//!
//! This is the FIRST vector to police the matcher, and its absence is why bare
//! prefix matching survived in all three implementations simultaneously: three
//! mirrored ports of the same wrong rule agreed with each other perfectly, and
//! nothing else was asking. A vector is the only thing that would have caught it,
//! because the bug is not a disagreement between implementations — it is a
//! disagreement between all of them and the intended semantics.
//!
//! Unlike every other vector in this crate, this one carries **no digest and no
//! signature**. Containment is a predicate *over* a document, never part of one,
//! so nothing here enters signed bytes. `mint_v1`/`mint_pop_v1`/`chain_v1`/
//! `attestation_v1` are untouched and are NOT re-frozen by this file's existence.

use serde::Deserialize;
use vaid_mint::scope_contains;

const VECTOR_JSON: &str = include_str!("vectors/scope_v1.json");

#[derive(Deserialize)]
struct Vector {
    rule: Rule,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Rule {
    separators: Vec<String>,
}

#[derive(Deserialize)]
struct Case {
    boundary: Vec<String>,
    resource: String,
    expected: bool,
    why: String,
}

fn vector() -> Vector {
    serde_json::from_str(VECTOR_JSON).expect("scope_v1.json must parse")
}

#[test]
fn every_vector_case_matches_the_reference_matcher() {
    let v = vector();
    assert!(!v.cases.is_empty(), "vector must carry cases");
    for case in &v.cases {
        let got = scope_contains(&case.boundary, &case.resource);
        assert_eq!(
            got, case.expected,
            "scope_v1 case failed: boundary={:?} resource={:?} expected={} got={} — {}",
            case.boundary, case.resource, case.expected, got, case.why
        );
    }
}

/// The vector must exercise BOTH outcomes. A conformance vector that only ever
/// expects `true` is satisfied by a matcher that always returns `true`.
#[test]
fn the_vector_exercises_both_outcomes() {
    let v = vector();
    assert!(v.cases.iter().any(|c| c.expected), "no positive case");
    assert!(v.cases.iter().any(|c| !c.expected), "no negative case");
}

/// The vector must pin the regression, not merely the rule. Every case here
/// disagrees with bare prefix matching — if this count ever drops, the vector has
/// stopped covering the bug it was written for.
#[test]
fn the_vector_pins_cases_where_bare_prefix_matching_disagreed() {
    let v = vector();
    let disagreements = v
        .cases
        .iter()
        .filter(|c| !c.boundary.is_empty())
        .filter(|c| {
            let old = c.boundary.iter().any(|s| c.resource.starts_with(s));
            old != c.expected
        })
        .count();
    assert!(
        disagreements >= 5,
        "the vector must pin the sibling-capture regression class; only {disagreements} \
         case(s) disagree with bare prefix matching"
    );
}

/// The separator set is normative and fixed by the spec, not by a deployment.
/// ADR-0003 has a third party recomputing containment from a presented chain; a
/// deployment-local set would leave it unable to reproduce the mint's verdict.
#[test]
fn the_separator_set_is_the_normative_one() {
    let v = vector();
    assert_eq!(
        v.rule.separators,
        vec!["/".to_string(), ".".to_string()],
        "the vector's separator set must be the spec's (S.2)"
    );
    let declared: Vec<String> = vaid_mint::SCOPE_SEPARATORS
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        declared, v.rule.separators,
        "the implementation's separator set must equal the vector's"
    );
}
