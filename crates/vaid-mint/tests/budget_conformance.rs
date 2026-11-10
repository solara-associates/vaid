//! Budget scope-kind conformance (spec `docs/spec/budget.md`, ADR-0011).
//!
//! The vendored vector `tests/vectors/budget_v1.json` is byte-identical to the
//! Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies. Like
//! `scope_kinds_v1.json` it carries no digest and no signature: every case is a
//! verdict over given bytes, never bytes over a given input.

use serde::Deserialize;
use vaid_mint::budget::{budget_attenuation_reason, BudgetAttenuationReason};
use vaid_mint::document::ScopeBoundaryEntry;

const VECTOR_JSON: &str = include_str!("vectors/budget_v1.json");

#[derive(Deserialize)]
struct Vector {
    rule: Rule,
    attenuation_cases: Vec<AttenuationCase>,
}

#[derive(Deserialize)]
struct Rule {
    kinds: Vec<String>,
}

#[derive(Deserialize)]
struct AttenuationCase {
    name: String,
    parent_scope: Vec<ScopeBoundaryEntry>,
    child_scope: Vec<ScopeBoundaryEntry>,
    expected_reason: String,
    #[allow(dead_code)]
    why: String,
}

fn reason_name(reason: BudgetAttenuationReason) -> &'static str {
    match reason {
        BudgetAttenuationReason::Attenuated => "attenuated",
        BudgetAttenuationReason::BudgetEscalation => "budget_escalation",
        BudgetAttenuationReason::UnknownBudgetKind => "unknown_budget_kind",
    }
}

fn load() -> Vector {
    serde_json::from_str(VECTOR_JSON).expect("budget_v1.json must parse")
}

#[test]
fn the_recognised_kind_registry_matches_the_specification() {
    let vector = load();
    assert_eq!(
        vector.rule.kinds,
        vaid_mint::budget::RECOGNISED_BUDGET_KINDS
    );
}

#[test]
fn every_attenuation_case_matches_the_reference_rule() {
    let vector = load();
    for case in &vector.attenuation_cases {
        let reason = budget_attenuation_reason(&case.parent_scope, &case.child_scope);
        assert_eq!(
            reason_name(reason),
            case.expected_reason,
            "case {:?} expected {:?}, got {:?}",
            case.name,
            case.expected_reason,
            reason_name(reason)
        );
    }
}

#[test]
fn the_vector_exercises_every_outcome_it_declares() {
    let vector = load();
    let seen: std::collections::HashSet<&str> = vector
        .attenuation_cases
        .iter()
        .map(|c| c.expected_reason.as_str())
        .collect();
    for reason in ["attenuated", "budget_escalation", "unknown_budget_kind"] {
        assert!(seen.contains(reason), "vector never exercises {reason:?}");
    }
}

#[test]
fn the_vector_carries_at_least_one_fan_out_case() {
    let vector = load();
    let fan_out_cases = vector
        .attenuation_cases
        .iter()
        .filter(|c| c.name.contains("fan-out"))
        .count();
    assert!(
        fan_out_cases >= 2,
        "expected at least two fan-out cases pinning that minting is not restricted per-sibling"
    );
}
