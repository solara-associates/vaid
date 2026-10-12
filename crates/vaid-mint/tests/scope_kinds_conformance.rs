//! Typed-scope-boundary conformance (spec `docs/spec/scope.md` S.8 to S.12,
//! ADR-0009).
//!
//! The vendored vector `tests/vectors/scope_kinds_v1.json` is byte-identical to
//! the Python (`vaid_mint/vectors/`) and TypeScript (`vectors/`) copies; CI `cmp`s
//! all three, so "the vectors are the same bytes" gives Rust == Python ==
//! TypeScript on the three surfaces it pins.
//!
//! Three surfaces, one file, because they share ONE recognised-kind registry and
//! splitting them is how the registry acquires two readers that disagree:
//!
//! - **containment** of a resource within a typed boundary;
//! - **attenuation** of one typed boundary within another;
//! - the **shape gate** over boundary bytes.
//!
//! Like `scope_v1.json` it carries no digest and no signature: every case is a
//! verdict over given bytes.

use serde::Deserialize;
use vaid_mint::{
    boundary_is_evaluable, scope_attenuates_within, scope_attenuation_reason, scope_contains,
    AttenuationReason, ScopeBoundaryEntry, RECOGNISED_SCOPE_KINDS,
};

const VECTOR_JSON: &str = include_str!("vectors/scope_kinds_v1.json");

#[derive(Deserialize)]
struct Vector {
    rule: Rule,
    containment_cases: Vec<ContainmentCase>,
    attenuation_cases: Vec<AttenuationCase>,
    shape_cases: Vec<ShapeCase>,
}

#[derive(Deserialize)]
struct Rule {
    kinds: Vec<String>,
    entry_members: Vec<String>,
}

#[derive(Deserialize)]
struct ContainmentCase {
    name: String,
    boundary: Vec<ScopeBoundaryEntry>,
    resource: String,
    expected: bool,
    expected_reason: String,
    why: String,
}

#[derive(Deserialize)]
struct AttenuationCase {
    name: String,
    parent_scope: Vec<ScopeBoundaryEntry>,
    child_scope: Vec<ScopeBoundaryEntry>,
    expected_valid: bool,
    expected_reason: String,
    why: String,
}

#[derive(Deserialize)]
struct ShapeCase {
    name: String,
    boundary_json: String,
    expected_reason: String,
    why: String,
}

fn vector() -> Vector {
    serde_json::from_str(VECTOR_JSON).expect("scope_kinds_v1.json must parse")
}

fn attenuation_code(reason: AttenuationReason) -> &'static str {
    match reason {
        AttenuationReason::Attenuated => "attenuated",
        AttenuationReason::ScopeEscalation => "scope_escalation",
        AttenuationReason::UnknownScopeKind => "unknown_scope_kind",
    }
}

/// The recognised-kind registry, BOTH directions.
///
/// A kind this build recognises that the specification does not declare is a
/// widening nobody wrote down. A kind the specification declares that this build
/// does not recognise is a fail-closed rule refusing something the standard says
/// is valid. Neither is visible in any other assertion here.
#[test]
fn the_recognised_kind_registry_matches_the_specification() {
    let v = vector();
    let built: Vec<String> = RECOGNISED_SCOPE_KINDS
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(
        v.rule.kinds, built,
        "the vector's declared kinds and this build's registry must be the same set"
    );
    assert!(
        !built.is_empty(),
        "a build that recognises no kind contains every boundary in nothing"
    );
    assert_eq!(
        v.rule.entry_members,
        vec!["kind".to_string(), "value".to_string()],
        "S.8 fixes the entry member set at exactly these two"
    );
}

#[test]
fn every_containment_case_matches_the_reference_matcher() {
    let v = vector();
    assert!(!v.containment_cases.is_empty(), "vector must carry cases");
    for case in &v.containment_cases {
        let got = scope_contains(&case.boundary, &case.resource);
        assert_eq!(
            got, case.expected,
            "containment case {:?}: expected {} got {} — {}",
            case.name, case.expected, got, case.why
        );
        // The REASON, not merely the boolean: a refusal and an inability to
        // evaluate are different accusations that agree on every boolean.
        let reason = if !boundary_is_evaluable(&case.boundary) {
            "unknown_scope_kind"
        } else if got {
            "contained"
        } else {
            "not_contained"
        };
        assert_eq!(
            reason, case.expected_reason,
            "containment case {:?} reason — {}",
            case.name, case.why
        );
    }
}

#[test]
fn every_attenuation_case_matches_the_reference_rule() {
    let v = vector();
    assert!(!v.attenuation_cases.is_empty(), "vector must carry cases");
    for case in &v.attenuation_cases {
        let reason = scope_attenuation_reason(&case.parent_scope, &case.child_scope);
        let ok = scope_attenuates_within(&case.parent_scope, &case.child_scope);
        assert_eq!(
            ok,
            reason == AttenuationReason::Attenuated,
            "attenuation case {:?}: the boolean and the reason disagree — one rule \
             with two readers is how the readers drift",
            case.name
        );
        assert_eq!(
            ok, case.expected_valid,
            "attenuation case {:?} — {}",
            case.name, case.why
        );
        assert_eq!(
            attenuation_code(reason),
            case.expected_reason,
            "attenuation case {:?} reason — {}",
            case.name,
            case.why
        );
    }
}

/// The shape gate (S.8), over TEXT, so the malformed cases travel the same code
/// path as the well-formed ones instead of one written just for them.
#[test]
fn every_shape_case_matches_the_reference_gate() {
    let v = vector();
    assert!(!v.shape_cases.is_empty(), "vector must carry cases");
    for case in &v.shape_cases {
        // Every case's bytes are themselves well-formed JSON, asserted here, so
        // what is under test is the SHAPE gate and never the JSON parser.
        let value: serde_json::Value =
            serde_json::from_str(&case.boundary_json).unwrap_or_else(|e| {
                panic!(
                    "shape case {:?} is not valid JSON ({e}) — it would be testing the \
                 parser rather than the shape gate",
                    case.name
                )
            });
        let reason = match serde_json::from_value::<Vec<ScopeBoundaryEntry>>(value) {
            Ok(_) => "parsed",
            Err(_) => "unparseable",
        };
        assert_eq!(
            reason, case.expected_reason,
            "shape case {:?} — {}",
            case.name, case.why
        );
    }
}

/// The same shape table, applied at the DOCUMENT surface.
///
/// `every_shape_case_matches_the_reference_gate` above checks the rule over a
/// bare boundary. This checks that a whole `Vaid` carrying such a boundary does
/// not deserialize, which is what makes `verify_vaid` unreachable with one in
/// Rust and is therefore why Rust needs no runtime well-formedness check in
/// `mint_root`, `mint_child` or `verify_vaid`: `Vaid::scope_boundary` is
/// `Vec<ScopeBoundaryEntry>`, the entry's fields are private, and every
/// construction path applies `validate_scope_entry`.
///
/// Python and TypeScript DID need explicit gates at those surfaces, because in
/// both a malformed boundary could be carried through the mint, signed, and
/// accepted by the local verifier while the wire parser refused it. Their
/// `scope_kinds` suites now drive these same cases through their mint and
/// verify surfaces. One table, three languages, three surfaces.
#[test]
fn a_document_carrying_an_unparseable_shape_case_does_not_deserialize() {
    let v = vector();
    let template = serde_json::json!({
        "sig_version": 4,
        "vaid_id": "00000000-0000-4000-8000-000000000001",
        "agent_id": "00000000-0000-4000-8000-000000000002",
        "agent_class": "x",
        "version": "1.0.0",
        "tenant_id": "t",
        "issued_at": "2026-06-04T12:00:00Z",
        "expires_at": "2999-01-01T00:00:00Z",
        "public_key_der": [],
        "kernel_signature": [],
        "parent_vaid": null,
        "scope_boundary": [],
        "lineage_hash": "lineage",
        "capability_set": ["read"],
        "trust_domain": "vaid.example",
        "kernel_key_thumbprint": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:x"
    });
    let mut checked = 0;
    for case in &v.shape_cases {
        let boundary: serde_json::Value =
            serde_json::from_str(&case.boundary_json).expect("case is valid JSON");
        let mut doc = template.clone();
        doc["scope_boundary"] = boundary;
        let text = serde_json::to_string(&doc).unwrap();
        let parsed = serde_json::from_str::<vaid_mint::Vaid>(&text);
        match case.expected_reason.as_str() {
            "unparseable" => {
                assert!(
                    parsed.is_err(),
                    "shape case {:?} must not deserialize as a document — {}",
                    case.name,
                    case.why
                );
                checked += 1;
            }
            // The positive half, which includes an UNRECOGNISED kind: well
            // formed, so it must deserialize and be refused later at verify.
            "parsed" => {
                assert!(
                    parsed.is_ok(),
                    "shape case {:?} is well formed and must deserialize — {}",
                    case.name,
                    case.why
                );
                checked += 1;
            }
            other => panic!("unexpected expected_reason {other:?}"),
        }
    }
    assert_eq!(
        checked,
        v.shape_cases.len(),
        "every shape case must be exercised at the document surface"
    );
}

/// The positive controls, counted. Without at least two the shape surface is
/// satisfied by a gate that refuses every boundary, and without one of them being
/// an UNRECOGNISED kind the parse/verify split of S.10 is untested: an
/// implementation refusing an unknown kind at parse would report `unparseable`
/// for an authentic future-version credential, and no other boolean here differs.
#[test]
fn the_shape_surface_carries_its_positive_controls() {
    let v = vector();
    let parsed: Vec<&ShapeCase> = v
        .shape_cases
        .iter()
        .filter(|c| c.expected_reason == "parsed")
        .collect();
    assert!(
        parsed.len() >= 2,
        "the shape surface needs at least two positive controls, got {}",
        parsed.len()
    );
    let unknown_kind_parses = parsed.iter().any(|c| {
        serde_json::from_str::<Vec<ScopeBoundaryEntry>>(&c.boundary_json)
            .map(|b| !boundary_is_evaluable(&b))
            .unwrap_or(false)
    });
    assert!(
        unknown_kind_parses,
        "one positive control must be an UNRECOGNISED kind, proving it parses and \
         is refused later rather than being refused as malformed bytes"
    );
}

/// Both surfaces must exercise both outcomes, and the attenuation surface must
/// reach all three reasons. A surface that only ever refuses is satisfied by an
/// implementation that refuses everything.
#[test]
fn the_vector_exercises_every_outcome_it_declares() {
    let v = vector();
    assert!(v.containment_cases.iter().any(|c| c.expected));
    assert!(v.containment_cases.iter().any(|c| !c.expected));
    for reason in ["attenuated", "scope_escalation", "unknown_scope_kind"] {
        assert!(
            v.attenuation_cases
                .iter()
                .any(|c| c.expected_reason == reason),
            "the attenuation surface declares no case for {reason:?} — a state with \
             no case behind it is a claim with no evidence"
        );
    }
    for reason in ["contained", "not_contained", "unknown_scope_kind"] {
        assert!(
            v.containment_cases
                .iter()
                .any(|c| c.expected_reason == reason),
            "the containment surface declares no case for {reason:?}"
        );
    }
}
