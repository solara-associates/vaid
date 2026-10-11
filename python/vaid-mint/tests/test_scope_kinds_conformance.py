"""Typed-scope-boundary conformance (spec ``docs/spec/scope.md`` S.8 to S.12,
ADR-0009).

The vendored vector ``vaid_mint/vectors/scope_kinds_v1.json`` is byte-identical to
the Rust (``tests/vectors/``) and TypeScript (``vectors/``) copies; CI ``cmp``s all
three, so "the vectors are the same bytes" gives Rust == Python == TypeScript on
the three surfaces it pins.

Like ``scope_v1.json`` it carries no digest and no signature: every case is a
verdict over given bytes.
"""

from __future__ import annotations

import json
from importlib.resources import files

import pytest

from vaid_mint.document import (
    RECOGNISED_SCOPE_KINDS,
    boundary_is_evaluable,
    entry_claimed_resource,
    entry_is_evaluable,
    is_well_formed_scope_boundary,
    prefix_entry,
    scope_contains,
)
from vaid_mint.mint import (
    AttenuationReason,
    scope_attenuates_within,
    scope_attenuation_reason,
)

VECTOR = json.loads(
    files("vaid_mint").joinpath("vectors/scope_kinds_v1.json").read_text()
)


def test_the_recognised_kind_registry_matches_the_specification() -> None:
    """The registry, BOTH directions.

    A kind this build recognises that the specification does not declare is a
    widening nobody wrote down. A kind the specification declares that this build
    does not recognise is a fail-closed rule refusing something the standard says
    is valid. Neither is visible in any other assertion here.
    """
    assert VECTOR["rule"]["kinds"] == list(RECOGNISED_SCOPE_KINDS)
    assert RECOGNISED_SCOPE_KINDS, (
        "a build that recognises no kind contains every boundary in nothing"
    )
    assert VECTOR["rule"]["entry_members"] == ["kind", "value"], (
        "S.8 fixes the entry member set at exactly these two"
    )


@pytest.mark.parametrize(
    "case", VECTOR["containment_cases"], ids=[c["name"] for c in VECTOR["containment_cases"]]
)
def test_every_containment_case_matches_the_reference_matcher(case: dict) -> None:
    boundary = case["boundary"]
    assert is_well_formed_scope_boundary(boundary), "the vector's own boundary must be valid"
    got = scope_contains(boundary, case["resource"])
    assert got == case["expected"], case["why"]
    # The REASON, not merely the boolean: a refusal and an inability to evaluate
    # are different accusations that agree on every boolean.
    if not boundary_is_evaluable(boundary):
        reason = "unknown_scope_kind"
    else:
        reason = "contained" if got else "not_contained"
    assert reason == case["expected_reason"], case["why"]


@pytest.mark.parametrize(
    "case", VECTOR["attenuation_cases"], ids=[c["name"] for c in VECTOR["attenuation_cases"]]
)
def test_every_attenuation_case_matches_the_reference_rule(case: dict) -> None:
    parent, child = case["parent_scope"], case["child_scope"]
    att = scope_attenuation_reason(parent, child)
    ok = scope_attenuates_within(parent, child)
    assert ok == (att is AttenuationReason.ATTENUATED), (
        "the attenuation boolean and the attenuation reason disagree — one rule "
        "with two readers is how the readers drift"
    )
    assert ok == case["expected_valid"], case["why"]
    assert att.value == case["expected_reason"], case["why"]


@pytest.mark.parametrize(
    "case", VECTOR["shape_cases"], ids=[c["name"] for c in VECTOR["shape_cases"]]
)
def test_every_shape_case_matches_the_reference_gate(case: dict) -> None:
    """The shape gate (S.8), over TEXT, so the malformed cases travel the same
    code path as the well-formed ones instead of one written just for them."""
    # Every case's bytes are themselves well-formed JSON, asserted here, so what
    # is under test is the SHAPE gate and never the JSON parser.
    value = json.loads(case["boundary_json"])
    reason = "parsed" if is_well_formed_scope_boundary(value) else "unparseable"
    assert reason == case["expected_reason"], case["why"]


def test_the_shape_surface_carries_its_positive_controls() -> None:
    """Without at least two the shape surface is satisfied by a gate that refuses
    every boundary, and without one of them being an UNRECOGNISED kind the
    parse/verify split of S.10 is untested: an implementation refusing an unknown
    kind at parse would report ``unparseable`` for an authentic future-version
    credential, and no other boolean here differs."""
    parsed = [c for c in VECTOR["shape_cases"] if c["expected_reason"] == "parsed"]
    assert len(parsed) >= 2
    assert any(
        not boundary_is_evaluable(json.loads(c["boundary_json"])) for c in parsed
    ), (
        "one positive control must be an UNRECOGNISED kind, proving it parses and "
        "is refused later rather than being refused as malformed bytes"
    )


def test_the_vector_exercises_every_outcome_it_declares() -> None:
    assert any(c["expected"] for c in VECTOR["containment_cases"])
    assert any(not c["expected"] for c in VECTOR["containment_cases"])
    for reason in ("attenuated", "scope_escalation", "unknown_scope_kind"):
        assert any(
            c["expected_reason"] == reason for c in VECTOR["attenuation_cases"]
        ), f"no attenuation case for {reason!r} — a state with no case is a claim with no evidence"
    for reason in ("contained", "not_contained", "unknown_scope_kind"):
        assert any(c["expected_reason"] == reason for c in VECTOR["containment_cases"])


def test_evaluability_does_not_depend_on_the_resource() -> None:
    """``entry_is_evaluable`` derives evaluability from ``_entry_contains`` over one
    arbitrary resource. That is exact only if the verdict's presence is a property
    of the entry alone. Asserted rather than assumed, over every entry the vector
    carries."""
    from vaid_mint.document import _entry_contains

    entries = [
        e
        for case in VECTOR["containment_cases"]
        for e in case["boundary"]
    ] + [
        e
        for case in VECTOR["attenuation_cases"]
        for e in case["parent_scope"] + case["child_scope"]
    ]
    assert entries, "the vector must carry entries to check"
    resources = ["", "data.governance", "data.governance.reports", "t/x", "z"]
    for entry in entries:
        derived = entry_is_evaluable(entry)
        for resource in resources:
            assert (_entry_contains(entry, resource) is not None) == derived, (
                f"evaluability of {entry!r} changed with the resource {resource!r}"
            )


def test_every_registered_kind_is_evaluable() -> None:
    """A kind named in the registry must be one both branches can answer for.
    Without this, a name could be added to the registry alone and the matcher
    would refuse a kind the specification says is recognised."""
    from vaid_mint.document import SCOPE_KIND_PREFIX

    witnesses = {SCOPE_KIND_PREFIX: prefix_entry("data.x")}
    for kind in RECOGNISED_SCOPE_KINDS:
        entry = witnesses.get(kind)
        assert entry is not None, (
            f"registered kind {kind!r} has no witness here — add one with the kind"
        )
        assert entry_is_evaluable(entry), f"{kind!r} is not evaluable by the matcher"
        assert entry_claimed_resource(entry) is not None, (
            f"{kind!r} has no attenuation projection"
        )
