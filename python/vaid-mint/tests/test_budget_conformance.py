"""Budget scope-kind conformance (``docs/spec/budget.md``, ADR-0011).

The vendored vector ``vaid_mint/vectors/budget_v1.json`` is byte-identical to the
Rust (``tests/vectors/``) and TypeScript (``vectors/``) copies. Like
``scope_kinds_v1.json`` it carries no digest and no signature: every case is a
verdict over given bytes, never bytes over a given input.
"""

from __future__ import annotations

import json
from importlib.resources import files

from vaid_mint.budget import RECOGNISED_BUDGET_KINDS, budget_attenuation_reason

VECTOR = json.loads(files("vaid_mint").joinpath("vectors/budget_v1.json").read_text())


def test_the_recognised_kind_registry_matches_the_specification() -> None:
    assert VECTOR["rule"]["kinds"] == list(RECOGNISED_BUDGET_KINDS)


def test_every_attenuation_case_matches_the_reference_rule() -> None:
    for case in VECTOR["attenuation_cases"]:
        reason = budget_attenuation_reason(case["parent_scope"], case["child_scope"])
        assert reason.value == case["expected_reason"], (
            f"case {case['name']!r} expected {case['expected_reason']!r}, got {reason.value!r}"
        )


def test_the_vector_exercises_every_outcome_it_declares() -> None:
    seen = {case["expected_reason"] for case in VECTOR["attenuation_cases"]}
    for reason in ("attenuated", "budget_escalation", "unknown_budget_kind"):
        assert reason in seen, f"vector never exercises {reason!r}"


def test_the_vector_carries_at_least_one_fan_out_case() -> None:
    fan_out_cases = [c for c in VECTOR["attenuation_cases"] if "fan-out" in c["name"]]
    assert len(fan_out_cases) >= 2, (
        "expected at least two fan-out cases pinning that minting is not restricted per-sibling"
    )
