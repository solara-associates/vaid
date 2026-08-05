"""Scope-containment conformance (spec ``docs/spec/scope.md`` S.3, ADR-0005).

The vendored vector ``vaid_mint/vectors/scope_v1.json`` is byte-identical to the
Rust (``tests/vectors/``) and TypeScript (``vectors/``) copies; CI ``cmp``s all
three, so "the vectors are the same bytes" gives Rust == Python == TypeScript on
the scope matcher.

This is the FIRST vector to police the matcher, and its absence is why bare prefix
matching survived in all three implementations simultaneously: three mirrored ports
of the same wrong rule agreed with each other perfectly, and nothing else was
asking.

Unlike every other vector in this package, this one carries **no digest and no
signature**. Containment is a predicate *over* a document, never part of one.
"""

from __future__ import annotations

import json
from importlib.resources import files

from vaid_mint.document import SCOPE_SEPARATORS, scope_contains

VECTOR = json.loads(files("vaid_mint").joinpath("vectors/scope_v1.json").read_text())


def test_every_vector_case_matches_the_reference_matcher() -> None:
    assert VECTOR["cases"], "vector must carry cases"
    for case in VECTOR["cases"]:
        got = scope_contains(case["boundary"], case["resource"])
        assert got == case["expected"], (
            f"scope_v1 case failed: boundary={case['boundary']!r} "
            f"resource={case['resource']!r} expected={case['expected']} got={got} "
            f"— {case['why']}"
        )


def test_the_vector_exercises_both_outcomes() -> None:
    """A vector that only ever expects True is satisfied by a matcher that always
    returns True."""
    assert any(c["expected"] for c in VECTOR["cases"]), "no positive case"
    assert any(not c["expected"] for c in VECTOR["cases"]), "no negative case"


def test_the_vector_pins_cases_where_bare_prefix_matching_disagreed() -> None:
    """The vector must pin the regression, not merely the rule."""
    disagreements = [
        c
        for c in VECTOR["cases"]
        if c["boundary"]
        and any(c["resource"].startswith(s) for s in c["boundary"]) != c["expected"]
    ]
    assert len(disagreements) >= 5, (
        "the vector must pin the sibling-capture regression class; only "
        f"{len(disagreements)} case(s) disagree with bare prefix matching"
    )


def test_the_separator_set_is_the_normative_one() -> None:
    """The set is fixed by the spec, not by a deployment: ADR-0003 has a third
    party recomputing containment from a presented chain, and a deployment-local
    set would leave it unable to reproduce the mint's verdict."""
    assert VECTOR["rule"]["separators"] == ["/", "."]
    assert list(SCOPE_SEPARATORS) == VECTOR["rule"]["separators"]
