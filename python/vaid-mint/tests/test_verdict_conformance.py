"""Negative-path conformance (``verdict_v1.json``) — failures must fail
IDENTICALLY, and for the SAME REASON.

The frozen happy-path vectors prove three implementations MINT the same bytes.
None of them proves they REFUSE the same way. A verifier that accepts an expired
VAID in one language and rejects it in another is a worse defect than a mint
mismatch, and until this vector existed nothing in the suite would have caught it.

**The assertion is the REASON, not the boolean.** Three implementations that
reject the same document for three different reasons agree on every boolean and
disagree about what happened. ``False`` collapses "this is forged" into "I could
not reach a revocation list"; a suite that only pins ``False`` cannot tell those
apart and therefore cannot notice when two implementations stop agreeing about
which one they got.

**What stops this decaying into a vector that asserts nothing** — four things,
each with a test below: positive controls on both surfaces; reason coverage in
both directions; vocabulary agreement with :class:`VaidVerdict` in both
directions; and reconstructed defects the vector must be shown to catch.
"""

from __future__ import annotations

import json
from importlib.resources import files

import pytest

from vaid_mint.mint import scope_attenuates_within
from vaid_mint.revocation import RevocationStatus
from vaid_mint.verify import VaidVerdict, verify_vaid_standing_from_json

VECTOR = json.loads(files("vaid_mint").joinpath("vectors/verdict_v1.json").read_text())
KERNEL_PK = bytes.fromhex(VECTOR["ed25519"]["kernel_public_key_hex"])
CASES = VECTOR["cases"]

REVOCATION = {
    "not_revoked": RevocationStatus.NOT_REVOKED,
    "revoked": RevocationStatus.REVOKED,
    "unavailable": RevocationStatus.UNAVAILABLE,
}


def _evaluate(case: dict) -> tuple[str, bool]:
    """Evaluate one case the way the vector says it must be evaluated."""
    if case["surface"] == "standing":
        verdict = verify_vaid_standing_from_json(
            KERNEL_PK, case["document_json"], REVOCATION[case["revocation"]]
        )
        return verdict.code, verdict.is_valid()
    ok = scope_attenuates_within(case["parent_scope"], case["child_scope"])
    return ("attenuated" if ok else "scope_escalation"), ok


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_every_case_returns_the_frozen_verdict_and_reason(case: dict) -> None:
    """THE ASSERTION. Both the reason and the boolean, per case."""
    reason, valid = _evaluate(case)
    assert reason == case["expected_reason"], (
        f"reason {reason!r}, expected {case['expected_reason']!r} — {case['why']}\n"
        "A reason mismatch is a defect even when the boolean agrees: it means this "
        "implementation and the vector disagree about WHAT HAPPENED."
    )
    assert valid == case["expected_valid"], f"{case['why']}"


@pytest.mark.parametrize("surface", ["standing", "attenuation"])
def test_positive_controls_exist_on_both_surfaces(surface: str) -> None:
    """THE CONTROL. An implementation that refuses everything passes every negative
    case in this file; only a case that must SUCCEED catches it. Both surfaces need
    one, because they are evaluated by different code."""
    positives = [c for c in CASES if c["surface"] == surface and c["expected_valid"]]
    negatives = [c for c in CASES if c["surface"] == surface and not c["expected_valid"]]
    assert positives, (
        f"the {surface} surface has no positive control — an implementation that "
        "rejected every input would pass every case on it"
    )
    assert negatives, (
        f"the {surface} surface has no negative case — an implementation that "
        "accepted every input would pass every case on it"
    )


def test_declared_reasons_and_exercised_reasons_are_the_same_set() -> None:
    """Reason coverage, BOTH directions: a declared reason with no case is a state
    that ships unchecked; a case naming an undeclared reason is a vector written
    against a vocabulary this file does not define."""
    declared = set(VECTOR["reasons"]["standing"]) | set(VECTOR["reasons"]["attenuation"])
    exercised = {c["expected_reason"] for c in CASES}
    assert not (declared - exercised), (
        f"reason(s) declared but exercised by no case: {sorted(declared - exercised)} — "
        "a state with no case behind it is a claim with no evidence"
    )
    assert not (exercised - declared), (
        f"case(s) name reason(s) the vector does not declare: {sorted(exercised - declared)}"
    )


def test_the_vector_vocabulary_and_the_enum_are_the_same_set() -> None:
    """Enum agreement, BOTH directions. A reason the vector declares that this build
    cannot return means the vector was written against a different implementation;
    a verdict this build can return that the vector never names is a state shipping
    without a case."""
    declared = set(VECTOR["reasons"]["standing"])
    implemented = {r.code for r in VaidVerdict}
    assert declared == implemented, (
        "verdict_v1.json's standing vocabulary and VaidVerdict disagree\n"
        f"  only in the vector:         {sorted(declared - implemented)}\n"
        f"  only in the implementation: {sorted(implemented - declared)}"
    )
    for reason in declared:
        assert VaidVerdict.from_code(reason) is not None, (
            f"the vector declares reason {reason!r}, which VaidVerdict.from_code "
            "does not recognise"
        )


def test_no_case_raises() -> None:
    """A refusal is never an exception. Malformed, truncated and empty input must
    reach a verdict, because a verifier that raises on hostile bytes is a denial of
    service wearing a safety property's clothes."""
    for case in CASES:
        _evaluate(case)  # a raise here fails the test by construction


def test_the_vector_catches_a_collapsed_indeterminate() -> None:
    """DISCRIMINATING POWER, part one. Reconstruct the two ways an implementation
    can collapse the third state, and require the vector to catch BOTH.

    This is what stops the fail-closed rule becoming decoration: a vector full of
    indeterminate cases proves nothing if an implementation that maps Unavailable
    straight to "clean" still passes it."""
    caught_fail_open = caught_false_accusation = False
    for case in CASES:
        if case["surface"] != "standing" or case["revocation"] != "unavailable":
            continue
        text = case["document_json"]
        as_clean = verify_vaid_standing_from_json(KERNEL_PK, text, RevocationStatus.NOT_REVOKED)
        if as_clean.code != case["expected_reason"]:
            caught_fail_open = True
        as_revoked = verify_vaid_standing_from_json(KERNEL_PK, text, RevocationStatus.REVOKED)
        if as_revoked.code != case["expected_reason"]:
            caught_false_accusation = True

    assert caught_fail_open, (
        "the vector no longer catches an implementation that reads Unavailable as "
        "'not revoked' — that is a FAIL-OPEN, and the more dangerous of the two"
    )
    assert caught_false_accusation, (
        "the vector no longer catches an implementation that reads Unavailable as "
        "'revoked' — accusing a holder because a store was unreachable is a false "
        "accusation, not a safe default"
    )


def test_reasons_are_load_bearing() -> None:
    """DISCRIMINATING POWER, part two. If every case with the same boolean also had
    the same reason, a boolean-only implementation would pass this vector and the
    whole premise of the file would be decorative."""
    refusal_reasons = {c["expected_reason"] for c in CASES if not c["expected_valid"]}
    assert len(refusal_reasons) > 1, (
        f"every refusing case expects the same reason ({sorted(refusal_reasons)}), so a "
        "boolean-only implementation would pass this vector and the reason assertions "
        "would be checking nothing"
    )
    ordering = [c for c in CASES if c["name"].startswith("order:")]
    assert len(ordering) >= 3, (
        f"only {len(ordering)} ordering case(s) — these are what pin the ORDER of the "
        "checks, and the order is the part that changes reason codes while leaving "
        "every boolean identical"
    )
