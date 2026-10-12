"""Positive controls for vectors 13 and 14 (docs/a2a/v1/vectors/): each vector
must fail a verifier that is deliberately careless about the exact property it
exists to police, and pass the real one.

Without this, "the vector passes the reference verifier" is the only evidence
either vector carries any weight at all — identical to what an all-ALLOW or
all-DENY vector set would show (``vaid_a2a.conformance.check_vector_set``'s own
polarity check, one level up). A careless verifier that fails a vector is what
proves the vector is actually discriminating rather than vacuously satisfied.

Each careless verifier is built by monkeypatching the ONE primitive the real
verifier calls to implement the rule the vector tests, in ``vaid_a2a.verifier``'s
own namespace — not a second hand-rolled verifier that might drift from the
real one on everything else.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

import vaid_a2a.verifier as verifier_module
from vaid_a2a import METADATA_CHAIN_KEY, METADATA_VAID_KEY, verify_a2a_message
from vaid_mint.document import _prefix_contains, prefix_entry, scope_contains
from vaid_mint.revocation import InMemoryRevocationList

VECTORS_DIR = Path(__file__).resolve().parents[3] / "docs" / "a2a" / "v1" / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def _parse_verification_time(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _run(vector: dict) -> verifier_module.VerifyResult:
    message = {
        "metadata": {
            METADATA_VAID_KEY: vector["inputs"]["leaf"],
            METADATA_CHAIN_KEY: vector["inputs"]["chain"],
        }
    }
    return verify_a2a_message(
        message,
        trust_config=vector["trust_config"],
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=vector.get("requested_action"),
        now=_parse_verification_time(vector["verification_time"]),
    )


def test_vector_13_passes_the_real_verifier() -> None:
    vector = _load("13-unknown-scope-kind-future-compat.json")
    result = _run(vector)
    assert result.allowed is False
    assert result.code is verifier_module.VerifyCode.UNKNOWN_SCOPE_KIND


def _careless_union_scope_contains(boundary: list[dict], resource: str) -> bool:
    """Reproduces the EXACT bug ADR-0009 S.10 exists to prevent — the natural,
    naive implementation of a union: keep scanning for a match, and silently
    SKIP any entry you cannot evaluate rather than refusing the boundary.

    Deliberately NOT ``vaid_mint.document.scope_contains``, which already
    bakes the S.10 refusal into the matcher itself (it returns ``False`` on
    the first unevaluable entry, even with a match already in hand) — a
    verifier built on that function cannot reach the bug this vector exists
    to catch. This reimplements ONLY the recognised ``prefix`` semantics, via
    that module's own ``_prefix_contains``, so the single difference under
    test is unknown-kind handling and not a second, unrelated matcher."""
    for entry in boundary:
        if entry.get("kind") == "prefix" and isinstance(entry.get("value"), str):
            if _prefix_contains(entry["value"], resource):
                return True
        # Anything else — including an entry of an unrecognised kind — is
        # silently skipped rather than refusing the whole boundary.
    return False


def test_vector_13_fails_a_verifier_that_ignores_unknown_scope_kinds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The careless verifier under test here never refuses S.10's unreadable
    entry: it skips step 2a entirely (``boundary_is_evaluable`` patched to
    always true) AND evaluates scope with the naive union matcher above
    instead of the real, refusal-aware one. With the unrecognised-kind entry
    treated as vacuous, the readable ``prefix`` entry in vector 13's boundary
    still matches the requested action, so this verifier wrongly ALLOWS the
    request — diverging from the vector's expected ``fail``/
    ``unknown_scope_kind``, which is the whole point: a verifier that skips
    this check is caught, not merely slower.

    Both patches are necessary: ``vaid_mint.document.scope_contains`` already
    refuses an unevaluable entry on its own (S.10 is enforced at the matcher,
    not only at the standing-verdict layer), so patching ``is_in_scope`` alone
    while leaving the real matcher in place would still (correctly) deny —
    for the right reason, reached by a different route than the one this test
    means to simulate."""
    monkeypatch.setattr(verifier_module, "boundary_is_evaluable", lambda boundary: True)
    monkeypatch.setattr(
        verifier_module,
        "is_in_scope",
        lambda vaid, resource: _careless_union_scope_contains(vaid["scope_boundary"], resource),
    )
    vector = _load("13-unknown-scope-kind-future-compat.json")
    result = _run(vector)
    assert result.allowed is True, (
        "expected the careless verifier to wrongly ALLOW this vector — if it "
        "did not, the monkeypatch is not reaching the code path this test "
        "means to exercise"
    )
    assert vector["expected_result"] == "fail"
    assert result.allowed != (vector["expected_result"] == "pass")


def test_vector_14_passes_the_real_verifier() -> None:
    vector = _load("14-no-privilege-via-unused-field.json")
    result = _run(vector)
    assert result.allowed is False
    assert result.code is verifier_module.VerifyCode.OUT_OF_SCOPE


def test_vector_14_matches_the_same_chain_with_the_extra_field_removed() -> None:
    """The no-privilege property, stated directly: deleting the unread field
    from the leaf must not change the verdict, proving the field was never
    load-bearing for it in the first place. (Deleting it changes the
    document's bytes, so the original signature no longer verifies over the
    shortened document — this checks the SCOPE verdict, which is reached
    after authenticity, by exercising ``scope_contains`` directly over each
    boundary rather than re-signing a second document.)"""
    vector = _load("14-no-privilege-via-unused-field.json")
    leaf = vector["inputs"]["leaf"]
    action = vector["requested_action"]
    real_boundary = leaf["scope_boundary"]
    assert scope_contains(real_boundary, action) is False, (
        "the real scope_boundary must NOT cover the requested action — "
        "otherwise this vector is not testing anything"
    )
    widened_boundary = leaf["x_elevated_scope_boundary"]
    assert scope_contains(widened_boundary, action) is True, (
        "the fabricated field must cover the requested action, or a careless "
        "verifier reading it would not be fooled either"
    )


def test_vector_14_fails_a_verifier_that_unions_the_extra_field_into_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The careless verifier under test here treats
    ``x_elevated_scope_boundary`` as a second scope to union against — exactly
    the "read it as an override, a fallback, or a second boundary" failure
    mode vector 14's description calls out. It wrongly ALLOWS the request,
    diverging from the vector's expected ``fail``/``out_of_scope``."""

    def _careless_is_in_scope(vaid: dict, action: str) -> bool:
        boundary = vaid.get("scope_boundary") or []
        extra = vaid.get("x_elevated_scope_boundary") or []
        return scope_contains([*boundary, *extra], action)

    monkeypatch.setattr(verifier_module, "is_in_scope", _careless_is_in_scope)
    vector = _load("14-no-privilege-via-unused-field.json")
    result = _run(vector)
    assert result.allowed is True, (
        "expected the careless verifier to wrongly ALLOW this vector — if it "
        "did not, the monkeypatch is not reaching the code path this test "
        "means to exercise"
    )
    assert vector["expected_result"] == "fail"
    assert result.allowed != (vector["expected_result"] == "pass")


def test_vector_14_extra_field_alone_cannot_be_mistaken_for_an_evaluable_entry() -> None:
    """Sanity check on the fixture, not the verifier: the extra field is a
    LIST OF ENTRIES shaped exactly like ``scope_boundary``
    (``prefix_entry``), so a careless verifier mistaking the field name is
    exercising the same matcher real boundaries use, not a strawman shape no
    real implementation would ever read."""
    vector = _load("14-no-privilege-via-unused-field.json")
    widened = vector["inputs"]["leaf"]["x_elevated_scope_boundary"]
    assert widened == [prefix_entry("data.acme")]
