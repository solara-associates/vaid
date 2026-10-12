"""Runs every vector in docs/a2a/v1/vectors/*.json against verify_a2a_message and
asserts the expected (result, error_code) pair.

The vectors live outside this package, under docs/a2a/v1/vectors/, because they
are the extension's vectors — not vaid-a2a's private fixtures — and
test_extension.py-equivalents in other languages would read the same files.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from vaid_a2a import METADATA_CHAIN_KEY, METADATA_VAID_KEY, verify_a2a_message
from vaid_mint.revocation import InMemoryRevocationList

VECTORS_DIR = Path(__file__).resolve().parents[3] / "docs" / "a2a" / "v1" / "vectors"


def _parse_verification_time(raw: str) -> datetime:
    """Parse a vector's own ``verification_time`` (RFC 3339, ``Z`` suffix) —
    never the wall clock, per the vectors README."""
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _vector_files() -> list[Path]:
    files = sorted(VECTORS_DIR.glob("*.json"))
    assert files, f"no vectors found under {VECTORS_DIR} — generator not run?"
    return files


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _revocation_for(revoked_ids: list[str]) -> InMemoryRevocationList:
    store = InMemoryRevocationList()
    if not revoked_ids:
        # An empty revocation list must still VOUCH for "nothing revoked",
        # not read as UNAVAILABLE (R.4.5/R.4.6) — assume_nothing_revoked()
        # is the explicit, named way to get that posture rather than relying
        # on an absent store by accident.
        return InMemoryRevocationList.assume_nothing_revoked()
    for vaid_id in revoked_ids:
        store.revoke(vaid_id)
    return store


@pytest.mark.parametrize("vector_path", _vector_files(), ids=lambda p: p.stem)
def test_vector(vector_path: Path) -> None:
    vector = _load(vector_path)

    message = {
        "metadata": {
            METADATA_VAID_KEY: vector["inputs"]["leaf"],
            METADATA_CHAIN_KEY: vector["inputs"]["chain"],
        }
    }
    revocation = _revocation_for(vector["revoked_vaid_ids"])

    result = verify_a2a_message(
        message,
        trust_config=vector["trust_config"],
        revocation=revocation,
        requested_action=vector.get("requested_action"),
        now=_parse_verification_time(vector["verification_time"]),
    )

    expected_pass = vector["expected_result"] == "pass"
    assert result.allowed is expected_pass, (
        f"{vector_path.name}: expected allowed={expected_pass}, got "
        f"{result.allowed} ({result.code.value}: {result.reason})"
    )
    if vector.get("expected_error_code") is not None:
        assert result.code.value == vector["expected_error_code"], (
            f"{vector_path.name}: expected code "
            f"{vector['expected_error_code']!r}, got {result.code.value!r} "
            f"({result.reason})"
        )


def test_all_vectors_covered() -> None:
    """A guard against the parametrized test silently collecting zero cases —
    the exact "ALL-PASS, a workflow not started" shape: a suite with no
    vectors loaded would otherwise report a clean, empty pass.

    The floor tracks the number of vectors that actually exist. Left at a
    stale lower number it stops being a guard against anything but total
    absence: with 14 vectors published, a floor of 6 would let more than half
    of them disappear and still report a clean pass."""
    assert len(_vector_files()) >= 14
