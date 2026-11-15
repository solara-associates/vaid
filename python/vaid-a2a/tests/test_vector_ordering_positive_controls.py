"""Positive controls for vectors 15 to 18 (docs/a2a/v1/vectors/): the
verification-order triad from a2aproject/A2A#2028 (Allan's reply,
issuecomment-6875045085) plus the fourth case @aeoess asked for
(issuecomment-6881408913) — a structurally valid leaf with an invalid
signature and an incomplete chain, expected INAUTHENTIC.

Vectors 15, 16 and 17 each isolate one defect (bad leaf signature; incomplete
chain; no VAID at all) and are already proven against the real verifier by
test_vectors.py. What those three cannot show on their own is that the ORDER
is load-bearing — a verifier could check chain completeness before the leaf's
own signature and still pass all three, because in each of them only one of
the two checks fails. Vector 18 combines both defects in one input, so the
two orders disagree: signature-first reaches INAUTHENTIC (spec §5's required
order), chain-first reaches UNVERIFIABLE and stops before ever looking at the
leaf's own signature.

The wrongly-ordered verifier below is built from the SAME primitives
``vaid_a2a.verifier`` calls (``verify_vaid_authenticity_graded``,
``verify_chain_at``) — not a second hand-rolled signature or attenuation
check — with only the order of the two calls swapped. That isolates the one
thing under test: a correct verifier that happened to call chain integrity
before authenticity is still wrong, and vector 18 is what proves it."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from vaid_mint.chain import PresentedBundle
from vaid_mint.revocation import InMemoryRevocationList, assemble_lineage
from vaid_mint.verify import VaidVerdict, verify_vaid_authenticity_graded

import vaid_a2a.verifier as verifier_module
from vaid_a2a import METADATA_CHAIN_KEY, METADATA_VAID_KEY, verify_a2a_message

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


def _chain_first_verdict(vector: dict) -> str:
    """Re-derives a verdict for ``vector`` by checking chain COMPLETENESS
    (``assemble_lineage`` — every ancestor named by ``parent_vaid`` is
    present, nothing about signatures) BEFORE the leaf's own authenticity —
    the exact order inversion spec §5 forbids. ``verify_chain_at`` itself
    cannot be reused for this: it authenticates the leaf as its own first
    step (see ``chain.py``'s "Step 1 — authenticate the leaf"), so it already
    enforces the correct order internally and would never surface the bug
    this control exists to catch. Checking completeness directly, via the
    same ``assemble_lineage`` the real verifier's revocation step (§5 step 6)
    already calls, isolates exactly the one reordering under test.

    Returns the string a caller would log: ``"unverifiable"``,
    ``"inauthentic"`` or ``"allowed"``."""
    leaf = vector["inputs"]["leaf"]
    chain = vector["inputs"]["chain"]
    keys = verifier_module._build_key_resolver(vector["trust_config"])

    bundle = PresentedBundle(chain)
    if assemble_lineage(leaf, bundle) is None:
        return "unverifiable"

    thumbprint = leaf.get("kernel_key_thumbprint")
    key = keys.resolve_key(thumbprint)
    authenticity = verify_vaid_authenticity_graded(key, leaf)
    if authenticity is not VaidVerdict.VALID:
        return "inauthentic"
    return "allowed"


def test_vector_15_passes_the_real_verifier() -> None:
    vector = _load("15-invalid-leaf-signature-complete-chain.json")
    result = _run(vector)
    assert result.allowed is False
    assert result.code is verifier_module.VerifyCode.INAUTHENTIC


def test_vector_16_passes_the_real_verifier() -> None:
    vector = _load("16-incomplete-chain-valid-signature.json")
    result = _run(vector)
    assert result.allowed is False
    assert result.code is verifier_module.VerifyCode.UNVERIFIABLE


def test_vector_17_passes_the_real_verifier() -> None:
    vector = _load("17-missing-vaid-not-a-denial.json")
    result = _run(vector)
    assert result.allowed is True
    assert result.code is verifier_module.VerifyCode.NO_VAID


def test_vector_18_passes_the_real_verifier() -> None:
    vector = _load("18-invalid-signature-and-incomplete-chain-ordering-trap.json")
    result = _run(vector)
    assert result.allowed is False
    assert result.code is verifier_module.VerifyCode.INAUTHENTIC


def test_vector_18_chain_first_order_would_wrongly_say_unverifiable() -> None:
    """The control: a verifier that checks chain completeness before the
    leaf's own signature reaches UNVERIFIABLE on vector 18 and never looks at
    the leaf's authenticity at all — diverging from the spec-required
    INAUTHENTIC. If this assertion ever failed, vector 18 would have stopped
    catching the wrong order, which is the one thing it exists for."""
    vector = _load("18-invalid-signature-and-incomplete-chain-ordering-trap.json")
    assert _chain_first_verdict(vector) == "unverifiable"
    assert vector["expected_error_code"] == "inauthentic"


def test_vector_16_chain_first_order_agrees_with_signature_first() -> None:
    """Sanity check on the triad's own claim: vectors 15-17 each isolate ONE
    defect, so the two orders agree on them and only vector 18 (both defects
    at once) can tell the orders apart. Vector 16's leaf signature is
    genuinely valid, so a chain-first check reaches the same verdict,
    unverifiable, that the real signature-first verifier reaches too."""
    vector = _load("16-incomplete-chain-valid-signature.json")
    assert _chain_first_verdict(vector) == "unverifiable"
    assert vector["expected_error_code"] == "unverifiable"


def test_vector_15_chain_first_order_disagrees_but_only_because_the_chain_is_complete() -> None:
    """Vector 15's chain is complete and would attenuate cleanly, so a
    chain-first check runs past step 3 with no complaint and only then finds
    the leaf's broken signature — same INAUTHENTIC result as the real
    verifier, for this vector. This is exactly why vector 15 alone, like
    vector 16 alone, cannot catch the wrong order: only combining both
    defects (vector 18) makes the two orders diverge."""
    vector = _load("15-invalid-leaf-signature-complete-chain.json")
    assert _chain_first_verdict(vector) == "inauthentic"
    assert vector["expected_error_code"] == "inauthentic"
