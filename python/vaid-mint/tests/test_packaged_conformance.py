"""The packaged firewall, tested where pytest can actually see it.

Mirror of `typescript/vaid-mint/test/packaged_conformance.test.ts`.

This file exists because the equivalent assertions used to live inside
``vaid_mint/conformance.py`` as ``test_`` functions and were **never collected** —
pytest's default ``python_files`` glob is ``test_*.py``, which ``conformance.py``
does not match. Five functions that read as coverage were run by nothing. That is
the same class of defect the firewall itself now guards against, one level up, so
the assertions moved here rather than being trusted where they sat.
"""

from __future__ import annotations

import pytest

from vaid_mint.conformance import (
    VECTOR_CHECKS,
    ConformanceError,
    bundled_vector_names,
    check_attestation,
    check_chain,
    check_document_digest,
    check_kernel_signature,
    check_lineage_hash,
    check_mint_pop,
    check_vaid_id_equals_agent_id,
    load_named_vector,
    load_vector,
    run,
)


def test_the_packaged_firewall_passes_against_every_bundled_vector() -> None:
    """Every vector that ships is reached — not a fixed list this test also has to
    remember. That duplication is precisely what let a new vector ship unchecked."""
    result = run()
    covered = sorted(result)

    assert covered == bundled_vector_names()

    # Each BYTE-PINNING vector produced a real digest, and no two are equal — a
    # firewall that silently checked one vector four times would pass a count
    # assertion.
    #
    # ``scope_v1.json`` is deliberately excluded from the digest assertions rather
    # than given a synthetic digest: containment is a predicate computed OVER a
    # document and never appears inside one, so it pins verdicts, not bytes. A
    # fabricated digest would assert byte-identity about a thing that has no bytes.
    # It is still covered by the ``covered == bundled_vector_names()`` assertion
    # above, and by ``check_scope`` inside ``run()``, which is where its real
    # content is verified.
    digested = [n for n in covered if "digest_sha256_hex" in result[n]]
    assert digested, "expected at least one byte-pinning vector"
    digests = [result[n]["digest_sha256_hex"] for n in digested]
    assert all(len(d) == 64 for d in digests)
    assert len(set(digests)) == len(digests)

    # A predicate vector must still carry content, so "no digest" cannot become a
    # way to ship an empty vector past the firewall.
    for name in (n for n in covered if "digest_sha256_hex" not in result[n]):
        assert result[name].get("cases"), (
            f"{name} has neither a digest nor any cases — it asserts nothing"
        )


def test_a_vector_shipped_with_no_check_is_a_blocker() -> None:
    """The defect this change exists to close, asserted directly in both
    directions."""
    present, known = set(bundled_vector_names()), set(VECTOR_CHECKS)
    assert not (present - known), f"bundled but unchecked: {sorted(present - known)}"
    assert not (known - present), f"checked but not bundled: {sorted(known - present)}"


def test_a_divergent_document_digest_is_a_blocker() -> None:
    v = load_vector()
    with pytest.raises(ConformanceError):
        check_document_digest({**v, "digest_sha256_hex": "00" * 32})


def test_a_divergent_kernel_signature_is_a_blocker() -> None:
    v = load_vector()
    with pytest.raises(ConformanceError):
        check_kernel_signature(
            {**v, "ed25519": {**v["ed25519"], "signature_hex": "00" * 64}}
        )


def test_a_divergent_chain_verdict_is_a_blocker() -> None:
    """The chain vector's load-bearing assertion: not the digests, the WALK."""
    v = load_named_vector("chain_v1.json")
    with pytest.raises(ConformanceError):
        check_chain({**v, "expected": {**v["expected"], "verification": "inauthentic"}})


def test_a_divergent_attestation_digest_is_a_blocker() -> None:
    v = load_named_vector("attestation_v1.json")
    with pytest.raises(ConformanceError):
        check_attestation({**v, "digest_sha256_hex": "00" * 32})


def test_the_packaged_checks_pass_on_the_real_vectors() -> None:
    """Positive control, so the blocker tests above cannot pass by everything
    throwing."""
    v = load_vector()
    check_document_digest(v)
    check_kernel_signature(v)
    check_lineage_hash(v)
    check_vaid_id_equals_agent_id(v)
    check_mint_pop(load_named_vector("mint_pop_v1.json"))
    check_chain(load_named_vector("chain_v1.json"))
    check_attestation(load_named_vector("attestation_v1.json"))
