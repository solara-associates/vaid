"""The mint's own output must satisfy the spec the mint publishes (E.6).

**The defect this exists to catch (BACKLOG B8).** The Rust issuer stored
``Utc::now()`` unmodified and emitted ``2026-08-11T08:04:18.165623Z`` — RFC 3339,
and not the whole-second ``Z`` profile ``docs/spec/encoding.md`` E.6 requires of
every timestamp inside signed bytes.

Python was **not** affected: it formats with ``strftime("%Y-%m-%dT%H:%M:%SZ")``,
so the profile is written out at the point the timestamp becomes a string. This
test exists anyway, for the reason the roundtrip gate gives for testing the
implementation that happened to be right: *that* is the one that silently
regresses, because nobody is watching it.

**Why the existing suite could not see the Rust defect.** Every test that touched
a minted document minted it and then verified it, which is self-consistent by
construction. Conformance to a profile is not a property any round-trip can
reveal; it has to be asserted against the document directly.
"""

from __future__ import annotations

import re

from vaid_mint import (
    InMemoryAudit,
    MintService,
    ReferenceIssuer,
    VaidSeed,
    has_conforming_timestamps,
)

#: The E.6 shape, spelled out rather than imported, so this test does not agree
#: with the implementation merely by sharing its definition of the answer.
E6 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _mint_one() -> dict:
    issuer = ReferenceIssuer.ephemeral(24, "vaid.example")
    mint = MintService(issuer, InMemoryAudit())
    return mint.mint_root(
        VaidSeed(
            agent_class="conformance",
            version="1.0.0",
            tenant_id="acme",
            scope_boundary=["data.acme"],
            capability_set=["read"],
        )
    )


def test_a_freshly_minted_document_carries_whole_second_z_timestamps() -> None:
    vaid = _mint_one()
    for field in ("issued_at", "expires_at"):
        value = vaid[field]
        assert E6.match(value), (
            f"the mint emitted {field}={value!r}, which is not the whole-second `Z` "
            "profile E.6 requires of every timestamp inside signed bytes — the mint's "
            "OWN output failing the mint's OWN spec (BACKLOG B8)"
        )


def test_the_predicate_agrees_with_the_bytes() -> None:
    """Guards against the predicate and the serialization drifting apart: it would
    be entirely possible to satisfy one and not the other."""
    assert has_conforming_timestamps(_mint_one())


def test_the_check_rejects_the_form_this_defect_shipped() -> None:
    """THE CONTROL. The pattern must reject the form Rust actually shipped,
    otherwise the test above passes for a check that accepts everything."""
    assert E6.match("2026-08-11T08:04:18Z")
    assert not E6.match("2026-08-11T08:04:18.165623Z"), "the sub-second form B8 shipped"
    assert not E6.match("2026-08-11T08:04:18+00:00"), "numeric offset is not E.6"
    assert not E6.match("2026-08-11T08:04:18.000Z"), "millisecond form is not E.6"
    assert not E6.match("not-a-timestamp"), "garbage is not E.6"
