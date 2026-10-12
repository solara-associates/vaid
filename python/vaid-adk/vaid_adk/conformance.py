"""Packaged ADK-verification conformance check — the firewall, shipped in the wheel.

Mirror of ``vaid_pop.conformance`` / ``vaid_mint.conformance`` /
``vaid_a2a.conformance``. A consumer who has only ``pip install vaid-adk`` — no
repo checkout — can prove the verifier they installed reaches the right verdict
on a frozen delegation chain, and denies fail-closed for every distinct reason
the plugin exists to deny for::

    python -m vaid_adk.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-adk-conformance                # same, via the console entry point

Programmatically::

    from vaid_adk.conformance import run
    run()  # raises ConformanceError on any divergence; returns the verdict table

WHAT THIS PINS, AND WHAT IT DOES NOT. Like ``vaid_a2a.conformance`` and
``verdict_v1.json``, this pins VERDICTS rather than bytes: for each case,
``(allowed, code)``. It is not a cross-language byte-identity proof — this
package signs nothing and canonicalizes nothing of its own, so it has no bytes
to be identical about. The bytes underneath it are proven by
``vaid-mint-conformance``, which this package's dependency ships; what is left to
prove here, and what this does prove, is that the ORDERING and the FAIL-CLOSED
posture of ``verify_presentation`` are intact in the artifact a consumer
received.

WHERE THE DOCUMENTS COME FROM: ``chain_v1.json``, the chain-presentation
conformance vector bundled inside the installed ``vaid-mint`` wheel. Nothing is
vendored here and nothing is minted at run time, which matters twice over. A
vendored second copy could drift from the vector the rest of the project is
proven against; a chain minted at run time would be different bytes on every
run, so a verdict over it could not be frozen at all, and the signing keys would
have to be generated rather than fixed.

THE VERIFICATION INSTANT IS THE VECTOR'S, NEVER THE WALL CLOCK. Every document in
``chain_v1`` expired on 2026-06-05. Checked against ``datetime.now()`` this whole
table silently changed meaning on that date — the exact defect vaid#79 recorded,
where an assertion went on passing because nothing consulted expiry.

CONTROLS ARE LOAD-BEARING ON BOTH SURFACES. ``CASES`` carries one case that MUST
be allowed and seven that must each be denied with a DIFFERENT code. A verifier
that denies everything fails the control; one that allows everything fails the
other seven; one that denies everything with a single code fails on the codes. A
firewall made only of negatives is satisfied by a package that refuses to work
at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from importlib.resources import files
from typing import Callable

from vaid_mint.document import entry_claimed_resource
from vaid_mint.revocation import InMemoryRevocationList

from vaid_adk import (
    TrustedIssuers,
    TrustedIssuersConfigError,
    VaidPresentation,
    verify_presentation,
)

#: The trust domain every document in ``chain_v1`` claims. Named here only so the
#: cross-domain case below can bind the SAME kernel key to a different one.
_OTHER_DOMAIN = "not-the-domain-this-key-is-trusted-for.example"


class ConformanceError(AssertionError):
    """A divergence from the frozen verdict table — a hard BLOCKER, never
    ship-anyway."""


def load_chain_vector() -> dict:
    """The chain-presentation vector bundled with the installed ``vaid-mint``.

    Read from the DEPENDENCY's wheel rather than from a copy of our own, so this
    firewall and ``vaid-mint-conformance`` cannot disagree about what the frozen
    chain is.
    """
    return json.loads(files("vaid_mint").joinpath("vectors/chain_v1.json").read_text())


def frozen_chain(v: dict) -> list[dict]:
    """The vector's three documents, root first, each with its frozen kernel
    signature attached.

    The vector stores each hop's signature alongside the document rather than
    inside it (``signature_hex``), so a document is only verifiable once it is
    reattached — the same reconstruction ``vaid_mint.conformance.check_chain``
    performs. Reconstructing it the same way is the point: a different
    reconstruction would be testing a different artifact.
    """
    return [
        {**e["document"], "kernel_signature": list(bytes.fromhex(e["signature_hex"]))}
        for e in v["chain"]
    ]


@dataclass(frozen=True)
class Case:
    """One frozen expectation about ``verify_presentation``."""

    name: str
    why: str
    expected_allowed: bool
    expected_code: str
    #: Given ``(root, intermediate, leaf, kernel_public_key)``, the keyword
    #: arguments this case calls ``verify_presentation`` with.
    build: Callable[[dict, dict, dict, bytes], dict]


def _trusted(domain: str, kernel_public_key: bytes) -> TrustedIssuers:
    return TrustedIssuers.from_raw_keys([(domain, kernel_public_key)])


def _vouching() -> InMemoryRevocationList:
    # An empty list must VOUCH for "nothing revoked" rather than read as
    # UNAVAILABLE (R.4.5/R.4.6); the named constructor is the explicit way to say
    # so instead of relying on an absent store by accident.
    return InMemoryRevocationList.assume_nothing_revoked()


def _base(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        "presentation": VaidPresentation(leaf=leaf, chain=(root, mid)),
        "keys": _trusted(leaf["trust_domain"], key),
        "revocation": _vouching(),
        # Since ADR-0009 a boundary entry is a typed ``{kind, value}`` object,
        # and ``requested_resource`` is a RESOURCE string. ``entry_claimed_resource``
        # is vaid-mint's own projection from the one to the other, reused here so
        # this firewall cannot branch on ``kind`` differently from the matcher it
        # is testing. Indexing ``[0]`` and passing the dict through fed a dict to
        # ``str.startswith`` inside ``scope_contains``.
        "requested_resource": entry_claimed_resource(leaf["scope_boundary"][0]),
        "requested_capability": leaf["capability_set"][0],
    }


def _cross_domain(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    # GHSA-hfjh-v2x2-r58v. The key is the RIGHT key and every signature verifies;
    # it is simply trusted for a different domain than the documents claim.
    # Before the fix, resolution was by thumbprint alone and this passed.
    return {**_base(root, mid, leaf, key), "keys": _trusted(_OTHER_DOMAIN, key)}


def _out_of_scope(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {**_base(root, mid, leaf, key), "requested_resource": "data.not.in.this.leaf"}


def _missing_capability(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {**_base(root, mid, leaf, key), "requested_capability": "a-capability-nobody-granted"}


def _no_vaid(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {**_base(root, mid, leaf, key), "presentation": None}


def _broken_chain(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    # The leaf alone, with the ancestry it needs withheld. A verifier that walks
    # only as far as the leaf's own signature would ALLOW this.
    return {**_base(root, mid, leaf, key), "presentation": VaidPresentation(leaf=leaf, chain=())}


def _revoked_ancestor(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    store = InMemoryRevocationList()
    store.revoke(mid["vaid_id"])
    return {**_base(root, mid, leaf, key), "revocation": store}


def _revocation_unavailable(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    # A store that cannot vouch. `indeterminate`, NOT `revoked` and NOT allowed:
    # unavailable is its own state, never collapsed into either neighbour.
    return {**_base(root, mid, leaf, key), "revocation": InMemoryRevocationList()}


CASES: tuple[Case, ...] = (
    Case(
        name="control: frozen chain, in scope, nothing revoked",
        why="THE CONTROL. Without a case that MUST be allowed, a verifier that "
        "denies every input satisfies every other case here.",
        expected_allowed=True,
        expected_code="allowed",
        build=_base,
    ),
    Case(
        name="trusted key, wrong trust domain (GHSA-hfjh-v2x2-r58v)",
        why="One issuer's key must not vouch for another issuer's domain. No "
        "forged signature and no stolen key: the whole attack is the missing "
        "binding, which is why a signature-only check cannot see it.",
        expected_allowed=False,
        expected_code="issuer_mismatch",
        build=_cross_domain,
    ),
    Case(
        name="requested resource outside the leaf's scope_boundary",
        why="Authority is bounded by the leaf, not by the root it descends from.",
        expected_allowed=False,
        expected_code="out_of_scope",
        build=_out_of_scope,
    ),
    Case(
        name="requested capability not in the leaf's capability_set",
        why="Scope and capability are separate containments; passing one is not "
        "passing the other.",
        expected_allowed=False,
        expected_code="missing_capability",
        build=_missing_capability,
    ),
    Case(
        name="no presentation at all",
        why="This function's caller has already decided a VAID is required, so a "
        "missing one is denied rather than passed through.",
        expected_allowed=False,
        expected_code="no_vaid",
        build=_no_vaid,
    ),
    Case(
        name="leaf presented with its ancestry withheld",
        why="A chain that cannot be walked back to a trusted root is unverifiable, "
        "never 'valid so far'. Fail-closed on absence.",
        expected_allowed=False,
        expected_code="unverifiable",
        build=_broken_chain,
    ),
    Case(
        name="an ancestor is revoked",
        why="Revocation is evaluated over the whole assembled lineage, not the "
        "leaf alone: a revoked middle link revokes what descends from it.",
        expected_allowed=False,
        expected_code="revoked",
        build=_revoked_ancestor,
    ),
    Case(
        name="revocation status unavailable",
        why="Unavailable is its own verdict (R.4.5/R.4.6) - indeterminate, never "
        "collapsed into 'revoked' and never into a pass.",
        expected_allowed=False,
        expected_code="indeterminate",
        build=_revocation_unavailable,
    ),
)


def check_case(case: Case, docs: list[dict], key: bytes, now: datetime) -> str:
    """Run one case and assert its frozen verdict. Returns the code observed."""
    root, mid, leaf = docs
    result = verify_presentation(**case.build(root, mid, leaf, key), now=now)
    if result.allowed is not case.expected_allowed:
        raise ConformanceError(
            f"{case.name}: verdict diverged — BLOCKER\n"
            f"  got    = allowed={result.allowed} ({result.code.value}: {result.reason})\n"
            f"  frozen = allowed={case.expected_allowed} ({case.expected_code})\n"
            f"  why this case exists: {case.why}"
        )
    if result.code.value != case.expected_code:
        raise ConformanceError(
            f"{case.name}: code diverged — BLOCKER\n"
            f"  got    = {result.code.value!r} ({result.reason})\n"
            f"  frozen = {case.expected_code!r}\n"
            f"  why this case exists: {case.why}"
        )
    return result.code.value


def check_controls() -> None:
    """The case table itself, before any case runs: both polarities present, and
    every denial reaching a DISTINCT code. A table of eight denials that all
    collapse to one code would let a verifier that refuses everything for one
    reason satisfy all of them."""
    allowed = [c for c in CASES if c.expected_allowed]
    denied = [c for c in CASES if not c.expected_allowed]
    if not allowed:
        raise ConformanceError(
            "no case expects a PASS — BLOCKER. With negatives only, a verifier "
            "that denies everything would satisfy this firewall."
        )
    if not denied:
        raise ConformanceError(
            "no case expects a DENIAL — BLOCKER. With positives only, a verifier "
            "that allows everything would satisfy this firewall."
        )
    codes = [c.expected_code for c in denied]
    if len(set(codes)) != len(codes):
        raise ConformanceError(
            f"denial cases do not each pin a distinct code — BLOCKER\n  codes = {codes}"
        )


def check_config_is_fail_closed() -> None:
    """A trust configuration that cannot bind a domain to a key is a defect in the
    DEPLOYMENT, so it raises rather than returning a denial — and it raises before
    anything about the presentation is looked at, so a caller cannot get a verdict
    out of an unbindable resolver by presenting nothing.

    This is the half of GHSA-hfjh-v2x2-r58v that no per-request case can cover: a
    resolver answering only "do I trust this key" has nowhere to put the answer to
    "for which domain", so accepting one would reintroduce the gap wholesale.
    """

    class _ThumbprintOnlyResolver:
        """The pre-fix resolver shape: a key lookup with no domain to bind it to."""

        def resolve_key(self, thumbprint: str) -> bytes | None:
            return b"\x00" * 32

    try:
        verify_presentation(
            None,
            keys=_ThumbprintOnlyResolver(),  # type: ignore[arg-type]
            revocation=_vouching(),
            requested_resource=None,
            requested_capability=None,
        )
    except TrustedIssuersConfigError:
        return
    raise ConformanceError(
        "a resolver that cannot bind a trust domain to a key was ACCEPTED — "
        "BLOCKER. require_domain_binding is the control that makes "
        "GHSA-hfjh-v2x2-r58v unreachable by configuration; without it a "
        "deployment can reintroduce the defect with no code change."
    )


def run() -> dict[str, str]:
    """Run the firewall. Raises ConformanceError on any divergence; returns the
    observed verdict table on PASS."""
    check_controls()
    check_config_is_fail_closed()
    v = load_chain_vector()
    docs = frozen_chain(v)
    key = bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    now = datetime.fromisoformat(v["expected"]["verification_instant"].replace("Z", "+00:00"))
    return {case.name: check_case(case, docs, key, now) for case in CASES}


# --- pytest discovery (so `pytest --pyargs vaid_adk` runs the firewall) ---


def test_packaged_controls_are_present() -> None:
    check_controls()


def test_packaged_unbindable_config_raises() -> None:
    check_config_is_fail_closed()


def test_packaged_verdicts_match_the_frozen_chain() -> None:
    v = load_chain_vector()
    docs = frozen_chain(v)
    key = bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    now = datetime.fromisoformat(v["expected"]["verification_instant"].replace("Z", "+00:00"))
    for case in CASES:
        check_case(case, docs, key, now)


def main() -> int:
    try:
        verdicts = run()
    except ConformanceError as exc:
        print(f"ADK VERIFICATION FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    v = load_chain_vector()
    print(
        "ADK VERIFICATION FIREWALL: PASS — installed verifier reaches the frozen "
        f"verdict on all {len(verdicts)} case(s)\n"
        f"  chain    = vaid-mint chain_v1.json, 3 hops, verified at "
        f"{v['expected']['verification_instant']}\n"
        "  config   = an unbindable trust resolver is refused, not tolerated"
    )
    for case in CASES:
        print(f"  {'allow ' if case.expected_allowed else 'deny  '} "
              f"{verdicts[case.name]:<22} {case.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
