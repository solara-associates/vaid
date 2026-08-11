"""Packaged cross-language mint conformance check — the firewall, shipped in the wheel.

Mirror of the Rust ``tests/mint_conformance.rs``. A consumer who has only
``pip install vaid-mint`` can prove the mint they installed reproduces the frozen
cross-language VAID-document vector byte-for-byte::

    python -m vaid_mint.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-mint-conformance                # same, via the console entry point

Two vectors are bundled with the package and both are checked:

- ``vaid_mint/vectors/mint_v1.json`` — the signed VAID document.
- ``vaid_mint/vectors/mint_pop_v1.json`` — the ``MintPopPayload`` a holder signs
  to prove it controls the BYO key it registers at mint. Frozen later than the
  others: it was the one signed structure with no artifact holding the
  implementations to it (``docs/spec/encoding.md`` E.11), and it is the only
  vector carrying a JSON ``null`` (E.7).

The Rust ``mint_conformance`` / ``mint_pop_conformance`` tests assert the
identical vectors; a repo-level drift-check proves every copy is byte-identical,
so Rust output == Python output == TypeScript output == vector.

Per Decision B this proves self-consistency WITHIN this repo, NOT conformance
against the managed authority's VAID format.
"""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files

import rfc8785

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vaid_pop import canonical_request_signing_bytes, verify_signed_payload

from vaid_mint.attestation import (
    canonical_attestation_signing_bytes,
    verify_attestation_authenticity,
)
from vaid_mint.chain import PresentedBundle, verify_chain
from vaid_mint.document import (
    SCOPE_SEPARATORS,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    scope_contains,
)
from vaid_mint.mint_types import VaidSeed, build_mint_pop_payload


class ConformanceError(AssertionError):
    """A cross-language byte-identity divergence — a hard BLOCKER."""


def load_vector() -> dict:
    """The mint conformance vector bundled with the installed package."""
    data = files("vaid_mint").joinpath("vectors/mint_v1.json").read_text()
    return json.loads(data)


def check_document_digest(v: dict) -> None:
    """Python JCS (kernel_signature nulled) + SHA-256 over the VAID document ==
    frozen digest."""
    digest = canonical_vaid_signing_bytes(v["input"])
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError(
            f"VAID-document digest diverged from the frozen vector — BLOCKER\n"
            f"  got    = {digest.hex()}\n  vector = {v['digest_sha256_hex']}"
        )
    if len(digest) != 32:
        raise ConformanceError(f"digest is {len(digest)} bytes, expected 32")


def check_kernel_signature(v: dict) -> None:
    """From the frozen kernel seed, derive the same public key + deterministic
    signature over the document digest."""
    seed = bytes.fromhex(v["ed25519"]["kernel_private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    pub = sk.public_key().public_bytes_raw()
    if pub.hex() != v["ed25519"]["kernel_public_key_hex"]:
        raise ConformanceError(
            f"kernel public key diverged — BLOCKER\n"
            f"  got    = {pub.hex()}\n  vector = {v['ed25519']['kernel_public_key_hex']}"
        )

    digest = canonical_vaid_signing_bytes(v["input"])
    sig = sk.sign(digest)
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError(
            f"kernel signature diverged — BLOCKER\n"
            f"  got    = {sig.hex()}\n  vector = {v['ed25519']['signature_hex']}"
        )
    Ed25519PublicKey.from_public_bytes(pub).verify(sig, digest)  # raises on failure


def check_lineage_hash(v: dict) -> None:
    """The document's ``lineage_hash`` == recompute from ``parent_vaid`` +
    ``agent_id`` — proves the derivation is cross-language identical."""
    inp = v["input"]
    recomputed = compute_lineage_hash(inp["parent_vaid"], inp["agent_id"])
    if recomputed != inp["lineage_hash"]:
        raise ConformanceError(
            f"recomputed lineage_hash diverged from the document — BLOCKER\n"
            f"  got    = {recomputed}\n  vector = {inp['lineage_hash']}"
        )


def check_vaid_id_equals_agent_id(v: dict) -> None:
    """``vaid_id`` is derived from ``agent_id`` (same UUID)."""
    inp = v["input"]
    if inp["vaid_id"] != inp["agent_id"]:
        raise ConformanceError("vaid_id must equal agent_id — BLOCKER")


def load_mint_pop_vector() -> dict:
    """The mint proof-of-possession vector bundled with the installed package."""
    data = files("vaid_mint").joinpath("vectors/mint_pop_v1.json").read_text()
    return json.loads(data)


def check_mint_pop(v: dict) -> None:
    """The ``MintPopPayload`` gate (``docs/spec/encoding.md`` E.11).

    Rebuilds the payload through :func:`~vaid_mint.mint_types.build_mint_pop_payload`
    — the single constructor both holder and mint use — rather than reading
    ``input`` back, so this proves the code path that actually runs at mint emits
    these bytes, not merely that a dict round-trips.

    Also asserts the two properties this vector exists to pin: ``parentVaid`` is a
    PRESENT JSON ``null`` (E.7 — an omitted key is a different key set and a
    different digest), and the signature verifies against the key the payload
    REGISTERS, which is the whole semantic content of proof-of-possession.
    """
    seed = bytes.fromhex(v["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    registered = sk.public_key().public_bytes_raw()

    if registered.hex() != v["ed25519"]["public_key_hex"]:
        raise ConformanceError(
            f"holder public key diverged — BLOCKER\n"
            f"  got    = {registered.hex()}\n  vector = {v['ed25519']['public_key_hex']}"
        )

    payload = build_mint_pop_payload(
        VaidSeed(
            agent_class="runner",
            version="1.0.0",
            tenant_id="aifactory",
            parent_vaid=None,
            scope_boundary=["data.aifactory"],
            capability_set=["read"],
            public_key_der=registered,
        ),
        public_key_der=registered,
        nonce="0123456789abcdef0123456789abcdef",
        issued_at="2026-06-04T12:00:00Z",
    )
    if payload != v["input"]:
        raise ConformanceError(
            f"the mint's own PoP payload constructor diverged from the frozen "
            f"vector — BLOCKER\n  got    = {payload}\n  vector = {v['input']}"
        )

    # E.7: a present null, not an omitted key.
    if "parentVaid" not in v["input"] or v["input"]["parentVaid"] is not None:
        raise ConformanceError(
            "parentVaid must be a PRESENT JSON null in this vector — encoding.md E.7"
        )
    without = {k: x for k, x in v["input"].items() if k != "parentVaid"}
    if canonical_request_signing_bytes(without).hex() == v["digest_sha256_hex"]:
        raise ConformanceError(
            "omitting parentVaid MUST change the digest — otherwise E.7 is untested"
        )

    digest = canonical_request_signing_bytes(payload)
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError(
            f"mint-PoP digest diverged from the frozen vector — BLOCKER\n"
            f"  got    = {digest.hex()}\n  vector = {v['digest_sha256_hex']}"
        )
    sig = sk.sign(digest)
    if sig.hex() != v["ed25519"]["signature_hex"]:
        raise ConformanceError(
            f"mint-PoP signature diverged — BLOCKER\n"
            f"  got    = {sig.hex()}\n  vector = {v['ed25519']['signature_hex']}"
        )

    # The PoP semantic: it must verify against the key it REGISTERS.
    if not verify_signed_payload(payload, bytes(payload["publicKeyDer"]),
                                 bytes.fromhex(v["ed25519"]["signature_hex"])):
        raise ConformanceError(
            "the frozen PoP must verify against the registered key — BLOCKER"
        )
    escalated = dict(payload, capabilitySet=["read", "write"])
    if verify_signed_payload(escalated, registered,
                             bytes.fromhex(v["ed25519"]["signature_hex"])):
        raise ConformanceError(
            "a captured PoP must not be replayable to mint a higher-privilege VAID"
        )


def load_named_vector(name: str) -> dict:
    """Read one bundled vector by filename."""
    return json.loads(files("vaid_mint").joinpath(f"vectors/{name}").read_text())


def check_chain(v: dict) -> None:
    """`chain_v1.json` — the WALK. Per-hop digests and signatures, the contract
    digest over the whole frozen chain, and the verdict a third party reaches."""
    seed = bytes.fromhex(v["ed25519"]["kernel_private_key_seed_hex"])
    key = Ed25519PrivateKey.from_private_bytes(seed)

    for entry in v["chain"]:
        digest = canonical_vaid_signing_bytes(entry["document"])
        if digest.hex() != entry["digest_sha256_hex"]:
            raise ConformanceError(
                f"chain hop {entry['_role']}: document digest != frozen vector"
            )
        if key.sign(digest).hex() != entry["signature_hex"]:
            raise ConformanceError(
                f"chain hop {entry['_role']}: kernel signature != frozen vector"
            )

    expected = {k: val for k, val in v["expected"].items() if k != "_comment"}
    contract = rfc8785.dumps({"chain": v["chain"], "expected": expected})
    if hashlib.sha256(contract).hexdigest() != v["digest_sha256_hex"]:
        raise ConformanceError("chain contract digest != frozen vector")

    docs = [
        {**e["document"], "kernel_signature": list(bytes.fromhex(e["signature_hex"]))}
        for e in v["chain"]
    ]
    verdict = verify_chain(
        bytes.fromhex(v["ed25519"]["kernel_public_key_hex"]), docs[-1], PresentedBundle(docs)
    )
    if verdict.value != v["expected"]["verification"]:
        raise ConformanceError(
            f"chain verdict {verdict.value!r} != frozen {v['expected']['verification']!r} "
            "— the installed verifier disagrees with the frozen walk"
        )


def check_attestation(v: dict) -> None:
    """`attestation_v1.json` — the consent attestation: canonicalization,
    signature, and that the frozen signature verifies as authentic."""
    a = v["attestation"]
    digest = canonical_attestation_signing_bytes(a)
    if digest.hex() != v["digest_sha256_hex"]:
        raise ConformanceError("attestation digest != frozen vector")

    seed = bytes.fromhex(v["ed25519"]["kernel_private_key_seed_hex"])
    if Ed25519PrivateKey.from_private_bytes(seed).sign(digest).hex() != v["signature_hex"]:
        raise ConformanceError("attestation signature != frozen vector")

    signed = {**a, "signature": list(bytes.fromhex(v["signature_hex"]))}
    if not verify_attestation_authenticity(
        bytes.fromhex(v["ed25519"]["kernel_public_key_hex"]), signed
    ):
        raise ConformanceError("the frozen attestation must verify as authentic")


def check_scope(v: dict) -> None:
    """``scope_v1.json`` — scope containment (spec S.3, ADR-0005).

    The only check here that verifies a PREDICATE rather than bytes. Containment is
    computed over a document and never appears inside one, so there is no digest to
    reproduce and no signature to re-derive; what must agree across languages is the
    verdict on every case.

    It also asserts the vector still disagrees with bare prefix matching in at least
    five places. Without that, a future edit could quietly reduce the vector to cases
    both rules accept, leaving a green firewall that no longer covers the
    sibling-capture bug the vector exists for.
    """
    cases = v.get("cases") or []
    if not cases:
        raise ConformanceError("scope vector carries no cases")

    positives = negatives = disagreements = 0
    for case in cases:
        boundary = case["boundary"]
        resource = case["resource"]
        expected = case["expected"]
        if not isinstance(expected, bool):
            raise ConformanceError("scope case has no boolean `expected`")

        got = scope_contains(boundary, resource)
        if got != expected:
            raise ConformanceError(
                f"scope containment mismatch: boundary={boundary!r} "
                f"resource={resource!r} expected={expected} got={got} — {case['why']}"
            )
        if expected:
            positives += 1
        else:
            negatives += 1
        if boundary and any(resource.startswith(s) for s in boundary) != expected:
            disagreements += 1

    if not positives or not negatives:
        raise ConformanceError("scope vector must exercise both outcomes")
    if disagreements < 5:
        raise ConformanceError(
            "scope vector must pin the sibling-capture regression class; only "
            f"{disagreements} case(s) disagree with bare prefix matching"
        )

    declared = list(SCOPE_SEPARATORS)
    frozen = v["rule"]["separators"]
    if declared != frozen:
        raise ConformanceError(
            f"separator set mismatch: implementation {declared!r} != vector {frozen!r}"
        )


def check_roundtrip(v: dict) -> None:
    """``roundtrip_v1.json`` -- round-trip verification (ADR-0006).

    Verify-only: it pins a VERDICT OVER GIVEN BYTES rather than bytes over a given
    input, which is the only shape that catches cross-implementation disagreement.
    It also asserts the vector still DISCRIMINATES -- a dropping implementation
    must fail it in BOTH directions -- so it cannot decay into cases every
    implementation passes regardless of behaviour.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    cases = v.get("cases") or []
    if not cases:
        raise ConformanceError("roundtrip vector carries no cases")
    pub = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    )

    def verify(doc: dict, payload: dict | None = None) -> bool:
        try:
            pub.verify(
                bytes(doc["kernel_signature"]),
                canonical_vaid_signing_bytes(payload if payload is not None else doc),
            )
            return True
        except InvalidSignature:
            return False

    for c in cases:
        got = verify(c["document"])
        if got != c["expected_valid"]:
            raise ConformanceError(
                f"roundtrip case {c['name']!r}: got {got}, expected "
                f"{c['expected_valid']} -- {c['why']}"
            )

    false_negative = false_accept = False
    for c in cases:
        doc = c["document"]
        dropped = {k: val for k, val in doc.items() if not k.startswith("x_")}
        if verify(doc, dropped) != c["expected_valid"]:
            if c["expected_valid"]:
                false_negative = True
            else:
                false_accept = True
    if not (false_negative and false_accept):
        raise ConformanceError(
            "the roundtrip vector no longer catches a dropping implementation in both "
            "directions -- its discriminating power has been weakened"
        )


def check_verdict(v: dict) -> None:
    """``verdict_v1.json`` — the negative path (graded verdicts).

    The other checks in this file ask "does the installed mint produce the same
    bytes as everyone else". This one asks "does it REFUSE the same way, and say
    the same thing about why". The happy-path vectors cannot answer that: they only
    ever exercise documents that work.

    It asserts the REASON, not just the boolean. Three implementations that reject
    the same document for three different reasons agree on every boolean and
    disagree about what happened — and a ``pip install`` consumer whose build
    disagrees with the vector on a reason has a mint that will log, alert and retry
    differently from every other deployment.

    It also refuses to pass a vector that has lost its teeth: no positive control
    on either surface, a single refusal reason across every negative case, or a
    vocabulary that has drifted from :class:`~vaid_mint.verify.VaidVerdict` are all
    BLOCKERs. A green firewall over a vector that asserts nothing is the
    masked-green defect this package keeps finding.
    """
    from vaid_mint.mint import scope_attenuates_within
    from vaid_mint.revocation import RevocationStatus
    from vaid_mint.verify import VaidVerdict, verify_vaid_standing_from_json

    cases = v.get("cases") or []
    if not cases:
        raise ConformanceError("verdict vector carries no cases")
    kernel_pk = bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    revocation_states = {
        "not_revoked": RevocationStatus.NOT_REVOKED,
        "revoked": RevocationStatus.REVOKED,
        "unavailable": RevocationStatus.UNAVAILABLE,
    }

    positives = {"standing": 0, "attenuation": 0}
    negatives = {"standing": 0, "attenuation": 0}
    refusal_reasons: set[str] = set()
    exercised: set[str] = set()

    for c in cases:
        name = c.get("name", "<unnamed>")
        surface = c.get("surface")
        if surface == "standing":
            if "document_json" not in c:
                raise ConformanceError(f"standing case {name!r} has no document_json")
            state = c.get("revocation")
            if state not in revocation_states:
                raise ConformanceError(
                    f"standing case {name!r} names unknown revocation state {state!r}"
                )
            verdict = verify_vaid_standing_from_json(
                kernel_pk, c["document_json"], revocation_states[state]
            )
            reason, valid = verdict.code, verdict.is_valid()
        elif surface == "attenuation":
            ok = scope_attenuates_within(c.get("parent_scope", []), c.get("child_scope", []))
            reason, valid = ("attenuated" if ok else "scope_escalation"), ok
        else:
            raise ConformanceError(f"verdict case {name!r} names unknown surface {surface!r}")

        if reason != c.get("expected_reason"):
            raise ConformanceError(
                f"verdict case {name!r}: reason {reason!r} != frozen "
                f"{c.get('expected_reason')!r} — {c.get('why', '')}\n  A reason mismatch "
                "is a divergence even where the boolean agrees: this build and the "
                "vector disagree about WHAT HAPPENED."
            )
        if valid != c.get("expected_valid"):
            raise ConformanceError(
                f"verdict case {name!r}: valid={valid}, frozen "
                f"{c.get('expected_valid')} — {c.get('why', '')}"
            )

        if c["expected_valid"]:
            positives[surface] += 1
        else:
            negatives[surface] += 1
            refusal_reasons.add(reason)
        exercised.add(c["expected_reason"])

    # The vector must still have teeth. Each of these is a way it could be edited
    # into something that passes for every implementation regardless of behaviour.
    if not all(positives.values()):
        raise ConformanceError(
            "the verdict vector has lost a positive control (standing and attenuation "
            "each need one) — an implementation that refused every input would pass it"
        )
    if not all(negatives.values()):
        raise ConformanceError(
            "the verdict vector has lost a negative case on one of its surfaces — an "
            "implementation that accepted every input would pass it"
        )
    if len(refusal_reasons) < 2:
        raise ConformanceError(
            f"every refusing case expects the same reason ({sorted(refusal_reasons)}) — "
            "a boolean-only implementation would pass this vector, so the reason "
            "assertions would be checking nothing"
        )

    # Vocabulary agreement, both directions: a reason the vector declares that this
    # build cannot return means the vector was written against a different
    # implementation; a verdict this build can return that the vector never names is
    # a state shipping unchecked.
    declared = set(v.get("reasons", {}).get("standing", []))
    implemented = {r.code for r in VaidVerdict}
    if declared != implemented:
        raise ConformanceError(
            "the verdict vector's standing vocabulary and this build's VaidVerdict "
            f"disagree\n  only in the vector:         {sorted(declared - implemented)}\n"
            f"  only in the implementation: {sorted(implemented - declared)}"
        )
    all_declared = declared | set(v.get("reasons", {}).get("attenuation", []))
    unexercised = sorted(all_declared - exercised)
    if unexercised:
        raise ConformanceError(
            f"reason(s) declared by the vector but exercised by no case: {unexercised} — "
            "a state with no case behind it is a claim with no evidence"
        )


#: Every vector this firewall knows how to check, by filename.
#:
#: The firewall ENUMERATES what actually ships and dispatches through this table
#: rather than naming a fixed set, and it fails in BOTH directions — see
#: :func:`run`. Adding a vector to the package without adding it here is a hard
#: failure, by design.
VECTOR_CHECKS = {
    "mint_v1.json": [
        check_document_digest,
        check_kernel_signature,
        check_lineage_hash,
        check_vaid_id_equals_agent_id,
    ],
    "mint_pop_v1.json": [check_mint_pop],
    "chain_v1.json": [check_chain],
    "attestation_v1.json": [check_attestation],
    "scope_v1.json": [check_scope],
    "roundtrip_v1.json": [check_roundtrip],
    "verdict_v1.json": [check_verdict],
}


def bundled_vector_names() -> list[str]:
    """Every `.json` vector actually present in the INSTALLED package.

    Read from the package rather than from a list in this file: a list is what
    silently stops matching reality.
    """
    return sorted(
        p.name
        for p in files("vaid_mint").joinpath("vectors").iterdir()
        if p.name.endswith(".json")
    )


def run() -> dict:
    """Run the firewall over every vector the installed package ships.

    Fails in BOTH directions, because each direction hides a different defect:

    - a vector PRESENT in the package with no entry in :data:`VECTOR_CHECKS` is a
      hard failure. This is the defect that motivated the change: the firewall
      named a fixed set, so a release whose entire purpose was a new vector passed
      a check that never looked at it. Silence there is indistinguishable from
      coverage.
    - a vector NAMED in :data:`VECTOR_CHECKS` but ABSENT from the package is also a
      hard failure — a checker that quietly checks nothing is the same masked-green
      defect wearing the other hat.

    Note what this does and does not buy. It cannot verify a vector nobody has
    written a checker for; nothing can. What it guarantees is that such a vector
    cannot ship *quietly* — the firewall goes red until someone says what the
    vector means.
    """
    present = set(bundled_vector_names())
    known = set(VECTOR_CHECKS)

    unchecked = sorted(present - known)
    if unchecked:
        raise ConformanceError(
            "vector(s) ship in this package but no firewall check covers them: "
            + ", ".join(unchecked)
            + " — add a checker to VECTOR_CHECKS. A shipped-but-unchecked vector "
            "makes a PASS mean less than it appears to."
        )

    missing = sorted(known - present)
    if missing:
        raise ConformanceError(
            "firewall expects vector(s) that are not in this package: "
            + ", ".join(missing)
            + " — the packaging dropped them, or the check is stale."
        )

    results = {}
    for name in sorted(present):
        vector = load_named_vector(name)
        for check in VECTOR_CHECKS[name]:
            check(vector)
        results[name] = vector
    return results


# NOTE: this module deliberately contains no `test_` functions.
#
# It used to. They were never collected: pytest's default `python_files` glob is
# `test_*.py`, which `conformance.py` does not match, so five functions that looked
# like coverage were run by nothing in CI. That is the same defect this module now
# guards against — something that reads as checked and is not — one level up.
#
# The real tests live in `tests/test_packaged_conformance.py`, which pytest does
# collect and which CI runs.

def main() -> int:
    try:
        result = run()
    except ConformanceError as exc:
        print(f"CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    print(
        f"CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == {len(result)} frozen "
        "vector(s), byte-for-byte"
    )
    # Every vector is named with its digest. The COUNT is the point: a release
    # that adds a vector visibly adds a line here, so "did the firewall look at
    # the thing this release was about" is answerable from the output alone.
    for name in sorted(result):
        # A predicate vector pins verdicts, not bytes, so it has no digest to
        # report. Say what it DID check rather than printing a blank, so the
        # output still evidences that this vector was looked at.
        vector = result[name]
        if "digest_sha256_hex" in vector:
            detail = vector["digest_sha256_hex"]
        elif "cases" in vector:
            detail = f"{len(vector['cases'])} case(s) — predicate vector, no digest"
        else:
            detail = "(no digest)"
        print(f"  {name:22} {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
