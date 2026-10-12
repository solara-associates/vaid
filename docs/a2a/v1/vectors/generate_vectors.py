#!/usr/bin/env python3
"""Generate the deterministic A2A-extension test vectors in this directory.

Uses the existing vaid-mint reference tooling (``build_unsigned_vaid_document``,
``canonical_vaid_signing_bytes``, ``kernel_key_thumbprint``) and a single
fixed, test-only Ed25519 kernel key — the same pattern
``python/vaid-mint/tests/test_chain_verification.py`` uses to build authentic
documents under full control of ``vaid_id``, ``parent_vaid`` and timestamps, so
these vectors are reproducible byte-for-byte by re-running this script.

Run from the repo root:

    PYTHONPATH=python/vaid-mint python3 docs/a2a/v1/vectors/generate_vectors.py

Regenerating overwrites every ``*.json`` vector in this directory except
``README.md`` and this script.
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    prefix_entry,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint

VECTORS_DIR = Path(__file__).parent

# Test-only kernel key. Fixed seed byte, exactly as
# tests/test_chain_verification.py's LocalMint does, so every run of this
# script signs with the identical key and produces identical bytes.
_KERNEL_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
KERNEL_PUBLIC_KEY = _KERNEL_KEY.public_key().public_bytes_raw()
KERNEL_KEY_THUMBPRINT = kernel_key_thumbprint(KERNEL_PUBLIC_KEY)

# A second, untrusted kernel key — used only for the "unknown root key" vector,
# to produce a document that is internally well-formed and self-consistent but
# signed by a key no verifier in these vectors is told to trust.
_UNTRUSTED_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
UNTRUSTED_PUBLIC_KEY = _UNTRUSTED_KEY.public_key().public_bytes_raw()
UNTRUSTED_KEY_THUMBPRINT = kernel_key_thumbprint(UNTRUSTED_PUBLIC_KEY)

# RFC 2606 reserved domain — a vector-publishing suite must not name a
# bindable one (matches the reasoning in verdict_v1 and test_chain_verification).
TRUST_DOMAIN = "vaid.example"

# A SECOND trust domain, for vector 12. Also under the reserved .example TLD.
# Vectors 01-11 never name it: it exists so one vector can configure two
# legitimately trusted issuers and show that neither one's key may vouch for
# the other one's domain.
OTHER_TRUST_DOMAIN = "other.example"
TENANT = "acme"

# Fixed, far-future-by-convention timestamps (see test_chain_verification.py's
# own note on this): these vectors are pinned by DISTANCE, not by a clock, so
# "expired" vectors use an explicit past date instead of depending on wall time.
ISSUED_AT = "2026-06-04T12:00:00Z"
FAR_FUTURE = "2999-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"

# The instant every vector must be verified at (test_vectors.py's own fixed
# "now", carried into the vector itself rather than left implicit in the test
# harness). Between ISSUED_AT and FAR_FUTURE, and after PAST, so it changes no
# existing vector's expected_result: a verifier evaluating any of these
# vectors at any other instant may disagree with the recorded expectation.
VERIFICATION_TIME = "2026-07-01T00:00:00Z"

# Placeholder agent public key bytes (DER). Not used for signature verification
# by any check these vectors exercise; held fixed for byte-reproducibility.
AGENT_PUBLIC_KEY_DER = list(range(32))


def vid(n: int) -> str:
    """A stable VAID id from a small integer, so vectors can be described by
    position in a chain (root=1, mid=2, leaf=3, ...) rather than by a random
    UUID that would differ on every regeneration."""
    return str(uuid.UUID(int=n))


def sign(
    key: Ed25519PrivateKey,
    thumbprint: str,
    *,
    agent_id: str,
    parent_vaid: str | None,
    scope: list[str] | None = None,
    raw_scope_boundary: list[dict] | None = None,
    caps: list[str],
    expires_at: str = FAR_FUTURE,
    issued_at: str = ISSUED_AT,
    trust_domain: str = TRUST_DOMAIN,
    tenant: str = TENANT,
    extra_fields: dict | None = None,
) -> dict:
    # ``scope`` is written as bare strings at every call site below and typed
    # HERE, once. Since ADR-0009 a boundary entry is ``{"kind", "value"}``,
    # and v4 defines exactly one kind, so every entry built this way is a
    # ``prefix``. ``raw_scope_boundary`` is the escape hatch vectors 13 and 14
    # need: an entry of a kind this repo's own producers never emit (13), or
    # extra top-level document fields that are not scope_boundary at all (14)
    # — neither is reachable by typing bare strings as ``prefix`` entries.
    if raw_scope_boundary is not None:
        if scope is not None:
            raise ValueError("pass scope or raw_scope_boundary, not both")
        scope_boundary = raw_scope_boundary
    else:
        scope_boundary = [prefix_entry(value) for value in (scope or [])]
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="a2a-test-agent",
        version="1.0.0",
        tenant_id=tenant,
        issued_at=issued_at,
        expires_at=expires_at,
        public_key_der=AGENT_PUBLIC_KEY_DER,
        parent_vaid=parent_vaid,
        scope_boundary=scope_boundary,
        lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
        capability_set=caps,
        trust_domain=trust_domain,
        kernel_key_thumbprint=thumbprint,
    )
    if extra_fields:
        # Added BEFORE signing, so the extra member is inside the signed
        # bytes (ADR-0006): the document is authentic WITH the field present,
        # not merely tolerated as noise outside the signature.
        unsigned = {**unsigned, **extra_fields}
    signature = key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def kernel_sign(**kwargs) -> dict:
    return sign(_KERNEL_KEY, KERNEL_KEY_THUMBPRINT, **kwargs)


#: docs/a2a/v1/vectors -> docs/a2a/v1 -> docs/a2a -> docs -> repo root. One
#: level deeper than before the v1 move, so this constant is named rather
#: than another bare ``.parent`` chain that would need to be recounted by eye
#: on the next move.
_REPO_ROOT = VECTORS_DIR.parent.parent.parent.parent


def write_vector(name: str, obj: dict) -> None:
    path = VECTORS_DIR / f"{name}.json"
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n")
    print(f"wrote {path.relative_to(_REPO_ROOT)}")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def main() -> None:
    trust_config = {
        "trustedIssuers": [
            {"trustDomain": TRUST_DOMAIN, "kernelPublicKey": b64url(KERNEL_PUBLIC_KEY)}
        ]
    }

    # ── 1. Valid two-hop chain, action in scope (pass) ──────────────────────
    root = kernel_sign(
        agent_id=vid(1), parent_vaid=None,
        scope=["data.acme"], caps=["read", "write"],
    )
    leaf = kernel_sign(
        agent_id=vid(2), parent_vaid=vid(1),
        scope=["data.acme.orders"], caps=["read"],
    )
    write_vector("01-valid-two-hop-chain", {
        "description": (
            "A root VAID and one attenuated child, both signed by the trusted "
            "kernel key, child scope/caps strictly within the parent's, leaf "
            "unexpired, requested action within the leaf's scope, nothing "
            "revoked."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders",
        "inputs": {"leaf": leaf, "chain": [root]},
        "revoked_vaid_ids": [],
        "expected_result": "pass",
        "expected_error_code": None,
    })

    # ── 2. Child scope wider than parent (fail: NOT_ATTENUATED) ─────────────
    root2 = kernel_sign(
        agent_id=vid(3), parent_vaid=None,
        scope=["data.acme.orders"], caps=["read"],
    )
    wide_child = kernel_sign(
        agent_id=vid(4), parent_vaid=vid(3),
        # Wider than the parent: parent only holds "data.acme.orders".
        scope=["data.acme"], caps=["read"],
    )
    write_vector("02-child-scope-wider-than-parent", {
        "description": (
            "The child's scope_boundary ('data.acme') is not contained by the "
            "parent's ('data.acme.orders') — a child claiming authority its "
            "parent never held."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders",
        "inputs": {"leaf": wide_child, "chain": [root2]},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "not_attenuated",
    })

    # ── 3. Expired leaf (fail: EXPIRED) ──────────────────────────────────────
    root3 = kernel_sign(
        agent_id=vid(5), parent_vaid=None,
        scope=["data.acme"], caps=["read"],
    )
    expired_leaf = kernel_sign(
        agent_id=vid(6), parent_vaid=vid(5),
        scope=["data.acme.orders"], caps=["read"],
        expires_at=PAST,
    )
    write_vector("03-expired-leaf", {
        "description": (
            "The leaf's own expires_at (2020-01-01) has passed at verification "
            "time. Authentic and otherwise well-attenuated; checked after "
            "authenticity and before revocation, per the extension's verification "
            "order."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders",
        "inputs": {"leaf": expired_leaf, "chain": [root3]},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "expired",
    })

    # ── 4. Revoked middle link (fail: REVOKED) ───────────────────────────────
    root4 = kernel_sign(
        agent_id=vid(7), parent_vaid=None,
        scope=["data.acme"], caps=["read", "write"],
    )
    mid4 = kernel_sign(
        agent_id=vid(8), parent_vaid=vid(7),
        scope=["data.acme.orders"], caps=["read", "write"],
    )
    leaf4 = kernel_sign(
        agent_id=vid(9), parent_vaid=vid(8),
        scope=["data.acme.orders.line_items"], caps=["read"],
    )
    write_vector("04-revoked-middle-link", {
        "description": (
            "A three-hop chain (root -> mid -> leaf) that is fully authentic and "
            "attenuated, but the MIDDLE link (hop 2) is revoked. Per R.4.4, a "
            "VAID is revoked if any VAID in its lineage is; the leaf itself was "
            "never revoked."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders.line_items",
        "inputs": {"leaf": leaf4, "chain": [root4, mid4]},
        "revoked_vaid_ids": [vid(8)],
        "expected_result": "fail",
        "expected_error_code": "revoked",
    })

    # ── 5. Valid chain, action outside leaf scope (fail) ─────────────────────
    root5 = kernel_sign(
        agent_id=vid(10), parent_vaid=None,
        scope=["data.acme"], caps=["read"],
    )
    leaf5 = kernel_sign(
        agent_id=vid(11), parent_vaid=vid(10),
        scope=["data.acme.orders"], caps=["read"],
    )
    write_vector("05-action-outside-leaf-scope", {
        "description": (
            "The chain is authentic, unexpired, unrevoked, and properly "
            "attenuated — but the REQUESTED ACTION ('data.acme.customers') is "
            "outside the leaf's own scope_boundary ('data.acme.orders'). A "
            "well-attenuated chain does not imply the leaf's scope covers "
            "whatever the message is actually asking to do."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.customers",
        "inputs": {"leaf": leaf5, "chain": [root5]},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "out_of_scope",
    })

    # ── 6. Unknown root key (fail: issuer not trusted) ───────────────────────
    root6 = sign(
        _UNTRUSTED_KEY, UNTRUSTED_KEY_THUMBPRINT,
        agent_id=vid(12), parent_vaid=None,
        scope=["data.acme"], caps=["read"],
    )
    leaf6 = sign(
        _UNTRUSTED_KEY, UNTRUSTED_KEY_THUMBPRINT,
        agent_id=vid(13), parent_vaid=vid(12),
        scope=["data.acme.orders"], caps=["read"],
    )
    write_vector("06-unknown-root-key", {
        "description": (
            "Internally consistent and self-signed chain, but signed by a "
            "kernel key this verifier's trust_config does not list. The "
            "verifier's trustedIssuers contains only the vector-01..05 kernel "
            "key; this chain's thumbprint is not in it, so it is not a 'the "
            "signature failed' case but a 'nobody told me to trust this issuer' "
            "case — both must be refused, but a verifier's audit trail SHOULD "
            "name this one as an untrusted issuer, not a corrupted signature."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders",
        "inputs": {"leaf": leaf6, "chain": [root6]},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "issuer_mismatch",
        "note": (
            "kernel_key_thumbprint on these documents: " + UNTRUSTED_KEY_THUMBPRINT +
            " (not in trust_config.trustedIssuers above, which lists only the "
            "vector 01-05 key)"
        ),
    })

    # 7 to 11: attenuation negatives. Each is a two-hop chain under the
    # trusted kernel key where only the child differs from a valid chain, so
    # step 4 is the only check that can refuse it.
    attenuation_cases = [
        (
            "07-sibling-scope-child",
            "The child's scope ('data.acme-secret') shares a text prefix with "
            "the parent's ('data.acme') but is a sibling, not a descendant "
            "(scope.md S.3: bare prefix matching is not containment).",
            {"scope": ["data.acme"], "caps": ["read"]},
            {"scope": ["data.acme-secret"], "caps": ["read"]},
            "data.acme-secret",
        ),
        (
            "08-capability-not-in-parent",
            "The child holds capability 'write' that its parent does not hold.",
            {"scope": ["data.acme"], "caps": ["read"]},
            {"scope": ["data.acme.orders"], "caps": ["read", "write"]},
            "data.acme.orders",
        ),
        (
            "09-tenant-changed",
            "The child's tenant_id ('globex') differs from its parent's "
            "('acme').",
            {"scope": ["data.acme"], "caps": ["read"]},
            {"scope": ["data.acme.orders"], "caps": ["read"], "tenant": "globex"},
            "data.acme.orders",
        ),
        (
            "10-child-outlives-parent",
            "The child's expires_at (2999-01-01) is later than its parent's "
            "(2998-01-01). Both are in the future, so only expiry containment "
            "(ADR-0007) refuses it.",
            {"scope": ["data.acme"], "caps": ["read"], "expires_at": "2998-01-01T00:00:00Z"},
            {"scope": ["data.acme.orders"], "caps": ["read"]},
            "data.acme.orders",
        ),
        (
            "11-unrestricted-child",
            "The child's scope_boundary is [] (unrestricted, encoding.md E.7) "
            "under a parent restricted to 'data.acme'.",
            {"scope": ["data.acme"], "caps": ["read"]},
            {"scope": [], "caps": ["read"]},
            "data.acme.orders",
        ),
    ]
    for i, (name, description, parent_kw, child_kw, action) in enumerate(attenuation_cases):
        parent_id, child_id = vid(14 + 2 * i), vid(15 + 2 * i)
        parent = kernel_sign(agent_id=parent_id, parent_vaid=None, **parent_kw)
        child = kernel_sign(agent_id=child_id, parent_vaid=parent_id, **child_kw)
        write_vector(name, {
            "description": description,
            "trust_config": trust_config,
            "verification_time": VERIFICATION_TIME,
            "requested_action": action,
            "inputs": {"leaf": child, "chain": [parent]},
            "revoked_vaid_ids": [],
            "expected_result": "fail",
            "expected_error_code": "not_attenuated",
        })

    # ── 12. Trust domain not bound to the signing key (fail: ISSUER_MISMATCH) ──
    #
    # GHSA-hfjh-v2x2-r58v. The only vector whose trust_config lists TWO
    # issuers, and the reason it has to: the defect is invisible with one.
    #
    # Both keys here are trusted. The 0x42 key is trusted for "vaid.example";
    # the 0x99 key is trusted for "other.example". Neither is compromised and
    # no signature is forged. The document below is signed by the 0x99 key,
    # correctly, and claims "vaid.example" — the domain the OTHER trusted
    # issuer's key is bound to.
    #
    # A verifier that resolves a kernel key by kernel_key_thumbprint alone
    # finds the 0x99 key, checks the signature against it, and PASSES: one
    # issuer's key vouching for another issuer's identity. Refusing it
    # requires carrying the pairing trustedIssuers declares (spec §2.1) and
    # comparing the claimed trust_domain against the domain bound to the key
    # that signed the document, never the other way round (spec §5 step 1).
    #
    # Note which key signs this and which domain it claims: swapping either
    # makes the vector pass, so a verifier cannot satisfy it by refusing
    # everything. Vector 01 is the standing positive control for that.
    two_issuer_trust_config = {
        "trustedIssuers": [
            {"trustDomain": TRUST_DOMAIN, "kernelPublicKey": b64url(KERNEL_PUBLIC_KEY)},
            {
                "trustDomain": OTHER_TRUST_DOMAIN,
                "kernelPublicKey": b64url(UNTRUSTED_PUBLIC_KEY),
            },
        ]
    }
    misbound_root = sign(
        _UNTRUSTED_KEY, UNTRUSTED_KEY_THUMBPRINT,
        agent_id=vid(24), parent_vaid=None,
        scope=["data.acme"], caps=["read"],
        # Claims the domain the 0x42 key is bound to, while signed by 0x99.
        trust_domain=TRUST_DOMAIN,
    )
    write_vector("12-trust-domain-not-bound-to-signing-key", {
        "description": (
            "Two legitimately trusted issuers, neither compromised. The leaf is "
            "signed, correctly, by the kernel key trusted for 'other.example', "
            "but claims trust_domain 'vaid.example' - the domain the OTHER "
            "trusted issuer's key is bound to. A verifier that resolves the "
            "kernel key by kernel_key_thumbprint alone finds a trusted key, "
            "verifies the signature against it and passes, which is one "
            "issuer's key vouching for another issuer's identity "
            "(GHSA-hfjh-v2x2-r58v). A key is trusted for the trust domain "
            "trustedIssuers pairs it with, never for a domain a document "
            "claims, so this must be refused as issuer_mismatch - the same "
            "code as an untrusted issuer, because in the domain it is "
            "claiming that is exactly what it is."
        ),
        "trust_config": two_issuer_trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme",
        "inputs": {"leaf": misbound_root, "chain": []},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "issuer_mismatch",
        "note": (
            "This leaf's kernel_key_thumbprint is " + UNTRUSTED_KEY_THUMBPRINT +
            ", which IS in trust_config.trustedIssuers above - bound to '" +
            OTHER_TRUST_DOMAIN + "'. Unlike vector 06, the issuer is trusted; "
            "the mismatch is between the domain this document claims and the "
            "domain its signing key is trusted for. The two vectors must not "
            "be collapsed: 06 is an unknown key, 12 is a known key used "
            "outside the one domain it was trusted for."
        ),
    })

    # ── 13. Forward compatibility: an unrecognised scope_boundary kind ──────
    #
    # a2aproject/A2A#2028 fixture request #1. A hop carries a well-formed
    # scope entry of a kind no verifier here recognises, alongside an entry
    # that DOES match the requested action. Per spec §5 step 2a / ADR-0009
    # S.10, a verifier MUST refuse the WHOLE boundary rather than fall back
    # to the entries it can read, because an unrecognised kind can only ever
    # narrow what the signer granted. The matching "prefix" entry is there
    # on purpose, mirroring
    # test_verifier.py's test_one_unreadable_entry_refuses_a_boundary_that_also_matches
    # — a verifier that evaluates the union and stops at the first match
    # never reaches the unreadable entry, and would wrongly ALLOW this
    # vector.
    #
    # A ROOT leaf (no parent, no presented chain) ON PURPOSE, not a two-hop
    # chain: per-hop attenuation (step 4) already refuses an unreadable
    # boundary on EITHER side of a hop, but only where there IS a parent to
    # attenuate against. A root reaches step 5 with no attenuation check ever
    # having run over its own boundary, so a root is the one shape that
    # isolates step 2a as the ONLY thing standing between this scope entry
    # and an ALLOW — exactly the gap spec §5 step 2a's own rationale names
    # ("a root leaf carrying an unrecognised kind would otherwise reach step
    # 5 unchecked"). A two-hop version of this vector would also be refused
    # by attenuation over the child's boundary, which would make it a weaker
    # positive control: a verifier that skipped step 2a entirely could still
    # pass a two-hop version of this vector for a reason that is not the one
    # under test.
    leaf13 = kernel_sign(
        agent_id=vid(25), parent_vaid=None,
        raw_scope_boundary=[
            prefix_entry("data.acme.orders"),
            {"kind": "amount_limit", "value": {"max": 100}},
        ],
        caps=["read"],
    )
    write_vector("13-unknown-scope-kind-future-compat", {
        "description": (
            "A root leaf (no parent, no presented chain) whose scope_boundary "
            "carries two entries: a 'prefix' entry ('data.acme.orders') that "
            "matches the requested action, and an 'amount_limit' entry of a "
            "kind no verifier here recognises. The document is otherwise "
            "authentic and unexpired. Per ADR-0009 S.10 one unreadable entry "
            "refuses the WHOLE boundary even though another entry in it would "
            "have matched: the unrecognised kind can only narrow what the "
            "signer meant, so skipping it would grant authority the signer "
            "withheld. It is a root ON PURPOSE: per-hop attenuation (spec §5 "
            "step 4) only runs where there is a parent, so a root is the one "
            "shape where step 2a is the ONLY check standing between this "
            "boundary and an ALLOW, which is exactly why spec §5 places step "
            "2a ahead of step 4 rather than relying on it. This is a refusal "
            "over an AUTHENTIC document (the entry is well formed, only its "
            "kind is unknown), never a parse failure — reporting it as "
            "malformed bytes would accuse a correctly signed future-version "
            "credential of being forged."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.orders",
        "inputs": {"leaf": leaf13, "chain": []},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "unknown_scope_kind",
    })

    # ── 14. No privilege via an unused field ─────────────────────────────────
    #
    # a2aproject/A2A#2028 fixture request #2. The leaf is correctly signed
    # OVER a top-level field, "x_elevated_scope_boundary", that it carries
    # alongside its real "scope_boundary" — additive and preserved per
    # ADR-0006, since an unrecognised DOCUMENT member sits outside every
    # predicate a verifier computes (unlike an unrecognised member INSIDE a
    # boundary entry, which S.11 refuses outright: that asymmetry is the
    # whole point of ADR-0009). The extra field is shaped exactly like what a
    # careless verifier might mistake for the real boundary: a wider
    # scope_boundary that WOULD cover the requested action if read.
    #
    # The real scope_boundary ('data.acme.orders', same on root and leaf — a
    # no-op attenuation) does not cover the requested action
    # ('data.acme.customers'). The correctly signed, authentic, properly
    # attenuated chain is therefore refused for exactly the reason it would
    # be refused with the extra field absent: out_of_scope. The extra field
    # changes nothing, because nothing in the specified verification order
    # ever reads it. A verifier that granted anything from
    # "x_elevated_scope_boundary" — treated it as an override, a fallback, or
    # a second boundary to union against — would wrongly ALLOW this vector.
    root14 = kernel_sign(
        agent_id=vid(27), parent_vaid=None,
        scope=["data.acme.orders"], caps=["read"],
    )
    leaf14 = kernel_sign(
        agent_id=vid(28), parent_vaid=vid(27),
        scope=["data.acme.orders"], caps=["read"],
        extra_fields={
            "x_elevated_scope_boundary": [prefix_entry("data.acme")],
        },
    )
    write_vector("14-no-privilege-via-unused-field", {
        "description": (
            "The leaf carries an extra top-level field, "
            "'x_elevated_scope_boundary', signed over (authentic, not "
            "inauthentic) and shaped like a WIDER scope_boundary "
            "('data.acme' instead of the real 'data.acme.orders'). The real "
            "scope_boundary is unchanged and properly attenuated from the "
            "parent. The requested action ('data.acme.customers') is outside "
            "the real scope_boundary but inside the fabricated one. Nothing "
            "in spec §5's verification order reads any field but "
            "scope_boundary for this check (ADR-0006: an unrecognised "
            "top-level member is preserved and ignored, never promoted into "
            "a predicate), so the correct verdict is identical to the same "
            "chain with the extra field removed: fail, out_of_scope. A "
            "verifier that read the extra field as an override, a fallback, "
            "or a second scope to union against would ALLOW this request, "
            "granting privilege the signer never put in scope_boundary."
        ),
        "trust_config": trust_config,
        "verification_time": VERIFICATION_TIME,
        "requested_action": "data.acme.customers",
        "inputs": {"leaf": leaf14, "chain": [root14]},
        "revoked_vaid_ids": [],
        "expected_result": "fail",
        "expected_error_code": "out_of_scope",
    })

    print(f"\nkernel public key (vectors 01-05): base64url {b64url(KERNEL_PUBLIC_KEY)}")
    print(f"  derived thumbprint: {KERNEL_KEY_THUMBPRINT}")
    print(f"second key (vectors 06, 12):      base64url {b64url(UNTRUSTED_PUBLIC_KEY)}")
    print(f"  derived thumbprint: {UNTRUSTED_KEY_THUMBPRINT}")


if __name__ == "__main__":
    main()
