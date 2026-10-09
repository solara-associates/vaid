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
    scope: list[str],
    caps: list[str],
    expires_at: str = FAR_FUTURE,
    issued_at: str = ISSUED_AT,
    trust_domain: str = TRUST_DOMAIN,
    tenant: str = TENANT,
) -> dict:
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
        scope_boundary=scope,
        lineage_hash=compute_lineage_hash(parent_vaid, agent_id),
        capability_set=caps,
        trust_domain=trust_domain,
        kernel_key_thumbprint=thumbprint,
    )
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

    print(f"\nkernel public key (vectors 01-05): base64url {b64url(KERNEL_PUBLIC_KEY)}")
    print(f"  derived thumbprint: {KERNEL_KEY_THUMBPRINT}")
    print(f"untrusted public key (vector 06):  base64url {b64url(UNTRUSTED_PUBLIC_KEY)}")
    print(f"  derived thumbprint: {UNTRUSTED_KEY_THUMBPRINT}")


if __name__ == "__main__":
    main()
