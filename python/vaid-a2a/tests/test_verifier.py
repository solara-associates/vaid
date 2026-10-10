"""Unit tests for vaid_a2a.verifier behaviour not exercised by the shared
vectors in docs/a2a/v1/vectors/ — metadata presence/shape and the revocation-
unavailable fail-closed path."""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_a2a import (
    METADATA_CHAIN_KEY,
    METADATA_VAID_KEY,
    TrustedIssuersConfigError,
    VerifyCode,
    verify_a2a_message,
)
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import InMemoryRevocationList

_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x7]) * 32)
_PUBLIC = _KEY.public_key().public_bytes_raw()
_THUMBPRINT = kernel_key_thumbprint(_PUBLIC)
NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


TRUST_CONFIG = {
    "trustedIssuers": [{"trustDomain": "vaid.example", "kernelPublicKey": _b64url(_PUBLIC)}]
}


def _leaf(agent_id: str, scope: list[str]) -> dict:
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="t",
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=scope,
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=["read"],
        trust_domain="vaid.example",
        kernel_key_thumbprint=_THUMBPRINT,
    )
    signature = _KEY.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def test_no_vaid_passes_through_when_not_required() -> None:
    result = verify_a2a_message(
        {"metadata": {}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is True
    assert result.code is VerifyCode.NO_VAID


def test_no_vaid_denied_when_required() -> None:
    result = verify_a2a_message(
        {"metadata": {}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        require_vaid=True,
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.NO_VAID


def test_malformed_vaid_metadata_is_unparseable() -> None:
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: "not-an-object"}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.UNPARSEABLE


def test_malformed_chain_metadata_is_unparseable() -> None:
    leaf = _leaf(str(uuid.uuid4()), ["data.acme"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: leaf, METADATA_CHAIN_KEY: "not-a-list"}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.UNPARSEABLE


def test_revocation_unavailable_fails_closed() -> None:
    """An absent (never-populated) revocation store must deny, never be read
    as not-revoked — R.4.5's fail-closed default, exercised at the extension
    layer rather than only inside vaid_mint itself."""
    leaf = _leaf(str(uuid.uuid4()), ["data.acme"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: leaf}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList(),  # absent: never revoked into, never populated
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.INDETERMINATE


def test_no_requested_action_skips_scope_check() -> None:
    """``requested_action=None`` still skips the scope check — it is just no
    longer reachable by omission (GHSA-hfjh-v2x2-r58v finding 3)."""
    leaf = _leaf(str(uuid.uuid4()), ["data.acme.orders"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: leaf}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is True
    assert result.code is VerifyCode.ALLOWED


def test_requested_action_cannot_be_omitted() -> None:
    """GHSA-hfjh-v2x2-r58v finding 3: skipping the scope check must be an
    explicit, named decision (``requested_action=None``), never the default
    a caller reaches by forgetting the argument."""
    leaf = _leaf(str(uuid.uuid4()), ["data.acme.orders"])
    try:
        verify_a2a_message(  # type: ignore[call-arg]
            {"metadata": {METADATA_VAID_KEY: leaf}},
            trust_config=TRUST_CONFIG,
            revocation=InMemoryRevocationList.assume_nothing_revoked(),
            now=NOW,
        )
    except TypeError:
        pass
    else:
        raise AssertionError(
            "verify_a2a_message must not accept a call with requested_action omitted"
        )


# ── GHSA-hfjh-v2x2-r58v finding 1: trust domain bound to key ────────────────
#
# ``trust_config.trustedIssuers`` pairs a trust domain with a key (spec §2).
# Before this fix, `_build_key_resolver` kept only the key bytes, so a
# document signed by a trusted key but claiming a DIFFERENT trusted issuer's
# trust_domain passed. Two issuers below: A (0x42) bound to "vaid.example",
# B (0x99) bound to "other.example" — both legitimately trusted, neither
# compromised, which is what makes the gap exploitable without stealing
# anything.

_ISSUER_A_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
_ISSUER_A_PUBLIC = _ISSUER_A_KEY.public_key().public_bytes_raw()
_ISSUER_A_THUMBPRINT = kernel_key_thumbprint(_ISSUER_A_PUBLIC)
_ISSUER_A_DOMAIN = "vaid.example"

_ISSUER_B_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
_ISSUER_B_PUBLIC = _ISSUER_B_KEY.public_key().public_bytes_raw()
_ISSUER_B_THUMBPRINT = kernel_key_thumbprint(_ISSUER_B_PUBLIC)
_ISSUER_B_DOMAIN = "other.example"

_TWO_ISSUER_TRUST_CONFIG = {
    "trustedIssuers": [
        {"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
        {"trustDomain": _ISSUER_B_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_B_PUBLIC)},
    ]
}


def _signed_root(
    key: Ed25519PrivateKey, thumbprint: str, trust_domain: str, scope: list[str]
) -> dict:
    """A standalone (``parent_vaid=None``) VAID, signed by ``key`` but
    claiming ``trust_domain`` — independently of which domain ``key`` is
    actually bound to in a trust_config. That independence is the bug
    surface this section tests."""
    agent_id = str(uuid.uuid4())
    unsigned = build_unsigned_vaid_document(
        vaid_id=agent_id,
        agent_id=agent_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="t",
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=scope,
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=["read"],
        trust_domain=trust_domain,
        kernel_key_thumbprint=thumbprint,
    )
    signature = key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def test_root_signed_by_a_trusted_key_claiming_the_wrong_domain_is_denied() -> None:
    """THE REPORTED BUG. B's key is trusted — for "other.example" — but this
    root claims A's domain, "vaid.example". Before the fix, `KernelKeyMap`
    found B's key by thumbprint alone, authenticity checked out, and the
    request was allowed: a key trusted for one issuer's domain vouching for
    another issuer's identity."""
    root = _signed_root(_ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: root}},
        trust_config=_TWO_ISSUER_TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False, "a trusted key must not vouch for a domain it is not bound to"
    assert result.code is VerifyCode.ISSUER_MISMATCH


def test_root_signed_by_a_trusted_key_claiming_its_own_domain_is_allowed() -> None:
    """Honest control for the test above: same two-issuer trust_config, same
    key, the document claims the domain that key IS actually bound to."""
    root = _signed_root(_ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_B_DOMAIN, ["data.acme"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: root}},
        trust_config=_TWO_ISSUER_TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is True
    assert result.code is VerifyCode.ALLOWED


def test_cross_key_hop_claiming_the_parents_domain_is_denied() -> None:
    """The chain-hop shape of the same bug: a genuine cross-key delegation
    from A to B, consented by A's own attestation naming B's VAID as claiming
    A's trust_domain (an operator error on A's side, or a misled consent —
    either way, not a forged signature). The leaf IS signed by B, a trusted
    issuer, and the attestation machinery that already exists in
    `vaid_mint.chain` (consent, scope and capability containment) all checks
    out. Only the domain-to-key binding this fix adds catches that B's key is
    configured for "other.example", not A's "vaid.example"."""
    from vaid_mint.attestation import build_unsigned_attestation, canonical_attestation_signing_bytes

    root = _signed_root(_ISSUER_A_KEY, _ISSUER_A_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"])

    leaf_id = str(uuid.uuid4())
    leaf_unsigned = build_unsigned_vaid_document(
        vaid_id=leaf_id,
        agent_id=leaf_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="t",
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=root["vaid_id"],
        scope_boundary=["data.acme.sub"],
        lineage_hash=compute_lineage_hash(root["vaid_id"], leaf_id),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,  # claims A's domain; B's key is bound to _ISSUER_B_DOMAIN
        kernel_key_thumbprint=_ISSUER_B_THUMBPRINT,
    )
    leaf = {
        **leaf_unsigned,
        "kernel_signature": list(_ISSUER_B_KEY.sign(canonical_vaid_signing_bytes(leaf_unsigned))),
    }

    attestation_unsigned = build_unsigned_attestation(
        parent_vaid=root["vaid_id"],
        child_vaid=leaf_id,
        child_trust_domain=_ISSUER_A_DOMAIN,
        child_tenant_id="t",
        issued_at="2026-06-04T11:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        scope_boundary=["data.acme.sub"],
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    attestation = {
        **attestation_unsigned,
        "signature": list(
            _ISSUER_A_KEY.sign(canonical_attestation_signing_bytes(attestation_unsigned))
        ),
    }

    result = verify_a2a_message(
        {
            "metadata": {
                METADATA_VAID_KEY: leaf,
                METADATA_CHAIN_KEY: [root],
            }
        },
        trust_config=_TWO_ISSUER_TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    # The attestation is presented so this failure is isolated to the
    # trust-domain binding, not to a missing-consent INAUTHENTIC that would
    # pass for an unrelated reason.
    assert attestation["parent_vaid"] == root["vaid_id"]
    assert result.allowed is False
    assert result.code is VerifyCode.ISSUER_MISMATCH


# ── GHSA-hfjh-v2x2-r58v finding 4: the README example must actually allow ──


def test_readme_main_example_denies_as_indeterminate() -> None:
    """The README's main `## Use` snippet, run for real. It passes a plain
    ``InMemoryRevocationList()`` (never populated, therefore
    ``UNAVAILABLE``), by design: a valid request is refused as
    ``indeterminate`` until a real ``RevocationCheck`` is configured, so the
    copy-paste path stays closed rather than silently assuming nothing is
    revoked (GHSA-hfjh-v2x2-r58v follow-up finding D)."""
    leaf = _leaf(str(uuid.uuid4()), ["data.acme.orders"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: leaf}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList(),
        requested_action="data.acme.orders",
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.INDETERMINATE


def test_readme_local_demo_example_allows() -> None:
    """The README's "Local demo only, never production" snippet, run for
    real: with ``assume_nothing_revoked()`` the same otherwise-valid request
    allows, confirming the labelled demo path still works for its stated
    purpose (exercising signature/expiry/chain/scope with no revocation
    source wired up) even though the main example above no longer uses it."""
    leaf = _leaf(str(uuid.uuid4()), ["data.acme.orders"])
    result = verify_a2a_message(
        {"metadata": {METADATA_VAID_KEY: leaf}},
        trust_config=TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action="data.acme.orders",
        now=NOW,
    )
    assert result.allowed is True
    assert result.code is VerifyCode.ALLOWED


# ── GHSA-hfjh-v2x2-r58v, reviewer follow-up A: trustedIssuers config errors ─
#
# These two shapes must raise a clear configuration error at config-build
# time, not resolve to "no trusted key" or (worse) silently bind a key to
# whichever domain a later duplicate entry happened to list.


def test_duplicate_key_across_trust_domains_raises() -> None:
    """The same kernel public key listed twice, for two different domains.
    Must name the key (its thumbprint) and both domains in the error."""
    bad_config = {
        "trustedIssuers": [
            {"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
            {"trustDomain": _ISSUER_B_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
        ]
    }
    try:
        verify_a2a_message(
            {"metadata": {}},
            trust_config=bad_config,
            revocation=InMemoryRevocationList.assume_nothing_revoked(),
            requested_action=None,
            now=NOW,
        )
    except TrustedIssuersConfigError as exc:
        message = str(exc)
        assert _ISSUER_A_THUMBPRINT in message
        assert _ISSUER_A_DOMAIN in message
        assert _ISSUER_B_DOMAIN in message
    else:
        raise AssertionError("a duplicated kernel key across trust domains must raise")


def test_entry_missing_trust_domain_raises() -> None:
    """A ``trustedIssuers`` entry with a parseable key but no ``trustDomain``
    must raise, not be silently skipped: a key with no declared domain
    binds to nothing, which is a configuration mistake, not an absent key."""
    bad_config = {"trustedIssuers": [{"kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)}]}
    try:
        verify_a2a_message(
            {"metadata": {}},
            trust_config=bad_config,
            revocation=InMemoryRevocationList.assume_nothing_revoked(),
            requested_action=None,
            now=NOW,
        )
    except TrustedIssuersConfigError:
        pass
    else:
        raise AssertionError("a trustedIssuers entry missing trustDomain must raise")


# ── GHSA-hfjh-v2x2-r58v, reviewer follow-up C: deterministic check order ───


def test_bad_leaf_signature_wins_over_a_wrong_domain_chain_document() -> None:
    """Regression for the reviewer's mixed case: a leaf with a bad signature,
    presented alongside a chain document that is independently misbound to
    the wrong trust_domain. The documented order (spec §5) checks the leaf's
    own signature (step 1) before any presented chain document's binding
    (step 3), so this must deny INAUTHENTIC, never ISSUER_MISMATCH, which
    would mean the chain document's defect pre-empted the leaf's own."""
    leaf_id = str(uuid.uuid4())
    leaf_unsigned = build_unsigned_vaid_document(
        vaid_id=leaf_id,
        agent_id=leaf_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="t",
        issued_at="2026-06-04T12:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=["data.acme"],
        lineage_hash=compute_lineage_hash(None, leaf_id),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    # Signed by the WRONG key (B's), so the leaf's own signature does not
    # verify against A's key, a bad signature, not a misbound domain.
    bad_signature = _ISSUER_B_KEY.sign(canonical_vaid_signing_bytes(leaf_unsigned))
    leaf = {**leaf_unsigned, "kernel_signature": list(bad_signature)}

    # A standalone, independently misbound chain document: signed by B's
    # key (bound to other.example) while claiming A's domain. On its own
    # this denies ISSUER_MISMATCH (see test_root_signed_by_a_trusted_key_...
    # above); here it is presented only to prove it does NOT pre-empt the
    # leaf's own INAUTHENTIC result.
    wrong_domain_doc = _signed_root(
        _ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"]
    )

    result = verify_a2a_message(
        {
            "metadata": {
                METADATA_VAID_KEY: leaf,
                METADATA_CHAIN_KEY: [wrong_domain_doc],
            }
        },
        trust_config=_TWO_ISSUER_TRUST_CONFIG,
        revocation=InMemoryRevocationList.assume_nothing_revoked(),
        requested_action=None,
        now=NOW,
    )
    assert result.allowed is False
    assert result.code is VerifyCode.INAUTHENTIC
