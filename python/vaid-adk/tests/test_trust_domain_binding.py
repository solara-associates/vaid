"""GHSA-hfjh-v2x2-r58v in ``vaid_adk``: a trusted kernel key must only vouch
for the trust domain it is configured for.

``vaid_adk._verify.verify_presentation`` resolved the kernel key by thumbprint
alone and never compared the resolved key's configured trust domain against
what the document claimed. A document signed by a trusted key but naming a
DIFFERENT trusted issuer's ``trust_domain`` therefore passed: one issuer's key
vouching for another issuer's identity, with no forged signature and no stolen
key anywhere in the attack. That is the same defect the merged
``python/vaid-a2a`` fix closed, and these tests mirror its three ``td_cases``
against this package's own entry points.

Two issuers throughout: A (seed ``0x42``) bound to ``"vaid.example"``, B (seed
``0x99``) bound to ``"other.example"`` — both legitimately trusted, neither
compromised, which is what makes the gap exploitable without stealing anything.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_adk import (
    ToolAuthorization,
    TrustedIssuers,
    TrustedIssuersConfigError,
    VaidAuthPlugin,
    VaidPresentation,
    VerifyCode,
    verify_presentation,
)
from vaid_mint.attestation import (
    build_unsigned_attestation,
    canonical_attestation_signing_bytes,
)
from vaid_mint.chain import KernelKeyMap, SingleKernelKey
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
    prefix_entry,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint
from vaid_mint.revocation import InMemoryRevocationList

NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)

_ISSUER_A_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
_ISSUER_A_PUBLIC = _ISSUER_A_KEY.public_key().public_bytes_raw()
_ISSUER_A_THUMBPRINT = kernel_key_thumbprint(_ISSUER_A_PUBLIC)
_ISSUER_A_DOMAIN = "vaid.example"

_ISSUER_B_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
_ISSUER_B_PUBLIC = _ISSUER_B_KEY.public_key().public_bytes_raw()
_ISSUER_B_THUMBPRINT = kernel_key_thumbprint(_ISSUER_B_PUBLIC)
_ISSUER_B_DOMAIN = "other.example"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


#: Both issuers trusted, each for its own domain. The configuration every
#: binding test below runs against, so no denial can come from an issuer
#: simply being unknown.
TWO_ISSUERS = TrustedIssuers(
    [
        {"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
        {"trustDomain": _ISSUER_B_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_B_PUBLIC)},
    ]
)

_NOTHING_REVOKED = InMemoryRevocationList.assume_nothing_revoked


def _signed_root(
    key: Ed25519PrivateKey, thumbprint: str, trust_domain: str, scope: list[str]
) -> dict:
    """A standalone (``parent_vaid=None``) VAID, signed by ``key`` but claiming
    ``trust_domain`` — independently of which domain ``key`` is actually bound
    to in a trust configuration. That independence is the bug surface here."""
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
        scope_boundary=[prefix_entry(v) for v in scope],
        lineage_hash=compute_lineage_hash(None, agent_id),
        capability_set=["read"],
        trust_domain=trust_domain,
        kernel_key_thumbprint=thumbprint,
    )
    signature = key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def _verify(presentation: VaidPresentation, *, keys: object = TWO_ISSUERS):
    return verify_presentation(
        presentation,
        keys=keys,
        revocation=_NOTHING_REVOKED(),
        now=NOW,
    )


# ── td_case T1: the reported bug ───────────────────────────────────────────


def test_t1_root_signed_by_a_trusted_key_claiming_the_wrong_domain_is_denied() -> None:
    """THE REPORTED BUG. B's key is trusted — for ``"other.example"`` — but
    this root claims A's domain, ``"vaid.example"``. Before the fix the
    resolver found B's key by thumbprint alone, authenticity checked out, and
    the agent was allowed to run and to call tools."""
    root = _signed_root(_ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"])
    result = _verify(VaidPresentation(leaf=root))
    assert result.allowed is False, "a trusted key must not vouch for a domain it is not bound to"
    assert result.code is VerifyCode.ISSUER_MISMATCH


# ── td_case T2: the honest control ─────────────────────────────────────────


def test_t2_root_signed_by_a_trusted_key_claiming_its_own_domain_is_allowed() -> None:
    """Honest control for T1: same trust configuration, same key, and the
    document claims the domain that key IS bound to. Without this, T1 would
    pass just as well against a verifier that refused everything."""
    root = _signed_root(_ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_B_DOMAIN, ["data.acme"])
    result = _verify(VaidPresentation(leaf=root))
    assert result.allowed is True, result.reason
    assert result.code is VerifyCode.ALLOWED


# ── td_case T3: the chain-hop shape of the same bug ────────────────────────


def test_t3_cross_key_hop_claiming_the_parents_domain_is_denied() -> None:
    """A genuine cross-key delegation from A to B, consented by A's own
    attestation naming B's VAID as claiming A's trust_domain (an operator
    error on A's side, or a misled consent — either way, not a forged
    signature). The leaf IS signed by B, a trusted issuer, and the consent,
    scope and capability containment ``vaid_mint.chain`` already enforces all
    check out. Only the domain-to-key binding catches that B's key is
    configured for ``"other.example"``, not A's ``"vaid.example"``."""
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
        scope_boundary=[prefix_entry("data.acme.sub")],
        lineage_hash=compute_lineage_hash(root["vaid_id"], leaf_id),
        capability_set=["read"],
        # Claims A's domain; B's key is bound to _ISSUER_B_DOMAIN.
        trust_domain=_ISSUER_A_DOMAIN,
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
        scope_boundary=[prefix_entry("data.acme.sub")],
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
    # Asserted so this failure is isolated to the trust-domain binding and is
    # not a missing-consent INAUTHENTIC passing for an unrelated reason.
    assert attestation["parent_vaid"] == root["vaid_id"]

    result = _verify(VaidPresentation(leaf=leaf, chain=(root,)))
    assert result.allowed is False
    assert result.code is VerifyCode.ISSUER_MISMATCH


# ── the step-3 half: a misbound ANCESTOR, with a clean leaf ────────────────


def test_misbound_ancestor_is_denied_even_when_the_leaf_is_clean() -> None:
    """T1/T3 both fail on the leaf's own binding (step 1). This pins the
    other half: the leaf is honestly bound, and a presented ancestor is the
    document claiming a domain its signing key is not bound to."""
    misbound_ancestor = _signed_root(
        _ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"]
    )
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
        parent_vaid=misbound_ancestor["vaid_id"],
        scope_boundary=[prefix_entry("data.acme.sub")],
        lineage_hash=compute_lineage_hash(misbound_ancestor["vaid_id"], leaf_id),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    leaf = {
        **leaf_unsigned,
        "kernel_signature": list(_ISSUER_A_KEY.sign(canonical_vaid_signing_bytes(leaf_unsigned))),
    }

    result = _verify(VaidPresentation(leaf=leaf, chain=(misbound_ancestor,)))
    assert result.allowed is False
    assert result.code is VerifyCode.ISSUER_MISMATCH
    assert misbound_ancestor["vaid_id"] in result.reason


# ── check order: the leaf's own verdict is never pre-empted ────────────────


def _bad_signature_leaf() -> dict:
    """A leaf claiming A's domain and A's thumbprint — so its binding is
    correct — but signed by B's key, so only its signature is wrong."""
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
        scope_boundary=[prefix_entry("data.acme")],
        lineage_hash=compute_lineage_hash(None, leaf_id),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    bad_signature = _ISSUER_B_KEY.sign(canonical_vaid_signing_bytes(leaf_unsigned))
    return {**leaf_unsigned, "kernel_signature": list(bad_signature)}


def test_bad_leaf_signature_wins_over_a_wrong_domain_chain_document() -> None:
    """The mixed case: a leaf with a bad signature presented alongside an
    ancestor that is independently misbound. Step 1 reaches its verdict on
    the leaf alone before step 3 looks at any presented document, so this
    must deny INAUTHENTIC, never ISSUER_MISMATCH — two verifiers given this
    input must not disagree about why they refused it."""
    result = _verify(
        VaidPresentation(
            leaf=_bad_signature_leaf(),
            chain=(
                _signed_root(
                    _ISSUER_B_KEY, _ISSUER_B_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"]
                ),
            ),
        )
    )
    assert result.allowed is False
    assert result.code is VerifyCode.INAUTHENTIC


def test_bad_leaf_signature_with_empty_chain_is_inauthentic() -> None:
    """Control for the test above: the same leaf with nothing else presented
    reaches the same verdict. There being another document to examine does
    not change the leaf's own result, in either direction."""
    result = _verify(VaidPresentation(leaf=_bad_signature_leaf()))
    assert result.allowed is False
    assert result.code is VerifyCode.INAUTHENTIC


def test_unknown_thumbprint_ancestor_is_left_to_chain_verification() -> None:
    """An ancestor whose thumbprint resolves to NO trusted key has no bound
    domain to compare against, so the binding check says nothing about it and
    leaves it to chain verification, which refuses it on its own terms. Pinned
    so a future change cannot turn "no domain to compare" into an accidental
    pass."""
    untrusted_key = Ed25519PrivateKey.from_private_bytes(bytes([0x07]) * 32)
    untrusted_public = untrusted_key.public_key().public_bytes_raw()
    stranger = _signed_root(
        untrusted_key,
        kernel_key_thumbprint(untrusted_public),
        _ISSUER_A_DOMAIN,
        ["data.acme"],
    )
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
        parent_vaid=stranger["vaid_id"],
        scope_boundary=[prefix_entry("data.acme.sub")],
        lineage_hash=compute_lineage_hash(stranger["vaid_id"], leaf_id),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    leaf = {
        **leaf_unsigned,
        "kernel_signature": list(_ISSUER_A_KEY.sign(canonical_vaid_signing_bytes(leaf_unsigned))),
    }
    result = _verify(VaidPresentation(leaf=leaf, chain=(stranger,)))
    assert result.allowed is False
    assert result.code is not VerifyCode.ALLOWED


# ── a resolver that cannot bind a domain is refused, at configuration time ──
#
# The negative test for the control itself. A bare vaid_mint resolver answers
# resolve_key and nothing else, so a verifier built on one cannot compare any
# document's claimed trust_domain against anything. Skipping the binding check
# for such a resolver would leave the whole defect open by omission, which is
# why it is refused outright rather than tolerated.


def test_bare_kernel_key_map_is_refused_by_verify_presentation() -> None:
    try:
        verify_presentation(
            VaidPresentation(leaf=_signed_root(
                _ISSUER_A_KEY, _ISSUER_A_THUMBPRINT, _ISSUER_A_DOMAIN, ["data.acme"]
            )),
            keys=KernelKeyMap([_ISSUER_A_PUBLIC]),
            revocation=_NOTHING_REVOKED(),
            now=NOW,
        )
    except TrustedIssuersConfigError as exc:
        assert "trust_domain_for" in str(exc)
        return
    raise AssertionError("a resolver with no domain binding must raise, not verify")


def test_bare_single_kernel_key_is_refused_with_no_presentation_at_all() -> None:
    """Raised before anything about the presentation is looked at: a
    configuration defect is a property of the caller, not of a request, so it
    must not depend on what this particular call happens to carry."""
    try:
        verify_presentation(
            None,
            keys=SingleKernelKey(_ISSUER_A_PUBLIC),
            revocation=_NOTHING_REVOKED(),
            now=NOW,
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("a resolver with no domain binding must raise even for no presentation")


def test_plugin_constructor_refuses_a_resolver_with_no_domain_binding() -> None:
    """Fails at startup, where an operator sees it, rather than silently on
    every later request: the plugin never comes into existence at all."""
    try:
        VaidAuthPlugin(
            keys=KernelKeyMap([_ISSUER_A_PUBLIC]),
            revocation=_NOTHING_REVOKED(),
            tool_authorizations={"t": ToolAuthorization(capability="read")},
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("VaidAuthPlugin must refuse a resolver that cannot bind a trust domain")


def test_plugin_constructor_accepts_trusted_issuers() -> None:
    """Control for the test above: the supported configuration still builds."""
    plugin = VaidAuthPlugin(
        keys=TWO_ISSUERS,
        revocation=_NOTHING_REVOKED(),
        tool_authorizations={"t": ToolAuthorization(capability="read")},
    )
    assert plugin.keys is TWO_ISSUERS


# ── TrustedIssuers loader strictness (A2A extension §2.1, mirrored) ────────


def _loader_raises(entries: list, label: str) -> None:
    try:
        TrustedIssuers(entries)
    except TrustedIssuersConfigError:
        return
    raise AssertionError(f"{label} must raise TrustedIssuersConfigError")


def _bad_key_raises(bad_key: object, label: str) -> None:
    """A well-formed ``trustDomain`` is always present, so the failure can
    only be the key itself."""
    _loader_raises([{"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": bad_key}], label)


def test_duplicate_key_across_trust_domains_raises() -> None:
    """The same kernel public key listed twice, for two different domains.
    Whichever entry a lookup landed on last would otherwise decide, silently,
    which domain that key is trusted for. The error must name the key and
    both domains so the operator sees the conflict directly."""
    try:
        TrustedIssuers(
            [
                {"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
                {"trustDomain": _ISSUER_B_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
            ]
        )
    except TrustedIssuersConfigError as exc:
        message = str(exc)
        assert _ISSUER_A_THUMBPRINT in message
        assert _ISSUER_A_DOMAIN in message
        assert _ISSUER_B_DOMAIN in message
        return
    raise AssertionError("a duplicated kernel key across trust domains must raise")


def test_entry_missing_trust_domain_raises() -> None:
    """A parseable key with no ``trustDomain`` binds to nothing, which would
    leave every document's claimed ``trust_domain`` unchecked for that key."""
    _loader_raises(
        [{"kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)}], "an entry missing trustDomain"
    )


def test_entry_empty_dict_raises() -> None:
    _loader_raises([{}], "an empty entry ({})")


def test_entry_trust_domain_only_raises() -> None:
    _loader_raises([{"trustDomain": _ISSUER_A_DOMAIN}], "a trustDomain-only entry")


def test_entry_non_string_key_raises() -> None:
    _bad_key_raises(42, "a non-string kernelPublicKey")


def test_entry_empty_string_key_raises() -> None:
    """A non-strict decoder returns zero bytes for ``""`` and would file that
    as a trusted key."""
    _bad_key_raises("", 'an empty kernelPublicKey ("")')


def test_entry_non_base64url_characters_raise() -> None:
    """``"!!!!"`` is outside the base64url alphabet.
    ``base64.urlsafe_b64decode`` DISCARDS all four characters and returns
    ``b""``, so a non-strict loader accepts this as a zero-byte key."""
    _bad_key_raises("!!!!", 'a kernelPublicKey of "!!!!"')


def test_entry_padded_key_raises() -> None:
    """The configured form is unpadded, so ``=`` is a padding error rather
    than an alternative spelling of the same key."""
    _bad_key_raises(
        base64.urlsafe_b64encode(_ISSUER_A_PUBLIC).decode("ascii") + "=",
        "a padded kernelPublicKey",
    )


def test_entry_non_canonical_key_raises() -> None:
    """The final character's unused low bits must be zero. Two distinct
    strings decoding to the same 32 bytes would otherwise both load, and the
    thumbprint a reader derives by hand from the configured text need not be
    the one the loader files the key under."""
    canonical = _b64url(_ISSUER_A_PUBLIC)
    # 32 bytes is 43 unpadded base64url characters carrying 2 unused low bits,
    # so the next character in the alphabet encodes the same bytes.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet[alphabet.index(canonical[-1]) + 1]
    non_canonical = canonical[:-1] + last
    assert non_canonical != canonical
    assert base64.urlsafe_b64decode(non_canonical + "=") == _ISSUER_A_PUBLIC
    _bad_key_raises(non_canonical, "a non-canonical kernelPublicKey")


def test_entry_key_one_byte_short_raises() -> None:
    """31 bytes is valid base64url and is not an Ed25519 public key."""
    _bad_key_raises(_b64url(bytes([0x11]) * 31), "a 31-byte kernelPublicKey")


def test_entry_key_one_byte_long_raises() -> None:
    """33 bytes, the other side of the same boundary."""
    _bad_key_raises(_b64url(bytes([0x11]) * 33), "a 33-byte kernelPublicKey")


def test_entry_not_an_object_raises() -> None:
    """An element that is not an object names neither a key nor a domain. It
    must surface as a configuration error, not as the ``AttributeError`` or
    ``TypeError`` an unguarded ``entry.get`` would raise."""
    for bad_entry in ("not-an-object", 42, None, ["trustDomain"]):
        _loader_raises([bad_entry], f"a non-object entry ({bad_entry!r})")


def test_valid_32_byte_key_still_loads() -> None:
    """Control for every strictness test above: a well-formed entry loads,
    files the key under its own derived thumbprint, and binds the domain."""
    issuers = TrustedIssuers(
        [{"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)}]
    )
    assert len(issuers) == 1
    assert issuers.resolve_key(_ISSUER_A_THUMBPRINT) == _ISSUER_A_PUBLIC
    assert issuers.trust_domain_for(_ISSUER_A_THUMBPRINT) == _ISSUER_A_DOMAIN
    assert issuers.resolve_key(_ISSUER_B_THUMBPRINT) is None
    assert issuers.trust_domain_for(_ISSUER_B_THUMBPRINT) is None


def test_from_raw_keys_matches_the_config_form() -> None:
    """``from_raw_keys`` is the in-process spelling of the same
    configuration, not a second notion of trust: it must resolve and bind
    identically to the base64url entries."""
    raw = TrustedIssuers.from_raw_keys(
        [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_B_DOMAIN, _ISSUER_B_PUBLIC)]
    )
    for thumbprint, domain, public in (
        (_ISSUER_A_THUMBPRINT, _ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC),
        (_ISSUER_B_THUMBPRINT, _ISSUER_B_DOMAIN, _ISSUER_B_PUBLIC),
    ):
        assert raw.resolve_key(thumbprint) == public == TWO_ISSUERS.resolve_key(thumbprint)
        assert raw.trust_domain_for(thumbprint) == domain == TWO_ISSUERS.trust_domain_for(thumbprint)


def test_from_raw_keys_rejects_one_key_under_two_domains() -> None:
    """``from_raw_keys`` goes through the same loader, so it enforces the
    same one-key-one-domain rule rather than being a way around it."""
    try:
        TrustedIssuers.from_raw_keys(
            [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_B_DOMAIN, _ISSUER_A_PUBLIC)]
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("one key under two domains must raise from from_raw_keys too")


def test_from_raw_keys_allows_two_keys_under_one_domain() -> None:
    """The converse is legitimate: an issuer rotating, or running more than
    one kernel key, holds several keys for its one domain."""
    issuers = TrustedIssuers.from_raw_keys(
        [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_A_DOMAIN, _ISSUER_B_PUBLIC)]
    )
    assert len(issuers) == 2
    assert issuers.trust_domain_for(_ISSUER_A_THUMBPRINT) == _ISSUER_A_DOMAIN
    assert issuers.trust_domain_for(_ISSUER_B_THUMBPRINT) == _ISSUER_A_DOMAIN
