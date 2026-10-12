"""GHSA-hfjh-v2x2-r58v in this bridge: a trusted kernel key must only vouch
for the trust domain it is configured for.

``exchange()`` resolved the leaf's signing key by ``kernel_key_thumbprint``
alone and never compared the resolved key's configured trust domain against
the ``trust_domain`` each document claimed. The profile's SS2 step 4, titled
"Trust-domain binding per issuer key", described ``verify_chain_at``'s consent
and parent-document binding, which are checks BETWEEN documents and are a
different thing: neither compares a claimed ``trust_domain`` against the domain
this bridge's own trusted issuer config binds to the signing key.

So a document signed by a trusted key but naming a DIFFERENT trusted issuer's
``trust_domain`` was exchanged for a JWT whose ``sub``/``act``/``vaid`` claims
named an identity the signing issuer never granted, which a downstream gateway
then honoured on the bridge's word. No forged signature and no compromised key
anywhere in the attack.

Two issuers throughout: A (seed ``0x42``) bound to ``"vaid.example"``, B (seed
``0x99``) bound to ``"other.example"`` — both legitimately trusted, neither
compromised, which is what makes the gap exploitable without stealing anything.
These mirror the three ``td_cases`` of the merged ``python/vaid-a2a`` fix.
"""

from __future__ import annotations

import base64
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_jwt_bridge import (
    DenialReason,
    Denied,
    ExchangeRequest,
    Issued,
    TrustedIssuers,
    TrustedIssuersConfigError,
    exchange,
)
from vaid_jwt_bridge.keys import KeyRing
from vaid_jwt_bridge.service import BridgeConfig
from vaid_mint.attestation import (
    build_unsigned_attestation,
    canonical_attestation_signing_bytes,
)
from vaid_mint.chain import KernelKeyMap, SingleKernelKey
from vaid_mint.document import (
    build_unsigned_vaid_document,
    canonical_vaid_signing_bytes,
    compute_lineage_hash,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint

_ISSUER_A_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
_ISSUER_A_PUBLIC = _ISSUER_A_KEY.public_key().public_bytes_raw()
_ISSUER_A_THUMBPRINT = kernel_key_thumbprint(_ISSUER_A_PUBLIC)
_ISSUER_A_DOMAIN = "vaid.example"

_ISSUER_B_KEY = Ed25519PrivateKey.from_private_bytes(bytes([0x99]) * 32)
_ISSUER_B_PUBLIC = _ISSUER_B_KEY.public_key().public_bytes_raw()
_ISSUER_B_THUMBPRINT = kernel_key_thumbprint(_ISSUER_B_PUBLIC)
_ISSUER_B_DOMAIN = "other.example"

_BRIDGE_ISSUER = "https://bridge.example.com"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _two_issuers() -> TrustedIssuers:
    """Both issuers trusted, each for its own domain, so no denial below can
    come from an issuer simply being unknown."""
    return TrustedIssuers(
        [
            {"trustDomain": _ISSUER_A_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)},
            {"trustDomain": _ISSUER_B_DOMAIN, "kernelPublicKey": _b64url(_ISSUER_B_PUBLIC)},
        ]
    )


def _vid(n: int) -> str:
    return str(uuid.UUID(int=n))


def _signed(
    key: Ed25519PrivateKey,
    thumbprint: str,
    *,
    vaid_id: str,
    parent_vaid: str | None,
    scope: list[str],
    trust_domain: str,
) -> dict:
    """A VAID signed by ``key`` but claiming ``trust_domain`` — independently
    of which domain ``key`` is actually bound to in a trust configuration.
    That independence is the bug surface here."""
    unsigned = build_unsigned_vaid_document(
        vaid_id=vaid_id,
        agent_id=vaid_id,
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=parent_vaid,
        scope_boundary=scope,
        lineage_hash=compute_lineage_hash(parent_vaid, vaid_id),
        capability_set=["read"],
        trust_domain=trust_domain,
        kernel_key_thumbprint=thumbprint,
    )
    signature = key.sign(canonical_vaid_signing_bytes(unsigned))
    return {**unsigned, "kernel_signature": list(signature)}


def _exchange(leaf, chain, *, keys, revocation, signer, now):
    return exchange(
        ExchangeRequest(leaf=leaf, chain=tuple(chain), audience="aud"),
        keys=keys,
        revocation=revocation,
        issuer=_BRIDGE_ISSUER,
        signer=signer,
        now=now,
    )


# ── td_case T1: the reported bug ───────────────────────────────────────────


def test_t1_root_signed_by_a_trusted_key_claiming_the_wrong_domain_issues_nothing(
    vouching_revocation, eddsa_signer, verification_now
):
    """THE REPORTED BUG. B's key is trusted — for ``"other.example"`` — but
    this root claims A's domain, ``"vaid.example"``. Before the fix the bridge
    found B's key by thumbprint alone, authenticity checked out, and it signed
    a JWT asserting A's identity."""
    root = _signed(
        _ISSUER_B_KEY,
        _ISSUER_B_THUMBPRINT,
        vaid_id=_vid(101),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    result = _exchange(
        root,
        (),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied), "a trusted key must not vouch for a domain it is not bound to"
    assert result.reason == DenialReason.ISSUER_MISMATCH


# ── td_case T2: the honest control ─────────────────────────────────────────


def test_t2_root_signed_by_a_trusted_key_claiming_its_own_domain_is_issued(
    vouching_revocation, eddsa_signer, verification_now
):
    """Honest control for T1: same trust configuration, same key, and the
    document claims the domain that key IS bound to, so a JWT is issued.
    Without this, T1 would pass just as well against a bridge that refused
    everything."""
    root = _signed(
        _ISSUER_B_KEY,
        _ISSUER_B_THUMBPRINT,
        vaid_id=_vid(102),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_B_DOMAIN,
    )
    result = _exchange(
        root,
        (),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Issued), getattr(result, "detail", result)
    assert result.access_token


# ── td_case T3: the chain-hop shape of the same bug ────────────────────────


def test_t3_cross_key_hop_claiming_the_parents_domain_issues_nothing(
    vouching_revocation, eddsa_signer, verification_now
):
    """A genuine cross-key delegation from A to B, consented by A's own
    attestation naming B's VAID as claiming A's trust_domain (an operator
    error on A's side, or a misled consent — either way, not a forged
    signature). The leaf IS signed by B, a trusted issuer, and the consent,
    scope and capability containment ``vaid_mint.chain`` already enforces all
    check out. Only the domain-to-key binding catches that B's key is
    configured for ``"other.example"``, not A's ``"vaid.example"``."""
    root = _signed(
        _ISSUER_A_KEY,
        _ISSUER_A_THUMBPRINT,
        vaid_id=_vid(103),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    leaf = _signed(
        _ISSUER_B_KEY,
        _ISSUER_B_THUMBPRINT,
        vaid_id=_vid(104),
        parent_vaid=root["vaid_id"],
        scope=["data.acme.sub"],
        # Claims A's domain; B's key is bound to _ISSUER_B_DOMAIN.
        trust_domain=_ISSUER_A_DOMAIN,
    )

    attestation_unsigned = build_unsigned_attestation(
        parent_vaid=root["vaid_id"],
        child_vaid=leaf["vaid_id"],
        child_trust_domain=_ISSUER_A_DOMAIN,
        child_tenant_id="acme",
        issued_at="2026-01-01T00:00:00Z",
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
    # Asserted so this failure is isolated to the trust-domain binding and is
    # not a missing-consent denial passing for an unrelated reason.
    assert attestation["parent_vaid"] == root["vaid_id"]

    result = _exchange(
        leaf,
        (root,),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.ISSUER_MISMATCH


# ── the step-3 half: a misbound ANCESTOR, with a clean leaf ────────────────


def test_misbound_ancestor_issues_nothing_even_when_the_leaf_is_clean(
    vouching_revocation, eddsa_signer, verification_now
):
    """T1/T3 both fail on the leaf's own binding (step 1). This pins the other
    half: the leaf is honestly bound, and a presented ancestor is the document
    claiming a domain its signing key is not bound to."""
    misbound_ancestor = _signed(
        _ISSUER_B_KEY,
        _ISSUER_B_THUMBPRINT,
        vaid_id=_vid(105),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    leaf = _signed(
        _ISSUER_A_KEY,
        _ISSUER_A_THUMBPRINT,
        vaid_id=_vid(106),
        parent_vaid=misbound_ancestor["vaid_id"],
        scope=["data.acme.sub"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    result = _exchange(
        leaf,
        (misbound_ancestor,),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.ISSUER_MISMATCH
    assert misbound_ancestor["vaid_id"] in result.detail


# ── check order: the leaf's own verdict is never pre-empted ────────────────


def _bad_signature_leaf() -> dict:
    """A leaf claiming A's domain and A's thumbprint — so its binding is
    correct — but signed by B's key, so only its signature is wrong."""
    unsigned = build_unsigned_vaid_document(
        vaid_id=_vid(107),
        agent_id=_vid(107),
        agent_class="test",
        version="1.0.0",
        tenant_id="acme",
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2999-01-01T00:00:00Z",
        public_key_der=list(range(32)),
        parent_vaid=None,
        scope_boundary=["data.acme"],
        lineage_hash=compute_lineage_hash(None, _vid(107)),
        capability_set=["read"],
        trust_domain=_ISSUER_A_DOMAIN,
        kernel_key_thumbprint=_ISSUER_A_THUMBPRINT,
    )
    return {
        **unsigned,
        "kernel_signature": list(_ISSUER_B_KEY.sign(canonical_vaid_signing_bytes(unsigned))),
    }


def test_bad_leaf_signature_wins_over_a_wrong_domain_chain_document(
    vouching_revocation, eddsa_signer, verification_now
):
    """The mixed case: a leaf with a bad signature presented alongside an
    ancestor that is independently misbound. Step 1 reaches its verdict on the
    leaf alone before step 3 looks at any presented document, so this must
    deny INAUTHENTIC, never ISSUER_MISMATCH — two implementations given this
    input must not disagree about why they refused it."""
    misbound = _signed(
        _ISSUER_B_KEY,
        _ISSUER_B_THUMBPRINT,
        vaid_id=_vid(108),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    result = _exchange(
        _bad_signature_leaf(),
        (misbound,),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.INAUTHENTIC


def test_bad_leaf_signature_with_empty_chain_is_inauthentic(
    vouching_revocation, eddsa_signer, verification_now
):
    """Control for the test above: the same leaf with nothing else presented
    reaches the same verdict. There being another document to examine does not
    change the leaf's own result, in either direction."""
    result = _exchange(
        _bad_signature_leaf(),
        (),
        keys=_two_issuers(),
        revocation=vouching_revocation,
        signer=eddsa_signer,
        now=verification_now,
    )
    assert isinstance(result, Denied)
    assert result.reason == DenialReason.INAUTHENTIC


# ── a resolver that cannot bind a domain is refused, at configuration time ──
#
# The negative test for the control itself. A bare vaid_mint resolver answers
# resolve_key and nothing else, so the bridge cannot compare any document's
# claimed trust_domain against anything. Skipping the binding check for such a
# resolver would leave the whole defect open by omission.


def test_bare_kernel_key_map_is_refused_by_exchange(
    vouching_revocation, eddsa_signer, verification_now
):
    root = _signed(
        _ISSUER_A_KEY,
        _ISSUER_A_THUMBPRINT,
        vaid_id=_vid(109),
        parent_vaid=None,
        scope=["data.acme"],
        trust_domain=_ISSUER_A_DOMAIN,
    )
    try:
        _exchange(
            root,
            (),
            keys=KernelKeyMap([_ISSUER_A_PUBLIC]),
            revocation=vouching_revocation,
            signer=eddsa_signer,
            now=verification_now,
        )
    except TrustedIssuersConfigError as exc:
        assert "trust_domain_for" in str(exc)
        return
    raise AssertionError("a resolver with no domain binding must raise, not exchange")


def test_bare_single_kernel_key_is_refused_with_no_leaf_at_all(
    vouching_revocation, eddsa_signer, verification_now
):
    """Raised before anything about the request is looked at, including the
    ``leaf is None`` denial: a configuration defect is a property of the
    deployment, not of a request, so it must not depend on what one exchange
    happens to carry."""
    try:
        _exchange(
            None,
            (),
            keys=SingleKernelKey(_ISSUER_A_PUBLIC),
            revocation=vouching_revocation,
            signer=eddsa_signer,
            now=verification_now,
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("a resolver with no domain binding must raise even with no leaf")


def test_bridge_config_refuses_a_resolver_with_no_domain_binding(
    vouching_revocation, eddsa_signer
):
    """Fails when the deployment is configured, where an operator sees it,
    rather than silently on every later exchange: a ``BridgeConfig`` carrying
    such a resolver never comes into existence, so no app can be built from
    it."""
    try:
        BridgeConfig(
            issuer=_BRIDGE_ISSUER,
            keys=KernelKeyMap([_ISSUER_A_PUBLIC]),
            revocation=vouching_revocation,
            keyring=KeyRing([eddsa_signer]),
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("BridgeConfig must refuse a resolver that cannot bind a trust domain")


def test_bridge_config_accepts_trusted_issuers(vouching_revocation, eddsa_signer):
    """Control for the test above: the supported configuration still builds."""
    issuers = _two_issuers()
    config = BridgeConfig(
        issuer=_BRIDGE_ISSUER,
        keys=issuers,
        revocation=vouching_revocation,
        keyring=KeyRing([eddsa_signer]),
    )
    assert config.keys is issuers


# ── TrustedIssuers loader strictness (A2A extension section 2.1, mirrored) ──


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


def test_duplicate_key_across_trust_domains_raises():
    """The same kernel public key listed twice, for two different domains.
    Whichever entry a lookup landed on last would otherwise decide, silently,
    which domain that key is trusted for. The error must name the key and both
    domains so the operator sees the conflict directly."""
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


def test_entry_missing_trust_domain_raises():
    """A parseable key with no ``trustDomain`` binds to nothing, which would
    leave every document's claimed ``trust_domain`` unchecked for that key."""
    _loader_raises(
        [{"kernelPublicKey": _b64url(_ISSUER_A_PUBLIC)}], "an entry missing trustDomain"
    )


def test_entry_empty_dict_raises():
    _loader_raises([{}], "an empty entry ({})")


def test_entry_trust_domain_only_raises():
    _loader_raises([{"trustDomain": _ISSUER_A_DOMAIN}], "a trustDomain-only entry")


def test_entry_non_string_key_raises():
    _bad_key_raises(42, "a non-string kernelPublicKey")


def test_entry_empty_string_key_raises():
    """A non-strict decoder returns zero bytes for ``""`` and would file that
    as a trusted key."""
    _bad_key_raises("", 'an empty kernelPublicKey ("")')


def test_entry_non_base64url_characters_raise():
    """``"!!!!"`` is outside the base64url alphabet.
    ``base64.urlsafe_b64decode`` DISCARDS all four characters and returns
    ``b""``, so a non-strict loader accepts this as a zero-byte key."""
    _bad_key_raises("!!!!", 'a kernelPublicKey of "!!!!"')


def test_entry_padded_key_raises():
    """The configured form is unpadded, so ``=`` is a padding error rather
    than an alternative spelling of the same key."""
    _bad_key_raises(
        base64.urlsafe_b64encode(_ISSUER_A_PUBLIC).decode("ascii") + "=",
        "a padded kernelPublicKey",
    )


def test_entry_non_canonical_key_raises():
    """The final character's unused low bits must be zero. Two distinct
    strings decoding to the same 32 bytes would otherwise both load."""
    canonical = _b64url(_ISSUER_A_PUBLIC)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    non_canonical = canonical[:-1] + alphabet[alphabet.index(canonical[-1]) + 1]
    assert non_canonical != canonical
    assert base64.urlsafe_b64decode(non_canonical + "=") == _ISSUER_A_PUBLIC
    _bad_key_raises(non_canonical, "a non-canonical kernelPublicKey")


def test_entry_key_one_byte_short_raises():
    """31 bytes is valid base64url and is not an Ed25519 public key."""
    _bad_key_raises(_b64url(bytes([0x11]) * 31), "a 31-byte kernelPublicKey")


def test_entry_key_one_byte_long_raises():
    """33 bytes, the other side of the same boundary."""
    _bad_key_raises(_b64url(bytes([0x11]) * 33), "a 33-byte kernelPublicKey")


def test_entry_not_an_object_raises():
    """An element that is not an object names neither a key nor a domain. It
    must surface as a configuration error, not as the ``AttributeError`` or
    ``TypeError`` an unguarded ``entry.get`` would raise."""
    for bad_entry in ("not-an-object", 42, None, ["trustDomain"]):
        _loader_raises([bad_entry], f"a non-object entry ({bad_entry!r})")


def test_valid_32_byte_key_still_loads():
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


def test_from_raw_keys_matches_the_config_form():
    """``from_raw_keys`` is the in-process spelling of the same configuration,
    not a second notion of trust: it must resolve and bind identically to the
    base64url entries."""
    config_form = _two_issuers()
    raw = TrustedIssuers.from_raw_keys(
        [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_B_DOMAIN, _ISSUER_B_PUBLIC)]
    )
    for thumbprint, domain, public in (
        (_ISSUER_A_THUMBPRINT, _ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC),
        (_ISSUER_B_THUMBPRINT, _ISSUER_B_DOMAIN, _ISSUER_B_PUBLIC),
    ):
        assert raw.resolve_key(thumbprint) == public == config_form.resolve_key(thumbprint)
        assert (
            raw.trust_domain_for(thumbprint)
            == domain
            == config_form.trust_domain_for(thumbprint)
        )


def test_from_raw_keys_rejects_one_key_under_two_domains():
    """``from_raw_keys`` goes through the same loader, so it enforces the same
    one-key-one-domain rule rather than being a way around it."""
    try:
        TrustedIssuers.from_raw_keys(
            [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_B_DOMAIN, _ISSUER_A_PUBLIC)]
        )
    except TrustedIssuersConfigError:
        return
    raise AssertionError("one key under two domains must raise from from_raw_keys too")


def test_from_raw_keys_allows_two_keys_under_one_domain():
    """The converse is legitimate: an issuer rotating, or running more than
    one kernel key, holds several keys for its one domain."""
    issuers = TrustedIssuers.from_raw_keys(
        [(_ISSUER_A_DOMAIN, _ISSUER_A_PUBLIC), (_ISSUER_A_DOMAIN, _ISSUER_B_PUBLIC)]
    )
    assert len(issuers) == 2
    assert issuers.trust_domain_for(_ISSUER_A_THUMBPRINT) == _ISSUER_A_DOMAIN
    assert issuers.trust_domain_for(_ISSUER_B_THUMBPRINT) == _ISSUER_A_DOMAIN
