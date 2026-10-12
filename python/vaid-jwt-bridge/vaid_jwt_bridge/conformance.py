"""Packaged token-bridge conformance check — the firewall, shipped in the wheel.

Mirror of ``vaid_pop.conformance`` / ``vaid_mint.conformance`` /
``vaid_a2a.conformance`` / ``vaid_adk.conformance``. A consumer who has only
``pip install vaid-jwt-bridge`` — no repo checkout — can prove the bridge they
installed exchanges a frozen delegation chain for a JWT whose claims and digest
are the frozen ones, and refuses to sign anything at all for every distinct
reason the profile says it must refuse::

    python -m vaid_jwt_bridge.conformance      # exit 0 = PASS, 1 = BLOCKER
    vaid-jwt-bridge-conformance                # same, via the console entry point

Programmatically::

    from vaid_jwt_bridge.conformance import run
    run()  # raises ConformanceError on any divergence; returns the verdict table

WHAT THIS PINS. Two different kinds of claim, and they are worth separating:

  BYTES    ``chain_sha256`` over the frozen chain is a deterministic SHA-256 over
           an RFC 8785 canonicalization, so it has one correct value and this
           module freezes it as :data:`FROZEN_CHAIN_SHA256`. That digest is the
           profile's audit hook (section 5): the thing a third party holding the
           same documents recomputes to confirm the bridge verified exactly
           those. A frozen literal is the only form of that check worth having —
           comparing the token's claim against this package's own
           ``chain_sha256()`` output would pass uniformly if both moved together,
           which is a check that cannot fail.

  VERDICTS For each case, whether a token was issued and, if not, the profile's
           denial reason. The ordered procedure in docs/jwt/v1/profile.md section
           2 is what is normative for a bridge, so that ordering is what a
           consumer needs to be able to re-check.

The issued token is verified against the bridge's OWN published JWKS, through
``KeyRing.jwks()`` — the same route a gateway uses — rather than against the
private signer, so this also proves the published verification material actually
verifies what was signed. Claim-time validation is switched off deliberately
during that step: the frozen verification instant is in the past, so a wall-clock
``exp`` check would reject a correctly-issued token. ``exp`` is asserted against
the vector's instant instead.

WHERE THE DOCUMENTS COME FROM: ``chain_v1.json``, bundled inside the installed
``vaid-mint`` wheel. Nothing is vendored here and nothing is minted at run time —
a run-time mint produces different bytes every run, so no digest over it could be
frozen, and ``vaid_mint``'s mint path stamps timestamps from the real clock.

CONTROLS ARE LOAD-BEARING ON BOTH SURFACES. One case MUST issue a token and seven
must each be denied with a DIFFERENT reason. A bridge that refuses everything —
the easiest way to look safe — fails the control case; one that signs
indiscriminately fails the other seven.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from vaid_mint.revocation import InMemoryRevocationList

from vaid_jwt_bridge import (
    ISSUED_TOKEN_TYPE_JWT,
    Denied,
    ExchangeRequest,
    Issued,
    KeyRing,
    TrustedIssuers,
    TrustedIssuersConfigError,
    exchange,
    require_domain_binding,
)
from vaid_jwt_bridge.keys import JwcryptoSigner

#: SHA-256 of the RFC 8785 canonical encoding of vaid-mint's frozen ``chain_v1``
#: chain, root first. A deterministic digest over frozen bytes: one correct
#: value, and a literal rather than a re-derivation so the check can actually
#: fail. If this moves, either the frozen chain moved or the canonicalization
#: did; both are wire-contract changes and neither is a conformance pass.
#:
#: **It moved once, at vaid-mint 0.10.0, and this is that move.** The frozen
#: chain was re-frozen at ``sig_version`` 4: each hop's ``scope_boundary`` went
#: from ``["data.aifactory"]`` to ``[{"kind": "prefix", "value":
#: "data.aifactory"}]`` (ADR-0009), so the canonical bytes of all three
#: documents changed and the digest over them changed with it. The
#: canonicalization did NOT change.
#:
#: The new value was derived, not transcribed from a failing run: re-deriving it
#: by the documented rule (SHA-256 over ``rfc8785.dumps`` of the three
#: signature-reattached documents, root first) reproduces the PREVIOUS frozen
#: value, ``daa5c6cf...``, byte for byte when pointed at the v3 chain. The same
#: derivation over the v4 chain gives the literal below.
FROZEN_CHAIN_SHA256 = "416b32406657a728ef2ed668909248689870ea75c0ea6a961bd54db008291eea"

#: The bridge's own JWT-signing key for this firewall: a fixed seed, never
#: randomness, so `kid` and the published JWKS are identical on every run. This
#: signs the ISSUED token and is unrelated to any VAID kernel key.
_BRIDGE_SIGNING_SEED = b"\x10" * 32

#: A second, unrelated bridge key, standing in for "somebody else's signer" so
#: that "the JWKS verifies the token" is proven to be a discriminating statement
#: rather than one any key would satisfy.
_FOREIGN_SIGNING_SEED = b"\x21" * 32

_ISSUER = "https://bridge.conformance.example"
_AUDIENCE = "https://gateway.conformance.example"
_OTHER_DOMAIN = "not-the-domain-this-key-is-trusted-for.example"


class ConformanceError(AssertionError):
    """A divergence from the frozen digest or verdict table — a hard BLOCKER,
    never ship-anyway."""


def load_chain_vector() -> dict:
    """The chain-presentation vector bundled with the installed ``vaid-mint``.

    Read from the DEPENDENCY's wheel rather than from a copy of our own, so this
    firewall and ``vaid-mint-conformance`` cannot disagree about what the frozen
    chain is.
    """
    return json.loads(files("vaid_mint").joinpath("vectors/chain_v1.json").read_text())


def frozen_chain(v: dict) -> list[dict]:
    """The vector's three documents, root first, each with its frozen kernel
    signature reattached — the same reconstruction
    ``vaid_mint.conformance.check_chain`` performs (the vector stores each hop's
    signature beside its document, not inside it)."""
    return [
        {**e["document"], "kernel_signature": list(bytes.fromhex(e["signature_hex"]))}
        for e in v["chain"]
    ]


def _signer(seed: bytes) -> JwcryptoSigner:
    return JwcryptoSigner(JWK.from_pyca(Ed25519PrivateKey.from_private_bytes(seed)), alg="EdDSA")


def _trusted(domain: str, kernel_public_key: bytes) -> TrustedIssuers:
    return TrustedIssuers.from_raw_keys([(domain, kernel_public_key)])


def _vouching() -> InMemoryRevocationList:
    # An empty list must VOUCH for "nothing revoked" rather than read as
    # UNAVAILABLE (R.4.5/R.4.6).
    return InMemoryRevocationList.assume_nothing_revoked()


@dataclass(frozen=True)
class Case:
    """One frozen expectation about :func:`exchange`."""

    name: str
    why: str
    expected_issued: bool
    #: The profile's denial reason, or ``None`` for the issuing case.
    expected_reason: str | None
    #: Given ``(root, intermediate, leaf, kernel_public_key)``, the keyword
    #: arguments this case calls :func:`exchange` with.
    build: Callable[[dict, dict, dict, bytes], dict]


def _base(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        "request": ExchangeRequest(leaf=leaf, chain=(root, mid), audience=_AUDIENCE),
        "keys": _trusted(leaf["trust_domain"], key),
        "revocation": _vouching(),
        "issuer": _ISSUER,
        "signer": _signer(_BRIDGE_SIGNING_SEED),
    }


def _cross_domain(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    # GHSA-hfjh-v2x2-r58v. The right key, every signature verifying, trusted for
    # a different domain than the documents claim. Before the fix this was
    # exchanged for a JWT naming an identity the signing issuer never granted.
    return {**_base(root, mid, leaf, key), "keys": _trusted(_OTHER_DOMAIN, key)}


def _no_leaf(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        **_base(root, mid, leaf, key),
        "request": ExchangeRequest(leaf=None, chain=(), audience=_AUDIENCE),
    }


def _no_audience(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        **_base(root, mid, leaf, key),
        "request": ExchangeRequest(leaf=leaf, chain=(root, mid), audience=None),
    }


def _wrong_token_type(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        **_base(root, mid, leaf, key),
        "request": ExchangeRequest(
            leaf=leaf,
            chain=(root, mid),
            audience=_AUDIENCE,
            requested_token_type="urn:ietf:params:oauth:token-type:saml2",
        ),
    }


def _withheld_ancestry(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {
        **_base(root, mid, leaf, key),
        "request": ExchangeRequest(leaf=leaf, chain=(), audience=_AUDIENCE),
    }


def _revoked_ancestor(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    store = InMemoryRevocationList()
    store.revoke(mid["vaid_id"])
    return {**_base(root, mid, leaf, key), "revocation": store}


def _revocation_unavailable(root: dict, mid: dict, leaf: dict, key: bytes) -> dict:
    return {**_base(root, mid, leaf, key), "revocation": InMemoryRevocationList()}


CASES: tuple[Case, ...] = (
    Case(
        name="control: frozen chain, audience given, nothing revoked",
        why="THE CONTROL. Without a case that MUST issue, a bridge that refuses "
        "every exchange satisfies every other case here - and refusing "
        "everything is the easiest way for a broken build to look safe.",
        expected_issued=True,
        expected_reason=None,
        build=_base,
    ),
    Case(
        name="trusted key, wrong trust domain (GHSA-hfjh-v2x2-r58v)",
        why="A trusted kernel key must vouch only for the domain it is "
        "configured for. Nothing is forged and nothing is stolen; before the "
        "fix this produced a signed JWT whose sub/act/vaid claims named an "
        "identity the signing issuer never granted, which a gateway then "
        "honoured on the bridge's word.",
        expected_issued=False,
        expected_reason="issuer_mismatch",
        build=_cross_domain,
    ),
    Case(
        name="no leaf presented",
        why="Nothing to verify is a denial, never an empty pass.",
        expected_issued=False,
        expected_reason="no_leaf",
        build=_no_leaf,
    ),
    Case(
        name="no audience requested",
        why="A JWT with no audience is a token any gateway may accept; the "
        "profile requires the caller to name one.",
        expected_issued=False,
        expected_reason="missing_audience",
        build=_no_audience,
    ),
    Case(
        name="requested_token_type this bridge does not issue",
        why="An unsupported requested_token_type is denied, never silently "
        "ignored and answered with a JWT the caller did not ask for.",
        expected_issued=False,
        expected_reason="unsupported_requested_token_type",
        build=_wrong_token_type,
    ),
    Case(
        name="leaf presented with its ancestry withheld",
        why="A chain that cannot be walked back to a trusted root is "
        "unverifiable, so nothing is signed. Fail-closed on absence.",
        expected_issued=False,
        expected_reason="chain_unverifiable",
        build=_withheld_ancestry,
    ),
    Case(
        name="an ancestor is revoked",
        why="Revocation is evaluated over the whole verified lineage, not the "
        "leaf alone.",
        expected_issued=False,
        expected_reason="revoked",
        build=_revoked_ancestor,
    ),
    Case(
        name="revocation status unavailable",
        why="Unavailable is its own state (R.4.5/R.4.6): it must not be read as "
        "'not revoked' and must not produce a token.",
        expected_issued=False,
        expected_reason="revocation_unavailable",
        build=_revocation_unavailable,
    ),
)


def check_controls() -> None:
    """The case table itself, before any case runs: both polarities present, and
    every denial pinning a DISTINCT reason. A table whose denials all collapse to
    one reason would be satisfied by a bridge that refuses everything for that one
    reason."""
    if not any(c.expected_issued for c in CASES):
        raise ConformanceError(
            "no case expects a token to be ISSUED — BLOCKER. With denials only, a "
            "bridge that refuses every exchange would satisfy this firewall."
        )
    denied = [c for c in CASES if not c.expected_issued]
    if not denied:
        raise ConformanceError(
            "no case expects a DENIAL — BLOCKER. With the control alone, a bridge "
            "that signs anything presented would satisfy this firewall."
        )
    reasons = [c.expected_reason for c in denied]
    if len(set(reasons)) != len(reasons):
        raise ConformanceError(
            f"denial cases do not each pin a distinct reason — BLOCKER\n  reasons = {reasons}"
        )


def check_config_is_fail_closed() -> None:
    """A trust configuration that cannot bind a domain to a key is a defect in the
    DEPLOYMENT, so it raises rather than returning a denial, and it raises before
    anything about the request is looked at.

    This is the half of GHSA-hfjh-v2x2-r58v no per-request case can cover: a
    resolver answering only "do I trust this key" has nowhere to put the answer
    to "for which domain", so tolerating one would reintroduce the defect through
    configuration alone, with no code change.
    """

    class _ThumbprintOnlyResolver:
        """The pre-fix resolver shape: a key lookup with no domain to bind it to."""

        def resolve_key(self, thumbprint: str) -> bytes | None:
            return b"\x00" * 32

    resolver = _ThumbprintOnlyResolver()
    try:
        require_domain_binding(resolver)
    except TrustedIssuersConfigError:
        pass
    else:
        raise ConformanceError(
            "require_domain_binding ACCEPTED a resolver that cannot bind a trust "
            "domain to a key — BLOCKER."
        )
    try:
        exchange(
            ExchangeRequest(leaf=None, chain=(), audience=_AUDIENCE),
            keys=resolver,  # type: ignore[arg-type]
            revocation=_vouching(),
            issuer=_ISSUER,
            signer=_signer(_BRIDGE_SIGNING_SEED),
        )
    except TrustedIssuersConfigError:
        return
    raise ConformanceError(
        "exchange() ACCEPTED a trust resolver that cannot bind a trust domain to "
        "a key — BLOCKER. The binding check must run before any request-shaped "
        "early return, or a deployment can reintroduce GHSA-hfjh-v2x2-r58v with "
        "no code change."
    )


def check_case(case: Case, docs: list[dict], key: bytes, now: datetime) -> str:
    """Run one case and assert its frozen outcome. Returns a label for the table."""
    root, mid, leaf = docs
    result = exchange(**case.build(root, mid, leaf, key), now=now)
    issued = isinstance(result, Issued)
    if issued is not case.expected_issued:
        got = (
            f"ISSUED ({result.issued_token_type})"
            if issued
            else f"DENIED {result.reason.value} ({result.detail})"
        )
        raise ConformanceError(
            f"{case.name}: outcome diverged — BLOCKER\n"
            f"  got    = {got}\n"
            f"  frozen = {'ISSUED' if case.expected_issued else 'DENIED ' + str(case.expected_reason)}\n"
            f"  why this case exists: {case.why}"
        )
    if isinstance(result, Denied):
        if result.reason.value != case.expected_reason:
            raise ConformanceError(
                f"{case.name}: denial reason diverged — BLOCKER\n"
                f"  got    = {result.reason.value!r} ({result.detail})\n"
                f"  frozen = {case.expected_reason!r}\n"
                f"  why this case exists: {case.why}"
            )
        return result.reason.value
    return "issued"


def check_issued_token(docs: list[dict], key: bytes, now: datetime) -> dict:
    """The issuing path in full: exchange the frozen chain, verify the token
    against the bridge's PUBLISHED JWKS, and assert the claims the profile
    specifies — including the frozen ``chain_sha256``.

    Returns the verified claims.
    """
    root, mid, leaf = docs
    signer = _signer(_BRIDGE_SIGNING_SEED)
    result = exchange(
        ExchangeRequest(leaf=leaf, chain=(root, mid), audience=_AUDIENCE),
        keys=_trusted(leaf["trust_domain"], key),
        revocation=_vouching(),
        issuer=_ISSUER,
        signer=signer,
        now=now,
    )
    if not isinstance(result, Issued):
        raise ConformanceError(
            f"the control case did not issue a token — BLOCKER\n"
            f"  denied = {result.reason.value}: {result.detail}"
        )
    if result.issued_token_type != ISSUED_TOKEN_TYPE_JWT:
        raise ConformanceError(
            f"issued_token_type is {result.issued_token_type!r}, expected "
            f"{ISSUED_TOKEN_TYPE_JWT!r} — BLOCKER"
        )

    # Verified against the PUBLISHED verification material, the way a gateway
    # does it, not against the private signer we happen to be holding.
    jwks = KeyRing([signer]).jwks()
    if any(private in jwks["keys"][0] for private in ("d", "p", "q")):
        raise ConformanceError(
            "the published JWKS carries private key material — BLOCKER. It is "
            "served to every gateway that verifies a token."
        )
    public = JWK(**jwks["keys"][0])
    # check_claims=False DELIBERATELY: the frozen verification instant is in the
    # past, so jwcrypto's wall-clock `exp` validation would reject a correctly
    # issued token. `exp` is asserted below against the vector's instant, which
    # is the only clock this firewall is allowed to have an opinion about.
    token = JWT(jwt=result.access_token, key=public, check_claims=False)
    claims = json.loads(token.claims)
    header = json.loads(token.header)

    if header.get("alg") != "EdDSA":
        raise ConformanceError(f"token alg is {header.get('alg')!r}, expected 'EdDSA' — BLOCKER")
    if header.get("kid") != signer.kid:
        raise ConformanceError(
            f"token kid {header.get('kid')!r} is not the signer's {signer.kid!r} — "
            "BLOCKER: a gateway could not select the right JWKS entry."
        )

    # A foreign key must NOT verify the same token. Without this, "the JWKS
    # verified it" is a statement that any key would satisfy.
    try:
        JWT(
            jwt=result.access_token,
            key=JWK(**KeyRing([_signer(_FOREIGN_SIGNING_SEED)]).jwks()["keys"][0]),
            check_claims=False,
        )
    except Exception:
        pass
    else:
        raise ConformanceError(
            "an unrelated key VERIFIED the issued token — BLOCKER. The signature "
            "check is not discriminating, so JWKS verification proves nothing."
        )

    expected_sub = root["vaid_id"]
    if claims.get("sub") != expected_sub:
        raise ConformanceError(
            f"sub is {claims.get('sub')!r}, expected the root {expected_sub!r} — BLOCKER"
        )
    # RFC 8693: most recent actor outermost, least recent most deeply nested.
    expected_act = {"sub": leaf["vaid_id"], "act": {"sub": mid["vaid_id"]}}
    if claims.get("act") != expected_act:
        raise ConformanceError(
            f"act diverged — BLOCKER\n  got    = {json.dumps(claims.get('act'))}\n"
            f"  frozen = {json.dumps(expected_act)}"
        )
    if claims.get("iss") != _ISSUER or claims.get("aud") != _AUDIENCE:
        raise ConformanceError(
            f"iss/aud diverged — BLOCKER\n  got = {claims.get('iss')!r} / {claims.get('aud')!r}"
        )

    vaid_claim = claims.get("vaid") or {}
    if vaid_claim.get("chain_sha256") != FROZEN_CHAIN_SHA256:
        raise ConformanceError(
            "chain_sha256 diverged from the frozen digest — BLOCKER\n"
            f"  got    = {vaid_claim.get('chain_sha256')}\n"
            f"  frozen = {FROZEN_CHAIN_SHA256}\n"
            "Either the frozen chain moved or the canonicalization did. Both are "
            "wire-contract changes: a third party recomputing this digest over "
            "the same documents would no longer agree with the bridge."
        )
    if vaid_claim.get("vaid_id") != leaf["vaid_id"]:
        raise ConformanceError("the vaid claim does not name the leaf — BLOCKER")
    if vaid_claim.get("trust_domain") != leaf["trust_domain"]:
        raise ConformanceError("the vaid claim does not carry the leaf's trust_domain — BLOCKER")
    if vaid_claim.get("scope_boundary") != list(leaf["scope_boundary"]):
        raise ConformanceError("the vaid claim does not carry the leaf's scope_boundary — BLOCKER")

    # exp is bounded by BOTH the bridge's TTL and the leaf's own expiry: a token
    # must never outlive the authority it was minted from.
    leaf_expiry = int(
        datetime.fromisoformat(leaf["expires_at"].replace("Z", "+00:00")).timestamp()
    )
    if claims["exp"] > leaf_expiry:
        raise ConformanceError(
            f"exp {claims['exp']} outlives the leaf's own expiry {leaf_expiry} — "
            "BLOCKER: the token would still be honoured after the VAID it "
            "represents had lapsed."
        )
    if claims["exp"] - claims["iat"] != result.expires_in:
        raise ConformanceError(
            f"exp - iat is {claims['exp'] - claims['iat']}s but expires_in says "
            f"{result.expires_in}s — BLOCKER: the caller is told a lifetime the "
            "token does not have."
        )
    if claims["iat"] != int(now.timestamp()):
        raise ConformanceError(
            f"iat {claims['iat']} is not the verification instant "
            f"{int(now.timestamp())} — BLOCKER: the token is stamped from a clock "
            "other than the one the exchange was evaluated against."
        )
    return claims


def run() -> dict[str, str]:
    """Run the firewall. Raises ConformanceError on any divergence; returns the
    observed outcome table on PASS."""
    check_controls()
    check_config_is_fail_closed()
    v = load_chain_vector()
    docs = frozen_chain(v)
    key = bytes.fromhex(v["ed25519"]["kernel_public_key_hex"])
    now = datetime.fromisoformat(v["expected"]["verification_instant"].replace("Z", "+00:00"))
    if now.tzinfo is None:  # a naive instant would compare against a local clock
        now = now.replace(tzinfo=timezone.utc)
    check_issued_token(docs, key, now)
    return {case.name: check_case(case, docs, key, now) for case in CASES}


# --- pytest discovery (so `pytest --pyargs vaid_jwt_bridge` runs the firewall) ---


def test_packaged_controls_are_present() -> None:
    check_controls()


def test_packaged_unbindable_config_raises() -> None:
    check_config_is_fail_closed()


def test_packaged_outcomes_match_the_frozen_chain() -> None:
    run()


def main() -> int:
    try:
        outcomes = run()
    except ConformanceError as exc:
        print(f"JWT BRIDGE FIREWALL: MISMATCH — BLOCKER\n{exc}")
        return 1
    v = load_chain_vector()
    print(
        "JWT BRIDGE FIREWALL: PASS — installed bridge issues the frozen claims and "
        f"refuses on all {len(outcomes) - 1} denial path(s)\n"
        f"  chain        = vaid-mint chain_v1.json, 3 hops, exchanged at "
        f"{v['expected']['verification_instant']}\n"
        f"  chain_sha256 = {FROZEN_CHAIN_SHA256}\n"
        "  token        = verified against the bridge's published JWKS; an "
        "unrelated key does not verify it\n"
        "  config       = an unbindable trust resolver is refused, not tolerated"
    )
    for case in CASES:
        print(f"  {'issue ' if case.expected_issued else 'deny  '} "
              f"{outcomes[case.name]:<34} {case.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
