"""Packaged conformance check - the firewall, shipped in the wheel.

This package implements no new cryptographic primitive of its own (minting
defers entirely to ``vaid_mint``; SPIFFE ID parsing defers entirely to
``spiffe``), so there is no byte-identity vector to pin the way
``vaid-mint-conformance`` does. What is worth proving from a clean,
wheel-only install is that the documented bind-by-reference path actually
runs end to end, and that its fail-closed checks actually fail closed - the
same reasoning ``npm/vaid-skill``'s ``verify_cmd`` uses for the same shape of
package.

A consumer who has only ``pip install vaid-spiffe`` can run::

    python -m vaid_spiffe.conformance     # exit 0 = PASS, 1 = BLOCKER
    vaid-spiffe-conformance                # same, via the console entry point

This generates its own throwaway trust root and SVID in-process (no live
SPIRE, no network) and checks:

1. A valid SVID mints a VAID that verifies under ``vaid_mint`` and carries
   the correct ``spiffe://`` ID.
2. An SVID in the wrong trust domain is refused, and nothing is minted.
3. A leaf with no URI SAN is refused, and nothing is minted.
"""

from __future__ import annotations

import datetime
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_mint import build_mint_pop_payload
from vaid_mint.error import IdentityError
from vaid_mint.mint_types import MintPop
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from vaid_spiffe import SpiffeMint, SvidPresentation
from vaid_spiffe.possession import (
    SvidPossession,
    build_svid_possession_payload,
    canonical_svid_possession_bytes,
)

TRUST_DOMAIN = "vaid-spiffe-conformance.test"


class ConformanceError(Exception):
    pass


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _key_usage(key_cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=key_cert_sign,
        crl_sign=key_cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance trust root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(key_cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, *, spiffe_id: str | None):
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance svid")]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if spiffe_id is not None:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return leaf_key, cert


def _mint_pop(seed: VaidSeed, operating_pub: bytes, operating_key) -> MintPop:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(
        seed, public_key_der=operating_pub, nonce=nonce, issued_at=issued_at
    )
    digest = canonical_request_signing_bytes(payload)
    return MintPop(nonce=nonce, issued_at=issued_at, signature=operating_key.sign(digest))


def _svid_possession(leaf_key, operating_pub: bytes) -> SvidPossession:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_svid_possession_payload(
        operating_public_key_der=operating_pub, nonce=nonce, issued_at=issued_at
    )
    signature = leaf_key.sign(canonical_svid_possession_bytes(payload), ec.ECDSA(hashes.SHA256()))
    return SvidPossession(nonce=nonce, issued_at=issued_at, signature=signature)


def _build_mint(trust_bundle_der: list[bytes], trust_domain: str):
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    mint = SpiffeMint(
        MintService(issuer, audit),
        audit,
        trust_bundle=trust_bundle_der,
        expected_trust_domain=trust_domain,
    )
    return mint, audit, issuer


def run() -> list[str]:
    """Run every check; return the list of checks that passed, or raise
    :class:`ConformanceError` naming the first one that didn't."""
    passed: list[str] = []
    ca_key, ca_cert = _make_ca()
    trust_bundle_der = [ca_cert.public_bytes(serialization.Encoding.DER)]

    # (1) Valid SVID mints, verifies, carries the right spiffe_id.
    spiffe_id = f"spiffe://{TRUST_DOMAIN}/agent/conformance"
    leaf_key, leaf_cert = _make_leaf(ca_key, ca_cert, spiffe_id=spiffe_id)
    mint, audit, issuer = _build_mint(trust_bundle_der, TRUST_DOMAIN)
    operating_key = ed25519.Ed25519PrivateKey.generate()
    operating_pub = operating_key.public_key().public_bytes_raw()
    seed = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=operating_pub,
    )
    pop = _mint_pop(seed, operating_pub, operating_key)
    possession = _svid_possession(leaf_key, operating_pub)
    presentation = SvidPresentation(
        leaf=leaf_cert.public_bytes(serialization.Encoding.DER), intermediates=[], possession=possession
    )
    result = mint.mint_root_with_svid(seed, presentation, pop)
    if not issuer.verify_vaid(result.vaid):
        raise ConformanceError("a VAID minted over a valid SVID did not verify")
    if result.spiffe_id != spiffe_id:
        raise ConformanceError(
            f"minted VAID carried spiffe_id {result.spiffe_id!r}, expected {spiffe_id!r}"
        )
    passed.append("valid SVID mints, verifies, and carries the correct spiffe_id")

    # (2) Wrong trust domain is refused, nothing minted.
    mint2, audit2, _ = _build_mint(trust_bundle_der, "a-different-trust-domain.test")
    operating_key2 = ed25519.Ed25519PrivateKey.generate()
    operating_pub2 = operating_key2.public_key().public_bytes_raw()
    seed2 = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=operating_pub2,
    )
    pop2 = _mint_pop(seed2, operating_pub2, operating_key2)
    possession2 = _svid_possession(leaf_key, operating_pub2)
    presentation2 = SvidPresentation(
        leaf=leaf_cert.public_bytes(serialization.Encoding.DER), intermediates=[], possession=possession2
    )
    try:
        mint2.mint_root_with_svid(seed2, presentation2, pop2)
    except IdentityError:
        pass
    else:
        raise ConformanceError("an SVID in the wrong trust domain minted a VAID")
    if not audit2.is_empty():
        raise ConformanceError("a refused SVID mint still wrote an audit record")
    passed.append("SVID in the wrong trust domain is refused, nothing minted")

    # (3) Leaf with no URI SAN is refused, nothing minted.
    bare_leaf_key, bare_leaf_cert = _make_leaf(ca_key, ca_cert, spiffe_id=None)
    mint3, audit3, _ = _build_mint(trust_bundle_der, TRUST_DOMAIN)
    operating_key3 = ed25519.Ed25519PrivateKey.generate()
    operating_pub3 = operating_key3.public_key().public_bytes_raw()
    seed3 = VaidSeed(
        agent_class="runner",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=operating_pub3,
    )
    pop3 = _mint_pop(seed3, operating_pub3, operating_key3)
    possession3 = _svid_possession(bare_leaf_key, operating_pub3)
    presentation3 = SvidPresentation(
        leaf=bare_leaf_cert.public_bytes(serialization.Encoding.DER),
        intermediates=[],
        possession=possession3,
    )
    try:
        mint3.mint_root_with_svid(seed3, presentation3, pop3)
    except IdentityError:
        pass
    else:
        raise ConformanceError("a leaf with no URI SAN minted a VAID")
    if not audit3.is_empty():
        raise ConformanceError("a refused SVID mint (no URI SAN) still wrote an audit record")
    passed.append("leaf with no URI SAN is refused, nothing minted")

    return passed


def main() -> int:
    try:
        checks = run()
    except ConformanceError as exc:
        print(f"VAID-SPIFFE FIREWALL: FAIL - BLOCKER\n{exc}")
        return 1
    print(f"VAID-SPIFFE FIREWALL: PASS - {len(checks)} check(s)")
    for c in checks:
        print(f" - {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
