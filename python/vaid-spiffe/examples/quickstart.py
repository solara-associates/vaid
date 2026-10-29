"""Offline quickstart: mint a VAID over a SPIFFE SVID with no live SPIRE.

Generates a throwaway trust root and SVID leaf locally (standing in for
what a real SPIRE deployment would hand you), then runs the full
verify-SVID -> prove-possession -> mint-VAID path end to end.

Run with:  python examples/quickstart.py
"""

from __future__ import annotations

import datetime
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339
from vaid_mint import build_mint_pop_payload
from vaid_mint.mint_types import MintPop

from vaid_spiffe import SpiffeMint, SvidPresentation
from vaid_spiffe.possession import SvidPossession, build_svid_possession_payload, canonical_svid_possession_bytes

TRUST_DOMAIN = "quickstart.example"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def make_trust_domain_and_svid():
    """Stand-in for what a real SPIRE server would issue: a trust root and an
    SVID leaf for one workload, both ECDSA P-256."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "quickstart trust root")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    spiffe_id = f"spiffe://{TRUST_DOMAIN}/agent/researcher"
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "researcher")]))
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
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.DER),
        leaf_cert.public_bytes(serialization.Encoding.DER),
        leaf_key,
        spiffe_id,
    )


def main() -> None:
    trust_bundle_der, leaf_der, leaf_key, expected_spiffe_id = make_trust_domain_and_svid()

    # Mint-side setup: an ephemeral reference issuer and the SPIFFE mint.
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    audit = InMemoryAudit()
    spiffe_mint = SpiffeMint(
        MintService(issuer, audit),
        audit,
        trust_bundle=[trust_bundle_der],
        expected_trust_domain=TRUST_DOMAIN,
    )

    # Holder side: a fresh Ed25519 operating key for the VAID itself.
    operating_key = ed25519.Ed25519PrivateKey.generate()
    operating_pub = operating_key.public_key().public_bytes_raw()
    seed = VaidSeed(
        agent_class="researcher",
        version="1.0.0",
        tenant_id="acme",
        scope_boundary=[prefix_entry("data.acme")],
        capability_set=["read"],
        public_key_der=operating_pub,
    )

    # Proof-of-possession for the operating key (the unmodified vaid_mint path).
    pop_nonce = uuid.uuid4().hex
    pop_issued_at = utc_whole_second_rfc3339()
    pop_payload = build_mint_pop_payload(
        seed, public_key_der=operating_pub, nonce=pop_nonce, issued_at=pop_issued_at
    )
    pop = MintPop(
        nonce=pop_nonce,
        issued_at=pop_issued_at,
        signature=operating_key.sign(canonical_request_signing_bytes(pop_payload)),
    )

    # Proof-of-possession for the SVID's own key, binding the operating key.
    svid_nonce = uuid.uuid4().hex
    svid_issued_at = utc_whole_second_rfc3339()
    possession_payload = build_svid_possession_payload(
        operating_public_key_der=operating_pub, nonce=svid_nonce, issued_at=svid_issued_at
    )
    possession = SvidPossession(
        nonce=svid_nonce,
        issued_at=svid_issued_at,
        signature=leaf_key.sign(
            canonical_svid_possession_bytes(possession_payload), ec.ECDSA(hashes.SHA256())
        ),
    )

    result = spiffe_mint.mint_root_with_svid(
        seed, SvidPresentation(leaf=leaf_der, intermediates=[], possession=possession), pop
    )

    assert issuer.verify_vaid(result.vaid)
    assert result.spiffe_id == expected_spiffe_id

    print(f"minted vaid_id:   {result.vaid['vaid_id']}")
    print(f"bound spiffe_id:  {result.spiffe_id}")
    print(f"trust_domain:     {result.trust_domain}")
    print(f"audit events:     {[e.event_type for e in audit.entries]}")


if __name__ == "__main__":
    main()
