"""Local test CA + SVID fixtures. No live SPIRE: every certificate here is
generated in-process with ``cryptography`` so the test suite is hermetic."""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def make_root_ca(common_name: str = "test trust root"):
    """A self-signed CA keypair, EC P-256."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(days=365))
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
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_svid_leaf(
    ca_key,
    ca_cert,
    *,
    spiffe_id: str,
    leaf_key=None,
    not_before_delta: datetime.timedelta = datetime.timedelta(hours=-1),
    not_after_delta: datetime.timedelta = datetime.timedelta(hours=1),
    extra_uri_sans: list[str] = (),
    omit_san: bool = False,
):
    """An SVID leaf signed by ``ca_key``/``ca_cert``, carrying ``spiffe_id`` as
    its (by default, sole) URI SAN. ``leaf_key`` defaults to a fresh EC P-256
    key; pass an Ed25519 or RSA key to exercise those possession branches."""
    if leaf_key is None:
        leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test svid")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() + not_before_delta)
        .not_valid_after(_now() + not_after_delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if not omit_san:
        uris = [x509.UniformResourceIdentifier(spiffe_id)]
        uris += [x509.UniformResourceIdentifier(u) for u in extra_uri_sans]
        builder = builder.add_extension(x509.SubjectAlternativeName(uris), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    return leaf_key, cert


@pytest.fixture
def trust_domain() -> str:
    return "vaid-spiffe.test"


@pytest.fixture
def ca(trust_domain):
    return make_root_ca(f"CA for {trust_domain}")


@pytest.fixture
def valid_svid(ca, trust_domain):
    ca_key, ca_cert = ca
    spiffe_id = f"spiffe://{trust_domain}/agent/researcher"
    leaf_key, leaf_cert = make_svid_leaf(ca_key, ca_cert, spiffe_id=spiffe_id)
    return {
        "leaf_key": leaf_key,
        "leaf_cert": leaf_cert,
        "leaf_der": leaf_cert.public_bytes(serialization.Encoding.DER),
        "trust_bundle_der": [ca_cert.public_bytes(serialization.Encoding.DER)],
        "spiffe_id": spiffe_id,
    }
