"""Prove vaid_spiffe.SpiffeMint.mint_root_with_svid against a real SPIRE
server and agent, not the local test CA the package's own tests use.

Runs as the workload a SPIRE registration entry was created for, in a
container that shares the SPIRE agent's Workload API socket. Fetches a real
X.509-SVID and trust bundle through spiffe.workloadapi.WorkloadApiClient,
then hands the DER bytes to the unmodified vaid_spiffe public API exactly as
examples/quickstart.py does with its synthetic certificate.

Checks:
  1. The real SVID mints a VAID that verifies under vaid_mint and carries
     the spiffe_id the real SPIRE agent assigned.
  2. The same real SVID, presented to a mint configured with the wrong
     expected_trust_domain, is refused and nothing is minted.

Exit code 0 means both checks passed against the live deployment.
"""

from __future__ import annotations

import sys
import time
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding

from vaid_mint import InMemoryAudit, MintService, ReferenceIssuer, VaidSeed, prefix_entry
from vaid_mint import build_mint_pop_payload
from vaid_mint.error import IdentityError
from vaid_mint.mint_types import MintPop
from vaid_pop import canonical_request_signing_bytes, utc_whole_second_rfc3339

from spiffe.workloadapi.workload_api_client import WorkloadApiClient
from spiffe.workloadapi.errors import FetchX509SvidError

from vaid_spiffe import SpiffeMint, SvidPresentation
from vaid_spiffe.possession import (
    SvidPossession,
    build_svid_possession_payload,
    canonical_svid_possession_bytes,
)


class LiveProofError(Exception):
    pass


def _sign_with_svid_key(key, message: bytes) -> bytes:
    """Sign with whatever key type the live SVID actually carries. Mirrors
    vaid_spiffe.possession._verify_with_leaf_key's dispatch on the other
    side of the same signature."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(message)
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hashes.SHA256()))
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    raise LiveProofError(f"unsupported SVID private key type: {type(key).__name__}")


def _der_chain(x509_svid) -> tuple[bytes, list[bytes]]:
    chain = x509_svid.cert_chain
    leaf_der = chain[0].public_bytes(serialization.Encoding.DER)
    intermediate_der = [c.public_bytes(serialization.Encoding.DER) for c in chain[1:]]
    return leaf_der, intermediate_der


def _mint_pop(seed: VaidSeed, operating_pub: bytes, operating_key) -> MintPop:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_mint_pop_payload(
        seed, public_key_der=operating_pub, nonce=nonce, issued_at=issued_at
    )
    digest = canonical_request_signing_bytes(payload)
    return MintPop(nonce=nonce, issued_at=issued_at, signature=operating_key.sign(digest))


def _svid_possession(svid_private_key, operating_pub: bytes) -> SvidPossession:
    nonce = uuid.uuid4().hex
    issued_at = utc_whole_second_rfc3339()
    payload = build_svid_possession_payload(
        operating_public_key_der=operating_pub, nonce=nonce, issued_at=issued_at
    )
    signature = _sign_with_svid_key(svid_private_key, canonical_svid_possession_bytes(payload))
    return SvidPossession(nonce=nonce, issued_at=issued_at, signature=signature)


def _build_seed_and_pop():
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
    return seed, pop, operating_pub


def main() -> int:
    passed: list[str] = []

    client = WorkloadApiClient()
    try:
        # The agent's Workload API socket can accept a connection slightly
        # before its gRPC service is actually ready to answer (observed as
        # a "connection reset by peer" on the first attempt right after the
        # agent process starts) - retry with backoff rather than racing it.
        last_exc: Exception | None = None
        ctx = None
        for attempt in range(10):
            try:
                ctx = client.fetch_x509_context(timeout=10)
                break
            except FetchX509SvidError as exc:
                last_exc = exc
                time.sleep(1)
        if ctx is None:
            raise LiveProofError(
                f"could not fetch an X.509 context from the Workload API after retrying: {last_exc}"
            )
    finally:
        client.close()

    svid = ctx.default_svid
    leaf_der, intermediate_der = _der_chain(svid)
    real_spiffe_id = str(svid.spiffe_id)
    trust_domain = str(svid.spiffe_id.trust_domain)

    bundle = ctx.x509_bundle_set.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
    trust_bundle_der = [
        c.public_bytes(serialization.Encoding.DER) for c in bundle.x509_authorities
    ]

    print(f"fetched real SVID from SPIRE: spiffe_id={real_spiffe_id}")
    print(f"leaf not_valid_after: {svid.cert_chain[0].not_valid_after_utc.isoformat()}")
    print(f"trust bundle authorities: {len(trust_bundle_der)}")

    # (1) Real SVID, correct trust domain: mints and verifies.
    audit = InMemoryAudit()
    issuer = ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked()
    mint = SpiffeMint(
        MintService(issuer, audit),
        audit,
        trust_bundle=trust_bundle_der,
        expected_trust_domain=trust_domain,
    )
    seed, pop, operating_pub = _build_seed_and_pop()
    possession = _svid_possession(svid.private_key, operating_pub)
    presentation = SvidPresentation(leaf=leaf_der, intermediates=intermediate_der, possession=possession)

    result = mint.mint_root_with_svid(seed, presentation, pop)
    if not issuer.verify_vaid(result.vaid):
        raise LiveProofError("a VAID minted over a real SPIRE-issued SVID did not verify")
    if result.spiffe_id != real_spiffe_id:
        raise LiveProofError(
            f"minted VAID carried spiffe_id {result.spiffe_id!r}, expected {real_spiffe_id!r}"
        )
    passed.append(
        f"real SPIRE SVID ({real_spiffe_id}) minted a VAID ({result.vaid['vaid_id']}) "
        "that verifies under vaid_mint and carries the correct spiffe_id"
    )

    # (2) Same real SVID, wrong expected_trust_domain: refused, nothing minted.
    audit2 = InMemoryAudit()
    mint2 = SpiffeMint(
        MintService(ReferenceIssuer.ephemeral(1, "vaid.example").assuming_nothing_revoked(), audit2),
        audit2,
        trust_bundle=trust_bundle_der,
        expected_trust_domain="not-" + trust_domain,
    )
    seed2, pop2, operating_pub2 = _build_seed_and_pop()
    possession2 = _svid_possession(svid.private_key, operating_pub2)
    presentation2 = SvidPresentation(leaf=leaf_der, intermediates=intermediate_der, possession=possession2)
    try:
        mint2.mint_root_with_svid(seed2, presentation2, pop2)
    except IdentityError:
        pass
    else:
        raise LiveProofError("a real SVID minted a VAID against a mismatched trust domain")
    if not audit2.is_empty():
        raise LiveProofError("a refused real-SVID mint still wrote an audit record")
    passed.append("the same real SVID, presented against the wrong expected_trust_domain, is refused")

    print(f"\nLIVE SPIRE PROOF: PASS - {len(passed)} check(s)")
    for p in passed:
        print(f" - {p}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except LiveProofError as exc:
        print(f"LIVE SPIRE PROOF: FAIL\n{exc}")
        sys.exit(1)
