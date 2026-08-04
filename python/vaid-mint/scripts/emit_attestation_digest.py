"""Byte-agreement probe for the detached consent attestation format. Python side.

Run with ``python3 scripts/emit_attestation_digest.py`` from ``python/vaid-mint``.

Deliberately NOT a frozen vector, and nothing vendors its output. The attestation is
a new signed object; freezing its canonicalization is the one decision here that is
expensive to unwind, so the format stays reviewable until it has been reviewed. What
this proves in the meantime is the property a vector would prove — that all three
implementations canonicalize and sign the same bytes — without committing to the
shape.

Emits byte-identical JSON to the Rust and TypeScript probes;
``scripts/attestation_byte_agreement.sh`` runs all three and diffs them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Run from a source checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "vaid-pop"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from vaid_mint.attestation import (  # noqa: E402
    build_unsigned_attestation,
    canonical_attestation_signing_bytes,
)
from vaid_mint.issuer_identity import kernel_key_thumbprint  # noqa: E402

KERNEL_SEED_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PARENT_UUID = "d0000000-0000-0000-0000-000000000001"
CHILD_UUID = "d0000000-0000-0000-0000-000000000002"

COMMENT = (
    "Byte-agreement probe for the consent attestation format. NOT A FROZEN VECTOR "
    "and not vendored anywhere. All three implementations must emit this file "
    "byte-identically; scripts/attestation_byte_agreement.sh checks it."
)


def main() -> None:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(KERNEL_SEED_HEX))
    kernel_pub = key.public_key().public_bytes_raw()

    unsigned = build_unsigned_attestation(
        parent_vaid=PARENT_UUID,
        child_vaid=CHILD_UUID,
        child_trust_domain="b.example",
        child_tenant_id="aifactory",
        scope_boundary=["data.aifactory.sub"],
        capability_set=["read"],
        trust_domain="a.example",
        kernel_key_thumbprint=kernel_key_thumbprint(kernel_pub),
    )

    digest = canonical_attestation_signing_bytes(unsigned)
    signature = key.sign(digest)

    out = {
        "_comment": COMMENT,
        "attestation": unsigned,
        "digest_sha256_hex": digest.hex(),
        "kernel_public_key_hex": kernel_pub.hex(),
        "signature_hex": signature.hex(),
    }
    # sort_keys + 2-space indent matches serde_json::to_string_pretty over a
    # BTreeMap-ordered Value, so the three probes are diffable as text.
    print(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
