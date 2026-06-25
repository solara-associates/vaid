#!/usr/bin/env python3
"""Emit the Python signer's PoP output for the cross-language firewall.

Reads the vendored vector's `input`, runs the canonical Python signer over it
with the frozen seed/nonce/timestamp, and prints a stable JSON blob:

    {"digest_sha256_hex": "...", "signature_hex": "...",
     "timestamp": "...", "client_nonce": "..."}

The repo-level `pop-conformance` CI job runs this AND the Rust emitter
(`cargo run -p vaid-client --example emit_pop`) and asserts the two blobs
are byte-identical to each other and to the frozen vector. A mismatch is a
hard blocker.
"""

from __future__ import annotations

import base64
import json
from importlib.resources import files

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vaid_pop import HEADER_SIGNATURE, RequestSigner, canonical_request_signing_bytes


def main() -> None:
    vector = json.loads(
        files("vaid_pop").joinpath("vectors/operator_pop_v1.json").read_text()
    )
    inp = vector["input"]
    seed = bytes.fromhex(vector["ed25519"]["private_key_seed_hex"])
    sk = Ed25519PrivateKey.from_private_bytes(seed)

    vaid = {"vaid_id": inp["vaidId"], "tenant_id": inp["tenantId"]}
    signer = RequestSigner(vaid=vaid, private_key=sk)

    # bodySha256 in the vector is sha256("") — sign the empty body so the
    # reconstructed payload equals the vector input exactly.
    from datetime import datetime, timezone

    ts = inp["timestamp"]
    now = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    headers = signer.sign_headers(
        inp["method"], inp["path"], b"", now=now, nonce=inp["clientNonce"]
    )

    digest = canonical_request_signing_bytes(inp)
    sig_hex = base64.b64decode(headers[HEADER_SIGNATURE]).hex()
    out = {
        "digest_sha256_hex": digest.hex(),
        "signature_hex": sig_hex,
        "timestamp": ts,
        "client_nonce": inp["clientNonce"],
    }
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()
