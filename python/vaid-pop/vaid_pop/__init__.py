"""vaid-pop — canonical Python proof-of-possession request signer.

The single Python definition of the VAID PoP signing contract. Import this
package directly to sign a VAID-bound request without pulling in a framework
(language-specific agent integrations depend on this package and re-export the
signer). Byte-identity with the Rust client (`vaid-client`) and the verifier
(`vaid_pop`) is locked by the vendored cross-language vector
``vaid_pop/vectors/operator_pop_v1.json``.

Usage::

    from vaid_pop import RequestSigner

    signer = RequestSigner(vaid=vaid_doc, private_key=agent_key)
    headers = signer.sign_headers("POST", "/vaid/mint", body_bytes)
"""

from vaid_pop.completion import AssuranceTier, build_completion_record
from vaid_pop.signer import (
    HEADER_NONCE,
    HEADER_SIGNATURE,
    HEADER_TIMESTAMP,
    HEADER_VAID,
    RequestSigner,
    build_request_auth_payload,
    canonical_request_signing_bytes,
    utc_whole_second_rfc3339,
)

__all__ = [
    "RequestSigner",
    "canonical_request_signing_bytes",
    "build_request_auth_payload",
    "utc_whole_second_rfc3339",
    "AssuranceTier",
    "build_completion_record",
    "HEADER_VAID",
    "HEADER_TIMESTAMP",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
]

__version__ = "0.1.0"
