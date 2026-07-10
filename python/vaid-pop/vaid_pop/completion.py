"""Completion / provenance record — Python mirror of the Rust
``vaid_pop::request_completion``.

A signed statement that a VAID-authorized action finished, over the SAME
JCS→SHA-256→Ed25519 pipeline as the request PoP (no new crypto). Byte-identity
with the Rust ``CompletionRecord`` is locked by the shared vector
``completion_v1.json``.

SCOPE — self-signed, DECLARED metadata only
-------------------------------------------
The record carries one detached signature by ``signer_vaid_id``. That proves only
that this signer signed the record. The ``assurance_tier`` is therefore
**declared, not proven**:

* ``AssuranceTier.SELF_REPORTED`` is the only tier this repo substantiates on its
  own (actor signs its own outcome; the signature verifies against the actor key).
* ``COUNTER_SIGNED`` / ``THIRD_PARTY_ATTESTED`` are NOT independently verifiable
  from this repo alone — a self-reporting signer can set either and the single
  signature still verifies. Provable counter-signing / third-party attestation is
  a separate, not-yet-built primitive and is OUT OF SCOPE here.
"""

from __future__ import annotations

from enum import Enum


class AssuranceTier(str, Enum):
    """Declared assurance level. String values mirror the Rust enum's
    ``rename_all = "camelCase"`` serialization EXACTLY — these strings go into the
    signed document, so any divergence breaks cross-language byte-identity (this is
    the enum-drift risk the conformance vector guards)."""

    SELF_REPORTED = "selfReported"
    COUNTER_SIGNED = "counterSigned"
    THIRD_PARTY_ATTESTED = "thirdPartyAttested"


def build_completion_record(
    *,
    vaid_id: str,
    request_digest_sha256: str,
    tenant_id: str,
    status: str,
    result_sha256: str,
    completed_at: str,
    signer_vaid_id: str,
    assurance_tier: AssuranceTier | str,
    record_nonce: str,
) -> dict:
    """Assemble the camelCase ``CompletionRecord`` a completer signs.

    Field names/encoding mirror the Rust ``CompletionRecord`` serde exactly. The
    result is a plain ``dict`` (like a ``RequestAuthPayload``) ready for
    ``canonical_request_signing_bytes`` → ``sign``. ``assurance_tier`` accepts the
    :class:`AssuranceTier` enum or its string value; it is written as the string.

    ``completed_at`` MUST be whole-second RFC 3339 ``…Z`` (the same fixed point as
    ``RequestAuthPayload.timestamp``) or byte-identity breaks.
    """
    tier = assurance_tier.value if isinstance(assurance_tier, AssuranceTier) else assurance_tier
    return {
        "vaidId": vaid_id,
        "requestDigestSha256": request_digest_sha256,
        "tenantId": tenant_id,
        "status": status,
        "resultSha256": result_sha256,
        "completedAt": completed_at,
        "signerVaidId": signer_vaid_id,
        "assuranceTier": tier,
        "recordNonce": record_nonce,
    }
