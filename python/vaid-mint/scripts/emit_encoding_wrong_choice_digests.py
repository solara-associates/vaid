#!/usr/bin/env python3
"""Recompute the `docs/spec/encoding.md` E.13 "what a wrong choice produces"
tables.

E.13 states that every digest in it is a COMPUTED value rather than an asserted
one, and that a stale row there is the documentation defect E.11 exists to shame.
Until this script existed there was no way to recompute them, so each wire change
left the tables silently wrong: the v4 re-freeze (ADR-0009) moved all nineteen.

# Proving the instrument

Run with ``--vectors`` pointing at a tree of v3 vectors and this reproduces every
digest the v3 tables carried, byte for byte. That is the check that each
transformation below is the one the table's prose actually names, and it is why
``E.4`` converts ``public_key_der`` ALONE (``kernel_signature`` is nulled before
canonicalization, so including it changes the answer) and why the ``E.16``
raw-key row uses the KERNEL public key rather than the document's
``public_key_der`` (the thumbprint commits to the signer's key, not the holder's).
Both were recovered by matching the committed v3 digests rather than guessed.

Run from ``python/vaid-mint``:

    PYTHONPATH=.:../vaid-pop python3 scripts/emit_encoding_wrong_choice_digests.py
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path

from vaid_pop import canonical_request_signing_bytes

THUMBPRINT_URI_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"


def digest(doc: dict) -> str:
    """JCS (RFC 8785) then SHA-256, which is what both signed structures use."""
    return canonical_request_signing_bytes(doc).hex()


def _camel(key: str) -> str:
    head, *rest = key.split("_")
    return head + "".join(w[:1].upper() + w[1:] for w in rest)


def _snake(key: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def document_rows(inp: dict, kernel_public_key: bytes) -> list[tuple[str, str, str]]:
    """``(rule, choice, digest)`` for the VAID-document table."""
    # The correct bytes null `kernel_signature` rather than dropping or keeping it
    # (E.5), so every row below starts from the nulled document.
    base = {**inp, "kernel_signature": None}
    public_key = bytes(inp["public_key_der"])
    bare_thumbprint = inp["kernel_key_thumbprint"].rsplit(":", 1)[-1]
    raw_thumbprint = base64.urlsafe_b64decode(
        bare_thumbprint + "=" * (-len(bare_thumbprint) % 4)
    )
    rows: list[tuple[str, str, str]] = [
        ("—", "**Correct — all rules applied**", digest(base)),
        ("E.3", "Document keys camelCased", digest({_camel(k): v for k, v in base.items()})),
        (
            "E.4",
            "Byte fields as base64 strings",
            digest({**base, "public_key_der": base64.b64encode(public_key).decode()}),
        ),
        (
            "E.4",
            "Byte fields as hex strings",
            digest({**base, "public_key_der": public_key.hex()}),
        ),
        (
            "E.5",
            "`kernel_signature` key deleted",
            digest({k: v for k, v in base.items() if k != "kernel_signature"}),
        ),
        ("E.5", "`kernel_signature` left as `[]`", digest({**base, "kernel_signature": []})),
        (
            "E.6",
            "Timestamps with milliseconds",
            digest(
                {
                    **base,
                    "issued_at": inp["issued_at"].replace("Z", ".000Z"),
                    "expires_at": inp["expires_at"].replace("Z", ".000Z"),
                }
            ),
        ),
        (
            "E.6",
            "Timestamps with a `+00:00` offset",
            digest(
                {
                    **base,
                    "issued_at": inp["issued_at"].replace("Z", "+00:00"),
                    "expires_at": inp["expires_at"].replace("Z", "+00:00"),
                }
            ),
        ),
        (
            "E.7",
            "`parent_vaid` key omitted (its value here is a UUID, not null — the "
            "null case is exercised by `mint_pop_v1` below)",
            digest({k: v for k, v in base.items() if k != "parent_vaid"}),
        ),
        (
            "E.8",
            f'`sig_version` as the string `"{inp["sig_version"]}"`',
            digest({**base, "sig_version": str(inp["sig_version"])}),
        ),
        (
            "E.15",
            "`trust_domain` uppercased — i.e. normalized rather than rejected",
            digest({**base, "trust_domain": inp["trust_domain"].upper()}),
        ),
        (
            "E.15",
            "`trust_domain` with a trailing dot",
            digest({**base, "trust_domain": inp["trust_domain"] + "."}),
        ),
        (
            "E.16",
            "`kernel_key_thumbprint` as a bare thumbprint, RFC 9278 URI prefix dropped",
            digest({**base, "kernel_key_thumbprint": bare_thumbprint}),
        ),
        (
            "E.16",
            "Thumbprint base64 (standard alphabet, padded) instead of base64url unpadded",
            digest(
                {
                    **base,
                    "kernel_key_thumbprint": THUMBPRINT_URI_PREFIX
                    + base64.b64encode(raw_thumbprint).decode(),
                }
            ),
        ),
        (
            "E.16",
            "Raw public key in place of its hash — the thumbprint never computed",
            digest(
                {
                    **base,
                    "kernel_key_thumbprint": THUMBPRINT_URI_PREFIX
                    + base64.urlsafe_b64encode(kernel_public_key).decode().rstrip("="),
                }
            ),
        ),
    ]
    boundary = inp.get("scope_boundary") or []
    if boundary and isinstance(boundary[0], dict):
        rows.append(
            (
                "S.8",
                "`scope_boundary` entries as bare strings, the pre-v4 form",
                digest({**base, "scope_boundary": [e["value"] for e in boundary]}),
            )
        )
    return rows


def pop_rows(inp: dict) -> list[tuple[str, str, str]]:
    """``(rule, choice, digest)`` for the `MintPopPayload` table."""
    rows: list[tuple[str, str, str]] = [
        ("—", "**Correct — all rules applied**", digest(inp)),
        (
            "E.3",
            "Payload keys snake_cased (the inverse error)",
            digest({_snake(k): v for k, v in inp.items()}),
        ),
        (
            "E.4",
            "`publicKeyDer` as a base64 string",
            digest(
                {**inp, "publicKeyDer": base64.b64encode(bytes(inp["publicKeyDer"])).decode()}
            ),
        ),
        (
            "E.7",
            "`parentVaid` key omitted instead of null",
            digest({k: v for k, v in inp.items() if k != "parentVaid"}),
        ),
        ("E.7", '`parentVaid` as the empty string `""`', digest({**inp, "parentVaid": ""})),
    ]
    boundary = inp.get("scopeBoundary") or []
    if boundary and isinstance(boundary[0], dict):
        rows.append(
            (
                "S.8",
                "`scopeBoundary` entries as bare strings, the pre-v4 form",
                digest({**inp, "scopeBoundary": [e["value"] for e in boundary]}),
            )
        )
    return rows


def render(rows: list[tuple[str, str, str]]) -> str:
    lines = ["| Rule | Choice | Resulting digest |", "|---|---|---|"]
    lines += [f"| {rule} | {choice} | `{value}` |" for rule, choice, value in rows]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vectors",
        default=str(Path(__file__).resolve().parents[1] / "vaid_mint" / "vectors"),
        help="directory holding mint_v1.json and mint_pop_v1.json",
    )
    args = parser.parse_args()
    root = Path(args.vectors)
    mint = json.loads((root / "mint_v1.json").read_text())
    pop = json.loads((root / "mint_pop_v1.json").read_text())
    kernel_public_key = bytes.fromhex(mint["ed25519"]["kernel_public_key_hex"])

    print("### VAID document (mint_v1)\n")
    print(render(document_rows(mint["input"], kernel_public_key)))
    print("\n### MintPopPayload (mint_pop_v1)\n")
    print(render(pop_rows(pop["input"])))


if __name__ == "__main__":
    main()
