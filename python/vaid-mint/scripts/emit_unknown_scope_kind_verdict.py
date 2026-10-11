#!/usr/bin/env python3
"""The verdicts this implementation returns for an UNRECOGNISED scope-boundary
kind, as JSON, for cross-language comparison (spec S.10, ADR-0009).

Mirror of the Rust ``emit_unknown_scope_kind_verdict`` example and the TypeScript
``emit-unknown-scope-kind-verdict.mjs``;
``scripts/unknown_scope_kind_agreement.sh`` runs all three and diffs the output.
See the Rust example for why this exists as well as the per-language vector
assertions.

Run from ``python/vaid-mint``:

    PYTHONPATH=.:../vaid-pop python3 scripts/emit_unknown_scope_kind_verdict.py
"""

from __future__ import annotations

import json
from importlib.resources import files

from vaid_mint.mint import scope_attenuation_reason
from vaid_mint.revocation import RevocationStatus
from vaid_mint.verify import verify_vaid_standing_from_json


def _vector(name: str) -> dict:
    return json.loads(files("vaid_mint").joinpath(f"vectors/{name}").read_text())


def main() -> None:
    verdict = _vector("verdict_v1.json")
    kinds = _vector("scope_kinds_v1.json")
    kernel_pk = bytes.fromhex(verdict["ed25519"]["kernel_public_key_hex"])

    # The STANDING surface: an authentic, unexpired, unrevoked document whose
    # boundary names a kind no v4 verifier recognises.
    standing = []
    for case in verdict["cases"]:
        if case.get("expected_reason") != "unknown_scope_kind":
            continue
        text = case.get("document_json")
        if text is None:
            continue
        got = verify_vaid_standing_from_json(kernel_pk, text, RevocationStatus.NOT_REVOKED)
        standing.append(
            {"case": case["name"], "reason": got.value, "valid": got.is_valid()}
        )

    # The ATTENUATION surface: an unreadable kind on either side of a hop.
    attenuation = []
    for case in kinds["attenuation_cases"]:
        if case.get("expected_reason") != "unknown_scope_kind":
            continue
        reason = scope_attenuation_reason(case["parent_scope"], case["child_scope"])
        attenuation.append({"case": case["name"], "reason": reason.value})

    # A refusal over zero inputs is not a reading. Asserted here rather than only
    # in the shell script, so an emitter that silently found nothing cannot be
    # diffed against another that also found nothing and report agreement.
    assert standing, "verdict_v1.json carries no unknown_scope_kind standing case"
    assert attenuation, "scope_kinds_v1.json carries no unknown_scope_kind attenuation case"

    print(
        json.dumps(
            {
                "surface": "unknown scope kind (spec S.10, ADR-0009)",
                "standing": standing,
                "attenuation": attenuation,
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
