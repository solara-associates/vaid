"""Packaged firewall: runs the installed wheel's four tool handlers against
fixed known-good and known-bad chains, and fails if any verdict is wrong.

vaid-mcp performs no cryptography of its own — see the module docstring in
`server.py` — so there is no byte-identity vector to re-check here. What this
proves from a clean install is the thing that IS specific to this package:
that the tool functions, called the way the MCP server calls them, reach the
verdicts this package documents.
"""

from __future__ import annotations

import sys

from vaid_mcp.chains import verify_chain_result
from vaid_mcp.demo import mint_demo_chain
from vaid_mcp.explain import explain_vaid
from vaid_mcp.keys import resolve_keys
from vaid_mcp.scope import check_scope


def _check(label: str, condition: bool, failures: list[str]) -> None:
    if not condition:
        failures.append(label)


def main() -> int:
    failures: list[str] = []

    demo = mint_demo_chain(resource="conformance.sandbox", capability="read")
    chain = {"leaf": demo.child, "ancestors": [demo.root]}
    good_keys = resolve_keys(public_key=demo.kernel_public_key_hex, key_url=None)

    result = verify_chain_result(chain, good_keys)
    _check("fresh demo chain verifies as attenuated", result.verdict.is_attenuated(), failures)

    scope_ok = check_scope(chain, good_keys, "read", "conformance.sandbox")
    _check("check_scope permits the capability the demo chain was minted with", scope_ok.permitted is True, failures)

    scope_denied = check_scope(chain, good_keys, "delete", "conformance.sandbox")
    _check("check_scope denies a capability the leaf was not minted with", scope_denied.permitted is False, failures)

    explanation = explain_vaid(demo.child)
    _check("explain_vaid reports the demo child as not a root", not explanation.is_root, failures)
    _check("explain_vaid names the demo child's parent", explanation.parent_vaid == demo.root["vaid_id"], failures)

    tampered = dict(demo.child)
    tampered["capability_set"] = list(tampered["capability_set"]) + ["admin"]
    tampered_result = verify_chain_result({"leaf": tampered, "ancestors": [demo.root]}, good_keys)
    _check("a tampered leaf is INAUTHENTIC, not attenuated", tampered_result.verdict.value == "inauthentic", failures)

    other_demo = mint_demo_chain(resource="unrelated.sandbox", capability="read")
    wrong_keys = resolve_keys(public_key=other_demo.kernel_public_key_hex, key_url=None)
    unknown_key_result = verify_chain_result(chain, wrong_keys)
    _check("an unknown signing key is INAUTHENTIC", unknown_key_result.verdict.value == "inauthentic", failures)

    if failures:
        print("✗ vaid-mcp conformance FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  · {f}", file=sys.stderr)
        return 1

    print("✓ vaid-mcp conformance — all tool handlers reached the documented verdicts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
