"""``max_delegation_depth`` validation — cross-language agreement (0.11.0,
spec ``docs/spec/delegation.md``).

Delegation-depth limiting is **outside the conformance surface** — it is
mint policy, not a protocol rule — so this is deliberately not a frozen
vector. The scenario table below is mirrored byte-for-intent by the Rust
(``crates/vaid-mint/tests/delegation_depth_validation.rs``) and TypeScript
(``typescript/vaid-mint/test/delegation_depth_validation.test.ts``) suites,
which assert the identical (depth -> valid/invalid) mapping. There is no
shared vector: the three languages agree by construction.

Only depths expressible as a plain non-negative integer in all three
languages are in the shared table below. Python's own dynamic-input edge
cases (a float, NaN, Infinity, None, a string, a bool) are covered in
``test_mint_behavior.py``, since Rust's ``usize`` parameter type rules those
out at compile time and has nothing to agree with.
"""

from __future__ import annotations

import pytest

from vaid_mint import validate_max_delegation_depth, DEFAULT_MAX_DELEGATION_DEPTH
from vaid_mint.error import ConfigError
from vaid_mint.revocation import MAX_LINEAGE_DEPTH

CASES = [
    (0, False),  # zero: no value means "unlimited"
    (1, True),  # the default
    (2, True),  # a deeper, explicitly configured limit
    (MAX_LINEAGE_DEPTH, True),  # at the bound: accepted
    (MAX_LINEAGE_DEPTH + 1, False),  # one past the bound: rejected
]


@pytest.mark.parametrize("depth,expected_valid", CASES)
def test_cross_language_scenarios(depth, expected_valid):
    if expected_valid:
        assert validate_max_delegation_depth(depth) == depth
    else:
        with pytest.raises(ConfigError):
            validate_max_delegation_depth(depth)


def test_the_default_is_itself_valid():
    assert validate_max_delegation_depth(DEFAULT_MAX_DELEGATION_DEPTH) == (
        DEFAULT_MAX_DELEGATION_DEPTH
    )
