//! `max_delegation_depth` validation — cross-language agreement (0.11.0, spec
//! `docs/spec/delegation.md`).
//!
//! Delegation-depth limiting is **outside the conformance surface** — it is
//! mint policy, not a protocol rule — so this is deliberately not a frozen
//! vector. The scenario table below is mirrored byte-for-intent by the Python
//! (`python/vaid-mint/tests/test_delegation_depth_validation.py`) and
//! TypeScript (`typescript/vaid-mint/test/delegation_depth_validation.test.ts`)
//! suites, which assert the identical (depth -> valid/invalid) mapping. There
//! is no shared vector: the three languages agree by construction.
//!
//! Only depths expressible as a plain non-negative integer in all three
//! languages are in this shared table. Each language additionally tests its
//! own dynamic-input edge cases (a float, `NaN`, `Infinity`, `None`/`null`, a
//! string, a bool) in its own unit tests, since Rust's `usize` parameter type
//! rules those out at compile time and has nothing to agree with.

use vaid_mint::mint::{validate_max_delegation_depth, DEFAULT_MAX_DELEGATION_DEPTH};
use vaid_mint::revocation::MAX_LINEAGE_DEPTH;

#[test]
fn cross_language_scenarios() {
    // (depth, is_valid)
    let cases: &[(usize, bool)] = &[
        (0, false),                     // zero: no value means "unlimited"
        (1, true),                      // the default
        (2, true),                      // a deeper, explicitly configured limit
        (MAX_LINEAGE_DEPTH, true),      // at the bound: accepted
        (MAX_LINEAGE_DEPTH + 1, false), // one past the bound: rejected
    ];

    for &(depth, expected_valid) in cases {
        let result = validate_max_delegation_depth(depth);
        assert_eq!(
            result.is_ok(),
            expected_valid,
            "depth {depth}: expected valid={expected_valid}, got {result:?}"
        );
    }
}

#[test]
fn the_default_is_itself_valid() {
    assert!(validate_max_delegation_depth(DEFAULT_MAX_DELEGATION_DEPTH).is_ok());
}
