//! Quantitative delegation caveats — budget scope kinds (`docs/spec/budget.md`,
//! ADR-0011).
//!
//! A budget caveat is a `scope_boundary` entry of a **recognised, non-resource-
//! shaped kind**. ADR-0009 built the typed-kind extension point for exactly this
//! ("a limit on an amount" is the first example in its own Context section), and
//! S.12 of `docs/spec/scope.md` already states the division: `scope_boundary` is
//! *where*, `capability_set` is *what*, and a condition on an action — a maximum
//! amount, a rate, a qualifier — is a future scope kind, never a new document
//! member (ADR-0006 would make old verifiers preserve-and-ignore it, which fails
//! open silently) and never a decoration on a capability string (S.12: capability
//! matching is exact equality and cannot carry a condition without becoming a
//! typed member itself).
//!
//! # Why this is a SEPARATE module from [`crate::document`]'s scope matcher
//!
//! `docs/spec/scope.md` S.13 flags this directly as a constraint on "whoever adds
//! kind number two": the `prefix` kind is decidable by projecting a child entry's
//! `value` AS IF it were a resource and feeding it back into the same matcher
//! (`entry_claimed_resource` + `scope_contains`) — "that projection does not
//! generalise." A budget entry has no resource to claim; its containment question
//! is `child.limit <= parent.limit` for a *matching* (kind, scope) pair, which is
//! a different predicate entirely. So budget kinds are RECOGNISED (added to the
//! S.10 refusal registry, via [`is_recognised_kind`]) but are deliberately absent
//! from [`crate::document::entry_contains`] and
//! [`crate::document::entry_claimed_resource`] — the resource matcher does not
//! grow a kind it cannot meaningfully answer for. Instead:
//!
//! - [`crate::document::scope_contains`] treats a recognised budget-kind entry as
//!   transparent to resource containment — it neither grants nor withholds reach,
//!   because budget is a third axis orthogonal to *where* (S.12 extended: "scope
//!   is where, capabilities are what, budget is how much").
//! - [`budget_attenuation_reason`] is the budget-specific containment rule,
//!   called ADDITIONALLY alongside [`crate::mint::scope_attenuates`] — the same
//!   "one matcher, independent call sites" pattern ADR-0007 used for expiry,
//!   which is also not resource-shaped and also lives beside, not inside, the
//!   `prefix` matcher.
use std::collections::BTreeMap;

use crate::document::ScopeBoundaryEntry;

/// A ceiling on cumulative model-call cost, in micro-USD (1 unit = $0.000001).
/// Singleton: at most one entry of this kind per boundary.
pub const BUDGET_KIND_COST_USD_MICRO: &str = "budget_cost_usd_micro";

/// A ceiling on cumulative token usage (input + output, summed). Singleton.
pub const BUDGET_KIND_TOKENS: &str = "budget_tokens";

/// A ceiling on a count of calls. NOT a singleton: an entry's `value.scope`
/// names what it counts (`"*"` for every tool, or `"tool:<name>"` for one), so a
/// boundary may carry a total-calls entry and any number of per-tool entries.
pub const BUDGET_KIND_CALLS: &str = "budget_calls";

/// A ceiling on wall-clock seconds since `issued_at`. Singleton. This is
/// deliberately distinct from `expires_at` (ADR-0007, an absolute deadline
/// clamped at mint): a wall-clock BUDGET is a duration, re-anchored to whenever
/// the VAID was actually issued, which `expires_at` alone cannot express for a
/// child minted well after its parent.
pub const BUDGET_KIND_WALL_CLOCK_S: &str = "budget_wall_clock_s";

/// THE budget-kind registry — stated once, the same discipline
/// `RECOGNISED_SCOPE_KINDS` documents for the same reason: two copies is how a
/// kind gets recognised by one code path and not another.
pub const RECOGNISED_BUDGET_KINDS: [&str; 4] = [
    BUDGET_KIND_COST_USD_MICRO,
    BUDGET_KIND_TOKENS,
    BUDGET_KIND_CALLS,
    BUDGET_KIND_WALL_CLOCK_S,
];

/// Kinds for which a boundary may carry at most one entry. `budget_calls` is
/// excluded: it is differentiated by `value.scope`, so several entries (one
/// total, several per-tool) are the normal, well-formed case.
const SINGLETON_BUDGET_KINDS: [&str; 3] = [
    BUDGET_KIND_COST_USD_MICRO,
    BUDGET_KIND_TOKENS,
    BUDGET_KIND_WALL_CLOCK_S,
];

/// Is `kind` one of this build's recognised budget kinds?
pub fn is_budget_kind(kind: &str) -> bool {
    RECOGNISED_BUDGET_KINDS.contains(&kind)
}

/// Is `kind` recognised AT ALL by this build — resource-shaped
/// (`crate::document::RECOGNISED_SCOPE_KINDS`) or a budget kind? THE union
/// consulted by S.10 refusal ([`crate::document::boundary_is_evaluable`]) now
/// that recognition is no longer the same question as "the resource matcher can
/// classify it."
pub fn is_recognised_kind(kind: &str) -> bool {
    crate::document::RECOGNISED_SCOPE_KINDS.contains(&kind) || is_budget_kind(kind)
}

const _: () = assert!(!RECOGNISED_BUDGET_KINDS.is_empty());

/// The `scope` sub-key a `budget_calls` entry's value carries: `"*"` (every
/// tool) or a specific tool. Returns `None` for a non-`budget_calls` kind or for
/// a value this build cannot read the scope out of.
fn calls_scope(value: &serde_json::Value) -> Option<&str> {
    value.get("scope").and_then(|v| v.as_str())
}

/// The `limit` a budget entry's value carries, as a non-negative integer. Every
/// budget kind's value shape fixes `limit` the same way (S.8: "value"'s type is
/// fixed by the kind — nothing stops two kinds fixing the same type).
fn limit(value: &serde_json::Value) -> Option<u64> {
    value.get("limit").and_then(|v| v.as_u64())
}

/// The S.8 value-shape rule for a RECOGNISED budget kind, consulted from
/// [`crate::document::validate_scope_entry`] exactly as the `prefix` arm is: a
/// recognised kind's shape IS enforced at parse (unlike an unrecognised kind's,
/// which S.10 says must not even be inspected).
pub(crate) fn validate_budget_value(kind: &str, value: &serde_json::Value) -> Result<(), String> {
    let obj = value.as_object().ok_or_else(|| {
        format!("scope_boundary entry of kind `{kind}` must carry an object value")
    })?;

    let allowed: &[&str] = if kind == BUDGET_KIND_CALLS {
        &["scope", "limit"]
    } else {
        &["limit"]
    };
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "scope_boundary entry of kind `{kind}` carries unexpected member `{key}`"
            ));
        }
    }

    match limit(value) {
        Some(_) => {}
        None => {
            return Err(format!(
                "scope_boundary entry of kind `{kind}` must carry a non-negative integer `limit`"
            ))
        }
    }

    if kind == BUDGET_KIND_CALLS {
        match calls_scope(value) {
            Some(s) if !s.is_empty() => {}
            _ => {
                return Err(format!(
                    "scope_boundary entry of kind `{kind}` must carry a non-empty string `scope` \
                     (`\"*\"` for every tool, or `\"tool:<name>\"` for one)"
                ))
            }
        }
    } else if obj.contains_key("scope") {
        return Err(format!(
            "scope_boundary entry of kind `{kind}` is a singleton kind and does not take a `scope` member"
        ));
    }

    Ok(())
}

/// The identity a budget entry is matched by: its kind, plus its `scope` for
/// `budget_calls` (`None` for every singleton kind, where the kind alone is the
/// identity).
fn budget_identity(entry: &ScopeBoundaryEntry) -> Option<(&str, Option<&str>)> {
    if !is_budget_kind(entry.kind()) {
        return None;
    }
    if entry.kind() == BUDGET_KIND_CALLS {
        calls_scope(entry.value()).map(|s| (entry.kind(), Some(s)))
    } else {
        Some((entry.kind(), None))
    }
}

/// Validate that a boundary carries no two entries of the same budget identity
/// (two `limit`s under one singleton kind, or two `budget_calls` entries with
/// the same `scope`, are not alternative admissible limits — S.3's "within a
/// kind, entries are a union" does not read sensibly for a numeric ceiling).
/// Checked at boundary construction, not per-entry, because uniqueness is a
/// property of the collection.
pub fn validate_budget_boundary(boundary: &[ScopeBoundaryEntry]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for entry in boundary {
        if let Some(identity) = budget_identity(entry) {
            if !seen.insert(identity) {
                return match identity.1 {
                    Some(scope) => Err(format!(
                        "duplicate `{}` entry for scope `{scope}` — at most one entry \
                         per (kind, scope) pair",
                        entry.kind()
                    )),
                    None => Err(format!(
                        "duplicate `{}` entry — it is a singleton kind, at most one per boundary",
                        entry.kind()
                    )),
                };
            }
        }
    }
    let _ = SINGLETON_BUDGET_KINDS; // documents intent; enforced via `seen` above
    Ok(())
}

/// Why a child's budget entries do or does not attenuate its parent's — the
/// budget counterpart of [`crate::mint::AttenuationReason`], with the same three
/// outcomes and the same reasoning for keeping them distinct
/// (`docs/spec/scope.md`'s rationale for `verdict_v1.json`: three verifiers
/// refusing the same chain for three different reasons agree on every boolean
/// and disagree about what happened).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetAttenuationReason {
    /// Every budget identity the parent carries is matched by a child entry
    /// whose `limit` does not exceed the parent's, and every budget identity
    /// the child carries beyond that is new (narrows further; always safe).
    Attenuated,
    /// A budget identity present in the parent's (non-empty) boundary is either
    /// absent from the child, or present with a wider `limit`.
    BudgetEscalation,
    /// A boundary entry's kind is not recognised by this build at all (S.10):
    /// containment cannot be computed, which is not the same accusation as
    /// escalation.
    UnknownBudgetKind,
}

/// THE budget attenuation rule (`docs/spec/budget.md` B.5–B.6).
///
/// # Omission is escalation (decided; not the conservative default for an
/// arbitrary future kind)
///
/// `docs/spec/scope.md` S.13 constraint 2 states the generic, conservative rule
/// for an unknown future kind: any asymmetry in which boundary carries it is
/// treated as escalation, in EITHER direction, because a generic kind's
/// semantics are unknown and might widen. Budget kinds are not generic: by
/// construction every budget entry can only ever NARROW authority (it can
/// refuse an action, never grant one), so the two directions are not
/// symmetric and are decided separately here:
///
/// - **Parent carries identity I, child omits it → escalation.** An omitted
///   ceiling is an unlimited one, which is strictly wider than the parent's
///   limited one. Refusing (rather than clamping to the parent's limit, as
///   `mint_child` does for `expires_at`) is the decision: `expires_at` is a
///   single scalar the issuer can clamp unambiguously, but a budget identity
///   is a union-of-possible-identities the issuer has no basis for
///   synthesising on the caller's behalf — a caller that meant to inherit the
///   parent's limits should say so, with [`inherit_parent_budgets`].
/// - **Child carries a NEW identity the parent lacked → always attenuated.**
///   Adding a cap is narrowing by definition; there is nothing to refuse.
///
/// # Fan-out is safe, and this is NOT the mechanism that makes it so
/// (`docs/spec/budget.md` B.7)
///
/// This function is pairwise: it bounds ONE child against ONE parent's
/// DECLARED ceiling. Minting several children, each attenuated to the exact
/// same parent ceiling, is permitted here — this function has no concept of
/// "already promised to a sibling" and is not where that would be enforced.
/// Safety comes from the LEDGER (phase 3, outside this conformance surface,
/// the same posture ADR-0001 gives revocation): every descendant's spend is
/// counted against EVERY ancestor's remaining budget, so however many children
/// are minted at the parent's limit, the parent's own total consumption
/// (itself plus its whole subtree) is what is checked against the parent's
/// limit — not the number of children that could, on paper, each reach it
/// alone. `budget_v1.json`'s fan-out case pins that minting two children each
/// at the parent's limit is `Attenuated` for BOTH, precisely because this
/// function does not and should not reject it.
pub fn budget_attenuation_reason(
    parent_scope: &[ScopeBoundaryEntry],
    child_scope: &[ScopeBoundaryEntry],
) -> BudgetAttenuationReason {
    if !parent_scope.iter().all(|e| is_recognised_kind(e.kind()))
        || !child_scope.iter().all(|e| is_recognised_kind(e.kind()))
    {
        return BudgetAttenuationReason::UnknownBudgetKind;
    }

    let parent_limits: BTreeMap<(&str, Option<&str>), u64> = parent_scope
        .iter()
        .filter_map(|e| budget_identity(e).zip(limit(e.value())))
        .collect();
    let child_limits: BTreeMap<(&str, Option<&str>), u64> = child_scope
        .iter()
        .filter_map(|e| budget_identity(e).zip(limit(e.value())))
        .collect();

    for (identity, parent_limit) in &parent_limits {
        match child_limits.get(identity) {
            None => return BudgetAttenuationReason::BudgetEscalation,
            Some(child_limit) if child_limit > parent_limit => {
                return BudgetAttenuationReason::BudgetEscalation
            }
            Some(_) => {}
        }
    }
    BudgetAttenuationReason::Attenuated
}

/// `budget_attenuation_reason(..) == Attenuated`. The bool counterpart, for a
/// call site that does not need the distinction
/// ([`crate::mint::scope_attenuates`]'s own pairing).
pub fn budget_attenuates(
    parent_scope: &[ScopeBoundaryEntry],
    child_scope: &[ScopeBoundaryEntry],
) -> bool {
    budget_attenuation_reason(parent_scope, child_scope) == BudgetAttenuationReason::Attenuated
}

/// Copy every budget-kind entry of `parent_scope` verbatim. The explicit
/// opt-in B.6 asks for: a developer building a requested `scope_boundary` calls
/// this instead of re-typing the parent's limits by hand (and risking a typo
/// that reads as a narrower, functioning-by-accident request, or a wider one
/// that `mint_child` then correctly refuses). Resource-shaped (`prefix`)
/// entries are untouched — this is budget-only, deliberately: inheriting a
/// parent's full RESOURCE reach is a different, pre-existing decision a caller
/// makes by copying `scope_boundary` itself, and folding it in here would make
/// a budget-only helper silently widen resource reach too.
pub fn inherit_parent_budgets(parent_scope: &[ScopeBoundaryEntry]) -> Vec<ScopeBoundaryEntry> {
    parent_scope
        .iter()
        .filter(|e| is_budget_kind(e.kind()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(kind: &str, value: serde_json::Value) -> ScopeBoundaryEntry {
        ScopeBoundaryEntry::new(kind, value).expect("valid budget entry")
    }

    fn cost(limit: u64) -> ScopeBoundaryEntry {
        budget(
            BUDGET_KIND_COST_USD_MICRO,
            serde_json::json!({ "limit": limit }),
        )
    }

    fn calls(scope: &str, limit: u64) -> ScopeBoundaryEntry {
        budget(
            BUDGET_KIND_CALLS,
            serde_json::json!({ "scope": scope, "limit": limit }),
        )
    }

    #[test]
    fn a_narrower_child_cost_ceiling_attenuates() {
        let parent = vec![cost(500_000)];
        let child = vec![cost(100_000)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::Attenuated
        );
    }

    #[test]
    fn an_equal_child_cost_ceiling_attenuates() {
        let parent = vec![cost(500_000)];
        let child = vec![cost(500_000)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::Attenuated
        );
    }

    #[test]
    fn a_wider_child_cost_ceiling_is_an_escalation() {
        let parent = vec![cost(500_000)];
        let child = vec![cost(500_001)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::BudgetEscalation
        );
    }

    #[test]
    fn omitting_a_parent_budget_kind_is_an_escalation() {
        let parent = vec![cost(500_000)];
        let child: Vec<ScopeBoundaryEntry> = vec![];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::BudgetEscalation
        );
    }

    #[test]
    fn a_child_adding_a_cap_the_parent_never_had_is_safe() {
        let parent: Vec<ScopeBoundaryEntry> = vec![];
        let child = vec![cost(500_000)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::Attenuated
        );
    }

    #[test]
    fn fan_out_two_children_each_at_the_parents_limit_both_attenuate() {
        let parent = vec![cost(500_000)];
        let child_a = vec![cost(500_000)];
        let child_b = vec![cost(500_000)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child_a),
            BudgetAttenuationReason::Attenuated
        );
        assert_eq!(
            budget_attenuation_reason(&parent, &child_b),
            BudgetAttenuationReason::Attenuated
        );
    }

    #[test]
    fn per_tool_calls_entries_are_matched_by_kind_and_scope() {
        let parent = vec![calls("*", 500), calls("tool:browser.navigate", 50)];
        let child_ok = vec![calls("*", 100), calls("tool:browser.navigate", 50)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child_ok),
            BudgetAttenuationReason::Attenuated
        );
        // widening ONE scoped entry, even while narrowing the total, is refused
        let child_wide = vec![calls("*", 100), calls("tool:browser.navigate", 51)];
        assert_eq!(
            budget_attenuation_reason(&parent, &child_wide),
            BudgetAttenuationReason::BudgetEscalation
        );
    }

    #[test]
    fn an_unrecognised_kind_anywhere_refuses_rather_than_escalates() {
        let weird =
            ScopeBoundaryEntry::new("future_kind_v9", serde_json::json!("whatever")).unwrap();
        let parent = vec![cost(500_000)];
        let child = vec![weird];
        assert_eq!(
            budget_attenuation_reason(&parent, &child),
            BudgetAttenuationReason::UnknownBudgetKind
        );
    }

    #[test]
    fn inherit_parent_budgets_copies_budget_entries_only() {
        let parent = vec![
            ScopeBoundaryEntry::prefix("orders/"),
            cost(500_000),
            calls("*", 500),
        ];
        let inherited = inherit_parent_budgets(&parent);
        assert_eq!(inherited.len(), 2);
        assert!(inherited.iter().all(|e| is_budget_kind(e.kind())));
    }

    #[test]
    fn a_malformed_limit_is_refused_at_construction() {
        assert!(
            ScopeBoundaryEntry::new(BUDGET_KIND_COST_USD_MICRO, serde_json::json!({})).is_err()
        );
        assert!(ScopeBoundaryEntry::new(
            BUDGET_KIND_COST_USD_MICRO,
            serde_json::json!({"limit": -1})
        )
        .is_err());
        assert!(
            ScopeBoundaryEntry::new(BUDGET_KIND_CALLS, serde_json::json!({"limit": 5})).is_err()
        );
    }

    #[test]
    fn duplicate_singleton_entries_are_refused_at_boundary_level() {
        let boundary = vec![cost(500_000), cost(100_000)];
        assert!(validate_budget_boundary(&boundary).is_err());
    }

    #[test]
    fn duplicate_calls_scopes_are_refused_at_boundary_level() {
        let boundary = vec![calls("*", 500), calls("*", 100)];
        assert!(validate_budget_boundary(&boundary).is_err());
    }

    #[test]
    fn distinct_calls_scopes_are_fine() {
        let boundary = vec![calls("*", 500), calls("tool:browser.navigate", 50)];
        assert!(validate_budget_boundary(&boundary).is_ok());
    }
}
