"""Budget scope kinds (``docs/spec/budget.md``, ADR-0011) — Python mirror of the
Rust ``budget`` module's own test module, plus ``mint_child`` integration tests
mirroring the Rust ``mint::tests`` budget cases.
"""

from __future__ import annotations

import pytest

from vaid_mint.budget import (
    BUDGET_KIND_CALLS,
    BUDGET_KIND_COST_USD_MICRO,
    BudgetAttenuationReason,
    budget_attenuation_reason,
    budget_entry,
    inherit_parent_budgets,
    is_budget_kind,
    validate_budget_boundary,
)
from vaid_mint.document import is_in_scope, prefix_entry
from vaid_mint.error import UnauthorizedError

from test_mint_behavior import fixture, parent_doc, signed_child  # noqa: E402


def cost(limit: int) -> dict:
    return budget_entry(BUDGET_KIND_COST_USD_MICRO, {"limit": limit})


def calls(scope: str, limit: int) -> dict:
    return budget_entry(BUDGET_KIND_CALLS, {"scope": scope, "limit": limit})


# ── pure attenuation-rule tests (mirror of Rust budget::tests) ──


def test_a_narrower_child_cost_ceiling_attenuates():
    assert budget_attenuation_reason([cost(500_000)], [cost(100_000)]) is BudgetAttenuationReason.ATTENUATED


def test_an_equal_child_cost_ceiling_attenuates():
    assert budget_attenuation_reason([cost(500_000)], [cost(500_000)]) is BudgetAttenuationReason.ATTENUATED


def test_a_wider_child_cost_ceiling_is_an_escalation():
    assert (
        budget_attenuation_reason([cost(500_000)], [cost(500_001)])
        is BudgetAttenuationReason.BUDGET_ESCALATION
    )


def test_omitting_a_parent_budget_kind_is_an_escalation():
    assert budget_attenuation_reason([cost(500_000)], []) is BudgetAttenuationReason.BUDGET_ESCALATION


def test_a_child_adding_a_cap_the_parent_never_had_is_safe():
    assert budget_attenuation_reason([], [cost(500_000)]) is BudgetAttenuationReason.ATTENUATED


def test_fan_out_two_children_each_at_the_parents_limit_both_attenuate():
    parent = [cost(500_000)]
    assert budget_attenuation_reason(parent, [cost(500_000)]) is BudgetAttenuationReason.ATTENUATED
    assert budget_attenuation_reason(parent, [cost(500_000)]) is BudgetAttenuationReason.ATTENUATED


def test_per_tool_calls_entries_are_matched_by_kind_and_scope():
    parent = [calls("*", 500), calls("tool:browser.navigate", 50)]
    child_ok = [calls("*", 100), calls("tool:browser.navigate", 50)]
    assert budget_attenuation_reason(parent, child_ok) is BudgetAttenuationReason.ATTENUATED
    child_wide = [calls("*", 100), calls("tool:browser.navigate", 51)]
    assert budget_attenuation_reason(parent, child_wide) is BudgetAttenuationReason.BUDGET_ESCALATION


def test_an_unrecognised_kind_anywhere_refuses_rather_than_escalates():
    weird = {"kind": "future_kind_v9", "value": "whatever"}
    assert (
        budget_attenuation_reason([cost(500_000)], [weird])
        is BudgetAttenuationReason.UNKNOWN_BUDGET_KIND
    )


def test_inherit_parent_budgets_copies_budget_entries_only():
    parent = [prefix_entry("orders/"), cost(500_000), calls("*", 500)]
    inherited = inherit_parent_budgets(parent)
    assert len(inherited) == 2
    assert all(is_budget_kind(e["kind"]) for e in inherited)


def test_a_malformed_limit_is_refused_at_construction():
    with pytest.raises(ValueError):
        budget_entry(BUDGET_KIND_COST_USD_MICRO, {})
    with pytest.raises(ValueError):
        budget_entry(BUDGET_KIND_COST_USD_MICRO, {"limit": -1})
    with pytest.raises(ValueError):
        budget_entry(BUDGET_KIND_CALLS, {"limit": 5})


def test_duplicate_singleton_entries_are_refused_at_boundary_level():
    assert validate_budget_boundary([cost(500_000), cost(100_000)]) is not None


def test_duplicate_calls_scopes_are_refused_at_boundary_level():
    assert validate_budget_boundary([calls("*", 500), calls("*", 100)]) is not None


def test_distinct_calls_scopes_are_fine():
    assert validate_budget_boundary([calls("*", 500), calls("tool:browser.navigate", 50)]) is None


# ── a_budget_only_boundary_does_not_block_resource_access (document.scope_contains) ──


def test_a_budget_only_boundary_does_not_restrict_resource_access():
    vaid = {"scope_boundary": [cost(500_000)]}
    assert is_in_scope(vaid, "anything/at/all")


def test_a_budget_entry_cannot_widen_a_prefix_restricted_boundary():
    vaid = {"scope_boundary": [prefix_entry("orders/"), cost(500_000)]}
    assert is_in_scope(vaid, "orders/123")
    assert not is_in_scope(vaid, "something/else")


# ── mint_child integration (mirror of Rust mint::tests budget cases) ──


def test_mint_child_with_narrower_budget_than_parent_mints():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory", cost(500_000)], ["read"])
    seed, pop = signed_child(parent, ["data.aifactory.sub", cost(100_000)], ["read"], "budget-ok")
    assert svc.mint_child(seed, parent, pop).vaid["parent_vaid"] == parent["vaid_id"]


def test_mint_child_with_wider_budget_than_parent_is_denied():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory", cost(500_000)], ["read"])
    seed, pop = signed_child(parent, ["data.aifactory.sub", cost(500_001)], ["read"], "budget-wide")
    with pytest.raises(UnauthorizedError, match="budget caveat"):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty()


def test_mint_child_omitting_a_parent_budget_caveat_is_denied():
    svc, audit, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory", cost(500_000)], ["read"])
    seed, pop = signed_child(parent, ["data.aifactory.sub"], ["read"], "budget-omit")
    with pytest.raises(UnauthorizedError, match="budget caveat"):
        svc.mint_child(seed, parent, pop)
    assert audit.is_empty()


def test_fan_out_two_children_each_at_the_parents_exact_budget_both_mint():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory", cost(500_000)], ["read"])
    seed_a, pop_a = signed_child(parent, ["data.aifactory.sub", cost(500_000)], ["read"], "fan-a")
    seed_b, pop_b = signed_child(parent, ["data.aifactory.sub", cost(500_000)], ["read"], "fan-b")
    svc.mint_child(seed_a, parent, pop_a)
    svc.mint_child(seed_b, parent, pop_b)


def test_inherit_parent_budgets_helper_produces_a_mintable_child():
    svc, _, _ = fixture()
    parent = parent_doc("aifactory", ["data.aifactory", cost(500_000)], ["read"])
    child_scope = [prefix_entry("data.aifactory.sub")] + inherit_parent_budgets(parent["scope_boundary"])
    seed, pop = signed_child(parent, child_scope, ["read"], "inherit-ok")
    assert svc.mint_child(seed, parent, pop).vaid["parent_vaid"] == parent["vaid_id"]
