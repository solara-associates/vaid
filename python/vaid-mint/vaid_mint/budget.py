"""Quantitative delegation caveats — budget scope kinds (``docs/spec/budget.md``,
ADR-0011). Python mirror of the Rust ``budget`` module; read that module's doc
comment for the full rationale. Short version:

``scope_boundary`` is *where*, ``capability_set`` is *what*, and a condition on
an action — a maximum amount, a rate, a qualifier — is a future ``scope_boundary``
**kind** (ADR-0009's own stated motivation), never a new document member
(ADR-0006 would make old verifiers preserve-and-ignore it) and never a capability
string decoration (capability matching is exact equality, S.12).

Budget kinds are RECOGNISED by this build (added to the S.10 refusal registry via
:func:`is_recognised_kind`) but are deliberately absent from
``vaid_mint.document._entry_contains`` / ``entry_claimed_resource`` — the resource
matcher does not grow a kind it cannot meaningfully answer for (S.13 constraint 3:
"that projection does not generalise"). Instead:

- :func:`vaid_mint.document.scope_contains` treats a recognised budget-kind entry
  as transparent to resource containment.
- :func:`budget_attenuation_reason` is the separate, additional containment rule,
  called alongside :func:`vaid_mint.mint.scope_attenuates` — the same
  "one matcher, independent call sites" pattern ADR-0007 uses for ``expires_at``.
"""

from __future__ import annotations

from enum import Enum

#: A ceiling on cumulative model-call cost, in micro-USD (1 unit = $0.000001).
#: Singleton: at most one entry of this kind per boundary.
BUDGET_KIND_COST_USD_MICRO = "budget_cost_usd_micro"

#: A ceiling on cumulative token usage (input + output, summed). Singleton.
BUDGET_KIND_TOKENS = "budget_tokens"

#: A ceiling on a count of calls. NOT a singleton: an entry's ``value["scope"]``
#: names what it counts (``"*"`` for every tool, or ``"tool:<name>"`` for one).
BUDGET_KIND_CALLS = "budget_calls"

#: A ceiling on wall-clock seconds since ``issued_at``. Singleton. Deliberately
#: distinct from ``expires_at`` (ADR-0007, an absolute deadline): a wall-clock
#: BUDGET is a duration, re-anchored to whenever the VAID was actually issued.
BUDGET_KIND_WALL_CLOCK_S = "budget_wall_clock_s"

#: THE budget-kind registry — stated once, the same discipline
#: ``RECOGNISED_SCOPE_KINDS`` documents for the same reason.
RECOGNISED_BUDGET_KINDS: tuple[str, ...] = (
    BUDGET_KIND_COST_USD_MICRO,
    BUDGET_KIND_TOKENS,
    BUDGET_KIND_CALLS,
    BUDGET_KIND_WALL_CLOCK_S,
)

#: Kinds for which a boundary may carry at most one entry. ``budget_calls`` is
#: excluded: it is differentiated by ``scope``, so several entries (one total,
#: several per-tool) are the normal, well-formed case.
_SINGLETON_BUDGET_KINDS: tuple[str, ...] = (
    BUDGET_KIND_COST_USD_MICRO,
    BUDGET_KIND_TOKENS,
    BUDGET_KIND_WALL_CLOCK_S,
)

assert RECOGNISED_BUDGET_KINDS, "a build recognising no budget kind is meaningless"


def is_budget_kind(kind: str) -> bool:
    """Is ``kind`` one of this build's recognised budget kinds?"""
    return kind in RECOGNISED_BUDGET_KINDS


def is_recognised_kind(kind: str) -> bool:
    """Is ``kind`` recognised AT ALL by this build — resource-shaped
    (``vaid_mint.document.RECOGNISED_SCOPE_KINDS``) or a budget kind? THE union
    consulted by S.10 refusal now that recognition is no longer the same
    question as "the resource matcher can classify it."
    """
    from vaid_mint.document import RECOGNISED_SCOPE_KINDS

    return kind in RECOGNISED_SCOPE_KINDS or is_budget_kind(kind)


def budget_entry(kind: str, value: dict) -> dict:
    """A typed budget boundary entry over ``value``. Mirror of Rust
    ``ScopeBoundaryEntry::new`` for a budget kind, validating as it goes."""
    error = validate_budget_value(kind, value)
    if error is not None:
        raise ValueError(error)
    return {"kind": kind, "value": value}


def _calls_scope(value: object) -> str | None:
    """The ``scope`` sub-key a ``budget_calls`` entry's value carries. ``None``
    for a value this cannot read a scope out of."""
    if isinstance(value, dict) and isinstance(value.get("scope"), str):
        return value["scope"]
    return None


def _limit(value: object) -> int | None:
    """The ``limit`` a budget entry's value carries, as a non-negative integer.

    ``bool`` is explicitly excluded even though Python's ``bool`` is an ``int``
    subclass — ``True``/``False`` reaching here would silently become ``1``/``0``,
    which is never what a caller meant by a JSON boolean in a numeric field.
    """
    if isinstance(value, dict):
        limit = value.get("limit")
        if isinstance(limit, int) and not isinstance(limit, bool) and limit >= 0:
            return limit
    return None


def validate_budget_value(kind: str, value: object) -> str | None:
    """The S.8 value-shape rule for a RECOGNISED budget kind, consulted from
    ``vaid_mint.document.is_well_formed_scope_entry`` exactly as the ``prefix``
    shape check is: a recognised kind's shape IS enforced at parse. Returns an
    error message, or ``None`` if ``value`` is well formed for ``kind``.
    """
    if not isinstance(value, dict):
        return f"scope_boundary entry of kind `{kind}` must carry an object value"

    allowed = {"scope", "limit"} if kind == BUDGET_KIND_CALLS else {"limit"}
    extra = set(value) - allowed
    if extra:
        return f"scope_boundary entry of kind `{kind}` carries unexpected member(s) {sorted(extra)}"

    if _limit(value) is None:
        return f"scope_boundary entry of kind `{kind}` must carry a non-negative integer `limit`"

    if kind == BUDGET_KIND_CALLS:
        scope = _calls_scope(value)
        if not scope:
            return (
                f"scope_boundary entry of kind `{kind}` must carry a non-empty string "
                '`scope` (`"*"` for every tool, or `"tool:<name>"` for one)'
            )
    elif "scope" in value:
        return f"scope_boundary entry of kind `{kind}` is a singleton kind and does not take a `scope` member"

    return None


def _budget_identity(entry: dict) -> tuple[str, str | None] | None:
    """The identity a budget entry is matched by: its kind, plus its ``scope``
    for ``budget_calls`` (``None`` for every singleton kind)."""
    if not isinstance(entry, dict):
        return None
    kind = entry.get("kind")
    if not isinstance(kind, str) or not is_budget_kind(kind):
        return None
    if kind == BUDGET_KIND_CALLS:
        scope = _calls_scope(entry.get("value"))
        return (kind, scope) if scope is not None else None
    return (kind, None)


def validate_budget_boundary(boundary: list[dict]) -> str | None:
    """Validate that ``boundary`` carries no two entries of the same budget
    identity (two ``limit``s under one singleton kind, or two ``budget_calls``
    entries with the same ``scope``, are not alternative admissible limits —
    S.3's "within a kind, entries are a union" does not read sensibly for a
    numeric ceiling). Returns an error message, or ``None`` if the boundary is
    well formed with respect to budget identities.
    """
    seen: set[tuple[str, str | None]] = set()
    for entry in boundary:
        identity = _budget_identity(entry)
        if identity is None:
            continue
        if identity in seen:
            kind, scope = identity
            if scope is not None:
                return f"duplicate `{kind}` entry for scope `{scope}` — at most one entry per (kind, scope) pair"
            return f"duplicate `{kind}` entry — it is a singleton kind, at most one per boundary"
        seen.add(identity)
    return None


class BudgetAttenuationReason(str, Enum):
    """Why a child's budget entries do or does not attenuate its parent's — the
    budget counterpart of ``vaid_mint.mint.AttenuationReason``, with the same
    three outcomes and the same reasoning for keeping them distinct.
    """

    #: Every budget identity the parent carries is matched by a child entry
    #: whose ``limit`` does not exceed the parent's; any identity the child
    #: carries beyond that is new (narrows further; always safe).
    ATTENUATED = "attenuated"
    #: A budget identity present in the parent's (non-empty) boundary is either
    #: absent from the child, or present with a wider ``limit``.
    BUDGET_ESCALATION = "budget_escalation"
    #: A boundary entry's kind is not recognised by this build at all (S.10).
    UNKNOWN_BUDGET_KIND = "unknown_budget_kind"


def budget_attenuation_reason(
    parent_scope: list[dict], child_scope: list[dict]
) -> BudgetAttenuationReason:
    """THE budget attenuation rule (``docs/spec/budget.md`` B.5-B.6). Mirror of
    Rust ``budget_attenuation_reason`` — see that function's doc comment for
    the full rationale on why omission is escalation, why addition of a new
    identity is always safe, and why fan-out (several children each up to the
    parent's limit) is deliberately NOT restricted here.
    """
    if not all(
        isinstance(e, dict) and isinstance(e.get("kind"), str) and is_recognised_kind(e["kind"])
        for e in parent_scope
    ) or not all(
        isinstance(e, dict) and isinstance(e.get("kind"), str) and is_recognised_kind(e["kind"])
        for e in child_scope
    ):
        return BudgetAttenuationReason.UNKNOWN_BUDGET_KIND

    parent_limits: dict[tuple[str, str | None], int] = {}
    for e in parent_scope:
        identity = _budget_identity(e)
        limit = _limit(e.get("value")) if isinstance(e, dict) else None
        if identity is not None and limit is not None:
            parent_limits[identity] = limit

    child_limits: dict[tuple[str, str | None], int] = {}
    for e in child_scope:
        identity = _budget_identity(e)
        limit = _limit(e.get("value")) if isinstance(e, dict) else None
        if identity is not None and limit is not None:
            child_limits[identity] = limit

    for identity, parent_limit in parent_limits.items():
        child_limit = child_limits.get(identity)
        if child_limit is None or child_limit > parent_limit:
            return BudgetAttenuationReason.BUDGET_ESCALATION

    return BudgetAttenuationReason.ATTENUATED


def budget_attenuates(parent_scope: list[dict], child_scope: list[dict]) -> bool:
    """``budget_attenuation_reason(..) == ATTENUATED``. The bool counterpart,
    mirroring ``vaid_mint.mint.scope_attenuates``'s own pairing."""
    return budget_attenuation_reason(parent_scope, child_scope) is BudgetAttenuationReason.ATTENUATED


def inherit_parent_budgets(parent_scope: list[dict]) -> list[dict]:
    """Copy every budget-kind entry of ``parent_scope`` verbatim. The explicit
    opt-in B.6 asks for: a caller building a requested ``scope_boundary`` calls
    this instead of re-typing the parent's limits by hand. Resource-shaped
    (``prefix``) entries are untouched — this is budget-only, deliberately.
    """
    return [dict(e) for e in parent_scope if isinstance(e, dict) and is_budget_kind(e.get("kind"))]
