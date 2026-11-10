# Phase 3 plan: live budget enforcement (ledger, gateway, UAB)

**Status:** PLANNING — no code in this PR. Builds on phase 2 (`feature/budget-scope-kinds`,
PR #172, draft, not merged, pending independent review) and the phase 1 design
report. This document is the thing Allan asked for before phase 3 starts: "the
ledger schema, the LiveStatusCheck seam shared with revocation, metering at
Solara's gateway, the refusal of budget caveats for customer-gateway agents,
and the UAB budget controls, with effort estimates."

**Owners:** substrate/forge-api changes are currently owned by sessions 605/609
per standing memory; UAB changes need their own owner assigned before work
starts. Not scoped here.

**Decided, carried over from phase 1/2:**

- Budget caveats are `scope_boundary` kinds (`docs/spec/budget.md`,
  ADR-0011) — static ceiling containment, offline, mint-time. Done in phase 2.
- *Remaining* budget is not decidable from two documents; it needs a durable
  ledger consulted at the point of use. That is this phase.
- Customer-supplied model gateway: **Option A is the default** — a budgeted
  agent MUST route through Solara's gateway; an agent configured with a
  customer gateway URL cannot carry `budget_cost_usd_micro`/`budget_tokens`
  caveats. **Option B (customer-attested usage) is built only on a concrete
  customer request**, explicit, labelled as self-reported, never a default.
  §5 below designs the refusal (A) in full; B is recorded as a stub only.

---

## 1. Ledger schema

Postgres, durable, no in-memory-only state anywhere in the path — the same
non-negotiable R.4.6/A5.10 posture this estate already applies to revocation
and lineage stores.

```sql
-- One row per (vaid_id, metric[, scope]). UPSERT by increment, never
-- read-then-write, so concurrent calls from the same agent cannot lose a
-- write racing another.
CREATE TABLE budget_ledger (
    vaid_id      uuid        NOT NULL,
    metric       text        NOT NULL,   -- 'budget_cost_usd_micro' | 'budget_tokens'
                                          -- | 'budget_calls' | 'budget_wall_clock_s'
    scope        text        NOT NULL DEFAULT '',  -- '*' or 'tool:<name>' for
                                                     -- budget_calls; '' for every
                                                     -- singleton metric
    spent        bigint      NOT NULL DEFAULT 0 CHECK (spent >= 0),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vaid_id, metric, scope)
);

-- INSERT ... ON CONFLICT (vaid_id, metric, scope)
--   DO UPDATE SET spent = budget_ledger.spent + $increment, updated_at = now();
```

**Lineage-aware aggregation, not a second table.** A child's spend must count
against every ancestor's budget (the design-doc requirement from phase 1,
restated by ADR-0011 §6 as the mechanism that makes fan-out safe). Two ways to
get this, and the recommendation is the second:

- **(a) Write one row per VAID in the lineage, per event.** On every metered
  call, resolve the caller's full ancestry (reusing the EXACT resolver
  revocation already requires — `assemble_lineage`, R.4.2) and upsert-increment
  `budget_ledger` for every VAID in that chain, not just the leaf. A check
  against any ancestor's limit is then a single-row read:
  `spent <= limit` for that `(vaid_id, metric, scope)`. Write amplification is
  bounded by delegation depth (`MAX_LINEAGE_DEPTH`), which is already small
  and capped.
- **(b) Write only the leaf, and sum on read** (`SELECT sum(spent) FROM
  budget_ledger JOIN lineage_closure ...`). Avoids write amplification but
  requires a lineage-closure table kept in sync, and turns every budget check
  into a join instead of a point read — on the hot path (every tool/model
  call), a point read is the one that keeps the policy-evaluation latency
  budget sane.

**Recommendation: (a).** It costs more writes, bounded and small; it buys a
single-row point read on every check, which is the operation that happens on
every metered call rather than once per mint.

**Durability failure mode, stated explicitly (mirrors R.4.6 for revocation).**
An unreachable `budget_ledger` must report `Unavailable`, never `WithinBudget`
— a budget check backed by a store that silently resets to empty is
indistinguishable from a legitimately fresh VAID, and is worse than no check
at all. The same two-halves lesson R.4.6 states for revocation (lineage store
+ revoked-set store, and the asymmetric failure when only one is durable)
applies here with the lineage resolver as the shared dependency: if the
lineage resolver is unavailable, a budget check cannot even assemble which
rows to aggregate, and must report `Unavailable` rather than checking only the
leaf's own row.

**Effort: 3–4 days** — schema + migration, the upsert-by-increment write path,
the lineage-aware write-fan-out, and the point-read check, with tests for
concurrent-write correctness and the unavailable-resolver case.

## 2. The `LiveStatusCheck` seam, shared with revocation

Phase 1 already named this: budget exhaustion and revocation are the same
*shape* of control — lineage-aware, three-state, fail-closed on unavailable,
outside VAID's pure offline-conformance surface for the live half (ADR-0001's
posture, applied here). Rather than building a second, independently-drifting
seam, generalise `RevocationCheck` (`docs/spec/revocation.md` R.4) into a
shared pattern with two instances.

**Division of responsibility, unchanged from R.4.1.** The verifier/policy
evaluator assembles the lineage (reusing `assemble_lineage`/`LineageResolver`
verbatim — one resolver, two consumers). The check answers about a lineage
and a requested increment it is handed; it does not perform its own lookups.

**Return type, generalised from R.4.3's three states:**

```rust
pub enum LiveStatus<D> {
    Ok,               // NotRevoked, or WithinBudget after this increment
    Violation(D),     // Revoked(vaid_id), or BudgetExceeded { metric, scope, limit, spent }
    Unavailable,      // store unreachable, or lineage incomplete
}
```

`RevocationCheck` becomes `LiveStatusCheck<RevokedDetail>` and a new
`BudgetCheck` becomes `LiveStatusCheck<BudgetExceededDetail>`; the lineage
assembly, the fail-closed-on-`Unavailable` rule (R.4.5), and the
inherited-up-the-chain semantics (R.4.4, generalised to "any ancestor over
budget blocks the whole subtree") are ONE implementation, not two. This is
also where the exhaustion evidence record attaches: a `Violation` return
carries enough (`metric`, `scope`, `limit`, `spent`, the VAID it fired on) to
build the signed receipt in §3.

**Invocation points, two not one.** Revocation today is "consulted during
verification, MAY be consulted during attenuation" (R.4.7). Budget needs a
THIRD point revocation does not: consulted **before granting** a metered
action, at the policy-evaluation choke point (§3), because unlike revocation,
budget state changes *during* a session, not only between mints.

**Effort: 4–5 days** — generalising the Rust seam (the reference implementation
already has three-state + lineage-aware revocation to generalise from; Python
and TypeScript mirror it), plus the new `BudgetCheck` instance and its
Postgres-backed implementation reading `budget_ledger`.

## 3. Metering at Solara's gateway, and why an agent cannot route around it

Two distinct chokepoints for two distinct things, as flagged in phase 1 — restated
here with the concrete wiring:

- **Cost and tokens** can only be known after a provider responds (actual
  billed usage), so the increment write happens in the **model gateway**
  itself, in the one code path every model call must pass through to reach a
  provider key. The agent never holds a provider key directly — that is
  already this estate's posture for secrets (`A7.agent-credentials`: no
  generating agent holds production write credentials; provider keys are the
  same class). After the provider responds, the gateway:
  1. resolves the caller's lineage (same resolver as §1/§2),
  2. calls `BudgetCheck` with the actual increment for `budget_cost_usd_micro`
     and `budget_tokens` against every ancestor,
  3. on `Ok`, commits the ledger write and returns the response to the agent;
  4. on `Violation`, the call still happened and was billed (cost is known only
     after the provider call completes) — the write still lands (so the ledger
     reflects reality) but the gateway marks the VAID (and its subtree)
     exhausted for that metric from this point on, and **refuses the next
     call** before it reaches a provider.
- **Call counts** (`budget_calls`, total or per-tool) are known BEFORE the
  call happens, so they are checked **before** granting, at the
  **policy-evaluation** point — the one place in this estate that already
  derives `verified_*` fields off the kernel-signed, PoP-verified VAID after
  stripping caller-asserted input (`engine.rs::evaluate_policy`, confirmed
  live on the rule path per existing estate memory). Adding a `BudgetCheck`
  call there, keyed off `verified_vaid_id` and the tool name being invoked,
  means a caller cannot assert its own remaining call count any more than it
  can today assert its own `agent_class` on the rule path.
- **Wall-clock budget** is checked at the same policy-evaluation point,
  comparing `now - issued_at` against the ceiling — no ledger write needed,
  since it is derived from the document's own `issued_at`, not from
  accumulated state.

**Why an agent cannot bypass either chokepoint.** It has no model-provider
credentials of its own (gateway-only secret custody) and it cannot supply its
own remaining-budget figure (the ledger lives server-side, keyed by the
kernel-verified `vaid_id`, incremented only by the gateway/policy-evaluation
code, never by caller-supplied request fields). These are the same two
chokepoints this estate already trusts for identity and secrets; this reuses
them rather than adding a third one an agent could find a gap around.

**Effort: 1.5–2 weeks** — the gateway-side metering hook (cost/tokens, after
every provider response) is the larger piece; the policy-evaluation hook
(calls, wall-clock) is smaller since it plugs into an existing, already-proven
bridge. Includes the exhaustion-receipt signer (a detached, additive, signed
artifact modelled on `consent-attestation.md`'s pattern — own version
discriminant, canonicalize/null-signature/JCS/SHA-256, never a VAID document
field — carrying `{vaid_id, metric, scope, limit, spent, exceeded_at}`).

## 4. UAB budget controls

- **Per-team and per-agent budget setting**, in the builder, writing the
  budget-kind `scope_boundary` entries at mint/provisioning time (reusing
  `inherit_parent_budgets` where a team-level default cascades to its agents).
  This is a provisioning-flow change, not a new storage layer — the limits
  live in the VAID documents themselves (phase 2), UAB just needs a form that
  produces well-formed budget entries instead of a developer hand-typing JSON.
- **Live spend display**, reading `budget_ledger` (point read per `(vaid_id,
  metric, scope)`, §1) — a progress-bar-style view per agent/team, refreshed
  on a short poll (not real-time push; this estate's existing `ledger-tail`
  precedent shows a live Cloud SQL read against this kind of table is
  workable but not sub-second, so set expectations accordingly rather than
  promising a live ticking counter).
- **The kill switch's user-visible half**: when a `BudgetCheck` fires
  `Violation`, UAB should show *which* limit, on *which* agent, with the
  signed exhaustion receipt available to download/inspect — turning "the
  agent just stopped" into a named, explained event rather than a silent
  failure, the same usability argument ADR-0007 made for reporting the
  `expires_at` clamp rather than leaving it implicit.
- **Customer-gateway agents show budgets as unavailable, not zero.** Per §5,
  an agent configured with a customer gateway cannot carry cost/token budget
  caveats at all; UAB must render that as "budgets not available for this
  agent — uses a customer-supplied model gateway," never as "$0 spent" (which
  reads as "fully within budget," the opposite of the truth).

**Effort: 1–1.5 weeks** — mostly UI/form work; the hard parts (ledger,
gateway, seam) are built in §1–§3 and UAB consumes them.

## 5. Refusing budget caveats for customer-gateway agents (Option A, the default)

**Enforcement point: provisioning / `mint_child`, not the gateway.** The
refusal has to happen before a budgeted, customer-gateway agent is ever
minted — catching it only at call time would mean the agent runs believing it
has a cap that nothing is checking.

Concretely, the provisioner (or whichever caller assembles `VaidSeed` for a
new agent) must, when the agent's configuration names a customer-supplied
model gateway URL, refuse to include any `budget_cost_usd_micro` or
`budget_tokens` entry in the requested `scope_boundary` — those two kinds
specifically, because they are the two phase 2 validated as metered **at the
gateway** (§3); `budget_calls` and `budget_wall_clock_s` are checked at
policy evaluation regardless of which model gateway the agent uses, so they
remain available even for a customer-gateway agent.

This is a provisioning-time validation, not a VAID-library change: phase 2's
`mint_child` has no concept of "which gateway" and should not grow one — that
information lives in the agent's provisioning spec (`GovernedSystemSpec` or
equivalent), not in the VAID document. The check belongs at the same seam
`provisioner-agent-env-vars-are-service-wide` already flags as the place a
genuinely per-agent value must be read from the spec's `AgentRole`, not
injected ad hoc.

**UAB-side:** the budget-setting form (§4) must grey out / explain-away the
cost and token fields the moment a customer gateway URL is set for that agent,
rather than accepting a value that provisioning will then silently drop or
refuse — the same "don't let the UI promise what the backend can't enforce"
rule the budget-only-unavailable rendering in §4 already follows.

**Option B is explicitly NOT built now.** If a concrete customer request
arrives, it is a customer-gateway-attested usage report: a `source:
customer_attested` field distinguishing every such ledger row from a
`source: solara_metered` one, surfaced in UAB wherever spend is shown, and
never the default path for a newly provisioned agent. Recorded here as the
shape it would take; no schema, seam, or UI for it is designed or built in
this phase.

**Effort: 2–3 days** — the provisioning-time refusal and its test, plus the
UAB form change. Small relative to §1–§3 because it is a validation, not new
infrastructure.

## Summary effort table

| Part | Effort |
|---|---|
| §1 Ledger schema (Postgres, lineage-aware writes) | 3–4 days |
| §2 `LiveStatusCheck` seam (generalised from `RevocationCheck`) + `BudgetCheck` | 4–5 days |
| §3 Metering at the gateway + policy-evaluation hook + exhaustion receipt | 1.5–2 weeks |
| §4 UAB budget controls (setting, live spend, kill-switch display) | 1–1.5 weeks |
| §5 Customer-gateway refusal (Option A) | 2–3 days |
| **Total** | **~4–5 weeks**, substrate/forge-api/UAB work, not counted against phase 2's branch |

Sequencing note: §1 and §2 are prerequisites for §3; §5 can be built in
parallel with any of them since it only touches provisioning validation and
UAB form logic, not the ledger or gateway.
