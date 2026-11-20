# Budget caveats

**Prose specification. VAID. NORMATIVE.**
Implements ADR-0011. Revision 1, 10 November 2026.

Terminology follows `docs/spec/scope.md`: a **VAID** is the document (`Vaid`);
**scope boundary** is its `scope_boundary` list; **attenuation** is the
`child ⊆ parent` check performed at mint and re-performed by a third party at
chain verification.

---

> **Companion document.** [`scope.md`](scope.md) specifies the typed-kind
> extension point this document uses and does not repeat. Read S.1, S.8, S.10,
> S.12 and S.13 first — this document assumes them. Where this document is
> silent, `scope.md`'s rules for `scope_boundary` as a whole (S.1, S.2, S.8,
> S.10, S.11) apply unchanged to budget entries as they do to any other entry.

## B.1 What this decides

A **budget caveat** is a numeric ceiling on an agent's consumption, carried as
a typed `scope_boundary` entry. It answers a third question alongside the two
S.12 already names:

> `scope_boundary` is *where*. `capability_set` is *what*. A budget entry is
> *how much*.

This document defines four budget kinds and the containment rule between a
parent's and a child's budget entries. It does **not** define how consumption
is metered, recorded, or enforced at the point of use — that is a live,
stateful question (ledger, policy evaluation, model gateway), structurally
identical to revocation (`revocation.md`) and **outside** this document's
surface for the same reason ADR-0001 gives revocation: a budget *remaining*
cannot be decided from two documents alone, because consumption happens after
mint, across time. What **is** decidable from two documents alone — and is
what this document specifies — is ceiling containment: `child.limit <=
parent.limit`, computed once and re-verified by any party holding the same two
boundaries, exactly as S.1 requires for `prefix`.

## B.2 Why a scope kind, not a document member or a capability

ADR-0009's own stated motivation for the typed-kind extension point names "a
limit on an amount" as the first foreseeable use. S.12 states the rule
directly: a condition on an action is a future scope kind, never a new
document member and never a capability string decoration. Repeating the
argument briefly, because it is the whole of why this document exists rather
than a wire change:

- **Not a document member.** ADR-0006 requires a verifier to preserve, not
  refuse, a member it does not recognise. A verifier that preserves and
  ignores `"max_cost_micro_usd": 500000` authorises the unlimited action —
  the exact failure ADR-0009 built the typed-kind registry to prevent.
- **Not a capability string.** `capability_set` is matched by exact string
  equality (S.12) and has no refusal rule for a member it cannot parse. A
  condition folded into a capability string fails open or fails closed
  depending only on which side wrote it, which is not a decision anyone made.
- **A scope kind.** S.10's refusal rule already gives a budget kind the
  property it needs for free: a verifier that has never heard of
  `budget_cost_usd_micro` refuses the whole boundary rather than silently
  granting unlimited spend.

## B.3 The budget kinds (normative)

Four kinds, each a typed entry whose `value` is a JSON **object** (S.8: "value"'s
type is fixed by the kind — nothing requires it to be a string).

| Kind | Singleton? | `value` shape | Meaning |
|---|---|---|---|
| `budget_cost_usd_micro` | yes | `{"limit": <non-negative integer>}` | ceiling on cumulative model-call cost, in micro-USD (1 unit = $0.000001) |
| `budget_tokens` | yes | `{"limit": <non-negative integer>}` | ceiling on cumulative token usage (input + output, summed) |
| `budget_calls` | **no** | `{"scope": <non-empty string>, "limit": <non-negative integer>}` | ceiling on a count of calls; `scope` is `"*"` (every tool) or `"tool:<name>"` (one tool) |
| `budget_wall_clock_s` | yes | `{"limit": <non-negative integer>}` | ceiling on wall-clock seconds since `issued_at` |

**Singleton kinds carry at most one entry per boundary.** Two `limit`s under
one singleton kind are not alternative admissible limits — S.3's "within a
kind, entries are a union" reading does not apply to a numeric ceiling, so a
boundary with two `budget_tokens` entries is malformed, refused at mint and at
construction, not resolved by picking one.

**`budget_calls` is not a singleton.** Its `scope` member differentiates
entries, so a boundary may carry one total (`scope: "*"`) entry and any number
of per-tool (`scope: "tool:<name>"`) entries simultaneously. At most one entry
per distinct `scope` value.

**`budget_wall_clock_s` is a duration, not a deadline.** It is deliberately
distinct from `expires_at` (ADR-0007). `expires_at` is an absolute instant,
clamped at mint to the earlier of the issuer's TTL and the parent's `expires_at`.
A wall-clock budget is a duration re-anchored to whenever a child is actually
minted — a parent minted at `T` with a 24-hour `expires_at` can still delegate
a child, minted hours later, a fresh one-hour wall-clock budget of its own,
which `expires_at` containment alone cannot express.

An entry of a recognised budget kind whose `value` does not match its shape
makes the document **unparseable** — the same class of fault S.8 gives a
malformed `prefix` entry, and distinct from S.10's `unknown_scope_kind`, which
is reserved for a kind this build has never heard of at all.

## B.4 The containment rule (normative)

A budget entry's **identity** is its kind, plus (for `budget_calls` only) its
`scope`. Two entries share an identity iff they have the same kind and — for
`budget_calls` — the same `scope`.

Parent boundary `P` and child boundary `C` (child) **attenuate** on the budget
axis iff, for every identity `I` with an entry in `P`:

- `C` carries an entry of identity `I`, and
- that entry's `limit` is `<=` `P`'s entry's `limit` for `I`.

**Equality is containment**, exactly as ADR-0007 states for `expires_at`: a
child at exactly its parent's ceiling holds no authority its parent lacks.

A child carrying an identity **absent from `P`** is always attenuated for that
identity — adding a cap only narrows, by construction (B.5 explains why this
is safe for budget kinds specifically, unlike a generic future kind).

Budget containment is **not** computed by `scope_contains`/`entry_contains`
(S.3's resource matcher). It is a separate predicate, for the reason S.13
constraint 3 already names: a budget entry has no resource to claim, so the
`prefix` kind's "project the child entry as a resource" trick does not
generalise. A recognised budget-kind entry is **transparent** to resource
containment — it neither grants nor withholds resource reach, because it
answers an orthogonal axis (B.1). Concretely: a `scope_boundary` carrying only
budget entries and no `prefix` entry is unrestricted on the resource axis,
exactly as an empty list is — the budget ceiling applies on top of, not
instead of, whatever resource reach the boundary's `prefix` entries (or their
absence) already establish.

## B.5 Omission is escalation; addition is always safe (normative — a deliberate
narrowing of S.13 constraint 2 for this kind family)

`scope.md` S.13 constraint 2 states the generic, conservative rule for an
arbitrary future kind: *any* asymmetry in which side carries it is treated as
an escalation, because a generic kind's semantics are unknown and might widen.
Budget kinds are not generic — by construction, a budget entry can only ever
**narrow** authority (refuse an action; it never grants one) — so the two
directions are decided separately, and only one keeps the conservative rule:

1. **Parent carries identity `I`, child omits it → escalation.** An omitted
   ceiling is an unlimited one, strictly wider than the parent's limited one.
2. **Child carries a NEW identity the parent lacked → always attenuated.**
   Adding a cap narrows by definition; there is nothing to refuse.

(1) is a decision, not a derivation, and a real alternative was considered and
rejected: `mint_child` could instead **clamp** an omitted budget identity to
the parent's limit, mirroring what it already does for `expires_at`
(ADR-0007). It does not, because the two cases are not the same shape.
`expires_at` is a single scalar an issuer can clamp unambiguously — there is
exactly one value the clamp could be. A budget identity is drawn from an open
set (a kind, plus for `budget_calls` a caller-chosen `scope` string); there is
no single value to synthesise on the caller's behalf, and guessing wrong in
either direction is worse than refusing. A caller that means to inherit the
parent's limits calls `inherit_parent_budgets` (B.6) and says so explicitly.

## B.6 `inherit_parent_budgets` (non-normative convenience)

Each of the three reference libraries exports `inherit_parent_budgets` (Rust:
`vaid_mint::budget::inherit_parent_budgets`; Python:
`vaid_mint.budget.inherit_parent_budgets`; TypeScript:
`inheritParentBudgets`), taking a parent's `scope_boundary` and returning
every budget-kind entry within it, verbatim. A caller building a child's
requested `scope_boundary` appends the result instead of re-typing the
parent's limits by hand — removing the one way B.5's omission-is-escalation
rule becomes a developer-experience tax rather than a safety property.
Resource-shaped (`prefix`) entries are deliberately untouched by this helper:
inheriting a parent's full resource reach is a separate, pre-existing decision
(copying `scope_boundary` itself), and folding it into a budget-only helper
would make it silently widen resource reach too.

## B.7 Fan-out is safe, and B.4 is not the mechanism that makes it so

B.4 is **pairwise**: it bounds one child against one parent's *declared*
ceiling. It has no concept of "already promised to a sibling," and is
deliberately not where fan-out is enforced. Minting several children, each
attenuated to the parent's exact limit, is **permitted** by B.4 — the frozen
vector `budget_v1.json` pins two fan-out cases specifically to record that
minting is not restricted per-sibling.

Fan-out is safe anyway, and the reason lives outside this document's surface
(phase 3, the ledger): every descendant's spend is counted against **every**
ancestor's remaining budget, lineage-aware exactly as revocation is (R.4.4). A
parent's *total* consumption — itself plus its whole subtree — is what the
ledger checks against the parent's own limit, independent of how many children
were minted at that limit on paper. B.4 answers "is this child's declared
ceiling within its parent's," once, at mint; the ledger answers "has this
subtree's actual consumption exceeded this ceiling," continuously, at use.
Conflating the two would mean `mint_child` refusing a second child because a
first one *might* spend its whole allowance — a restriction with no basis,
since the first child might spend nothing at all.

## B.8 Wire format and versioning (normative)

A budget entry is wire-identical in shape to any other `scope_boundary` entry
(S.8): `{"kind": <string>, "value": <object>}`, no other member. Adding these
four kind values to a build's recognised-kind registry is, per `scope.md`
S.13 constraint 4, **not** a `sig_version` bump: it changes no document's
required member set, only which `kind` strings a build with the new code
recognises. An old verifier refuses a budget-kind entry it has never heard of
via S.10 (`unknown_scope_kind`) — the same additivity ADR-0009 built the whole
mechanism to provide. No existing frozen vector's canonical bytes or verdict
changes; `budget_v1.json` is a new, separate predicate vector (no digest, no
signature — a verdict over given bytes, exactly as `scope_kinds_v1.json`
carries none).

## B.9 Enforcement, metering, and the live surface (non-normative; scoped for
phase 3)

This document fixes the *static* half of the design — what a budget caveat
says, and how two boundaries compare. It does not fix:

- where consumption is metered (the model gateway, for cost/tokens; policy
  evaluation, for call counts) and why an agent cannot route around either
  choke point;
- the ledger schema, its durability requirements, or its lineage-aware
  aggregation;
- the signed exhaustion-evidence record a kill fires with;
- how a customer-supplied model gateway interacts with cost/token metering,
  which it structurally cannot see.

These are live, stateful questions, deliberately **outside the conformance
surface** this document defines — the same posture ADR-0001 states for
revocation, for the same reason: no vector here polices them, and nothing
else would catch independent deployments drifting into different shapes. They
are addressed separately.
