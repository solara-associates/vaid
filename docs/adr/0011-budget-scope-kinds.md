# ADR-0011: Budget caveats are scope kinds, with omission-is-escalation and no
clamp

**Status:** Accepted
**Date:** 10 November 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0009 (typed extensible `scope_boundary`, whose extension
point this uses exactly as foreseen), ADR-0007 (expiry containment, the
closest existing precedent for a numeric ceiling and for the clamp-vs-refuse
decision), ADR-0001 (revocation outside the conformance surface, the
structural precedent for why live enforcement is out of scope here),
`docs/spec/budget.md`, `budget_v1.json`

---

## Context

Solara's agent delegation substrate needs a way for a parent VAID to hand a
child a *quantitative* ceiling — a maximum spend, token count, call count, or
wall-clock duration — that the child cannot widen, verifiable offline by any
party holding the parent and child documents, exactly as scope and expiry
already are.

`scope_boundary` has carried exactly one kind, `prefix`, since ADR-0009 typed
it. That ADR's own Context section names "a limit on an amount" as the first
foreseeable reason the typed-kind extension point exists, and `docs/spec/scope.md`
S.12 already states the architectural rule a budget caveat must follow:
`scope_boundary` is *where*, `capability_set` is *what*, and a condition on an
action is a future scope kind — never a document member (ADR-0006 would make
old verifiers preserve-and-ignore it) and never a capability decoration
(exact-match capability strings have no refusal rule for an embedded
condition).

What ADR-0009 and `scope.md` S.13 did **not** settle, because no second kind
existed yet to settle it against, is: what does a kind whose boundary is not
resource-shaped actually attenuate against, how do omission and addition of
an identity behave, and is a numeric ceiling clamped (as `expires_at` is) or
refused when a child omits it. This ADR answers those questions.

## Decision

**1. Budget caveats are four new `scope_boundary` kinds**
(`budget_cost_usd_micro`, `budget_tokens`, `budget_calls`,
`budget_wall_clock_s`), specified in full in `docs/spec/budget.md`. Three are
singletons; `budget_calls` is differentiated by a `scope` sub-member
(`"*"` or `"tool:<name>"`) and may carry several entries.

**2. Budget containment is a SEPARATE predicate from `scope_contains`,
not a new arm inside it.** `scope.md` S.13 constraint 3 already flags this:
the `prefix` kind's attenuation trick — projecting a child entry as if it
were a resource and feeding it back into the same matcher — does not
generalise to a kind with no resource to claim. `budget_attenuation_reason`
is new code in all three libraries, called ADDITIONALLY alongside
`scope_attenuates` at every site that already calls it (`mint_child`,
`verify_chain_at`, consent-attestation verification) — the same "one matcher,
independent call sites" pattern ADR-0007 used for `expires_at`, which is also
not resource-shaped.

**3. A recognised budget-kind entry is transparent to resource containment.**
`scope_contains` recognises budget kinds (so an old, budget-naive build still
refuses them under S.10) but skips them in its resource-containment walk. A
boundary carrying only budget entries and no `prefix` entry is unrestricted
on the resource axis, exactly as an empty list is — a budget cap must not
become, as a side effect of being stated, a boundary that blocks every
resource.

**4. Omission is escalation; addition of a new identity is always safe.**
`scope.md` S.13 constraint 2 states the generic, conservative rule for an
arbitrary future kind: any presence asymmetry is an escalation, because a
generic kind's semantics are unknown and might widen. Budget kinds are known,
and known to be narrowing-only (a budget entry refuses an action; it never
grants one), so the two directions are decided separately:

- A budget identity present in a non-empty parent and absent from the child
  is `budget_escalation` — an omitted ceiling is an unlimited one.
- A budget identity present in the child and absent from the parent is always
  `attenuated` — adding a cap only narrows.

**5. `mint_child` REFUSES an omitted budget identity; it does not clamp.**
A real alternative, considered and rejected: mirror ADR-0007's clamp for
`expires_at`. Rejected because the two cases are not the same shape.
`expires_at` is a single scalar with one unambiguous clamp value (the
parent's own `expires_at`). A budget identity is drawn from an open set — a
kind, plus for `budget_calls` a caller-chosen `scope` string — so there is no
single value an issuer could synthesise on the caller's behalf without
guessing. Refusing, with a named helper (`inherit_parent_budgets`) to make the
common case a one-line opt-in rather than hand-retyping, is the pairing
ADR-0007 itself used for a different problem (the fail-open revocation
default, `the-fail-open-default-priced.md`): a behaviour change ships
together with the one line that restores the old convenience, in the same
release, in all three languages.

**6. Fan-out is explicitly NOT restricted by this predicate.** Minting
several children, each attenuated to the exact same parent ceiling, is
permitted — `budget_v1.json` pins two cases proving it. Safety is the
ledger's job (phase 3, outside this conformance surface, the same posture
ADR-0001 gives revocation): every descendant's spend aggregates against every
ancestor's remaining budget, so a parent's actual total consumption — not the
number of children that could, on paper, each reach its limit — is what is
checked. `budget_attenuation_reason` has no visibility into siblings and
should not acquire any; teaching it to count would mean refusing a second
child because a first one *might* spend its whole allowance, which has no
basis.

**7. No `sig_version` bump; no re-freeze of any existing vector.** Per
`scope.md` S.13 constraint 4, adding a recognised `kind` value changes no
document's required member set, so it is additive and minor-version only. A
budget-naive verifier refuses an entry it does not recognise (S.10) rather
than silently granting unlimited authority. `budget_v1.json` is a new vector
(predicate-only, no digest, no signature, the same shape as
`scope_kinds_v1.json`), not a revision of an existing one.

## Consequences

**Accepted:**

- `scope_boundary` gains a quantitative axis without a wire break, exactly as
  ADR-0009 anticipated it could.
- A budget cap composes with every existing kind: `scope_contains`,
  `scope_attenuates`, revocation, and expiry containment are all unaffected,
  because budget containment is additive code, not a modification of theirs.
  The full existing suite (Rust 120 lib tests + integration suites; Python
  375; TypeScript 336) passes unchanged with these additions.
- Fan-out — several agents each delegated up to a shared parent's ceiling —
  is possible without `mint_child` needing any knowledge of siblings, because
  safety is pushed to the one place that actually has the information
  (the ledger).

**Costs, accepted knowingly:**

- `mint_child`'s attenuation check for budgets requires an explicit
  `inherit_parent_budgets` call on every delegation path that means to carry
  limits forward; an omission is a hard refusal, not a silent narrowing. This
  is the same trade ADR-0007 made for the fail-open revocation default:
  changing a default without a named one-line opt-in is the unacceptable
  outcome, not the behaviour change itself.
- This ADR fixes only the STATIC half (ceiling containment, offline,
  reproducible by any party from two documents). The LIVE half — actual
  remaining budget, which requires a durable ledger — is explicitly out of
  scope here, exactly as revocation is out of VAID's conformance surface
  under ADR-0001, for the identical reason: it requires state no document
  can carry.

**Explicitly not decided here:**

- Where metering happens in a deployed substrate (model gateway, policy
  evaluation) and the ledger's schema and durability requirements — phase 3,
  a separate decision, owned by the services that need it (SYNTHERA substrate,
  forge-api, UAB).
- The signed exhaustion-evidence record's exact format — modelled on
  `consent-attestation.md`'s detached, additive, independently-versioned
  pattern, but not specified here.
- How a customer-supplied model gateway (UAB's "customer gateway URL") interacts
  with cost/token metering, which the Solara-operated gateway cannot see once
  bypassed. Flagged for Allan's decision in the phase-3 planning note; not
  resolved by this ADR.

## Alternatives considered

**Clamp an omitted budget identity to the parent's, as `expires_at` is
clamped (ADR-0007).** Rejected — see decision point 5. The clamp value for a
scalar deadline is unambiguous; the clamp value for an open-set identity is
not, and guessing is worse than refusing.

**Fold a budget condition into a capability string** (e.g.
`payments.transfer<=100`). Rejected on S.12's own terms: capability matching
is exact equality with no refusal rule, so an embedded condition fails open
or fails closed depending only on which side wrote it — not a decision
anyone made, and the exact defect ADR-0005 found in the pre-typed `prefix`
matcher, in a different place.

**Add a top-level document member** (`"budget": {...}`). Rejected on
ADR-0006's own terms: an old verifier preserves and ignores an unknown
document member, which means it grants the unlimited action silently — the
precise failure the typed-kind registry (ADR-0009) exists to prevent.

**Restrict fan-out at mint time** (refuse a second child at the same ceiling
as a first). Rejected: `mint_child` does not and should not know what a
sibling has spent — only the ledger does, continuously, at use. Enforcing a
static per-sibling restriction would refuse delegations with no actual
overconsumption, on the basis of a worst case that may never occur.
