# ADR-0005: Scope containment is segment-bounded, over two reserved separators

**Status:** Accepted
**Date:** 5 August 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0001 (revocation outside the conformance surface — which deferred
exactly this decision), ADR-0003 (attenuation verification via detached chain),
`docs/spec/scope.md`, `scope_v1.json`

---

## Context

ADR-0001 §"Explicitly not decided here" ends with one line:

> The `scope_boundary` expressiveness limitation. Separate decision, separate ADR.

This is that ADR. What it turns out to be is not an expressiveness question but a
security one.

All three reference implementations decided scope containment by bare prefix
matching — `resource.startsWith(entry)` in TypeScript, `.startswith` in Python,
`starts_with` in Rust. Under that rule:

```
boundary  data.governance
resource  data.governance-secret     →  CONTAINED
```

`data.governance-secret` is a **sibling**. It shares a textual prefix with
`data.governance` and nothing else. No hierarchy relates them.

That predicate is not decorative. It decides both of the things scope exists to
decide, and ADR-0001 §2 puts both inside the conformance surface:

1. **mint-time attenuation** — whether a child may be issued authority under a
   parent; and
2. **third-party chain verification** (ADR-0003) — whether a verifier holding a
   presented chain confirms that delegation.

So a holder of a VAID scoped to `data.governance` could mint a child scoped to
`data.governance-secret`, and a conforming third-party verifier would confirm the
child as a legitimate attenuation of its parent. That is privilege escalation across
a delegation boundary, and it verifies.

**Three facts about how this survived**, because they matter more than the bug:

- It was present identically in Rust, Python and TypeScript. Cross-implementation
  agreement was total, and worthless — three mirrored ports of one wrong rule agree
  perfectly.
- **No frozen vector polices the matcher.** `mint_v1`, `mint_pop_v1`, `chain_v1` and
  `attestation_v1` all pin *bytes*; containment is a predicate computed over a
  document and never appears inside one, so nothing was asking.
- **No existing test exercised the bug class.** Across all 23 scope literals in the
  three test suites, every one is either equal or properly dot-nested. Zero tests
  change verdict under the fix. The bug was not weakly tested; it was untested.

## Decision

**Containment is segment-bounded over two reserved separators, `/` and `.`, both
always honoured, with segments constrained not to contain either.**

Normatively specified in [`docs/spec/scope.md`](../spec/scope.md); summarised:

1. **S.2 — the separator set is `{/, .}`**, closed and fixed by the specification. An
   implementation MUST NOT add, remove or configure it. A scope segment MUST NOT
   contain a separator.
2. **S.3 — entry `P` contains resource `R`** iff `R == P`, or `P` ends with a
   separator and `R` starts with `P`, or `R` starts with `P` followed by a separator.
   An empty boundary *list* is ⊤. Bare prefix matching is not containment.
3. **S.6 — the segment constraint is normative on producers but not enforced by the
   matcher in 0.5.0.** Enforcement would reject documents this version accepts, which
   is a second breaking change; it is deferred to its own revision.
4. **A new frozen vector, `scope_v1.json`**, pins the verdicts in all three
   languages. It carries no digest and no signature — there are no bytes to pin.

### Strictly narrower, verified not asserted

The new rule denies cases the old allowed and **permits nothing the old denied**.
This is checked exhaustively over a generated corpus by
`the_rule_is_strictly_narrower_than_bare_prefix_matching`, which fails on any
widening. It follows that:

- no previously-rejected delegation becomes possible;
- no document bytes change, and **no existing frozen vector's verdict changes** —
  `chain_v1.json` was checked specifically, since it is the one vector whose
  verification runs containment: its scopes are properly dot-nested and both rules
  accept every hop;
- the sole behavioural change is that some delegations that used to succeed now fail.

## Options considered

**A — a single normative separator.** Cleanest rule, and unavailable. A `.`-only rule
stops `t/research` containing `t/research/sub`; a `/`-only rule stops
`data.governance` containing `data.governance.reports`. Both conventions exist in
production today, the standard has no principled basis for preferring one, and either
choice forces a full scope-vocabulary migration on somebody.

**B — a deployment-configurable separator set.** Superficially the flexible answer,
and ruled out by ADR-0003 rather than by taste. A third party recomputing containment
from a presented chain has only the documents; if the separator set were
deployment-local it could not know which rule the mint applied, and could not
reproduce the verdict. Containment would stop being decidable from the documents,
which is the property the entire attenuation-verification design rests on.

**C — both separators, unconstrained segments.** This is the substrate's rule as
inherited. Rejected as *specified*, adopted as *implemented*. The mechanism is right;
the justification does not survive the move to an open standard.

The substrate's own record (synthera ADR-0010 phase 3B) defends honouring both on the
grounds that its producers are each constrained to a single grammar, so mixed
separators are unreachable **by construction**. That is true of the substrate and
false of an open standard, which controls none of its implementers. Shipped as-is, an
implementer treating `/` as their separator and `.` as an ordinary character would
find `data/user` containing `data/user.admin` — the identical sibling-capture bug,
reintroduced through the other separator.

**D — both separators, with segments constrained (chosen).** Same matcher as C,
different foundation: the specification **reserves both characters** rather than
hoping producers avoid the collision. `data/user.admin` is then unambiguously the
path `data`, `user`, `admin`, and containment is correct rather than accidental. This
inverts the substrate's logic — instead of relying on producers happening to use one
grammar, the standard imposes the grammar — and it is the only option that is safe
without assuming anything about who implements it.

## Consequences

**Accepted:**

- The escalation is closed at mint and at third-party verification simultaneously,
  because both call one matcher.
- The matcher acquires a conformance vector for the first time. Given how this bug
  survived, that is the more durable half of the change: `scope_v1.json` is what will
  catch the next mirrored-port mistake.
- The separator set and the segment constraint are now stated where an implementer
  reads them, with the reasoning attached, instead of being inherited from another
  repository's ADR that does not apply to them.

**Costs, accepted knowingly:**

- **It is a breaking change**, shipped as 0.5.0 across all three packages. Under
  Cargo 0.x semantics minor is the breaking slot; PyPI and npm follow the same number
  for parity. A deployment relying — knowingly or not — on a sibling being contained
  will see mints and chain verifications start failing. That is the fix presenting
  itself, and the release notes say so in those words.
- **S.2 is unenforced in this revision.** A producer that violates it gets a
  containment result that follows S.3 exactly, which will not be the one it intended.
  Enforcement is deferred, named, and scoped in S.6 rather than left implicit.
- **No escaping mechanism is defined.** An implementer needing a literal separator
  inside a name must encode it before it reaches `scope_boundary`. Defining escaping
  would change the canonical bytes of the field and is a future versioned change.

## Revisiting

- **A producer with a legitimate need for a literal separator in a segment.** That is
  the trigger for specifying an escaping mechanism, and it is a bytes-affecting
  change, so it needs its own vector and its own version.
- **Enforcement of S.2 at mint** — the deferred half. It should ship on its own,
  since it rejects documents that 0.5.0 accepts.
- **A third separator convention appearing in a real deployment.** The set is closed
  deliberately; adding to it is a specification change, not a configuration one, and
  it would need to explain how existing verifiers reproduce verdicts across the
  change.
