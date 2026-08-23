# ADR-0007: Durable revocation is two stores, and they are injected as one

**Status:** Accepted. Shipped in `vaid-mint` **0.8.0** (Rust, Python, TypeScript), **prepared not published** — see "Release", below.
**Date:** 23 August 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0001 (revocation outside the conformance surface),
`docs/spec/revocation.md` R.4.1/R.4.2/R.4.6,
`docs/findings/durable-revocation-is-two-stores-and-the-symptom-is-an-outage.md`,
`docs/findings/the-reference-revocation-default-is-documented-not-hidden.md`

---

## Context

R.4.6 requires durability of **two** stores: the revoked set and the lineage
resolver. The crate offered an injection point for exactly one.

`ReferenceIssuer::with_revocation_check` replaced the revoked set. The resolver was
a private map on `ReferenceIssuer` with no way to substitute it, and — the part that
made substitution impossible rather than merely inconvenient — **no write half at
all.** `LineageResolver` is read-only; the issuer wrote every mint into its own map
directly. A self-hoster who implemented `LineageResolver` had no way to get anything
into it.

So the half-configuration was not one of the states a self-hoster could reach. It
was the **only** state a self-hoster could reach, and it is the state whose symptom
is an outage:

| Persisted | Child credential | Root credential |
|---|---|---|
| both | verifies | revocation in force |
| lineage only | verifies | **verifies — the revocation is gone** |
| revoked set only | **`Unavailable` — outage** | revocation in force |

Persist the revoked set alone and, after a restart, every VAID carrying a
`parent_vaid` is unresolvable → `Incomplete` (R.4.2) → `Unavailable` (R.4.3) →
refused (R.4.5). Every rootless VAID is untouched, because it is trivially complete
and never consults the resolver. The failure is therefore **total for delegated
credentials and invisible for root ones**, it arrives at restart rather than at
deploy, and — since nothing was revoked — it is first diagnosed as a signing or
clock problem.

None of that is a defect in the specification. R.4.2 and R.4.6 both name the two
stores, and failing closed on an unresolvable ancestry is the whole point: the
alternative is a child masquerading as rootless and silently discarding its
ancestors' revocations. The system is choosing an outage over a security hole,
correctly. The defect is that the API let you reach that choice by omitting an
argument.

## Decision

**Make the half-configuration unreachable by omission, rather than making the two
stores durable together.**

The brief offered both framings. The second is the better fix, for a reason that
outlives this change: a seam that can express "revocation persisted, lineage not"
will eventually be configured that way, and no amount of documentation converts a
reachable state into an unreachable one. A seam that cannot express it needs no
documentation to be safe.

Concretely:

1. **`LineageStore`** — `LineageResolver` plus `record(vaid_id, parent)`. The write
   half. Without it a durable resolver is injectable and permanently empty, which is
   the same outage with extra steps. Roots are recorded as `None`, not omitted; a
   store that omits roots answers *unknown* for every root and turns the whole
   deployment `Unavailable`.

2. **`InMemoryLineageStore`** — the reference resolver, lifted out of
   `ReferenceIssuer` into a named, injectable object. It was already the reference
   resolver; it was not previously a thing you could name.

3. **`RevocationBackend`** — holds both halves. **There is no single-half
   constructor.** The failure being prevented is not a wrong value, it is a missing
   second argument, and a missing argument is the one class of mistake a type can
   refuse outright.

4. **`ReferenceIssuer::with_revocation_backend`** — the only way to replace either
   half. `with_revocation_check` was deprecated when this landed and **removed in the
   same 0.8.0 release**: a deprecation window is a period during which the
   reachable failure stays reachable, and the two breaking changes in 0.8.0 are
   the same argument made twice.

### Two objects, not one trait

`RevocationBackend` holds two `Arc`s rather than being a single trait with both
methods. A combined trait would also make the half-state unrepresentable, and it
would violate R.4.1: *"the check does not perform lookups and is not given the means
to."* A pair requires both halves without handing either one the other's job.

### What this does not claim

The half-state is unreachable **by omission**, not unreachable. A caller can still
pass `InMemoryLineageStore` as the second half. That is deliberate: it is a
legitimate choice for a single process that mints and verifies and is never
restarted, and after this change making it requires naming the non-durable store at
the call site. "Cannot happen by accident" is the property available here; "cannot
happen at all" would forbid a legitimate deployment.

`with_revocation_check` was removed in 0.8.0 rather than carried through a
deprecation window (decision owner, 2026-08-23). It replaced one store and left the
other in memory; that is not a degraded mode but an outage, and a window is a period
during which the reachable failure stays reachable.

### Durable backends stay out

Durable hash-chained revocation remains outside the open crate. What landed is the
seam and an **in-repo durable test double** — JSON files, no locking, no integrity,
no concurrency story — which exists only to prove the seam can carry a durable
implementation across a restart.

## Proof: a restart, not a round trip

Every prior revocation test in this repository writes and reads back inside one
process. `clear_lineage()` *models* a restart and cannot catch a store that silently
fails to persist.

`crates/vaid-mint/tests/durable_restart.rs`, `python/vaid-mint/tests/test_durable_restart.py`
and `typescript/vaid-mint/test/durable_restart.test.ts` spawn **real child
processes**. One mints a root, a child of it, and a second root; revokes the second
root; and exits. A second process rebuilds the issuer from the persisted seed and
the stores from the persisted files, and reports what the restarted deployment
believes.

Non-vacuity is asserted **positively**, not as "the test goes red". Each mutation is
its own test with its own expected observations:

- **lineage dropped** → child `Unavailable` and refused; revoked root still
  `Revoked`; **child still authentic** — the assertion that retires the "it must be
  a signing or clock problem" diagnosis.
- **revoked set vouching-when-absent** → the revoked root verifies clean. The
  security half, and the reason a durable store must never copy the shape of
  `assume_nothing_revoked`.
- **control** — the same absent revoked set read by a store that reports absence
  honestly: `Unavailable`, refused.

The first mutation is also the proof that the harness restarts at all: it can only
pass if the in-memory store the second process builds is empty, which can only be
true if that process did not inherit the first's memory.

The honest test was additionally observed going red under each break, one at a time,
with the expected diff in each case.

## Cross-language and conformance

The seam lands in **all three implementations simultaneously** — Rust, Python,
TypeScript — with the same names and the same shape. A seam present in one language
and absent in another is worse than no seam.

**No conformance impact.** Revocation is outside the conformance surface (R.1), and
`verdict_v1.json` takes revocation status as an *input* rather than deriving it, so
no case in it depends on how a status is obtained. `verify-vector-freeze` reports 32
vectors unchanged.

## Release

Shipped in **0.8.0**, alongside the reference-default flip
(`docs/findings/the-fail-open-default-priced.md`) — two breaking changes in one
release, in all three languages simultaneously. **Prepared, not published:** the
version numbers are moved, the changelogs are promoted, and the release is gated on
the decision owner running the publish tags. A default that is fail-closed in one
language and fail-open in another would make the reference implementations disagree
about a safety property while every conformance vector still passes, which is exactly
the class of divergence the vectors exist to prevent and cannot see.
