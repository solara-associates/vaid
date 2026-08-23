# Durable revocation is two stores, and getting it half right is an outage, not a hole

**Date:** 2026-08-23
**Repo:** `vaid`
**Raised by:** on-premise deployment scoping (`solara/docs/findings/on-premise-deployment-scope.md` §3.3)
**Status:** PARTLY CLOSED 2026-08-23. The summary surfaces were corrected (root,
Rust, Python and TypeScript READMEs now say *"durable revocation **and** durable
lineage resolution are host-application responsibilities"*), and a code change this
finding did not propose followed from it: the crate offered an injection point for
the revoked set and **none at all** for the resolver, so the half-configuration
described below was the only one a self-hoster could build. `RevocationBackend` now
requires both halves — see ADR-0007 and `docs/spec/revocation.md` R.4.6. Unreleased.
Original status: OPEN — a documentation gap between the specification and the
summary of it in circulation. **No code change proposed.**
**Audience:** anyone implementing a durable `RevocationCheck` — internally or as a self-hoster.

---

## Correction first

This finding was commissioned as *"a second durable store nobody has named."*

**The specification names it, twice, and in the right places.** **VERIFIED** — I read
both sections on `origin/main`:

- **R.4.2 Lineage assembly** — *"The full lineage is not recoverable from the VAID
  itself. Assembly requires a resolver, and the reference implementation's resolver is
  the issuer's in-process lineage map."* It then spends a paragraph on the exact
  failure that follows from an empty map after restart, and closes: *"An
  implementation that cannot distinguish 'this VAID has no parent' from 'I could not
  resolve this VAID's parent' does not satisfy this section."*
- **R.4.6 Durability** — *"Revocation state **and lineage state** that do not survive
  process restart do not provide revocation."* R.6's status table carries two separate
  rows, *"Revocation store durability"* and *"Lineage store durability"*, and the
  paragraph beneath says *"The reference implementation currently ships non-durable
  in-memory stores **for both revocation and lineage**."*

So the spec is complete on this point. **The gap is not in the specification. It is
between the specification and the one-line summary of it that circulates internally**
— "pluggable `RevocationCheck` seam, TTL enforced at verification,
`InMemoryRevocationList` as the self-hoster default, durable hash-chained revocation
as a deliberate design boundary." That summary is accurate about the seam and silent
about the resolver, and it is the version most people carry in their heads, because it
is shorter.

Anyone implementing durable revocation from **the summary** will build one store.
Anyone implementing from **the spec** will build two. This document exists so the
first group finds out cheaply.

## The part neither document spells out: what half-done looks like from operations

The spec states the requirement. It does not state the **symptom**, and the symptom is
counter-intuitive enough to be worth writing down, because it will be diagnosed as a
different problem.

Persist the revocation set, leave the lineage resolver in memory, restart the process,
and:

- **every root VAID keeps verifying** — a root is *trivially complete* under R.4.2, no
  resolution needed, so the durable set answers cleanly;
- **every child VAID stops verifying** — its `parent_vaid` is present and now
  unresolvable, so assembly returns *Incomplete*, which R.4.2 requires be reported as
  `Unavailable`, and R.4.5 requires verification fail closed on `Unavailable`.

So the failure is **total for delegated credentials and invisible for root ones**, and
it appears at restart rather than at deploy. The likely first diagnosis is a signing,
clock or key-rotation problem, because "revocation" is the last subsystem anyone
suspects when nothing was revoked.

**This is the design working exactly as specified.** Failing closed on an
unresolvable ancestry is the whole point of R.4.2 — the alternative is a child
masquerading as rootless and silently discarding its ancestors' revocations. The
system is choosing an outage over a security hole, correctly.

It is still worth saying out loud, because "I implemented durable revocation and now
delegation is broken" is a support conversation that will otherwise be had from
scratch every time, and because the fix is not obvious from the symptom.

## What to build, stated as a checklist

Two durable things, not one:

1. **The revocation set** — the `RevocationCheck` implementation. A single method over
   an already-assembled lineage. Genuinely small; an afternoon against any store.
2. **The lineage resolver** — a durable `LineageResolver` that survives restart and,
   critically, **distinguishes a known root from an unknown identifier**
   (`ParentResolution::Root` vs `ParentResolution::Unknown`). A resolver that returns
   "no parent" for an id it has never seen re-introduces exactly the bug R.4.2 exists
   to refuse, and does so while looking correct.

Sequencing that avoids the outage: **make the resolver durable first, or make both
durable in the same change.** Doing the set first is the ordering that produces the
symptom above.

An intermediate posture the spec already blesses, and which is the safe way to deploy
either half: start the revocation store in **absent** state, so it reports
`Unavailable` and verification fails closed, until state has been loaded into it.
Refusing to verify while a store warms is a deliberate, brief, visible outage rather
than a silent window of unrevoked credentials.

## The one place this is already solved, for reference

The SYNTHERA substrate has both halves durable — `[audit] backend = "postgres"` and
`[identity] revocation_backend = "postgres"`, the revoked set write-through behind an
in-memory read cache and warmed via `load_all()` at startup, and VAID lineage in
`PgVaidStore`. **VERIFIED.** Its config carries a paired warning for the half-done
case: a durable kernel key with an in-memory revoked set *"would let a revoked VAID
wrongly re-verify after restart"*.

That substrate is proprietary and is not what a self-hoster gets. It is named here
only as evidence that the two-store shape is the real shape, and that someone has
already paid for the lesson.

## Suggested change, minimal

Not to the specification — R.4.2 and R.4.6 are correct and complete.

To **the summary**. Wherever the revocation position is stated in short form —
internal briefs, sales enablement, the site, README prose — the phrase
*"durable revocation is a host-application responsibility"* should read
*"durable revocation and durable lineage resolution are host-application
responsibilities"*. Six words, and it is the difference between an implementer
building one store and building two.
