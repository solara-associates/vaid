# ADR-0001: Revocation is outside the VAID conformance surface

**Status:** Accepted
**Date:** 27 July 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Supersedes:** none
**Related:** VAID v0.1 frozen conformance vectors

---

## Context

VAID v0.1 shipped on 13 July 2026 with four packages across Rust and Python and a set of frozen, byte-identical cross-language conformance vectors. Those vectors are the load-bearing claim of the project: a conforming implementation in any language agrees byte for byte with every other conforming implementation.

The reference mint shipped a pluggable `RevocationCheck` seam in 0.1.2, in both Rust and Python, but it is a boolean, leaf-only check, and three weaknesses follow from that. Its state is held in memory only, so revocation is lost on restart, is not shared across instances, and is not verifiable by any party other than the mint process itself. A boolean cannot express that the check was unavailable, so a failed or unreachable check is indistinguishable from a clean one. And because only the presented leaf is checked, revoking a parent does not revoke a VAID attenuated from it — the check is bypassable by minting a child. This work replaces that seam with a three-state, lineage-aware one; it is not the addition of a seam where none existed. For a bearer-token system this is the first gap a knowledgeable evaluator finds, and it is found early.

Two pieces of work are now committed:

1. Closing the revocation gap on the reference mint, in Rust, Python and TypeScript.
2. A TypeScript implementation published to npm, validated against the existing frozen vectors.

These collide on timing. A TypeScript port cannot begin against a stable target until it is known whether a conforming implementation must reproduce revocation semantics. If revocation is inside the conformance surface, new vectors must be designed and frozen before the port starts.

A further constraint: as of this date no party outside Solara has built anything on VAID. The first external evaluator, expected 4 August 2026, will read and assess rather than integrate. Any revocation format frozen before that point would be frozen without having survived contact with a single external implementer.

This shapes what has to exist first. What a first-time evaluator meets on 4 August is the specification, not the implementation. The revocation gap is discoverable in the first ten minutes of a serious read. Whether it costs credibility depends entirely on whether the spec has already named it as a deliberate decision.

## Decision

**Revocation is outside the VAID v0.1 conformance surface.**

Specifically:

1. The existing frozen conformance vectors do not change. They remain the complete definition of v0.1 conformance.
2. Conformance is defined over mint, attenuation, and verification of VAID credentials. It does not extend to revocation list format, revocation distribution, or revocation check semantics.
3. The specification states this exclusion explicitly and argues for it. Silence on this point is not acceptable. An identity protocol that omits revocation from its conformance surface without saying so reads as an oversight, and will be read that way by exactly the people whose opinion matters.
4. The specification also defines the `RevocationCheck` seam as non-normative guidance. It is a host-application integration point, not a protocol element, and implementations may back it with any store.
5. Short TTL enforcement remains in place as defence in depth. It is never described, in code comments, documentation, or public material, as the answer to the revocation gap. It is a mitigation that limits blast radius, nothing more.

A signed pollable revocation list may ship later as the reference default behind the seam. Shipping it does not, by itself, bring revocation into the conformance surface. That would require a separate ADR.

## Ordering

Specification text lands first, ahead of any implementation work. It is roughly a day of writing and it is the artifact that carries the decision to a reader.

Implementations follow per language and are not required to land together:

- Rust and Python replace their 0.1.2 boolean seam with the three-state, lineage-aware one after the spec.
- TypeScript is born with the three-state seam as part of the port, against a spec that already exists rather than one being drafted.
- All three carry the three-state seam at v0.2.

Because the spec defines the replacement shape before any language implements it, the interval in which the three differ is a stated roadmap position rather than an inconsistency a reader discovers. This is the reason spec-first matters here and not merely a matter of convenience.

## Seam definition

The seam's shape is specified in [docs/spec/revocation.md](../spec/revocation.md) R.4, not here. It is pinned down there because revocation sits outside the conformance surface: no vector polices it, and nothing else would catch independent implementations drifting into different shapes. The spec fixes the input and how ancestry is handled, the three-state return, the failure semantics, and where the check is invoked; this ADR does not duplicate that shape.

One point belongs to the decision rather than the shape, and is recorded here: the default on check-unavailable is **fail-closed** (settled in R.4.5). Prior SENTINEL work in this tree surfaced five separate paths that failed open while reporting success, and a revocation check that silently passes when its backing store is unreachable is the same defect in a more sensitive place. Fail-open exists only as an explicit, recorded, non-default configuration, never a default that arrives by omission.

## Consequences

**Accepted:**

- The TypeScript port proceeds against an unchanged, already frozen target, with no dependency on revocation design completing first.
- The specification a first-time evaluator reads on 4 August already accounts for the revocation gap.
- Revocation design is stress tested against real integrators before any part of it is frozen.
- v0.1 conformance claims made in launch materials remain true and unmodified.

**Costs, accepted knowingly:**

- VAID publicly declares an identity protocol whose conformance surface excludes revocation. Defensible, but it must be defended in writing rather than assumed.
- Two conforming implementations can differ in revocation behaviour while both remaining conformant. Correct for v0.1, less correct as adoption grows.
- Between the spec landing and v0.2, the three implementations are not at parity on the seam. Stated openly in the spec roadmap.
- The decision is likely to be revisited. Expect a v0.3 ADR proposing that revocation move inside the surface once there is field evidence for what the format should be.

**Explicitly not decided here:**

- Whether a signed pollable revocation list ships as the reference default, and on what timeline.
- Fail-closed versus fail-open on check-unavailable. Flagged above, needs its own record.
- The `scope_boundary` expressiveness limitation. Separate decision, separate ADR.

## Alternatives considered

**Revocation inside the conformance surface (option B).** Stronger long-term protocol position and the more complete answer for an identity system. Rejected for v0.1 on timing: it requires designing and freezing new vectors before the TypeScript port can start, and freezes a revocation design that no external implementer has yet touched. The position is right; the moment is wrong.

**Implementation first, spec text later.** Rejected. It puts the artifact before the argument, which is the same error the launch made. It also leaves three implementations building a seam with no written definition to agree on.

**Short TTL only.** Rejected. A time bound is a mitigation, not a revocation mechanism, and a knowledgeable reader will correctly read it as one. Shipping it as the answer would cost more credibility than the original gap.

**Leave the gap open and say nothing until v0.2.** Rejected. Evaluators who find it will not open an issue. They will leave silently, and the project learns nothing.

## Implementation notes

- No changes to the frozen vector files. Any diff to those files during this work is a defect.
- Replacing the 0.1.2 boolean seam changes the public `RevocationCheck` signature in Rust and Python; it ships as the 0.2.0 breaking change. TypeScript is born with the three-state seam and has nothing to break.
- Spec roadmap must state per-language seam availability so the parity gap is visible rather than discovered.
