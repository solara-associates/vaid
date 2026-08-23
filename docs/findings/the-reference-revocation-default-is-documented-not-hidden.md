# The reference revocation default is documented, not hidden — and the spec that documents it is five versions stale

**Date:** 2026-08-23
**Repo:** `vaid`
**Raised by:** on-premise deployment scoping (`solara/docs/findings/on-premise-deployment-scope.md` §3.3)
**Status:** OPEN — one spec edit needed. **No code change proposed.**

---

## Why this document exists, and the correction it opens with

This finding was commissioned on the premise that
`InMemoryRevocationList::assume_nothing_revoked()` is *"a fail-open default whose
docstring admits it is a fail-open posture, shipping in our public package under our
name"* — i.e. an unflagged hazard.

**That premise is wrong, and the record should say so plainly.** The default is not
undocumented, not buried, and not accidental. `docs/spec/revocation.md` R.6 carries a
dedicated, titled note — *"Note on the reference default (0.2 onward)"* — which:

- names the constructor and explains the naming (*"named `assume_nothing_revoked`,
  not for its empty state but for what it does"*);
- states the exact failure verbatim: *"after a restart it is reconstructed empty and
  again vouches `NotRevoked`, so a VAID revoked before the restart verifies clean"*;
- calls it *"a deliberate trade of restart-detection for out-of-the-box usability in
  development"*;
- argues its legitimacy under **R.4.6** (which requires only that an *absent* store
  report `Unavailable`, and that absent be distinguishable from vouching — both hold)
  and explicitly disclaims it under **R.4.5**: *"it is not a fail-open verifier
  setting, it is the reference's development default, and it is named to be
  unmisreadable"*;
- gives both remediations — inject a durable `RevocationCheck`, or start the store in
  absent state until revocation state has been loaded.

**VERIFIED** — I read R.4.5, R.4.6 and R.6 in full on `origin/main`.

So the disclosure discipline here is better than the estate's own summary of it. The
earlier scope-document phrasing (*"the shipped default does not exercise the
fail-closed guarantee"*) is factually right about behaviour and misleading about
posture, because it implies an omission that does not exist.

**The real defect is the opposite of the one alleged, and it is worth fixing.**

## The real defect: R.6 describes a product five minor versions old

`docs/spec/revocation.md` R.6 "Implementation status" is a two-column table headed
**"0.1.2 (current)"** and **"0.2 (planned)"**. Under it, in bold:

> **The 0.1.2 seam does not satisfy R.4.** It accepts a single identifier and returns
> a boolean, so revocation of a parent does not affect an attenuated child, and a
> failed check is indistinguishable from a clean one. Deployments on 0.1.2 should
> treat revocation as covering root VAIDs only, on a single issuer process, with no
> restart.

**`crates/vaid-mint/Cargo.toml` is at version 0.7.0.** **VERIFIED.** The three-state,
lineage-aware seam described in the "planned" column shipped at 0.2 and has been the
only seam since. There is no boolean seam; ADR-0001 records that it was replaced with
*"deliberately no shim keeping the old signature alive"*.

So a reader arriving at the specification today — which is exactly what ADR-0001 says
the specification is for, *"What a first-time evaluator meets on 4 August is the
specification, not the implementation"* — is told in bold that the shipped seam does
not satisfy the spec's own central section, and is given deployment advice for a
version nobody can install.

This is **underclaiming**, not overclaiming, which is the rarer direction and the one
nobody checks for. It costs credibility differently but it costs it: a careful
evaluator either believes it and discounts the product, or checks the source, finds it
false, and now distrusts the rest of a document whose entire value is that it tells
the truth about limitations.

It also has a second-order effect worth naming: **R.6 is the section an evaluator uses
to calibrate how much of the rest of the spec is aspirational.** A stale status table
makes every honest disclosure elsewhere in the document read as possibly-stale too —
and this document's honest disclosures are its whole value. The cost of the stale
table is therefore not confined to R.6; it is a discount applied to R.4.5, R.4.6 and
the reference-default note as well.

**This drifted for a structural reason, not a human one — see "The cause" below.
Fixing the table without fixing the asymmetry buys one correction, not the class.**

## What should change, and what should not

**Change:** R.6's table columns and the bold paragraph beneath it. The columns become
something like "0.1.2 (superseded)" and "0.2 onward (current)", and the paragraph
retains the 0.1.2 description as history while stating that the shipped seam satisfies
R.4. The "Note on the reference default" beneath it needs no change at all — it is
already written for "0.2 onward" and is correct as it stands.

**Do not change:** `assume_nothing_revoked()` itself. `vaid` is published to three
registries; the reference issuer's default store is observable behaviour, and changing
it is a semver decision, not a docs fix. Recorded here so nobody treats this finding
as authorisation to touch it.

For completeness, the argument each way, since the question will be asked:

- **For flipping the default to absent-state.** Verification would then fail closed
  out of the box, and a self-hoster who reads nothing still gets safe behaviour. R.4.6
  already blesses absent-state as the mechanism.
- **Against.** A fresh issuer would verify nothing until revocation state is loaded,
  which breaks first-run experience for every new adopter and every quickstart — the
  exact usability the current default was chosen to buy. And it is a breaking
  behavioural change to a published package, so it needs a major version, a migration
  note, and a reason better than "a summary of it was misleading."

That trade is a product decision for whoever owns `vaid` versioning. This finding does
not take it.

## The cause: two claim surfaces, one guarded and one not

The stale table is the symptom. **The cause is an asymmetry in what this repository
enforces, and it is worth stating on its own because it predicts the next occurrence
as well as explaining this one.**

`vaid` publishes version-bearing status claims in **two** places. They are guarded
very differently:

| Surface | What it claims | CI enforcement |
|---|---|---|
| `docs/capabilities.json` | per-capability status, `shipped`/`planned`, package versions | **Two checks.** A drift check requiring every vendored copy to byte-match, and `scripts/verify-capabilities.mjs`, which fails when a `shipped` capability's package version is not published on its registry, and when a `roadmap`/`planned` capability is blocked on a PR that has since merged. |
| `docs/spec/revocation.md` R.6 | which version is current, and whether it satisfies R.4 | **None.** |

**VERIFIED** — the capabilities checks and their rationale are stated in
`capabilities.json`'s own `_comment`; the specification has no equivalent guard
anywhere in the repository.

So one surface cannot go stale without turning a build red, and the other can only go
stale — and did, for five minor versions, unnoticed. That is not carelessness by
whoever last edited R.6. It is the predictable output of guarding one claim surface
and leaving the other to human diligence, and the same asymmetry will produce the same
result again in whichever section next carries a version number.

Two consequences follow, and the second is the one that matters:

1. **The immediate fix is small.** Assert that the version R.6 names as "current"
   matches `crates/vaid-mint/Cargo.toml`. The machinery already exists; this is a few
   lines alongside `verify-capabilities.mjs`.
2. **The general fix is to stop treating the specification as prose.** R.6 is not
   commentary — it is a structured status claim in a table, of exactly the kind
   `capabilities.json` exists to keep honest. Either it should be generated from that
   file, or it should be checked against it. Anything version-bearing in the spec that
   is neither is a claim with no owner.

**Related estate notes.** *"Drift checks prove match, not currency"* applies here in
reverse: there was no check at all, so nothing even proved a match. And
*"absence has no representation"* is the precise mechanism — a guard that walks
`capabilities.json` cannot see a claim that lives in a markdown table it was never
pointed at.
