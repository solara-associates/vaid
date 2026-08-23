# `vaid-skill` reports a document authentic that the specification says is not a document

**Severity: MODERATE.** A conformance divergence in a published tool, on the path its
users exercise, that no version bump fixes. **Not** a privilege-escalation vector —
measured, below, and the signature closes that path. It is misrepresentation, not
elevation: the tool answers a question the standard says has no answer.

**Date:** 2026-08-23
**Repo:** `vaid` (subject: `skill/`)
**Status:** OPEN, **not fixed**. No code changed. The fix is a decision about the
skill's parse path, not a dependency bump.
**Second instance of a known class** — see
`forge-agents:docs/findings/agent-verifier-parses-its-own-documents-e7a-unreached.md`
(2026-08-14), which found the identical mechanism in the agent templates.

---

## The claim, and the correction it opens with

This was raised as *"the skill pins `vaid-mint` ^0.6.0 and so misses the E.7a
duplicate-member refusal that landed in 0.7.0; bump it."*

**The exposure is real. The remedy is wrong, and stating it wrongly is worse than not
raising it**, because it converts a live defect into a version number somebody ticks
off. **Bumping the pin does not fix this.** `vaid-skill` accepts a duplicate-member
document at 0.6.0, at 0.7.0 and at 0.8.0, and will keep accepting it at every future
version, because the refusal is not on the function it calls.

## Measured, not reasoned

Minted a real VAID with the in-tree implementation, then presented the same document
with `scope_boundary` repeated, to `verifyVaidAuthenticity` from **0.6.0** (what the
skill installs) and from **0.8.0** side by side:

| presented document | 0.6.0 | 0.8.0 |
|---|---|---|
| clean (control) | `authentic=true` | `authentic=true` |
| duplicate, second occurrence **wider** | `authentic=false` | `authentic=false` |
| duplicate, second occurrence **identical** | **`authentic=true`** | **`authentic=true`** |
| duplicate, **first** occurrence wider | **`authentic=true`** | **`authentic=true`** |

**VERIFIED.** Two things follow, and they point in opposite directions:

1. **There is no escalation path.** Rows 2 and 4 are the attack shapes — a duplicate
   whose two values differ. `JSON.parse` keeps the last occurrence, so if the
   attacker's wider value is last, the canonical signing bytes change and the
   signature fails; if it is first, the parser discards it and the verified scope is
   the narrow, signed one. The signature closes it in both versions. Nobody widens a
   scope this way.
2. **Both versions accept a document the specification refuses.** Rows 3 and 4 are
   documents whose raw text carries a repeated member name. Spec **E.7a** — *"a
   duplicate member name at any depth is not a document"* — says they are not
   documents. `vaid-skill` reports them genuine.

## Why the bump does not reach it

`vaid-mint`'s E.7a check lives in `parseVaidDocument`, and it can only live there:

```ts
export function parseVaidDocument(documentJson: string): Vaid | null {
  // Checked FIRST and on the raw text: every parser here resolves a duplicate
  // before returning, so this is the only point at which the evidence exists.
  if (hasDuplicateMemberNames(documentJson)) return null;
```

By the time a duplicate reaches an object, the evidence is gone — `JSON.parse` has
already silently kept one occurrence. So a caller holding a *parsed object* cannot be
protected by any version of the library.

`vaid-skill` holds a parsed object. `skill/src/envelope.mjs` parses the whole envelope
with plain `JSON.parse` (`parseJson`, line 124), and `skill/src/verify-core.mjs` calls
`verifyVaidAuthenticity(entry.key, vaid)` on the result (line 211). **VERIFIED** by
reading both. `parseVaidDocument` is never called — and at 0.6.0 it does not exist to
call: loading the resolved package shows `parseVaidDocument`, `verifyVaidStanding` and
`verifyVaidAuthenticityGraded` are all `undefined`.

## Why MODERATE and not higher or lower

**Not HIGH:** no privilege escalation, no forged authenticity, no revocation bypass.
The signature holds. Measured above rather than argued.

**Not LOW:** `vaid-skill` is published on npm and installed into Claude Code, Codex,
Cursor, Gemini CLI and Copilot. It is the surface an evaluator meets first, and the
whole product claim is *"a consumer can check the artifact they received rather than
trust a README."* A checker that says **genuine** where the standard says **not a
document** is wrong in the one direction that matters for a tool whose only output is
a verdict. In a mixed deployment — the skill accepting, a substrate refusing — two of
our own components disagree about the same bytes, which is the exact class ADR-0006
and B7 exist to close.

**And it is invisible.** The user sees a clean verdict. Nothing in the output hints
that a check was skipped, which is the property that separates this from the skill's
honest `revocation: NOT CHECKED` reporting.

## The fix, stated as a decision

One line, with a behaviour change behind it: parse the VAID document through
`parseVaidDocument` (present from 0.7.0) instead of `JSON.parse`, and treat `null` as
a rejection with a distinct reason.

It requires the pin to move to at least `^0.7.0` first — `parseVaidDocument` does not
exist at 0.6.0 — which is why this and
`docs/findings/vaid-skill-pins-a-superseded-mint.md` travel together and are still two
decisions. **The pin bump is a precondition for the fix and is not the fix.** Shipping
the bump alone and closing this finding would leave the defect in place under a
version number that looks like it addressed it.

Behaviour change to weigh: envelopes that verify today would begin to fail. That set
should be empty for any honestly produced document, but "should be" is the reason this
is a decision and not a patch.

## The class

Two instances, fourteen days apart, same mechanism, found the same way — while
checking whether a dependency bump was safe:

- `forge-agents` agent templates (2026-08-14), Python, `json.loads`.
- `vaid-skill` (2026-08-23), TypeScript, `JSON.parse`.

**A library check that can only run on raw text is unreachable to every caller that
parses first**, and callers parse first by default because an object is the convenient
thing to hold. The library cannot enforce it and the changelog entry announcing it
reads, to every such caller, as protection they now have.

Worth asking whether `vaid-mint` should make this harder to get wrong — a
`verifyVaidAuthenticityFromJson(key, text)` that owns the parse, so the safe path is
the short one. That is a `vaid-mint` API question, recorded here and not taken.
