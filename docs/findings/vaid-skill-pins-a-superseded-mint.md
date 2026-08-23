# `vaid-skill` pins a superseded `vaid-mint`, and the pin is a decision nobody has made

**Date:** 2026-08-23
**Repo:** `vaid`
**Status:** OPEN — **its own decision, not a footnote to the 0.8.0 release.** No code
changed. Raised at the repository owner's instruction while preparing `vaid-mint`
0.8.0.
**Audience:** whoever decides what `vaid-skill` ships against.

---

## The fact

`skill/package.json` declares `"vaid-mint": "^0.6.0"`. npm resolves `^0.6.0` to
`>=0.6.0 <0.7.0`, so the skill installs **0.6.0** — confirmed by reading the resolved
`skill/node_modules/vaid-mint/package.json`, not by reading the range. **VERIFIED.**

`vaid-mint` has been 0.7.0 on npm since 2026-08-11 and 0.8.0 is prepared. After 0.8.0
the skill is **two compatibility steps behind** — under both npm and Cargo 0.x rules
the minor is the compatibility unit, so 0.6 → 0.8 is the pre-1.0 equivalent of two
major versions.

The skill is ours, it is published on npm, and it is the surface an evaluator reaches
first — `vaid-skill` is the Agent Skill, installed from a public registry into Claude
Code, Codex, Cursor, Gemini CLI and Copilot.

## Correcting the obvious reading first

The natural conclusion — *"it will be two versions behind on a security default"* — is
**wrong on the specific**, and the reason matters more than the correction.

**The skill never calls `verifyVaid`.** **VERIFIED** by reading its source:

- `ReferenceIssuer` is constructed in exactly one place, `src/cli.mjs:145`
  (`cmdMint`), and is used **to mint**.
- Verification runs through `src/verify-core.mjs`, which imports
  `verifyVaidAuthenticity`, `verifyChainAt` and `isExpired`. None of those consults
  revocation (spec R.7).
- Revocation is reported to the user as **`NOT CHECKED`**, deliberately and
  visibly, with a local-only revocation list the CLI itself describes as *"a file on
  one machine … not a published revocation list"*.

So the fail-open default that 0.8.0 removes was **never on the skill's path**. It did
not have the exposure and it does not gain a fix. Shipping 0.8.0 changes nothing about
the skill's revocation posture, which was already the honest one: it says it does not
check.

That is the correction. What follows is the exposure that is actually there, and it is
a different one.

## The real exposure, and a correction to this document's first draft

`vaid-mint` **0.7.0** fixed a verification defect that **is** on the skill's path:
spec **E.7a**, *"a duplicate member name at any depth is not a document"*. TypeScript
was one of the two implementations that silently accepted such a document.

**The first draft of this section said the bump closes that gap. It does not, and the
error was worth catching before it reached a release note.** The E.7a check lives in
`parseVaidDocument`, which is the only place it *can* live — `JSON.parse` resolves a
duplicate before returning, so the evidence is gone by the time a caller holds an
object. `vaid-skill` parses the envelope itself with plain `JSON.parse` and hands
`verifyVaidAuthenticity` an object, so **no version of `vaid-mint` protects it**.
Measured at 0.6.0 and 0.8.0 side by side: both report a duplicate-member document
authentic.

That exposure is filed on its own, with the measurements and a severity line, in
`docs/findings/vaid-skill-accepts-duplicate-member-names.md`. It is a **separate
decision** from this one, and the relationship between them is one-way:

> **Moving the pin is a precondition for fixing E.7a and is not the fix.**
> `parseVaidDocument` does not exist at 0.6.0, so the pin must move before the skill
> can call it — but moving the pin alone changes nothing about duplicate members.

Shipping the bump and closing the E.7a finding with it would leave a live defect
behind a version number that looks like it addressed it.

## What the bump *does* buy

Real, and worth having on its own:

- **A verifier tested against negative vectors.** 0.7.0 ships `verdict_v1.json`'s 37
  cases, which pin what a conforming implementation must *reject*. 0.6.0 shipped no
  such vector.
- **`parseVaidDocument`, `verifyVaidStanding`, `verifyVaidAuthenticityGraded`** — all
  `undefined` at 0.6.0, confirmed by loading the resolved package. The skill cannot
  report a graded verdict, check standing, or fix E.7a without them.
- **B7's re-projection fix**, which was a Rust defect; TypeScript was already correct,
  so this is currency rather than repair.

## What is *not* wrong with the pin

- `^0.6.0` is a correct and conservative range. It is not a mistake; it is a range
  nobody has revisited.
- B1 (`vaid-mint` reaches for `node:crypto` and an ambient `Buffer`, so it is not
  browser-native) does not affect the skill: the skill is a Node CLI.
- B7 (the Rust verifier re-projecting typed values) was a **Rust** defect. TypeScript
  was already correct, so 0.6.0 is not exposed to it.

## The decision to make

Three options, and they are genuinely different:

1. **Bump the skill to `^0.8.0` and release `vaid-skill` 0.1.4.** Closes E.7a on the
   skill's path. Requires its own release — the skill has its own version, its own
   changelog and its own trusted publisher. It is a *separate* publish from
   `vaid-mint` 0.8.0 and must not be bundled into it.
2. **Bump to `^0.7.0`.** Closes E.7a without adopting anything from 0.8.0. Defensible
   if the 0.8.0 default flip is judged to need soak time on the library before the
   skill follows — but note the skill is unaffected by that flip, so this option buys
   caution against a change that cannot reach it.
3. **Leave it, and record why.** Legitimate only with a stated reason and a date to
   revisit. "Nobody looked" is not that reason, and is the current state.

**Recommendation: option 1, as its own release, after `vaid-mint` 0.8.0 is published
and verified** — and then, as a second and separate decision, the E.7a parse-path
change on top of it. The ordering matters twice: `^0.8.0` cannot resolve until 0.8.0
exists on npm, so bumping the skill first turns its install red; and the E.7a fix
cannot be written until the pin has moved.

## Why this is recorded separately

A stale dependency pin inside our own published tool is the kind of thing that reads
as housekeeping and gets appended to someone else's release note, where it is decided
by whoever is already mid-release rather than by whoever should decide it. It also has
a live correctness consequence (E.7a) that the "two versions behind" framing hides,
because that framing points at the wrong defect.

Related: `docs/findings/vaid-skill-accepts-duplicate-member-names.md` (the live
defect this pin blocks the fix for),
`docs/findings/the-fail-open-default-priced.md` (the estate sweep that found this
pin), ADR-0007, BACKLOG B1.
