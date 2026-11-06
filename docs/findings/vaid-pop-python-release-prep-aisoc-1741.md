# Python `vaid-pop` (0.2.0) vs. current `vaid-mint` (0.11.0) — compatibility review, release prep

**Date:** 2026-11-06
**Repo:** `vaid`
**Status:** OPEN — review complete, release deliberately NOT cut. Raised as a
follow-up from the upstream maintainer's review of beenuar/AiSOC#1741.
**Audience:** whoever cuts the next Python `vaid-pop`/`vaid-mint` release pair.

---

## The fact

Python `vaid-pop` is at `0.2.0`, last functionally changed 2026-07-29
(`0babbe1`); the 2026-11-01 commit touching it (`0295dc6`) added a dependency
lockfile, no code. Python `vaid-mint` is at `0.11.0` and has released nine
times since. The gap in release count is correct, not drift: `vaid-pop`'s own
`CHANGELOG.md` already states the three language packages "are versioned
independently and their numbers legitimately diverge."

## Compatibility — VERIFIED, no fix required

`vaid-mint`'s `pyproject.toml` pins `vaid-pop>=0.2.0,<0.3`. The two symbols
`vaid-mint` imports from it —
`vaid_mint/mint.py:27: from vaid_pop import canonical_request_signing_bytes`
and `vaid_mint/conformance.py:41: from vaid_pop import
canonical_request_signing_bytes, verify_signed_payload` — are both present and
unchanged in `vaid_pop/signer.py` at `0.2.0`. `vaid-pop`'s own CHANGELOG shows
no wire-shape or public-API change since 0.2.0 in any of the three languages
(Rust 0.2.1 and npm 0.3.0/0.3.1 are packaging/firewall-robustness releases
only, "no change to the public API").

Ran the full Python `vaid-pop` suite (`python3 -m pytest`, 9 passed) and the
full Python `vaid-mint` suite (351 passed) against this pairing: both green.

**Conclusion: current `vaid-pop` 0.2.0 is fully compatible with current
`vaid-mint` 0.11.0. No functional fix is required for compatibility.**

## A latent defect noted, not fixed here

Python's packaged firewall (`vaid_pop/conformance.py:load_vector`,
`load_completion_vector`) names its two vector files literally rather than
scanning `vaid_pop/vectors/`. This is the identical shape Rust's `vaid-pop`
0.2.1 fixed (`crates/vaid-pop/CHANGELOG.md`): a third vector added to the
package later would ship unverified while the firewall still prints PASS. It
is not live today — exactly two vectors exist and both are checked — so it is
not a compatibility defect against current `vaid-mint` and is out of scope for
this review's ask. The npm package has the same shape. Flagged for whoever
next touches either firewall; not itself a reason to delay this pairing's
release.

## The compatibility rule, documented

No prior doc stated *how* `vaid-pop` and `vaid-mint` release in relation to
each other, beyond "versioned independently." Recording it here so the next
release follows a rule rather than a guess:

1. **Version numbers never need to match.** Each package's own semver tracks
   its own API/wire-format stability, as already stated in every `vaid-pop`
   CHANGELOG preamble. A `vaid-mint` release does not force a `vaid-pop`
   release, and vice versa.
2. **Compatibility is declared per language, in the consumer's manifest, as a
   version range — not by a shared number.** Python: `>=X.Y,<X.(Y+1)`
   (`pyproject.toml`). npm: `^X.Y.Z` (`package.json`). Rust: pinned to the
   workspace's own `vaid-pop` crate version (`Cargo.toml`, `workspace = true`).
   Each already follows its own ecosystem's convention; this review found no
   reason to standardize them into one shape.
3. **When `vaid-pop` needs a real fix, it releases in the same cycle as the
   next scheduled `vaid-mint` monthly release**, not out of band — so a
   consumer who upgrades `vaid-mint` that month also picks up the `vaid-pop`
   fix in one pass, and `vaid-mint`'s lower bound is only raised in that same
   release if the fix changed something `vaid-mint` actually depends on.
4. **When `vaid-pop` needs no fix, it does not release just to keep pace.**
   This review found no such fix for Python `vaid-pop`: see above. It stays
   at 0.2.0 and is not released this cycle.

## Decision

**Not releasing now.** Python `vaid-pop` remains at 0.2.0. Re-run this review
(or confirm the two symbols `vaid-mint` imports are unchanged, and the pytest
suites above) at the next scheduled `vaid-mint` monthly release, and cut a
`vaid-pop` release alongside it only if a fix has actually accumulated by
then — per rule 4, "no release" is the correct outcome of an empty backlog,
not a thing left undone.
