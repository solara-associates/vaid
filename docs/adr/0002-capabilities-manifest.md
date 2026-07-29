# ADR-0002: Capabilities manifest — status as verifiable data, not prose

**Status:** Accepted
**Date:** 28 July 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0001; the marketing site (synthera-site)

---

## Context

Marketing and doc copy asserted capability status ("verify a VAID on sight", "reference mint on the roadmap") in prose, written at different times against different states of the code and never reconciled. A single audit found the **same overclaim class on seven pages** plus **one understatement** — the reference mint was called "roadmap" while `vaid-mint` was shipped and installable. Status woven into sentences on eight pages means one capability change is thirteen edits, done by hand, which is exactly what drifted.

The fix is structural: **separate volatile status from stable prose.** Prose like "every multi-agent system you build today is a liability" does not drift. What drifts is *what ships, in which language, at what version* — and *what is still blocked, on what*. That belongs in data.

## Decision

**A machine-readable capabilities manifest, `docs/capabilities.json`, is the single source of truth for VAID capability status.** Prose renders status from it rather than asserting it.

Per capability: `id`, `status` (`shipped` | `roadmap` | `planned`), `landed_in`, `packages` (per language: registry + package + version), a one-line `status_text`, and `blocked_on` (a PR, or a human-owned decision).

Two CI checks guard it, and they check different things:

1. **Drift check** — every vendored copy (e.g. the site's `src/data/capabilities.json`) must byte-match this file (full-file SHA-256), same pattern as the frozen conformance vector. Proves copies *agree*.
2. **Verification check** (`scripts/verify-capabilities.mjs`) — proves the manifest matches **reality**, not just itself:
   - `shipped` + a package version → that version **must be published** on its registry (crates.io / PyPI / npm), else fail.
   - `shipped` + no published package → must carry a `repo_ref` (a path that exists, or a merged PR) that resolves.
   - `roadmap`/`planned` blocked on a PR → that PR **must still be OPEN**. *A capability blocked on a merged PR is a status that should have flipped* — and this check fails it.
   - Both checks **fail loudly and fail closed on network failure** — they never pass without verifying.

Without the verification check, a stale manifest would propagate cleanly to eight pages — the same failure with an extra step in front of it. The verification check is what makes the manifest load-bearing.

**Release gate:** the vaid release process carries one checklist line — *"Does this release change `capabilities.json`? If a capability's status or version moved, update the manifest in the same PR."* Status is updated **when it ships**, not reconciled afterward.

**Claims register:** `docs/claims-register.json` holds evidence-backed prose claims that are *not* a simple status — e.g. "governance demonstrated across ADK, LangChain and OpenAI." Per claim: the claim, its evidence, `date_last_verified`, and — when a date is set — a `verifier` (who/what verified it) and a `verified_artifact` (the dated evidence it points at). An optional per-claim `max_age_days` overrides the default freshness budget.

## Three boundaries, stated rather than discovered

1. **`status_text` is hand-written prose.** The manifest is therefore not *purely* generated — one field per capability is authored. That is a far smaller surface than status woven into eight pages, and it is a **review item at release**, not a generated field. Naming it here so it is not found later and mistaken for a gap in the design.
2. **One finding class the manifest cannot catch.** Of the thirteen findings, twelve reduce to a capability status (the six verification overclaims → roadmap/planned; the understatement → shipped) or to a claims-register entry (the framework-governance claim). The thirteenth — the `/compare` "checkable by anyone" → "…holding the signer's public key" nuance — is a **trust-anchoring nuance in prose**, not a status. It stays a **human review item**; the manifest does not and is not meant to catch it.
3. **The verification check proves a version is *published*, not that the capability *works*.** `vaid-mint 0.1.2` existing on crates.io is not evidence that the reference mint does what a page claims about it — only that a package by that name and version was released. The check confirms *existence and publication*, and that a roadmap capability's blocker has not silently merged; it does not run the code or assert behaviour. This gap is acceptable and likely permanent (behavioural proof is what the conformance vectors, unit tests, and the claims register's evidence are for). It is recorded here so that a green `capabilities` check is not read as stronger than it is: it means "the status is internally honest and the artifacts exist," not "the capability is proven to work."

## Claims-register freshness — automated for freshness, not for truth

The register originally stated, in its own header, that there was **deliberately no automated verifier** for these claims — they were a human review item at release. A `date_last_verified` with nothing enforcing it, however, is decoration: a claim can be published in prose, its date can quietly rot, and nothing flags it. That is the same hole — a stale assertion nobody reconciles — one level up from what the manifest exists to close.

**This ADR reverses that stance for one axis only: freshness.** `scripts/verify-claims.mjs` runs in the same `capabilities` CI job and enforces:

- `date_last_verified` **null/missing → FAIL.** A null that passes silently is exactly the hole above; an unverified claim in the register is unsupported.
- a set date with an empty `verifier` **or** `verified_artifact` **→ FAIL.** A date with no backing is worse than a null one — it looks verified and is not.
- **age ≥ 90 days → FAIL; age ≥ 60 days → WARN** (WARN is two-thirds of the FAIL budget, so a per-claim `max_age_days` scales both). WARN gives runway to re-verify before CI goes red.
- like the other checks, it **fails loud and fails closed**: an unreadable register, a malformed date, or a malformed override is a hard failure.

**The distinction, stated plainly:** this check proves a claim is *fresh*, not that it is *true*. It confirms that someone/something verified the claim, recorded who and with what artifact, and did so recently enough — it does **not** re-run a conformance harness or re-establish the claim. Truth remains a human review item at release, backed by the claim's own evidence (e.g. the phase1e conformance artifact). A green `capabilities` job now means "statuses are internally honest and their artifacts exist, **and** every register claim's verification is fresh and backed" — still not "the capabilities and claims are proven to work."

*Not yet built (cross-repo):* the freshness check confirms `verified_artifact` is a non-empty string, not that the path resolves. Most artifacts (e.g. the phase1e run) live in **other repos** (`forge-agents`), so existence cannot be checked from a vaid-only checkout. Asserting resolution needs either a pinned cross-repo checkout in CI or a committed digest/URL the check can fetch; recorded as a follow-on, deliberately out of scope here.

## Consequences

- A capability change is one manifest edit; the site (and any consumer) re-vendors and re-renders — copy edits, not rewrites.
- **A `shipped` flip that depends on a published artifact lands *after* the registry publish, as its own PR — not in the code-merge PR.** Merging PR #2 lands the revocation / public-key-verification *code*, but `vaid-document-verification` / `revocation-lineage-aware` flip to `shipped` only once **vaid-mint 0.2.0 is on crates.io + PyPI**, because `shipped` means *published* and the verification check requires the versions to exist. (An earlier draft of this ADR said "PR #2 merging flips them to `shipped`" — that was wrong: merging publishes nothing. The release order is merge → tag → publish → manifest-flip PR. See CONTRIBUTING's release gate.)
- **Evidence the design holds (2026-07-28):** on its *first real use*, `verify-capabilities.mjs` caught a `shipped`-but-unpublished assertion **before it reached a page**. A simulated post-merge flip of those two capabilities to `shipped vaid-mint@0.2.0` failed with four errors — *"claims shipped, but vaid-mint@0.2.0 is NOT published on crates.io / pypi"* — because 0.2.0 was not yet released. The check did exactly what it exists to do: stop the manifest asserting a status the registries do not back.
- Prose can no longer silently assert a status the code does not have.
- Cost: the two boundaries above (hand-written `status_text`; the trust-anchoring nuance needing human review).
