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

**Claims register:** `docs/claims-register.json` holds evidence-backed prose claims that are *not* a simple status — e.g. "governance demonstrated across ADK, LangChain and OpenAI." Per claim: the claim, its evidence, and `date_last_verified`, so the claim visibly ages until re-verified.

## Two boundaries, stated rather than discovered

1. **`status_text` is hand-written prose.** The manifest is therefore not *purely* generated — one field per capability is authored. That is a far smaller surface than status woven into eight pages, and it is a **review item at release**, not a generated field. Naming it here so it is not found later and mistaken for a gap in the design.
2. **One finding class the manifest cannot catch.** Of the thirteen findings, twelve reduce to a capability status (the six verification overclaims → roadmap/planned; the understatement → shipped) or to a claims-register entry (the framework-governance claim). The thirteenth — the `/compare` "checkable by anyone" → "…holding the signer's public key" nuance — is a **trust-anchoring nuance in prose**, not a status. It stays a **human review item**; the manifest does not and is not meant to catch it.

## Consequences

- A capability change is one manifest edit; the site (and any consumer) re-vendors and re-renders. Copy edits, not rewrites — and PR #2 merging flips `vaid-document-verification`/`revocation-lineage-aware` to `shipped` by updating this file, with the verification check enforcing the flip (a merged PR #2 with those still `roadmap` fails CI).
- Prose can no longer silently assert a status the code does not have.
- Cost: the two boundaries above (hand-written `status_text`; the trust-anchoring nuance needing human review).
