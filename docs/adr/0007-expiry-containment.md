# ADR-0007: A child VAID may not outlive its parent

**Status:** Accepted
**Date:** 21 September 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Amends:** ADR-0003 (third-party attenuation verification) — step 4 of its
verification procedure gains expiry, and the procedure gains a lapse check
**Related:** ADR-0001 (revocation outside the conformance surface), ADR-0005
(segment-bounded scope containment), ADR-0006 (verify over presented bytes),
`docs/spec/scope.md`, vaid#79, vaid#76 (open)

---

## Context

`mint_child` enforced four containment properties — tenant, lineage, scope,
capabilities — and not a fifth. A child's `expires_at` was never compared against
its parent's, in any of the three reference implementations, and
`grep expires_at mint.py mint.rs` returned nothing on the delegation path.

The child's expiry came from the issuer's own TTL: `expires = now + ttl`, evaluated
afresh at each mint. So **any** child minted after its parent expired later than its
parent, by exactly the delegation delay — not an edge case but the continuous,
ordinary behaviour of a correctly configured mint.

`verify_chain` did not catch it, because chain verification consulted no expiry at
all. A chain whose root expired hours ago returned `Attenuated`: a third party
holding only the kernel public key — the party detached-chain presentation exists to
serve — was told the delegation was legitimately derived, when the authority it was
derived from no longer existed. Reproduced and executed in all three languages
against the published 0.7.0 packages (vaid#79).

Two artefacts show how long it had been true without being noticed. `chain_v1.json`,
the frozen chain vector, carries three documents that expired on 2026-06-05 and
pinned the verdict `attenuated` against the wall clock — so from that date it was
asserting that a chain of dead documents verifies, and all three implementations
agreed. And a test in each implementation, named
`an_expired_parent_document_does_not_affect_the_verdict`, pinned exactly that as a
property "so it is not lost by accident".

This is invariant **I3 (TTL monotonicity)** of
`draft-niyikiza-oauth-attenuating-agent-tokens-01` §4.4 — `derived.exp <=
parent.exp`, checked at every hop by the enforcement point (§7 step 4).

## Decision

**A child's `expires_at` MUST NOT exceed its parent's, enforced at mint and at every
hop of verification, through one shared matcher.**

Four sub-decisions, each of which had a defensible alternative.

### 1. The mint CLAMPS; it does not refuse an over-long child

The child is issued with the earlier of the issuer's own TTL and the parent's
`expires_at`.

Refusing was the first choice — it is consistent with the other four containment
refusals and needs no change to the issuance seam. It was implemented and then
measured, and the measurement settled it: with one issuer at one TTL, delegation
succeeded at a 0.0s delay and was refused at 1.1s, because `now + ttl` moves and the
parent's expiry does not. A refusing mint can only delegate inside the whole second
in which its parent was minted. That is not a rule anyone would keep; they would
remove it.

### 2. A delegation from an ALREADY-EXPIRED parent is refused

The one case a clamp cannot answer: the ceiling is in the past, so the child would be
issued dead-on-arrival, and handing back a credential that cannot be used while
saying nothing is worse than a refusal. It raises the same unauthorized-delegation
error as the other containment refusals, names the parent's expiry so the caller can
act, and runs with checks (4) and (5) **before** the proof-of-possession, so it burns
no nonce. An unreadable parent expiry is expired, and is refused by the same line.

### 3. The issuance seam takes the ceiling, and the mint CHECKS what comes back

`issue_vaid_with_key` / `issueVaidWithKey` and their `_with_lineage` twins take a
`not_after` upper bound. This is a breaking change to a public trait in Rust and a
public interface in TypeScript: a third-party issuer implementation will not compile
until it takes the parameter. That is the preferred failure — the alternative
considered was a defaulted parameter, which keeps such an issuer compiling and starts
silently emitting over-long children.

The ceiling alone is not the guarantee, because the issuer is a seam a deployment
supplies. So `mint_child` applies the same matcher to the document the issuer
actually returned and withholds a child that still exceeds its parent. That one
refusal consumes the nonce, unavoidably — the PoP is spent by the time a document
exists to check — and it fires only for a broken issuer, never for a caller's
mistake.

### 4. A lapsed ancestor is `Expired`, a structural overrun is `NotAttenuated`

Two distinct faults get two distinct verdicts, and `ChainVerification` gains
`Expired` for the first.

- **`Expired`** — a document ABOVE the leaf has passed its own `expires_at` at the
  verification instant. Nothing was forged, so `Inauthentic` would misdescribe it; no
  child overreached, so `NotAttenuated` would be wrong. It says *the delegation has
  run out*; the others say *you were never authorized*. This is the same reasoning
  that gave `ConsentExpired` its own state.
- **`NotAttenuated`** — a child's `expires_at` exceeds its parent's. A document that
  was never built consistently, true at every instant, including long before anything
  expires.

**Order is normative.** Authenticity, then assembly, then ancestor lapse, then hop
containment, then cross-key consent. Where a chain breaks more than one rule, the
first fault found is reported — three verifiers that reject the same chain for three
different reasons agree on every boolean and disagree about what happened.

**Equality is containment.** `child <= parent`. A child ending at the same instant as
its parent holds authority for no instant in which its parent holds none.

**The comparison is over parsed instants, never over strings.** A presented timestamp
may be in any valid RFC 3339 form (ADR-0006), and two spellings of the same instant
do not compare as text. An absent or unreadable expiry on either side is refused —
the same fail-closed rule `is_expired` already applies to standing.

## Scope: what this does NOT do

**The leaf's own expiry is still not consulted by chain verification**, nor is
revocation anywhere on the chain. That is **vaid#76**, open and wider than this. The
leaf is the document the caller holds and can check with `is_expired`; its ancestors
are the ones it cannot, and vaid#79's point is that a caller doing the obvious
conscientious thing still accepted a leaf whose parent died hours ago. That gap is
closed here; #76's is not. The boundary is pinned by a case in
`chain_expiry_v1.json` so that all three implementations draw it in the same place —
which records where the line currently is, not where it belongs.

**`issued_at` monotonicity is not enforced.** AAT I3 also requires `derived.iat >=
parent.iat`. Only the `exp` half is implemented; the `iat` half remains open.

## Consequences

**Behavioural break, no wire change.** No signed field changes, no new member, no
`sig_version` bump, and `mint_v1.json`, `mint_pop_v1.json` and `attestation_v1.json`
are untouched. What changes is which documents verify: a chain that returned
`Attenuated` yesterday may now return `Expired` or `NotAttenuated`, and delegated
children are shorter-lived than the issuer's TTL alone would have given them. Minor
version bump in all three languages.

**`chain_v1.json` states its verification instant.** Its verdict was previously
asserted against whatever the clock said. `expected.verification_instant` is now
normative and inside the contract digest. No document in the vector moved: every
per-hop digest and signature is unchanged.

**A new predicate vector, `chain_expiry_v1.json`**, byte-identical across the three
languages, pinning both surfaces: the matcher, and the walk.

**B9 is half-answered.** The verify side now takes a stated instant end to end
(`verify_chain_at` → `is_expired_at`). The standing predicate still reads the wall
clock in its convenience form, which is what B9 is about.
