# Changelog

All notable changes to the npm `vaid-mint` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written TypeScript implementation — not a build
or mirror of the Rust crate or the Python package**. All three are versioned
independently and their numbers legitimately diverge; a shared version number is a
coincidence, not a guarantee. At the time of writing this package is at 0.4.1 while
the Rust crate is at 0.4.2, and that is correct rather than drift. Byte-identity
between the three is asserted by the frozen conformance vectors, never by the
version number.

## [0.4.1]

### Fixed — the packaged firewall checked two of four vectors and printed PASS

`vaid-mint-conformance` is what the quickstart tells a consumer to run. In 0.4.0 it
named a fixed set of vectors — `mint_v1` and `mint_pop_v1` — so it verified neither
`chain_v1` nor `attestation_v1`, the two vectors 0.4.0 existed to ship, and printed
PASS regardless. **The artifact was correct; the check that vouched for it was not.**
A consumer-facing check that overstates what it verified is worse than no check,
because it is indistinguishable from coverage.

The firewall now **enumerates the vectors actually present in the installed
package** and dispatches through a filename → checker table, failing in BOTH
directions: a vector present with no checker is a blocker, and a checker whose
vector is absent is a blocker. It cannot verify a vector nobody has written a
checker for; what it guarantees is that such a vector cannot ship *quietly*.

The output now names every vector with its digest and states the count, so what was
actually checked is answerable from the output rather than from the source.

**No format change and no vector change:** every frozen vector is byte-identical to
0.4.0, and no public API moved.

## [0.4.0]

### Added — third-party end-to-end lineage verification (ADR-0003)

A third party holding only the issuer's kernel **public** key and the ancestor
documents a presenter supplies can verify a full delegation chain end to end. **No
format change:** no new field in the VAID document, no `sig_version` bump, no
`mint_v1.json` re-freeze.

- `PresentedBundle` — a new implementation of the existing `LineageResolver` over
  the documents a presenter supplies, so `assembleLineage`, cycle detection and the
  depth bound are reused rather than reimplemented.
- `verifyChain` — authenticate every document, pin each hop against the signed
  `parent_vaid`, fail closed on any gap, then check containment at every hop using
  the **mint-time** matchers, so verify-time cannot drift from the check that gated
  issuance.
- `ChainVerification` keeps its failure states apart. `Unverifiable` means
  attenuation could not be established — never that it was satisfied.

### Added — tenant containment at verification time

Checked at every hop as the qualified `(trust_domain, tenant_id)` pair, sharing
`tenantAttenuates` with `mintChild` so the two cannot drift. `tenant_id` alone is
not globally meaningful (ADR-0004), so bare equality would be correct today and
wrong the moment chains cross kernel keys.

`trust_domain` is issuer-stamped and inside the signed bytes, but **self-asserted**:
this is defence against operator error, not against a hostile issuer.

### Added — detached consent attestations and multi-key verification

Nothing in a VAID document proves the parent *consented* to a delegation. Under one
kernel key that is invisible and sound; across keys an issuer B can mint a document
naming issuer A's root `vaid_id` as `parent_vaid` and have it verify while A
delegated nothing.

- `ConsentAttestation` — a separate signed object over the same
  JCS → SHA-256 → Ed25519 discipline, with its own `att_version` independent of
  `sig_version`. Frozen as `attestation_v1.json`.
- `KernelKeyResolver` / `SingleKernelKey` / `KernelKeyMap` — per-document key
  selection by `kernel_key_thumbprint`. **Lands strictly behind consent:** a
  cross-key hop without a valid attestation is `Inauthentic`, never `Attenuated`.
- Time-bounded consent — `issued_at` and `expires_at`, `expires_at` **required with
  no default**, and a fifth verdict `ConsentExpired`. Expiry is exact; the opening
  edge tolerates `MINT_POP_FRESHNESS_SECS` of clock skew.
- `verifyChainAt` takes an explicit instant; `verifyChainWith` is the system-clock
  wrapper.

**A time bound is a mitigation, not withdrawal.** `expires_at` bounds how long stale
consent stays usable and does nothing about consent retracted inside its window.
Retraction needs durable revocation, and durable revocation does not exist in this
implementation. Consent is time-bounded, not revocable.

### Added — two frozen vectors, both additive

`chain_v1.json` pins the walk (assembled lineage order and verdict);
`attestation_v1.json` pins `att_version` 1. Neither re-freezes `mint_v1.json` or
`mint_pop_v1.json`, and `sig_version` is unchanged.

### Not changed

Document expiry is still not consulted by chain verification. An attestation may
outlive the parent VAID it delegates from.

## [0.3.0]

**The first release published to npm.**

Contents at publication, read from the published package rather than recalled: the
open, self-hostable reference mint — mint a root VAID and mint attenuated child
VAIDs with scope and capability containment — shipping `mint_v1.json` and
`mint_pop_v1.json`, plus the `vaid-mint-conformance` executable so a consumer with
only `npm install vaid-mint` can prove the mint they received reproduces those
vectors without a checkout.

Anything below this version in git predates publication to npm. The repository
history is the record for it; it is deliberately not reconstructed here, because
entries written from a diff after the fact produce a plausible history rather than a
recorded one.
