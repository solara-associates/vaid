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

## [0.8.0]

### BREAKING — the reference issuer now fails closed out of the box

`ReferenceIssuer`'s default revocation store was `assumeNothingRevoked()`: it
vouched `NotRevoked` over an empty set, so a fresh issuer verified immediately.
Because the store is non-durable it could not detect its own restart, so a VAID
revoked before a restart verified clean afterwards. That is a **fail-open posture**,
and it was the **default**.

It is now **absent**: `revocationStatus` reports `Unavailable` and `verifyVaid`
returns `false` until revocation state is loaded. Verification fails closed (R.4.5).

R.4.5 requires that fail-open *"MUST NOT be the default"* and *"MUST be named to
state what it does rather than obscure it."* R.6 argued the old default sat outside
that requirement, being a development default rather than a verifier setting. The
argument was sound and it was a **carve-out** — one that existed only because the
posture was a default. It is no longer one.

**Blast radius, measured rather than estimated** — the flip was applied, all three
suites run, and the tree restored:

- **16 test failures across three languages, all one class**: *a bare issuer no
  longer verifies what it just minted*. There is no second failure mode.
- **Minting, attenuation and scope containment are unaffected.** `MintService` never
  calls `verifyVaid`.
- **Authenticity is unaffected.** `verifyVaidAuthenticity` never consults
  revocation (R.7), so third-party, offline and cross-organisation verification —
  the portable property that is the point of a VAID — does not change.
- **No conformance vector is affected.** Revocation is outside the conformance
  surface (R.1) and `verdict_v1.json` takes revocation status as an *input* rather
  than deriving it. The vector freeze reports 32 vectors unchanged.

You are affected only if you call `ReferenceIssuer.verifyVaid` or
`revocationStatus` on an issuer you have not given a revocation backend.

### BREAKING — `withRevocationCheck` is removed

It replaced one of the two durable stores R.4.6 requires and left the other in
memory. That configuration is not a degraded mode, it is an outage: after a restart
every **child** credential fails closed while every **root** keeps verifying (see
below). It was deprecated in the same breath as `RevocationBackend` landed and is
removed here rather than kept through a deprecation window, because a window is a
period during which the reachable failure stays reachable.

Replace with `withRevocationBackend(new RevocationBackend(check, lineage))`. To
keep an in-memory resolver deliberately, pass `InMemoryLineageStore` as the second
half — the same behaviour, named at the call site.

### Added — `assumingNothingRevoked()`

The pre-0.8.0 posture, asked for by name:

```ts
const issuer = ReferenceIssuer.ephemeral(24).assumingNothingRevoked();
```

Identical behaviour to the old default — a vouching in-memory revoked set, with the
lineage store untouched and still in-memory. It is a fail-open posture and this
spelling says so where it is chosen. Fine for local development, quickstarts and
tests; not for anything that must survive a restart. This is what R.4.5 permits:
fail-open as an explicit configuration.

### Added — durable revocation is TWO stores, and the seam now says so (spec R.4.6)

`RevocationBackend`, `LineageStore` and `InMemoryLineageStore`, plus
`ReferenceIssuer.withRevocationBackend`. `withRevocationCheck` is removed (above).

R.4.6 has always required **two** durable stores — the revoked set and the lineage
resolver — and until now the crate offered an injection point for exactly one of
them. `withRevocationCheck` replaced the revoked set; the resolver was a private `Map`
on `ReferenceIssuer` with no way to substitute it and, more decisively, no write
half at all. A self-hoster following the documented path could only build
the half-configuration, and the half-configuration is an outage:

| Persisted | Child credential | Revoked root |
|---|---|---|
| both | verifies | refused |
| lineage only | verifies | **verifies — the revocation is gone** |
| revoked set only | **`Unavailable` — outage** | refused |

Persist the revoked set alone and every **child** VAID fails closed after a
restart (its `parent_vaid` no longer resolves, so assembly is incomplete → R.4.2
`Unavailable` → R.4.5 fails closed) while every **root** VAID keeps verifying,
because a root is trivially complete and never consults the resolver. Total for
delegated credentials, invisible for root ones, arriving at restart rather than at
deploy, and — since nothing was revoked — first diagnosed as a signing or clock
problem. The behaviour is correct; reaching it by omitting an argument is not.

The `RevocationBackend` constructor takes both halves and there is no single-half
constructor, so that state is no longer reachable **by omission**. It stays
reachable by explicitly naming `InMemoryLineageStore` as the second half, which is
a legitimate single-process choice and is visible at the call site. The two halves
remain separate objects rather than one interface with both methods: R.4.1 requires
that the check "does not perform lookups and is not given the means to", and a
combined interface hands one object both jobs.

`LineageStore.record` is the write half the resolver never had. Without it an
injected durable resolver would be permanently empty — the same outage with extra
steps — because the issuer wrote every mint into its own map.

**Proven by a restart, not by a round trip.** `test/durable_restart.test.ts` (and its
Rust and Python mirrors) spawns real child processes: one mints and revokes
into file-backed stores and exits, a second rebuilds the issuer from the persisted
seed and the persisted files. Both mutations — lineage dropped, revoked set
vouching-when-absent — are asserted positively, so the suite measures the outage
and the security hole rather than merely asserting the happy path. The file-backed
stores are **test doubles**; durable hash-chained revocation remains deliberately
outside the open package.

**No conformance impact.** Revocation is outside the conformance surface (R.1),
`verdict_v1.json` takes revocation status as an *input* rather than deriving it,
and no vector changed. The same seam lands in all three implementations
simultaneously — Rust `RevocationBackend`/`LineageStore`, Python
`RevocationBackend`/`LineageStore`, TypeScript `RevocationBackend`/`LineageStore`.

**The reference default changed in the same release** — see the first BREAKING
entry above. The seam and the default were decided separately and shipped together:
the seam makes durable revocation implementable, and the flip stops the
non-durable one from vouching.

## [0.7.0]

### Fixed — a verifier canonicalizes the member VALUES it was presented (BACKLOG B7)

ADR-0006 closed re-projection for unrecognised *members*. It stayed open for
recognised members whose **values** have more than one spelling, and the three
implementations disagreed on eight classes of document as a result. All eight now
return the same verdict and the same reason; the differential probe that found
them reports zero divergences across thirty-four inputs, and each class is pinned
by a case in `verdict_v1.json`.

Normative, in `docs/spec/encoding.md`: **E.1a** (values are canonicalized as
presented; absent and present-null are different documents; parse permissively and
verify strictly) and **E.7a** (a duplicate member name at any depth is not a
document). E.6's stated rationale was corrected — it claimed verifiers re-serialize
timestamps into the profile, which described one implementation and was never true
of the other two. E.6 binds **producers**; a non-conforming timestamp still
verifies, because the signature covers the bytes actually carried.

### Fixed — duplicate member names are refused (spec E.7a)

`serde` refused a repeated struct field while `json.loads` and `JSON.parse` kept
the last occurrence silently, so the same bytes were unparseable to one
implementation and authentic to two. All three now refuse, at any depth, scanning
the raw text — the only place the evidence survives, since every parser resolves
the collision before returning.

### Added — mint-side E.6 conformance gate

Asserts that a freshly minted document carries whole-second `Z` timestamps
(`docs/spec/encoding.md` E.6).

**This implementation was not affected** by the defect that prompted it — the
Rust mint emitted sub-second timestamps (BACKLOG B8) while this one formats the
profile explicitly at the point the timestamp becomes a string. The gate is added
here anyway, for the reason the roundtrip gate already gives for testing the
implementation that happened to be right: that is the one that silently
regresses, because nobody is watching it.

No behaviour change.

## [0.6.0]

### Fixed — a verifier canonicalizes the bytes it was PRESENTED (SECURITY / correctness)

**Rust only.** Python and TypeScript were already correct and are unchanged.

Rust `vaid-mint` returned **the wrong verdict** on a valid document. Given a
conforming VAID plus one additive extension field, signed by its issuer over the
bytes as presented:

| implementation | behaviour | verdict |
|---|---|---|
| Python | canonicalizes the raw dict | correct — verifies |
| TypeScript | spreads the object as received | correct — verifies |
| **Rust (before 0.6.0)** | **projects through the typed `Vaid`** | **wrong — rejects** |

`Vaid` is a typed struct and serde's default is to ignore unknown fields, so
deserializing discarded every member the struct did not name and
`canonical_vaid_signing_bytes` hashed what survived. **The digest was over a
document nobody sent.** It failed closed, so nothing was accepted that should not
have been — but the verdict was about different bytes.

Tolerant parsing is right for a consumer and wrong for a canonicalizer, whose
whole job is to reproduce the bytes the signer signed. One type served both needs
and the parsing need won silently.

**Fix** (ADR-0006): unrecognised members are captured and preserved, so
canonicalization covers the presented key set.

```rust
#[serde(flatten)]
unknown_fields: BTreeMap<String, serde_json::Value>,
```

Chosen over `deny_unknown_fields` because the standard's extension rule permits
additive fields, and a verifier that rejects every extension makes that rule
unusable. Rejecting remains a **conforming** choice — what is now forbidden is
silently dropping a member and reporting a verdict as though it had not been
there.

### Added — `roundtrip_v1.json`, a verify-only vector

Every other vector pins **one implementation's output for a given input**. This
one pins **a verdict over given bytes** — the only shape that catches
cross-implementation disagreement, because the defect appears only when one
implementation *mints* and another *verifies*.

Four cases, and it discriminates in **both** directions: a dropping
implementation fails the extension case as a false negative *and* wrongly accepts
the not-covered-by-the-signature case. Its own checks assert that, so it cannot
decay into cases every implementation passes regardless of behaviour.

Checked before writing it: across all five existing mint-side vectors, **zero
documents carry an unknown field**. The gap was structural, not an oversight.

### Breaking

An implementation relying on Rust silently dropping unknown members will now see
them in the digest. That reliance was on a defect. **Minted documents are
unchanged** — a document minted by this crate has an empty capture map and is
byte-identical to one minted by 0.5.0, and `mint_v1.json` still reproduces.

### Note

The same defect exists in the Solara substrate (`synthera-types`), which projects
through its own typed `Vaid`, and it is in production. Tracked separately; this
release is the normative statement that fix will cite.

## [0.5.0]

### Fixed — scope containment is segment-bounded (SECURITY)

**Bare prefix matching decided scope containment, so a sibling counted as a child.**

```
boundary  data.governance
resource  data.governance-secret     ->  CONTAINED (0.4.x)
                                     ->  NOT CONTAINED (0.5.0)
```

`data.governance-secret` shares a textual prefix with `data.governance` and nothing
else. No hierarchy relates them.

That predicate decides two things, and both are inside the conformance surface
(ADR-0001 §2): **mint-time attenuation**, and **third-party chain verification**
(ADR-0003). So a holder of a VAID scoped to `data.governance` could mint a child
scoped to `data.governance-secret`, and a conforming third-party verifier would
confirm that child as a legitimate attenuation of its parent. Privilege escalation
across a delegation boundary, and it verified.

**The new rule** (spec [`docs/spec/scope.md`](../../docs/spec/scope.md) S.3, ADR-0005):
an entry `P` contains a resource `R` iff `R == P`, or `P` ends with a separator and
`R` starts with `P`, or `R` starts with `P` followed by a separator. An empty
boundary list remains unrestricted.

**Separators are `/` and `.`, both always honoured, and now normative.** A scope
segment MUST NOT contain either — that constraint is what makes honouring both safe
rather than widening, and it is why the set is fixed by the specification instead of
being a deployment setting. A configurable set would break ADR-0003 outright: a third
party recomputing containment from a presented chain has only the documents, and
could not know which rule the mint applied.

### Breaking

Some delegations that succeeded under 0.4.x now fail. That is the fix presenting
itself. Concretely, a child scope is now rejected unless it sits at or below a
segment boundary of a parent scope.

**Nothing else changes.** The rule is *strictly narrower* — verified exhaustively
over a generated corpus, not asserted — so it denies cases the old rule allowed and
permits nothing the old rule denied:

- no previously-rejected delegation becomes possible;
- **no document bytes change** — containment is a predicate computed over a document
  and never appears inside one;
- **no existing frozen vector's verdict changes.** `chain_v1.json` was checked
  specifically, as the one vector whose verification runs containment: its scopes are
  properly dot-nested and both rules accept every hop. `mint_v1`, `mint_pop_v1` and
  `attestation_v1` are untouched and are not re-frozen.

### Added — `scope_v1.json`, the first vector to police the matcher

The matcher had no vector until now, and that is how bare prefix matching survived in
Rust, Python and TypeScript simultaneously: three mirrored ports of one wrong rule
agreed with each other perfectly, and nothing else was asking. Across all 23 scope
literals in the three test suites, every one was either equal or properly dot-nested
— the bug was not weakly tested, it was untested.

`scope_v1.json` carries **no digest and no signature**, because there are no bytes to
pin — it pins verdicts. It is byte-identical across all three packages (CI `cmp`s
them), it is registered in each packaged firewall, and its own checks assert that it
still disagrees with bare prefix matching in at least five places, so it cannot
quietly decay into cases both rules accept.

### Known limitation

The segment constraint is normative on producers and **not enforced** by the matcher
in this release (spec S.6). Enforcing it would reject documents 0.5.0 accepts, which
is a second breaking change; it is deferred to its own revision. No escaping
mechanism is defined for a literal separator inside a segment — encode it before it
reaches `scope_boundary`.

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
