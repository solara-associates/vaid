# Changelog

All notable changes to `vaid-mint` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0]

### BREAKING — the reference issuer now fails closed out of the box

`ReferenceIssuer`'s default revocation store was `assume_nothing_revoked()`: it
vouched `NotRevoked` over an empty set, so a fresh issuer verified immediately.
Because the store is non-durable it could not detect its own restart, so a VAID
revoked before a restart verified clean afterwards. That is a **fail-open posture**,
and it was the **default**.

It is now **absent**: `revocation_status` reports `Unavailable` and `verify_vaid`
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
  calls `verify_vaid`.
- **Authenticity is unaffected.** `verify_vaid_authenticity` never consults
  revocation (R.7), so third-party, offline and cross-organisation verification —
  the portable property that is the point of a VAID — does not change.
- **No conformance vector is affected.** Revocation is outside the conformance
  surface (R.1) and `verdict_v1.json` takes revocation status as an *input* rather
  than deriving it. The vector freeze reports 32 vectors unchanged.

You are affected only if you call `ReferenceIssuer::verify_vaid` or
`revocation_status` on an issuer you have not given a revocation backend.

### BREAKING — `with_revocation_check` is removed

It replaced one of the two durable stores R.4.6 requires and left the other in
memory. That configuration is not a degraded mode, it is an outage: after a restart
every **child** credential fails closed while every **root** keeps verifying (see
below). It was deprecated in the same breath as `RevocationBackend` landed and is
removed here rather than kept through a deprecation window, because a window is a
period during which the reachable failure stays reachable.

Replace with `with_revocation_backend(RevocationBackend::new(check, lineage))`. To
keep an in-memory resolver deliberately, pass `InMemoryLineageStore` as the second
half — the same behaviour, named at the call site.

### Added — `assuming_nothing_revoked()`

The pre-0.8.0 posture, asked for by name:

```rust
let issuer = ReferenceIssuer::ephemeral(24, "vaid.example")?.assuming_nothing_revoked();
```

Identical behaviour to the old default — a vouching in-memory revoked set, with the
lineage store untouched and still in-memory. It is a fail-open posture and this
spelling says so where it is chosen. Fine for local development, quickstarts and
tests; not for anything that must survive a restart. This is what R.4.5 permits:
fail-open as an explicit configuration.

### Added — durable revocation is TWO stores, and the seam now says so (spec R.4.6)

`RevocationBackend`, `LineageStore` and `InMemoryLineageStore`, plus
`ReferenceIssuer::with_revocation_backend`. `with_revocation_check` is removed (above).

R.4.6 has always required **two** durable stores — the revoked set and the lineage
resolver — and until now the crate offered an injection point for exactly one of
them. `with_revocation_check` replaced the revoked set; the resolver was a private
`HashMap` on `ReferenceIssuer` with no way to substitute it and, more decisively,
no write half at all. A self-hoster following the documented path could only build
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

`RevocationBackend::new` takes both halves and there is no single-half
constructor, so that state is no longer reachable **by omission**. It stays
reachable by explicitly naming `InMemoryLineageStore` as the second half, which is
a legitimate single-process choice and is visible at the call site. The two halves
remain separate objects rather than one trait with both methods: R.4.1 requires
that the check "does not perform lookups and is not given the means to", and a
combined trait hands one object both jobs.

`LineageStore::record` is the write half the resolver never had. Without it an
injected durable resolver would be permanently empty — the same outage with extra
steps — because the issuer wrote every mint into its own map.

**Proven by a restart, not by a round trip.** `tests/durable_restart.rs` (and its
Python and TypeScript mirrors) spawns real child processes: one mints and revokes
into file-backed stores and exits, a second rebuilds the issuer from the persisted
seed and the persisted files. Both mutations — lineage dropped, revoked set
vouching-when-absent — are asserted positively, so the suite measures the outage
and the security hole rather than merely asserting the happy path. The file-backed
stores are **test doubles**; durable hash-chained revocation remains deliberately
outside the open crate.

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

### Changed — BREAKING: `Vaid::issued_at()` / `expires_at()` return `Option<DateTime<Utc>>`

The fields hold the presented string and are parsed on demand. The previous
`DateTime<Utc>` return was total only because the field was parsed at
deserialization, which is the behaviour ADR-0006 Requirement 3 forbids.
`issued_at_as_presented()` / `expires_at_as_presented()` expose the bytes the
signature covers.

**`Vaid::is_expired()` now fails closed**: an `expires_at` that cannot be parsed
returns `true`. A document whose expiry cannot be read is not one that can be shown
to be unexpired. That path became reachable in Rust for the first time with this
change, and it is stated rather than left to be discovered — Python and TypeScript
have always behaved this way, so this is the third implementation arriving at a
rule the other two already had.

`vaid_id`, `agent_id` and `parent_vaid` are `PresentedUuid`, which serializes the
spelling it was given. `parent_vaid` is three-state (absent / present-null /
present-value), because a two-state optional renders a missing member back as
`null` and reproduces bytes the presenter never sent.

### Fixed — the mint emitted timestamps that fail the spec's own E.6 profile (BACKLOG B8)

**Rust only.** Python and TypeScript were already conforming and are unchanged.

The issuer stored `Utc::now()` unmodified. `chrono` serializes a `DateTime<Utc>`
with whatever precision it carries, so every document this crate minted went out
with sub-second precision:

```
issued_at  = "2026-08-11T08:04:18.165623Z"
```

`docs/spec/encoding.md` E.6 requires **every timestamp inside signed bytes** to be
whole-second RFC 3339 in UTC with a literal `Z`. That document is not, and
`has_conforming_timestamps` returns false for it — the reference mint's own output
failing the reference mint's own spec.

**Why it hid.** Every test that touched a minted document minted it and then
verified it, which is self-consistent by construction: the mint signs over the
sub-second form and the verifier recomputes over the same form, so the signature
matches. Cross-language checks agreed too, because Python and TypeScript
canonicalize the presented string verbatim. Conformance to a *profile* is not a
property any round-trip can reveal.

**Why only Rust.** In Python the profile is written out at the point the timestamp
becomes a string (`strftime("%Y-%m-%dT%H:%M:%SZ")`), and in TypeScript likewise
(`utcWholeSecondRfc3339`). In Rust the field is rendered by a derived `Serialize`
nobody reads, and nothing in the type system distinguishes a conforming instant
from a non-conforming one — both are `DateTime<Utc>`. `vaid-client` shows the same
contrast inside Rust: its request timestamp goes through
`to_rfc3339_opts(SecondsFormat::Secs, true)` and has always been conforming,
because there the rendering is explicit code.

Clock reads that may reach a signed document now go through the named
`issuer::whole_second_now()`, so a clock read that is *not* that one is visibly a
clock read that is not that one. `attest_delegation` also truncates the caller's
`expires_at`: the profile is a property of the signed bytes rather than of who
chose the value, and truncation can only move an expiry earlier by under a second,
which is the safe direction.

### Added — `Vaid::has_conforming_timestamps`

The Rust half of the issue-#10 split, which **this changelog announced under
0.3.0 and which was never implemented here**. Python and TypeScript have carried
it since; Rust had no way to ask whether a document met E.6, which is the direct
reason the mint could emit non-conforming timestamps for as long as it did. See
BACKLOG B11 for the general form of that defect.

### Added — mint-side E.6 conformance gates

`tests/mint_emits_conforming_timestamps.rs`, with equivalents in Python and
TypeScript. Asserts the serialized string directly as well as the new predicate,
so a new predicate is not being checked with a new predicate, and carries a
negative control requiring the sub-second form to be rejected.

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

## [0.4.2]

### Added — `vaid-mint-conformance`, the packaged firewall as a Rust binary

Python and TypeScript shipped an executable a consumer could run against the
package they installed. Rust did not: its gates were `#[test]`s under `tests/`, and
`cargo test` needs a checkout, so the only Rust answer was "clone our repository and
trust that it is the source your crate was built from" — a strictly weaker claim
than the other two languages make, and the quickstart's advice covered two
languages out of three.

```console
$ cargo install vaid-mint
$ vaid-mint-conformance      # exit 0 = PASS, 1 = BLOCKER
```

Because `cargo install` compiles from the crate tarball, the bytes checked are the
bytes you received from crates.io.

**It enumerates rather than naming a fixed set.** `build.rs` scans `tests/vectors/`
at build time and emits one `include_str!` per file, which is the closest Rust gets
to the runtime directory read Python and TypeScript do — an installed binary has no
directory left to read. It fails in both directions: a vector embedded with no
checker is a BLOCKER, a checker with no vector is a BLOCKER, and no embedded vectors
at all is a BLOCKER, because a firewall that checked nothing must never report PASS.

The build script never fails the build. It runs for every consumer who merely
depends on the library, so a missing `tests/vectors/` emits an empty table instead of
panicking, and the binary fails closed at runtime where it belongs.

Output is byte-identical to the Python and TypeScript firewalls.

**Patch release. No format change and no vector change:** every frozen vector is
byte-identical to 0.4.1, `sig_version` and `att_version` are unchanged, and no
existing public API moved.

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
directions:

- a vector present with no registered checker is a hard failure — the defect above;
- a registered checker whose vector is absent is a hard failure — a checker that
  quietly checks nothing is the same defect wearing the other hat.

It cannot verify a vector nobody has written a checker for; nothing can. What it
guarantees is that such a vector cannot ship *quietly*.

The output now names every vector with its digest and states the count, so what was
actually checked is answerable from the output rather than from the source:

```
CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == 4 frozen vector(s), byte-for-byte
  attestation_v1.json    50c20577...
  chain_v1.json          991e5e65...
  mint_pop_v1.json       5360ff1f...
  mint_v1.json           eef6c92f...
```

`chain_v1` and `attestation_v1` gain real packaged checks, including the chain
**walk verdict** — a third party's actual answer, not only its bytes.

**Patch release. No format change and no vector change:** every frozen vector is
byte-identical to 0.4.0, `sig_version` and `att_version` are unchanged, and no
public API moved. Only the packaged conformance check differs.

## [0.4.0]

### Added — third-party end-to-end lineage verification (ADR-0003)

A third party holding only the issuer's kernel **public** key and the ancestor
documents a presenter supplies can now verify a full delegation chain end to end.
**No format change:** no new field in the VAID document, no `sig_version` bump,
no `mint_v1.json` re-freeze.

- **`PresentedBundle`** — a new implementation of the existing `LineageResolver`
  over the documents a presenter supplies, so `assemble_lineage`, cycle detection
  and `MAX_LINEAGE_DEPTH` are reused unchanged rather than reimplemented.
- **`verify_chain`** — authenticate every document, pin each hop against the
  signed `parent_vaid`, fail closed on any gap, then check containment at every
  hop using the **mint-time** matchers, so verify-time cannot drift from the check
  that gated issuance.
- **`ChainVerification`** keeps its failure states apart. `Unverifiable` means
  attenuation could not be established — never that it was satisfied.
- **`chain_v1.json`**, a new cross-language vector pinning the *walk*: the
  assembled lineage order and the verdict. Additive; it re-freezes nothing.

### Added — tenant containment at verification time

Tenant is now checked at every hop as the qualified `(trust_domain, tenant_id)`
pair, sharing `tenant_attenuates` with `mint_child` so the two cannot drift.
`tenant_id` alone is not globally meaningful (ADR-0004), so bare equality would be
correct today and wrong the moment chains cross kernel keys.

`trust_domain` is issuer-stamped and inside the signed bytes, but **self-asserted**:
this is defence against operator error, not against a hostile issuer.

### Added — detached consent attestations and multi-key verification

Nothing in a VAID document proves the parent *consented* to a delegation;
`mint_child` enforces it in-process and none of that enforcement lands in the
child document. Under one kernel key that is invisible and sound. Across keys it
is not: an issuer B can mint a document naming issuer A's root `vaid_id` as
`parent_vaid`, inside A's authority, and it would verify while A delegated nothing.

- **`ConsentAttestation`** — a separate signed object over the same
  JCS → SHA-256 → Ed25519 discipline. Its `att_version` is independent of
  `sig_version`. Frozen as `attestation_v1.json`.
- **`KernelKeyResolver`** / `SingleKernelKey` / `KernelKeyMap` — per-document key
  selection by `kernel_key_thumbprint`. **Lands strictly behind consent:** a
  cross-key hop without a valid attestation is `Inauthentic`, never `Attenuated`.
- **Time-bounded consent** — `issued_at` and `expires_at`, `expires_at` REQUIRED
  with no default, and a fifth verdict `ConsentExpired`. Expiry is exact; the
  opening edge tolerates `MINT_POP_FRESHNESS_SECS` of clock skew.
- **The clock is injected.** `verify_chain_at` takes an explicit instant;
  `verify_chain_with` is the system-clock wrapper.

**A time bound is a mitigation, not withdrawal.** `expires_at` bounds how long
stale consent stays usable and does nothing about consent retracted inside its
window. Retraction needs durable revocation, and durable revocation does not exist
in this implementation (`docs/spec/revocation.md` R.4.6). Consent is time-bounded,
not revocable. See `docs/spec/consent-attestation.md` C.6.

### Changed

- `scope_attenuates` / `caps_attenuate` now delegate to slice-based forms
  (`scope_contains` / `caps_contain` on the document), so an attestation's bare
  authority is matched by exactly the document rule — including the empty-scope ⊤
  guard. Behaviour is unchanged.
- ADR-0003's chain-substitution argument records that it holds only under a single
  kernel key.

### Not changed

Document expiry is still not consulted by chain verification. An attestation may
outlive the parent VAID it delegates from; whether that changes is a separate
decision. `mint_v1.json` and `mint_pop_v1.json` are untouched.

## [0.3.0]

### Changed — VAID v3: the document names its issuer and commits to its key (BREAKING)

ADR-0004. `sig_version` 2 → 3. A v2 document does not verify under this release
and a v3 document does not verify under 0.2.0; this is a clean break, not a
migration, and there is no dual-version path.

- **`trust_domain`** — the issuing deployment's DNS-shaped name. Constrains *who
  claims to have issued* a document, so a verifier has something to look the
  thumbprint up under. Validated at issuer construction, so an issuer whose every
  output would fail verification cannot be built. Compared by byte equality and
  never normalized: the value is inside the signed bytes, so a verifier that
  "corrects" it recomputes different bytes from the ones the signer covered.
- **`kernel_key_thumbprint`** — RFC 9278 thumbprint URI over the RFC 7638 JWK
  thumbprint of the signing key. **Derived at mint from the signing key, never
  supplied**, so it cannot disagree with the key that signs.
- **`VAID_SIG_VERSION_V2` is REMOVED**, not retained. Every use site became a
  compile error, so none could be missed.
- **`verify_vaid_authenticity` now also checks key commitment** — that
  `kernel_key_thumbprint` corresponds to the key it was handed. Without it a
  caller could verify against a key the document never named, and "verified under
  some key we hold" is a verdict nobody can audit. Ordered *before* the signature
  check: one hash is cheaper than an Ed25519 verification already known to fail.

RFC 7638 is not hand-rolled and no JOSE dependency is added. Its substance is the
canonicalization — required members only, lexicographic, no whitespace — and for
an OKP key those are exactly `crv`/`kty`/`x` (RFC 8037 §2), which is byte-identical
to what RFC 8785 (JCS) emits. The risky half is delegated to `serde_jcs`, the same
implementation the signing path already uses and the frozen vectors already prove.

Correctness is pinned against the **published RFC 8037 Appendix A.3 vector**, so
this is checked against the standard rather than only against itself.

### Changed — `mint_v1` re-frozen at v3 (BREAKING for anyone pinning the digest)

    old digest a5d73cf487b4eade190acdae31e61322a83dae5639b6891ede3a8d32af0bbf86
    new digest eef6c92fed497f5a2fc9abfc781b74da62bd54b8c66a2fcb6e7915d2d95d22f0

Generated from Rust, then Python and TypeScript were each proven to reproduce the
digest and signature from the vector's `input` **before** it was written to any
vector file — the `mint_pop_v1` discipline.

The vector's `trust_domain` is `vaid.example`, **reserved by design**. The vector
publishes its own kernel private seed, so anyone can produce validly-signed
documents under it. That is harmless while the document names no issuer; the
moment it carries a trust domain, a real name would be a published, working
forgery generator for that deployment. RFC 2606 reserves `.example`, and a
conforming verifier SHOULD refuse to bind a trust bundle to a special-use name,
so the vector's issuer is unbindable by rule rather than by convention.

### Added — `has_conforming_timestamps`

`is_expired` stays **total** and never panics. `has_conforming_timestamps` is the
new explicit `encoding.md` E.6 profile check, so a caller wanting strictness asks
for it and can tell the two failures apart (issue #10, settled by splitting the
surface rather than picking a winner).

## [0.2.0]

### Added — public-key-only document verification (additive, non-breaking)

- **`verify_vaid_authenticity(kernel_public_key: &[u8], vaid: &Vaid) -> bool`** and
  **`verify_lineage_hash(vaid: &Vaid) -> bool`** (module `verify`). A third party
  holding only an issuer's kernel **public** key can now confirm a VAID document is
  authentic — no `ReferenceIssuer`, no private key. Previously the only VAID-document
  verifier was `ReferenceIssuer::verify_vaid`, whose every constructor needs the
  private key. Scope is authenticity + `lineage_hash` consistency; it does **not**
  check expiry and does **not** consult revocation (a resolver-less verifier must not
  be gated on a lookup it cannot perform).

### ⚠️ Breaking — the `RevocationCheck` seam is replaced (read this before upgrading)

**The 0.1.2 boolean, leaf-only `RevocationCheck` is gone, replaced by a
three-state, lineage-aware seam** per `docs/spec/revocation.md` R.4. This is a
deliberate, authorised breaking change — two traits named `RevocationCheck` with
different safety properties is the outcome being avoided, so there is no shim.

- **`RevocationCheck::is_revoked(&VaidId) -> bool` → `check_lineage(&[VaidId]) ->
  RevocationStatus`.** The check is now handed the full ordered lineage (root
  first, leaf last) that the verifier assembled, and returns
  `RevocationStatus::{NotRevoked, Revoked, Unavailable}`. Custom backends must be
  updated; the boolean interface will not compile.
- **Revocation is inherited (R.4.4).** A VAID is revoked if **any** VAID in its
  lineage is. Revoking a parent now rejects every child attenuated from it — the
  0.1.2 leaf-only check did not, which was a bypass.
- **Fail closed on `Unavailable` (R.4.5).** An incomplete lineage (e.g. an empty
  resolver after a restart) or an unreachable store rejects verification rather
  than silently passing. No fail-open option ships in this release.
- **`NeverRevoked` removed.** It was a boolean-era no-op footgun.
- **`ReferenceIssuer` records every mint** (roots as well as children) so it can
  act as the verifier-side `LineageResolver` and tell a known root from an
  unresolvable id (R.4.2). New: `revocation_status`, `resolve_parent`,
  `clear_lineage`; `is_revoked`/`parent_of` removed. `with_revocation_check` now
  *replaces* the consulted store rather than layering on a built-in set.
- **Document bytes are unchanged.** No conformance vector changes; revocation
  remains outside the conformance surface (R.1).

### Migration — porting a custom `RevocationCheck`

Before (0.1.2) — a boolean, leaf-only check:

```rust
impl RevocationCheck for MyBackend {
    fn is_revoked(&self, vaid_id: &VaidId) -> bool {
        self.deny_list.contains(vaid_id)
    }
}
```

After (0.2.0) — three-state, handed the full ordered lineage:

```rust
impl RevocationCheck for MyBackend {
    fn check_lineage(&self, lineage: &[VaidId]) -> RevocationStatus {
        match self.load_deny_list() {
            Err(_unreachable) => RevocationStatus::Unavailable,
            Ok(deny) if lineage.iter().any(|id| deny.contains(id)) => RevocationStatus::Revoked,
            Ok(_) => RevocationStatus::NotRevoked,
        }
    }
}
```

Why the shape changed:

- **A boolean cannot express `Unavailable`.** When the backing store is
  unreachable, `is_revoked` had to answer `true` or `false`, and `false` is a
  silent fail-open. `RevocationStatus` makes "could not determine" a first-class
  outcome that verification fails closed on.
- **A leaf-only check is bypassable by minting a child.** `is_revoked(vaid_id)`
  saw only the presented leaf, so revoking a parent left its attenuated children
  verifiable. `check_lineage` receives the whole ancestry; a VAID is revoked if any
  ancestor is.

The default in-memory store's constructor is renamed `initialised_empty` →
`assume_nothing_revoked` to state its (fail-open-on-restart) posture rather than its
state. `NeverRevoked` is removed.

## [0.1.2]

### ⚠️ Behavior change — expiry is now enforced (read this before upgrading)

**`ReferenceIssuer::verify_vaid` now rejects expired VAIDs.** Previously, expiry
was *reported only* (via `Vaid::is_expired`) and a well-signed but expired VAID
would **pass** `verify_vaid`. As of 0.1.2 an expired VAID returns `false` from
`verify_vaid` even when its kernel signature is valid.

**The API signature is unchanged, but this is a semantic break, not a routine
patch.** If you depend on the `vaid-mint` **Rust crate** from crates.io and your
code relies — deliberately or accidentally — on expired-but-signed VAIDs
continuing to verify, that behavior is gone. Any such VAID that verified under
0.1.1 will now fail. If you need to distinguish "forged" from merely "expired",
call `Vaid::is_expired()` yourself before `verify_vaid`; the method is still there.

Action required: audit any flow that verifies long-lived or replayed VAIDs, and
confirm your issuance TTL is long enough for legitimate use before upgrading.

### Scope — Rust crate only; PyPI `vaid-mint` is NOT covered by this release

This 0.1.2 release covers the **Rust crate only.** The PyPI `vaid-mint` package
is a **separate, hand-written Python implementation — not a build or mirror of
this crate** — and it is **not** updated here. As of this release the PyPI
package remains on **0.1.1** and still has the **original, advisory-only expiry
behavior** that this release fixes in Rust: its `verify_vaid` does **not** reject
expired VAIDs, and it has **no `RevocationCheck` seam**. If you consume `vaid-mint`
from PyPI, you still have the revocation/expiry gap disclosed at launch —
upgrading is not yet possible on the Python side. Behavioral parity between the
Rust and Python implementations is broken until a follow-up ports these changes to
the Python package.

> **Update (superseded):** the follow-up has landed and is **published to PyPI**.
> The Python `vaid-mint` package **0.1.2** ports both changes — TTL is
> hard-enforced at verification and the `RevocationCheck` seam
> (`with_revocation_check`, `InMemoryRevocationList`, `NeverRevoked`,
> `DEFAULT_VAID_TTL_HOURS`) is available in Python. `pip install vaid-mint` now
> gets you the seam, and behavioral parity between the two implementations is
> restored.
>
> **The same ⚠️ expiry semantic break described above applies to the Python
> package as of 0.1.2** — audit any Python flow that verifies long-lived or
> replayed VAIDs before upgrading. See `python/vaid-mint/CHANGELOG.md`.
>
> The scope note above is retained as the historical record of what the Rust 0.1.2
> release itself covered.

### Added

- **`revocation::RevocationCheck`** — a pluggable, synchronous revocation seam
  consulted at verification time. Inject a durable, restart-surviving backend via
  the new **`ReferenceIssuer::with_revocation_check`** without patching the crate.
  The injected check is layered *in addition to* the built-in in-memory revoked
  set (a VAID is rejected if either reports it revoked), so enabling the seam
  never silently disables existing behavior.
  - **`revocation::InMemoryRevocationList`** — a standalone, injectable in-memory
    implementation (non-durable; same guarantees as the built-in set).
  - **`revocation::NeverRevoked`** — an honest no-op implementation, available as
    an explicit opt-in. It is **not** the default: for revocation, a no-op default
    would be a functional regression (nothing checked), not a neutral "not wired
    yet" state, so the reference issuer keeps its working in-memory set as the
    default. This deliberately deviates from the `PermitAll` / `NoopAudit`
    convention; see the type's docs.
- **`DEFAULT_VAID_TTL_HOURS`** (`= 1`) — the recommended baseline issuance TTL.
  With only non-durable revocation in this reference, a short TTL is the primary
  control that bounds a leaked or compromised VAID's exposure window. The
  `ReferenceIssuer` constructors still take an explicit `vaid_ttl_hours`.

### Changed

- `verify_vaid` now hard-rejects expired VAIDs (see the behavior-change note
  above) and additionally consults any injected `RevocationCheck`.

### Notes

- **Additive at the API level.** No existing public signatures changed; the new
  seam is opt-in and the default construction path preserves the existing
  in-memory revocation behavior.
- **Revocation durability is still unsolved in this crate.** The seam exists, but
  the shipped default remains in-memory and non-durable — it does not survive a
  restart. A durable, hash-chained store remains a property of the hosted
  authority. See the README "Trust model" section.
- The frozen mint conformance vector (`tests/vectors/mint_v1.json`) is unchanged;
  none of these changes touch the VAID document shape or signing bytes.

## [0.1.1]

- Prior release. See git history.
