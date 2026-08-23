# Changelog

All notable changes to the Python `vaid-mint` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written Python implementation — not a build or
mirror of the Rust `vaid-mint` crate**. The two are versioned independently, and
their changelogs are separate files (`crates/vaid-mint/CHANGELOG.md` covers Rust).
Where a change lands in both, as 0.1.2 does, each changelog documents its own
language's behavior.

## [0.8.0]

### BREAKING — the reference issuer now fails closed out of the box

`ReferenceIssuer`'s default revocation store was `assume_nothing_revoked()`: it
vouched ``NOT_REVOKED`` over an empty set, so a fresh issuer verified immediately.
Because the store is non-durable it could not detect its own restart, so a VAID
revoked before a restart verified clean afterwards. That is a **fail-open posture**,
and it was the **default**.

It is now **absent**: `revocation_status` reports ``UNAVAILABLE`` and `verify_vaid`
returns ``False`` until revocation state is loaded. Verification fails closed (R.4.5).

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

You are affected only if you call `ReferenceIssuer.verify_vaid` or
`revocation_status` on an issuer you have not given a revocation backend.

### BREAKING — `with_revocation_check` is removed

It replaced one of the two durable stores R.4.6 requires and left the other in
memory. That configuration is not a degraded mode, it is an outage: after a restart
every **child** credential fails closed while every **root** keeps verifying (see
below). It was deprecated in the same breath as `RevocationBackend` landed and is
removed here rather than kept through a deprecation window, because a window is a
period during which the reachable failure stays reachable.

Replace with `with_revocation_backend(RevocationBackend(check=..., lineage=...))`. To
keep an in-memory resolver deliberately, pass `InMemoryLineageStore` as the second
half — the same behaviour, named at the call site.

### Added — `assuming_nothing_revoked()`

The pre-0.8.0 posture, asked for by name:

```python
issuer = ReferenceIssuer.ephemeral(24, "vaid.example").assuming_nothing_revoked()
```

Identical behaviour to the old default — a vouching in-memory revoked set, with the
lineage store untouched and still in-memory. It is a fail-open posture and this
spelling says so where it is chosen. Fine for local development, quickstarts and
tests; not for anything that must survive a restart. This is what R.4.5 permits:
fail-open as an explicit configuration.

### Added — durable revocation is TWO stores, and the seam now says so (spec R.4.6)

`RevocationBackend`, `LineageStore` and `InMemoryLineageStore`, plus
`ReferenceIssuer.with_revocation_backend`. `with_revocation_check` is removed (above).

R.4.6 has always required **two** durable stores — the revoked set and the lineage
resolver — and until now the crate offered an injection point for exactly one of
them. `with_revocation_check` replaced the revoked set; the resolver was a private
`dict` on `ReferenceIssuer` with no way to substitute it and, more decisively, no
write half at all. A self-hoster following the documented path could only build
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

`RevocationBackend` takes both halves and there is no single-half
constructor, so that state is no longer reachable **by omission**. It stays
reachable by explicitly naming `InMemoryLineageStore` as the second half, which is
a legitimate single-process choice and is visible at the call site. The two halves
remain separate objects rather than one protocol with both methods: R.4.1 requires
that the check "does not perform lookups and is not given the means to", and a
combined protocol hands one object both jobs.

`LineageStore.record` is the write half the resolver never had. Without it an
injected durable resolver would be permanently empty — the same outage with extra
steps — because the issuer wrote every mint into its own dict.

**Proven by a restart, not by a round trip.** `tests/test_durable_restart.py` (and its
Rust and TypeScript mirrors) spawns real child interpreters: one mints and revokes
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

ADR-0004. `VAID_SIG_VERSION_V3 = 3`. A v2 document does not verify under this
release and a v3 document does not verify under 0.2.0; a clean break, not a
migration.

- **`trust_domain`** — the issuing deployment's DNS-shaped name, validated at
  issuer construction. Compared by byte equality and never normalized: the value
  is inside the signed bytes, so a verifier that "corrects" it recomputes
  different bytes from the ones the signer covered.
- **`kernel_key_thumbprint`** — RFC 9278 thumbprint URI over the RFC 7638 JWK
  thumbprint of the signing key. **Derived at mint, never supplied.**
- **`verify_vaid_authenticity` now also checks key commitment**, ordered before
  the signature check.

Pinned against the **published RFC 8037 Appendix A.3 vector**, and proven to
produce a thumbprint byte-identical to the Rust and TypeScript implementations
before the conformance vector was re-frozen.

### Changed — `mint_v1` re-frozen at v3 (BREAKING for anyone pinning the digest)

    old digest a5d73cf487b4eade190acdae31e61322a83dae5639b6891ede3a8d32af0bbf86
    new digest eef6c92fed497f5a2fc9abfc781b74da62bd54b8c66a2fcb6e7915d2d95d22f0

### Fixed — `is_expired` no longer raises from a function that promises a `bool`

`is_expired` is now **total** and never raises. It previously raised `ValueError`
from a function whose signature promises a `bool`, with no mention in the
docstring, so callers did not guard against it.

`has_conforming_timestamps` is the new explicit `encoding.md` E.6 profile check,
so a caller wanting strictness asks for it and can distinguish the two failures
(issue #10).

### Note on the 0.2.0 → 0.3.0 gap

This package's manifest sat at `0.2.0` while `__version__` already read `0.3.0`:
the v3 work bumped the code and the TypeScript package but missed this manifest
and this changelog. PyPI therefore served a v2 `vaid-mint` while the repository's
code was v3. The `verify-internal-versions` gate caught the self-disagreement;
this release resolves it in the honest direction, since the code really is v3.

## [0.2.0]

### Added — public-key-only document verification (additive, non-breaking)

- **`verify_vaid_authenticity(kernel_public_key: bytes, vaid: dict) -> bool`** and
  **`verify_lineage_hash(vaid: dict) -> bool`** (module `verify`), mirroring the Rust
  `vaid_mint::verify`. A third party holding only an issuer's kernel **public** key can
  confirm a VAID document is authentic — no `ReferenceIssuer`, no private key. Scope is
  authenticity + `lineage_hash` consistency; it does **not** check expiry and does
  **not** consult revocation. (Separately, the Python `vaid-pop` package gains
  `verify_signed_payload`, the request-PoP verifier it previously lacked — Rust already
  had it.)

### ⚠️ Breaking — the `RevocationCheck` seam is replaced (read this before upgrading)

**The 0.1.2 boolean, leaf-only `RevocationCheck` is gone, replaced by a
three-state, lineage-aware seam** per `docs/spec/revocation.md` R.4. A deliberate,
authorised breaking change, mirroring the Rust `vaid-mint` 0.2.0.

- **`RevocationCheck.is_revoked(vaid_id) -> bool` → `check_lineage(list[str]) ->
  RevocationStatus`.** The check is handed the full ordered lineage (root first,
  leaf last) and returns `RevocationStatus.{NOT_REVOKED, REVOKED, UNAVAILABLE}`.
  Custom backends must be updated.
- **Revocation is inherited (R.4.4).** A VAID is revoked if **any** VAID in its
  lineage is; revoking a parent now rejects every child attenuated from it. The
  0.1.2 leaf-only check did not — a bypass.
- **Fail closed on `UNAVAILABLE` (R.4.5).** An incomplete lineage (e.g. an empty
  resolver after restart) or an unreachable store rejects rather than passing
  silently. No fail-open option ships in this release.
- **`NeverRevoked` removed.** It was a boolean-era no-op footgun.
- **`ReferenceIssuer` records every mint** (roots as well as children) so it can
  act as the verifier-side `LineageResolver` (R.4.2). New: `revocation_status`,
  `resolve_parent`, `clear_lineage`; `is_revoked`/`parent_of` removed.
  `with_revocation_check` now *replaces* the consulted store.
- **Document bytes are unchanged.** No conformance vector changes; revocation
  remains outside the conformance surface (R.1).

### Migration — porting a custom `RevocationCheck`

Before (0.1.2) — a boolean, leaf-only check:

```python
class MyBackend:
    def is_revoked(self, vaid_id: str) -> bool:
        return vaid_id in self.deny_list
```

After (0.2.0) — three-state, handed the full ordered lineage:

```python
class MyBackend:
    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        try:
            deny = self.load_deny_list()
        except StoreUnreachable:
            return RevocationStatus.UNAVAILABLE
        if any(vaid_id in deny for vaid_id in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED
```

Why the shape changed:

- **A boolean cannot express `UNAVAILABLE`.** When the backing store is
  unreachable, `is_revoked` had to answer `True` or `False`, and `False` is a
  silent fail-open. `RevocationStatus` makes "could not determine" a first-class
  outcome that verification fails closed on.
- **A leaf-only check is bypassable by minting a child.** `is_revoked(vaid_id)`
  saw only the presented leaf, so revoking a parent left its attenuated children
  verifiable. `check_lineage` receives the whole ancestry; a VAID is revoked if any
  ancestor is.

The default in-memory store's constructor is renamed `initialised_empty` →
`assume_nothing_revoked` to state its (fail-open-on-restart) posture rather than its
state. `NeverRevoked` is removed.

## [0.1.3]

### Docs only — no behavior change

Identical in behavior to 0.1.2. This release exists solely to replace the
README rendered on the package's PyPI page.

- **Corrected a stale upgrade note.** The README bundled in the 0.1.2 sdist
  said *"0.1.2 is not yet on PyPI — `pip install vaid-mint` still serves
  0.1.1"*. That was true when written but was overtaken by the 0.1.2 PyPI
  publish itself, leaving the 0.1.2 page asserting its own non-existence.
  The note was corrected in git immediately after that publish, but a
  README is baked into the uploaded artifact, so the correction could not
  reach PyPI without a new version.
- **The CHANGELOG link now resolves on PyPI.** It was relative
  (`CHANGELOG.md#012`), which only works on GitHub; it is now absolute.

No code, API, wire-format, or conformance-vector change. The Rust
`vaid-mint` crate is unaffected and stays at 0.1.2 — its README never
carried the note.

## [0.1.2]

### ⚠️ Behavior change — expiry is now enforced (read this before upgrading)

**`ReferenceIssuer.verify_vaid` now rejects expired VAIDs.** Previously this
package did **not check expiry at all**: a well-signed but long-expired VAID would
**pass** `verify_vaid`, and there was no `is_expired` to check it with — a caller
who wanted expiry enforced had to parse `expires_at` themselves. As of 0.1.2 an
expired VAID returns `False` from `verify_vaid` even when its kernel signature is
valid.

**The API signature is unchanged, but this is a semantic break, not a routine
patch.** Semantic Versioning is not a safety guarantee here: **this is a breaking
behavioral change shipped under a patch version bump, and it is not safe to
auto-upgrade.** Pin deliberately, and read the next paragraph before you do.

**Who this breaks.** Any caller currently verifying long-lived VAIDs — or VAIDs
minted with a long `vaid_ttl_hours` and expected to keep verifying past that
window — will see previously-passing `verify_vaid` calls start returning `False`.
Nothing raises; the call simply returns `False` where it used to return `True`, so
this surfaces as an authorization failure at runtime rather than an import-time or
type-level error. If your code relies — deliberately or accidentally — on
expired-but-signed VAIDs continuing to verify, that behavior is gone. Any such
VAID that verified under 0.1.1 will now fail.

If you need to distinguish "forged" from merely "expired", call the new
`is_expired(vaid)` yourself before `verify_vaid`.

Action required: audit any flow that verifies long-lived or replayed VAIDs, and
confirm your issuance TTL is long enough for legitimate use before upgrading.

### Scope — cross-language parity restored

Published to PyPI as `vaid-mint` 0.1.2. This closes the gap disclosed at the Rust
crate's 0.1.2 release, when the seam and TTL enforcement existed only in Rust and
the PyPI package was still on 0.1.1: **both reference implementations now ship the
`RevocationCheck` seam and hard expiry enforcement**, and are at behavioral parity.

The two remain separate implementations versioned independently — a shared version
number is a coincidence, not a guarantee. Git tags are language-prefixed
(`python-v0.1.2` here, `rust-v0.1.2` for the crate); see `CONTRIBUTING.md`.

### Added

- **`revocation.RevocationCheck`** — a pluggable revocation seam consulted at
  verification time, defined as a `runtime_checkable` `Protocol` (mirroring the
  `AuthorizationGate` / `AuditSink` convention already used in this package).
  Inject a durable, restart-surviving backend via the new
  **`ReferenceIssuer.with_revocation_check`** without patching the package; it
  returns `self`, so it chains:
  `ReferenceIssuer.ephemeral(1).with_revocation_check(check)`.

  **The seam is additive, not a replacement.** The built-in in-memory revoked set
  remains the default and is **always consulted**; an injected check is consulted
  **in addition to** it, **never instead of** it. A VAID is rejected if **either**
  reports it revoked. Enabling the seam therefore never silently disables existing
  behavior, and there is no way to switch the built-in set off through this seam.
  - **`revocation.InMemoryRevocationList`** — a standalone, injectable in-memory
    implementation (non-durable; same guarantees as the built-in set). Exposes
    `revoke`, `is_revoked`, `__len__`, and `is_empty`.
  - **`revocation.NeverRevoked`** — an honest no-op implementation, available as
    an explicit opt-in. It is **not** the default: for revocation, a no-op default
    would be a functional regression (nothing checked), not a neutral "not wired
    yet" state, so the reference issuer keeps its working in-memory set as the
    default. This deliberately deviates from the `PermitAll` / `NoopAudit`
    convention; see the class's docs. Injecting it does **not** mean "this package
    performs no revocation checks" — the built-in set still runs.
- **`DEFAULT_VAID_TTL_HOURS`** (`= 1`) — the recommended baseline issuance TTL.
  With only non-durable revocation in this reference, a short TTL is the primary
  control that bounds a leaked or compromised VAID's exposure window. The
  `ReferenceIssuer` constructors still take an explicit `vaid_ttl_hours`.
- **`document.is_expired(vaid)`** — reports whether a document has passed its
  `expires_at`. New in Python (the Rust crate has had `Vaid::is_expired` as an
  informational check since 0.1.0). Available for callers who need to distinguish
  "forged" from "expired" before calling `verify_vaid`.
- `RevocationCheck`, `NeverRevoked`, `InMemoryRevocationList`,
  `DEFAULT_VAID_TTL_HOURS`, and `is_expired` are exported from the package root.

### Changed

- `verify_vaid` now hard-rejects expired VAIDs (see the behavior-change note
  above) and additionally consults any injected `RevocationCheck`. Its gating
  order now matches the Rust crate exactly: `sig_version` → **expiry** →
  built-in revoked set → **injected check** → signature verification.
- **Version metadata drift resolved.** `vaid_mint.__version__` had been left at
  `"0.1.0"` since the initial release while `pyproject.toml` advanced to `0.1.1`,
  so the published 0.1.1 package reported `__version__ == "0.1.0"` on
  introspection. Both now read `0.1.2` and agree.

### Notes

- **Additive at the API level.** No existing public signatures changed; the new
  seam is opt-in and the default construction path preserves the existing
  in-memory revocation behavior. The expiry enforcement is the one behavioral
  change, and it is not opt-in.
- **Revocation durability is still unsolved in this package.** The seam exists,
  but the shipped default remains in-memory and non-durable — it does not survive
  a restart. A durable, hash-chained store remains a property of the hosted
  authority. See the README "Trust model" section.
- The frozen mint conformance vector (`vaid_mint/vectors/mint_v1.json`) is
  unchanged; none of these changes touch the VAID document shape or signing bytes.
  All gating added here runs *before* signature verification.

## [0.1.1]

- Internal-vocabulary scrub: docstrings, README, and test-fixture naming
  (`substrate` → `managed authority`, `codex` → `acme` as the test tenant). No
  behavior or API change. Published to PyPI. Note: this release reported
  `__version__ == "0.1.0"` — see the drift note under 0.1.2.

## [0.1.0]

- Initial release. See git history.
