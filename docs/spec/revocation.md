# Revocation

**Prose specification. VAID.**
Implements ADR-0001. Revision 2, incorporating Phase 0 findings of 27 July 2026.

Terminology follows the repo: a **VAID** is the document (`Vaid`); **lineage** is the
child to parent ancestry (`parent_vaid`, `lineage_hash`); **mint**, **attenuate** and
**verify** are used as in the crates.

---

## R.1 Revocation and conformance

Revocation is outside the VAID conformance surface.

Conformance is defined over the minting, attenuation and verification of VAID
documents, and is fixed by the frozen conformance vectors. Conformance does **not**
extend to:

- revocation list format
- revocation distribution or transport
- revocation check semantics
- revocation storage or durability

An implementation MAY provide no revocation mechanism and remain conformant. Two
conformant implementations MAY differ arbitrarily in revocation behaviour.

This exclusion is deliberate. It is stated here rather than left implicit because a
specification that omits revocation without saying so is indistinguishable from one
that overlooked it.

## R.2 Why revocation is excluded

VAID's central claim is that a conforming implementation in any language produces and
verifies documents that agree byte for byte with every other conforming
implementation. That claim is worth making only if the conformance surface is small
enough to be verified exhaustively by frozen vectors and stable enough to build
against.

Revocation does not currently meet either condition. Its semantics are coupled to
deployment topology in ways the document format is not. A single-process mint, a
multi-instance service, an offline verifier, and a cross-organisation verifier that
does not trust the issuing mint's availability have materially different
requirements. Specifying one as normative would either exclude the others from
conformance or produce a specification loose enough to be meaningless.

Freezing a revocation format now would freeze a design that no implementer outside the
authoring organisation has built against.

Revocation is expected to move inside the conformance surface in a future version,
once there is implementation evidence for the normative shape. That change will be
made by amendment, with vectors, and announced as a conformance-surface change.

## R.3 Implementations SHOULD provide revocation

Excluding revocation from the conformance surface does not make it optional in
production.

VAIDs are bearer documents. A deployment that issues them with no means of
invalidating an outstanding VAID before expiry has no response to key compromise,
leakage, or a misbehaving agent other than waiting out the TTL.

Implementations intended for production SHOULD provide revocation. Section R.4 defines
a common shape so that independent implementations converge voluntarily ahead of any
normative requirement.

## R.4 The RevocationCheck seam (non-normative)

Non-normative: an implementation departing from this remains conformant. It is
specified in detail because no conformance vector covers revocation, and there is
therefore nothing else preventing independent implementations from diverging.

### R.4.1 Division of responsibility

Two distinct jobs, and conflating them is the principal design error available here.

**The verifier assembles the lineage.** It resolves the ordered ancestry of the VAID
under verification, root first, leaf last. The check does not perform lookups and is
not given the means to.

**The check answers about a lineage it is handed.** It receives an ordered list of
VAID identifiers and reports revocation status for that list.

This split keeps the check implementable against any backing store without that store
needing knowledge of lineage resolution.

### R.4.2 Lineage assembly

A VAID carries `parent_vaid`, which is one hop, and `lineage_hash`, which is one-way
and encodes only the immediate parent. **The full lineage is not recoverable from the
VAID itself.** Assembly requires a resolver, and the reference implementation's
resolver is the issuer's in-process lineage map.

Assembly therefore has three outcomes, and all three MUST be representable:

| Outcome | Condition |
|---|---|
| Complete | Every hop resolved from leaf to a VAID with `parent_vaid` absent. |
| Incomplete | Some `parent_vaid` present but unresolvable. |
| Trivially complete | Leaf has no `parent_vaid`. It is its own root. |

An **incomplete** lineage MUST be reported to the caller as `Unavailable` under R.4.3.
It MUST NOT be presented to the check as though it were the whole lineage, and the
resulting verification MUST NOT succeed.

This requirement exists because of a specific failure. The reference resolver is an
in-memory map that is empty after process restart. A child VAID verified against an
empty map resolves nothing, and a naive implementation returns a single-element
lineage containing only the leaf. That result is indistinguishable from a legitimately
rootless VAID and passes verification. The revocation of every ancestor is silently
discarded.

An implementation that cannot distinguish "this VAID has no parent" from "I could not
resolve this VAID's parent" does not satisfy this section.

### R.4.3 Return

The check returns exactly three states:

| State | Meaning |
|---|---|
| `NotRevoked` | The check completed against a complete lineage. Nothing in it is revoked. |
| `Revoked` | At least one VAID in the lineage is revoked. |
| `Unavailable` | Status could not be determined. |

`Unavailable` covers both failure modes: the revocation store could not be consulted,
and the lineage could not be completely assembled. The caller MUST be able to
distinguish `Unavailable` from `NotRevoked`.

An interface returning a boolean does not satisfy this section. Neither does one that
expresses `Unavailable` only as an error the caller may discard.

### R.4.4 Revocation is inherited

A VAID is revoked if any VAID in its lineage is revoked. Revoking a parent revokes
every VAID attenuated from it, transitively.

An implementation checking only the presented leaf leaves revocation bypassable by
minting a child, and does not satisfy this section.

### R.4.5 Behaviour on Unavailable

Verification MUST fail closed on `Unavailable`. A VAID whose revocation status cannot
be determined is rejected.

An implementation MAY offer fail-open as an explicit configuration option for
deployments prioritising availability. Where offered:

- it MUST NOT be the default
- it MUST be named to state what it does rather than obscure it
- selecting it MUST be recorded in verification output for every verification
  performed under it

A verifier operating fail-open is, for that period, a verifier without revocation.
That is a legitimate deployment choice and an illegitimate silent default.

### R.4.6 Durability

Revocation state and lineage state that do not survive process restart do not provide
revocation. A store that is empty after restart reports `NotRevoked` for every VAID
ever revoked, and does so without any indication that anything is wrong.

Implementations providing non-durable stores MUST make state loss detectable, so it
surfaces as `Unavailable` rather than as `NotRevoked`. An in-memory store that cannot
distinguish "initialised and empty" from "never populated" does not satisfy this
section.

The reference implementation currently ships non-durable in-memory stores for both
revocation and lineage. See R.6.

### R.4.7 Invocation

Consulted during verification.

MAY additionally be consulted during attenuation, so a revoked parent cannot mint a
child. Implementations that do not are not deficient: the child carries its parent in
its lineage and fails verification under R.4.4 regardless.

Not consulted during minting of a root VAID. A VAID that does not yet exist cannot be
revoked.

## R.5 Time to live is not revocation

VAIDs carry a short time to live and implementations enforce it strictly.

TTL bounds the window in which a compromised VAID remains usable. It does not close
that window on demand and it is not a revocation mechanism. It is defence in depth and
is described as such throughout.

An implementation relying on TTL expiry alone has no response to compromise other than
waiting.

## R.6 Implementation status

Stated plainly because it is the current state and an evaluator will determine it from
the source within minutes.

| | 0.1.2 (current) | 0.2 (planned) |
|---|---|---|
| Seam present | Yes, Rust and Python | Yes, all languages |
| Return type | Boolean | Three-state per R.4.3 |
| Lineage-aware | No, leaf identifier only | Yes, per R.4.2 and R.4.4 |
| Assembly failure detected | No | Yes |
| Behaviour on store failure | Not representable | Fail closed per R.4.5 |
| Revocation store durability | In-memory only | See note |
| Lineage store durability | In-memory only, issuer-local | See note |

**The 0.1.2 seam does not satisfy R.4.** It accepts a single identifier and returns a
boolean, so revocation of a parent does not affect an attenuated child, and a failed
check is indistinguishable from a clean one. Deployments on 0.1.2 should treat
revocation as covering root VAIDs only, on a single issuer process, with no restart.

Durable backing stores are a host-application responsibility in all versions. The
reference implementation ships in-memory stores for development. R.4.6 governs how
those stores must behave when their state is absent, not whether the reference
implementation must become durable.

**Note on the reference default (0.2 onward).** The reference issuer defaults its
revocation store to a *vouching* posture (the constructor is named
`assume_nothing_revoked`, not for its empty state but for what it does): it answers
`NotRevoked` over an empty set so a fresh issuer verifies out of the box. Being
non-durable, it cannot detect its own restart — after a restart it is reconstructed
empty and again vouches `NotRevoked`, so a VAID revoked before the restart verifies
clean. This is a deliberate trade of restart-detection for out-of-the-box usability
in development, and it is legitimate under R.4.6 (which requires only that an
*absent* store report `Unavailable`, and that absent be distinguishable from
vouching — both of which hold), **not** under R.4.5 as a configuration: it is not a
fail-open verifier setting, it is the reference's development default, and it is
named to be unmisreadable. Two alternatives make a deployment restart-safe: (1)
inject a durable `RevocationCheck`; or (2) start the store in absent state until
revocation state has been loaded into it — an absent store reports `Unavailable`,
so verification fails closed until the load completes.

## R.7 Authenticity is separate from policy

Verifying a VAID answers two different questions, and they must not be collapsed:

- **Authenticity** — was this document genuinely issued under a given kernel key, and
  is it internally consistent? This needs only the issuer's **public** key. It is
  answered by `verify_vaid_authenticity` (checks the signature-scheme version, the kernel
  signature over the canonical document, and `lineage_hash` consistency), and it is
  available to any third party — cross-organisation, offline, or after the fact —
  because a signature needs only the public key to check.
- **Standing** — may this VAID be *used* right now? That is policy: at minimum
  **expiry** (a temporal check) and **revocation** (this section). Standing is
  evaluated on top of authenticity, by the party that holds the relevant state.

`verify_vaid_authenticity` deliberately answers authenticity **only**. It does not check
expiry, and — the load-bearing point for this specification — it does **not** consult
revocation. Gating authenticity on revocation would reintroduce the R.4.2 problem in
a new place: a resolver-less verifier cannot perform the lineage/revocation lookup, so
every third-party verification would fail closed, and the portable, publicly-checkable
authenticity that is the point of a VAID would be lost. Revocation status is therefore
reported on a **separate path** (`RevocationCheck` / the reference's
`revocation_status`), or not at all where the verifier has no revocation state — never
as a precondition of confirming the document is real.
