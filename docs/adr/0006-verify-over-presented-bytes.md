# ADR-0006: A verifier canonicalizes the bytes it was presented, not its own projection

**Status:** Accepted
**Date:** 7 August 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0001 (conformance covers mint, attenuation and **verification**),
ADR-0003 (third-party chain verification), ADR-0004 (v3 identity fields),
ADR-0005 (segment-bounded scope containment — the previous "all three agreed and
all three were wrong" case), forge-agents ADR-0018, `roundtrip_v1.json`

---

## Context

Rust `vaid-mint` returns **the wrong verdict** on a valid document.

Given a conforming VAID plus one additive extension field, signed by its issuer
over the bytes as presented:

| implementation | behaviour | verdict |
|---|---|---|
| Python `vaid-mint` | canonicalizes the raw dict | **correct** — verifies |
| TypeScript `vaid-mint` | spreads the object as received | **correct** — verifies |
| **Rust `vaid-mint`** | **projects through the typed `Vaid`** | **wrong** — rejects |

All three are certified by the same frozen vectors. Two agree with the issuer;
one does not. Verified against a real production document and against a
synthetic `zzz_future_extension` field, so this is not about any particular
field.

### The mechanism

Rust's `Vaid` is a typed struct and serde's default is to **ignore unknown
fields**. Deserializing a presented document therefore discards every field the
struct does not name, and `canonical_vaid_signing_bytes` then hashes what
survived. The digest is over a document **nobody sent**.

That is the defect, stated exactly: *the implementation answered a question it was
not asked.* It is not that the answer was insecure — it fails closed, rejecting
rather than accepting — it is that the verdict is about different bytes.

Tolerant parsing is correct for a consumer reading a document. It is wrong for a
**canonicalizer**, whose entire job is to reproduce the bytes the signer signed.
The two needs were served by one type, and the parsing need won silently.

### Why no vector caught it

Every existing vector pins **one implementation's output for a given input**:
`mint_v1` fixes the digest a mint must produce, `chain_v1` the verdict of a walk
over documents the vector itself supplies. This defect only appears when one
implementation **mints** and another **verifies** — and only when the document
carries a field the verifier does not know.

Checked: across all five mint-side vectors (`mint_v1`, `mint_pop_v1`, `chain_v1`,
`attestation_v1`, `scope_v1`), **zero documents carry an unknown field**. The gap
is structural, not an oversight in any one vector.

### Why this is the second time

ADR-0005 fixed bare prefix matching that was identical in all three
implementations: three mirrored ports of one wrong rule agreed perfectly and
nothing was asking. This is the mirror image — the ports **disagree**, and still
nothing was asking. Both were invisible for the same reason: conformance was
defined over output-for-input, never over agreement between implementations on
bytes one of them did not produce.

## Decision

**A conforming verifier MUST canonicalize the document it was presented.**

Normatively, for any implementation computing `canonical_vaid_signing_bytes` or
any verdict derived from it:

1. **MUST NOT silently discard** fields it does not recognise. The canonical
   bytes MUST cover every member of the presented JSON object.
2. **MUST either** verify over the presented bytes, **or** reject the document
   explicitly as unrecognised. It **MUST NOT** re-project and return a verdict —
   a verdict about bytes the caller did not supply is worse than no verdict,
   because it is indistinguishable from one about the bytes they did.
3. **MUST round-trip byte-exactly.** Parsing a document and re-serializing it
   MUST reproduce the presented object, so that canonicalization is a function of
   the input alone.

Requirement 2 is the load-bearing one. Rejecting an extension you cannot
understand is a legitimate, conservative posture; *quietly deciding it says
something different and then judging that* is not.

### The reference adopts the permissive branch

Rust `vaid-mint` captures unrecognised members rather than rejecting:

```rust
#[serde(flatten)]
unknown_fields: BTreeMap<String, serde_json::Value>,
```

Chosen over `#[serde(deny_unknown_fields)]` because the standard's own extension
rule (synthera ADR-0034) permits additive fields, and a verifier that rejects
every extension makes that rule unusable across implementations. Preserving them
is also what Python and TypeScript already do, so it converges the three rather
than adding a fourth behaviour.

A document minted by this crate has an empty map and is **byte-identical** to one
minted before the change; `mint_v1.json` is unaffected and still reproduces.

### A new vector shape: verify-only

`roundtrip_v1.json` pins **a verdict over given bytes**, not bytes over a given
input. That is a shape the surface did not previously have, and it is the only
shape that can catch cross-implementation disagreement: every implementation is
handed the *same signed document* and must return the *same verdict*.

Its core cases are unknown-field cases:

- a conforming document **plus an unknown field**, signed over the extended
  bytes → MUST verify;
- the same document with that field **removed** → MUST NOT verify under the same
  signature, proving the field is inside the digest rather than ignored;
- a document whose signature covers only the known fields, presented **with** an
  extra field → MUST NOT verify, proving the extra field is not being dropped.

It stays **inside** the existing conformance surface. ADR-0001 §2 already defines
conformance over "mint, attenuation, and verification"; verification was in scope
and simply had no vector. Adding a surface would imply this is a new kind of
obligation, and it is not — it is the obligation that was always there and never
tested.

## Options considered

**A — `deny_unknown_fields` in Rust.** Simplest, and safe: an unrecognised
document is rejected loudly. Rejected as the default because it makes the
ADR-0034 extension rule unusable — the substrate's own `external_identity`
documents would be refused by the reference outright — and because it diverges
from Python and TypeScript, leaving three behaviours instead of one. It remains a
**conforming** choice under Decision 2 for an implementation that wants it.

**B — capture unknown fields (chosen).** Converges Rust onto what the other two
already do, keeps additive extensions verifiable, and leaves minted documents
byte-identical.

**C — declare Python and TypeScript wrong and standardise on projection.**
Rejected on principle: a verifier that hashes its own projection cannot verify
any document containing anything it has not been taught, which forecloses
extension permanently and makes every future field a breaking change for every
existing verifier.

**D — fix Rust, skip the vector.** Rejected. The defect survived because nothing
asked; fixing the instance without adding the question leaves the next one to be
found the same way. The vector is the durable half.

## Consequences

**Accepted:**

- Rust `vaid-mint` agrees with Python and TypeScript on documents carrying
  extensions. The three implementations now give the same verdict on the same
  bytes, which is what "conforming" was supposed to mean.
- Additive extensions become verifiable across implementations, so the ADR-0034
  extension rule works in practice rather than only on paper.
- The conformance surface gains a verify-only shape, and with it the ability to
  catch cross-implementation disagreement at all.

**Costs, accepted knowingly:**

- **A breaking change**, shipped as 0.6.0. An implementation relying on Rust
  silently dropping unknown fields will now see them in the digest. That reliance
  was on a defect.
- `Vaid` grows a field that is not part of the document. It is a capture
  buffer, not a member, and is documented as such.
- **The same defect exists in the substrate** (`synthera-types`
  `canonical_vaid_signing_bytes` projects through its typed `Vaid`), and it is in
  production. Confirmed by test: a valid 17-key document is re-projected to 16
  and rejected. That is a synthera fix, tracked separately, and this ADR is the
  normative statement it will cite.

## Revisiting

- **An implementation that legitimately needs to reject extensions.** Decision 2
  already permits it; if that becomes the common case rather than the exception,
  the reference default should be reconsidered.
- **A field that must NOT be covered by the signature.** None exists today
  (`kernel_signature` is nulled, not excluded). One would need its own decision,
  because it breaks the rule that canonicalization is a function of the input.
