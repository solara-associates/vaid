# ADR-0008: A second signature algorithm is a new `sig_version` value, not a new field

**Status:** Accepted
**Date:** 25 September 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Amends:** none. This ADR adds a rule for a case the format already admits; no
existing decision changes.
**Related:** ADR-0004 (v3 issuer identifier and kernel key thumbprint) — the
thumbprint is the second binding this ADR relies on; ADR-0006 (verify over
presented bytes) — Req. 3's three-state precedent is why the algorithm is not an
optional member; ADR-0003 (attenuation verification via detached chain) — the
per-hop rule in §3 below; ADR-0007 (expiry containment) — the "first fault found,
same fault in all three" discipline reused in §3; `docs/spec/encoding.md`,
`docs/trust-anchor.md`

---

## Context

VAID signs with pure Ed25519 and nothing else. `verify_vaid_authenticity_graded`
verifies with `ring`'s `ED25519` (`crates/vaid-mint/src/verify.rs:290`), and a
sweep of `crates/` for any other primitive returns nothing. The specification says
so as a commitment: `docs/spec/encoding.md:86` pins "**Pure Ed25519** (RFC 8032
Ed25519, *not* Ed25519ph and *not* Ed25519ctx)", and `CONTRIBUTING.md:15-17`
states the canonicalization path is "RFC 8785 (JCS) → SHA-256 → Ed25519, and stays
that way unless the standard itself is versioned".

**This ADR is that versioning, and it is being written before any second algorithm
exists.** The reason is that the rules below are properties of a signed format
other people implement. They are cheap to state now and expensive to change after
a second algorithm is in the field, because at that point every rule has a
deployed implementation that assumed something.

**Why a second algorithm is in question at all.** The operator key that
`OperatorSigningPort` fronts (`crates/vaid-pop/src/ports.rs:36-47`) lives in an
external key store, and the store's supported algorithms are not ours to choose.
Several hardware modules validated to FIPS 140-2/3 Level 3 offer ECDSA P-256 and
RSA and **not** Ed25519 — including one major cloud HSM service whose Ed25519
support this estate asserted in its own tree and which does not exist. So an
Ed25519-only standard is not a preference; it decides which key stores a deployment
may use, and today it excludes several that a buyer will already own.

Nothing here commits to implementing P-256. It commits to what the answer must
look like if any second algorithm is added, so that the answer is not improvised
three times in three languages.

### What the tree already provides, which changes the shape of the decision

Three things exist already, and each removes work the obvious design would have
created.

1. **`sig_version` is a signed member, and signing it is already stated to be the
   anti-downgrade mechanism.** `canonical_vaid_signing_bytes` serializes the whole
   document with only `kernel_signature` nulled, and the field list is explicit
   that "every other field is covered, including `sig_version`"
   (`crates/vaid-mint/src/document.rs:626-628`). The constant's own documentation
   says the version "is itself a signed field, so a downgrade to a weaker payload
   cannot be forged without breaking verification" (`document.rs:25-28`).
2. **`kernel_key_thumbprint` binds the algorithm a second time, transitively.**
   ADR-0004's thumbprint is RFC 7638 over `{"crv":"Ed25519","kty":"OKP","x":…}`
   (`crates/vaid-mint/src/issuer_identity.rs:63`). `crv` and `kty` are inside the
   hashed preimage. The document commits to the resulting thumbprint in a signed
   member, and the verifier recomputes it from the key **it** holds
   (`verify.rs:281-284`). A P-256 key is an EC JWK with `x` **and** `y`, so its
   thumbprint has a different preimage and cannot collide with an OKP one by
   construction.
3. **`UnsupportedSigVersion` already exists in all three implementations and is
   already the first branch checked** — `verify.rs:144,275`,
   `python/vaid-mint/vaid_mint/verify.py:140`, and the TypeScript mirror. It is
   reached before the trust-domain check, before the thumbprint check and before
   any signature verification.

So the format already carries a signed algorithm discriminant, already binds the
key's algorithm into a second signed member, and already has a fail-closed verdict
for a discriminant it does not recognise. **The question is not how to add a
binding. It is which of the two existing bindings is normative, and what a verifier
that does not accept an algorithm is obliged to say.**

## Decision

### 1. The algorithm is identified by `sig_version`, and by nothing else

**A second signature algorithm is introduced as a new value of the existing
`sig_version` member. No new member is added to the document.**

`sig_version` becomes the single discriminant for the whole signing scheme: the
signature algorithm, the digest, the canonicalization, and the document's required
members. It is not a schema version with an algorithm bolted alongside it. One
integer selects one complete, named scheme, and the mapping from value to scheme is
a **total function fixed in this specification** — not a negotiation, not a lookup,
and not something a document can extend.

Three alternatives were considered and rejected.

**A new optional `sig_alg` member, absent meaning Ed25519.** This is what the
session-249 inventory identified as the cheap branch, because an absent member
leaves the 35 frozen vector digests untouched. It is rejected, and ADR-0006 Req. 3
is why. That requirement exists because `Option<PresentedUuid>` could not tell an
**absent** member from one present as JSON `null`, serde rendered `None` as `null`
on the way out, and a document with `parent_vaid` deleted re-serialized with it
restored — reproducing bytes the presenter never sent
(`document.rs:263-274`). The estate has already paid for one member whose meaning
depended on its absence, and the remedy was a three-state encoding in three
languages. An algorithm identifier is a worse candidate for that treatment than
`parent_vaid` was: absence would have to resolve to a specific algorithm, and
absence resolving to any particular claim is the failure this repository has hit
before. `sig_version` is mandatory, bounded and already signed. It needs no
absence semantics at all.

**Deriving the algorithm from the key.** Rejected. It inverts the trust direction:
the verifier would learn what to run from material selected by reference to the
document in front of it. The resolver comment already states the principle for keys
— "returning a key is an assertion of trust … resolving a thumbprint from the
document itself, or from any source the presenter controls, verifies that a number
equals itself" (`crates/vaid-mint/src/chain.rs:211-218`). The same applies to the
algorithm.

**Deriving the algorithm from the key's length.** Rejected, and it is worth naming
because it is the shortcut an implementer will reach for. A raw Ed25519 public key
is 32 bytes; a compressed P-256 point is 33 and an uncompressed one is 65, so the
lengths happen not to collide. But `kernel_key_thumbprint` takes `&[u8]` and
hardcodes `"crv":"Ed25519","kty":"OKP"` (`issuer_identity.rs:62-63`): handed 32
bytes it will label them Ed25519 whatever they are. **Key bytes do not name their
own algorithm.** Any function that computes a thumbprint must therefore take the
algorithm as an argument rather than infer it, and that argument must come from the
verifier's own trust bundle.

### 1a. `sig_version` becomes a scheme identifier, and the no-dual-acceptance rule narrows to match

Today `VAID_SIG_VERSION_V3` carries a strict single-value rule, and its stated
reason is specific: "There is no dual-version acceptance — a v2 document must not
verify under a v3 verifier, because accepting both would recreate the very
downgrade surface that signing `sig_version` exists to close"
(`document.rs:31-36`). v3 added `trust_domain` and `kernel_key_thumbprint`; a v2
document is one that commits to **less**. Refusing it is refusing a weaker
document.

**That rule is retained for its actual reason and narrowed to it.** A verifier MAY
accept more than one `sig_version` **only** where the values it accepts are
equivalent in what they commit to, and differ only in the signature primitive. A
verifier MUST NOT accept a value that omits any member a value it also accepts
requires. Concretely: accepting `{3, N}` where `N` is v3's member set signed with a
different algorithm is permitted; accepting `{2, 3}` is not, and stays not.

This is the sub-decision most likely to be misread, so the test is stated as a
rule an implementer can apply: **if two accepted values do not require the same
members, one of them is a downgrade of the other and the pair is forbidden.**
A scheme that changes both the member set and the algorithm is two changes and gets
two version numbers, the schema change being the one that forbids dual acceptance.

### 1b. The Ed25519 digests do not move, and that is a consequence rather than a goal

Because no member is added and no member's encoding changes, the canonical bytes of
every existing document are unchanged, and so are all 35 frozen vector digests.
Under `scripts/verify-vector-freeze.mjs` a moved digest beneath an already-released
version is a hard failure — "a wire-contract break shipped without a version bump"
(`:320`) — and nothing here moves one. New vectors for a new scheme are new files,
which the checker reports as "new since `<tag>`" and passes (`:296`).

**This is stated as a consequence, not as the reason for the decision.** The reason
is §1: one signed discriminant with no absence semantics. If the cheap outcome and
the correct one had diverged, ADR-0006 Req. 3 would still have decided it.

### 2. A chain may mix algorithms. A verifier may refuse to, and must say which it did

Mixed chains will occur. A chain is verified hop by hop from the presented bundle,
each document against the key its own `kernel_key_thumbprint` names
(`chain.rs:379-385`), and different issuers hold different keys in different key
stores. An estate adopting a second algorithm does so gradually, so a parent signed
under one scheme legitimately delegating to a child signed under another is the
ordinary case, not an attack.

**So mixing is permitted at the format level, and the rule is per hop:**

1. **Each hop is verified under the scheme its own document names.** There is no
   chain-level algorithm. A hop is authentic or it is not, on its own terms.
2. **A chain is no stronger than its weakest hop**, and a verifier that reports a
   chain verdict reports one for the chain as a whole — so a caller who needs to
   know the algorithms cannot learn them from the verdict, and must inspect the
   documents. This ADR does not add a strength lattice; ranking primitives is a
   policy question that does not belong in a format decision.
3. **A verifier configured to accept only a subset of schemes MUST reject the whole
   chain, not the hops it can check.** Verifying a prefix and declaring the chain
   attenuated is exactly the "attenuation satisfied when it means attenuation
   unverifiable" conflation that `ChainVerification` was split to prevent
   (`chain.rs:136-141`). A chain is a claim about an unbroken path to a root; a path
   with an unchecked hop is not a shorter valid chain, it is an unverified one.
4. **That rejection is `Unverifiable`, never `Inauthentic`.** This is the
   load-bearing half of the sub-decision. The existing failure path for a key the
   resolver does not hold is `Inauthentic`, on the stated ground that "an unaccepted
   issuer is not a degraded issuer, it is somebody else" (`chain.rs:378-381`). That
   reasoning is right for an unknown key and **wrong for a known key under an
   unaccepted algorithm**: there, the verifier is not saying the document is forged,
   it is saying it cannot form an opinion. Reporting a forgery when the truth is a
   missing capability sends an operator to an incident that is not happening —
   the same argument ADR-0007 made for keeping `Expired` apart from `NotAttenuated`,
   and `ConsentExpired` apart from both.
5. **The first fault found is the fault reported**, ancestors before descendants, so
   that three implementations report the same reason and not merely the same
   boolean — the discipline ADR-0007 §4 established and `verdict_v1.json` exists to
   enforce.

Forbidding mixed chains outright was considered. It is smaller — the session-249
inventory notes that forbidding it deletes the per-hop algorithm handling entirely
— and it is rejected because it makes gradual adoption impossible. A single
delegation into an issuer that has moved to a different key store would break every
chain through it, and the pressure that creates is to move every issuer at once,
which no estate can do.

### 3. A verifier declares its accepted schemes explicitly, in the trust bundle, and fails closed outside it

**The accepted set is per key, declared in the same structure that declares the
accepted keys, and it is an input to verification rather than a property of the
build.**

The trust bundle is already the right home and already carries the right semantics.
`KernelKeyResolver::resolve_key` answers "the raw key for this thumbprint, or `None`
if this verifier does not accept that key", and returning one is documented as an
assertion of trust (`chain.rs:205-222`). A key entry becomes a key **and its
scheme**, for three reasons:

1. The thumbprint preimage already contains `kty` and `crv` (§Context item 2), so a
   thumbprint that resolves to a key whose scheme the bundle does not name is
   internally inconsistent — a contradiction the bundle can be made to reject when
   it is loaded, once, rather than on every verification.
2. It makes the scheme arrive from the verifier's own configuration and never from
   the document, which §1 requires.
3. A per-key declaration is strictly more expressive than a global one and costs
   nothing: a deployment that accepts one scheme everywhere states it once per key,
   and a deployment migrating one issuer at a time can say so.

**The declaration must be visible to whoever relies on the verdict.** A verifier
that accepts a narrower set than another verifier returns `Valid` for a different
population of documents, and "verified" then means different things in different
deployments — the property VAID exists to remove. The accepted set is therefore
part of what a verifier publishes about itself, alongside the trust anchor it uses.
`docs/capabilities.json` is where this repository already states what an
implementation does, and it is where an implementation's accepted schemes belong.

**Outside the accepted set, the verdict is a refusal to check, distinguishable from
an accusation.** `UnsupportedSigVersion` is retained as that verdict for documents
and is the first branch, before the trust-domain, thumbprint and signature checks
(`verify.rs:275-277`), so an unaccepted scheme is never reported as a signature
failure. Two constraints on it:

- `is_valid()` stays "`Valid` only" (`verify.rs:207-209`). It is a boolean and
  cannot carry this distinction; a caller that needs it uses the graded verdict.
  What must **not** happen is a second boolean that reads as "acceptable" — an
  unaccepted scheme is not acceptable, it is uncheckable, and those are the same
  answer for an authorization decision and different answers for an operator.
- The branch order is load-bearing and unchanged. `verify.rs:264-270` says so and
  says why: reordering silently changes which reason a document gets while leaving
  every boolean identical, "precisely the class of divergence `verdict_v1.json`
  exists to catch". Adding a scheme must not reorder it.

**A verifier that accepts no scheme for a key it holds fails closed.** An empty
accepted set is a verifier that verifies nothing, not one that verifies everything,
and it is a configuration error that should refuse at load rather than return
`UnsupportedSigVersion` for every document it is shown.

### 4. A second scheme needs a second KIND of conformance vector

Every frozen vector asserts that "any conforming mint derives the same public key
and produces the same signature"
(`crates/vaid-mint/tests/vectors/mint_v1.json:5`). That is true because RFC 8032
Ed25519 is deterministic. **It is a property of the algorithm, not of the format**,
and it is false for ECDSA without RFC 6979 — which no external key store offers,
and an externally held key is the case a second algorithm exists to serve.

So a scheme whose signatures are not reproducible gets vectors that freeze the
canonical bytes, the digest and the public key, and assert
**verifies-under-the-frozen-key** — never **reproduces-the-frozen-signature**. This
is a second assertion shape in the conformance suites, not more vectors of the
existing shape.

**The reproduce-assertion is not weakened for Ed25519.** It is what proves three
independent implementations agree rather than merely accepting each other's output,
and it stays exactly as it is for every existing vector. A scheme that cannot
support it is a scheme whose conformance evidence is weaker, and that difference
must be legible in the vector rather than smoothed over by a shared assertion that
quietly drops to the weaker one for both.

## Scope: what this does NOT do

- **It adds no algorithm.** No second scheme is defined, numbered or implemented
  here. `VAID_SIG_VERSION_V3 = 3` remains the only value any implementation emits
  or accepts, and every existing document, vector and verifier is unaffected.
- **It does not change the operator key's algorithm.** `OperatorSigningPort` is
  still typed `[u8; 64]` / `[u8; 32]` (`ports.rs:41,46`). A raw ECDSA P-256 `r‖s`
  signature is also 64 bytes so the signature type would survive, but a P-256
  public key is 33 or 65 bytes and the key type would not. Widening that interface
  is where an algorithm enters the port, and it is not done here.
- **It does not settle the thumbprint and anchor work.** A non-OKP key needs an
  algorithm argument through four thumbprint implementations, a different entry
  shape in the published `docs/kernel-keys.json`, and two gates widened that
  currently hard-reject anything but an OKP JWK — `skill/src/verify-core.mjs:106`
  and the site's kernel-key drift check. §1's last paragraph states the constraint
  those changes must satisfy; it does not do them.
- **It does not revise `CONTRIBUTING.md:16`.** Two of the three languages cannot
  sign an ECDSA prehash with the library they have — Rust's `ring` keeps
  `sign_digest` private, and the TypeScript PoP package is Ed25519-only by
  construction — so a P-256 implementation needs a new runtime dependency in the
  PoP path, which that line forbids. The rule is ours to revise and it should be
  revised deliberately rather than discovered in a pull request. Python needs
  nothing.
- **It does not rank primitives.** §2 item 2 says a chain is no stronger than its
  weakest hop and deliberately declines to define an ordering.
- **It says nothing about the substrate's own keys.** The kernel signing key, the
  audit signer, the mesh envelope key and per-tenant keys are different keys from
  the operator key and are out of scope here. That distinction is load-bearing and
  is treated in the companion scoping document.

## Consequences

**No coordinated re-freeze, and no release prerequisite.** Because §1 adds no
member, the wire contract for `sig_version = 3` is untouched and the freeze checker
stays green. A second scheme is additive in the strongest sense available: existing
documents verify unchanged under an updated verifier, and an updated document is
`UnsupportedSigVersion` — not `Inauthentic` — to a verifier that has not been
updated.

**The field-upgrade ordering is still real and is now the whole of the cost.**
Every verifier must accept a scheme before anything signed with it is presented,
because until then a legitimate document is reported as unverifiable. That is an
ordering constraint on deployment, not a format problem, and it is the reason §3
puts the accepted set in configuration rather than in a build.

**The publication deadlock previously cited here no longer applies.** Both input
documents to this decision treat the release path as blocked by vaid#84, sized as a
prerequisite. vaid#84 is closed, and `vaid-mint` 0.8.0 is present on all three
registries — crates.io, PyPI and npm, each read on 25 September 2026. A coordinated
three-ecosystem publish is therefore a demonstrated path rather than a hoped-for
one. This does not make a second algorithm cheap; it removes one reason it was
thought impossible.

**`UnsupportedSigVersion` acquires a second meaning, and the two are not
distinguishable in the verdict.** It already means "the discriminant is not the
current one" — reached by a v2 document and by a forged document with no
`sig_version` at all, which deserializes to `0` (`verify.rs:141-144`). Under §3 it
also means "a scheme this verifier does not accept". A caller cannot tell those
apart from the verdict alone, and this ADR accepts that rather than splitting the
variant, because splitting it changes a value in `verdict_v1.json` — a frozen
vector — for a distinction that is a property of the verifier's configuration and
already legible from it. An implementation SHOULD log which of the two it meant.
This is a known sharp edge, recorded rather than hidden.

**The `sig_version` doc comment is already stale and should be corrected
separately.** `document.rs:238-241` describes the field as "`2` for every VAID
minted here" while the constant is `3`. It is a comment, outside every gate, and
correcting it is not part of this decision.

**Nothing in the substrate can usefully change until the port does.** The substrate
consumes `OperatorSigningPort`; the algorithm enters the interface in this
repository and surfaces there.
