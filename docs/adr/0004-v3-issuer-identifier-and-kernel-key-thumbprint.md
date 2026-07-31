# ADR-0004: VAID v3 carries an issuer identifier and a kernel key thumbprint

**Status:** Accepted
**Date:** 30 July 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0001 (revocation outside the conformance surface), ADR-0002
(capabilities manifest), ADR-0003 (attenuation via detached chain),
`docs/spec/encoding.md`, synthera#16

---

## Context

A VAID document today carries fourteen fields and none of them identifies the
issuer or the key that signed it. This was established by direct inspection of
all fourteen fields, all five frozen vectors, and the Rust, Python and TypeScript
implementations, which agree on the field set.

Three fields look as though they might identify and do not:

- `sig_version` is a scheme discriminant, identical in every deployment
  worldwide.
- `vaid_id` is a random UUIDv4, byte-equal to `agent_id`, with no issuer-derived
  structure. Contrast a SPIFFE ID, which carries the trust domain in the
  identifier itself.
- `public_key_der` is the holder's key, the subject of the proof of possession,
  never the kernel's. `mint_v1.json` demonstrates the independence directly.

`kernel_signature` cannot help either. Ed25519 has no public-key recovery, so the
signing key cannot be derived from the signature.

`tenant_id` partially identifies and misleadingly so. It names a tenant within an
unnamed deployment, is namespaced by nothing, and is holder-supplied through
`VaidSeed`. Two self-hosters both minting `tenant_id: "acme"` produce documents a
verifier cannot distinguish.

The consequence is that a third party holding a leaf VAID cannot determine which
key to verify it against. Every SYNTHERA deployment holds its own kernel key, and
self-hosting is on the roadmap, so this is precisely the cross-organisation case
the project's positioning rests on.

This is the root of a chain of gaps found over the preceding week. The site
claimed on-sight verification. The reference implementation shipped no public-key
document verifier. When one shipped, no consumer used it. STATUTE holds VAIDs it
never verifies. All of it terminates here: verification was never available to
anyone outside, because there was no way to know what to verify against.

## Decision

**VAID v3 adds two fields to the document: an issuer identifier and a kernel key
thumbprint.** `sig_version` becomes 3.

1. **`trust_domain`** — a constrained, DNS-shaped trust-domain identifier naming
   the issuing deployment. Modelled on SPIFFE's trust domain: the identity
   carries the domain, and bundles are scoped per domain. Schema in the next
   section.
2. **`kernel_key_thumbprint`** — an RFC 7638 JWK thumbprint over the Ed25519
   kernel public key, expressed as an RFC 9278 thumbprint URI
   (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url>`).
3. Both fields are inside the signed structure and therefore inside the canonical
   bytes. Both are **required**; neither is optional. An optional field would
   admit two possible key sets and therefore two canonical forms.
4. **Scope is the VAID document only.** No thumbprint in `MintPopPayload`: it is
   issuer-side output and the holder cannot know it. `operator_pop_v1`,
   `pathquery_v1` and `completion_v1` are untouched. One vector, `mint_v1.json`,
   is re-frozen.
5. **Attenuation does not ride this break.** This reverses the intent recorded in
   the draft of this ADR. Per ADR-0003, third-party attenuation verification is
   achievable by detached chain presentation with no document field at all, so
   there is no second break to consolidate. v3 carries these two fields and
   nothing else.
6. **No dual-version acceptance.** A v2 document must not verify under a v3
   verifier. Version gating already exists in all four verifiers and is mutually
   rejecting by construction. Accepting both recreates the downgrade surface that
   signing `sig_version` was designed to close.

## The `trust_domain` schema

Deferred by the draft of this ADR as needing its own record; decided here,
because it is inside the signed bytes and cannot be settled mid-implementation.

**Form: a bare, constrained, DNS-shaped trust domain. Not a URI.**

```
"trust_domain": "synthera.solara.associates"
```

Grammar, normative:

- lowercase ASCII only: `a`–`z`, `0`–`9`, `-`, `.`
- at least two labels separated by `.`; each label 1–63 bytes; no leading or
  trailing `-`
- no trailing dot, no empty labels
- total length 1–253 bytes
- the final label MUST NOT be all-numeric, which excludes dotted-quad IP literals
- **compared by byte equality.** Never normalized at verification: normalizing
  would make the verifier's recomputed canonical bytes differ from the signer's,
  which is the `encoding.md` E.6 timestamp failure in a new place. Because the
  grammar forbids uppercase, an uppercase producer is non-conforming rather than
  corrected.

Special-use names (RFC 2606 / RFC 6761 — `example`, `invalid`, `localhost`,
`test`, `local`, `internal`) are permitted by the grammar but a production issuer
MUST NOT use one, and a verifier SHOULD refuse to bind a trust bundle to one.
Grammar permits; policy forbids.

### Why a bare domain rather than a URI or a SPIFFE ID

- **It composes directly with the eventual WebPKI or DNS anchor.** The anchor is
  control of the name, and a TLS certificate or DNS record proves control of
  exactly the field's bytes. Every other form requires a parse step to extract
  the anchorable component, and a parse step is a three-language divergence
  opportunity.
- **It composes with SPIFFE federation without committing to SPIFFE.** A bare
  trust domain *is* a SPIFFE trust domain; promotion is prefixing
  (`spiffe://`, `wimse://`, `did:web:`), which loses nothing. Emitting
  `spiffe://` today would claim conformance the project does not hold — no SVIDs,
  no Workload API — and a SPIFFE ID's path component invites encoding tenant or
  agent data, creating a second identity that drifts against `tenant_id` and
  `vaid_id`. In SPIFFE the trust domain is the issuer and the SPIFFE ID is the
  subject; this field is the issuer.
- **It is checkable in three languages with no dependency.** Roughly fifteen
  lines of character checks, hand-rolled rather than regex, so JavaScript,
  Python and Rust regex dialects cannot disagree.
- **A general URI is disqualified.** RFC 3986 equivalence is not decidable by
  inspection — trailing slash, default port, percent-encoding case, empty versus
  `/` path. Inside signed bytes compared byte-wise, an ambiguous canonical form
  is a defect generator of the E.6/E.7 class. WIMSE tolerates this by requiring
  whole-URI comparison, which works because WIMSE never anchors on the component.
  This field does.

Two deliberate divergences from SPIFFE, each with a reason: **no underscore**
(not valid in a hostname, so unbindable by the anchor being targeted), and
**byte equality rather than case-insensitive comparison** (see above).

### Bindable, not resolvable

The identifier MUST be unique and bindable. It MUST NOT be required to resolve.

- IETF WIMSE workload credentials forbids looking up trust anchor material from
  information carried only in the token. A resolvability requirement would push
  implementers toward the prohibited pattern.
- Resolution per verification is a network dependency, which breaks the offline
  and edge cases and destroys the cache-once property that is this design's main
  benefit.
- SPIFFE is explicit that a trust domain need not be a resolvable DNS name.
- An air-gapped self-hoster must be able to hold an issuer identity at all.

"Bindable" means the identifier is the kind of name whose control can be
demonstrated, so that an out-of-band binding has something to attest. DNS-shaped
names have that property whether or not any given deployment resolves. **The
shape is DNS because bindability requires it; resolution is a deployment
choice.**

Consequently the specification MUST NOT make a well-known location normative. A
non-normative note about a conventional path is acceptable; a normative one
recreates the pattern WIMSE prohibits.

### The vector must use a reserved documentation name

`mint_v1.json` publishes `kernel_private_key_seed_hex`. The vector's kernel
signing key is public by design, so anyone can produce validly-signed documents
under it. That is harmless while the document names no issuer.

**It stops being harmless the moment the document carries a trust domain.** A
vector whose `trust_domain` named a real deployment would be a published,
working generator for validly-signed documents claiming that deployment's
issuance.

The re-frozen `mint_v1.json` therefore uses **`vaid.example`**, reserved by
RFC 2606 for exactly this purpose. Combined with the verifier-SHOULD-refuse rule
above, the vector's issuer is unbindable by rule rather than by convention.

### Field naming

`trust_domain` rather than `issuer` or `issuer_id`: it names what the value is,
matches SPIFFE and WIMSE vocabulary, and avoids the JWT `iss` connotation that
invites `https://` values and OIDC discovery semantics this ADR rejects. In a
format whose entire E.13 table is "plausible wrong value", a field name that
steers the implementer toward the right shape is load-bearing. `issuer` invites a
URL; `trust_domain` invites a domain.

`kernel_key_thumbprint` rather than `kernel_key_id`: `key_id` is already taken in
the estate for a different value — the bootstrap UUIDv4 in the substrate's kernel
key store, surfaced on `GET /status` as `kernel_signing_key.key_id`. Reusing the
name would guarantee confusion between two live values, one already on an HTTP
surface. `thumbprint` is also simply accurate. The field is **not** named
`kernel_public_key_*`, which would invite the fail-open line the next section
exists to prevent.

Both are snake_case per `encoding.md` E.3, matching the document convention.

## Why a thumbprint rather than the key itself

Embedding the kernel public key directly was considered and rejected, but not on
the grounds given in synthera#16. That analysis rejected it as circular: a key
carried inside the document it verifies is no more trustworthy than the document.
That reasoning is correct and it applies with exactly equal force to a
thumbprint. A hash of a key is no more trustworthy than the key. The proposal
cannot be justified by claiming it escapes that critique.

The actual reason is a failure-mode argument.

You cannot verify an Ed25519 signature with a hash. Embedding the key produces a
document that looks independently verifiable and invites
`verify(vaid.kernel_public_key, vaid)` — a fail-open in a single line a reviewer
may not flag. Embedding a thumbprint makes that mistake unrepresentable: the
verifier is structurally forced to source the key from elsewhere, and the trust
decision stays visible in the call signature.

Same trust content, opposite failure mode. That is the argument, and it should not
be restated as a trust argument later.

## What this does and does not solve

**Solves: key selection.** The document commits to its verification key, so for
any document and candidate key, correspondence is decidable offline by one hash.
In a multi-key deployment — which is any deployment after a rotation — this
removes trial verification against every key in a bundle, removes an
amplification surface, and removes "verified under some key we hold" verdicts that
nobody can audit.

**Solves: a distinguishable failure.** Today a wrong key and a forged signature
both produce `false`. With a thumbprint, an unknown key produces "unknown kernel
key `<thumbprint>`" and a bad signature produces a verification failure.
Collapsing those two into one boolean is the shape catalogued in the fail-open
pattern record.

**Solves: cacheable trust material.** The thumbprint is what a verifier pins and
what names a cache miss. Demand-driven refresh — refetch only on encountering an
unknown thumbprint — is expressible only because the identifier is in the
document. This is the strongest single argument for the design.

**Does not solve: attribution.** The residual attack is exact and is recorded
here verbatim so it is never claimed away:

> An adversary generates a keypair, mints a well-formed v3 document with any
> `tenant_id`, sets the kernel key thumbprint to their own key's thumbprint, and
> signs. Signature valid, thumbprint matches, `lineage_hash` consistent,
> `sig_version` correct. The document is self-consistently authentic and entirely
> unauthorized: a valid VAID from a kernel nobody trusts.

What solves that is a binding from an issuer name to a key set, obtained over a
channel the verifier already trusts, independent of the document. `trust_domain`
makes the mismatch *detectable* — the document claims `acme.example` and the
thumbprint is not in `acme.example`'s bundle — which a bare thumbprint would not.
But detection is not attribution. The anchor is separate work and it is the larger
half.

**Does not solve:** authorization that a trusted key was permitted to issue a
given tenant or scope; cross-issuer `tenant_id` collision; revocation of a kernel
key.

## Trust anchoring is out of band, by standard

The issuer-to-key-set binding is a static published fact, distributed out of
band, consulted once per issuer and cached. This is not a compromise; it is what
the standards require. IETF WIMSE workload credentials states that consumers must
bind each trust domain to authorized issuers and trust anchors via a secure
out-of-band mechanism, and that the issuer claim must not be used to look up trust
anchor material from information carried only in the token. SPIFFE does the same
with per-trust-domain bundles.

Two residuals on caching:

- Rotation is where the in-document thumbprint earns its place. A cached bundle
  stays valid for all historical keys, and refetch is triggered only by an
  unknown thumbprint.
- Compromise makes indefinite caching unsafe. A verifier caching forever accepts
  documents from a revoked kernel key. This is consistent with ADR-0001, which
  places revocation outside the conformance surface, but it is a residual and not
  a solved problem.

## Prior art adopted rather than invented

- **RFC 7638** for the thumbprint computation. For Ed25519 the required JWK
  members are `crv`, `kty`, `x`, lexicographically ordered, no whitespace,
  SHA-256. Inventing `sha256(raw_32_bytes)` buys nothing and costs interop.
- **RFC 9278** for the string form, which gives hash agility for free and
  composes with DID and SPIFFE tooling.
- **JOSE `kid` and WIMSE** for the architecture: in-document identifier selects,
  anchors strictly out of band.
- **SPIFFE** for the trust domain in the identity and for federation as bundle
  exchange between named domains.

Explicitly **not** adopted: the JWS or JWT envelope. The existing pipeline — JCS,
SHA-256, raw Ed25519, per `encoding.md` E.2 — is deliberate, documented, and
backed by computed wrong-answer tables. Borrow the identifier formats and the
architecture, not the envelope.

## Sequencing

**One break, and it is this one.** The cost of a format break is almost entirely
fixed: version bump, re-freeze and cross-verify vectors across three languages
and their vendored copies, re-release across three registries, revise
`encoding.md` including the computed wrong-choice digest tables in E.13, update
three READMEs, the claims register, capabilities and the site. Two breaks pay the
fixed cost twice and put a published standard through two mutually incompatible
versions in one quarter, which is the most damaging thing an open standard can do
to early adopters.

The draft of this ADR proposed consolidating attenuation into this break for that
reason. ADR-0003 removes the need: attenuation requires no document field, so
there is no second break to avoid. The two decisions compose — detached chain
verification must authenticate each ancestor, which requires selecting the key
that signed it, which is what `kernel_key_thumbprint` provides. v3 first, then
attenuation as additive work.

**npm is unpublished, and that decides the release order.** PyPI and crates.io
carry 0.2.0. npm carries nothing. Landing v3 before publishing to npm means the
only JavaScript SDK version ever published is current, and no npm consumer ever
sees a v2 package. If 0.2.0 is published to npm first, it should be shipped
deliberately as a parity-proof release with the break pre-announced in the
release notes.

**Move the kernel key to KMS in parallel.** Today it is a PKCS#8 blob in a
secret, loaded in process. Holding it as a KMS key version is a posture
improvement every publication option benefits from and is where a real rotation
story comes from. `publicKeyViewer` publication is a near-free consequence. This
is not the interim answer to third-party verification; it serves principals inside
the GCP org, not the cross-organisation case.

**Do not build a well-known JWKS route yet.** It requires load balancer work the
substrate does not have, and its content should be decided after the thumbprint
format is fixed, or it will publish bootstrap UUIDs that must later be re-keyed.

**Cheap and worth doing now:** publish the current kernel key's RFC 7638
thumbprint as a static, human-checkable fact in the docs, on the site, and in
release notes. No format break required, no automated verification gained, but it
is the out-of-band anchor material every option eventually needs.

## Consequences

**Accepted:**

- Third-party key selection becomes possible and decidable offline.
- Unknown key and bad signature become distinguishable failures.
- Rotation gains a demand-driven cache story.
- One break, and attenuation does not need a second.

**Costs, accepted knowingly:**

- A hard break for anyone on 0.2.x. A v2 document will not verify under a v3
  verifier and vice versa. Correct, and there is no silent degradation path.
  Exposure is bounded by both being pre-1.0. A migration note is required.
- The wrong-choice digest tables in `encoding.md` E.13 are computed and every row
  must be recomputed. Stale rows would be exactly the documentation defect E.11
  exists to shame.
- `synthera-kernel` must emit both fields; it already holds the key material, so
  this side is small.

**The residual, stated in the same breath as the mechanism:**

This does not deliver third-party verification. It delivers the identifier that
makes third-party verification expressible. The hard half is operating an
issuer-to-trust-bundle distribution a third party will actually trust: WebPKI or
DNS anchored, with rotation and revocation. Ship this format change without ever
shipping that anchor and the cross-organisation wedge is exactly as blunt as it is
today, with a nicer document.

If this work is ever described as having solved third-party verification, that
description is false, and it is the same shape as the defects in the fail-open
pattern record: a claimed safety property not actually held.

## Still not decided here

- Whether v3 ships before or after the npm publish of 0.2.0.
- The publication route for the issuer-to-key-set binding (synthera#16 options).
