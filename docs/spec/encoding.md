# Encoding

**Prose specification. VAID.**
Revision 3, 31 July 2026. Written from the findings of the third (TypeScript)
implementation; revised 29 July to record that E.11's gap is closed by
`mint_pop_v1.json`; revised again for **v3** (ADR-0004), which adds
`trust_domain` and `kernel_key_thumbprint` to the VAID document and moves
`sig_version` to `3`.

**On the section numbering.** The two new field rules are E.15 and E.16 but appear
below between E.10 and E.11, where they belong logically — with the other
field-level rules rather than after the conformance statement. They are not
numbered E.11 and E.12 because renumbering would silently invalidate every `E.n`
citation in the three implementations' source and in ADR-0003 and ADR-0004. Stable
citations were judged worth more than tidy ordering.

Terminology follows the repo: a **VAID** is the document (`Vaid`); a **payload** is
any other structure that is canonicalized and signed (`RequestAuthPayload`,
`CompletionRecord`, `MintPopPayload`); **canonical bytes** are the RFC 8785 output
that SHA-256 is taken over.

---

## E.1 Encoding is inside the conformance surface

Everything in this document is **normative**.

This is the opposite posture to [`revocation.md`](revocation.md) R.1, and the
contrast is the point. Revocation is excluded from the conformance surface because
its semantics are coupled to deployment topology. Encoding is the conformance
surface: it is precisely what "two conforming implementations agree byte for byte"
means. An implementation that departs from any rule here does not conform.

**Why this document exists.** The frozen conformance vectors already pin the
answer — a candidate implementation either reproduces `mint_v1.json` or it does
not. But a vector is a fixture, not a rule. Until this document existed, the rules
below lived only in Rust doc-comments, Python docstrings, and the `_comment` fields
of the vectors. An implementer working from the specification alone could not
derive the bytes; they had to read the reference source. That is a specification
defect, and it was found the way such defects usually are — by writing a third
implementation and noticing which questions the spec could not answer.

The vectors freeze the answer. This writes down the rule.

Each section below states the rule, then states what a wrong choice produces.
Those consequences are computed, not asserted: E.13 lists the digest each wrong
choice yields for the `mint_v1` input, against the correct
`eef6c92fed497f5a2fc9abfc781b74da62bd54b8c66a2fcb6e7915d2d95d22f0`.

## E.2 The pipeline

Every signature in VAID is produced by the same four steps, and no other:

1. Serialize the structure to JSON per the rules in E.3 through E.9.
2. Canonicalize per **RFC 8785 (JCS)**.
3. **SHA-256** the canonical UTF-8 bytes, yielding a 32-byte digest.
4. **Pure Ed25519** (RFC 8032 Ed25519, *not* Ed25519ph and *not* Ed25519ctx) over
   that 32-byte digest **as the raw message**, yielding a raw 64-byte signature.

Keys are **raw**: a 32-byte private seed, a 32-byte public key. No PKCS#8 wrapper,
no DER, no PEM on the wire.

The digest is the *message*, not a pre-hash. An implementation that passes the
digest to Ed25519ph, or that hashes it again before signing, produces a valid-looking
64-byte signature that no conforming verifier accepts. Note that the field name
`public_key_der` is historical and **does not** indicate DER encoding; see E.4.

## E.3 Field naming: two conventions, and which applies where

There are exactly two naming conventions, and mixing them is the single easiest way
to produce bytes that are wrong in a way that looks right.

| Structure | Convention | Example fields |
|---|---|---|
| The VAID document (`Vaid`) | **snake_case** | `sig_version`, `vaid_id`, `agent_class`, `public_key_der`, `kernel_signature`, `parent_vaid`, `scope_boundary`, `lineage_hash`, `capability_set`, `trust_domain`, `kernel_key_thumbprint` |
| `RequestAuthPayload` | **camelCase** | `vaidId`, `method`, `path`, `bodySha256`, `tenantId`, `timestamp`, `clientNonce` |
| `CompletionRecord` | **camelCase** | `vaidId`, `requestDigestSha256`, `tenantId`, `status`, `resultSha256`, `completedAt`, `signerVaidId`, `assuranceTier`, `recordNonce` |
| `MintPopPayload` | **camelCase** | `publicKeyDer`, `tenantId`, `agentClass`, `version`, `parentVaid`, `scopeBoundary`, `capabilitySet`, `nonce`, `issuedAt` |

The VAID document is snake_case; **every signed payload is camelCase**. The
asymmetry is historical — in the reference the document struct carries no
`serde(rename_all)` while the payload structs carry
`#[serde(rename_all = "camelCase")]` — but it is now fixed by the vectors and MUST
be reproduced.

JCS sorts object keys, so the *order* in which an implementation declares fields is
irrelevant. The *names* are not. A document serialized with camelCase keys is a
different object with a different key set, and canonicalizes to different bytes.

Field sets are closed. An implementation MUST NOT add fields to a signed structure,
and MUST NOT omit one (see E.7 for absent *values*, which is a different matter).

## E.4 Byte-valued fields are arrays of numbers

Every byte-valued field is a **JSON array of integers in the range 0–255**, one per
byte. Not base64. Not hexadecimal. Not an object.

This applies to `public_key_der` and `kernel_signature` in the VAID document, and
to `publicKeyDer` in `MintPopPayload`. It follows from the reference serializing
Rust's `Vec<u8>` with the default serde representation.

```json
"public_key_der": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, ...]
```

The name `public_key_der` is inherited and is **not** a statement about the
encoding of the key material: the bytes it carries are a raw 32-byte Ed25519 public
key, and the field carries them as an array of numbers.

Hash-valued and identifier fields are *not* byte arrays — `lineage_hash`,
`bodySha256`, `resultSha256`, `requestDigestSha256` are **lowercase hexadecimal
strings**, and `vaid_id` / `agent_id` / `parent_vaid` are UUIDs in canonical
lowercase hyphenated string form. A conforming implementation MUST NOT normalize a
UUID to uppercase or strip its hyphens.

## E.5 The self-signature exclusion: nulled, not deleted

A signature cannot cover its own value. The VAID document is the only structure in
VAID that carries its signature inside the signed object, and it is handled by one
rule:

> Before canonicalizing a VAID document for signing or verification, set
> `kernel_signature` to JSON **`null`**. Do not remove the key.

All four of the following are distinct, and only the first is correct:

| Treatment | Result |
|---|---|
| `"kernel_signature": null` | **Correct.** |
| key deleted entirely | Wrong — JCS canonicalizes a different key set. |
| `"kernel_signature": []` (left empty) | Wrong — an unsigned document would verify differently from a signed one. |
| left at its actual signature value | Impossible — the value is not known until after signing. |

Nulling rather than deleting is what makes the digest **independent of the
signature value**: the canonical bytes of a freshly-built unsigned document and of
that same document once signed are identical. Deleting the key would also achieve
signature-independence, but it would produce a different, non-conforming digest,
and the two mistakes are easy to conflate.

The signed payloads (`RequestAuthPayload`, `CompletionRecord`, `MintPopPayload`)
carry **no** signature field — the signature travels detached, alongside — so
nothing is nulled for them. This rule is specific to the VAID document.

## E.6 Timestamps: whole-second RFC 3339 with `Z`

Every timestamp inside signed bytes MUST be **whole-second RFC 3339 in UTC with the
literal `Z` designator**:

```
2026-06-04T12:00:00Z
```

This applies to `issued_at` and `expires_at` in the document, `timestamp` in
`RequestAuthPayload`, `completedAt` in `CompletionRecord`, and `issuedAt` in
`MintPopPayload`.

This is a **profile narrower than RFC 3339**, and it is deliberate. It is the
round-trip fixed point of the reference's date serialization: a verifier parses the
timestamp into a datetime and **re-serializes it** when it recomputes the canonical
bytes. A whole-second `…Z` string parses and re-serializes to itself, so the
signer's bytes and the verifier's recomputation agree. Any other RFC 3339 form is
re-serialized into this one, and the recomputed digest then differs from the signed
one — the signature fails to verify for a reason that has nothing to do with the
key.

Two forms are RFC 3339-valid and non-conforming here, and both are what a naive
implementation reaches for first:

- **Sub-second precision** — `2026-06-04T12:00:00.000Z`. JavaScript's
  `Date.prototype.toISOString()` always emits milliseconds, so a TypeScript
  implementation gets this wrong by default and must truncate.
- **A numeric offset** — `2026-06-04T12:00:00+00:00`, even when the offset is zero.

Implementations MUST emit this form and SHOULD reject other forms rather than
silently normalizing them.

## E.7 An absent value is `null`, and the key stays

An optional field with no value is serialized as JSON **`null`** with its key
present. The key is never omitted.

The case that matters is `parent_vaid` on a root VAID, and `parentVaid` on a
`MintPopPayload` for a root mint:

```json
"parent_vaid": null
```

Verified across all three reference implementations: a minted root document
contains the `parent_vaid` key with a null value.

Omitting the key changes the key set and therefore the canonical bytes. This is the
same class of error as E.5, and it is worth stating separately because the
languages disagree about which is natural: serde emits `null` for `Option::None` by
default, Python's `json` emits `null` for `None`, but a TypeScript object literal
with an `undefined` property drops the key entirely, and many JSON libraries offer
an omit-empty mode that would silently do the wrong thing.

Empty *collections* are a different matter and are **not** null: an empty
`scope_boundary` or `capability_set` is `[]`. Note that an empty `scope_boundary`
carries meaning — it denotes an unrestricted scope (⊤), not an absent one — so the
distinction between `[]` and `null` here is semantic as well as syntactic.

## E.8 Numbers are numbers

`sig_version` is a JSON **number** (`3` at v3), not a string (`"3"`).

Numeric values are serialized per RFC 8785 §3.2.2.3, which is ECMAScript
`Number::toString`. VAID's signed structures contain only small non-negative
integers, so no implementation should encounter the exponent-form or
round-tripping edge cases of that rule; an implementation MUST nonetheless follow
it rather than a locally-invented number format.

## E.9 Object key ordering is UTF-16 code unit ordering

Per RFC 8785 §3.2.3, object keys are sorted by **UTF-16 code unit**, not by
Unicode code point, not by byte, and not by any locale-aware collation.

For VAID's field names — all ASCII — every one of those orderings coincides, so
this rule is not exercised by any current field. It is stated because an
implementation that reaches for a locale-aware comparator (for example JavaScript's
`localeCompare`, or a `LC_COLLATE`-sensitive sort) has a latent divergence that no
present vector will catch, and that would surface the first time a field name or a
map key outside ASCII enters a signed structure.

The same section governs string escaping: the short escapes for `"`, `\`, and the
five whitespace controls; `\u00xx` for the remaining C0 range; **no** escaping of
non-ASCII characters; and lone surrogates emitted as `\udxxx`. Implementations MUST
NOT `\u`-escape non-ASCII characters — a JSON serializer configured for
ASCII-safe output (for example Python's `json.dumps` default
`ensure_ascii=True`) produces non-conforming bytes for any signed structure
containing a non-ASCII string, such as an agent class or a tenant id.

## E.10 Derived fields that affect the bytes

Two document fields are derived, not free. An implementation that stores a
different value produces a document that is internally inconsistent, and
`verify_lineage_hash` rejects it explicitly rather than incidentally.

**`lineage_hash`** is the lowercase-hex SHA-256 of a UTF-8 string built by exact
concatenation:

| Case | Material |
|---|---|
| Root (`parent_vaid` is null) | `GENESIS:{agent_id}` |
| Child | `{parent_vaid}:{agent_id}` |

The separator is a single ASCII colon, the literal is `GENESIS` in uppercase, and
the UUIDs are in canonical lowercase hyphenated form. There is no length prefix and
no delimiter escaping.

**`vaid_id` equals `agent_id`** — they are the same UUID, and the document carries
it twice.

## E.15 `trust_domain` is constrained, and compared byte-for-byte

`trust_domain` (v3, ADR-0004) names the issuing deployment. It is **required** —
never absent, never `null` — because an optional field would admit two possible
key sets and therefore two canonical forms.

The grammar is normative:

- lowercase ASCII only: `a`–`z`, `0`–`9`, `-`, `.`
- at least two labels separated by `.`; each label 1–63 bytes; no leading or
  trailing `-`
- no trailing dot, no empty labels
- 1–253 bytes total
- the final label MUST NOT be all-numeric, which excludes dotted-quad IP literals

**Comparison is byte equality. An implementation MUST NOT normalize.** This is the
rule most likely to be got wrong, because normalizing looks helpful. It is not: the
value is inside the signed bytes, so a verifier that lowercases before comparing
recomputes different canonical bytes from the ones the signer covered, and the
signature fails for a reason that has nothing to do with the key — the same failure
mode as E.6. An uppercase producer is **non-conforming**, not something to correct.

Two deliberate divergences from SPIFFE's trust-domain grammar, each with a reason:
**no underscore**, because an underscore cannot appear in a hostname and such a name
cannot be bound by the WebPKI or DNS anchor this identifier exists to be bound by;
and **no case-insensitive comparison**, for the reason above. SPIFFE also permits IP
addresses; this does not, because an IP has no controller to bind to.

Implementations SHOULD validate with explicit character checks rather than a regular
expression: JavaScript, Python and Rust regex dialects disagree about `\w`, Unicode
classes and anchoring, and this predicate must give the same answer in all three.

Special-use names (RFC 2606 / RFC 6761 — `example`, `invalid`, `localhost`, `test`,
`local`, `internal`) are **permitted by the grammar** and forbidden by policy: a
production issuer MUST NOT use one, and a verifier SHOULD refuse to bind a trust
bundle to one. The frozen vector depends on that split — see E.11.

## E.16 `kernel_key_thumbprint` is an RFC 9278 URI over an RFC 7638 thumbprint

`kernel_key_thumbprint` (v3, ADR-0004) commits the document to the key that signed
it. Also **required**.

The value is the full RFC 9278 thumbprint URI, not a bare thumbprint:

```
urn:ietf:params:oauth:jwk-thumbprint:sha-256:<base64url, unpadded>
```

The thumbprint itself is RFC 7638 over the Ed25519 public key as a JWK. For an OKP
key the required members are exactly `crv`, `kty`, `x` (RFC 8037 §2), ordered
lexicographically with no whitespace:

```json
{"crv":"Ed25519","kty":"OKP","x":"<base64url of the raw 32-byte key, unpadded>"}
```

SHA-256 that, then base64url-encode the digest **without padding**.

**This is byte-identical to what RFC 8785 (JCS) produces for the same object** — JCS
sorts keys by UTF-16 code unit, and `crv` < `kty` < `x` under every ordering. An
implementation SHOULD therefore compute it with the JCS implementation it already
uses for E.2 rather than adding a JOSE dependency or hand-rolling the member
selection, which is the part of RFC 7638 that is actually easy to get wrong.

Note the encoding asymmetry with E.4, which is deliberate and easy to trip on:
`public_key_der` is an **array of numbers**, while the key material inside the
thumbprint's JWK is **base64url**. They are different serializations of a key in the
same document, because one is VAID's own convention and the other is RFC 7638's.

Carrying the URI prefix rather than a bare thumbprint gives hash agility for free: a
later move off SHA-256 changes the value, not the field.

**A verifier MUST check that this value corresponds to the key it is verifying
against**, and reject the document if it does not. Skipping that check makes the
field decorative — a caller could verify a document against a key the document never
named, and "verified under some key we hold" is a verdict nobody can audit.

Correctness should be pinned against the **published RFC 8037 Appendix A.3
thumbprint vector**, not only against the other implementations. Three
implementations agreeing with each other is precisely the situation E.11 exists to
warn about.

## E.11 Vector coverage

Every signed structure is pinned by a frozen vector:

| Structure | Frozen vector |
|---|---|
| VAID document | `mint_v1.json` |
| `RequestAuthPayload` | `operator_pop_v1.json`, and `pathquery_v1.json` for the path convention |
| `CompletionRecord` | `completion_v1.json` |
| `MintPopPayload` | `mint_pop_v1.json` |

**The vector's `trust_domain` MUST be a reserved documentation name, and
`mint_v1.json` uses `vaid.example`.** This is a security rule, not a convention.
Every vector publishes its own private key seed so that any implementation can
reproduce the signature — which means anyone can produce validly-signed documents
under the vector's kernel key. That was harmless while the document named no
issuer. It stops being harmless the moment the document carries one: a vector
naming a real deployment would be a published, working forgery generator for that
deployment, shipped inside the standard's own test fixture. RFC 2606 reserves
`.example` for exactly this, and E.15's rule that a verifier SHOULD refuse to bind
a trust bundle to a special-use name is what makes the vector's issuer unbindable
by rule rather than by good intentions.

**Only `mint_v1.json` was re-frozen for v3.** `MintPopPayload` gains no field: the
thumbprint is issuer-side output and a holder cannot know it, so `mint_pop_v1.json`
is untouched, as are `operator_pop_v1.json`, `pathquery_v1.json` and
`completion_v1.json`. A format break should touch the smallest number of frozen
artifacts that the change actually requires.

**This was not true when revision 1 of this document was written**, and the gap is
recorded here rather than quietly closed, because how it was found and closed is
the useful part.

`MintPopPayload` — the proof-of-possession a holder signs to register a BYO key at
mint — was signed, was covered by every rule in this document, and had **no frozen
vector**. The three reference implementations agreed on it *by construction*: they
share the `vaid-pop` primitive and were written against each other. Nothing held
them to it. For exactly that one structure, this document was the only thing
pinning the bytes — the inverse of the usual relationship between a spec and its
vectors. A fourth implementation could have encoded it differently, passed every
conformance gate in the repo, and failed only later as an unexplained
proof-of-possession rejection at mint, with nothing pointing at the cause.

`mint_pop_v1.json` closes it. It was generated from the Rust implementation, and
Python and TypeScript were confirmed to reproduce its digest and signature
byte-for-byte **before** it was frozen — so it records an agreement that was
verified to exist, not one assumed from shared lineage. Freezing it while all three
were known to agree also mattered for timing: that window closes the moment one
drifts, and a vector frozen after a drift would enshrine whichever implementation
happened to generate it.

**Two things this vector pins that no other one does:**

1. **A JSON `null` inside signed bytes.** It is the root case, so `parentVaid` is
   `null`. No other frozen vector contains a null — `mint_v1`'s `parent_vaid`
   carries a UUID — so before it, nothing held an implementation to **E.7**. That
   rule was written from reading source, and was the one rule in this document with
   no artifact behind it.
2. **The registered key is the signing key.** `publicKeyDer` is the public half of
   the seed that produces the signature, unlike `mint_v1` where `public_key_der` is
   arbitrary fixed bytes independent of the kernel key. That makes the vector
   checkable end-to-end through `verify_signed_payload` — the same call the mint
   makes before issuing — so it pins the *semantics* of proof-of-possession
   (a signature FOR the key being registered) and not only its encoding.

## E.12 The `path` convention

`RequestAuthPayload.path` is the **on-the-wire request target including the query
string**, not the path alone:

```
/vaid/mint?tenant=acme&limit=10
```

This is a security rule, not a formatting one. Signing the path alone leaves the
query string outside the signature and therefore tamperable: `?limit=10` could be
rewritten to `?limit=1000000` under a signature that still verifies. It is pinned
by `pathquery_v1.json`.

The `method` is upper-cased before signing.

## E.13 What a wrong choice produces

Each row is the digest actually produced by applying that single wrong choice to
the `mint_v1.json` input, holding everything else correct. An implementation
debugging a vector failure can match its own output against this table to identify
which rule it broke.

**Every digest below was recomputed for v3.** They are computed values, not
asserted ones, so the v3 field additions changed all of them — a stale row here
would be exactly the documentation defect E.11 exists to shame.

| Rule | Choice | Resulting digest |
|---|---|---|
| — | **Correct — all rules applied** | `eef6c92fed497f5a2fc9abfc781b74da62bd54b8c66a2fcb6e7915d2d95d22f0` |
| E.3 | Document keys camelCased | `320c00f79438a359450bc6f77f2fdda17b56f17dcce71a3fd556fd234fdc0386` |
| E.4 | Byte fields as base64 strings | `35f1a0101717c37f0f81bc910a7866b31819cd96713fb90b977935138efd1e39` |
| E.4 | Byte fields as hex strings | `7622e1e253e674f7f7939ed94f81cf3ed13df04e9579556eb4e884375325885f` |
| E.5 | `kernel_signature` key deleted | `ee352179f515329b9698227565f8764a5310b141254369259c113e7441fb68cd` |
| E.5 | `kernel_signature` left as `[]` | `88d844a78690f7748d0821807c489d2e3e9ad105d1e3f9fdbbdf9d28a6ac15b1` |
| E.6 | Timestamps with milliseconds | `32e408ba68f7dfcda03b92db42386d16eba406550b6f8ba848f668c7e4547b9d` |
| E.6 | Timestamps with a `+00:00` offset | `34fbca5466cb9afa84a95c0fccbb5956d75b98784df4423242ab08abf8a67f81` |
| E.7 | `parent_vaid` key omitted (its value here is a UUID, not null — the null case is exercised by `mint_pop_v1` below) | `18b94a22485f6015ac7a8651d609b30abdeee47119eefb580adfd24994f082a2` |
| E.8 | `sig_version` as the string `"3"` | `2c3c24fb01fa6ade8ee98a96b8ae6be5b6a731580afd957b7d2b1c6ed2cc10aa` |
| E.15 | `trust_domain` uppercased — i.e. normalized rather than rejected | `c10c41523236d31b3c63eeb33f409d60bf7e81a1af72641aa00909074b6cebdf` |
| E.15 | `trust_domain` with a trailing dot | `7d6b0608ee40a8c5c74691d7017a8a4abec4dad1baa08e55dac95abac894cd83` |
| E.16 | `kernel_key_thumbprint` as a bare thumbprint, RFC 9278 URI prefix dropped | `b9840d4bc3397ffc7cfbac0fae0599df81094bd5bc5887238e9c85a599e4f187` |
| E.16 | Thumbprint base64 (standard alphabet, padded) instead of base64url unpadded | `0fec448428fb446275fbc03ba2dd5ea38d2dc35c5e059c51b19b4865c8407476` |
| E.16 | Raw public key in place of its hash — the thumbprint never computed | `81c346a15b2174adcb197c662bfbdaf88c51641395b132e4c5995d20a76503ec` |

The last three rows are the v3 additions worth dwelling on. Dropping the URI prefix
and using the wrong base64 alphabet are both what an implementer reaches for when
reading "thumbprint" and skipping RFC 9278; and putting the raw key where its hash
belongs is the shortcut that makes the document look self-verifying, which is
exactly the failure mode ADR-0004 rejects the embedded-key design over. All three
are well-formed JSON that a non-conforming implementation would sign happily.

Every wrong choice yields a digest that is wrong in the ordinary way — completely
different, immediately visible. None of them produces a near-miss, and none of them
is detectable from the document alone: each of these documents is well-formed JSON
that a non-conforming implementation would sign and consider valid.

### The same rules against `mint_pop_v1`

Two rules bite differently on `MintPopPayload`, so it gets its own table. E.3
inverts — the payload is camelCase, so *snake_case* is the error — and E.7 is
genuinely exercised for the first time, because this is the only vector whose input
contains a null. Correct digest:
`5360ff1f70ea39b3bca277301f9d0a8f9280e8530d32a405bc25b1b46dcf810c`.

| Rule | Choice | Resulting digest |
|---|---|---|
| E.3 | Payload keys snake_cased (the inverse error) | `86bdb94b8d65d4c316a4001913079e69f4bb99754a0d9268ec64dd2aed1ddb5e` |
| E.4 | `publicKeyDer` as a base64 string | `f7f7bc94f27395bbc2e51fb92b4ad53d0ff1dd9a9c3abafec12d5c9cd17cf756` |
| E.7 | `parentVaid` key omitted instead of null | `b4d7fdb1afd59ce9dabca67998aaf1517f6ef9fce89bec9263bc7da65cb66eda` |
| E.7 | `parentVaid` as the empty string `""` | `5383b00aedf24e4088596914b9fe5a7bbd0d732d8d2f26814f9c0e359480e618` |

The last row is worth its own line. An empty string is the substitution a
statically-typed implementation reaches for when its `parentVaid` field is a
non-nullable string — it is not obviously wrong, it round-trips, and it produces a
digest that differs from the correct one only in the way every other error does.
`null` and `""` are different values, and only `null` conforms.

## E.14 Conformance

An implementation conforms to this document if and only if it reproduces all five
frozen vectors byte-for-byte (`mint_v1.json` is at v3; the other four are unchanged
by ADR-0004 and were NOT re-frozen) — both the digest and, from the given seed, the
Ed25519 signature. The vectors are the test; this document is the reason the test
passes.

Vector locations (all copies are byte-identical, enforced by a CI `cmp` in every
conformance-drift job):

| Vector | Rust | Python | TypeScript |
|---|---|---|---|
| `mint_v1.json` | `crates/vaid-mint/tests/vectors/` | `python/vaid-mint/vaid_mint/vectors/` | `typescript/vaid-mint/vectors/` |
| `operator_pop_v1.json` | `crates/vaid-client/tests/vectors/` | `python/vaid-pop/vaid_pop/vectors/` | `typescript/vaid-pop/vectors/`, `typescript/vaid-client/vectors/` |
| `pathquery_v1.json` | `crates/vaid-client/tests/vectors/` | `python/vaid-langchain/vaid_langchain/vectors/` | `typescript/vaid-client/vectors/` |
| `completion_v1.json` | `crates/vaid-pop/tests/vectors/` | `python/vaid-pop/vaid_pop/vectors/` | `typescript/vaid-pop/vectors/` |
| `mint_pop_v1.json` | `crates/vaid-mint/tests/vectors/` | `python/vaid-mint/vaid_mint/vectors/` | `typescript/vaid-mint/vectors/` |

A change to any rule in this document is a change to the canonical bytes, breaks
every existing signature, and requires a standard version bump — not a patch
release. See `CONTRIBUTING.md`.
