# Detached consent attestation

**Status:** implemented, format **FROZEN** at `att_version` 1 (`attestation_v1.json`)
**Related:** ADR-0003 (attenuation via detached chain), ADR-0004 (v3 issuer
identifier and kernel key thumbprint), [revocation.md](revocation.md) R.4–R.5,
[encoding.md](encoding.md) E.6

---

## C.1 What it is

A **consent attestation** is a parent issuer's signed statement that a particular
child may hold particular authority under a particular parent. It is a separate
signed object, presented alongside a chain — not a field in any VAID document.

It exists because nothing in a VAID document proves the parent consented to the
delegation. `mint_child` enforces consent in-process against an authenticated parent
principal, but that enforcement is a property of the mint's *session*: none of it
lands in the child document, which carries only a `parent_vaid` its own issuer chose
and signed with its own kernel key.

Under a single kernel key that is invisible and sound — one mint is the only thing
that can sign, and it enforced consent before signing. Across kernel keys it is not:
an issuer B can mint a document naming issuer A's root `vaid_id` as `parent_vaid`,
with authority inside A's, and sign it with B's key. B needs only to *know* A's root
`vaid_id`, which every chain presentation discloses to its verifier.

## C.2 Whose fields are whose

The object names **two** parties, and the top-level fields belong to the
**attesting parent issuer** — not to the attestation and not to the child. Stated
explicitly, because `trust_domain` and `kernel_key_thumbprint` unprefixed read as
"the attestation's own" to anyone meeting the format for the first time, and the
`child_` prefix on the other pair is too thin a thing to carry the distinction.

| Field | Belongs to | Meaning |
|---|---|---|
| `trust_domain` | **the attesting parent issuer** | the domain of the party giving consent. MUST equal the **parent document's** `trust_domain`. |
| `kernel_key_thumbprint` | **the attesting parent issuer** | the key that signed this attestation. MUST equal the **parent document's** `kernel_key_thumbprint`, and the signature MUST verify under the key it resolves to. |
| `parent_vaid` | the parent | which delegation is being consented to, upper end |
| `child_vaid` | the child | which delegation is being consented to, lower end |
| `child_trust_domain` | **what is authorized** | the domain the parent consents to the child claiming. MUST equal the **child document's**. |
| `child_tenant_id` | **what is authorized** | the tenant the parent consents to the child claiming. MUST equal the **child document's**. |
| `scope_boundary`, `capability_set` | **what is authorized** | the ceiling on the child's authority |

So the whole object reads:

> *The issuer in `trust_domain`, holding the key committed to by
> `kernel_key_thumbprint` — which is the issuer that minted `parent_vaid` —
> consents to `child_vaid`, claiming `child_trust_domain`/`child_tenant_id`,
> holding at most `scope_boundary`/`capability_set` under `parent_vaid`.*

The unprefixed pair being the **parent's** is what makes C.7 step 2 meaningful:
the party consenting must be the party that issued the parent. If those fields
were the attestation's own, any accepted key could consent on any parent's behalf,
which is the forgery the cross-key requirement exists to stop, moved one level up.

The reference signer never takes them as parameters — it stamps its own trust
domain and derives the thumbprint from the key about to sign — so an attestation
cannot name a key or a domain other than the one signing it.

## C.3 It is additive

No VAID document changes. No new field inside `sig_version` 3, no `mint_v1`
re-freeze. `att_version` is the attestation's own discriminant and is deliberately
independent of `sig_version`: bumping one must not imply the other.

## C.4 Canonicalization

Identical discipline to the VAID document: serialize, force `signature` to JSON
`null` (a signature cannot cover its own value), canonicalize per RFC 8785 (JCS),
SHA-256, sign that digest with the kernel key. Nulling rather than removing means
the digest of an unsigned attestation and of the same attestation once signed are
identical.

Timestamps follow the E.6 profile: whole-second RFC 3339 in UTC with a literal `Z`.

## C.5 Validity window

An attestation carries `issued_at` and `expires_at`. **`expires_at` is REQUIRED and
has no default**, in the format and in every reference signer. Consent that outlives
its purpose must be somebody's stated intention, never a value that arrived by
omission.

Verification against an instant `now`:

| Condition | Result |
|---|---|
| `expires_at <= issued_at` | never current — a window satisfiable at no instant |
| either timestamp unparseable | never current |
| `now > expires_at` | lapsed |
| `now < issued_at - MINT_POP_FRESHNESS_SECS` | not yet valid |
| otherwise | current |

The two edges are treated asymmetrically **on purpose**:

- **Expiry is exact — no grace.** Being generous at the end of a validity window is
  being generous in the one direction that extends unauthorized access. The closing
  instant itself is inside the window; the instant after it is not.
- **The opening edge tolerates clock skew**, by `MINT_POP_FRESHNESS_SECS` — the
  same allowance the mint already makes for a proof-of-possession, reused rather
  than reinvented. A verifier whose clock is a few seconds behind the attesting
  issuer should not reject consent that is merely young.

An unparseable timestamp is **never current**. A timestamp that cannot be read is
not a timestamp that can be shown to be current; the opposite reading is the
`Date.parse` → `NaN` fail-open that `isExpired` once had, and it is not repeated
here.

Because the verdict depends on `now`, verification takes the instant explicitly.
A system-clock convenience wrapper exists, but anything needing a reproducible
verdict — a conformance vector, a boundary test, replaying a historical decision —
must pass an instant.

## C.6 A time bound is not withdrawal

**This is the section that must not be dropped.**

`expires_at` bounds how long stale consent remains usable. **It does not let a
parent withdraw consent.** An organisation that changes its mind *inside* the window
has no mechanism here: the attestation stays valid until it lapses.

Retracting consent inside its window requires **durable revocation**, and **durable
revocation does not exist in this implementation.** The reference stores are
in-memory and do not survive restart ([revocation.md](revocation.md) R.4.6). Until
that changes, the honest statement is:

> Consent is time-bounded, not revocable.

Choosing a short `expires_at` is the whole of the mitigation. A long window is a
long window.

This is the same distinction R.5 draws for VAID time-to-live, and it is restated
here for the same reason: a validity window is exactly the kind of field that gets
read as solving withdrawal when it does not. An implementation, a deployment guide,
or any public material that describes `expires_at` as consent revocation is wrong,
and the error is the one R.5 exists to prevent.

## C.7 What verification checks

For a hop whose parent and child were signed by **different** kernel keys, a valid
attestation is required. For a hop signed by the **same** key none is required or
consulted: the single issuer enforced consent at mint time.

Required of the attestation, in order:

1. present for exactly this `(parent_vaid, child_vaid)` pair;
2. `kernel_key_thumbprint` and `trust_domain` equal to the **parent document's** —
   the party consenting must be the party that issued the parent;
3. signature valid under the key that thumbprint resolves to;
4. **current at `now`** (C.5);
5. `child_trust_domain` / `child_tenant_id` equal to the child document's — consent
   must name the identity the child actually claims;
6. the child's authority contained by the attestation's, and the attestation's
   contained by the parent's — a parent cannot consent to more than it holds.

Verdicts: 1–3 fail as **authenticity** failures; 4 is its own verdict
(`ConsentExpired`); 5–6 fail as **authority** failures. Only a chain with every hop
satisfied verifies.

`ConsentExpired` is kept distinct from the other failures deliberately. An expired
attestation is not forged — the parent really did sign it — and the child did not
overreach. The operational difference is the point: it says *renew the attestation*,
where the others say *you were never authorized*.

## C.8 Replayed and absent consent share a verdict

Attestations are indexed by the hop they name, so one minted for a different
delegation is not found rather than rejected — there is no rejection path, and so no
rejection path to get wrong. The cost is that replayed consent and absent consent
produce the same verdict. Both are safe; neither can verify. But the verdict alone
does not distinguish them, and diagnosing "I presented consent and it was ignored"
means comparing the attestation's own pair against the hop by hand.

## C.9 What is deliberately not checked

**Document expiry.** Chain verification has never consulted the `expires_at` of the
VAID documents themselves, and adding attestation expiry did not change that. An
attestation may outlive the parent VAID it delegates from. Whether that should
change is a separate decision and is not made here.

**Revocation.** Neither of documents nor of attestations. See R.4.

## C.10 Conformance

`att_version` 1 is **frozen** as `attestation_v1.json`, vendored byte-identically
into all three implementations and gated the same way every other vector is: CI
`cmp`s the three copies, then re-runs each language's gate against its own copy, so
Rust == Python == TypeScript follows without a fourth comparison.

The vector freezes the field set, the canonicalization and the signature over it. It
deliberately uses **different** trust domains for the attesting issuer (`a.example`)
and the authorized child (`b.example`), so the C.2 distinction is visible in the
frozen bytes and a future change that conflated the two fails the gate rather than
passing quietly.

Freezing this re-freezes nothing else. The attestation is a separate signed object:
`mint_v1.json`, `mint_pop_v1.json` and `chain_v1.json` are untouched, and
`sig_version` is unchanged.

`scripts/attestation_byte_agreement.sh` is retained as a fast local three-way check.
It is no longer the evidence of agreement — the vector and its gates are — but it
remains the quickest way to see a divergence while editing.
