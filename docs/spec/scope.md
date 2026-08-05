# Scope containment

**Prose specification. VAID. NORMATIVE.**
Implements ADR-0005. Revision 1, 5 August 2026.

Terminology follows the repo: a **VAID** is the document (`Vaid`); **scope boundary**
is its `scope_boundary` list; **attenuation** is the `child ⊆ parent` check performed
at mint and re-performed by a third party at chain verification.

---

> **Companion documents.** [`encoding.md`](encoding.md) specifies the canonical bytes.
> This document specifies a **predicate over** those bytes — containment is computed
> from a document and never appears inside one. [`revocation.md`](revocation.md) takes
> the opposite posture to this one: it specifies where conformance *stops*. Scope
> containment is inside the surface (ADR-0001 §2 defines conformance over "mint,
> attenuation, and verification"), and until 0.5.0 no vector policed it.

## S.1 What this decides

`scope_boundary` is a list of scope entries. Containment answers one question:

> Is resource `R` within boundary `B`?

That single predicate decides two things, and it must give the same answer to both:

1. **Mint-time attenuation.** A child VAID may be issued under a parent only if every
   entry of the child's `scope_boundary` is contained in the parent's.
2. **Third-party chain verification** (ADR-0003). A verifier holding a presented
   chain re-checks containment at every hop, with no access to the mint.

Because (2) exists, containment MUST be computable from the documents alone. Nothing
in this rule may depend on deployment configuration, out-of-band knowledge, or which
implementation is asking. A verifier that cannot reproduce the mint's verdict is the
failure this specification exists to prevent.

## S.2 Separators (normative)

The **reserved hierarchy separators** are exactly:

```
/    U+002F SOLIDUS
.    U+002E FULL STOP
```

Both are normative. Both are ALWAYS honoured, by every conforming implementation, in
every deployment. The set is closed: an implementation MUST NOT add, remove, or
configure separators.

A **segment** is a maximal run of characters containing no separator. A scope entry
is a separator-delimited sequence of segments.

> **A scope segment MUST NOT contain a separator.**

This constraint is what makes honouring both separators safe rather than widening,
and it is the reason the set is fixed here instead of being a property of a
deployment. See S.5.

Producers MUST NOT emit a scope entry whose intended segment contains `/` or `.`. An
entry such as `svc/api.internal` is the three-segment path `svc`, `api`, `internal` —
it is **not** a two-segment path whose second segment is literally `api.internal`. If
an implementation needs a literal separator inside a name, it MUST encode it (for
example percent-encoding) before placing it in a scope entry. This specification
defines no escaping mechanism; introducing one would change the canonical bytes of
`scope_boundary` and is therefore a future versioned change, not an implementation
choice.

## S.3 The containment rule (normative)

An empty boundary **list** is unrestricted (⊤): it contains every resource. This is
how "no restriction" is expressed; it is not the same as a boundary containing an
empty string.

Otherwise, boundary `B` contains resource `R` iff **at least one** entry `P` of `B`
contains `R`. A single entry `P` contains `R` iff any of:

1. `R` is equal to `P`; or
2. `P` ends with a separator, and `R` starts with `P`; or
3. `R` starts with `P` followed by a separator.

An empty entry (`""`) contains every resource. It is unreachable from a well-formed
boundary — ⊤ is expressed by the empty list — and is specified only so the rule is
total.

**Bare prefix matching is NOT containment.** `R.startsWith(P)` is not the rule and
MUST NOT be used. See S.4.

Implementations MUST express this rule using only equality, `starts_with`,
`ends_with` and concatenation. Character or index arithmetic MUST NOT be used, so
that Rust (bytes), Python (code points) and TypeScript (UTF-16) cannot diverge at a
multi-byte boundary.

### Worked cases

| Boundary entry | Resource | Contained | Why |
|---|---|---|---|
| `data.governance` | `data.governance` | yes | clause 1 |
| `data.governance` | `data.governance.reports` | yes | clause 3, `.` |
| `data.governance` | `data.governance-secret` | **no** | sibling; no separator at the boundary |
| `data.governance` | `data.governanceX` | **no** | bare textual prefix |
| `t/research` | `t/research/sub` | yes | clause 3, `/` |
| `t/research` | `t/research-secret` | **no** | sibling |
| `a/b` | `a/b.c` | yes | clause 3 — `.` is a separator by S.2 |
| `a/b` | `a/bc` | **no** | no separator at the boundary |
| `data.` | `data.x` | yes | clause 2, trailing separator |
| `data.` | `datax` | **no** | clause 2 requires the prefix, separator included |
| `data` | `database` | **no** | the regression class in one line |

The frozen vector `scope_v1.json` pins these and more. It carries no digest and no
signature, because there are no bytes to pin — only verdicts.

## S.4 What this replaces, and why it is a security fix

Before 0.5.0 all three reference implementations used bare prefix matching:

```
contained(P, R)  ==  R.startsWith(P)
```

Under that rule `data.governance` contained `data.governance-secret` — a **sibling**,
sharing a textual prefix and nothing else. Because the same predicate decides both
uses in S.1, the consequence was not cosmetic:

- a child COULD be minted with authority its parent never held; and
- a third-party verifier WOULD confirm that delegation as legitimate.

That is privilege escalation across a delegation boundary, reachable by any holder of
a parent VAID, and it was reproduced identically in Rust, Python and TypeScript. Three
mirrored ports of the same wrong rule agreed with each other perfectly, which is
exactly why cross-implementation agreement is not a substitute for a vector.

**The rule in S.3 is strictly narrower than bare prefix matching.** It denies cases
the old rule allowed and permits nothing the old rule denied. This is verified
exhaustively rather than argued: `the_rule_is_strictly_narrower_than_bare_prefix_matching`
enumerates a generated corpus and fails on any widening. Consequently:

- no previously-rejected delegation becomes possible;
- no document's bytes change, and no existing frozen vector's verdict changes
  (`chain_v1.json` was checked specifically: its scopes are properly dot-nested and
  both rules accept every hop);
- the only behavioural change is that some delegations that used to succeed now fail
  — which is the fix.

## S.5 Why both separators, rather than one

Three options were available. Two are unsafe for an open standard.

**A single normative separator** breaks real deployments in opposite directions: a
`.`-only rule stops `t/research` containing `t/research/sub`; a `/`-only rule stops
`data.governance` containing `data.governance.reports`. Either choice forces existing
producers to migrate their entire scope vocabulary, and the standard has no basis for
preferring one convention.

**A deployment-configurable separator set** is worse, and is ruled out by S.1. Under
ADR-0003 a third party recomputes containment from a presented chain. If the set were
deployment-local, that verifier could not reproduce the mint's verdict — it would not
know which rule the mint applied. Containment would stop being decidable from the
documents, which is the property the whole attenuation-verification design rests on.

**Both separators, with segments constrained (chosen).** The danger of honouring both
is that an implementer treating `/` as their hierarchy separator and `.` as an
ordinary character would find `data/user` containing `data/user.admin` — the same
sibling-capture bug in the other separator. S.2 removes that danger at its root by
**reserving both characters**, so `data/user.admin` is unambiguously the path `data`,
`user`, `admin` and the containment is correct rather than accidental.

The substrate implementation this rule was derived from reached the same matcher by a
different argument: that its producers each use a single grammar, so mixed separators
are unreachable in practice. **That argument does not travel to an open standard**,
which has no control over its implementers. This specification therefore imposes the
constraint rather than assuming it. The rule is the same; the justification is not,
and the justification is what an implementer needs.

## S.6 Enforcement of the segment constraint

The segment constraint in S.2 is **normative on producers** and is **NOT enforced by
the matcher** in this revision.

This is deliberate and bounded. Enforcing it would mean rejecting documents that
0.5.0 accepts — a second breaking change, bundled into a release whose purpose is a
security fix. The matcher is strictly narrower with or without enforcement (S.4), so
0.5.0 is a strict improvement on its own.

A future revision SHOULD add validation at mint, rejecting a scope entry that a
producer intended to contain a literal separator. Until then, an implementation MAY
validate scope entries at its own boundary, and a producer that violates S.2 gets a
containment result that follows S.3 exactly — which will not be the one it intended.

## S.7 Conformance

A conforming implementation MUST:

- honour exactly the separators in S.2;
- implement the rule in S.3, expressed without character indexing;
- reproduce every verdict in `scope_v1.json`;
- apply the SAME predicate to mint-time attenuation and to chain verification. A
  single shared matcher is the only way to guarantee this; two copies of the rule is
  how they drift.

A conforming implementation MUST NOT make containment depend on configuration,
locale, normalisation, or case folding. Scope entries are compared by exact byte
equality of their segments.
