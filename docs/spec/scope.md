# Scope containment

**Prose specification. VAID. NORMATIVE.**
Implements ADR-0005 and ADR-0009. Revision 2, 11 October 2026.

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

`scope_boundary` is a list of **typed boundary entries**. Each entry carries a
`kind`, naming the sort of boundary it is, and a `value`, whose type and meaning
are fixed by that kind. v1 of the typed format defines exactly one kind,
`prefix`, whose semantics are the resource-prefix containment of S.3 and are
unchanged from revision 1. Containment answers one question:

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

That requirement now carries a second consequence, stated in S.10: a verifier
that cannot READ a boundary cannot reproduce the mint's verdict over it either,
so it must refuse rather than approximate.

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

## S.3 The containment rule for the `prefix` kind (normative)

An empty boundary **list** is unrestricted (⊤): it contains every resource. This is
how "no restriction" is expressed; it is not the same as a boundary containing an
empty string.

Otherwise, boundary `B` contains resource `R` iff **at least one** entry of `B` is
a `prefix` entry whose `value` contains `R` by the clauses below, and no entry of
`B` is of an unrecognised kind (S.10). Throughout this section `P` denotes the
`value` of a `prefix` entry. A single `P` contains `R` iff any of:

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
- reproduce every verdict in `scope_v1.json` and `scope_kinds_v1.json`;
- state its recognised kinds in exactly ONE place, and consult that one place from
  both the matcher and the standing verdict. Two copies of the registry is how a
  kind gets recognised by one and not the other, which is the fail-closed rule of
  S.10 failing open;
- apply the SAME predicate to mint-time attenuation and to chain verification. A
  single shared matcher is the only way to guarantee this; two copies of the rule is
  how they drift.

A conforming implementation MUST NOT make containment depend on configuration,
locale, normalisation, or case folding. Scope entries are compared by exact byte
equality of their segments.

## S.8 The wire format (normative)

`scope_boundary` is a JSON **array**. Each element is a JSON **object** with
exactly two members:

```json
{ "kind": "prefix", "value": "orders/123/" }
```

- `kind` MUST be present and MUST be a non-empty JSON string. It names the sort of
  boundary. v1 of the typed format defines exactly one value, `prefix`.
- `value` MUST be present. Its JSON type is fixed by the `kind`: for `prefix` it
  MUST be a JSON string.
- An entry MUST carry no other member. See S.11 for why this is stricter than the
  document-level rule.

An entry that violates any of the above makes the document **unparseable**: it is
not a VAID. This is the same class of fault as [`encoding.md`](encoding.md) E.5
and E.7a, and it is the class the bare-string form of revision 1 now falls into.
There is no dual acceptance and no per-entry fallback: a single malformed entry is
a malformed boundary.

An empty array is unrestricted, exactly as in revision 1, and remains distinct
from `null` (E.6). A boundary that is `null`, or a JSON object rather than an
array, is not a boundary.

Array order is not semantically significant. It is nevertheless significant to the
canonical bytes, because RFC 8785 sorts object members and does not sort array
elements. A producer that reorders entries produces a different document, as it
already did in revision 1.

Duplicate entries are permitted and are semantically idempotent. Rejecting them
would be a new validation with no safety payoff, and E.7a already covers the
dangerous duplicate, which is a repeated member name.

## S.9 `scope_boundary` is a list, not a single entry

Two shapes were available and the list was chosen.

A single `{kind, value}` object would be smaller, and for a one-kind format it
would be sufficient. It was rejected on two counts. It cannot express two disjoint
resource trees, and `["t/research", "t/legal"]` was expressible in revision 1 and
is in use, so collapsing the shape would be a second, unrelated narrowing bundled
into a typing change. And it has no empty form: unrestricted would have to be
`null`, which contradicts E.6's rule that an empty collection is `[]` and never
`null`, and here that rule is semantic rather than cosmetic because `[]` is how
unrestricted is said.

The list also keeps the quantifier where revision 1 put it. Within the `prefix`
kind, entries are a **union**: at least one must contain the resource. That is the
rule a reader of S.3 already has, and the typing does not move it.

## S.10 Unrecognised kinds are refused (normative)

A verifier MUST refuse a credential whose `scope_boundary` carries an entry of a
kind it does not recognise. It MUST NOT skip the entry, MUST NOT treat it as
vacuous, and MUST NOT report containment or attenuation computed from the entries
it could read.

This is the rule that makes future kinds additive. Because an old verifier refuses
a kind it has never heard of, a new kind can be introduced in a minor version
without any old verifier silently granting authority it cannot evaluate. The
alternative, which is ignoring what you cannot read, makes every future kind a
2.0: an entry meant to **narrow** authority would be dropped by exactly the
verifiers that most need it.

**An unreadable entry refuses the whole boundary, not merely itself.** The natural
implementation of a union is "at least one entry matched", and that implementation
returns true for a boundary holding one satisfied `prefix` entry plus one entry of
an unrecognised kind: it finds the match and never reaches the entry it cannot
read. An unrecognised kind can only ever narrow what the signer meant, so skipping
it grants authority the signer withheld.

An unrecognised kind is **not** a parse fault. The entry's shape is well formed
and only its `kind` is unknown, so the document parses, its signature is verified,
and the refusal is a verdict over an authentic document. The distinction is
load-bearing in both directions:

- Collapsing it into unparseable would report an authentic, correctly signed,
  future-version credential as malformed bytes. That is the wrong accusation, and
  a holder cannot act on it.
- Collapsing it into a scope escalation would accuse a delegation of being wider
  than its parent when the verifier has in fact formed no opinion about its width.

The standing verdict is `unknown_scope_kind` and it fails closed. It is evaluated
**after** the kernel signature and after expiry, and **before** revocation: the
complaint is only meaningful about a document shown to be authentic, expiry is the
cheaper and more actionable fact where both hold, and a credential that can never
be used should not cost a revocation lookup. Inserting it there changes no
pre-existing verdict, because no document in any existing vector carries an
unrecognised kind.

The attenuation verdict is the same name on its own surface, and is distinct from
`scope_escalation` for the reason above. Both sides of a hop are checked: an
unreadable CHILD boundary cannot be shown to be within anything, and an unreadable
PARENT boundary bounds nothing the verifier can compute, so no child is provably
within it.

A verifier MUST NOT inspect the `value` of an entry whose `kind` it does not
recognise. It does not know what type a later kind's value takes, and validating
it would mean refusing an authentic future document for a reason the verifier
invented.

## S.11 An entry carries no member beyond `kind` and `value`

ADR-0006 requires a verifier to **preserve** unknown members of the document it
was presented, rather than dropping them. S.8 requires it to **refuse** an unknown
member inside a boundary entry. The asymmetry is deliberate and it is the whole
mechanism of this revision.

At document level an unknown member is outside every predicate the verifier
computes: the verifier reads named members, and preserving the rest is what keeps
the canonical bytes faithful to what was signed. Inside a boundary entry there is
no such outside. Every member of an entry is part of the authority that entry
states, so a verifier that ignored `{"kind": "prefix", "value": "a", "max": 5}`
would compute a boundary strictly wider than the one the signer committed to, and
would do it silently.

**This is why a condition on an action is a scope kind and not a member.** A new
kind is refused by old verifiers by S.10. A new member alongside a known kind is
refused by S.8. A new **top-level document** member would be preserved and
ignored, by ADR-0006, which is the one remaining way to write a constraint that
old verifiers do not see. Producers MUST NOT express a constraint on authority as
a top-level document member. That exposure is noted here rather than closed,
because closing it means revisiting ADR-0006 and is not in this revision.

## S.12 Scope is where, capabilities are what

The two members divide as follows, and the division is normative.

- `scope_boundary` is the **resource** boundary. It answers *where* authority
  reaches. It is hierarchical, it is matched by containment, and it is the member
  that carries conditions.
- `capability_set` is the set of **permitted actions**. It answers *what* may be
  done. It is matched by exact string equality and nothing else: there is no
  hierarchy, no prefixing, and no containment among capabilities.

A condition that constrains an action, such as a maximum amount, a rate, or a
qualifier on which instances of an action are permitted, is a **future scope
kind**. It is not a new capability and it is not a decoration on an existing one.

The reason is S.10 set against exact matching. A capability is compared by
equality, so a producer that wrote `payments.transfer<=100` where a verifier
expects `payments.transfer` would simply not hold the capability, and one that
wrote `payments.transfer` while meaning the limited form would hold the unlimited
one. Encoding a condition in a capability string therefore either fails closed by
accident or fails open by accident, depending only on which side wrote it, and
neither outcome is a decision anybody made. Scope kinds have a refusal rule;
capability strings have none, and cannot be given one without making
`capability_set` a typed member too.

## S.13 Rationale, and what this costs

**What this buys.** A single reserved extension point with a refusal rule. Before
this revision, `scope_boundary` was a list of opaque strings, so every future
boundary semantics had exactly two homes: overload the string grammar, which no
verifier can police and which S.4 has already shown goes wrong silently in all
three implementations at once, or add a document member, which old verifiers
preserve and ignore. Typing the entries and refusing unknown kinds replaces both
with one mechanism whose failure mode is a refusal.

**What this costs.** It is a breaking wire change. The canonical bytes of every
document with a non-empty `scope_boundary` move, and with them the frozen digests
of `mint_v1`, `mint_pop_v1`, `chain_v1`, `chain_expiry_v1`, `attestation_v1` and
`roundtrip_v1`. Three signed structures carry the member and all three are
affected: the VAID document, `MintPopPayload` (as `scopeBoundary`), and the
detached consent attestation. Credentials have a one hour default TTL, so the
in-flight population expires on its own and no migration window is needed beyond
that.

**`sig_version` moves to 4.** ADR-0010 makes `sig_version` the discriminant for
the whole signing scheme including the document's required member set, and states
the test directly: if two accepted values do not require the same members, one is
a downgrade of the other and the pair is forbidden. A v3 document's boundary
entries are strings and a v4 document's are objects, so dual acceptance is
forbidden, which is the same conclusion as "no legacy acceptance of the
bare-string form" reached from the other end.

The bump does **not** change which reason either side reports, and it is worth
being exact about that rather than claiming a benefit it does not deliver. A v3
credential presented to a v4 verifier is refused as `unparseable`, because the
bare-string boundary fails the shape gate of S.8 before `sig_version` is ever
read; a v4 credential presented to a v3 verifier is refused as `unparseable`
there for the mirror-image reason. `verdict_v1.json` pins the first of those
directly, with a real v3 credential carried verbatim. What the bump buys is that
dual acceptance is formally forbidden rather than merely unwise, which is what a
later verifier wanting to accept both would otherwise have no rule against.

**What this deliberately does not change.** The containment rule of S.3, the
separator set of S.2, and the segment constraint of S.6 are all carried over
exactly. S.6's unenforced segment constraint stays unenforced. Enforcing it here
would be a third change in a release that already carries two, and the argument of
S.6 is unaffected by the typing.

**Constraints on the next revision, not normative here.** This format has one
kind, so no code path in this revision can observe two. The following are
therefore recorded as constraints on whoever adds kind number two, and are
deliberately not implemented: writing unreachable code for them would ship an
untested branch that reads as coverage.

1. Within a kind, entries are a union. **Across kinds they must be an
   intersection**: a request must satisfy at least one entry of every kind
   present. Union across kinds would mean a boundary of a prefix and an amount cap
   is satisfied by a request that honours either, which is wider than either, and
   it is the reading a naive extension of S.3 produces.
2. A kind present in a child boundary and absent from a non-empty parent boundary
   is an escalation, not a free grant.
3. A kind whose boundary is not resource-shaped needs its own containment rule.
   The `prefix` kind is decidable with one predicate because a boundary and a
   resource are the same shape for it, which is why a child entry can be fed to
   the matcher as if it were a resource. That projection does not generalise.
4. A new kind is a new `sig_version` value only if it changes the required member
   set. Adding a recognised `kind` value does not change the member set, so it is
   a minor version with no `sig_version` bump, and old verifiers refuse it by
   S.10. That is the additivity this revision exists to buy.
