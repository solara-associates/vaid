# ADR-0009: `scope_boundary` entries are typed, and an unrecognised kind is refused

**Status:** Accepted
**Date:** 11 October 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Related:** ADR-0005 (segment-bounded scope containment, whose rule this carries
over unchanged), ADR-0006 (verify over presented bytes, whose unknown-member
posture this deliberately inverts inside an entry), ADR-0008 (a second signature
algorithm is a new `sig_version` value), `docs/spec/scope.md` revision 2,
`scope_kinds_v1.json`

---

## Context

`scope_boundary` has been a list of opaque strings since v2. ADR-0005 fixed what
containment MEANS for such a string and left the shape alone: a boundary entry is
a resource prefix, matched segment-wise, and that is all a boundary can say.

The question this ADR answers is what happens the first time a boundary needs to
say something else. Two kinds of constraint are already foreseeable, and both are
narrowing rather than widening: a limit on an amount, and a qualifier on which
instances of an action are permitted. Under the string form there were exactly two
places to put either one, and both are wrong.

**Overload the string grammar.** Write `payments/transfer<=100` and let producers
and verifiers agree on a convention. No verifier can police a convention, and
ADR-0005 is the evidence: three reference implementations shared one wrong reading
of a string boundary, agreed with each other perfectly, and nothing in the suite
was asking. A grammar inside a string is a second specification with no gate on
it.

**Add a document member.** Write `"amount_limit": 100` alongside
`scope_boundary`. This is worse, and it is worse in the one direction that
matters. ADR-0006 requires a verifier to PRESERVE members it does not recognise,
so that it canonicalizes what it was presented. A verifier that preserves and
ignores `amount_limit` authorises the unlimited action. The constraint is inside
the signed bytes, the signature verifies, and the limit does nothing. Every old
verifier in the field fails open, silently, on exactly the field added to make
them stricter.

So the shape has to change, and the change has to come with a rule that makes an
old verifier REFUSE rather than ignore.

## Decision

**1. Each `scope_boundary` entry becomes an object carrying a `kind` and a
`value`.**

```json
"scope_boundary": [{ "kind": "prefix", "value": "orders/123/" }]
```

`kind` names the sort of boundary; the type and meaning of `value` are fixed by
the kind. The entry carries no other member.

**2. v1 of the typed format defines exactly one kind, `prefix`.** Its semantics
are ADR-0005's containment rule, unchanged, applied to the entry's `value`. No
separator changes, no clause changes, no change to the worked cases. The typing
changes the envelope and not the rule, which is what keeps the security fix of
ADR-0005 intact and independently reviewable.

**3. A verifier MUST refuse a credential carrying a kind it does not recognise,
and MUST NOT report a verdict computed from the entries it could read.**

This is the decision the rest of it exists for. A new kind becomes additive
precisely because old verifiers refuse it: a constraint that narrows authority
cannot be dropped by the verifiers that most need it, and a new kind therefore
arrives as a minor version rather than as a 2.0.

The refusal is a verdict over an authentic document (`unknown_scope_kind`), not a
parse failure. An entry of an unknown kind is well formed; only its `kind` is
unknown. Reporting it as malformed bytes would accuse a correctly signed
future-version credential of being forged, which is both false and unactionable.

**4. An unreadable entry refuses the WHOLE boundary.** The natural implementation
of a union is "at least one entry matched", and that implementation returns true
for a boundary of one satisfied `prefix` entry plus one unreadable entry: it finds
the match and never reaches what it cannot read. Since an unrecognised kind can
only narrow, skipping it grants authority the signer withheld.

**5. An entry carries no member beyond `kind` and `value`, and that is the
deliberate inverse of ADR-0006.** At document level an unknown member sits outside
every predicate the verifier computes, and preserving it is what keeps the
canonical bytes faithful. Inside an entry there is no outside: every member is part
of the authority the entry states. A verifier ignoring
`{"kind": "prefix", "value": "a", "max": 5}` computes a wider boundary than was
signed. Refusing the entry is the only resolution that cannot do that.

**6. Scope is where; capabilities are what.** `scope_boundary` is the resource
boundary and the member that carries conditions. `capability_set` is the set of
permitted actions, matched by exact string equality and nothing else. A condition
on an action is a future scope KIND, never a new capability and never a decoration
on an existing one, because a capability compared by equality either fails closed
by accident or fails open by accident depending only on which side wrote it.

**7. `sig_version` moves to 4, and there is no legacy acceptance.** ADR-0008 makes
`sig_version` the discriminant for the whole signing scheme including the required
member set, and gives the test: if two accepted values do not require the same
members, one is a downgrade of the other and the pair is forbidden. A v3 boundary's
entries are strings and a v4 boundary's are objects, so `{3, 4}` is forbidden.
Credentials carry a one hour default TTL, so the in-flight population expires on
its own; this is a breaking wire change, taken pre-1.0 on purpose.

**8. `scope_boundary` stays a LIST.** See `docs/spec/scope.md` S.9. A single
object cannot express two disjoint resource trees, which is expressible today and
in use, and it has no empty form, so unrestricted would have to be `null` against
E.6's rule that an empty collection is `[]`.

## What this costs

The canonical bytes of every document with a non-empty boundary move. Three signed
structures carry the member and all three are affected: the VAID document,
`MintPopPayload` (as `scopeBoundary`), and the detached consent attestation. Six
frozen vectors are re-frozen: `mint_v1`, `mint_pop_v1`, `chain_v1`,
`chain_expiry_v1`, `attestation_v1` and `roundtrip_v1`. `verdict_v1` and `scope_v1`
are re-issued because their case tables are written in the old wire form, and
`scope_kinds_v1` is new.

`chain_expiry_v1`, `roundtrip_v1` and `verdict_v1` had no generator before this
change and could only have been re-frozen by hand, over 18, 4 and 32 signed
documents respectively. Generators were written for all three rather than editing
signatures into agreement with bytes nobody recomputed. The `verdict_v1` generator
is the interesting one: its case table was DERIVED from the v3 vector by searching,
per case, for the subset of that case's difference from the base whose signature
over the resulting bytes reproduced the committed signature exactly. 31 of its 32
cases were reproduced byte for byte that way, which is what makes the pre-sign
versus post-sign split in that table a reading rather than a guess.

One thing the bump does NOT buy, stated because it is the obvious thing to claim:
it does not improve the reason either side reports across the break. A v3
credential presented to a v4 verifier is `unparseable`, because the bare-string
boundary fails the shape gate before `sig_version` is read, and a v4 credential
presented to a v3 verifier is `unparseable` there for the mirror-image reason. The
bump's value is that dual acceptance is formally forbidden rather than merely
unwise.

## Alternatives rejected

**Keep strings, add a parallel `scope_boundary_v2` member.** Both members in the
document, old verifiers reading the old one. This is the ADR-0006 fail-open in
another costume: an old verifier reads `scope_boundary` and ignores the narrower
member beside it. It also doubles the member set permanently.

**Accept both forms, normalising a bare string to a `prefix` entry at parse.**
Forbidden by ADR-0008 §1a as written, and for its stated reason: two accepted
`sig_version` values must require the same members. It also reintroduces the
downgrade surface that signing `sig_version` exists to close, for no benefit given
a one hour TTL.

**Refuse an unknown kind at parse rather than at verify.** Simpler to implement,
and wrong in a way that only shows up cross-language. Rust gets its boundary shape
gate from `serde`, and an adjacently-tagged enum would make an unknown variant a
deserialization error; Python and TypeScript hand-roll their gate and would not.
The three would then return `unparseable` and `unknown_scope_kind` for the same
bytes: identical booleans, different accusations, which is the divergence class
`verdict_v1.json` exists to police. The entry is therefore parsed structurally and
classified afterwards, by the same two steps in all three implementations, and
`scripts/unknown_scope_kind_agreement.sh` reads the three reasons directly rather
than inferring agreement from three separate vector assertions.

**Define the cross-kind quantifier now.** Recorded in `docs/spec/scope.md` S.13 as
a constraint on the next revision, and deliberately NOT implemented: with one kind
no code path can observe two, so an implementation of it would be an untested
branch that reads as coverage. The constraint is written down because getting it
wrong later is a silent widening (union across kinds makes a boundary of a prefix
and an amount cap satisfiable by a request honouring either, which is wider than
either), and writing it down costs nothing that a stub would not cost more.

## Consequences

- A future boundary semantics is a new `kind`: a minor version, no `sig_version`
  bump, refused by old verifiers rather than ignored by them.
- `unknown_scope_kind` joins the standing verdict vocabulary and the attenuation
  vocabulary. Standing order becomes parse, `sig_version`, `trust_domain`,
  thumbprint, `lineage_hash`, signature, expiry, unknown scope kind, revocation.
  No pre-existing case's reason changes.
- The recognised-kind set is a registry stated once per implementation and
  consulted by both the matcher and the verdict. `scope_kinds_v1.json` declares the
  same set and is checked against each registry in both directions, so a kind
  present in one and not the other fails conformance.
- A top-level document member remains the one way to write a constraint that old
  verifiers do not see, by ADR-0006. The specification forbids producers from doing
  it; the exposure is recorded rather than closed, because closing it means
  reopening ADR-0006.
