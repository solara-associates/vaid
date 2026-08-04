# ADR-0003: Third-party attenuation verification, via detached chain presentation

**Status:** Accepted
**Date:** 30 July 2026
**Repo:** solara-associates/vaid
**Decision owner:** A. Smeyatsky
**Supersedes:** the undocumented v0.2 deferral cited in prose as "ADR-0003"
**Related:** ADR-0001 (revocation outside the conformance surface), ADR-0002
(capabilities manifest), ADR-0004 (v3 issuer identifier and kernel key
thumbprint), `docs/spec/encoding.md`, `docs/spec/revocation.md` R.4

---

## Context

A VAID carries its own `scope_boundary` and `capability_set`, plus `parent_vaid`
(one hop) and `lineage_hash` (a one-way digest binding the immediate parent). It
does not carry its ancestors' authority.

Attenuation — the requirement that a child's authority is a subset of its
parent's — is enforced at mint time by `scope_attenuates` and `caps_attenuate`.
It has not been checked at verification time. A third party could therefore
verify that a VAID is authentic and that the authority written into it was signed
by the mint, but not that this authority was legitimately derived from the
parent's. Under that format, authority is a property of the mint's word.

That gap sits directly underneath the project's positioning: identity is a
property of the request itself rather than the path it took.

### The prior deferral, and why this record exists

For v0.2 the decision was to leave attenuation mint-time enforced and to document
it as not third-party verifiable, with a commitment-based format planned as the
destination. The rationale had three parts:

1. A commitment field changes the canonical bytes of every document, invalidates
   `mint_v1` and requires re-freezing across every implementation.
2. The TypeScript port was in progress, so re-freezing meant porting to a moving
   target.
3. Two format breaks in one quarter, on a standard with no external adopters,
   would cost more credibility than the gap did.

**That decision was never written down.** It was cited in prose as "ADR-0003" for
a week — the only reference being a line in `typescript/vaid-mint/README.md` —
while `docs/adr/` contained 0001 and 0002 only. The reasoning treated as
documented was recollection. This record fills the gap and then supersedes it,
and the sequence is worth stating plainly: a decision that exists only as a
citation is indistinguishable from one that was never made.

Two of the three original reasons have since expired. The TypeScript port is
complete and green against all five frozen vectors, and reason 3 is addressed by
ADR-0004, which lands a single deliberate break.

## Decision

**Third-party attenuation verification is achieved by detached chain
presentation, which requires no change to the VAID document.** The presenter
supplies the ancestor documents alongside the leaf; the verifier walks them.

This supersedes the planned commitment-based format. `mint_v1.json` is not
re-frozen for attenuation, `sig_version` is not bumped for attenuation, and
attenuation does not need to ride ADR-0004's break.

1. No new field in the VAID document. No new encoding rule inside signed bytes.
2. The verification procedure and the presented-bundle resolver are added as
   library surface, not format.
3. Any conformance artifact for chain presentation is a **new** vector.
   New vectors are additive; they do not invalidate existing ones.
4. Attenuation therefore lands **after** v3, as additive work, rather than riding
   its break.

## Why no document field is needed

The prior analysis rested on the observation that a leaf "does not carry its
ancestors' authority". That is true, and it is the wrong thing to measure. The
leaf carries their **identity**, signed:

- `parent_vaid` is inside the canonical bytes, so it cannot be altered without
  breaking the kernel signature.
- `verify_lineage_hash` independently recomputes `lineage_hash` from
  `parent_vaid` and `agent_id`, so an inconsistent value is caught explicitly
  rather than incidentally.

An ancestor VAID is itself a kernel-signed, self-authenticating statement of its
own authority. The verifier does not need the leaf to *describe* its ancestors.
It needs the ancestors, plus a pinned reference telling it which ones are real.
Both already exist.

### The verification procedure

Given a leaf `L` and the ancestor documents presented alongside it:

1. **Authenticate every document.** `verify_vaid_authenticity(kernel_key, doc)`
   for the leaf and each ancestor. Under v3 the key is selected by the
   document's `kernel_key_thumbprint` (ADR-0004).
2. **Pin each hop.** Require a presented document whose `vaid_id` equals
   `L.parent_vaid`; call it `P1`. Recurse on `P1.parent_vaid` until a document
   with `parent_vaid == null` is reached.
3. **Fail closed on an incomplete chain.** A `parent_vaid` that is present but
   not resolvable in the presented bundle yields
   `LineageAssembly::Incomplete`, which means *attenuation unverifiable* — never
   *attenuation satisfied*. Cycles and implausible depth
   (`MAX_LINEAGE_DEPTH`) resolve the same way.
4. **Check containment.** `scope_L ⊆ scope_P1 ⊆ … ⊆ scope_root`, and the same for
   capabilities, using the single existing matchers so the verify-time check
   cannot drift from the mint-time one.

### Chain substitution is prevented by the existing signature

To present a more privileged parent, an adversary needs a kernel-signed document
whose `vaid_id` equals the `L.parent_vaid` pinned inside the leaf's signed bytes.
Because `vaid_id` equals `agent_id` and is a fresh UUIDv4 per mint, that requires
a kernel-key compromise or a UUID collision. No new field contributes to this
property; the pin is already signed.

**This argument holds only while every document on the chain is signed by one
kernel key**: once a verifier accepts more than one, a second accepted issuer can
sign a document naming any `vaid_id` it knows as `parent_vaid` without compromising
anyone's key, so a cross-key hop additionally requires a detached consent
attestation from the issuer that minted the parent (`crates/vaid-mint/src/attestation.rs`).

### The primitives already exist

`docs/spec/revocation.md` R.4.2 and `crates/vaid-mint/src/revocation.rs` already
define `assemble_lineage`, `LineageResolver`, `LineageAssembly`,
`MAX_LINEAGE_DEPTH`, cycle detection, and the `Root`-versus-`Unknown`
distinction — with incomplete assembly failing closed.

One caveat deserves stating because it appears to cut the other way. R.4.2 says
the full lineage is not recoverable from the VAID itself and that assembly
requires a resolver, whose reference implementation is the issuer's in-process
lineage map — precisely what a third party lacks. That is true **for
revocation**, where assembly starts from a bare identifier and must resolve
upward.

It is not a constraint here, because the presenter supplies documents rather than
identifiers, and every document carries its own `parent_vaid`. The resolver
becomes a lookup over the presented bundle: `Root` when `parent_vaid` is absent,
`Parent(p)` when present, `Unknown` when the document was not presented. No
issuer, no network, no new trait, and the three-state shape is already correct.

## Correction to the earlier options table

The prior assessment compared three shapes and credited the commitment shape (B)
with "discloses chain authority: no, only when values are supplied", rejecting
the embedding shape (A) for disclosing to every verifier. Assessed against a
detached shape (D), B's disclosure advantage is **narrower than credited**.

**Full-path attenuation requires full-path values.** To establish
`L ⊆ P1 ⊆ … ⊆ root`, a verifier needs every link's authority. Revealing only some
ancestors leaves a gap in the subset chain and proves nothing transitive. B
therefore does not provide *selective* disclosure for this property. What it
provides is **narrower** disclosure: authority tuples per ancestor rather than
whole documents, so tenant, agent class, timestamps and keys stay unrevealed.

That is a real advantage and a modest one. It is not the property the earlier
table implied.

| | A: embed in leaf | B: commit in leaf | **D: detached chain** |
|---|---|---|---|
| New signed document field | Yes | Yes | **No** |
| `mint_v1` re-freeze | Yes | Yes | **No** |
| `sig_version` bump | Yes | Yes | **No** |
| New encoding rule in signed bytes | Yes | Yes, undecided | **None** |
| Leaf size | Grows with chain depth | Fixed | **Fixed** |
| Disclosed at verification | Everything, always | Authority tuples per ancestor | Full ancestor documents |
| Incremental (verify *k* hops) | No | Partially | **Yes** |
| Anti-lying mechanism | Signature | New commitment construction | **Signature, existing and vector-pinned** |
| Presenter must retain ancestors | No | Yes | Yes |
| Third-party attenuation verification | Yes | Yes | **Yes** |

## Rationale for D over B

1. **The anti-lying property is equivalent; the mechanism is not.** B commits, D
   signs. Both prevent a presenter lying about ancestor authority. D's mechanism
   is already built, already three-language, and already pinned by frozen
   vectors.
2. **B's construction is undecided and would live inside signed bytes.** What is
   committed, in what order, canonicalized how — each is a new normative
   encoding rule needing its own specification section and its own vector.
   Inventing a construction is also what ADR-0004's prior-art section says not to
   do.
3. **D is incrementally disclosable.** Presenting one hop yields one-hop
   verification. Neither A nor B offers that.
4. **The revisiting trigger has not fired.** The earlier record named a named
   evaluator stating the requirement as the strongest signal for moving B
   forward. None has.
5. **D closes the gap sooner.** The accepted cost of the deferral — a verifier
   must trust the mint on attenuation — is closed without waiting for a format
   decision.
6. **v3 enables D rather than competing with it.** D must authenticate each
   ancestor, which means selecting the key that signed it. That is exactly what
   ADR-0004's `kernel_key_thumbprint` provides. The ordering is therefore
   substantive, not merely cheaper: v3 first, D second.

## Consequences

**Accepted:**

- Third-party attenuation verification becomes available with no format break.
- `mint_v1.json` is re-frozen once, for ADR-0004's two identity fields, not
  twice.
- The verify-time containment check reuses the mint-time matchers, so the two
  cannot drift.
- Incomplete chains fail closed, consistent with R.4's existing three-state
  discipline.

**Costs, accepted knowingly:**

- **Full-chain verification requires full-chain disclosure.** A verifier
  performing the complete check sees every ancestor document, including fields it
  does not need. Disclosure is conditional on the verifier asking, and
  incremental, which is better than A — but it is not minimal.
- **The presenter must retain and present ancestors.** A leaf whose ancestor
  documents were discarded has unverifiable attenuation. A is the only
  self-contained shape, and it was rejected on other grounds.
- **Attenuation is verifiable but not yet verified anywhere.** This record
  decides the construction. Until the resolver, the procedure and a chain
  presentation vector ship, the gap is unchanged in shipped code, and claims must
  stay scoped accordingly.

**The residual:**

If minimal disclosure at verification becomes a hard requirement, B is better
than D, B needs a field inside the VAID document, and it would therefore need its
own format break. There is no evidence of that requirement today. Should it
arrive, the cost is a further `sig_version` bump — and by then D will have proven
the transport and the verifier, so B's value can be judged against real usage
rather than estimated.

Until the procedure ships, the honest statement is unchanged: a third party
verifies authenticity and the leaf's own stated authority. Claims that a third
party can verify authority relative to a parent, or trace a delegation chain end
to end, are not made until the code exists.

## Revisiting

- **A named evaluator requiring minimal disclosure** at verification. That is the
  trigger for reopening B, and it is the falsification test for this decision.
- **A chain depth or presentation size that makes full-document presentation
  impractical.** B's narrower payload would then matter for reasons of size
  rather than privacy.
- **A competitor shipping verifiable cross-organisation delegation**, at which
  point the remaining gap between decided and shipped becomes a liability rather
  than a roadmap item.
