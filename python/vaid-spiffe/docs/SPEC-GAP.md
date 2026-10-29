# Spec gap: no field for an external identity binding

**Status:** proposal, not adopted. Nothing in this repository implements it;
`vaid-spiffe` works around the gap as described below and in its README
"Scope" section.

## The gap

The open VAID document (`vaid_mint.document`, the format `canonical_vaid_signing_bytes`
signs) has no field for recording an external identity a VAID was minted
against - a `spiffe://` URI, or any other non-VAID identity reference. Every
field in the signed document is either the VAID's own identity
(`vaid_id`, `agent_id`, `agent_class`, `public_key_der`, ...) or its
delegation/authority shape (`parent_vaid`, `scope_boundary`,
`capability_set`, `lineage_hash`). None of them is meant to carry a
foreign-system identity string, and none of the existing scope-boundary
kinds (`prefix` is the only one v4 defines - `vaid_mint.document.RECOGNISED_SCOPE_KINDS`)
is a sound place to put one: a scope-boundary entry asserts *authority*, and
an identity binding is not authority.

A closed deployment (SYNTHERA, ADR-0034) solved this by adding a proprietary
`external_identity: Option<String>` field to its own (non-open) document
struct, signed in exactly the same way as every other field. That is a sound
design for a closed, single-implementation document - but it makes that
document a **superset** of the open standard's, not the same document
(`docs/trust-anchor.md`). It verifies against an open-standard verifier only
because `ADR-0006` canonicalizes over presented bytes rather than a
re-projected struct; a verifier that re-projects into its own strict schema
would reject it. It is not something another open-standard implementation
(Rust, TypeScript, or this package) can safely reproduce, because there is no
cross-language agreement on the field's name, type, or where it sits in the
canonical signing bytes.

## What this package does instead

`vaid-spiffe` does not add a field to the open document. The `spiffe://` ID
is carried **outside** the signed bytes: in `SpiffeMintResult.spiffe_id`
(returned alongside the unmodified VAID) and in a second audit event written
through the same `AuditSink` the mint itself uses. A verifier holding only
the VAID document cannot recover or confirm the binding; a party trusting the
mint's audit trail can.

## The proposal

Add an **optional, versioned, standard** field to the open VAID document for
exactly this: a single external-identity reference, typed (so `spiffe://` is
one case among others a future adapter could use - a DID, an x5c thumbprint,
whatever a binding like this turns out to need), present in the canonical
signing bytes so it is covered by the kernel signature like every other
field, and specified in `docs/spec/` with cross-language vectors the way
every other v4 field is. That would let an adapter like this one bind the
identity **inside** the document a verifier already checks, instead of
asking the verifier to additionally trust an audit trail it cannot itself
inspect.

This is a proposal only. It is not evaluated here against the full `ADR-0001`
conflict-handling process (idiom vs. principle), and no ADR is opened by this
package - that is a decision for the spec's own maintainers, following the
process `docs/adr/` already uses for v4 field changes.
