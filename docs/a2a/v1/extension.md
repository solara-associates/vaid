# A2A extension: VAID as a per-hop delegation proof

**Status: draft.**
Implements the VAID attenuation and revocation primitives (ADR-0003, ADR-0007,
`docs/spec/revocation.md`) as an [A2A](https://a2a-protocol.org) extension. Not
part of the VAID conformance surface (no frozen vector polices this document);
normative where stated, otherwise explanatory.

Terminology follows the repo: a **VAID** is the signed document (`Vaid`);
**attenuation** is the parent-to-child containment of scope, capabilities, tenant
and expiry; **chain verification** is end-to-end authority checking over a
presented ancestry (`vaid_mint.chain`).

---

## 0. Extension URI

```
https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md
```

This is the permanent extension URI, decided by Allan in the session 306
follow-up. It resolves to this versioned document, satisfying the A2A
requirement that an extension URI be a resolvable, stable identifier.

## 1. Relationship to #2028

[a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028) proposes
`actorChain`: a caller-supplied, append-only record of who acted for whom, with
monotonic scope narrowing checked hop by hop. The thread is explicit, and correctly
so, that narrowing is a **well-formedness** check on the payload alone and proves
nothing about **authority** — a fabricated chain narrows perfectly. The thread's
own proposed fix is a per-hop `proof_ref`: an externally resolvable reference that
lets a verifier confirm a hop's authority without trusting the caller's payload.

This extension does not compete with `actorChain`. It supplies one concrete,
checkable shape for that reference: a VAID is a self-contained, offline-verifiable
proof of attenuated authority, Ed25519-signed, with its own revocation and
expiry semantics already specified (`docs/spec/revocation.md`, ADR-0007). Where
`actorChain` carries `actors[n].scopes` as a claim, this extension lets a hop
additionally carry a VAID as the resolvable evidence for that claim — the
`proof_ref` / `credentialRef` slot the #2028 thread converges on, filled with a
format this repo already mints and verifies in three languages.

Carrying a VAID under this extension's metadata key does not require `actorChain`
to be present. The two compose: a deployment running both puts the VAID's
`vaid_id` in the hop's `proof_ref` (or `credentialRef`, per the ZeroID mapping in
the thread) and the VAID document itself under this extension's metadata key, so
a verifier that understands both extensions can resolve the reference and check
the attached proof, while a verifier that understands only `actorChain` sees an
opaque reference it cannot resolve — which the #2028 thread already establishes
must never be read as a denial.

## 2. AgentCard declaration

Declared as an `AgentExtension` entry in `capabilities.extensions[]`:

```json
{
  "uri": "https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md",
  "description": "VAID per-hop delegation proof: attenuated, Ed25519-signed, revocable.",
  "required": false,
  "params": {
    "acceptedVersions": ["v3"],
    "issuerKeyDiscovery": "static",
    "trustedIssuers": [
      {
        "trustDomain": "vaid.example",
        "kernelPublicKey": "<base64url, raw 32-byte Ed25519 public key>"
      }
    ],
    "requireVaid": false
  }
}
```

`params` fields:

| field | meaning |
|---|---|
| `acceptedVersions` | VAID signature-scheme versions this agent verifies. Currently always `["v3"]` (`VAID_SIG_VERSION_V3`); listed as an array so a future `v4` can be added without a new extension URI. |
| `issuerKeyDiscovery` | How this agent resolves a kernel public key for an incoming document's `kernel_key_thumbprint`. `"static"` means the keys are listed inline in `trustedIssuers`. Other discovery methods (a JWKS-style endpoint, a registry) are out of scope for this draft and MUST NOT be assumed from the field's absence. |
| `trustedIssuers` | Present when `issuerKeyDiscovery` is `"static"`. Each entry is a trust domain and the **raw kernel public key** this agent accepts for it — never a bare thumbprint. A thumbprint alone cannot verify a signature; it is a selector, not key material, and listing only a thumbprint here would verify nothing. The verifier derives each entry's thumbprint from `kernelPublicKey` itself (`kernel_key_thumbprint`, ADR-0004) and uses that to select which key to check an incoming document's signature against — mirroring `vaid_mint.chain.KernelKeyMap`, which is built the same way, from keys, never from a caller-supplied thumbprint. A document whose claimed thumbprint matches no derived entry here is not trusted, full stop; this is the extension-level expression of the `docs/trust-anchor.md` rule that resolving a key from a source the presenter controls verifies nothing. |
| `requireVaid` | If `true`, this agent refuses any request activating this extension that carries no resolvable VAID on the leaf hop. If `false` (default), a request with no VAID is handled as if the extension were not activated for that hop — the extension degrades to absent, never to a weaker check. |

An agent declaring `required: true` is stating that peers MUST understand and
honour this extension to interoperate with it at all — ordinary A2A extension
semantics, not special to VAID.

### 2.1 `trustedIssuers` validity

Each `trustedIssuers` entry pairs exactly one kernel key with exactly one
trust domain. A conforming implementation MUST reject the following shapes
as a configuration error, at the point this list is loaded, rather than
accept a narrowed or best-guess reading of it:

- **An entry with no `trustDomain`.** A kernel key with no trust domain
  attached binds to nothing, so accepting it would leave every document's
  claimed `trust_domain` effectively unchecked for that key. Entries
  without `trustDomain` are not accepted.
- **The same kernel public key listed more than once.** Whichever
  `trustDomain` a lookup happened to resolve to last would otherwise decide,
  silently, which domain that key is actually trusted for. The error MUST
  name the key (its derived thumbprint) and every trust domain it was
  listed under, so the operator can see the conflict directly rather than
  re-deriving it from the raw configuration.

These two rules apply before anything in section 5 runs: a `trustedIssuers`
list that violates either one is a defect in the agent's own configuration,
not a property of any particular incoming request.

## 3. Activation

Standard A2A per-request activation: a client that wants a VAID-bearing request
checked under this extension sends the extension's URI in the `A2A-Extensions`
request header (comma-separated if other extensions are also activated). An agent
that supports the extension and chooses to honour it on this request echoes the
URI back in its own `A2A-Extensions` response header. An agent that does not
support it, or declines to activate it for this request, omits the URI from its
response header — the client then knows the extension was not applied and must not
assume VAID verification occurred.

## 4. Where the VAID travels

The VAID document (the full JSON object, not a wrapped or re-encoded form) is
carried in `Message.metadata`, keyed by this extension's URI with a `/vaid`
suffix, following the `metadata["{extension-uri}/{field-name}"]` pattern A2A
extensions use generally:

```json
{
  "metadata": {
    "https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md/vaid": {
      "vaid_id": "...",
      "agent_id": "...",
      "agent_class": "...",
      "version": "...",
      "tenant_id": "...",
      "issued_at": "...",
      "expires_at": "...",
      "public_key_der": [ ... ],
      "kernel_signature": [ ... ],
      "scope_boundary": [ ... ],
      "lineage_hash": "...",
      "capability_set": [ ... ],
      "trust_domain": "...",
      "kernel_key_thumbprint": "...",
      "sig_version": 3,
      "parent_vaid": null
    }
  }
}
```

This is the leaf — the VAID of the agent that produced the `Message`. Ancestor
documents the verifier needs to walk the chain (§5) travel the same way, under a
sibling key with a `/vaidChain` suffix, as a JSON array of VAID documents in no
particular order (the verifier assembles ancestry from `parent_vaid`, not from
array position):

```json
{
  "metadata": {
    "https://github.com/solara-associates/vaid/blob/main/docs/a2a/v1/extension.md/vaidChain": [
      { "vaid_id": "...parent...", "parent_vaid": "...grandparent-or-null...", "...": "..." },
      { "vaid_id": "...grandparent...", "parent_vaid": null, "...": "..." }
    ]
  }
}
```

An agent that activates the extension but finds no `/vaid` key present treats the
hop as not carrying a VAID (§2's `requireVaid` governs whether that is fatal). A
`/vaidChain` key present with no `/vaid` key is malformed input under §6's
authenticity check.

### 4.1 Mapping onto a #2028 `actorChain` hop

When both extensions are active, a hop in `actors[]` that carries a VAID as its
proof sets its reference field (`proof_ref` or `credentialRef`, per whichever name
the `actorChain` text settles on) to the VAID's `vaid_id`. The verifier resolves
that reference by looking up the matching `vaid_id` in this extension's `/vaid` or
`/vaidChain` metadata on the same message — resolution is local to the message,
not a network fetch, which is exactly the "opaque reference, dereference
authorized separately" shape the #2028 thread asks for: the reference is inert
until the resolving party chooses to look at the attached proof.

## 5. Verification rules

A receiving agent that activates this extension on an incoming request applies
the following checks, **in this order**, against the VAID in the `/vaid` metadata
key and, where the request requires chain verification, the documents in
`/vaidChain`. The order is load-bearing, for the same reason it is load-bearing in
`vaid_mint.verify` and `vaid_mint.chain`: two verifiers that reach the same boolean
by different routes can still disagree about *why*, and that disagreement is
invisible unless the reason is named.

1. **Signature.** First, the leaf VAID's own binding: its claimed
   `trust_domain` MUST equal the trust domain that its `kernel_key_thumbprint`
   is bound to under §2's `trustedIssuers` (never the other way round, since a key
   is trusted for the domain `trustedIssuers` pairs it with, not for any
   domain a document cares to claim). A thumbprint resolving to no entry, or
   resolving to an entry bound to a different domain, is `ISSUER_MISMATCH`.
   Only once that binding holds does the leaf VAID's Ed25519 kernel signature
   get checked, against the key that same thumbprint resolved to. Equivalent
   to `vaid_mint.verify.verify_vaid_authenticity_graded`. Any `UNPARSEABLE`,
   `UNSUPPORTED_SIG_VERSION`, `MALFORMED_TRUST_DOMAIN`, `ISSUER_MISMATCH`,
   `LINEAGE_INCONSISTENT` or `INAUTHENTIC` result fails the request; see §6 for
   the specific error returned. This step is scoped to the leaf alone: it
   MUST reach its own verdict (`INAUTHENTIC` or otherwise) without being
   affected by any defect in a chain document considered under step 3.
2. **Expiry / TTL.** The leaf VAID has not passed its own `expires_at` at the
   verification instant (`vaid_mint.document.is_expired`).
3. **Chain integrity back to a trusted root.** For each document presented in
   `/vaidChain`, its own binding is checked first, the same rule as step 1:
   its claimed `trust_domain` MUST equal the trust domain its own
   `kernel_key_thumbprint` is bound to under `trustedIssuers`. A document
   whose thumbprint resolves to a different bound domain is `ISSUER_MISMATCH`,
   the same code step 1 uses for the leaf's own binding failure, applied here
   to a chain document instead. Only then does chain integrity proceed: every
   ancestor named by a signed `parent_vaid` is present in `/vaidChain`, every
   document in the chain is itself authentic under a trusted key, and no
   ancestor has passed its own `expires_at` at the verification instant.
   Equivalent to `vaid_mint.chain.verify_chain_at` through the point where it
   would return `INAUTHENTIC`, `UNVERIFIABLE` or `EXPIRED`.

   **Every step above applies to every request.** There is no leaf-only mode: a
   leaf's own authority cannot be assessed without its lineage, because ancestor
   revocation (a parent whose standing was withdrawn after it delegated) can
   only be established by walking the chain, never by looking at the leaf alone.
   An agent that requires chain verification for a request but receives no
   `/vaidChain` (or an incomplete one) MUST deny it: a missing chain where one is
   required is `UNVERIFIABLE`, never a reason to fall back to checking the leaf in
   isolation.

   **The order is deterministic, and this is why it matters in practice.**
   Step 1 runs to completion, and only to a final verdict on the leaf alone,
   before step 3 examines any chain document. A leaf whose own signature does
   not verify is `INAUTHENTIC` regardless of what else is presented in
   `/vaidChain`, including a chain document that is independently misbound
   to the wrong trust domain. A conforming implementation MUST NOT let a
   defect discovered while examining the chain in step 3 pre-empt a verdict
   that step 1 would already have reached about the leaf; two implementations
   presented with the same bad-leaf-signature-plus-misbound-chain-document
   input MUST both return `INAUTHENTIC`, not one `INAUTHENTIC` and the other
   `ISSUER_MISMATCH`.
4. **Scope at each hop is a subset of its parent's.** Every hop in the assembled
   chain holds `scope_boundary` and `capability_set` contained in its parent's,
   and `expires_at` no later than its parent's. Equivalent to the per-hop
   `scope_attenuates`, `caps_attenuate` and `expiry_attenuates` checks inside
   `verify_chain_at`; a violation is `NOT_ATTENUATED`.

   **The empty-set rules.** An empty `scope_boundary` means unrestricted: it
   contains every resource (`vaid_mint.document.is_in_scope`,
   `vaid_mint.mint.scope_attenuates_within`). An empty `capability_set` means no
   capabilities: it contains none (`vaid_mint.document.has_capability`,
   `vaid_mint.mint.caps_attenuate_within`). Because an empty scope is
   unrestricted, a child may carry an empty `scope_boundary` only if its
   parent's `scope_boundary` is also empty; a child with no declared parent
   scope to inherit from cannot be granted the unrestricted one
   (`vaid_mint.mint.scope_attenuates_within`'s empty-child guard). There is no
   corresponding guard for `capability_set`, because an empty child
   capability set is already the most restrictive case and attenuates under
   any parent.
5. **Requested action is within the leaf's scope.** The specific action the
   message is requesting is checked against the leaf VAID's `scope_boundary`
   (`vaid_mint.document.is_in_scope`) and, if the action corresponds to a named
   capability, `capability_set` (`has_capability`). This is a property of the
   single leaf document, not of the chain, and is NOT subsumed by step 4: a
   well-attenuated chain can still present a leaf whose own scope does not cover
   the action actually being requested.
6. **Revocation of every link, via a pluggable check.** The agent consults its own
   `vaid_mint.revocation.RevocationCheck` (or equivalent in another language) over
   the full assembled lineage, root to leaf. A `REVOKED` result anywhere in the
   lineage fails the request (R.4.4: revoked anywhere in the lineage means revoked).
   An `UNAVAILABLE` result — the check could not be consulted — **fails closed**,
   exactly as `vaid_mint.revocation` specifies: it is never treated as
   `NOT_REVOKED`, and never silently skipped.
7. If every applicable step above passes, the request is **authorized** by this
   extension's check. This extension makes no statement about any other
   authorization layer the receiving agent runs; a VAID clearing this check is a
   necessary signal, not an all-encompassing one, exactly as `actorChain` narrowing
   is explicitly not a grant of authority in #2028.

**Fail closed throughout.** Every step above that can return "could not
determine" — an unresolvable issuer key, an incomplete chain, an unavailable
revocation check — is a distinct failure from "determined and rejected", and
both are refusals. Neither is ever treated as a pass. This mirrors
`vaid_mint.verify.VaidVerdict.INDETERMINATE` and
`vaid_mint.revocation.RevocationStatus.UNAVAILABLE`: "could not tell" is reported
as itself, not folded into either boundary.

## 6. Error behaviour

A2A defines JSON-RPC-shaped errors on the `Message/send` and related methods.
This extension does not introduce a new wire-level error class; it maps a
verification failure onto the existing A2A error space as follows:

- A malformed or absent VAID where `requireVaid` is `true` (§2), or a VAID that
  fails §5 step 1 (authenticity) or step 3 (chain integrity/`UNVERIFIABLE`): the
  agent returns an A2A **`InvalidRequestError`** (or the transport's equivalent
  "the request could not be validated" error), since the fault is in what the
  caller presented, not in a transient condition.
- A VAID that fails §5 step 2 (expired), step 4 (not attenuated) or step 5
  (action outside scope): the agent returns an A2A **authorization-class error**
  — the error A2A defines for "the caller is not permitted to do this", with a
  `message` naming which check failed (expiry, attenuation, or out-of-scope
  action) without echoing signed document bytes back on the wire unnecessarily.
- A revocation check that reports `REVOKED`: the same authorization-class error
  as above, naming revocation as the cause.
- A revocation check (or key resolution) that reports it could not determine an
  answer (`UNAVAILABLE`): the agent returns the same authorization-class error —
  fail-closed, per §5 — but SHOULD distinguish this in its own logs/audit from a
  positive `REVOKED` determination, for the reason `VaidVerdict.INDETERMINATE`'s
  docstring gives: one is an accusation, the other is a refusal to vouch.

Exact A2A error type names are left to the A2A core error taxonomy as published;
this section states the mapping principle (fault class -> which existing A2A
error family) rather than inventing new error codes, since inventing one here
would be exactly the kind of extension-introduced vocabulary §7 warns against for
metadata keys.

## 7. Naming

Every metadata key, `params` field and concept this extension introduces is named
`vaid*` (`/vaid`, `/vaidChain`, `acceptedVersions`, etc. under the VAID extension
URI's namespace). None of them is named `synthera*`, and none of them reuses or
aliases any `x-synthera-*` header defined elsewhere in this repository. This
extension is VAID-neutral: it specifies nothing about any particular commercial
deployment of VAID, and a party with no relationship to Synthera can implement it
from this document alone.

## 8. Non-goals

- This extension does not define how a client obtains a VAID in the first place
  (minting is `vaid_mint.mint.MintService`, out of scope for A2A).
- This extension does not define revocation transport (`docs/spec/revocation.md`
  R.1 already excludes that from the VAID conformance surface; the same exclusion
  applies here).
- This extension does not require `actorChain` (#2028) or any other extension to
  be active. §4.1 describes an optional composition, not a dependency.
