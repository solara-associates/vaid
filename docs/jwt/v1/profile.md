# VAID-to-JWT Token Bridge Profile v1

**Status: draft.**

Defines a **token bridge**: a service that verifies a full VAID delegation chain
and, only if verification fully passes, issues a short-lived standard JWT that a
gateway can verify against a published JWKS using ordinary JWT libraries — no VAID
code in the gateway's request path. This is not "VAID as a JWT end to end"; a
gateway holding one of these JWTs trusts the bridge's verification, not any
individual hop in the original chain.

Builds only on primitives already defined by the Python `vaid_mint` package
(`vaid_mint.chain`, `vaid_mint.revocation`, `vaid_mint.document`,
`vaid_mint.verify`) and by the IETF specifications referenced below. Introduces
no change to the VAID document format, the mint, or `vaid_mint` itself.

---

## 0. Normative references

- **RFC 8693** — OAuth 2.0 Token Exchange. Defines the `act` (actor) claim, its
  nesting rule, the token-exchange grant request/response shape, and the
  `urn:ietf:params:oauth:token-type:*` namespace.
- **RFC 7519** — JSON Web Token (JWT).
- **RFC 7515** — JSON Web Signature (JWS).
- **RFC 7517** — JSON Web Key (JWK) and JWK Set.
- **RFC 7638** — JSON Web Key (JWK) Thumbprint. Used here for `kid` derivation.
- **RFC 8037** — EdDSA and Ed25519 for JOSE (`alg: EdDSA`, `kty: OKP`,
  `crv: Ed25519`).
- **RFC 7518 §3.4 / §6.2.1** — ECDSA with P-256 (`alg: ES256`, `kty: EC`,
  `crv: P-256`).

---

## 1. Input

An exchange request supplies, conceptually (the wire shape is §6):

- **leaf** — one signed VAID document, the identity being exchanged.
- **chain** — the leaf's presented ancestor documents, detached-chain-presentation
  style (`vaid_mint.chain.PresentedBundle`): zero or more documents, not including
  the leaf, sufficient to resolve the leaf's ancestry back to a root.
- a **`RevocationCheck`** (`vaid_mint.revocation.RevocationCheck`) — required
  configuration. There is no default and no fail-open behavior; a bridge
  deployment that has not wired a revocation backend cannot issue anything.
- **trusted issuer config** — a `KernelKeyResolver`
  (`vaid_mint.chain.KernelKeyResolver`): the set of kernel public keys this bridge
  deployment accepts, keyed by `kernel_key_thumbprint`. A document signed by a key
  not in this set is untrusted, full stop — this is the bridge's trust anchor and
  MUST NOT be populated from anything the presenter controls.
- a **requested audience** — the intended `aud` of the issued JWT. Required; see
  §3.

## 2. Verification (fail closed)

The bridge performs exactly the chain-verification procedure already specified for
a VAID presentation, reusing `vaid_mint` primitives without modification:

1. **Leaf authenticity** — resolve the leaf's signing key from its
   `kernel_key_thumbprint` via the trusted issuer config; an unresolved thumbprint
   or a failing signature denies the exchange.
2. **Leaf expiry** — the leaf's own `expires_at` has not passed
   (`vaid_mint.document.is_expired_at`).
3. **Chain integrity and attenuation to a trusted root** —
   `vaid_mint.chain.verify_chain_at` over the leaf and the presented bundle:
   every presented document authentic, the chain assembles completely to a root
   with no gap or cycle, and authority (scope, capability, tenant, expiry) is
   contained at every hop. Anything other than `ChainVerification.ATTENUATED`
   denies the exchange.
4. **Trust-domain binding per issuer key** — enforced inside `verify_chain_at`
   itself: a hop that crosses a `kernel_key_thumbprint` requires a current,
   authentic consent attestation naming that exact `(parent, child)` pair and
   trust domain (`vaid_mint.chain`, cross-key hop handling). A same-key hop binds
   tenant and trust domain directly from the parent document.
5. **Revocation of every link** — the full lineage is assembled
   (`vaid_mint.revocation.assemble_lineage`) and checked via the configured
   `RevocationCheck.check_lineage`. `REVOKED` denies. `UNAVAILABLE` **denies** —
   this bridge profile never treats "could not determine" as "not revoked."

**Any failure at any step issues nothing.** There is no partial or degraded JWT.
The exchange is atomic: a full pass is required before step 3 of §3 runs, and the
bridge performs no caching of a verification result across exchanges — each
exchange re-verifies and re-checks revocation from scratch (see §7).

## 3. Output JWT claims

On a full pass, the bridge issues a JWT with:

| Claim | Value |
| :- | :- |
| `iss` | the bridge's own issuer identifier (deployment config, stable per bridge instance) |
| `aud` | **required** — exactly the audience requested of this exchange (§1); the bridge does not invent or widen it |
| `iat` | time of issuance |
| `exp` | `min(iat + default_ttl, leaf.expires_at)` — see §3.1 |
| `jti` | a fresh random identifier (UUIDv4), unique per issued token |
| `sub` | see §4 |
| `act` | see §4; **omitted** when the leaf has no parent (no delegation occurred) |
| `vaid` | see §5 |

### 3.1 `exp` — short-lived, and never past the leaf

The default lifetime is **5 minutes**. A deployment MAY configure a shorter
default; it MUST NOT configure one that could exceed the leaf's remaining life.
Formally:

```
exp = min(iat + configured_ttl_seconds, parse(leaf.expires_at))
```

This is a hard ceiling, not a target: a leaf with less than `configured_ttl_seconds`
remaining gets a JWT that expires exactly when the leaf does, never later. A
gateway honoring `exp` therefore never accepts the bridge's word for an identity
past the point the leaf itself would have lapsed.

## 4. `sub` and `act` — RFC 8693 mapping

RFC 8693 §4.1 fixes the nesting direction unambiguously: *"The outermost `act`
claim represents the current actor while nested `act` claims represent prior
actors. The least recent actor is the most deeply nested."* In the RFC's own
example, the top-level `sub` is the original subject (the user), the outermost
`act.sub` is the current actor, and each further nesting level steps back toward
the earliest actor in the chain.

A verified VAID chain is produced by `vaid_mint.chain`/`vaid_mint.revocation` as an
ordered list, **root first, leaf last** (`assemble_lineage`,
`verify_chain_at`'s `chain_docs`). Call this `chain = [root, h1, h2, ..., leaf]`
(`h1` is the root's immediate child; `leaf` is the presented identity). This
list maps onto RFC 8693 with **no ambiguity**, because the RFC's "current actor"
is by construction the most recently delegated identity, and a VAID chain's most
recently delegated identity is, by construction, the leaf:

- **`sub`** = `chain[0].vaid_id` — the root of the delegation chain. This is the
  party RFC 8693's example calls "the user": the original authority all
  subsequent delegation derives from.
- **`act`** = built from `chain[1:]` (every hop after the root, oldest first),
  nested from the oldest (`h1`, innermost) out to the leaf (outermost):

  ```
  node = { "sub": h1.vaid_id }
  for hop in chain[2:]:               # h2, h3, ..., leaf, oldest to newest
      node = { "sub": hop.vaid_id, "act": node }
  act = node
  ```

  so for a 4-node chain `[root, h1, h2, leaf]`:

  ```json
  {
    "sub": "<root.vaid_id>",
    "act": {
      "sub": "<leaf.vaid_id>",
      "act": {
        "sub": "<h2.vaid_id>",
        "act": { "sub": "<h1.vaid_id>" }
      }
    }
  }
  ```

  Each `act` level identifies a hop by its `vaid_id`; no other VAID fields are
  placed in `act` nodes (field detail belongs in the `vaid` claim, §5, which
  describes only the leaf — a verifier that needs ancestor detail re-fetches and
  re-verifies the original chain via `chain_sha256`, §5).

**Degenerate cases**, handled by the same construction with no special-casing of
RFC 8693 itself:

- `chain` has exactly one element (the leaf is its own root — `parent_vaid` is
  absent): no delegation occurred. `sub = leaf.vaid_id`, and **no `act` claim is
  emitted**. Per RFC 8693 §4.1, `act` exists to express that delegation occurred;
  it is not emitted when it did not.
- `chain` has exactly two elements (`[root, leaf]`, i.e. the leaf's own parent is
  the root): `sub = root.vaid_id`, `act = { "sub": leaf.vaid_id }` — one level,
  no nested `act.act`. The leaf is simultaneously the only actor and the current
  one.

This mapping is total over every chain `verify_chain_at` can return `ATTENUATED`
for, and was checked against the RFC's example by substitution before being
adopted — it does not require interpreting an ambiguous case, so this profile
does **not** invoke the halt condition for an unmappable chain.

## 5. The `vaid` claim

A single object describing the **leaf** (the identity actually being exchanged),
carrying at minimum:

| Field | Source |
| :- | :- |
| `vaid_id` | `leaf.vaid_id` |
| `trust_domain` | `leaf.trust_domain` |
| `scope_boundary` | `leaf.scope_boundary` |
| `capability_set` | `leaf.capability_set` |
| `chain_sha256` | see below |

`chain_sha256` is the lowercase hex SHA-256 digest of the RFC 8785 (JCS) canonical
JSON encoding of the full verified chain, root first leaf last, **exactly as
presented and verified** (`[root, h1, ..., leaf]`, the same list structure
`verify_chain_at` built internally) — i.e. `sha256(JCS([root, h1, ..., leaf]))`.
Because JCS canonicalization is deterministic and the documents are the originals
(no field stripped or reordered beforehand), an auditor holding the same chain can
recompute this digest independently and confirm the bridge verified *these exact
documents* and not some other presentation claiming the same `sub`/`act` values.

## 6. The token-exchange wire protocol

RFC 8693, carried over HTTP POST with `application/x-www-form-urlencoded`
(§2.1):

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<the leaf VAID document plus its chain, see encoding below>
subject_token_type=urn:vaid:params:oauth:token-exchange:token-type:vaid-chain-v1
requested_token_type=urn:ietf:params:oauth:token-type:jwt
audience=<the requested aud>
```

- **`subject_token_type`** — `urn:vaid:params:oauth:token-exchange:token-type:vaid-chain-v1`.
  This is a profile-defined URI under a VAID-specific namespace, not an
  IETF-registered one; RFC 8693 §3 explicitly permits token types beyond the
  `urn:ietf:params:oauth:token-type:*` set it defines ("Other URIs MAY be used to
  indicate other token types"). It names *this exact wire encoding* (next bullet)
  so a future `-v2` can change the encoding without colliding with v1 callers.
- **`subject_token` encoding** — a JSON object `{"leaf": <VAID document>, "chain":
  [<VAID document>, ...]}`, url-form-encoded as the parameter value. `chain` is
  the detached ancestor presentation of §1 (not including the leaf), in any
  order — `vaid_mint.chain.PresentedBundle` resolves it by `vaid_id`, not by
  position.
- **`audience`** is required by this profile (RFC 8693 lists it as OPTIONAL in
  general; §1 above makes it mandatory here, because an issued JWT's `aud` must
  never be left to a bridge default).
- **`requested_token_type`**, if present, MUST be
  `urn:ietf:params:oauth:token-type:jwt`; any other value is a denial (this
  profile issues only JWTs).

On success, the response is RFC 8693 §2.2 shape:

```json
{
  "access_token": "<the signed JWT, compact serialization>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "N_A",
  "expires_in": <seconds until exp>
}
```

`token_type` is `N_A` (RFC 8693 §2.2.1): the issued JWT is not a bearer OAuth
access token meant to be presented to *this* bridge; it is a credential a
gateway verifies directly against the JWKS (§8), so no token-type-specific usage
instruction applies.

On denial, the bridge returns an RFC 6749 §5.2-shaped `invalid_grant` error body
with no token fields. §7 enumerates the denial reasons; none of them produce a
partially-populated response.

## 7. Security notes

- **The gateway trusts the bridge, not every hop.** A gateway verifying the
  issued JWT's signature against the JWKS is relying entirely on the bridge
  having performed §2 correctly at issuance time. The bridge is a trust
  boundary, not a transparent relay — it must be operated with the same care as
  any token issuer.
- **Keep `exp` short.** §3.1 fixes a 5-minute default specifically so that a
  compromised or misused JWT has a short window, and so that the bridge's
  per-exchange revocation check (next bullet) stays meaningfully fresh relative
  to the token's own lifetime.
- **The bridge must re-check revocation on every exchange.** §2 step 5 is not a
  one-time gate; it runs for every `exchange()` call, including a second
  exchange for the same leaf moments after the first. There is no
  cross-exchange cache of "this chain was fine last time."
- **Never cache an issued JWT beyond its `exp`.** The bridge issues; it does not
  store, index, or re-serve a previously-issued token. A caller needing a fresh
  token after expiry must present the chain again and pass §2 again — a revoked
  link between the two exchanges is caught the second time specifically because
  there is no cache to shield it.
- **`act` is informational only**, per RFC 8693 §4.1: a gateway or downstream
  consumer MUST base authorization decisions on the token's top-level claims
  (`sub`, `vaid`, `aud`, `exp`) and MUST NOT treat a nested `act` entry as
  granting independent authority. `act` exists for audit and traceability, not
  as a second credential.
- **`chain_sha256` is an audit aid, not a secrecy boundary.** It lets a party
  that already holds (or can re-fetch) the original chain confirm what the
  bridge verified; it reveals nothing to a party that does not already have the
  chain.

## 8. JWKS

Served at a stable path, `GET /.well-known/jwks.json`, `Content-Type:
application/json`, body an RFC 7517 JWK Set: `{"keys": [...]}`.

- **Key types.** Both EdDSA (RFC 8037: `kty: OKP`, `crv: Ed25519`, `alg: EdDSA`)
  and ES256 (RFC 7518: `kty: EC`, `crv: P-256`, `alg: ES256`) are supported,
  selectable per deployment (bridge config, not per-request). A deployment MAY
  configure more than one key (e.g. during a rotation); every configured key's
  **public** half is published here, each with its own `alg` matching its key
  type — the JWKS never mixes an `alg` with a mismatched `kty`/`crv`.
- **`kid` derivation.** RFC 7638 JWK Thumbprint: SHA-256 over the canonical JWK
  member set for the key's type (`crv`, `kty`, `x` for OKP; `crv`, `kty`, `x`,
  `y` for EC), base64url-encoded without padding. This is the standard
  IETF thumbprint, chosen deliberately over this repository's VAID-specific
  `kernel_key_thumbprint` (`vaid_mint.issuer_identity`) — the two serve
  different consumers (a VAID-aware verifier vs. an arbitrary JWT/JWKS client)
  and this profile's `kid` must be computable by a client that has never heard
  of VAID.
- **`use`** is `"sig"` on every published key; this bridge publishes no
  encryption keys.
- Every issued JWT's header `kid` matches exactly one key published in the
  JWKS at the moment of issuance.

## 9. Halt condition check (informational)

This profile was written against the explicit instruction to halt if a VAID
chain could not be mapped to RFC 8693 `act` claims unambiguously. §4 gives a
total, order-preserving construction directly from the chain structure
`vaid_mint.chain` already produces, with no case requiring a judgment call. The
halt condition was evaluated and does not apply.
