# vaid-jwt-bridge

A **token bridge** for the VAID standard (https://github.com/solara-associates/vaid):
it verifies a full VAID delegation chain and, only if verification fully
passes, issues a short-lived standard JWT that a gateway can verify against
a published JWKS using any ordinary JWT library — no VAID code in the
gateway's request path.

This is deliberately **not** "VAID as a JWT end to end". A gateway holding
one of these JWTs is trusting the bridge's verification, not any individual
hop of the original chain. The normative profile is
[`docs/jwt/v1/profile.md`](../../docs/jwt/v1/profile.md) at the repository
root; this package implements it.

## What it checks before it issues anything

Reusing only `vaid_mint` primitives (same verification order as
`vaid_adk`/`vaid_a2a`, re-derived rather than imported — see
`vaid_jwt_bridge/exchange.py`):

1. the leaf's **trust-domain binding** — its claimed `trust_domain` equals the
   domain its `kernel_key_thumbprint` is bound to in `keys` — and only then the
   leaf VAID's signature, against the key that thumbprint resolved to;
2. the leaf's own expiry;
3. each presented ancestor's own trust-domain binding, by the same rule, and
   then full chain integrity and attenuation back to a trusted root
   (`vaid_mint.chain.verify_chain_at`), which additionally requires consent on
   any cross-key hop;
4. revocation of **every** VAID in the assembled lineage.

The order is load-bearing: step 1 reaches its verdict on the leaf alone before
step 3 examines any presented document, so a leaf whose own signature does not
verify is `inauthentic` regardless of what else was presented alongside it.

Any failure issues nothing. There is no partial or degraded JWT, and no
fail-open default anywhere in this package — a deployment with no
`RevocationCheck` configured cannot construct a working bridge at all.

## Issued JWT shape

- `iss`, `aud`, `iat`, `exp`, `jti` — ordinary JWT claims. `exp` is short
  (5 minutes by default) and is **never later than the leaf's own
  `expires_at`** — a leaf closer to expiry than the default TTL gets a JWT
  that expires exactly when the leaf does.
- `sub` / `act` — an RFC 8693 actor-delegation chain built directly from the
  verified VAID chain: `sub` is the chain's root, and each further hop is
  one level of `act`, nested so the current (leaf) actor is outermost and
  the earliest delegate is most deeply nested — see profile §4 for why this
  mapping is total and unambiguous.
- `vaid` — the leaf's own `vaid_id`, `trust_domain`, `scope_boundary`,
  `capability_set`, and `chain_sha256`: a hash over the canonical verified
  chain so an auditor holding the same documents can independently confirm
  what was verified.

## Keys: EdDSA and ES256, selectable per deployment

Both Ed25519 (`alg: EdDSA`) and NIST P-256 (`alg: ES256`) signing keys are
supported; a deployment configures whichever it wants (or both, for a
rotation), and the JWKS at `/.well-known/jwks.json` publishes exactly the
public keys configured. `vaid_jwt_bridge.keys.Signer` is a small seam
specifically so a signer backed by a cloud KMS (which never puts the private
key in this process at all) can be dropped in later without changing
`exchange()` or the service.

```python
from vaid_jwt_bridge import load_signer_from_file, KeyRing

signer = load_signer_from_file("signing-key.pem")  # Ed25519 or P-256 PEM
keyring = KeyRing([signer])
```

## Trust anchor: a key is trusted for one domain

`keys` is a `TrustedIssuers`, and each kernel key in it is bound to the **one
trust domain it is trusted for** (profile section 1). A document signed by a
trusted key is accepted only if it also claims that key's domain.

Binding matters because without it a trusted key vouches for any domain a
document cares to claim. Given two legitimately trusted issuers, A and B, a
document signed by B's key while claiming A's `trust_domain` verifies perfectly
against B's key, and the bridge signed a JWT whose `sub`/`act`/`vaid` claims
named A's identity — which a downstream gateway then honoured on the bridge's
word. No forged signature and no compromised key anywhere in the attack
(GHSA-hfjh-v2x2-r58v).

Two spellings of the same configuration:

```python
# From config: the VAID A2A extension's `trustedIssuers` shape
# (docs/a2a/v1/extension.md section 2.1), so one operator's trust
# configuration reads the same across A2A, ADK and this bridge.
keys = TrustedIssuers([
    {"trustDomain": "vaid.example",  "kernelPublicKey": "IVL40Zt5HSRF..."},
    {"trustDomain": "other.example", "kernelPublicKey": "My6-jSfLcyOz..."},
])

# From key bytes already held in the process.
keys = TrustedIssuers.from_raw_keys([("vaid.example", kernel_public_key)])
```

`kernelPublicKey` is decoded as **strict unpadded base64url to exactly 32
bytes**. A padded, non-canonical, out-of-alphabet, empty or wrong-length value
raises `TrustedIssuersConfigError`, as do a non-object entry, an entry with no
`trustDomain`, and the same key listed under two domains. One domain may hold
several keys (an issuer rotating); one key may not hold two domains.

A bare `vaid_mint.chain.KernelKeyMap` or `SingleKernelKey` is **not** accepted
as `keys`. Those resolve a key by thumbprint and cannot say which domain it is
trusted for, so the binding could not be checked at all; `BridgeConfig` refuses
one when the deployment is configured, so the gap cannot be left open by
omission. Any resolver answering both `resolve_key` and `trust_domain_for` is
accepted, so a KMS-backed one remains possible.

## Library usage

```python
from vaid_jwt_bridge import (
    ExchangeRequest,
    TrustedIssuers,
    exchange,
    load_signer_from_file,
)
from vaid_mint.revocation import InMemoryRevocationList

signer = load_signer_from_file("signing-key.pem")
result = exchange(
    ExchangeRequest(leaf=leaf_vaid, chain=(), audience="https://api.example.com"),
    keys=TrustedIssuers.from_raw_keys([("vaid.example", kernel_public_key)]),
    revocation=InMemoryRevocationList.assume_nothing_revoked(),
    issuer="https://bridge.example.com",
    signer=signer,
)
```

`result` is either `Issued` (`access_token`, `expires_in`, ...) or `Denied`
(`reason`, `detail`) — never an exception for an ordinary verification
failure. See `examples/quickstart.py` for a full 3-hop chain exchanged end
to end and verified independently with `PyJWT` against the served JWKS.

## HTTP service (optional, `pip install vaid-jwt-bridge[service]`)

`vaid_jwt_bridge.service.build_app` builds a Starlette ASGI app exposing:

- `POST /token-exchange` — RFC 8693 token exchange
  (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token_type=urn:vaid:params:oauth:token-exchange:token-type:vaid-chain-v1`).
- `GET /.well-known/jwks.json` — the JWKS this deployment's `KeyRing`
  publishes.

The library (`vaid_jwt_bridge.exchange`) has no web-framework dependency;
the `service` extra is only for running this bridge as its own process.
Gateway-side configuration examples (agentgateway, Envoy AI Gateway) are in
[`docs/jwt/v1/gateways.md`](../../docs/jwt/v1/gateways.md).

## What this package does not do

- It does not mint VAIDs. It only verifies a chain someone else minted.
- It does not implement its own revocation backend; `RevocationCheck` is
  required configuration, supplied by the deployment (`vaid_mint.revocation`
  ships an in-memory one for tests and local development).
- It does not cache issued tokens, and re-checks revocation on every
  exchange — see profile §7.
