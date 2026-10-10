# REPORT-309: VAID token bridge (VAID chain in, standard JWT out)

Branch: `feat/vaid-jwt-bridge`. PR: https://github.com/solara-associates/vaid/pull/111

## What was built

A token bridge (`python/vaid-jwt-bridge`): it verifies a full VAID delegation
chain and, only on a full pass, exchanges it (RFC 8693 token exchange) for a
short-lived standard JWT a gateway verifies against a published JWKS with no
VAID-aware code in its request path. Not "VAID as a JWT end to end" — per
Allan's decision, the gateway trusts the bridge's verification, not any
individual hop of the original chain.

No tag, version bump, or release was made. `python/vaid-a2a` and
`vaid_mint` core were not touched.

## RFC 8693 mapping chosen

RFC 8693 SS4.1, read directly: *"The outermost `act` claim represents the
current actor while nested `act` claims represent prior actors. The least
recent actor is the most deeply nested."* A verified VAID chain is produced
root-first, leaf-last by `vaid_mint.chain`/`vaid_mint.revocation`
(`assemble_lineage`, `verify_chain_at`'s internal ordering). That gives a
total, unambiguous construction with no judgment call required:

- `sub` = the chain's root `vaid_id` (the RFC's "user" — the original
  authority everything else derives from).
- `act` = every hop after the root, nested oldest-innermost to
  leaf-outermost, built as `node = {"sub": h1}`, then
  `node = {"sub": hop, "act": node}` for each further hop toward the leaf.

Two degenerate cases fall out of the same construction with no
special-casing: a 2-node chain (`sub=root`, `act={"sub": leaf}`, no nested
`act.act`) and a 1-node chain (the leaf is its own root — no `act` claim at
all, since RFC 8693 SS4.1 exists to express delegation that did not occur).
Verified against the RFC's own worked example by substitution before being
adopted (`docs/jwt/v1/profile.md` SS4). The halt condition for an unmappable
chain was evaluated and does not apply (SS9).

Full normative spec: `docs/jwt/v1/profile.md`.

## Libraries chosen and why

- **jwcrypto** (producer side: JWK construction, JWS/JWT signing, RFC 7638
  thumbprints for `kid`). It is the one library in this evaluation that
  covers all three jobs — JWK build, EdDSA + ES256 signing, and standard
  thumbprinting — without hand-rolling JWK serialization or risking an
  `alg`/`kty`/`crv` mismatch. `Signer`/`JwcryptoSigner`
  (`vaid_jwt_bridge/keys.py`) wrap it behind a two-method seam so a future
  KMS-backed signer (never holding the private key in-process) can be
  dropped in without changing `exchange()`.
- **PyJWT** — used only in tests and the example, as an INDEPENDENT
  verifier: every round-trip test decodes the jwcrypto-issued token using
  ONLY the served JWKS, via a different JOSE implementation. This is a
  stronger proof than self-verification would be: it shows the token is
  genuinely standard-compliant, not merely consistent with the library that
  produced it.
- **Starlette** (optional `service` extra) for the HTTP layer — a bare ASGI
  toolkit with no templating/ORM/form-validation bundled in, matching this
  package's own posture: the library (`vaid_jwt_bridge.exchange`) has no
  web-framework dependency at all, so embedding it in another service pulls
  in nothing extra. There is exactly one request body to parse and two
  responses to shape; a batteries-included framework buys nothing here.
- **rfc8785** for `chain_sha256` — the same JCS canonicalization library
  `vaid_mint.document` already depends on, so a third party computing the
  digest independently uses the identical canonicalization rule.

## Claim set (issued JWT)

`iss`, `aud` (required, from the request, never invented), `iat`, `exp`
(default 5 minutes, hard-capped at `min(iat + ttl, leaf.expires_at)` — never
later than the leaf itself), `jti`, `sub`/`act` (RFC 8693, above), and a
`vaid` object: `vaid_id`, `trust_domain`, `scope_boundary`, `capability_set`
of the leaf, plus `chain_sha256` — a SHA-256 of the JCS-canonical verified
chain (root first, leaf last) so an auditor holding the same documents can
independently confirm what the bridge actually verified.

JWKS at `/.well-known/jwks.json`: both EdDSA (Ed25519) and ES256 (P-256)
keys are supported, selectable per deployment (or both together, for
rotation); `kid` is the RFC 7638 thumbprint (the IETF standard one, not
`vaid_mint`'s VAID-specific `kernel_key_thumbprint` — deliberately, since
this `kid` must be computable by a client that has never heard of VAID).

## Verification: fail closed, five steps

Re-derives (does not import) the same order `vaid_adk._verify`/
`vaid_a2a.verifier` already use, built only on `vaid_mint.chain`,
`vaid_mint.revocation`, `vaid_mint.document`, `vaid_mint.verify`: leaf
authenticity, leaf expiry, `verify_chain_at` (chain integrity, attenuation
to a trusted root, trust-domain binding, cross-key consent), revocation of
the full assembled lineage (re-checked on every exchange — never cached).
Any failure returns a typed `Denied`, never a partial or degraded token.
`RevocationCheck` is required constructor input with no default — a
deployment cannot build a working bridge without one.

## Tests

25 tests in `python/vaid-jwt-bridge`, all passing:

- EdDSA and ES256 round trips, each independently verified via PyJWT
  against the served JWKS (`test_exchange_eddsa.py`, `test_exchange_es256.py`,
  plus a combined-JWKS test).
- `act` nesting for a 3-hop chain, a 2-hop chain, and the no-delegation
  trivial chain (`test_act_nesting.py`).
- `exp` capping, both when the default TTL binds and when the leaf's own
  remaining life binds (`test_exp_boundary.py`).
- Denials, each confirmed to issue nothing: no leaf, missing audience,
  unsupported requested token type, tampered/inauthentic leaf, expired
  leaf, incomplete (unverifiable) chain, a child claiming wider authority
  than its parent, a same-key hop crossing trust domains, an untrusted
  issuer key, a revoked middle link, and revocation `UNAVAILABLE`
  (`test_denials.py`). The wider-than-parent and trust-domain cases use a
  `LocalMint` helper — the same pattern `vaid_mint`'s own
  `tests/test_chain_verification.py` uses — because `MintService` itself
  already refuses to mint either shape fail-closed; those two tests
  specifically prove the *bridge* also refuses an authentically-signed but
  adversarially-shaped chain, not merely that minting is guarded.
- Client-shaped HTTP tests against the real Starlette app (`test_service.py`):
  a full token-exchange + JWKS round trip, a denied exchange returning
  `invalid_grant` with no token fields, a wrong grant type, and a malformed
  `subject_token`.

Fixed seeds throughout (kernel key, every per-hop BYO key, both bridge
signing keys); `exchange(..., now=...)` is always passed an explicit
instant rather than defaulting to the wall clock. `vaid_mint`'s mint
functions have no `now` override of their own (a `vaid_mint` property, not
changed here), so a minted document's own timestamps are not fully
deterministic — noted explicitly in `tests/conftest.py`.

`python -m pytest python/vaid-pop python/vaid-mint python/vaid-langchain python/vaid-jwt-bridge`
(the exact CI `python` job command) passes all 233 tests together — checked
locally because adding a fourth package's `conftest.py`/test files to that
shared invocation hit a real collision with the existing rootless-import
scheme (sibling packages share a bare `conftest` module name, and a
`test_denials.py` basename already existed in `vaid-pop/tests`). Fixed by
giving only `python/vaid-jwt-bridge/tests/` an `__init__.py`, which makes
pytest import it under a qualified `tests.*` name instead of colliding with
the bare names other packages still use — no other package's files were
touched.

## CI status

All 16 checks on PR #111 pass, including two fixes required beyond the
package itself: `release-map.json` (required, per the task) and
`scripts/verify-package-versions.mjs`'s `REGISTRY_SCOPE` (discovered when
CI's "Capabilities manifest & claims-register verified" job failed —
`vaid-jwt-bridge` existed in the tree and in `release-map.json` but had no
`REGISTRY_SCOPE` entry; added the same way `vaid-a2a`/`vaid-adk` already
are, listed as "in flight", not released). The CI `python` pytest job was
also extended to install and run `python/vaid-jwt-bridge` alongside the
three packages it already covered — without that, nothing would have run
this package's tests in CI at all. `vaid-adk`/`vaid-a2a` are not in that
job either; that gap predates this PR and was left alone, out of scope.

## What is and is not verified about the gateway configs

`docs/jwt/v1/gateways.md` gives one snippet each for agentgateway
(Kubernetes `AgentgatewayPolicy`, field names `issuer`/`audiences`/
`jwks.remote.url`/`jwks.remote.cacheDuration`) and Envoy Gateway /
Envoy AI Gateway (`SecurityPolicy`, `jwt.providers[].issuer`/`audiences`/
`remoteJWKS.uri`). Every field name was checked against that project's
current published docs (linked in the file, with access dates). Neither
snippet was run against a live gateway — both are labeled
`UNTESTED AGAINST A LIVE GATEWAY` in the doc itself. One known gap is
flagged explicitly rather than filled by guessing: agentgateway's
*standalone* (non-Kubernetes) JWT config showed only a file-based JWKS
example in the page checked, so the doc does not claim a remote-URL field
name for that variant and says so.

## Halt conditions — not triggered

- VAID chain → RFC 8693 `act` mapping: unambiguous, see above and profile
  SS4/SS9. Not halted.
- No `vaid_mint` core change was needed anywhere in this work. Not halted.
- Every CI check that ran, passed; the two failures encountered during
  development (`REGISTRY_SCOPE`, the test-collection collision) were both
  caused by this change and fixed within this branch, not failures "for a
  reason outside this branch." Not halted.
