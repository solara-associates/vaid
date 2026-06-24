# vaid-pop

The proof-of-possession (PoP) signing primitive: the minimal, self-contained
surface an external client needs to authenticate a VAID-bound request.

## What it carries

- **`vaid_pop`** — the canonical signing primitive: RFC 8785 (JCS) → SHA-256 →
  pure Ed25519 over the 32-byte digest. `canonical_request_signing_bytes`,
  `sign_payload`, `verify_signed_payload`.
- **`request_auth`** — `RequestAuthPayload`, the exact camelCase payload a holder
  signs per request, plus the four `x-synthera-*` header names and `Principal`.
- **`VaidId` / `TenantId`** — the VAID identity newtypes the payload binds.
- **`ports::OperatorSigningPort`** — the signing port for keys held in external
  custody (sign the digest without the private key leaving its keystore), with its
  own minimal `OperatorSigningError`.

## Single source

This crate is the one home of the canonicalization primitive, so a signer
(`vaid-client`) and a conforming verifier agree byte-for-byte. Byte-identity
is locked by the frozen conformance vector; a change to the canonicalization is a
**major** version bump here by definition.

## License

Apache-2.0.
