# vaid-pop

The proof-of-possession (PoP) signing primitive: the minimal, self-contained
surface an external client needs to authenticate a VAID-bound request.

## Install

```
cargo add vaid-pop
```

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

## Check the crate you received

Do not take byte-identity on trust. This crate ships the check as an executable,
so you can run it against the artifact you installed rather than against our
repository:

```console
$ cargo install vaid-pop
$ vaid-pop-conformance
CROSS-LANGUAGE PoP FIREWALL: PASS — installed signer == frozen vectors, byte-for-byte
  operator   digest    = ee474ba87d703ebeacf663d7d6a2f15319bdef285c5b702e336d0f4af5b61327
  operator   signature = 77e79744c362d352ce678992a3e3934fa57c33c3f307f6ffbe6ffc4ec5e726e0…
```

Exit `0` is PASS, `1` is a BLOCKER with a byte-level diff on stderr. The vectors
are compiled into the binary from the published crate, so no checkout and no
network are involved. The Python (`vaid-pop-conformance`) and TypeScript
(`npx -p vaid-pop vaid-pop-conformance`) packages ship the same executable and
print the same digests; that all three agree is the interoperability claim, and
running any two of them is how you verify it without us.

The request *signer* lives in `vaid-client`, so its conformance gate is
`cargo test -p vaid-client --test conformance` rather than this binary.

## License

Apache-2.0.
