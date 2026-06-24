# vaid-client

The Synthera VAID client SDK for Rust. This crate is the seed of a general client
SDK, not a single-purpose signer: its first shipped capability is
proof-of-possession (PoP) request signing; the HTTP-calling surface against a
deployment is the intended next inhabitant.

```rust
use vaid_client::RequestSigner;
use ring::signature::Ed25519KeyPair;

// `vaid_json` is the VAID document; `key` is its Ed25519 key pair.
let signer = RequestSigner::from_vaid_json(vaid_json, key)?;
let headers = signer.sign_headers("POST", "/v1/agents/execute", body)?;
for (name, value) in headers.into_pairs() {
    // attach `name: value` to your outbound request
}
# Ok::<(), vaid_client::PopError>(())
```

Two signing strategies, for two key custodies:

- `RequestSigner` — holds a raw `ring` Ed25519 key pair (a tenant holding its own
  private key).
- `PortRequestSigner` — defers signing to an `OperatorSigningPort` (an external
  key store: the key never leaves its keystore).

## Byte-identity

Canonicalization is **not** reimplemented here — it reuses the `vaid-pop`
primitive, so this client and a conforming verifier derive identical signing bytes
by construction. Byte-identity is locked by the vendored vector
`tests/vectors/operator_pop_v1.json`, which the conformance test reproduces
exactly.

Contract: RFC 8785 (JCS) over the camelCase `RequestAuthPayload` → SHA-256 →
pure Ed25519 over the 32-byte digest → raw 64-byte signature.

## Versioning

Independent semver. Bump **major** on any change to the PoP canonicalization /
wire shape — it breaks byte-identity against the conformance vector. Depends on
`vaid-pop`, which must be published first.

## License

Apache-2.0.
