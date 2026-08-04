# Changelog

All notable changes to the Python `vaid-pop` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written Python implementation — not a build or
mirror of the Rust crate or the npm package**. All three are versioned
independently and their numbers legitimately diverge; a shared version number is a
coincidence, not a guarantee. Byte-identity between the three is asserted by the
frozen conformance vectors, never by the version number.

## [0.2.0]

### Added — public-key-only verification

`verify_signed_payload` joins the public API. A holder of the signer's **public**
key can check a proof-of-possession offline — no service, no private key, no issuer
instance. This is the property the standard's positioning rests on, and until this
release the Python package could produce a PoP but not check one.

`tests/test_verify.py` covers it.

### Fixed

- Packaging: the `Author` metadata field was empty on PyPI. PEP 621 routes any
  author entry carrying an email entirely into `Author-email`, leaving `Author`
  unpopulated, so a name-only entry is needed alongside the one with the address.

## [0.1.0]

Initial release: the canonical Python proof-of-possession request signer.

Read from the package as published rather than described from memory, it exposes
`RequestSigner`, `canonical_request_signing_bytes`, `build_request_auth_payload`,
`utc_whole_second_rfc3339`, the completion-record pair `AssuranceTier` and
`build_completion_record`, and the four wire header constants (`HEADER_VAID`,
`HEADER_TIMESTAMP`, `HEADER_NONCE`, `HEADER_SIGNATURE`).

The signing primitive is RFC 8785 (JCS) → SHA-256 → Ed25519, byte-identical to the
Rust and TypeScript implementations against the frozen vectors.
