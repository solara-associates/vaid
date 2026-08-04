# Changelog

All notable changes to the Rust `vaid-client` crate are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This crate versions **independently** of `vaid-pop` and `vaid-mint`; a shared
version number between them is a coincidence, not a guarantee.

## [0.1.0]

Initial release: the VAID reference client SDK for Rust. First capability is
proof-of-possession request signing, byte-identical to any conforming verifier.

Read from the crate as published rather than described from memory, it exposes
`RequestSigner`, `PortRequestSigner`, `PopHeaders` and `PopError` from
`vaid_client::auth`.

It is also where the **signer** side of conformance is asserted. The crate vendors
`operator_pop_v1.json` and `pathquery_v1.json` and gates them with
`tests/conformance.rs` and `tests/pathquery_conformance.rs`. `vaid-pop` is the
signing *primitive* and depends on nothing here, so checking the signer from that
crate would invert the dependency — a packaging difference from Python, whose
signer ships in the same package as its primitive, and not a coverage gap in the
standard.

This is the only released version to date. Anything below it in git predates
publication.
