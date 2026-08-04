# Changelog

All notable changes to the npm `vaid-client` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written TypeScript implementation — not a build
or mirror of the Rust `vaid-client` crate**. The two version independently and
their numbers legitimately diverge; at the time of writing this package is at 0.3.0
and the crate at 0.1.0, and that is correct rather than drift. Byte-identity
between the implementations is asserted by the frozen conformance vectors, never by
the version number.

## [0.3.0]

**The first release published to npm**, and the only one to date.

The package sat at `0.2.0` in the repository before this and was never published at
that version — `0.3.0` is where it entered the registry. The tree records the
version numbers but not the reasoning for starting there, so no rationale is
offered here; `git log typescript/vaid-client/package.json` is the record.

Contents at publication, read from the published package rather than recalled: the
VAID proof-of-possession request signer, which signs requests into the four
`x-synthera-*` PoP headers byte-identically to the Rust and Python clients. It
ships `operator_pop_v1.json` and `pathquery_v1.json`, and the
`vaid-client-conformance` executable, so a consumer with only
`npm install vaid-client` can prove the signer they received reproduces those
vectors without a checkout.
