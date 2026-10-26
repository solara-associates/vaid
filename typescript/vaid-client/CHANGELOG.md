# Changelog

All notable changes to the npm `vaid-client` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written TypeScript implementation — not a build
or mirror of the Rust `vaid-client` crate**. The two version independently and
their numbers legitimately diverge; at the time of writing this package is at 0.3.0
and the crate at 0.1.0, and that is correct rather than drift. Byte-identity
between the implementations is asserted by the frozen conformance vectors, never by
the version number.

## [0.3.1]

No code changes. This release exists to publish once through npm trusted
publishing — the 0.3.0 release above predates the trusted publisher being
configured on this package and used a classic npm token instead. `0.3.1` is the
first `vaid-client` publish carrying automatic npm provenance (a signed
attestation binding the published tarball to the workflow, repository and
commit that built it — see `.github/workflows/release.yml`), and the publish
itself is what confirms the trusted publisher configured on npmjs.com for this
package actually works, which until now had been configured but never
exercised.

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
