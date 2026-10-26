# Changelog

All notable changes to the npm `vaid-pop` package are documented here. This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written TypeScript implementation — not a build
or mirror of the Rust crate or the Python package**. All three are versioned
independently and their numbers legitimately diverge; a shared version number is a
coincidence, not a guarantee. Byte-identity between the three is asserted by the
frozen conformance vectors, never by the version number.

## [0.3.1]

No code changes. This release exists to publish once through npm trusted
publishing — the 0.3.0 release above predates the trusted publisher being
configured on this package and used a classic npm token instead. `0.3.1` is the
first `vaid-pop` publish carrying automatic npm provenance (a signed attestation
binding the published tarball to the workflow, repository and commit that built
it — see `.github/workflows/release.yml`), and the publish itself is what
confirms the trusted publisher configured on npmjs.com for this package actually
works, which until now had been configured but never exercised.

## [0.3.0]

**The first release published to npm**, and the only one to date.

The package sat at `0.2.0` in the repository before this and was never published at
that version — `0.3.0` is where it entered the registry. The tree records the
version numbers but not the reasoning for starting there, so no rationale is
offered here; `git log typescript/vaid-pop/package.json` is the record.

Contents at publication, read from the published package rather than recalled: the
VAID proof-of-possession signing primitive — RFC 8785 (JCS) → SHA-256 → Ed25519,
byte-identical to the Rust and Python implementations against the frozen vectors —
plus the `vaid-pop-conformance` executable, so a consumer with only
`npm install vaid-pop` can prove the primitive they received reproduces those
vectors without a checkout.
