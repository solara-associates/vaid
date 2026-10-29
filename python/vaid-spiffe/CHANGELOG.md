# Changelog

All notable changes to the Python `vaid-spiffe` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [0.1.0]

Initial release: mint a VAID over a verified SPIFFE X.509-SVID, bound by
reference rather than by key reuse (see the README "How it mints" section).

Depends on `vaid-mint>=0.11.0,<0.12` (the root-mint and BYO-key PoP path are
reused unmodified) and `spiffe>=0.3,<0.4` (the SPIFFE project's own Python
library, for SPIFFE ID / trust domain parsing - not reimplemented here).

Exposes `SpiffeMint`, `SvidPresentation`, `SpiffeMintResult`,
`verify_svid_chain` / `VerifiedSvid`, and `SvidPossession` /
`verify_svid_possession` / `build_svid_possession_payload` /
`canonical_svid_possession_bytes`.

This is the only released version to date. Anything below it in git predates
publication.
