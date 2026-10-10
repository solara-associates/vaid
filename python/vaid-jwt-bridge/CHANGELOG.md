# Changelog

All notable changes to the Python `vaid-jwt-bridge` package are documented
here. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [0.1.0]

Initial release: a token bridge that verifies a full VAID delegation chain
and, only on a full pass, exchanges it (RFC 8693 token exchange) for a
short-lived standard JWT (EdDSA or ES256, selectable per deployment) a
gateway can verify against this bridge's published JWKS.

Normative profile: `docs/jwt/v1/profile.md` (v1, draft).
