# Changelog

All notable changes to the Python `vaid-langchain` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-pop` and `vaid-mint`; a shared
version number between them is a coincidence, not a guarantee.

## [0.1.0]

Initial release: a LangChain request-signing adapter for the VAID standard.

Read from the package as published rather than described from memory, it exposes
three names — `VaidAuth`, `make_vaid_tool`, and `request_target` — and depends on
`vaid-pop>=0.1.0`, which it reuses verbatim rather than reimplementing the signing
primitive. Signing every outbound agent HTTP request with a VAID
proof-of-possession happens through a thin `httpx.Auth` seam, so the adapter sits
beside the HTTP client rather than inside the agent framework.

This is the only released version to date. Anything below it in git predates
publication.
