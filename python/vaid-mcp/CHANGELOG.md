# Changelog

All notable changes to the Python `vaid-mcp` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint` and every other
package in this repo; a shared version number is a coincidence, not a
guarantee.

## [0.1.0] — UNRELEASED

### Added

- Initial MCP server: `verify_chain`, `explain_vaid_tool`, `check_scope_tool`,
  `mint_demo_chain_tool`. Stdio transport only. Depends on
  `vaid-mint>=0.11.0,<0.12` for every cryptographic and attenuation check;
  implements none of its own.
