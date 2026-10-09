# Changelog

All notable changes to the Python `vaid-a2a` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-pop`, `vaid-mint` and
`vaid-langchain`; a shared version number between them is a coincidence, not
a guarantee.

## [Unreleased]

Security fixes to the reference verifier, reported by Tymofii Pidlisnyi (Agent
Passport System):

- `trust_config.trustedIssuers` pairs a trust domain with a kernel key (spec
  section 2). The verifier now enforces that pairing for the leaf and every
  chain document: a document signed by a trusted key is accepted only if it
  also claims the trust domain that key is configured for. Previously only the
  key was checked, so a key trusted for one issuer's domain could vouch for a
  document claiming a different trusted issuer's domain. Denied as
  `issuer_mismatch`, the existing code for an untrusted issuer.
- `requested_action` is now a required keyword argument with no default.
  Skipping the requested-action scope check is still possible by passing
  `requested_action=None` explicitly, but it can no longer happen because a
  caller forgot the argument.
- The spec (`docs/a2a/v1/extension.md` section 5, step 3) no longer allows an
  agent to check only the leaf and skip chain verification for a request.
  Every step applies to every request; a chain that is missing where one is
  required is denied.
- The README's example now uses `InMemoryRevocationList.assume_nothing_revoked()`
  and explains why the plain, never-populated constructor denied every
  request, so a reader copying the example gets a working starting point
  rather than one that fails closed on everything.

## [0.1.0]

Initial draft: a reference verifier for the VAID A2A extension
(`docs/a2a/v1/extension.md`, status: draft). Exposes one function,
`verify_a2a_message`, over the existing `vaid_mint` primitives — no
`a2a-python` dependency, `Message` accepted as a plain `dict`.

Checks, in order: signature/authenticity, leaf expiry, chain integrity,
per-hop attenuation, requested-action scope, revocation. Fails closed on
every "could not determine" case, never folding it into a pass or a
specific denial.

Not released. Not registered for independent publication outside this
repository's own release workflow.
