# Changelog

All notable changes to the Python `vaid-adk` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [Unreleased]

Security fix: a trusted kernel key now vouches only for the trust domain it is
configured for (GHSA-hfjh-v2x2-r58v, reported by Tymofii Pidlisnyi, Agent
Passport System). This package has never been released, so there is no
published version carrying the defect and no version bump here.

- `verify_presentation` resolved the kernel key by thumbprint alone and never
  compared the resolved key's configured trust domain against the
  `trust_domain` each document claimed. A document signed by a trusted key but
  naming a different trusted issuer's `trust_domain` was therefore accepted:
  one issuer's key vouching for another issuer's identity, with no forged
  signature and no compromised key. The binding is now enforced for the leaf
  and for every presented ancestor, denied as `issuer_mismatch`, the existing
  code for an untrusted issuer. This mirrors the `vaid-a2a` 0.1.1 fix and
  `docs/a2a/v1/extension.md` section 5 rather than being a second design.
- New `vaid_adk.TrustedIssuers`: the trust configuration this package verifies
  against, holding each kernel key bound to the one trust domain it is trusted
  for. Entries use the A2A extension's `trustedIssuers` shape
  (`{"trustDomain": ..., "kernelPublicKey": "<unpadded base64url>"}`, spec
  section 2.1), with `TrustedIssuers.from_raw_keys` for keys already held as
  bytes in the process. `kernelPublicKey` is decoded as strict unpadded
  base64url to exactly 32 bytes: a padded, non-canonical, out-of-alphabet,
  empty or wrong-length value raises `vaid_adk.TrustedIssuersConfigError`
  rather than being repaired or skipped, as do a non-object entry, an entry
  with no `trustDomain`, and the same key listed under two domains.
- **Breaking for callers:** `keys=` on `VaidAuthPlugin` and
  `verify_presentation` no longer accepts a bare `vaid_mint.chain.KernelKeyMap`
  or `SingleKernelKey`. Such a resolver cannot name the domain a key is trusted
  for, so the binding could not be checked at all, and silently skipping it
  would leave the defect above open by omission. It is refused with
  `TrustedIssuersConfigError` in `VaidAuthPlugin.__init__` rather than at the
  first request, so a missing control fails where an operator sees it. Any
  resolver answering both `resolve_key` and `trust_domain_for` is accepted, so
  a KMS- or directory-backed resolver remains possible. Migration:
  `KernelKeyMap([key])` becomes
  `TrustedIssuers.from_raw_keys([("your.trust.domain", key)])`.
- No change to `vaid_mint`'s public API: the domain-to-key pairing is held
  here, which is the half `vaid_mint` documents as deliberately out of band
  (see `vaid_mint.mint.tenant_attenuates`).
- `python/vaid-adk` is now run by CI's Python job. Its tests, these included,
  were not executed by any CI job before this change.

## [0.1.0]

Initial release: VAID verification for Google ADK.

A `BasePlugin` (`VaidAuthPlugin`) that verifies a presented VAID's
signature, expiry, delegation-chain attenuation and revocation status before
an ADK agent runs, before it is delegated to as a sub-agent, and before any
tool call. It maps the verified leaf's `scope_boundary` and
`capability_set` onto the tool being called via a required
`tool_authorizations` map, and denying fail-closed whenever any check
cannot be positively confirmed (missing VAID, unmapped tool, expired leaf,
unattenuated chain, unavailable revocation).

Depends only on `vaid-mint>=0.9.0` and `google-adk>=2.0,<3`. Reuses the
hook choice (`before_agent_callback` for delegation gating) proven in the
June 2026 ADK adapters in `forge-agents` (commit `85fdaa8`) and `synthera`
(commit `dd0503c`), extended to `before_tool_callback` for per-tool
authorization and registered through `BasePlugin` rather than per-agent
fields so no agent can be forgotten. Mints nothing; verification only.

This is the only released version to date.
