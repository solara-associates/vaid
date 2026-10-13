# Changelog

All notable changes to the Python `vaid-adk` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [0.2.0] — UNRELEASED

> **Read this before upgrading. This release follows `vaid-mint` 0.10.0's
> BREAKING WIRE CHANGE and requires `sig_version` 4.** A `scope_boundary` entry
> is now a typed `{kind, value}` object rather than a bare string, so a v3
> credential does not verify here. There is no dual-acceptance path and
> deliberately none to add; credentials carry a one hour default TTL, so the
> in-flight population expires on its own. Taken pre-1.0 on purpose. See
> `docs/adr/0009-typed-extensible-scope-boundary.md`.

- Requires `vaid-mint>=0.10.0,<0.11`. Typed `scope_boundary` entries are
  constructed with `vaid_mint.document.prefix_entry`; `prefix` is the only kind
  v4 defines and its containment rule is ADR-0005's, unchanged.
- **New denial `VerifyCode.UNKNOWN_SCOPE_KIND` (ADR-0009 S.10), and it closes a
  fail-open.** `verify_presentation` now refuses any call where the leaf or a
  presented chain document carries a `scope_boundary` entry of a kind it does not
  recognise. The gap this closes: a ROOT leaf has no attenuation check run over
  it, and when `requested_resource` is `None` the leaf's own scope is never
  consulted, so such a credential was previously ALLOWED while carrying a
  constraint the verifier could not evaluate. An unrecognised kind can only ever
  NARROW authority, so reading around it granted what the signer withheld.
  Checked after authenticity and expiry and before revocation, mirroring
  `vaid_mint.verify.verify_vaid_standing`.
- One unreadable entry refuses the **whole** boundary, even when another entry in
  the same boundary would have matched the requested resource. A union
  implemented as "at least one entry matched" finds the match and never reaches
  what it cannot read.
- The refusal is reported over an **authentic** document, never as `inauthentic`.
  An entry of an unknown kind is well formed and only its `kind` is unknown.
- Every GHSA-hfjh-v2x2-r58v fix is unchanged: leaf and per-document trust-domain
  binding, `issuer_mismatch`, strict unpadded base64url key decoding, and the
  T1/T2/T3 binding cases.

- The packaged firewall (`vaid-adk-conformance`) projects a boundary entry to a
  resource with `vaid_mint.document.entry_claimed_resource` before passing it as
  `requested_resource`. It indexed `scope_boundary[0]` and passed the entry
  through, which fed a `{kind, value}` object to `str.startswith` inside
  `scope_contains` once entries became typed. Reusing mint's own projection keeps
  the firewall from branching on `kind` differently from the matcher it tests.
- The `vaid-mint` dependency ceiling moves to `>=0.10.0,<0.11`. The previous
  `<0.10` was correct and was doing its job: it said this package does not work
  with a typed boundary, which was true until this release.

## [0.1.0] — released 2026-10-12

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
- New `vaid-adk-conformance` console entry point (`vaid_adk.conformance`): the
  packaged firewall. It replays the frozen three-hop chain bundled in
  `vaid-mint` and asserts one allowed outcome plus seven denials, each with a
  distinct code, together with the refusal of a trust resolver that cannot bind
  a domain to a key - the configuration half of the fix above. `release.yml`
  runs this executable against the published artifact, so the package could not
  have been released without it.

### What 0.1.0 ships

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
