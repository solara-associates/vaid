# Changelog

All notable changes to the Python `vaid-a2a` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-pop`, `vaid-mint` and
`vaid-langchain`; a shared version number between them is a coincidence, not
a guarantee.

## [0.2.1] — UNRELEASED

### Changed

- Requires `vaid-mint>=0.11.0,<0.12`. `vaid-mint` 0.11.0 makes delegation
  depth a configurable `MintService` policy (defaulting to 1); this
  package's own behavior is otherwise unchanged. It mints and verifies
  exactly as before, under whatever depth the `MintService` it is handed
  is configured with. No other change in this release.

## [0.2.0] — UNRELEASED

> **Read this before upgrading. This release follows `vaid-mint` 0.10.0's
> BREAKING WIRE CHANGE and requires `sig_version` 4.** A `scope_boundary` entry
> is now a typed `{kind, value}` object rather than a bare string, so a v3
> credential does not verify here and `0.1.1` does not verify a v4 one. There is
> no dual-acceptance path and deliberately none to add; credentials carry a one
> hour default TTL, so the in-flight population expires on its own. Taken pre-1.0
> on purpose. See `docs/adr/0009-typed-extensible-scope-boundary.md`.

- Requires `vaid-mint>=0.10.0,<0.11`. Typed `scope_boundary` entries are
  constructed with `vaid_mint.document.prefix_entry`; `prefix` is the only kind
  v4 defines and its containment rule is ADR-0005's, unchanged.
- All 24 documents across the 12 vectors in `docs/a2a/v1/vectors/` are
  regenerated at `sig_version` 4 with typed boundaries, by re-running
  `generate_vectors.py`. Vector 12 still reports `issuer_mismatch`, and every
  other vector keeps the verdict it had: the typing changes the envelope, not the
  rule.
- **New denial `unknown_scope_kind` (ADR-0009 S.10), and it closes a fail-open.**
  `verify_a2a_message` now refuses any request where the leaf or a presented
  chain document carries a `scope_boundary` entry of a kind it does not
  recognise, and reports a verdict computed from no entries rather than from the
  ones it could read. The gap this closes: a ROOT leaf has no attenuation check
  run over it, and when `requested_action` is `None` the leaf's own scope is
  never consulted, so such a credential was previously ALLOWED while carrying a
  constraint the verifier could not evaluate. An unrecognised kind can only ever
  NARROW authority, so reading around it granted what the signer withheld.
  Checked after authenticity and expiry and before revocation, mirroring
  `vaid_mint.verify.verify_vaid_standing`; specified as step 2a in
  `docs/a2a/v1/extension.md` §5 and mapped in §6.
- The refusal is reported over an **authentic** document, never as `inauthentic`
  or `unparseable`. An entry of an unknown kind is well formed and only its
  `kind` is unknown, so calling it forged would be both false and unactionable.
- Every GHSA-hfjh-v2x2-r58v fix from `0.1.1` is unchanged: leaf and per-document
  trust-domain binding, `issuer_mismatch`, strict unpadded base64url key
  decoding, and `TrustedIssuersConfigError` on a missing `trustDomain` or a
  duplicated key.

- The vectors vendored into the wheel (`vaid_a2a/vectors/`) are re-vendored from
  the regenerated `docs/a2a/v1/vectors/`, so the packaged firewall runs against
  `sig_version` 4 bytes. The CI drift-check `cmp`s the two copies and compares the
  listings before the bytes.
- The `vaid-mint` dependency ceiling moves to `>=0.10.0,<0.11`. The previous
  `<0.10` was correct and was doing its job: it said this package does not work
  with a typed boundary, which was true until this release.

## [0.1.1] — released 2026-10-12

Security fixes to the reference verifier, reported by Tymofii Pidlisnyi (Agent
Passport System). `0.1.0` was never published, so this is the first version of
this package that exists anywhere outside the repository's own history.

- `trust_config.trustedIssuers` pairs a trust domain with a kernel key (spec
  section 2). The verifier now enforces that pairing for the leaf and every
  chain document: a document signed by a trusted key is accepted only if it
  also claims the trust domain that key is configured for. Previously only the
  key was checked, so a key trusted for one issuer's domain could vouch for a
  document claiming a different trusted issuer's domain. Denied as
  `issuer_mismatch`, the existing code for an untrusted issuer.
- `trust_config.trustedIssuers` entries without `trustDomain` are no longer
  accepted. Building the key resolver now raises
  `vaid_a2a.TrustedIssuersConfigError` for an entry missing `trustDomain`, and
  for the same kernel public key listed more than once (naming the key's
  thumbprint and every domain it was listed under), instead of silently
  skipping the entry or letting the last-seen domain win.
- The exact order of checks in `verify_a2a_message` is now specified
  (`docs/a2a/v1/extension.md` section 5): the leaf's own trust-domain binding
  is checked as part of step 1, before its signature; each presented chain
  document's trust-domain binding is checked as part of step 3, after the
  leaf has cleared steps 1-2. Previously the binding check ran over the leaf
  and every chain document in one pass, before the leaf's own signature was
  checked, so a leaf with an invalid signature could be denied
  `issuer_mismatch` instead of `inauthentic` whenever an unrelated,
  independently misbound chain document was also present. Both verifier and
  spec now agree, and a regression test pins the mixed case.
- `requested_action` is now a required keyword argument with no default.
  Skipping the requested-action scope check is still possible by passing
  `requested_action=None` explicitly, but it can no longer happen because a
  caller forgot the argument.
- The spec (`docs/a2a/v1/extension.md` section 5, step 3) no longer allows an
  agent to check only the leaf and skip chain verification for a request.
  Every step applies to every request; a chain that is missing where one is
  required is denied.
- The README's main example no longer uses
  `InMemoryRevocationList.assume_nothing_revoked()`. It now uses the default,
  never-populated `InMemoryRevocationList()`, which denies every request as
  `indeterminate` until the caller configures a real
  `vaid_mint.revocation.RevocationCheck`, so the copy-paste path stays
  closed, and the README says so plainly instead of silently assuming nothing
  is revoked. `assume_nothing_revoked()` remains, clearly labelled
  "local demo only, never production", in a separate example further down.
- `trustedIssuers` keys are now decoded strictly. The loader previously
  decoded `kernelPublicKey` with a permissive base64 decoder and never
  checked the decoded length, so three shapes spec section 2.1 rejects still
  loaded: `""` and `"!!!!"` both decoded to zero bytes (the decoder discards
  characters outside the alphabet) and were filed as a trusted zero-byte
  key, and a value decoding to 31 or 33 bytes was accepted and thumbprinted
  as if it were an Ed25519 public key. `kernelPublicKey` must now be strict
  unpadded base64url (alphabet only, no `=` padding, canonical encoding
  only) decoding to exactly 32 bytes, and anything else raises
  `vaid_a2a.TrustedIssuersConfigError` at load. Spec section 2.1 now states
  that rule exactly, and also states the already-enforced rejection of a
  `trustedIssuers` element that is not an object.
- New `vaid-a2a-conformance` console entry point (`vaid_a2a.conformance`): the
  packaged firewall. The 12 extension vectors now ship inside the wheel, so a
  consumer who installed only the wheel can replay them through
  `verify_a2a_message` and confirm the verdict the extension specifies for
  each, with no repository checkout. It pins verdicts rather than bytes, and
  asserts both polarities and a vector-count floor so a truncated or one-sided
  bundle cannot report a clean pass. `release.yml` runs this executable against
  the published artifact, so the package could not have been released without
  it.

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
