# Changelog

All notable changes to the Python `vaid-a2a` package are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-pop`, `vaid-mint` and
`vaid-langchain`; a shared version number between them is a coincidence, not
a guarantee.

## [0.1.1]

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
