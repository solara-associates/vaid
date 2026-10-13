# Changelog

All notable changes to the Python `vaid-jwt-bridge` package are documented
here. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [0.2.1] — UNRELEASED

### Changed

- Requires `vaid-mint>=0.11.0,<0.12`. `vaid-mint` 0.11.0 makes delegation
  depth a configurable `MintService` policy (defaulting to 1); this
  package's own behavior is otherwise unchanged. `exchange()` verifies
  exactly as before, under whatever depth the `MintService` a caller mints
  with is configured with. The test fixture that mints a three-hop chain
  (`tests/conftest.py`'s `three_hop_chain`) now configures
  `max_delegation_depth=2` explicitly, since the previous default minted a
  grandchild with no depth check at all. No other change in this release.

## [0.2.0] — UNRELEASED

> **Read this before upgrading. This release follows `vaid-mint` 0.10.0's
> BREAKING WIRE CHANGE and requires `sig_version` 4.** A `scope_boundary` entry
> is now a typed `{kind, value}` object rather than a bare string, so a v3
> credential cannot be exchanged here, and the `vaid` claim of an issued JWT now
> carries objects rather than strings in `scope_boundary`. A relying party
> reading that claim must be updated with the bridge. There is no
> dual-acceptance path and deliberately none to add. Taken pre-1.0 on purpose.
> See `docs/adr/0009-typed-extensible-scope-boundary.md`.

- Requires `vaid-mint>=0.10.0,<0.11`. Typed `scope_boundary` entries are
  constructed with `vaid_mint.document.prefix_entry`; `prefix` is the only kind
  v4 defines and its containment rule is ADR-0005's, unchanged.
- **New denial `DenialReason.UNKNOWN_SCOPE_KIND` (ADR-0009 S.10), and it closes
  the fail-open that mattered most.** `exchange()` now issues nothing when the
  leaf or a presented document carries a `scope_boundary` entry of a kind it does
  not recognise. The bridge authorises no specific resource, so there was no
  later containment check to fail closed, and `build_vaid_claim` copies
  `scope_boundary` verbatim into the issued token: without this step the bridge
  would mint a signed, audience-scoped JWT asserting a boundary it could not
  evaluate and hand it to a relying party even less likely to recognise the kind,
  laundering a narrowing constraint through a token that looks fully verified.
  Specified as step 2a in `docs/jwt/v1/profile.md` §2.
- The refusal is reported over an **authentic** document, never as `inauthentic`.
  An entry of an unknown kind is well formed and only its `kind` is unknown.
- `build_vaid_claim` now copies each boundary entry rather than only the list.
  Entries are objects since ADR-0009, so the previous `list(...)` aliased every
  entry and let a caller editing the returned claim reach into the verified leaf.
  It was a true snapshot while entries were strings.
- Every GHSA-hfjh-v2x2-r58v fix is unchanged: leaf and per-document trust-domain
  binding, `issuer_mismatch`, and strict unpadded base64url key decoding.

- **`FROZEN_CHAIN_SHA256` in the packaged firewall moves to `416b3240...`**, from
  `daa5c6cf...`. The frozen `chain_v1` chain was re-frozen at `sig_version` 4, so
  each hop's `scope_boundary` went from `["data.aifactory"]` to
  `[{"kind": "prefix", "value": "data.aifactory"}]` and the canonical bytes of all
  three documents moved. The canonicalization itself did not change.

  The new literal was derived rather than transcribed from a failing run:
  re-deriving it by the documented rule reproduces the previous value byte for
  byte when pointed at the v3 chain, and the same derivation over the v4 chain
  gives the new one. A third party recomputing the audit digest over the same
  three documents still agrees with the bridge; it is the documents that moved.
- The `vaid-mint` dependency ceiling moves to `>=0.10.0,<0.11`. The previous
  `<0.10` was correct and was doing its job: it said this package does not work
  with a typed boundary, which was true until this release.

## [0.1.0] — released 2026-10-12

Security fix: a trusted kernel key now vouches only for the trust domain it is
configured for (GHSA-hfjh-v2x2-r58v, reported by Tymofii Pidlisnyi, Agent
Passport System). This package has never been released, so there is no
published version carrying the defect and no version bump here.

- `exchange()` resolved the leaf's signing key by `kernel_key_thumbprint` alone
  and never compared the resolved key's configured trust domain against the
  `trust_domain` each document claimed. A document signed by a trusted key but
  naming a different trusted issuer's `trust_domain` was therefore exchanged for
  a JWT whose `sub`/`act`/`vaid` claims named an identity the signing issuer
  never granted, which a downstream gateway then honoured on the bridge's word.
  The binding is now enforced for the leaf and for every presented ancestor,
  denied as `issuer_mismatch`. This mirrors the `vaid-a2a` 0.1.1 fix and the
  verification order in `docs/a2a/v1/extension.md` section 5 rather than being a
  second design.
- `docs/jwt/v1/profile.md` section 2 step 4 was titled "Trust-domain binding per
  issuer key" but described `verify_chain_at`'s cross-key consent attestation and
  same-key parent binding. Those relate documents to each other; neither compares
  a document's claimed `trust_domain` against the domain the bridge's own trusted
  issuer config binds to the signing key. The profile now specifies the real
  binding as part of steps 1 and 3, states the deterministic order between them,
  and renames step 4 to what it actually is, with an explicit note that it does
  not satisfy steps 1 and 3.
- New `vaid_jwt_bridge.TrustedIssuers`: the trusted issuer config of profile
  section 1, holding each kernel key bound to the one trust domain it is trusted
  for. Entries use the A2A extension's `trustedIssuers` shape
  (`{"trustDomain": ..., "kernelPublicKey": "<unpadded base64url>"}`, section
  2.1), with `TrustedIssuers.from_raw_keys` for keys already held as bytes.
  `kernelPublicKey` is decoded as strict unpadded base64url to exactly 32 bytes:
  a padded, non-canonical, out-of-alphabet, empty or wrong-length value raises
  `vaid_jwt_bridge.TrustedIssuersConfigError` rather than being repaired or
  skipped, as do a non-object entry, an entry with no `trustDomain`, and the same
  key listed under two domains.
- **Breaking for callers:** `keys=` on `exchange()` and `BridgeConfig` no longer
  accepts a bare `vaid_mint.chain.KernelKeyMap` or `SingleKernelKey`. Such a
  resolver cannot name the domain a key is trusted for, so the binding could not
  be checked at all, and silently skipping it would leave the defect above open
  by omission. `BridgeConfig` refuses one in `__post_init__`, so a misconfigured
  deployment fails where an operator sees it rather than per-exchange. Any
  resolver answering both `resolve_key` and `trust_domain_for` is accepted, so a
  KMS-backed one remains possible. Migration: `SingleKernelKey(key)` becomes
  `TrustedIssuers.from_raw_keys([("your.trust.domain", key)])`.
- `tests/test_denials.py`'s same-key cross-trust-domain hop now denies
  `issuer_mismatch` rather than `chain_not_attenuated`, because the trust anchor
  binds each key to exactly one domain and so refuses at step 1, before chain
  verification is reached. `verify_chain_at`'s own `NOT_ATTENUATED` verdict for
  that shape stays pinned in `python/vaid-mint/tests/test_chain_verification.py`.
- `vaid-mint` dependency gains an upper bound (`>=0.9.0,<0.10`), required by
  `scripts/verify-dependency-bounds.mjs` (PR #118).
- No change to `vaid_mint`'s public API: the domain-to-key pairing is held here,
  which is the half `vaid_mint` documents as deliberately out of band (see
  `vaid_mint.mint.tenant_attenuates`).
- New `vaid-jwt-bridge-conformance` console entry point
  (`vaid_jwt_bridge.conformance`): the packaged firewall. It exchanges the
  frozen three-hop chain bundled in `vaid-mint`, verifies the issued JWT
  against the bridge's own published JWKS, and asserts the profile's claims
  including a frozen `chain_sha256` literal, plus seven denial paths each with
  a distinct reason. `release.yml` runs this executable against the published
  artifact, so the package could not have been released without it.

### What 0.1.0 ships

Initial release: a token bridge that verifies a full VAID delegation chain
and, only on a full pass, exchanges it (RFC 8693 token exchange) for a
short-lived standard JWT (EdDSA or ES256, selectable per deployment) a
gateway can verify against this bridge's published JWKS.

Normative profile: `docs/jwt/v1/profile.md` (v1, draft).
