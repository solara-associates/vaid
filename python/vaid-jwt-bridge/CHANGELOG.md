# Changelog

All notable changes to the Python `vaid-jwt-bridge` package are documented
here. This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package versions **independently** of `vaid-mint`; a shared version
number between them is a coincidence, not a guarantee.

## [Unreleased]

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

## [0.1.0]

Initial release: a token bridge that verifies a full VAID delegation chain
and, only on a full pass, exchanges it (RFC 8693 token exchange) for a
short-lived standard JWT (EdDSA or ES256, selectable per deployment) a
gateway can verify against this bridge's published JWKS.

Normative profile: `docs/jwt/v1/profile.md` (v1, draft).
