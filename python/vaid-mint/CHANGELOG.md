# Changelog

All notable changes to the Python `vaid-mint` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written Python implementation — not a build or
mirror of the Rust `vaid-mint` crate**. The two are versioned independently, and
their changelogs are separate files (`crates/vaid-mint/CHANGELOG.md` covers Rust).
Where a change lands in both, as 0.1.2 does, each changelog documents its own
language's behavior.

## [0.1.2]

### ⚠️ Behavior change — expiry is now enforced (read this before upgrading)

**`ReferenceIssuer.verify_vaid` now rejects expired VAIDs.** Previously this
package did **not check expiry at all**: a well-signed but long-expired VAID would
**pass** `verify_vaid`, and there was no `is_expired` to check it with — a caller
who wanted expiry enforced had to parse `expires_at` themselves. As of 0.1.2 an
expired VAID returns `False` from `verify_vaid` even when its kernel signature is
valid.

**The API signature is unchanged, but this is a semantic break, not a routine
patch.** Semantic Versioning is not a safety guarantee here: **this is a breaking
behavioral change shipped under a patch version bump, and it is not safe to
auto-upgrade.** Pin deliberately, and read the next paragraph before you do.

**Who this breaks.** Any caller currently verifying long-lived VAIDs — or VAIDs
minted with a long `vaid_ttl_hours` and expected to keep verifying past that
window — will see previously-passing `verify_vaid` calls start returning `False`.
Nothing raises; the call simply returns `False` where it used to return `True`, so
this surfaces as an authorization failure at runtime rather than an import-time or
type-level error. If your code relies — deliberately or accidentally — on
expired-but-signed VAIDs continuing to verify, that behavior is gone. Any such
VAID that verified under 0.1.1 will now fail.

If you need to distinguish "forged" from merely "expired", call the new
`is_expired(vaid)` yourself before `verify_vaid`.

Action required: audit any flow that verifies long-lived or replayed VAIDs, and
confirm your issuance TTL is long enough for legitimate use before upgrading.

### Scope — cross-language parity restored

Published to PyPI as `vaid-mint` 0.1.2. This closes the gap disclosed at the Rust
crate's 0.1.2 release, when the seam and TTL enforcement existed only in Rust and
the PyPI package was still on 0.1.1: **both reference implementations now ship the
`RevocationCheck` seam and hard expiry enforcement**, and are at behavioral parity.

The two remain separate implementations versioned independently — a shared version
number is a coincidence, not a guarantee. Git tags are language-prefixed
(`python-v0.1.2` here, `rust-v0.1.2` for the crate); see `CONTRIBUTING.md`.

### Added

- **`revocation.RevocationCheck`** — a pluggable revocation seam consulted at
  verification time, defined as a `runtime_checkable` `Protocol` (mirroring the
  `AuthorizationGate` / `AuditSink` convention already used in this package).
  Inject a durable, restart-surviving backend via the new
  **`ReferenceIssuer.with_revocation_check`** without patching the package; it
  returns `self`, so it chains:
  `ReferenceIssuer.ephemeral(1).with_revocation_check(check)`.

  **The seam is additive, not a replacement.** The built-in in-memory revoked set
  remains the default and is **always consulted**; an injected check is consulted
  **in addition to** it, **never instead of** it. A VAID is rejected if **either**
  reports it revoked. Enabling the seam therefore never silently disables existing
  behavior, and there is no way to switch the built-in set off through this seam.
  - **`revocation.InMemoryRevocationList`** — a standalone, injectable in-memory
    implementation (non-durable; same guarantees as the built-in set). Exposes
    `revoke`, `is_revoked`, `__len__`, and `is_empty`.
  - **`revocation.NeverRevoked`** — an honest no-op implementation, available as
    an explicit opt-in. It is **not** the default: for revocation, a no-op default
    would be a functional regression (nothing checked), not a neutral "not wired
    yet" state, so the reference issuer keeps its working in-memory set as the
    default. This deliberately deviates from the `PermitAll` / `NoopAudit`
    convention; see the class's docs. Injecting it does **not** mean "this package
    performs no revocation checks" — the built-in set still runs.
- **`DEFAULT_VAID_TTL_HOURS`** (`= 1`) — the recommended baseline issuance TTL.
  With only non-durable revocation in this reference, a short TTL is the primary
  control that bounds a leaked or compromised VAID's exposure window. The
  `ReferenceIssuer` constructors still take an explicit `vaid_ttl_hours`.
- **`document.is_expired(vaid)`** — reports whether a document has passed its
  `expires_at`. New in Python (the Rust crate has had `Vaid::is_expired` as an
  informational check since 0.1.0). Available for callers who need to distinguish
  "forged" from "expired" before calling `verify_vaid`.
- `RevocationCheck`, `NeverRevoked`, `InMemoryRevocationList`,
  `DEFAULT_VAID_TTL_HOURS`, and `is_expired` are exported from the package root.

### Changed

- `verify_vaid` now hard-rejects expired VAIDs (see the behavior-change note
  above) and additionally consults any injected `RevocationCheck`. Its gating
  order now matches the Rust crate exactly: `sig_version` → **expiry** →
  built-in revoked set → **injected check** → signature verification.
- **Version metadata drift resolved.** `vaid_mint.__version__` had been left at
  `"0.1.0"` since the initial release while `pyproject.toml` advanced to `0.1.1`,
  so the published 0.1.1 package reported `__version__ == "0.1.0"` on
  introspection. Both now read `0.1.2` and agree.

### Notes

- **Additive at the API level.** No existing public signatures changed; the new
  seam is opt-in and the default construction path preserves the existing
  in-memory revocation behavior. The expiry enforcement is the one behavioral
  change, and it is not opt-in.
- **Revocation durability is still unsolved in this package.** The seam exists,
  but the shipped default remains in-memory and non-durable — it does not survive
  a restart. A durable, hash-chained store remains a property of the hosted
  authority. See the README "Trust model" section.
- The frozen mint conformance vector (`vaid_mint/vectors/mint_v1.json`) is
  unchanged; none of these changes touch the VAID document shape or signing bytes.
  All gating added here runs *before* signature verification.

## [0.1.1]

- Internal-vocabulary scrub: docstrings, README, and test-fixture naming
  (`substrate` → `managed authority`, `codex` → `acme` as the test tenant). No
  behavior or API change. Published to PyPI. Note: this release reported
  `__version__ == "0.1.0"` — see the drift note under 0.1.2.

## [0.1.0]

- Initial release. See git history.
