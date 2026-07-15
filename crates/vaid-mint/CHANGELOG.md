# Changelog

All notable changes to `vaid-mint` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2]

### ⚠️ Behavior change — expiry is now enforced (read this before upgrading)

**`ReferenceIssuer::verify_vaid` now rejects expired VAIDs.** Previously, expiry
was *reported only* (via `Vaid::is_expired`) and a well-signed but expired VAID
would **pass** `verify_vaid`. As of 0.1.2 an expired VAID returns `false` from
`verify_vaid` even when its kernel signature is valid.

**The API signature is unchanged, but this is a semantic break, not a routine
patch.** If you depend on the `vaid-mint` **Rust crate** from crates.io and your
code relies — deliberately or accidentally — on expired-but-signed VAIDs
continuing to verify, that behavior is gone. Any such VAID that verified under
0.1.1 will now fail. If you need to distinguish "forged" from merely "expired",
call `Vaid::is_expired()` yourself before `verify_vaid`; the method is still there.

Action required: audit any flow that verifies long-lived or replayed VAIDs, and
confirm your issuance TTL is long enough for legitimate use before upgrading.

### Scope — Rust crate only; PyPI `vaid-mint` is NOT covered by this release

This 0.1.2 release covers the **Rust crate only.** The PyPI `vaid-mint` package
is a **separate, hand-written Python implementation — not a build or mirror of
this crate** — and it is **not** updated here. As of this release the PyPI
package remains on **0.1.1** and still has the **original, advisory-only expiry
behavior** that this release fixes in Rust: its `verify_vaid` does **not** reject
expired VAIDs, and it has **no `RevocationCheck` seam**. If you consume `vaid-mint`
from PyPI, you still have the revocation/expiry gap disclosed at launch —
upgrading is not yet possible on the Python side. Behavioral parity between the
Rust and Python implementations is broken until a follow-up ports these changes to
the Python package.

> **Update (superseded):** the follow-up has landed and is **published to PyPI**.
> The Python `vaid-mint` package **0.1.2** ports both changes — TTL is
> hard-enforced at verification and the `RevocationCheck` seam
> (`with_revocation_check`, `InMemoryRevocationList`, `NeverRevoked`,
> `DEFAULT_VAID_TTL_HOURS`) is available in Python. `pip install vaid-mint` now
> gets you the seam, and behavioral parity between the two implementations is
> restored.
>
> **The same ⚠️ expiry semantic break described above applies to the Python
> package as of 0.1.2** — audit any Python flow that verifies long-lived or
> replayed VAIDs before upgrading. See `python/vaid-mint/CHANGELOG.md`.
>
> The scope note above is retained as the historical record of what the Rust 0.1.2
> release itself covered.

### Added

- **`revocation::RevocationCheck`** — a pluggable, synchronous revocation seam
  consulted at verification time. Inject a durable, restart-surviving backend via
  the new **`ReferenceIssuer::with_revocation_check`** without patching the crate.
  The injected check is layered *in addition to* the built-in in-memory revoked
  set (a VAID is rejected if either reports it revoked), so enabling the seam
  never silently disables existing behavior.
  - **`revocation::InMemoryRevocationList`** — a standalone, injectable in-memory
    implementation (non-durable; same guarantees as the built-in set).
  - **`revocation::NeverRevoked`** — an honest no-op implementation, available as
    an explicit opt-in. It is **not** the default: for revocation, a no-op default
    would be a functional regression (nothing checked), not a neutral "not wired
    yet" state, so the reference issuer keeps its working in-memory set as the
    default. This deliberately deviates from the `PermitAll` / `NoopAudit`
    convention; see the type's docs.
- **`DEFAULT_VAID_TTL_HOURS`** (`= 1`) — the recommended baseline issuance TTL.
  With only non-durable revocation in this reference, a short TTL is the primary
  control that bounds a leaked or compromised VAID's exposure window. The
  `ReferenceIssuer` constructors still take an explicit `vaid_ttl_hours`.

### Changed

- `verify_vaid` now hard-rejects expired VAIDs (see the behavior-change note
  above) and additionally consults any injected `RevocationCheck`.

### Notes

- **Additive at the API level.** No existing public signatures changed; the new
  seam is opt-in and the default construction path preserves the existing
  in-memory revocation behavior.
- **Revocation durability is still unsolved in this crate.** The seam exists, but
  the shipped default remains in-memory and non-durable — it does not survive a
  restart. A durable, hash-chained store remains a property of the hosted
  authority. See the README "Trust model" section.
- The frozen mint conformance vector (`tests/vectors/mint_v1.json`) is unchanged;
  none of these changes touch the VAID document shape or signing bytes.

## [0.1.1]

- Prior release. See git history.
