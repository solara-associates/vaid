# Changelog

All notable changes to the Python `vaid-mint` package are documented here. This
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This package is a **separate, hand-written Python implementation — not a build or
mirror of the Rust `vaid-mint` crate**. The two are versioned independently, and
their changelogs are separate files (`crates/vaid-mint/CHANGELOG.md` covers Rust).
Where a change lands in both, as 0.1.2 does, each changelog documents its own
language's behavior.

## [0.3.0]

### Changed — VAID v3: the document names its issuer and commits to its key (BREAKING)

ADR-0004. `VAID_SIG_VERSION_V3 = 3`. A v2 document does not verify under this
release and a v3 document does not verify under 0.2.0; a clean break, not a
migration.

- **`trust_domain`** — the issuing deployment's DNS-shaped name, validated at
  issuer construction. Compared by byte equality and never normalized: the value
  is inside the signed bytes, so a verifier that "corrects" it recomputes
  different bytes from the ones the signer covered.
- **`kernel_key_thumbprint`** — RFC 9278 thumbprint URI over the RFC 7638 JWK
  thumbprint of the signing key. **Derived at mint, never supplied.**
- **`verify_vaid_authenticity` now also checks key commitment**, ordered before
  the signature check.

Pinned against the **published RFC 8037 Appendix A.3 vector**, and proven to
produce a thumbprint byte-identical to the Rust and TypeScript implementations
before the conformance vector was re-frozen.

### Changed — `mint_v1` re-frozen at v3 (BREAKING for anyone pinning the digest)

    old digest a5d73cf487b4eade190acdae31e61322a83dae5639b6891ede3a8d32af0bbf86
    new digest eef6c92fed497f5a2fc9abfc781b74da62bd54b8c66a2fcb6e7915d2d95d22f0

### Fixed — `is_expired` no longer raises from a function that promises a `bool`

`is_expired` is now **total** and never raises. It previously raised `ValueError`
from a function whose signature promises a `bool`, with no mention in the
docstring, so callers did not guard against it.

`has_conforming_timestamps` is the new explicit `encoding.md` E.6 profile check,
so a caller wanting strictness asks for it and can distinguish the two failures
(issue #10).

### Note on the 0.2.0 → 0.3.0 gap

This package's manifest sat at `0.2.0` while `__version__` already read `0.3.0`:
the v3 work bumped the code and the TypeScript package but missed this manifest
and this changelog. PyPI therefore served a v2 `vaid-mint` while the repository's
code was v3. The `verify-internal-versions` gate caught the self-disagreement;
this release resolves it in the honest direction, since the code really is v3.

## [0.2.0]

### Added — public-key-only document verification (additive, non-breaking)

- **`verify_vaid_authenticity(kernel_public_key: bytes, vaid: dict) -> bool`** and
  **`verify_lineage_hash(vaid: dict) -> bool`** (module `verify`), mirroring the Rust
  `vaid_mint::verify`. A third party holding only an issuer's kernel **public** key can
  confirm a VAID document is authentic — no `ReferenceIssuer`, no private key. Scope is
  authenticity + `lineage_hash` consistency; it does **not** check expiry and does
  **not** consult revocation. (Separately, the Python `vaid-pop` package gains
  `verify_signed_payload`, the request-PoP verifier it previously lacked — Rust already
  had it.)

### ⚠️ Breaking — the `RevocationCheck` seam is replaced (read this before upgrading)

**The 0.1.2 boolean, leaf-only `RevocationCheck` is gone, replaced by a
three-state, lineage-aware seam** per `docs/spec/revocation.md` R.4. A deliberate,
authorised breaking change, mirroring the Rust `vaid-mint` 0.2.0.

- **`RevocationCheck.is_revoked(vaid_id) -> bool` → `check_lineage(list[str]) ->
  RevocationStatus`.** The check is handed the full ordered lineage (root first,
  leaf last) and returns `RevocationStatus.{NOT_REVOKED, REVOKED, UNAVAILABLE}`.
  Custom backends must be updated.
- **Revocation is inherited (R.4.4).** A VAID is revoked if **any** VAID in its
  lineage is; revoking a parent now rejects every child attenuated from it. The
  0.1.2 leaf-only check did not — a bypass.
- **Fail closed on `UNAVAILABLE` (R.4.5).** An incomplete lineage (e.g. an empty
  resolver after restart) or an unreachable store rejects rather than passing
  silently. No fail-open option ships in this release.
- **`NeverRevoked` removed.** It was a boolean-era no-op footgun.
- **`ReferenceIssuer` records every mint** (roots as well as children) so it can
  act as the verifier-side `LineageResolver` (R.4.2). New: `revocation_status`,
  `resolve_parent`, `clear_lineage`; `is_revoked`/`parent_of` removed.
  `with_revocation_check` now *replaces* the consulted store.
- **Document bytes are unchanged.** No conformance vector changes; revocation
  remains outside the conformance surface (R.1).

### Migration — porting a custom `RevocationCheck`

Before (0.1.2) — a boolean, leaf-only check:

```python
class MyBackend:
    def is_revoked(self, vaid_id: str) -> bool:
        return vaid_id in self.deny_list
```

After (0.2.0) — three-state, handed the full ordered lineage:

```python
class MyBackend:
    def check_lineage(self, lineage: list[str]) -> RevocationStatus:
        try:
            deny = self.load_deny_list()
        except StoreUnreachable:
            return RevocationStatus.UNAVAILABLE
        if any(vaid_id in deny for vaid_id in lineage):
            return RevocationStatus.REVOKED
        return RevocationStatus.NOT_REVOKED
```

Why the shape changed:

- **A boolean cannot express `UNAVAILABLE`.** When the backing store is
  unreachable, `is_revoked` had to answer `True` or `False`, and `False` is a
  silent fail-open. `RevocationStatus` makes "could not determine" a first-class
  outcome that verification fails closed on.
- **A leaf-only check is bypassable by minting a child.** `is_revoked(vaid_id)`
  saw only the presented leaf, so revoking a parent left its attenuated children
  verifiable. `check_lineage` receives the whole ancestry; a VAID is revoked if any
  ancestor is.

The default in-memory store's constructor is renamed `initialised_empty` →
`assume_nothing_revoked` to state its (fail-open-on-restart) posture rather than its
state. `NeverRevoked` is removed.

## [0.1.3]

### Docs only — no behavior change

Identical in behavior to 0.1.2. This release exists solely to replace the
README rendered on the package's PyPI page.

- **Corrected a stale upgrade note.** The README bundled in the 0.1.2 sdist
  said *"0.1.2 is not yet on PyPI — `pip install vaid-mint` still serves
  0.1.1"*. That was true when written but was overtaken by the 0.1.2 PyPI
  publish itself, leaving the 0.1.2 page asserting its own non-existence.
  The note was corrected in git immediately after that publish, but a
  README is baked into the uploaded artifact, so the correction could not
  reach PyPI without a new version.
- **The CHANGELOG link now resolves on PyPI.** It was relative
  (`CHANGELOG.md#012`), which only works on GitHub; it is now absolute.

No code, API, wire-format, or conformance-vector change. The Rust
`vaid-mint` crate is unaffected and stays at 0.1.2 — its README never
carried the note.

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
