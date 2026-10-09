# Session 307: vaid-a2a security fix (GHSA-hfjh-v2x2-r58v)

Private advisory fork: https://github.com/solara-associates/vaid-ghsa-hfjh-v2x2-r58v
Branch: `fix/trust-domain-binding`
PR (private, within the fork): https://github.com/solara-associates/vaid-ghsa-hfjh-v2x2-r58v/pull/1
Reporter: Tymofii Pidlisnyi (Agent Passport System, GitHub: aeoess)

Ran unattended. No questions were asked; the decisions Allan delegated in the
task are recorded under "Decisions made on Allan's behalf" below.

## Clone verification

Cloned the fork to `~/solara/vaid-s307` with `gh repo clone`. Confirmed the
clone contains PR #109 (`feat(a2a): explicit verification_time on vectors;
spec states empty-set rules`, merge commit `0fb85e4`) before starting work.
No halt condition.

## Blast radius

Checked whether the trust-domain-binding gap (a key accepted for one domain
vouching for a document claiming a different domain) exists anywhere besides
`vaid_a2a.verifier`:

- **vaid-mint core, all three languages** (`python/vaid-mint`,
  `crates/vaid-mint`, `typescript/vaid-mint`): `KernelKeyMap` and
  `SingleKernelKey` resolve a key by thumbprint only, with no multi-domain
  binding concept at all. This is by design.
  `vaid_mint.mint.tenant_attenuates`'s docstring states explicitly that the
  domain-to-key binding is "out-of-band" and that `vaid_mint` enforces
  tenant/domain containment between parent and child, never an external
  binding to a published issuer registry. No other language exposes a
  `trustedIssuers`-shaped structure for this to even apply to.
- **vaid-langchain**: client-side request signing only (`VaidAuth`,
  `RequestSigner`). No verification path, no key resolver.
- **skill (the `vaid` CLI, TypeScript)**: its `verify-core.mjs` looks up a
  single key per document by the document's own claimed thumbprint, against
  a thumbprint-keyed anchor (`trust-anchor.json` and `trusted-keys.json`).
  There is no per-entry trust-domain field in that anchor to bind against.
  `trust-anchor.json`'s own `$note` explains the one published key's
  `trust_domain` (`substrate.internal`) is deliberately omitted from the
  anchor precisely because no domain-to-key binding has been published yet.
  There is no declared binding for this verifier to fail to enforce.

Conclusion: the gap is isolated to `vaid_a2a.verifier`, the only place in the
codebase that accepts a `trustedIssuers`-shaped `{trustDomain, kernelPublicKey}`
list (spec section 2) and is supposed to enforce that pairing. No halt
condition; fixed within scope.

## Fixes

### 1. Trust domain not bound to key

`_build_key_resolver` previously built a `vaid_mint.chain.KernelKeyMap` from
only the key bytes in each `trustedIssuers` entry, discarding `trustDomain`.
A document signed by any trusted key, claiming ANY trust domain (including
one bound to a different trusted issuer), passed signature and authenticity
checks.

Fix: replaced `KernelKeyMap` with a local `_TrustedIssuerMap` that keeps the
`(key, trustDomain)` pairing, keyed by the key's own derived thumbprint (same
derivation rule as before, never from a caller-supplied thumbprint).
`verify_a2a_message` now checks, for the leaf and every document presented
in `/vaidChain`, that the document's claimed `trust_domain` equals the
domain its signing key's thumbprint is configured for in
`trust_config.trustedIssuers`. A mismatch denies with
`VerifyCode.ISSUER_MISMATCH`, the existing code this module already uses
for "this issuer is not in trust_config.trustedIssuers", since a key trusted
for domain X is, by this fix, not trusted for domain Y either.

The check runs before signature verification and before
`verify_chain_at`, over `(leaf, *chain_raw)`, so it catches a misbound
document whether it is the leaf or any ancestor, and does not depend on
whether that document ends up on the assembled chain path.

Diff: `python/vaid-a2a/vaid_a2a/verifier.py`. New `_TrustedIssuer` and
`_TrustedIssuerMap` classes, rewritten `_build_key_resolver`, new
binding-check loop in `verify_a2a_message`.

### 2. Spec section 5 step 3, leaf-only clause

Removed: "An agent that does not require chain verification for this
request MAY check only the leaf (steps 1-2 and step 6 against the leaf's
own authority) and skip to step 7." Replaced with a normative statement
that every step applies to every request, and that a missing chain where
one is required is `UNVERIFIABLE`/denied, never a fallback to leaf-only
checking, because ancestor revocation can only be established by walking
the chain. `Status: draft` is unchanged; step 4's empty-set rules (from
#109) are unchanged.

The Python reference verifier already called `verify_chain_at`
unconditionally regardless of whether `/vaidChain` was present, so this is a
spec-text-only change; no code behavior changed.

Diff: `docs/a2a/v1/extension.md`, section 5.

### 3. `requested_action=None` default

`verify_a2a_message`'s `requested_action` parameter had a default of `None`,
so a caller who forgot the argument silently skipped the scope check.
Changed to a required keyword argument with no default
(`requested_action: str | None,`, still nullable, just not optional).
Updated the docstring, the module example (`examples/guard.py` already
passed it explicitly), and every existing test call site to pass the
argument explicitly.

Diff: `python/vaid-a2a/vaid_a2a/verifier.py`, `python/vaid-a2a/tests/test_verifier.py`.

### 4. README example denies everything

The `## Use` example passed `InMemoryRevocationList()`, an empty,
never-populated store, which is `UNAVAILABLE` by design and therefore fails
closed on every request. Replaced with
`InMemoryRevocationList.assume_nothing_revoked()` plus a comment explaining
the difference and where a real revocation source (a database, a feed)
plugs in via `vaid_mint.revocation.RevocationCheck`.

Diff: `python/vaid-a2a/README.md`.

## Decisions made on Allan's behalf

- None beyond what the task already specified. Finding 1's fix used
  `VerifyCode.ISSUER_MISMATCH` (no new code added), matching the task's
  instruction to reuse the most fitting existing code.
- Finding 2's spec change required no corresponding code change, since the
  Python implementation never had a leaf-only code path to remove. Noted
  here rather than silently assumed.

## Tests

Added to `python/vaid-a2a/tests/test_verifier.py`, built with seeds
`0x42` and `0x99` (not copies of the reporter's files):

- `test_root_signed_by_a_trusted_key_claiming_the_wrong_domain_is_denied`.
  The reported bug: a standalone root signed by issuer B's key (bound to
  `other.example`), claiming issuer A's domain (`vaid.example`). Now denies
  with `ISSUER_MISMATCH`.
- `test_root_signed_by_a_trusted_key_claiming_its_own_domain_is_allowed`.
  Honest control: same two-issuer trust config, B's key, B's own domain.
  Allows.
- `test_cross_key_hop_claiming_the_parents_domain_is_denied`. A genuine
  cross-key delegation from A to B with a valid, correctly-scoped consent
  attestation (every existing `vaid_mint.chain` check passes), where the
  leaf claims A's domain while signed by B's key (bound to `other.example`).
  Denies with `ISSUER_MISMATCH`, isolating the new check from the existing
  consent and attenuation machinery.
- `test_requested_action_cannot_be_omitted`. A call omitting
  `requested_action` now raises `TypeError`.
- `test_readme_example_allows`. Runs the corrected README example and
  pins that it allows.

Also updated 5 existing test call sites to pass `requested_action=None`
explicitly (now required).

Full local run, four packages:

```
python -m pytest python/vaid-pop python/vaid-mint python/vaid-a2a python/vaid-langchain
226 passed
```

(`langchain-core` installed as an optional dependency for `vaid-langchain`'s
suite. Without it, 3 unrelated pre-existing tests in that package fail with
`ModuleNotFoundError`, independent of this change.)

No file under `docs/a2a/v1/vectors/` was read or modified. `test_vectors.py`
(6 vectors plus a coverage guard) still passes unchanged.

CI note: `.github/workflows/ci.yml`'s `python` job installs and tests only
`vaid-pop`, `vaid-mint` and `vaid-langchain`. `vaid-a2a` is not wired into
CI yet (consistent with it being an unreleased draft package). No CI check
exists for this package to run locally beyond the pytest suite above.

## Commits

- `38d90e4`: `fix(a2a): bind trust_config.trustedIssuers domains to keys`
  (branch `fix/trust-domain-binding`, pushed to the fork)

## What was not done (ground rules)

- Nothing merged, tagged, released, or published to any registry.
- No change under `docs/a2a/v1/vectors/`.
- No push, branch, issue, or PR anywhere other than this private fork.
- No em-dashes introduced in `docs/a2a/v1/extension.md`'s new text,
  `python/vaid-a2a/CHANGELOG.md`, or this report.
