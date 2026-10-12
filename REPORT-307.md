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

## Follow-up 2

Four items of reviewer feedback from Tymofii Pidlisnyi on PR #1, all
addressed on `fix/trust-domain-binding`. None of A, B, C or D was already
in place on the branch before this follow-up: checked each against the
branch at `adb434d` (the commit "docs: add session 307 report") before
writing anything, and none raised a config error for a duplicate key or a
missing `trustDomain`, section 5 step 3 did not mention `ISSUER_MISMATCH`,
the check order was not documented, and the README's main example still
used `assume_nothing_revoked()`. All four required new work; none skipped.

### A. Duplicate key / missing trustDomain configuration errors

`_build_key_resolver` (`python/vaid-a2a/vaid_a2a/verifier.py`) now raises a
new `TrustedIssuersConfigError` (exported from `vaid_a2a`) for either shape,
instead of silently skipping the entry or letting a later duplicate's domain
win:

- An entry with a parseable `kernelPublicKey` but no `trustDomain` raises,
  naming the key.
- The same kernel public key listed more than once (any domains, equal or
  different) raises, naming the key's derived thumbprint and every trust
  domain it was listed under.

Moved the call to `_build_key_resolver` to the top of `verify_a2a_message`,
before any metadata-shaped early return, so a malformed `trust_config`
always raises, whether or not the particular message being checked happens
to carry a VAID. (Without this move, a config error would have gone
unnoticed on any request with no VAID present, since the function returned
before ever building the key resolver.)

Spec section 2 gained a new "§2.1 `trustedIssuers` validity" subsection
stating both rules normatively. Exact wording:

> Each `trustedIssuers` entry pairs exactly one kernel key with exactly one
> trust domain. A conforming implementation MUST reject the following
> shapes as a configuration error, at the point this list is loaded, rather
> than accept a narrowed or best-guess reading of it:
>
> - **An entry with no `trustDomain`.** A kernel key with no trust domain
>   attached binds to nothing, so accepting it would leave every document's
>   claimed `trust_domain` effectively unchecked for that key. Entries
>   without `trustDomain` are not accepted.
> - **The same kernel public key listed more than once.** Whichever
>   `trustDomain` a lookup happened to resolve to last would otherwise
>   decide, silently, which domain that key is actually trusted for. The
>   error MUST name the key (its derived thumbprint) and every trust domain
>   it was listed under, so the operator can see the conflict directly
>   rather than re-deriving it from the raw configuration.
>
> These two rules apply before anything in section 5 runs: a `trustedIssuers`
> list that violates either one is a defect in the agent's own
> configuration, not a property of any particular incoming request.

CHANGELOG line (`python/vaid-a2a/CHANGELOG.md`):

> `trust_config.trustedIssuers` entries without `trustDomain` are no longer
> accepted. Building the key resolver now raises
> `vaid_a2a.TrustedIssuersConfigError` for an entry missing `trustDomain`,
> and for the same kernel public key listed more than once (naming the
> key's thumbprint and every domain it was listed under), instead of
> silently skipping the entry or letting the last-seen domain win.

Tests: `test_duplicate_key_across_trust_domains_raises` (asserts the
thumbprint and both domains appear in the message),
`test_entry_missing_trust_domain_raises`.

### B. Spec section 5 step 3: explicit binding, ISSUER_MISMATCH in its list

Step 1 ("Signature") now states the leaf's own binding check explicitly and
names `ISSUER_MISMATCH` as its outcome. Step 3 ("Chain integrity") now states
the same rule for every presented chain document and names `ISSUER_MISMATCH`
there too, rather than leaving it implied only by step 1's list. Exact new
wording for step 1 and step 3 (`docs/a2a/v1/extension.md` section 5):

> 1. **Signature.** First, the leaf VAID's own binding: its claimed
>    `trust_domain` MUST equal the trust domain that its
>    `kernel_key_thumbprint` is bound to under §2's `trustedIssuers` (never
>    the other way round, since a key is trusted for the domain
>    `trustedIssuers` pairs it with, not for any domain a document cares to
>    claim). A thumbprint resolving to no entry, or resolving to an entry
>    bound to a different domain, is `ISSUER_MISMATCH`. Only once that
>    binding holds does the leaf VAID's Ed25519 kernel signature get
>    checked, against the key that same thumbprint resolved to. Equivalent
>    to `vaid_mint.verify.verify_vaid_authenticity_graded`. Any
>    `UNPARSEABLE`, `UNSUPPORTED_SIG_VERSION`, `MALFORMED_TRUST_DOMAIN`,
>    `ISSUER_MISMATCH`, `LINEAGE_INCONSISTENT` or `INAUTHENTIC` result fails
>    the request; see §6 for the specific error returned. This step is
>    scoped to the leaf alone: it MUST reach its own verdict (`INAUTHENTIC`
>    or otherwise) without being affected by any defect in a chain document
>    considered under step 3.
> 2. **Expiry / TTL.** [unchanged]
> 3. **Chain integrity back to a trusted root.** For each document presented
>    in `/vaidChain`, its own binding is checked first, the same rule as
>    step 1: its claimed `trust_domain` MUST equal the trust domain its own
>    `kernel_key_thumbprint` is bound to under `trustedIssuers`. A document
>    whose thumbprint resolves to a different bound domain is
>    `ISSUER_MISMATCH`, the same code step 1 uses for the leaf's own binding
>    failure, applied here to a chain document instead. Only then does
>    chain integrity proceed: every ancestor named by a signed `parent_vaid`
>    is present in `/vaidChain`, every document in the chain is itself
>    authentic under a trusted key, and no ancestor has passed its own
>    `expires_at` at the verification instant. Equivalent to
>    `vaid_mint.chain.verify_chain_at` through the point where it would
>    return `INAUTHENTIC`, `UNVERIFIABLE` or `EXPIRED`.

### C. Deterministic check order

Confirmed the reviewer's report against the code at `adb434d`: the binding
check ran as a single loop over `(leaf, *chain_raw)` before step 1's
signature check, so a leaf with a bad signature returned `ISSUER_MISMATCH`
(from a wrong-domain chain document) rather than `INAUTHENTIC`, whenever
such a chain document happened to be presented alongside it. The order was
incoherent: the leaf's own result should not depend on an unrelated
document elsewhere in the request.

Changed code and spec together, per the task's instruction for an
incoherent order:

- The leaf's own trust-domain binding check moved into step 1, immediately
  before (not instead of) the leaf's signature check, so step 1 reaches a
  verdict on the leaf alone before anything about `/vaidChain` is examined.
- The per-document trust-domain binding check for `/vaidChain` moved into
  step 3, running only after the leaf has cleared steps 1-2, and scoped to
  `chain_raw` only (not the leaf, already settled).

Net effect: a bad leaf signature is always `INAUTHENTIC`, regardless of
what else is presented in `/vaidChain`; a wrong-domain chain document is
`ISSUER_MISMATCH` only once the leaf itself has already passed. Spec
section 5 states this ordering explicitly in a new paragraph under step 3
("The order is deterministic, and this is why it matters in practice"),
quoted in full in section B above (step 3's trailing paragraph).

Regression test: `test_bad_leaf_signature_wins_over_a_wrong_domain_chain_document`.
A leaf whose signature does not verify against its own correctly-bound key
(signed by the wrong of two trusted keys), presented alongside a standalone
chain document that is independently misbound to the wrong domain. Asserts
`VerifyCode.INAUTHENTIC`, pinned to the documented order, never
`ISSUER_MISMATCH`.

### D. README revocation

Removed `InMemoryRevocationList.assume_nothing_revoked()` from the README's
main `## Use` example. It now passes the default, never-populated
`InMemoryRevocationList()`, which is `UNAVAILABLE` by design and denies
every request `indeterminate`, including a fully valid one, until the
caller configures a real `vaid_mint.revocation.RevocationCheck`. Added a
paragraph stating this plainly directly under the example, and a new
"Configuring real revocation" subsection showing a minimal
`RevocationCheck` implementation (a `check_lineage` method that queries a
caller's own store and returns `UNAVAILABLE` on any error, never
`NOT_REVOKED`).

`assume_nothing_revoked()` is kept in a new subsection titled "Local demo
only, never production", with a `# LOCAL DEMO ONLY, NEVER PRODUCTION.`
comment on the snippet itself.

Renamed and split the README example test to match: `test_readme_example_allows`
(which asserted the old, now-removed example's behaviour) became
`test_readme_main_example_denies_as_indeterminate` (runs the main example as
written, asserts `VerifyCode.INDETERMINATE`, `allowed is False`) and
`test_readme_local_demo_example_allows` (runs the local-demo snippet,
asserts `VerifyCode.ALLOWED`, `allowed is True`), so the test suite now
follows the main example's actual, intentionally-closed behaviour, not the
behaviour it had before this follow-up.

### Tests

Full local run, four packages (same command as the first session 307
report; `langchain-core` installed as an optional dependency, same
pre-existing caveat noted there):

```
PYTHONPATH=.../vaid-pop:.../vaid-mint:.../vaid-a2a:.../vaid-langchain \
  python3 -m pytest python/vaid-pop python/vaid-mint python/vaid-a2a python/vaid-langchain
230 passed
```

(229 after the first session 307 report's 226 plus the 5 new/changed
`vaid-a2a` tests for this follow-up: A adds 2, B adds 0 new tests of its
own (covered by C's regression test and A/existing tests), C adds 1, D
replaces 1 test with 2, net +4 over the 226 baseline, 230 total.)

No file under `docs/a2a/v1/vectors/` was read or modified. No change to
`vaid_mint` core in any language. `test_vectors.py` still passes unchanged.

### Decisions made on Allan's behalf

- Duplicate-key detection treats ANY repeat of the same kernel public key as
  an error, including a hypothetical repeat under the *same* domain, not
  only a repeat across two different domains. The task's title ("Duplicate
  key across trust domains") names the exploitable case, but the stated
  mechanism ("the same kernel public key appears more than once") does not
  itself require the domains to differ, and a benign-looking duplicate
  entry is still a configuration mistake worth surfacing rather than
  silently accepting.
- Moved `_build_key_resolver`'s call to the top of `verify_a2a_message`
  (before the metadata-shaped early returns) so that a malformed
  `trust_config` always raises. This was necessary for finding A's own
  tests to pass: calling `verify_a2a_message` with `{"metadata": {}}` (no
  VAID present) previously returned early, before the key resolver was
  ever built, so a bad `trust_config` would have gone unnoticed on exactly
  that kind of request. Not explicitly requested, but required to make the
  stated behaviour ("raise a clear configuration error when trustedIssuers
  is loaded") actually hold for every call, not only calls that also
  happen to carry a VAID.

### Ground rules re-confirmed

- Private fork only; no release, no publish, no tag.
- No change under `docs/a2a/v1/vectors/`.
- No `vaid_mint` core change, in any language.
- No em-dashes introduced in this follow-up's new text in
  `docs/a2a/v1/extension.md`, `python/vaid-a2a/CHANGELOG.md`, or this report
  (also swept and cleaned from the new text added to `verifier.py` and
  `tests/test_verifier.py` in this follow-up, as a precaution beyond what
  was strictly asked).

## Follow-up 3

Reviewer Tymofii Pidlisnyi confirmed `e7f174f` fixes the issue. Three items
before publishing: a PR head mismatch to resolve first, a section 5 wording
amendment, and a stricter, loader-matching section 2.1.

### Item 1: PR #1 head mismatch

Before any change, `gh api repos/.../pulls/1` and `gh pr view 1` both
reported PR #1's head SHA as `adb434d`, while the local `fix/trust-domain-
binding` branch (and `origin`'s copy of it, confirmed via `git ls-remote`
and `GET /git/refs/heads/fix/trust-domain-binding`) was already at
`b369dd8`, a fast-forward descendant of `adb434d` that already contains
`e7f174f`. `git merge-base --is-ancestor adb434d b369dd8` confirmed the
ancestry; `pushed_at` on the PR's head repo (`2026-10-10T08:24:07Z`) is
after both `e7f174f` and `b369dd8`'s commit timestamps, consistent with
the push having already landed. `gh pr list --json ... ,isCrossRepository`
reported `true` for PR #1, but the head repository's GraphQL node ID
(`R_kgDOVCU4Cw`) is identical to the base repository's own node ID, so
head and base are the same repository and the same branch
(`fix/trust-domain-binding`); `isCrossRepository: true` here is an
artifact of how a GHSA private-fork PR is represented internally, not
evidence of a second fork. The PR's reported `head_sha` was simply a
stale read on GitHub's side of a branch that had already moved forward;
there were no commits to push that the branch did not already have.

This follow-up's own commit (`c8157ce`, see below) was pushed as an
ordinary fast-forward of the already-current branch. Re-querying both
the REST and GraphQL endpoints afterward shows the PR's head catching up
immediately:

| | repo | branch | SHA |
|---|---|---|---|
| Before this follow-up's push | `solara-associates/vaid-ghsa-hfjh-v2x2-r58v` | `fix/trust-domain-binding` | `adb434dff13aa08506753a9bb1b9a807a85110ee` (stale API read; live branch was already at `b369dd8`) |
| After this follow-up's push | `solara-associates/vaid-ghsa-hfjh-v2x2-r58v` | `fix/trust-domain-binding` | `c8157ce275c824209aa258fe2fc796c8a8e8503d` |

`git merge-base --is-ancestor e7f174f c8157ce` confirms `e7f174f` is an
ancestor of the new head. No force-push was used or needed; no commits
belonging to anyone else were at risk.

### Item 2: section 5 order wording

Code unchanged, as asked. `docs/a2a/v1/extension.md` section 5 gained one
paragraph, inserted between the introductory paragraph and numbered step 1,
stating that input-shape validation precedes the ordered steps and that the
order governs only input that has already parsed:

> **Input-shape validation comes first, before step 1.** Malformed input,
> meaning the `/vaid` metadata value present but not a VAID document
> object, or `/vaidChain` present but not a list of VAID document objects
> (a value such as `[null]` is such a case: a list, but not a list *of
> documents*), is rejected as `UNPARSEABLE` before step 1 is ever reached.
> This is not itself one of the numbered, ordered steps below; it is a
> precondition on them. The ordering stated for steps 1 onward governs
> only input that has already parsed into the expected shapes. It says
> nothing about, and makes no claim about, the relative order of two
> different malformed-shape rejections, because that question does not
> arise until parsing has already succeeded.

Two new regression tests in `python/vaid-a2a/tests/test_verifier.py` pin
both halves of the claimed input, reusing the same bad-signature leaf
(`_bad_signature_leaf`, a leaf claiming issuer A's domain and thumbprint
but signed by issuer B's key):

- `test_bad_leaf_signature_with_empty_chain_is_inauthentic`: bad leaf
  signature, `vaidChain: []` -> `VerifyCode.INAUTHENTIC`.
- `test_bad_leaf_signature_with_unparseable_chain_is_unparseable`: the same
  bad leaf signature, `vaidChain: [None]` -> `VerifyCode.UNPARSEABLE`.

No change was needed in `verifier.py`'s behaviour for this item: the
existing shape check on `/vaidChain` (lines before step 1's comment block)
already ran ahead of the authenticity check; only the spec's wording and
the pinning tests were missing.

### Item 3: section 2.1 and the loader, made stricter and brought into agreement

Before this follow-up, `_build_key_resolver` (`python/vaid-a2a/vaid_a2a/
verifier.py`) silently `continue`d past (skipped) a `trustedIssuers` entry
with no parseable `kernelPublicKey`: an empty object `{}`, an entry
naming only `trustDomain`, or an entry whose key string failed
base64url-decoding, rather than raising `TrustedIssuersConfigError`, the
same exception already used for a missing `trustDomain` or a duplicate
key. That asymmetry meant section 2.1's two documented rules and the
loader's actual behaviour disagreed on a third shape neither named.

`_build_key_resolver` now raises `TrustedIssuersConfigError` for all of:
an entry that is not an object, an entry with no `kernelPublicKey` field,
an entry whose `kernelPublicKey` is present but not a string, and an
entry whose `kernelPublicKey` string cannot be base64url-decoded, in
addition to the two cases already raised (no `trustDomain`; the same key
listed under more than one domain).

`docs/a2a/v1/extension.md` section 2.1 gained a third bullet, listing this
rule alongside the two it already stated, and its closing sentence now
says "any one of them" rather than "either one", since there are now
three rules, not two.

Four new tests in `test_verifier.py`:

- `test_entry_empty_dict_raises`: `trustedIssuers: [{}]` raises.
- `test_entry_trust_domain_only_raises`: `trustedIssuers:
  [{"trustDomain": ...}]` (no key at all) raises.
- `test_entry_unparseable_key_raises`: `kernelPublicKey: "a"` (one data
  character, a length base64 padding can never fix) raises.
- `test_valid_config_still_loads`: the existing two-issuer well-formed
  config still loads without raising (control).

### Tests

Full local run across all four Python packages, in a fresh venv with each
package installed editable (`pip install -e python/vaid-mint -e
python/vaid-a2a -e python/vaid-pop -e python/vaid-langchain`, plus
`langchain-core` for the optional `vaid-langchain` suite, same
pre-existing environment note as the earlier follow-ups):

```
python/vaid-mint:      185 passed
python/vaid-a2a:        28 passed
python/vaid-pop:         9 passed
python/vaid-langchain:  14 passed
-----------------------------------
Total:                 236 passed, 0 failed
```

(28 in `vaid-a2a` is follow-up 2's 22 plus this follow-up's 6 new tests:
2 for item 2's ordering regression, 4 for item 3's loader strictness.)

No file under `docs/a2a/v1/vectors/` was read or modified. No change to
`vaid_mint` core in any language.

### Commit and push

Commit `c8157ce` ("fix(a2a): reviewer follow-up 3 (loader strictness on
kernelPublicKey, order wording)") on `fix/trust-domain-binding`, pushed as
an ordinary fast-forward. PR #1's head SHA, re-queried via both the REST
and GraphQL APIs after the push, is `c8157ce275c824209aa258fe2fc796c8a8e8503d`,
the exact commit pushed, confirmed to contain `e7f174f` as an ancestor.

### Ground rules re-confirmed

- Private fork only; no release, no publish, no tag.
- No change under `docs/a2a/v1/vectors/`.
- No `vaid_mint` core change, in any language: this follow-up touched only
  `docs/a2a/v1/extension.md` and the `vaid-a2a` package.
- No force-push used; the one push in this follow-up was an ordinary
  fast-forward of a branch that was already current.
- No em-dashes introduced in this follow-up's new text in
  `docs/a2a/v1/extension.md`, `python/vaid-a2a/vaid_a2a/verifier.py`,
  `python/vaid-a2a/tests/test_verifier.py`, or this report section.

## Follow-up 4

Reviewer Tymofii Pidlisnyi approved publishing, with two items to close
first: the loader was still decoding `kernelPublicKey` non-strictly despite
section 2.1 saying an undecodable key is rejected at load, and the package
needed a version for the advisory.

Head SHA: `1cb9a32c9d2de32461efd54520eaac042da3a80b`, the commit carrying
the code, spec and version change. The commits after it on this branch are
docs-only appends to this report, so they advance PR #1's head without
touching any shipped file; the Commit and push section below lists them and
the API confirmation for each push.

### Item 1: strict key decoding

Confirmed the reviewer's finding before changing anything.
`_build_key_resolver` called `_b64url_decode`, which re-padded the string
and handed it to `base64.urlsafe_b64decode`. That decoder runs without
`validate=True`, so it **discards** every character outside the base64
alphabet rather than rejecting it, and nothing checked the decoded length.
Three shapes section 2.1 rejects therefore still loaded:

- `""` re-padded to `""`, decoded to `b""`, and was filed under
  `kernel_key_thumbprint(b"")` as a trusted zero-byte key.
- `"!!!!"` had all four characters discarded, decoded to `b""`, and loaded
  identically. Follow-up 3's own test used `"a"`, which raises only because
  one data character is an impossible base64 length, so it never exercised
  the discard path at all.
- A value decoding cleanly to 31 or 33 bytes was accepted and thumbprinted
  as if it were an Ed25519 public key, which it cannot be.

`_b64url_decode` is replaced by `_strict_b64url_decode`
(`python/vaid-a2a/vaid_a2a/verifier.py`), which rejects:

- any character outside the unpadded base64url alphabet (`A`-`Z`, `a`-`z`,
  `0`-`9`, `-`, `_`), `=` padding included, and the empty string, by
  `fullmatch` against `[A-Za-z0-9_-]+` before any decode;
- an impossible length (`len % 4 == 1`), which surfaces as the
  `binascii.Error` the existing `except` clause already caught;
- a non-canonical encoding, checked by re-encoding the decoded bytes
  unpadded and comparing against the input. Re-encoding rather than masking
  the final character's bits asserts the property that matters directly:
  this string is the one and only base64url spelling of these bytes, so the
  thumbprint an operator derives by hand from the configured text is the one
  the loader files the key under.

The loader then requires `len(key_bytes) == _ED25519_PUBLIC_KEY_BYTES` (32).
Both failures raise `TrustedIssuersConfigError`, with the raw value and,
for the length case, the actual byte count in the message.

Six new tests in `python/vaid-a2a/tests/test_verifier.py`, each asserting
`TrustedIssuersConfigError` with a well-formed `trustDomain` present so the
failure can only be the key:

- `test_entry_empty_string_key_raises`: `""`.
- `test_entry_non_base64url_characters_raise`: `"!!!!"`.
- `test_entry_key_one_byte_short_raises`: a 31-byte key.
- `test_entry_key_one_byte_long_raises`: a 33-byte key.
- `test_entry_not_an_object_raises`: a `trustedIssuers` element that is a
  string and one that is a number. The loader has raised for this since
  follow-up 3, but nothing pinned it, so a regression to `entry.get` on
  either would have surfaced as `AttributeError` or `TypeError` rather than
  as a configuration error. This is the missing test the reviewer asked for.
- `test_valid_32_byte_key_still_loads`: the control. A well-formed entry
  whose key is exactly 32 bytes in unpadded base64url still loads, and the
  call still returns `NO_VAID`, allowed.

Checked by hand against the new loader, beyond the test suite: `"a"`
(impossible length), a correctly-sized but `=`-padded 44-character key, and
a 43-character key whose final character carries non-zero trailing bits all
raise; a valid 32-byte key loads and resolves its trust domain.

#### Exact new section 2.1 wording

`docs/a2a/v1/extension.md` section 2.1 keeps its opening paragraph, its
`trustDomain` and duplicate-key bullets and its closing paragraph unchanged.
The first bullet is replaced, and one bullet is added before it. Verbatim,
the two bullets as they now read:

```
- **An entry that is not an object.** `trustedIssuers` is a list of objects
  (§2). A string, a number or any other non-object element names neither a
  key nor a domain, so it is rejected rather than skipped.
- **An entry with no parseable `kernelPublicKey`.** `kernelPublicKey` MUST be
  present, MUST be a string, and MUST be **strict unpadded base64url**
  decoding to **exactly 32 bytes**, the length of a raw Ed25519 public key.
  Strict means exactly three things: the value uses only the unpadded
  base64url alphabet (`A`-`Z`, `a`-`z`, `0`-`9`, `-` and `_`), carries no
  `=` padding, and is the canonical encoding of its bytes, so the unused low
  bits of its final character are zero. Every other shape is a configuration
  error: no `kernelPublicKey` field at all (`{}`), an entry that names only a
  `trustDomain`, a non-string value, the empty string, any character outside
  the alphabet, a padded or non-canonical encoding, and a value that decodes
  cleanly but to any length other than 32 bytes. A loader MUST NOT use a
  permissive base64 decoder that discards characters outside the alphabet:
  `"!!!!"` is not a key, and a decoder that returns zero bytes for it has
  accepted one. A thumbprint alone is not key material (§2's
  `trustedIssuers` row), so there is no reading of any of these entries that
  resolves to key material the loader could actually trust: each is rejected
  outright, never silently dropped from the list.
```

### Item 2: version for the advisory

`vaid-a2a` has never been published: PyPI serves nothing for the name, and
`releaseTagFor('python', 'vaid-a2a', ...)` resolves to no tag for any
version, the legacy bare-tag restriction added in session 306 being what
keeps the unrelated `python-v0.1.0` and `python-v0.1.1` tags from being read
as this package's own releases. So 0.1.0 exists only in this repository's
history and the fixes land as 0.1.1.

Three sources, exactly the three `scripts/verify-internal-versions.mjs`
compares for every other Python package in the tree, and nothing else in
the repository records a `vaid-a2a` version:

| source | before | after |
|---|---|---|
| `python/vaid-a2a/pyproject.toml` `[project] version` | `0.1.0` | `0.1.1` |
| `python/vaid-a2a/vaid_a2a/__init__.py` `__version__` | `0.1.0` | `0.1.1` |
| `python/vaid-a2a/CHANGELOG.md` top heading | `## [Unreleased]` | `## [0.1.1]` |

The CHANGELOG's existing `Unreleased` section becomes the `0.1.1` section
unchanged except for the heading, a note that 0.1.0 was never published, and
a new entry for this follow-up's strict decoding. The `## [0.1.0]` section
below it is untouched. The format matches `vaid-pop` and `vaid-langchain`:
a bare `## [x.y.z]` heading, no date.

No tag was created, nothing was released and nothing was published. The
registry-parity check classifies the result as "in flight", which is the
state it defines for a bumped, untagged, unpublished package that is ahead
of its registry:

```
IN FLIGHT - 1 package(s) bumped, not yet released (no tag, ahead of the registry):
  -> [python/vaid-a2a] vaid-a2a 0.1.1 - pypi serves up to (nothing published)
      Clears when vaid-a2a 0.1.1 is published AND tagged python-vaid-a2a-v0.1.1.
      Until then this is NOT evidence of a release; it is evidence of an intention.
```

### Version and release-map checks

Run locally, all exit 0:

```
node scripts/verify-internal-versions.mjs
  ✓ internal version agreement - 11 package(s), each self-consistent.
  ✓ [python/vaid-a2a] vaid-a2a 0.1.1 - 3 source(s) agree

node scripts/verify-release-map.mjs
  ✓ release map - 11 entries, each resolving to the package it names
  ✓ every publishable package found in the tree (11) has an entry

node scripts/verify-package-versions.mjs
  ✓ self-check - parity classifier agrees with all seven fixed fixtures
  ✓ self-check - legacy bare-tag fallback agrees with real repository history
  ✓ scope declaration - 11 declared pair(s)
  ✓ registry parity - 10 package(s) checked: 9 released and present, 1 in flight
  ✓ release tag parity - every published version has a release tag.
```

Also run, unaffected and green: `verify-release-version.mjs` (9 sites all
read 0.9.0), `verify-vector-freeze.mjs` (35 vectors unchanged, 0 not
checked), `verify-spec-status.mjs`, `verify-claims.mjs`,
`check-readme-drift.mjs`, and `verify-no-guarded-terms.mjs origin/main`
(1402 added lines scanned, no guarded term). `verify-crosslang-parity.mjs`
reports its two pre-existing advisory skews, neither involving `vaid-a2a`.

### Tests

Full local run across all four Python packages:

```
python/vaid-mint:      185 passed
python/vaid-a2a:        34 passed
python/vaid-pop:         9 passed
python/vaid-langchain:  14 passed
-----------------------------------
Total:                 242 passed, 0 failed
```

(34 in `vaid-a2a` is follow-up 3's 28 plus this follow-up's 6 new tests.
242 total is follow-up 3's 236 plus the same 6. No existing test changed,
and `test_vectors.py` passes unchanged.)

### Commit and push

Commits on `fix/trust-domain-binding`, each pushed as an ordinary
fast-forward, none force-pushed:

- `1cb9a32` ("fix(a2a): reviewer follow-up 4 (strict kernelPublicKey
  decoding, version 0.1.1)"), the code, spec and version change
  (`1a8be96..1cb9a32`).
- `3af395b` ("docs: append session 307 follow-up 4 report"), this report
  section (`1cb9a32..3af395b`).
- `e8d060d` and the commit appending this paragraph, both docs-only
  corrections to the two SHA references in this section, which named only
  the code commit as the head. A report that names its own commit's SHA
  cannot be written in that commit, so the stable statement is the one
  above: `1cb9a32` is this follow-up's change, and the report commits that
  follow it move the head without changing a shipped file.

Confirmed via the REST API after each push:
`GET /repos/solara-associates/vaid-ghsa-hfjh-v2x2-r58v/pulls/1` reported
`head.sha` = `1cb9a32c9d2de32461efd54520eaac042da3a80b`, then
`3af395b1feb3c27b91b6a05569436a89792be989`, then
`e8d060d7b9963afc99433a92d8dab30fac276bcc`, each time matching
`GET /git/refs/heads/fix/trust-domain-binding` exactly. PR #1 is open
against `main`.

### Decisions made on Allan's behalf

- **`=` padding is rejected outright**, not accepted as an alternative
  spelling. The reviewer asked for "strict unpadded base64url" and named
  "padding errors" as a thing to reject, and section 2's example already
  shows an unpadded key, so a padded key is now a configuration error even
  though it decodes to the right 32 bytes. Every fixture in the test suite
  already encodes unpadded, so nothing in the repository relied on the
  permissive behaviour. If a real operator's configuration file turns out to
  carry padded keys, that is a one-line relaxation in
  `_strict_b64url_decode` plus the matching sentence in section 2.1.
- **Section 2.1 gained the non-object bullet** as well as the rewritten key
  bullet. Only the key rule was asked for, but the reviewer also asked for
  the missing non-object test, and the loader has rejected non-objects since
  follow-up 3 while section 2.1 said nothing about them. Leaving the spec
  silent on a rule the loader enforces and a test now pins is the exact
  spec-versus-loader drift this series of follow-ups has been closing.
- **The `Unreleased` heading was consumed rather than kept alongside
  `0.1.1`.** No other package in the tree carries a standing `Unreleased`
  section, and `verify-internal-versions.mjs` reads the first parseable
  `## [x.y.z]` heading, so an empty `Unreleased` above it would be harmless
  but unlike every sibling package.

### Ground rules re-confirmed

- Private fork only; no release, no publish, no tag. The version bump is a
  manifest edit only, and the registry-parity check's "in flight" verdict is
  the repository's own representation of exactly that state, so no tag or
  publish was needed for the checks to pass.
- No change under `docs/a2a/v1/vectors/`: no file there was read or
  modified.
- No `vaid_mint` core change, in any language. This follow-up touched six
  files, all of them `docs/a2a/v1/extension.md` or inside
  `python/vaid-a2a/`.
- No force-push. The one push was an ordinary fast-forward.
- No em-dashes introduced in this follow-up's new text, swept over every
  added line in the diff.
