# Supply-chain audit — PyPI attestations and "require trusted publishing"

**Date:** 2026-08-12
**Branch:** `supplychain/attestations`
**Scope:** BACKLOG B15 (PyPI provenance attestation) and B16 (require trusted publishing).

**No release was cut. No registry setting was changed.**

> ## Read [§7](#7-vaid-skill-013--reconciled-to-source-supersedes-a3) first
>
> **The published `vaid-skill` 0.1.3 tarball reconciles to source bit-for-bit.** Rebuilding it from commit `5f717a14` with `npm pack` produces shasum `21f6c7ce…` — byte-identical to what npm serves. All 14 files match the tree exactly. Its SHA-512 is the subject digest of a SLSA provenance attestation naming this repository, `release.yml`, tag `npm-vaid-skill-v0.1.3` and that same commit, so the whole chain closes from the registry alone.
>
> **This retracts a claim in A3 of this document.** 0.1.3 was **not** published by hand — it was published by run `31380539098` through trusted publishing. I inferred "by hand" from that run's `conclusion: failure` without opening it; the **publish job succeeded and a later job failed**. The corrected count is **6 of 10** pairs unproven, not 7, and BACKLOG **B2/B3** already recorded the right version.
>
> **Third pass also covers:** why all three `vaid-skill` runs failed and why none of those causes is still present (§7.2), a precise provenance comparison against the `vaid-mint` 0.7.0 legs — **no difference in kind** (§7.3), a survey finding **no published claim** that 0.1.3 fails to satisfy (§7.4), why a 0.1.4 is **not** the right remedy (§7.5), and the restated `trustpub_only` scope (§7.6).

> **Second pass (same day) — see the [Appendix](#appendix--second-pass-2026-08-12).** It leads with the question that gated the push: **where invariant 8 executes.** Short answer — its integrity-endpoint clause is a *static text assertion* over `release.yml`, not a query; the actual integrity query runs **only in the release job**, against the version just published. CI never contacts a registry. **This diff cannot turn main red over 0.7.0, and no code change was needed.** The appendix also narrows the CI-token claim (A2), records the unproven publish paths (A3 — **corrected by §7**), and restates item 4 by evidence (A4).

---

## Headline

- **No stop condition fired.** All three 0.7.0 publishes went through trusted publishing (OIDC). Confirmed twice over: from the run logs, and from each registry's own record of the publish.
- **Item 3 (PyPI attestations) was already on `main`** before this session — commit `73a864a`, 2026-08-11 15:57. The publish step already generates and uploads attestations. What was missing was any check holding it there; that is what this branch adds.
- **Item 4 is half-impossible as specified.** crates.io has the setting. **PyPI does not.** The prior B16 entry claimed both did; that was wrong and is corrected.
- **The crates.io half is blocked on a credential**, not a decision. The stored token lacks the required scope.

---

## 1. Which path actually ran for 0.7.0

Only **three** packages published at 0.7.0 — all of them `vaid-mint`, one per registry. There is no fourth 0.7.0 publish. (The repo declares ten package/ecosystem pairs in `release-map.json`; the other seven were not part of this release.)

Every claim below is backed by two independent sources: the run log, and the registry's own record. The workflow file was not treated as evidence of anything.

### rust — `vaid-mint` 0.7.0 → crates.io · **TRUSTED PUBLISHING**

Run [`31485249456`](https://github.com/solara-associates/vaid/actions/runs/31485249456), job `Publish to rust`:

```
11:11:20 Retrieving GitHub Actions JWT token with audience: crates.io
11:11:20 Retrieved JWT token successfully
11:11:20 Requesting token from: https://crates.io/api/v1/trusted_publishing/tokens
11:11:21 Retrieved token successfully
11:11:31 Uploaded vaid-mint v0.7.0 to registry `crates-io`
11:11:33 Revoking trusted publishing token
11:11:33 Token revoked successfully
```

Registry side — `GET /api/v1/crates/vaid-mint/0.7.0`:

```json
{ "published_by": null,
  "trustpub_data": { "provider": "github",
                     "repository": "solara-associates/vaid",
                     "run_id": "31485249456",
                     "sha": "95aebbaecffb0a98dbbec092883907b481af9825" } }
```

`published_by: null` with a populated `trustpub_data` is crates.io stating that no user token was involved — and the `run_id` matches the run above exactly.

### python — `vaid-mint` 0.7.0 → PyPI · **TRUSTED PUBLISHING**

Run [`31485249478`](https://github.com/solara-associates/vaid/actions/runs/31485249478), job `Publish to python`:

```
11:11:20 twine 7.0.0 — at or above the 6.1.0 trusted-publishing floor
11:11:24 Uploading distributions to https://upload.pypi.org/legacy/
11:11:25 WARNING  Got OIDC token for audience pypi
11:11:25 WARNING  Minted upload token for trusted publishing
11:11:27 View at: https://pypi.org/project/vaid-mint/0.7.0/
```

twine only attempts the OIDC exchange when it finds *no* credentials — so those two lines are also positive proof that no `TWINE_PASSWORD` was set, which is the B14 trap.

### npm — `vaid-mint` 0.7.0 → npmjs · **TRUSTED PUBLISHING**

Run [`31480914087`](https://github.com/solara-associates/vaid/actions/runs/31480914087), job `Publish to npm`:

```
10:28:19 npm notice Publishing to https://registry.npmjs.org/ with tag latest and public access
10:28:20 npm notice publish Signed provenance statement with source and build information from GitHub Actions
10:28:20 npm notice publish Provenance statement published to transparency log:
         https://search.sigstore.dev/?logIndex=2419979064
10:28:22 + vaid-mint@0.7.0
```

The npm log does not print an explicit "OIDC exchange" line, so the log alone is suggestive rather than conclusive. The registry record settles it — `registry.npmjs.org/vaid-mint`, version 0.7.0:

```json
{ "_npmUser": { "name": "GitHub Actions",
                "email": "npm-oidc-no-reply@github.com",
                "trustedPublisher": { "id": "github",
                                      "oidcConfigId": "oidc:2da6b3c8-…" } },
  "_npmVersion": "11.7.0",
  "dist": { "attestations": { "provenance": { "predicateType": "https://slsa.dev/provenance/v1" } } } }
```

Corroborating: `verify-artifact` ran `npm audit signatures` from a clean consumer install and reported *"4 packages have verified registry signatures / 3 packages have verified attestations"*.

### Supporting fact — and its exact scope

`gh secret list` returns **empty** for both the repository and the `release` environment. **Within GitHub Actions**, there is no token for any of the three registries, so no CI fallback path existed for 0.7.0 to have taken.

**That is a statement about CI only, and it is not the threat item 4 was written against.** An empty `gh secret list` says nothing about **account-scoped registry tokens** — a PyPI or crates.io token held by a maintainer, in a password manager, on a laptop, or in another system. Those remain a live publishing route for these projects regardless of what CI holds, and they are precisely what "require trusted publishing" exists to shut off.

Account-level tokens are **out of scope for this audit and unverifiable from the registry side**: the absence of a token is not a public fact on either registry. They remain the **open half of item 4**, and on PyPI they are the *only* half, since no registry-side control exists there at all (§3).

---

## 2. Item 3 — PyPI attestations

### Already landed; not by this session

Commit `73a864a` (2026-08-11 15:57) added to the publish step:

```
python -m pip install ... pypi-attestations
python -m pypi_attestations sign <dir>/dist/*
twine upload --attestations <dir>/dist/*
```

and to `verify-artifact`, a check that queries `pypi.org/integrity/{pkg}/{ver}/{file}/provenance` for every published file and fails if any carries zero attestations.

This is correct, and it matters that `--attestations` is not the whole fix: twine only *discovers* adjacent `.attestation` files, it never creates them. The flag alone is a no-op — which is exactly how 0.7.0 shipped unattested.

**0.7.0 itself carries no attestation and never will.** It published at 11:11; the fix landed at 15:57. Measured today, both files return 404 from the integrity endpoint. (The JSON API's `provenance` key reads like the answer and is `null` for every package on PyPI including ones that demonstrably attest — it is not the signal.)

### What this branch changes

**a. A guard, so the fix cannot silently drop out.** `verify-release-workflow.mjs` asserted `npm audit signatures` for npm and *nothing* for PyPI. The sign step could be deleted, reordered after the upload, or stripped of `--attestations`, and CI would stay green until the next release republished the original defect. New invariant 8 asserts:

1. any job running `twine upload` runs `pypi_attestations sign` **first**;
2. that upload passes `--attestations`;
3. `verify-artifact` queries the **integrity** endpoint (not the JSON API).

Each was mutation-tested — the four corresponding edits applied to `release.yml` one at a time, each producing a distinct failure, baseline clean.

The first draft of this check was wrong in a way worth recording: it matched `/twine upload/` anywhere, which also matches the words *"or twine uploaded without --attestations"* inside `verify-artifact`'s own B15 error message. It reported that the verify job publishes to PyPI, on a workflow that is correct. That is the third time in this file that a command's **name** was mistaken for the command. Matchers are now anchored to line start.

**b. A stale claim removed.** `release.yml`'s header still read:

> NOT ENABLED: Rust and Python have no equivalent here. crates.io has no provenance mechanism, and PyPI attestations need Trusted Publishing (OIDC) instead of the API token this workflow uses.

Untrue in both halves since 2026-08-11, sitting at the top of a file that does exactly what it says is not done. Replaced with a per-registry statement of what each actually proves — including that crates.io's `trustpub_data` is registry-attested build metadata, not a signed statement a consumer can check without trusting crates.io. Two orphaned comment fragments describing the wrong adjacent steps were also removed.

### Unproven

**The attestation change is unproven and stays unproven until a release carries it.** No release was cut to demonstrate it. What is proven is that the steps are present, correctly ordered, and now guarded; whether the signature verifies is not knowable before a publish, because the identity is minted from the workflow's ambient OIDC at run time. **Item 3 is not done.**

### On the TestPyPI option

Not taken, and it would not have closed the gap. Validating there needs a TestPyPI trusted-publisher configuration for the project — a registry-side action requiring an interactive login, the same class of blocker as item 4. It would also prove the TestPyPI path, not the PyPI one. The available partial validation is the mutation-tested structural guard above; the real proof is the next release.

---

## 3. Item 4 — require trusted publishing

### What item 4 actually is, scoped by the evidence

It was briefed as "enable a setting on two registries". It is not that. Restated to match what was measured:

> **One setting** (`trustpub_only`) on **one crate of three** (`vaid-mint` — the only one with proven trusted publishing), currently **blocked on cargo token scope**; plus a **PyPI half that does not exist as a setting at all**, where no registry-side control is available and the nearest action is account token deletion, which is unverifiable.

Item 4 therefore cannot be "done" in the sense briefed. The most that is available is one crate's flag, and a manual, unverifiable account cleanup on PyPI.

### crates.io — the setting exists, and is blocked on a credential

Per-crate `trustpub_only` boolean (rust-lang/crates.io#12361). A checkbox on the crate settings page, and `PATCH /api/v1/crates/{name}` with `{"crate":{"trustpub_only":true}}`. Usefully, it is **publicly readable unauthenticated**, so live state can be confirmed rather than assumed.

Live state, read today:

| crate | latest | `trustpub_only` |
|---|---|---|
| `vaid-mint` | 0.7.0 | **false** |
| `vaid-pop` | 0.2.1 | **false** |
| `vaid-client` | 0.1.0 | **false** |

The PATCH was attempted against `vaid-mint` and returned **403 `this token does not have the required permissions to perform this action`**. `~/.cargo/credentials.toml` holds a `publish-update`-scoped token; `trustpub_only` needs cookie auth (web UI) or a non-legacy token with the `trustpub` scope plus a matching crate scope. Re-read afterwards to confirm nothing moved: still `false`.

**Do not enable it on `vaid-pop` or `vaid-client` yet.** This is B16's own reasoning applied per crate rather than per registry. The trusted-publishing evidence is `vaid-mint` only. `vaid-pop` 0.2.1 and `vaid-client` 0.1.0 both predate the migration and have never published through this workflow; whether either has a publisher configured is not readable with the credential on hand. Enabling `trustpub_only` there would not remove a fallback — it would remove the only path.

### PyPI — the setting does not exist

There is no per-project switch to reject token-authenticated uploads once a trusted publisher is configured. PyPI's own security-model documentation treats tokens and trusted publishers as coexisting authentication methods, and the request for this (pypi/warehouse#17260 — which proposes auto-revoking *unused* tokens rather than refusing them) is **still open**.

The B16 entry asserting the setting lives "under the project's Publishing settings" was wrong. It has been corrected in `BACKLOG.md`.

The nearest available action is different in kind: **delete the project-scoped API tokens from the PyPI account**, removing the route rather than refusing it. Note that unlike crates.io this **cannot be verified from the registry side** — the absence of a token is not a public fact — so the check is a human reading the account's token list.

---

## 4. Sequencing — what the next release exercises

The caution in the brief was aimed at landing two changes at once. As it stands the risk is smaller than assumed, because the two are not in fact simultaneous:

- The attestation change is already on `main` and would have ridden the next release regardless.
- **No registry setting was changed**, so nothing was removed from any publish path.

So the next release exercises **one** unproven change: PyPI attestation generation. If it fails, it fails in `verify-artifact` — *after* a successful publish — which reports UNVERIFIED rather than blocking the release. The `--attestations` upload itself could fail the publish step, but the CI fallback question is moot: **no token has been present in GitHub Actions** since 2026-08-11, so there is nothing for CI to fall back to. (A maintainer holding an account-scoped token could still publish by hand — that route is unaffected by anything in this repository, and is the open half of item 4. See §1.)

Once `trustpub_only` is enabled on crates.io, the crates.io side stays **untested until a real publish**. `cargo publish --dry-run` does not exercise the registry auth path. That is unavoidable; there is no test registry for crates.io.

**Recommended order:** enable `trustpub_only` on `vaid-mint` only → cut the next release → confirm the PyPI attestation lands (`verify-artifact` now asserts this) and that crates.io still accepts the publish → then extend `trustpub_only` to `vaid-pop` and `vaid-client` after each has published once through the workflow.

---

## 5. Per-package summary

| package | registry | 0.7.0 path | evidence | changed | unproven until next release |
|---|---|---|---|---|---|
| `vaid-mint` | crates.io | trusted publishing | log: JWT→`/trusted_publishing/tokens`, token revoked. registry: `published_by:null` + `trustpub_data.run_id=31485249456` | header comment corrected | `trustpub_only` not yet enabled (403, wrong token scope) |
| `vaid-mint` | PyPI | trusted publishing | log: "Got OIDC token for audience pypi" / "Minted upload token for trusted publishing" | invariant 8 guard added | **attestation generation — no PyPI release has ever carried one** |
| `vaid-mint` | npm | trusted publishing | registry: `_npmUser.trustedPublisher.id=github`; provenance in sigstore tlog `2419979064`; `npm audit signatures` clean | — | nothing; npm provenance is proven |
| `vaid-pop` | crates.io | *not released at 0.7.0* | latest 0.2.1, predates migration | — | trusted publishing never exercised for this crate |
| `vaid-client` | crates.io | *not released at 0.7.0* | latest 0.1.0, predates migration | — | trusted publishing never exercised for this crate |

---

## 6. Actions needed from a human

1. **crates.io**: log into the web UI and tick "require trusted publishing" on **`vaid-mint` only** — or issue an API token with the `trustpub` scope so it can be set from a script. Verify with `curl -sS https://crates.io/api/v1/crates/vaid-mint | jq .crate.trustpub_only`.
2. **PyPI**: no setting to enable. Decide whether to delete the project-scoped API tokens from the account; if so, do it manually and record it, since it cannot be read back.
3. **Neither is a release blocker.** Both are safe to leave until after the next release, which is also when item 3 gets its first real proof.

---

# Appendix — second pass, 2026-08-12

## A1. Where invariant 8 executes (the question that gated the push)

**Answer: the integrity-endpoint query runs only in the release job. Nothing changed, because nothing needed to.**

The concern was that invariant 8 might query the integrity endpoint for the latest published release on every main run, turning main permanently red over 0.7.0's timing accident. That cannot happen, because two different things were being conflated.

**1. Invariant 8's integrity clause is a static text assertion.** It runs on PR and on main — `ci.yml` line 99, job *"Release workflow structure"*, triggers `push: branches:[main]` and `pull_request: branches:[main]`. But the clause is:

```js
if (publishesToPyPI && !/pypi\.org\/integrity\//.test(v))
```

where `v` is **the text of the `verify-artifact` job in `release.yml`**. It asserts that the workflow *contains* an integrity check. It never contacts PyPI, never resolves a version, and never references 0.7.0 or any release.

Evidence, not inference:

- `scripts/verify-release-workflow.mjs` imports exactly `node:fs`, `node:path`, `node:url`. Grepping it for `fetch|https?://|urllib|curl|request|net\.|dns\.` returns **nothing**. It is a pure text check over one file.
- Grepping all of `.github/workflows/ci.yml` for `pypi.org|registry.npmjs|crates.io|integrity` returns **one comment line and zero commands**. CI never contacts a registry, before or after this change.

**2. The actual integrity query lives in `release.yml`**, in the `verify-artifact` job. That workflow triggers only on `push: tags: [rust-*-v*, python-*-v*, npm-*-v*]`, and the query targets `needs.resolve.outputs.version` — the version just published. It cannot examine 0.7.0 unless 0.7.0 is re-tagged.

**Consequence:** this diff cannot make main red for a historical release. The separate session's stop condition is not at risk.

### What was deliberately not built

An "expected absent" assertion for 0.7.0 was **not** added, and this is a judgement worth overruling if you disagree.

The principle — absence should be declared rather than silently skipped — is right, and it is the reason invariant 8 exists at all. It does not apply here. The release-job check only ever examines the version currently being released, so pre-attestation releases are **structurally out of scope**, not skipped by an unchecked branch. There is no branch to declare.

Building one would mean adding a network call to CI where none exists today — introducing exactly the "main goes red for reasons unrelated to the commit" failure this question was asked to prevent, and going red if anyone ever legitimately backfilled an attestation for 0.7.0. The declaration would cost more than the absence it documents.

**Verified green before push:** `verify-release-workflow.mjs`, `check-readme-drift.mjs`, `verify-release-map.mjs`, `verify-internal-versions.mjs` all pass on this branch. The diff touches only comments in `release.yml`, the checker script, `BACKLOG.md`, and this file; no CI job reads `BACKLOG.md` or `docs/`.

## A2. Correction — the CI-scope claim was too broad

§1 and §4 previously said no token fallback has existed since 2026-08-11. Corrected in place: that is true **of GitHub Actions only**.

An empty `gh secret list` says nothing about **account-scoped registry tokens** — held by a maintainer, in a password manager, on a laptop, or in another system. Those remain a live publishing route regardless of what CI holds, and they are precisely the threat "require trusted publishing" was written against. They are **out of scope for this audit, unverifiable from the registry side** (absence of a token is not a public fact), and they remain the **open half of item 4** — on PyPI, the only half.

## A3. Recorded, not fixed — the unproven publish paths are wider than two crates

> ### ⚠️ RETRACTED IN PART — see [§7](#7-vaid-skill-013--reconciled-to-source-supersedes-a3)
>
> **The claim that `vaid-skill` 0.1.3 "was published by hand" is false.** It was published by run `31380539098`, through trusted publishing, with a full SLSA provenance attestation. I inferred "by hand" from the run's *conclusion* (`failure`) without opening the run: the **publish job succeeded and a later job failed**, which is the partial-release shape this workflow exists to surface. The count below is **6 of 10 unproven, not 7**, and the repository already recorded the correct version in BACKLOG **B2 and B3** — which I had not read.
>
> The rest of this section stands. §7 has the evidence and the corrected table.

Stated for the record; **no rehearsal was attempted.**

Auditing every `release.yml` run ever executed (4 distinct tags, 14 runs) against what is live on each registry gives this — **corrected**:

| pair | live version | ever published via workflow |
|---|---|---|
| `rust/vaid-mint` | 0.7.0 | ✅ run `31485249456` |
| `python/vaid-mint` | 0.7.0 | ✅ run `31485249478` |
| `npm/vaid-mint` | 0.7.0 | ✅ run `31480914087` |
| `npm/vaid-skill` | 0.1.3 | ✅ run `31380539098` — **corrected**, see §7 |
| `rust/vaid-pop` | 0.2.1 | ❌ never |
| `rust/vaid-client` | 0.1.0 | ❌ never |
| `python/vaid-pop` | 0.2.0 | ❌ never |
| `python/vaid-langchain` | 0.1.0 | ❌ never |
| `npm/vaid-pop` | 0.3.0 | ❌ never |
| `npm/vaid-client` | 0.3.0 | ❌ never |

**It is six pairs, not two — and not seven.** The brief named `vaid-pop` 0.2.1 and `vaid-client` 0.1.0; the true figure is **6 of the 10 declared pairs**.

The workflow's successful publishes are the three `vaid-mint` legs of 0.7.0 (2026-08-11) and `vaid-skill` 0.1.3 (2026-08-10) — **four**, across two days. The next release of any *other* package is still a **first run of an unproven path with no CI token fallback**, and the failure would present as B14 did: a message indistinguishable from a misconfigured trusted publisher.

Compounding it: crates.io trusted publishers are configured **per crate**, npm **per package**. `vaid-mint`'s working configuration confers nothing on `vaid-pop` or `vaid-client`. Whether they have one at all is not readable with the credential on hand (403).

### What a rehearsal would require, and cost

| registry | rehearsal available? | what it needs | cost |
|---|---|---|---|
| **PyPI** | Partial — TestPyPI | Create each project on TestPyPI, configure a **separate** trusted publisher there, add a workflow path targeting `test.pypi.org` | Registry config per package + a workflow branch. Proves the **TestPyPI** publisher, not the PyPI one — they are distinct configurations, so a pass does not transfer. Free, irreversible only in the sense that TestPyPI version numbers are also consumed. |
| **crates.io** | **None** | — | No test registry exists. `cargo publish --dry-run` packages the crate but never touches the auth path, which is the thing in doubt. The only rehearsal is a **real publish**, burning a version number permanently (yanking is not deletion). |
| **npm** | Partial | Publish a prerelease tag (e.g. `0.3.1-rc.0`) under `--tag next` so it does not move `latest` | A consumed version number, but no disruption to consumers. Closest thing to a genuine rehearsal of the three. |

The cheapest honest option for crates.io is to accept that the next `vaid-pop`/`vaid-client` release **is** the test, and to read back its trusted-publisher configuration in the crates.io UI beforehand rather than discovering it at publish time.

## A4. Item 4, restated by evidence

Moved into §3 as the section's opening frame. In full:

**One setting, one crate, blocked; plus a PyPI half that does not exist.**

- **crates.io — `trustpub_only`.** Exists, publicly readable, currently `false` on all three crates. Enable on **`vaid-mint` only** — the sole crate with proven trusted publishing. **Blocked:** `~/.cargo/credentials.toml` holds a `publish-update`-scoped token; the PATCH returns 403. Needs web-UI login or a token with the `trustpub` scope. Do **not** enable on `vaid-pop` or `vaid-client` — per A3 they have never published through the workflow, so the flag would remove the only path rather than a fallback.
- **PyPI — no registry-side control available.** No per-project switch to reject token-authenticated uploads exists; pypi/warehouse#17260 is open and proposes only auto-revoking *unused* tokens. Nearest action is **account token deletion**, which removes the route instead of refusing it — manual, and **unverifiable**, since absence of a token is not a public fact.

Neither is a release blocker. Both can wait until after the next release, which is also when item 3 gets its first real proof.

---

# 7. `vaid-skill` 0.1.3 — reconciled to source (supersedes A3)

Promoted from a table row at the reviewer's instruction, on the expectation that it documented an unreconcilable hand-published artifact. **It documents the opposite.** Every question below resolved in the artifact's favour, and the finding that prompted the investigation was my error.

## 7.1 Can the published tarball be reconciled to a commit? — **Yes. Bit for bit.**

Not "matches in content" — the published tarball is **byte-identical to one rebuilt from source**, which is the strongest of the three answers that were on offer.

```
$ curl -sSL -o published.tgz https://registry.npmjs.org/vaid-skill/-/vaid-skill-0.1.3.tgz
$ shasum published.tgz
21f6c7cef1606d94580fcb249c3509dd081ff743      # == npm dist.shasum

$ git archive 5f717a14 skill | tar x -C /tmp/repro && cd /tmp/repro/skill && npm pack
$ shasum vaid-skill-0.1.3.tgz
21f6c7cef1606d94580fcb249c3509dd081ff743      # identical
```

SHA-512 agrees too: `rFkFSF6HSl11OMBKM+luQf2jj7pgO4sCF3MBeTvjY4jy/5rkzTh0kAt7onMKfFAp/UJsj9lPeh6HSDYUQi/c5A==` equals npm's recorded `dist.integrity`.

Independently of the archive hash, all **14 files compared byte-for-byte** against `5f717a14:skill/*`: `identical=14 differ=0 absent-from-tree=0`, and the file lists match exactly in both directions — nothing added, nothing omitted relative to `package.json`'s `files` array.

**Why reconciliation was even possible here**, when it usually is not: `vaid-skill` is a standalone package with **no build step** (`scripts` at that commit are `test`, `check:anchor`, `test:documented` — no `prepack`, no `prepublishOnly`, no compile). `npm pack` is a straight file copy with normalised mtimes, so the tarball is a deterministic function of the tree. The same exercise on `vaid-mint` would *not* reproduce this cleanly — it compiles TypeScript through `prepublishOnly`.

**The commit was not guessed.** npm records `gitHead: 5f717a14cf9a26e04b4f53bb169478c17ef68013` in the version metadata, and the provenance attestation independently names the same commit (§7.3).

## 7.2 Why the three runs failed — and the cause is already fixed

**The premise that 0.1.3 was hand-published is false, and the run timeline disproves it on its own:**

| run | SHA | window | conclusion | publish job |
|---|---|---|---|---|
| `31376944072` | `20b2ed74` | 09:56:53 → 10:08:09 | failure | **failed** — `npm publish` |
| `31378059338` | `2f92ec16` | 10:11:40 → 10:13:18 | failure | **failed** — `npm publish` |
| `31380539098` | `5f717a14` | 10:45:46 → **10:47:28** | failure | ✅ **succeeded** |

npm records the publish at **10:47:12.889Z** — inside the third run's window — and `gitHead` `5f717a14` is exactly that run's head SHA. The publish happened *in* the run.

Per-job outcomes for `31380539098`:

```
Resolve tag -> package                       => success
Preflight                                    => success
Publish to npm                               => success      <-- 0.1.3 published HERE
Verify published artifact from a clean install => failure
    ✗ npm publish --dry-run (packages exactly as the real publish will)
Release complete (fails on any partial)      => failure
    ✗ Assert every stage succeeded
```

and the publish job's own log:

```
10:47:10 npm notice Publishing to https://registry.npmjs.org/ with tag latest and public access
10:47:11 npm notice publish Signed provenance statement with source and build information from GitHub Actions
10:47:11 npm notice publish Provenance statement published to transparency log:
         https://search.sigstore.dev/?logIndex=2406670539
10:47:13 + vaid-skill@0.1.3
```

**Root causes, all three:**

1. **`31376944072` — `ENOENT`.** `npm publish --prefix skill` from the repo root. `npm publish` ignores `--prefix` when locating the package; it reads `package.json` from the CWD and died on `open '/home/runner/work/vaid/vaid/package.json'`. **Fixed** by `13a5879` (`cd` instead of `--prefix`).
2. **`31378059338` — `ENEEDAUTH`.** `need auth This command requires you to be logged in`. The runner's default npm 10.9.8 has no OIDC support at all, so it looked for a token and found none. **Fixed** by pinning npm 11.7.0 with an asserted 11.5.1 floor.
3. **`31380539098` — the run that published.** An unbounded edit had inserted `npm publish --dry-run` into `verify-artifact`, which deliberately has no checkout, so the job died on its first step and *every real verification in it was skipped* — the consumer install, the declared verify command, `npm audit signatures`. **Fixed** by `90d2e3e`, and now guarded by `verify-release-workflow.mjs` invariants 1–4, which exist precisely for this defect.

**All three causes are fixed on `main`.** A 0.1.4 through the workflow is **not blocked**. This directly contradicts the brief's hypothesis that "if the cause is still present, the next attempt fails the same way" — no fix is outstanding, and per the stop conditions none was applied.

The one thing that *is* worth noting: 0.1.3 published without its verification ever running. `release-outcome.mjs` was added afterwards to name that state UNVERIFIED rather than leaving it ambiguous.

## 7.3 What provenance npm holds for 0.1.3 vs the `vaid-mint` 0.7.0 legs

**No difference in kind. Both carry full, verifiable provenance.** The concern that published material asserts provenance "true of one and not the other" does not arise on npm.

| | `vaid-skill@0.1.3` | `vaid-mint@0.7.0` |
|---|---|---|
| `_npmUser` | `GitHub Actions` / `npm-oidc-no-reply@github.com` | same |
| `trustedPublisher` | `github`, `oidc:15006352-…` | `github`, `oidc:2da6b3c8-…` |
| npm / node | 11.7.0 / 22.23.1 | 11.7.0 / 22.23.1 |
| attestations | **2** — npm-publish v0.1 + **SLSA provenance v1** | **2** — identical pair |
| sourceUri | `github.com/solara-associates/vaid` | same |
| ref | `refs/tags/npm-vaid-skill-v0.1.3` | `refs/tags/npm-vaid-mint-v0.7.0` |
| workflow | `.github/workflows/release.yml` | same |
| source commit | `5f717a14cf9a26e04b4f53bb169478c17ef68013` | `b8b29c83afba792c2986698e9b0553276c0c4835` |
| invocationId | `…/actions/runs/31380539098/attempts/1` | `…/actions/runs/31480914087/attempts/1` |
| sigstore tlog | `2406670539` | `2419979064` |
| `npm audit signatures` | ✅ verified, clean consumer install | ✅ verified |

The differing `oidcConfigId` is expected and correct — npm trusted publishers are configured **per package**, so each has its own.

**The chain closes completely for 0.1.3**, which is a stronger result than the attestation alone:

```
commit 5f717a14
  → npm pack reproduces the tarball bit-for-bit
    → its SHA-512 is ac5905485e874a5d7538c04a…
      → which is exactly the SLSA attestation's subject digest
        → in an attestation naming run 31380539098 and tag npm-vaid-skill-v0.1.3
```

Anyone can walk that chain from the registry with no access to this repository's secrets, and no need to trust npm's word for it.

**Where provenance genuinely is absent — 0.1.0, 0.1.1, 0.1.2:**

| version | publisher | attestations |
|---|---|---|
| 0.1.0 | `solara-eng` (user token) | **none** |
| 0.1.1 | `solara-eng` (user token) | **none** |
| 0.1.2 | `solara-eng` (user token) | **none** |
| **0.1.3** | **GitHub Actions (trusted publisher)** | **2** |

Those three *were* hand-published, and BACKLOG **B2** already says so. 0.1.3 is the version that fixed it — the exact opposite of what A3 claimed. Since 0.1.3 is `latest`, a consumer installing today gets the attested artifact.

## 7.4 Published claims that 0.1.3 does not satisfy — **none found**

Surveyed read-only, nothing edited: `skill/README.md`, `skill/CHANGELOG.md`, `skill/GEMINI.md`, `skill/skills/vaid/SKILL.md`, `skill/.claude-plugin/plugin.json`, root `README.md`, `CLAIMS.md`, `docs/RELEASE-NOTES.md`, `docs/capabilities.json`, `docs/claims-register.json`.

Grepping for `provenance | trusted publish | npm audit signatures | built and signed | slsa | sigstore | supply.chain` returns **no supply-chain provenance assertion in any consumer-facing file**. The three `README.md` hits are VAID's own domain vocabulary — "a self-reported provenance record" describing `vaid-pop` completion records — not a claim about npm packaging. `CLAIMS.md` cites a paper on "authentication and provenance for autonomous agents".

So there is nothing to correct: **no published claim overstates 0.1.3's provenance, and 0.1.3 would satisfy such a claim if one were made.** The only inaccurate statement found anywhere was in my own A3, in this document, now retracted above.

## 7.5 Is a 0.1.4 through the workflow the correct remedy? — **No**

Attestation cannot be retrofitted to a build that had no run; that premise is right. But it does not apply, because **0.1.3 had a run and carries an attestation.**

- There is **no provenance gap to close.** A 0.1.4 would produce a second attested artifact identical in kind to the one already published.
- The unattested versions — 0.1.0 through 0.1.2 — **cannot be remedied by any future release.** They are immutable. The remedy already in place is that `latest` points at an attested 0.1.3; the residual exposure is a consumer pinning an old version, which no new publish changes.
- A release should be cut when there is **something to ship**. Cutting 0.1.4 to demonstrate a property 0.1.3 already demonstrates is the version-burning this repository has repeatedly declined (see B15's status note).

**What *is* worth doing on the next `vaid-skill` release, whenever it happens for its own reasons:** it will be the first `vaid-skill` publish to run `verify-artifact` to completion, since 0.1.3's died on the stray dry-run step. That is a genuine gap — not in the artifact, but in the verification of it.

## 7.6 Revised `trustpub_only` recommendation

Unchanged in substance; restated in the terms the evidence supports. Note `vaid-skill` is npm-only and does not bear on crates.io.

**Enable `trustpub_only` on `vaid-mint` only.** Not as an endorsement of the mechanism generally, but because:

- `vaid-mint` is the **only crate of the three** with any successful workflow history at all;
- that history is **one crate deep and, at time of writing, one day old** — a single publish on 2026-08-11;
- `vaid-pop` (0.2.1) and `vaid-client` (0.1.0) have **never published through this workflow**, and crates.io trusted publishers are per-crate, so `vaid-mint`'s working configuration confers nothing on them. Enabling the flag there removes the only path rather than a fallback.

A sample size of one is enough to justify protecting the path that worked. It is not enough to justify closing the alternative on paths that have never run.

---

## Corrections issued in this pass

1. **A3's "published by hand" — retracted.** `vaid-skill` 0.1.3 was published by run `31380539098` through trusted publishing, with full SLSA provenance. I read a run's `conclusion: failure` as "the publish failed" without opening the run; the publish job succeeded and a *later* job failed. The registry metadata (`_npmUser.trustedPublisher`, `gitHead`, npm 11.7.0) contradicted the inference and was already in hand when I made it.
2. **The count is 6 of 10 unproven, not 7.**
3. **BACKLOG B2 and B3 already recorded this correctly**, including the reproducible-digest argument. I had read B15–B17 and generalised from an incomplete read of the file.

The underlying concern that prompted the promotion — that a widely-installed artifact might not be reconcilable to source — was worth raising, and is now closed with a positive result rather than an assumption.

---

# 8. Session close — pattern, permanent surface, and next-release expectation

## 8.1 PATTERN: a completed step under a failed summary

Recorded as a named failure mode, not an apology, because the estate already has a register of its mirror image.

**The general form.** A workflow run reports **one** conclusion for **many** jobs. When an early job succeeds and a later one fails, the run's conclusion is `failure` — and that word describes the run, not the work. Reading the conclusion in place of the job asserts that nothing happened, when something irreversible did.

**What it produced here.** `gh run list` showed three `npm-vaid-skill-v0.1.3` runs, all `failure`. npm served 0.1.3. The only reading that reconciles those two facts *without opening a run* is that someone published by hand — so that is what I recorded, and it stood as a finding until the tarball was reconciled to source. The truth was that run `31380539098`'s `Publish to npm` job **succeeded**, and `verify-artifact` failed after it.

**Why the existing guard does not catch it.** This estate's recurring defect, documented across several BACKLOG entries and prior sessions, runs in the opposite direction: *success reported over a step that never happened* — a green summary above a skipped or fail-open check. The discipline that grew from it is "do not trust the green." That rule is **directional**, and this case is its mirror: a **completed step under a failed summary**. A skeptic of green reads a red run and stops, satisfied, having concluded the safe thing — which here was the false thing.

**The rule that covers both directions:**

> **Read the step, not the summary.** A run-level conclusion is an aggregate. It is evidence about the aggregate and about nothing else — in either direction.

Operationally, for this repo: `gh run view <id> --json jobs` before drawing any inference from a run's conclusion, and treat `publish` as its own fact independent of the run that contains it. `release-outcome.mjs` already exists to say exactly this — it names RELEASED / UNVERIFIED / NOT-RELEASED precisely because "partial is not an instruction" — and I did not consult it.

**The aggravating detail, recorded deliberately.** The contradicting evidence was **already in hand when the inference was made**. The npm metadata dump that produced the finding also contained, in the same output, `_npmUser.trustedPublisher: {id: "github"}`, `_npmVersion: 11.7.0`, and `gitHead: 5f717a14` — the head SHA of one of the runs I had just called failed. Three independent contradictions, read past. The defect was not missing data; it was a conclusion formed before the data on screen was read. BACKLOG **B2** and **B3** also already stated the correct version, in a file I had opened but read only in part.

## 8.2 The permanent unattested surface

**Unfixable, not outstanding.** This is not a backlog item; there is no action that resolves it.

| version | publisher | attestations | can support a provenance check |
|---|---|---|---|
| 0.1.0 | `solara-eng` (user token) | none | ❌ **never** |
| 0.1.1 | `solara-eng` (user token) | none | ❌ **never** |
| 0.1.2 | `solara-eng` (user token) | none | ❌ **never** |
| 0.1.3 | GitHub Actions (trusted publisher) | 2 | ✅ |

**Three of the four published `vaid-skill` versions cannot support a provenance check.** (The brief said three of five; the registry lists **four** versions — 0.1.0, 0.1.1, 0.1.2, 0.1.3 — so the ratio is three of four. The substance is unchanged.)

Published artifacts are **immutable**. Attestation cannot be retrofitted to a build that had no run, and no 0.1.4, 0.2.0 or any later release changes what 0.1.0–0.1.2 are. There is no remediation path, only a description of the exposure:

- **A default install is clean.** `latest` resolves to **0.1.3**, which is attested, reproducible from `5f717a14`, and verifies under `npm audit signatures`. Anyone running `npm install vaid-skill` today receives an artifact with a complete chain.
- **A pinned install may not be.** Anyone pinned to `0.1.0`, `0.1.1` or `0.1.2` — in a lockfile, a Dockerfile, a vendored manifest — holds an artifact with **no chain at all**. Not a broken chain: no attestation exists to check. `npm audit signatures` reports a registry signature but no attestation for those versions.

The exposure shrinks only as consumers move forward on their own; it cannot be pushed.

## 8.3 Next-release expectation — the checks are likelier to fail than the publish

Recorded so that a red release is not misread as a publish defect.

The next `vaid-skill` release exercises **two verification paths that have never run to completion**, at the same time:

1. **`verify-artifact` has never completed against a real `vaid-skill` publish.** On 0.1.3 it died on its first step — the stray `npm publish --dry-run` — so the consumer install, the declared verify command (`verify_bin`/`verify_cmd` from `release-map.json`) and `npm audit signatures` have **never executed** for this package against a live artifact. The fix landed afterwards and has only ever been exercised by `vaid-mint`, which is a different package with a different verify command and a different install shape (`vaid-skill` is standalone and resolves the *published* SDKs from the registry; `vaid-mint` is a workspace member).
2. **Invariant 8 has never run at release.** It is a static check and passes in CI, but the PyPI steps it guards — `pypi_attestations sign`, `twine upload --attestations`, the integrity-endpoint assertion — have **never executed in a release**. On the Python leg, the next release is their first run.

**Therefore: on the next release, the most likely first failure is in the checks, not in the publish.** The publish paths have each succeeded at least once; the verification paths have not. A failure in `verify-artifact` or the integrity assertion means *the release published and the check is new*, which is the state `release-outcome.mjs` names **UNVERIFIED** — materially different from NOT-RELEASED, and it must not be read as a broken publish.

This is the correct order of risk, not a defect. Verification that has never run is the residue of fixing verification that ran wrongly. But it should be **expected**, so that the first red release is diagnosed as a check to debug rather than a registry to roll back — and so nobody reaches for a token to "publish the other way", which is the reflex B14 was written about and the one thing that would undo the property this whole branch defends.

## 8.4 Confirmations at close

Each verified live at close of session, not asserted from intent:

| claim | verification | result |
|---|---|---|
| No fix applied to the npm workflow | all three causes already on `main` — `13a5879` (`--prefix` ENOENT), the `npm@11.7.0` pin (ENEEDAUTH), `90d2e3e` (stray dry-run) | ✅ confirmed ancestors of `origin/main`; no workflow logic touched this session |
| Nothing published | `vaid-skill` versions `0.1.0, 0.1.1, 0.1.2, 0.1.3`, latest `0.1.3`; `vaid-mint` latest `0.7.0` | ✅ unchanged |
| No version cut | no tag created, no release run triggered | ✅ |
| No published claim edited | `skill/`, `README.md`, `CLAIMS.md`, `docs/RELEASE-NOTES.md`, `capabilities.json`, `claims-register.json` all untouched | ✅ diff is `docs/supply-chain-audit-2026-08-12.md` only |
| `trustpub_only` unset on all three crates | `GET /api/v1/crates/{vaid-mint,vaid-pop,vaid-client}` | ✅ `false`, `false`, `false` |
| No PR opened | `gh pr list --head supplychain/attestations` | ✅ `[]` |
| `main` untouched | `origin/main` == `cc379ac` throughout | ✅ |

**Session B closes here.** Branch `supplychain/attestations` is pushed and unmerged. Open items, none blocking: enable `trustpub_only` on `vaid-mint` only (needs a `trustpub`-scoped credential or the web UI); decide on PyPI account token deletion (manual, unverifiable); and the PyPI attestation fix stays **unproven until a release carries it**.
