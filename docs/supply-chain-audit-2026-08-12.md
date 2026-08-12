# Supply-chain audit — PyPI attestations and "require trusted publishing"

**Date:** 2026-08-12
**Branch:** `supplychain/attestations`
**Scope:** BACKLOG B15 (PyPI provenance attestation) and B16 (require trusted publishing).

**No release was cut. No registry setting was changed.**

> **Second pass (same day) — see the [Appendix](#appendix--second-pass-2026-08-12).** It leads with the question that gated the push: **where invariant 8 executes.** Short answer — its integrity-endpoint clause is a *static text assertion* over `release.yml`, not a query; the actual integrity query runs **only in the release job**, against the version just published. CI never contacts a registry. **This diff cannot turn main red over 0.7.0, and no code change was needed.** The appendix also narrows the CI-token claim (A2), records that **7 of 10** package/registry pairs have never published through this workflow (A3), and restates item 4 by evidence (A4).

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

Stated for the record; **no rehearsal was attempted.**

Auditing every `release.yml` run ever executed (4 distinct tags, 14 runs) against what is live on each registry gives this:

| pair | live version | ever published via workflow |
|---|---|---|
| `rust/vaid-mint` | 0.7.0 | ✅ run `31485249456` |
| `python/vaid-mint` | 0.7.0 | ✅ run `31485249478` |
| `npm/vaid-mint` | 0.7.0 | ✅ run `31480914087` |
| `rust/vaid-pop` | 0.2.1 | ❌ never |
| `rust/vaid-client` | 0.1.0 | ❌ never |
| `python/vaid-pop` | 0.2.0 | ❌ never |
| `python/vaid-langchain` | 0.1.0 | ❌ never |
| `npm/vaid-pop` | 0.3.0 | ❌ never |
| `npm/vaid-client` | 0.3.0 | ❌ never |
| `npm/vaid-skill` | 0.1.3 | ❌ never — **see below** |

**It is seven pairs, not two.** The brief named `vaid-pop` 0.2.1 and `vaid-client` 0.1.0; the true figure is **7 of the 10 declared pairs**.

**`vaid-skill` is the one that changes the shape of this.** All three `npm-vaid-skill-v0.1.3` runs **failed**, yet npm serves 0.1.3 — it was published **by hand**. So the workflow's only successful publishes in its entire history are the three `vaid-mint` legs of 0.7.0, all on the same day. The next release of any other package is a **first run of an unproven path with no CI token fallback**, and the failure would present as B14 did: a message indistinguishable from a misconfigured trusted publisher.

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
