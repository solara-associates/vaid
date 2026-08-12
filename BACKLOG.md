# Backlog

Known defects and deferred work in this repository. Entries are numbered and never
renumbered, so a reference to `B1` in a commit or an issue stays valid.

An entry here is a defect that has been **observed**, not a wish. Each one records
what breaks, how it presents (which is often not how it is described), the shape
of the fix, and why it has not been done yet.

---

## B1 — `vaid-mint` depends on the ambient `Buffer` global, and cannot run in a browser

**Status:** open. Blocked by the release freeze — the fix touches frozen code.
**Observed:** 2026-08-10, building the public verify page at `/vaid/verify`.
**Affects:** `typescript/vaid-mint` (all published versions through 0.6.0).

### What breaks

`vaid-mint` reaches for two Node-only platform facilities on the **verification**
path — not in an optional corner, but in code every call to
`verifyVaidAuthenticity` executes:

| where | what | reached from |
|---|---|---|
| `issuerIdentity.ts` | `createHash('sha256')` from `node:crypto` | `kernelKeyThumbprint` |
| `issuerIdentity.ts` | `Buffer.from(bytes).toString('base64url')` | `kernelKeyThumbprint` |
| `issuerIdentity.ts` | `Buffer.byteLength(s, 'utf8')` ×2 | `isValidTrustDomain` |

`verifyVaidAuthenticity` calls `isValidTrustDomain` and then compares the
document's `kernel_key_thumbprint` against `kernelKeyThumbprint(key)`, so a
browser build reaches all three on the first verification it attempts.

**Nothing is unexported.** The VAID API is complete: a browser can verify a real
substrate-minted document against the published anchor using only what
`vaid-mint` exports. This is purely a runtime-environment dependency.

### Why it is worse than it sounds: it is invisible to bundlers

`node:crypto` is an *import*, so a bundler reports it and an alias fixes it.

`Buffer` is an **ambient global**. Nothing resolves it, so nothing complains. The
bundle builds clean, ships, and throws `Buffer is not defined` at the first
verification — in the browser, at runtime, in front of whoever is trying to check
a credential. No build-time check in any toolchain catches this. It was found by
an actual browser test and could not have been found any other way.

### This breaks a property `vaid-pop` deliberately holds

`typescript/vaid-pop/src/crypto.ts` carries the comment:

> *Written against `btoa` rather than `Buffer` so the packages stay
> runtime-neutral.*

`vaid-pop` is runtime-neutral on purpose. `vaid-mint` sits directly on top of it
and is not, which means the stated property does not survive one layer up — and
`vaid-mint` is the layer a third-party verifier actually calls.

### Fix shape

Substitute what is already in the dependency tree. No new dependency, and no new
SHA-256 — `@noble/hashes` is what the rest of the standard already hashes with via
`vaid-pop`.

- `Buffer.byteLength(s, 'utf8')` → `new TextEncoder().encode(s).length`
- `Buffer.from(bytes).toString('base64url')` → the base64url encoder that already
  exists in `vaid-pop`'s runtime-neutral `crypto.ts`, re-exported rather than
  rewritten
- `createHash('sha256')` → `sha256` from `@noble/hashes/sha2.js` (already a
  transitive dependency through `vaid-pop`)

All three are drop-in and byte-identical to what they replace. The conformance
vectors are what should prove that, not review.

**Add a browser guard to CI at the same time.** A source-level fix without one
leaves the same trap open: the next Node-only global added to this package will
also build clean and throw at runtime. A test that imports `vaid-mint` and
verifies the frozen vector in a real browser (or at minimum a `no-node-globals`
lint over `dist/`) is what makes the property hold rather than merely be true
today.

### Interim

`synthera-site-redesign` carries build-time shims at
`src/lib/node-crypto-browser-shim.mjs` and `src/lib/node-buffer-browser-shim.mjs`,
aliased in `astro.config.mjs`, with `tests/unit/shim-parity.test.mjs` asserting the
SHA-256 shim byte-identical to `node:crypto`. That is a workaround in one consumer;
it does not help anyone else who bundles `vaid-mint` for a browser, and they will
each rediscover this the same way.

A divergent shim is worth calling out as its own hazard: it does not crash. It
computes a *wrong thumbprint*, so every VAID is rejected as signed by an unknown
key, which reads like a trust-anchor failure and is not one. Hence the parity test.

---

## B2 — the release workflow cannot release `vaid-skill`

**Status:** FIXED 2026-08-10 by `release-map.json` + `scripts/verify-release-map.mjs`.
Three releases (0.1.0, 0.1.1, 0.1.2) were published **by hand** before the fix, and
so carry no provenance attestation; 0.1.3 is the first released through the
workflow. The history below is kept because the failure shape — deriving a
package's location from its ecosystem — is worth recognising again.

**Originally:** open. `vaid-skill@0.1.0` was published **by hand** on 2026-08-10.
**Observed:** 2026-08-10, preparing that release.
**Affects:** `.github/workflows/release.yml`.

### What breaks

`release.yml` resolves a tag to a directory by ecosystem alone:

```bash
case "$ECO" in
  rust)   DIR="crates/$PKG" ;;
  python) DIR="python/$PKG" ;;
  npm)    DIR="typescript/$PKG" ;;
esac
```

Every npm package is assumed to live at `typescript/<pkg>` and to be a member of
the `typescript` workspace — the publish step is
`npm publish --workspace <pkg> --prefix typescript`.

`vaid-skill` lives at `skill/`. It is deliberately not in the `typescript`
workspace: it depends on the **published** `vaid-mint` and `vaid-pop` from the
registry rather than on this repo's sources, so that it breaks when what users
actually install breaks, rather than when `main` moves. Being a workspace member
would resolve those dependencies locally and destroy that property.

So the tag `npm-vaid-skill-v0.1.0` resolves to `typescript/vaid-skill`, which does
not exist, and the workflow exits at the resolve step:

```
::error::Tag 'npm-vaid-skill-v0.1.0' resolves to 'typescript/vaid-skill', which does not exist.
```

That is a correct refusal — the workflow declines rather than publishing something
wrong — but the consequence is that this package has no automated release path.

### Why the by-hand publish is a real cost, not a formality

`release.yml` is not just a convenience. Its preflight re-runs the repo's own
verifiers *on the tagged commit* precisely because "a tag can point anywhere", and
its `release-complete` job uses `if: always()` so a partial publish exits
non-zero. A manual `npm publish` has none of that: no manifest-equals-tag check,
no self-consistency check, no post-publish verification that what landed on the
registry is what was tagged.

For 0.1.0 those were run by hand and recorded — the published tarball's
`dist.shasum` `7c80c898…` was confirmed to reproduce exactly from `npm pack` at
`b5e4f10`, and a clean install from the registry was exercised end to end. That is
evidence for one release, not a property of the next one.

### Fix shape

Make the directory a property of the package rather than of the ecosystem. Either:

- a small `release-map.json` at the repo root mapping `<eco>/<pkg>` → directory,
  read by the resolve step, so a package in a new location is one entry rather
  than a workflow edit; **or**
- keep the `case` but let `npm` fall back to `skill/$PKG`-style lookup by scanning
  known roots for a `package.json` whose `name` matches `$PKG` — the manifest
  already states the name, so nothing new has to be kept in step.

The publish step also needs to stop assuming `--workspace`/`--prefix typescript`
and publish from the resolved directory. Both changes are contained; neither
touches frozen code.

### What was done

The first option. `release-map.json` declares, per package: its directory, whether
it is an npm workspace member, and how a consumer verifies the published artifact.
`resolve` reads it instead of a `case` on the ecosystem, and refuses a tag naming a
package that is not in it — or an npm package that declares no way to be verified,
because a published artifact nobody checks is not a release.

`publish` no longer assumes `--workspace`/`--prefix typescript`: a workspace member
publishes through its root, a standalone package publishes from its own directory.
`verify-artifact` no longer assumes a `<pkg>-conformance` binary, which `vaid-skill`
does not ship — it implements no cryptography, so the byte-identity a firewall would
assert belongs to `vaid-mint`. What is worth proving for it is that the documented
commands run from what a stranger installs, and that is what its `verify_cmd` does.

`scripts/verify-release-map.mjs` keeps the map from becoming the next instance of
this bug. It asserts both directions — every entry resolves to the package it names,
and every publishable package found **in the tree** has an entry — because a list of
things to check cannot notice something that was never added to it. It runs in CI, so
a missing entry fails in the PR that adds the package rather than at tag time, after
a bump and a changelog. Control-tested against all three failure shapes.

---

## B3 — the release workflow has no npm credential, and had never run

**Status:** RESOLVED and **proven live 2026-08-10**. `vaid-skill` 0.1.3 published
through the workflow with no npm credential anywhere; the registry records
`_npmUser: "GitHub Actions"` and a SLSA provenance attestation whose subject digest
equals the published tarball's, bound to this repository, `release.yml`,
`refs/tags/npm-vaid-skill-v0.1.3` and commit `5f717a1`. Resolved by **npm Trusted
Publishing (OIDC)** rather than by adding a token — the workflow carries no npm
credential at all. Kept because the way it
hid is worth recognising, and because the npm-version trap below will catch the next
person.

**Originally:** open, blocking every automated npm release.
**Observed:** 2026-08-10, running the workflow for the first time.

### What breaks

`publish` fails with:

```
npm error code ENEEDAUTH
npm error need auth This command requires you to be logged in to https://registry.npmjs.org/
```

`secrets.NPM_TOKEN` does not exist. Confirmed as a real absence rather than a
permissions artifact — the API returns `200` with `total_count: 0` at both scopes,
through the same access that successfully reads the environment list, its protection
rules, and its pending deployments:

```
repo secrets:            total_count 0
release env secrets:     total_count 0
```

### Why nobody noticed

**The workflow had never run.** `gh run list --workflow Release` returns exactly two
entries, both from 2026-08-10 and both mine. It was added on 2026-08-07 as "the first
publish automation" and every release since — `vaid-skill` 0.1.0, 0.1.1 and 0.1.2 —
was published by hand, for the unrelated reason recorded as B2. So the credential gap
sat behind a gap that stopped execution earlier, and fixing B2 is what exposed it.

That is the general shape worth remembering: **a workflow that has never executed has
not been tested, however carefully it was reviewed.** Its preflight, its resolve step
and its gates were all correct on the first run; the parts that touch the outside
world were not, and could not have been.

### Not a partial release

Both failed runs stopped before any upload. The registry showed `0.1.0, 0.1.1,
0.1.2` with `latest = 0.1.2` throughout, so `0.1.3` is **not burned** and the tag can
be re-pushed once this is fixed. `release-complete` reported `PARTIAL RELEASE`
correctly on both, and its instruction to check the registry by hand before
re-tagging is what established that.

### Fix shape

Two options, and the second is better:

1. **An npm automation token** in the `release` environment as `NPM_TOKEN`. Simple,
   and it is what the workflow already expects. It is also a long-lived credential
   with publish rights sitting in CI.

2. **npm Trusted Publishing (OIDC).** npm supports publishing authenticated by the
   GitHub Actions OIDC token, with no stored secret at all. The `publish` job already
   has `id-token: write` for provenance, so the token this needs is already being
   minted — this is close to free here, and it removes a standing credential rather
   than adding one.

### What was done

Option 2. `NODE_AUTH_TOKEN` is gone from the workflow entirely; `npm publish`
exchanges the Actions OIDC token — already minted for provenance — for a short-lived
credential. Nothing long-lived with publish rights sits in CI.

A useful side effect: with no token to fall back to, a trusted-publishing
misconfiguration **cannot** quietly publish an unattested tarball. It fails
ENEEDAUTH. The attestation is structurally guaranteed rather than flag-dependent,
which is why no `--provenance` flag is passed — npm generates it automatically under
trusted publishing, and `verify-artifact`'s `npm audit signatures` is the positive
proof it landed.

### The trap this exposed, worth its own note

Trusted publishing requires **npm >= 11.5.1 and node >= 22.14.0**.
`node-version: 22` gives node 22.23.1 — fine — and **npm 10.9.8**, which has no OIDC
support whatsoever. That mismatch does not announce itself: npm 10 looks for a token,
finds none, and fails **ENEEDAUTH** — indistinguishable from the missing-secret
failure this entry was originally about, and it would have sent the next person
looking for a secret that should not exist.

The workflow now installs a pinned npm and **asserts the floor**, so a bad pin fails
with "npm X is below the 11.5.1 floor" rather than as a phantom auth problem.

### Configured per PACKAGE, not per repository

All four packages were configured on 2026-08-10 with identical values — the form
has no per-package field, and `repository.directory` is a provenance source-link
hint that plays no part in publisher matching.

Configuration is possible from the CLI as well as the web UI, which was not obvious:
`npm trust github <pkg> --file release.yml --repo solara-associates/vaid --env
release --allow-publish`, requiring **npm >= 11.15.0** (`npx npm@11` resolves to the
locally installed npm, so the version must be pinned explicitly; `npm@latest` is 12.x
and refuses Node 22.17). There is also a documented REST endpoint,
`POST /-/package/{package}/trust`.

**Every trust operation requires 2FA, including `list`.** So nothing in CI can assert
that a package's trusted publisher exists before depending on it, and only
`vaid-skill` has been *proven* by an actual release. The other three are configured
as reported, not as observed; the first release of each is what confirms it.

A missing or wrong entry surfaces as **ENEEDAUTH at publish** — the same error a
too-old npm produces. That ambiguity is why the npm version floor is asserted
separately: if publish fails ENEEDAUTH on a run whose npm is >= 11.5.1, the version
floor is already ruled out and the trusted publisher is the thing to check.

`--allow-stage-publish` was deliberately not granted. The workflow only runs
`npm publish`, and an unused permission widens what a compromised workflow could do
for no benefit.

---

## B4 — a wrong digest delists the skill from the `skills` channel with no error anyone would see

**Status:** mitigated, not fixable. The mitigation is a scheduled check that must not
be removed — see "Why the scheduled job is not redundant" below.
**Observed:** 2026-08-10, publishing `skill/skills/vaid/SKILL.md` at
`https://solara.associates/.well-known/agent-skills/index.json`.
**Affects:** distribution of `vaid-skill` through `npx skills add https://solara.associates`.
Not the npm package, and not `npx vaid-skill`.

### What breaks

The agentskills.io discovery v0.2.0 index publishes a `digest` beside each artifact,
and the `skills` CLI (`vercel-labs/skills`, `src/providers/wellknown.ts`) gates the
install on it:

```js
const bytes = new Uint8Array(await response.arrayBuffer());
if (this.computeDigest(bytes) !== entry.digest) return null;
```

That is the correct behaviour and the reason to publish a digest at all. The defect
is in **how the refusal presents**.

### How it presents — which is not how it is described

`fetchArtifactSkillByEntry` returns `null`. `fetchAllSkills` filters nulls, gets an
empty array, and the CLI falls through to its direct-download fallback, which fails
on an index file. The installing user sees:

```
◇  No well-known skills found; trying direct download...
■  Downloaded URL is not a valid SKILL.md file or supported archive
└  Installation failed
```

There is **no checksum error, no digest, no mention of verification**. The message is
indistinguishable from "this domain publishes no skills" — that is, from us never
having published at all. Verified by running the real CLI against the real production
artifact with one hex character of the digest changed: exit 1, nothing written to
disk, and no output naming the cause.

### Why that is worse than a loud failure

Nothing reports back to us. There is no webhook, no error budget, no failed request
in our logs — the fetch of the artifact **succeeds**, and the rejection happens on a
stranger's machine. The only observable symptom on our side is that the skills.sh
install counter stops moving, which is indistinguishable from nobody installing it.

The window is real because deploy of the site is manual and has no trigger: the
repository can be correct and green while the origin serves something else. That is
the same shape as the stale trust anchor on 2026-08-10, where every copy in git was
byte-identical and correct while the origin served a note corrected three days
earlier.

### Why the scheduled job is not redundant

`synthera-site-redesign` guards this in two places, and they are **not** duplicates:

| check | where | proves |
|---|---|---|
| `check-agent-skills-index.mjs` | `vector-drift.yml`, PR gate | the committed index and the committed artifact agree with each other, and with this repo at a resolved head SHA |
| `check-agent-skills-index.mjs --live` | `anchor-origin.yml`, scheduled | the **origin** serves an index and an artifact that agree |

The PR gate cannot see a stale or failed deploy, because it never looks at the origin.
The scheduled job is the only thing that observes what an installer actually
downloads. It looks redundant precisely because it usually agrees with the PR gate —
it earns its place on the day it does not, and on that day nothing else is watching.

A served artifact also cannot gate the pull request that fixes it: such a check would
fail on the very PR that corrects the index and stay failing until that PR merged
**and** deployed. That is why it is scheduled rather than PR-gated, and why moving it
into the PR suite to "consolidate" would break it.

### Fix shape

None available on our side. The presentation is the CLI's, and we do not control it.
The mitigation is detection, and it is already in place. Two things must hold:

1. `agent-skills-origin` in `anchor-origin.yml` stays scheduled and stays enabled.
2. The digest is never hand-written. `npm run revendor:agent-skills-index` regenerates
   it from the artifact bytes; the check recomputes rather than trusting the written
   value, because a publisher that does not recompute is asking consumers to run a
   check it never ran itself.

Worth reporting upstream: the CLI could distinguish "digest mismatch" from "no index
here" in its output at no cost to the security property. Not filed.

---

## B5 — the discovery format we publish has no specification, and an upstream change delists us the same silent way

**Status:** open, unmitigated. B4's mitigation does **not** cover this; see
"Why the B4 checks cannot see this" below.
**Observed:** 2026-08-10, auditing distribution channels for the skill.
**Affects:** distribution of `vaid-skill` through `npx skills add https://solara.associates`.
Same channel as [B4](#b4), different cause: B4 is a value *we* get wrong, B5 is the
format being redefined underneath a value that is correct.

### What breaks

`public/.well-known/agent-skills/index.json` declares:

```json
"$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
```

That URL does not resolve. Not a 404 — the host does not answer at all
(`curl` exits with no response; HTTP code `000`). There is no schema document at the
other end of the identifier we publish.

Nor is the format specified anywhere else. `agentskills.io/llms.txt` lists nine pages;
none concerns discovery, distribution, hosting, or well-known URIs. The published
specification covers `SKILL.md` frontmatter and directory layout only. agentskills.io
is a **format spec, not a distribution channel**, and the discovery index is not part
of what it specifies.

The format is therefore defined in exactly one place: the TypeScript interfaces
`WellKnownIndexV2` / `WellKnownSkillEntryV2` in `vercel-labs/skills`,
`src/providers/wellknown.ts` — a Vercel implementation wearing an agentskills.io
identifier that agentskills.io does not serve. The consequence is that **the format
has no version we can track and no compatibility promise we can hold anyone to.**
Whatever that file says on the day a user runs `npx skills add` is the format.

### How it presents — identically to B4, and to never having published

The CLI rejects an index whose `$schema` it does not recognise, and treats an absent
`$schema` as legacy v0.1.0, which it then rejects for having no `files` array. Either
path discards the whole index rather than the offending entry. So if upstream ships
`discovery/0.3.0` and stops accepting `0.2.0`, our index — byte-correct, digest-valid,
serving exactly what it always served — stops being read, and the installing user sees:

```
◇  No well-known skills found; trying direct download...
```

The same message as a wrong digest, and the same message as a domain that publishes
nothing. Three distinct causes, one indistinguishable symptom, none of which reaches us.

### Why the B4 checks cannot see this

This is the part worth being precise about, because the checks look like they cover it
and do not:

| check | compares | would see a B5 break? |
|---|---|---|
| `check-agent-skills-index.mjs` (PR gate) | committed index ↔ committed artifact ↔ vaid repo at a resolved head SHA | **No** |
| `check-agent-skills-index.mjs --live` (scheduled) | origin index ↔ origin artifact | **No** |

Both validate us against the format **as transcribed on 2026-08-10**.
`DISCOVERY_SCHEMA_V2` is a hard-coded constant in our script, and `fetch-source.mjs`
pins the *vaid* repo — nothing in the estate fetches, pins, or diffs
`vercel-labs/skills`. An upstream redefinition leaves both checks green: our index
remains perfectly self-consistent, and self-consistency is the only thing they test.

That transcription is still the right call — the CLI is the authority, because the CLI
is what runs on the installing machine, and there is no spec to defer to instead. The
gap is not that we read the wrong source. It is that we **copied** the source instead
of **watching** it, and a copy cannot notice the original changing. Same shape as
"drift checks prove match, not currency": both sides can agree and both be stale.

### Fix shape

Watch the upstream definition rather than only our own conformance to a copy of it.
Cheapest sufficient version, additive to the existing scheduled job:

1. Fetch `vercel-labs/skills` `src/providers/wellknown.ts` at a resolved head SHA
   (same discipline as `fetch-source.mjs`: resolve, then pin, then print the SHA).
2. Assert the recognised schema constant still contains `discovery/0.2.0`, and that
   the well-known paths still include `/.well-known/agent-skills/index.json`.
3. Fail loudly on any change. A red X here means "read the diff and decide", not
   "something is broken" — the point is to be told, not to be correct.

Deliberately *not* proposed: vendoring the upstream file, or parsing it structurally.
Both re-create the copy problem one level up. A substring assertion over a pinned SHA
is enough to convert a silent delisting into a scheduled failure, which is the whole
requirement.

Not done because it belongs in `synthera-site-redesign` (where the index and the
existing checks live), not here, and because it wants an issue in that repo rather than
a drive-by commit. Recorded here so the reasoning is not re-derived.

---

## B6 — a check that derives its subject set, then translates it through a hand-written table, narrows silently when the table misses

**Status:** the one unsafe instance is fixed (PR #56). Recorded because the
construction recurs and nothing stops the next one being written the unsafe way.
**Observed:** 2026-08-11, auditing `scripts/check-readme-drift.mjs`.
**Affects:** the `scripts/` checks generally; three use the construction today.

### The shape

Deriving a check's subject set from the tree instead of hardcoding it is the right
instinct, and this repo does it deliberately — `check-readme-drift.mjs` says so in
its header: *"A second hardcoded list would drift the same way the first one did. So
the sets come from the tree."*

Derivation alone is not sufficient. If the derived keys are **translated** through a
hand-written table before use, that table is a second hardcoded list — the exact
thing derivation was meant to remove — and it sits where nobody looks for one. The
failure is not that the lookup errors. It is that the lookup *succeeds* at producing
nothing, and the set quietly comes out smaller than reality.

```js
const ecos = [...new Set(Object.keys(map.packages).map((k) => k.split('/')[0]))];
members: ecos.map((e) => ECO_TO_LANGUAGE[e]).filter(Boolean)   // <- the drop
```

`.filter(Boolean)` is the tell. So are `?? []`, `.filter((x) => TABLE[x])`, and
`for (…) { if (!TABLE[k]) continue }`. Each reads as defensive hygiene and each
converts *"I was not told about this"* into *"this does not exist."*

### What it cost here

`check-readme-drift.mjs` exists to catch stale enumerations in `README.md`, and its
header promised the derivation guaranteed it: *"Add a fourth language … and every
stale sentence here fails on the next run without anyone editing this file."*

It did not. Proven by adding a `go/` entry to `release-map.json`:

```
ecosystems parsed from release-map: [ 'rust', 'python', 'npm', 'go' ]
after map+filter(Boolean):          [ 'Rust', 'Python', 'TypeScript' ]
DROPPED SILENTLY:                   [ 'go' ]

✓ README.md — no stale enumerations, no hardcoded versions, every vector named.
```

A fourth language could have shipped with every "three languages" sentence in the
README still passing — this file's own defect class, reproduced inside the file
written to catch it. Fixed by halting on an untranslated ecosystem, on the principle
the packaged conformance firewall had already settled: **a check that cannot see the
whole set must never report PASS.**

The vector half of the same file was never affected: those come from `readdirSync`
with no translation step, so a tenth vector genuinely does appear on its own. The
difference between the two halves is precisely the lookup table.

### The other two instances, audited — both fail closed

Neither reproduces the defect. Recording the finding so this is not re-derived:

| script | table | behaviour on an unknown key |
|---|---|---|
| `release-outcome.mjs` | `REGISTRY` | `REGISTRY[ECO]?.(…)` → `url` undefined → `isPublished()` returns `null`, reported as `COULD NOT BE REACHED` and handled as a distinct third state. **Correct.** |
| `verify-package-versions.mjs` | `ECO` | `ECO[p.registry]` → `undefined` → `releaseTagFor` builds `undefined-<pkg>-v<ver>`, matches no tag, so every published version reports as untagged. **Fails closed, but misdiagnoses.** |

`release-outcome.mjs` is the model: an unreachable answer is a third state, not a
false negative. It degrades to "unknown" and says so.

`verify-package-versions.mjs` is safe but unhelpful — the remedy it prints tells you
to tag `undefined-vaid-pop-v0.2.1`, which is not a fix for anything. A reader would
eventually work out the table was the problem, having first gone looking for missing
tags that are not missing.

### Fix shape

Not another assertion — a rule about where these tables live:

1. **Every derive-then-translate site validates its table against the derived keys
   before use, and halts on a miss.** One guard at the derivation point, not a check
   per consumer. This is what PR #56 added to `check-readme-drift.mjs`.
2. **`verify-package-versions.mjs` gets the same guard**, so an unknown registry says
   so instead of blaming the tags.
3. Optionally, a lint over `scripts/` for `.filter(Boolean)` / `?? []` sitting
   between a derivation and an assertion. Deliberately listed last: the idiom appears
   in four of these scripts and in three of them it is the legitimate
   `split(…).filter(Boolean)` for dropping empty lines, so a naive rule is mostly
   false positives and would get muted.

Items 1 and 2 are small and worth doing. Item 3 probably is not, and is written down
mainly so the next person does not spend an afternoon discovering why.

### Why it has not been done

Item 1 is done for the file where it mattered. Item 2 is a real but low-severity
polish item on a check that already fails safely, and it wants to land with the guard
factored into something shared rather than pasted a second time — which is a slightly
larger change than the defect justifies on its own. Recorded rather than rushed.

---

## B7 — the Rust verifier re-projects typed field values and returns a verdict anyway, so the three implementations disagree on eight classes of document

**Status:** **fixed** 2026-08-11 by *preserve*. All eight classes now return the
same verdict AND the same reason in all three implementations — verified by
re-running the differential probe that found them, which went from eight
divergences to zero across thirty-four inputs. Each class is pinned by a case in
`verdict_v1.json`, so the agreement is a contract rather than a fact about one
afternoon. Shipped unreleased; changes which documents verify, so it needs a
version bump (breaking in Rust).

Preserve was chosen because it is what ADR-0006 already requires, not as a
preference between two open options. Requirement 3 ("MUST round-trip
byte-exactly... so that canonicalization is a function of the input alone") is
unconditional and Rust violates it; Decision 2's reject branch is scoped to
refusing a document *as unrecognised*, and a valid-RFC-3339 timestamp is a
recognised field in a non-canonical form, so reject would have extended the ADR
rather than applied it. B8 settled it empirically: under reject, every document
the Rust mint has ever produced stops verifying everywhere, including in Rust.
**Observed:** 2026-08-11, by differential probe while building `verdict_v1.json`.
Reproduced against untouched `main` (`9f47657`) through the pre-existing public
API only — `serde_json::from_str::<Vaid>` followed by `verify_vaid_authenticity`.
Nothing here depends on the graded verdict added alongside it.
**Affects:** `crates/vaid-mint`, `python/vaid-mint`, `typescript/vaid-mint`.

### What breaks

ADR-0006 states the rule plainly:

> An implementation MUST either verify over the presented bytes or reject the
> document explicitly; it MUST NOT re-project and return a verdict.

ADR-0006 closed this for unknown *members* — the `unknown_fields` flatten map on
`Vaid`. It did not close it for **typed field values**. `Vaid` deserializes
`vaid_id`/`parent_vaid` into `Uuid` and `issued_at`/`expires_at` into
`DateTime<Utc>`, both of which **normalize on re-serialization**. The verifier
then canonicalizes its normalized projection rather than the bytes it was handed.

Eight document classes on which the three implementations disagree:

| document | Rust | Python | TypeScript |
|---|---|---|---|
| `vaid_id` uppercased after signing | **valid** | inauthentic | inauthentic |
| `vaid_id` braced (`{…}`) after signing | **valid** | inauthentic | unparseable |
| `vaid_id` as `urn:uuid:…` after signing | **valid** | inauthentic | unparseable |
| `vaid_id` hyphenless after signing | **valid** | inauthentic | unparseable |
| `parent_vaid: null` deleted after signing | **valid** | inauthentic | inauthentic |
| `expires_at` as `…+00:00` (signed) | inauthentic | **valid** | **valid** |
| `expires_at` as `….000Z` (signed) | inauthentic | **valid** | **valid** |
| duplicate JSON keys | unparseable | **valid** | **valid** |

Both directions are live defects, and they are different defects.

**Rust accepts documents that were altered after signing.** The first five rows
were signed over one byte string and presented as a different one, and Rust
vouches for them. The alterations are all identity-preserving today — the same
UUID, the same absent parent — so no privilege changes hands, and that is the
only reason this is a correctness defect rather than a forgery bypass. It is not
a property anyone should rely on continuing to hold: it rests on the current
field set happening to contain no typed value whose normalization is semantically
significant.

**Python and TypeScript accept documents Rust rejects.** Rows six and seven are
an interop break, not a hypothetical: `Date.prototype.toISOString()` emits
`….000Z` *by default*, so a TypeScript caller who lets the platform format a
timestamp mints a document that verifies in two implementations and fails in the
third. There is no error message anywhere that would explain why.

**Duplicate keys** are a parser differential: `serde` rejects a repeated struct
field, `json.loads` and `JSON.parse` both take last-wins.

### How it presents

As a signature failure with no explanation — `verify_vaid_authenticity` returns
`false` and says nothing, because that is its documented contract. The holder has
a document that another implementation calls genuine.

Rust's own ADR-0006 gate would catch every row: `every_case_round_trips_byte_exactly`
asserts exactly the property being violated. It passes because no case in
`roundtrip_v1.json` uses an alternate UUID spelling, an omitted `parent_vaid`, or
a non-`Z` timestamp. The test is right and its inputs are too narrow — the
vector, not the assertion, is what is missing.

### A documented safety property that is not held

All three implementations carry this sentence on `has_conforming_timestamps`:

> *Not consulted by authenticity verification: a document that reached a verifier
> with a non-conforming timestamp will already fail the signature check, because
> the verifier re-serializes into the profile and recomputes different bytes.*

That is true of Rust and **false of Python and TypeScript**, which pass the
timestamp string through verbatim. Measured directly: for `…+00:00` and `….000Z`,
Python reports `has_conforming_timestamps=False` **and** `verify_vaid_authenticity=True`
on the same document. The comment describes one implementation's behaviour and is
asserted in all three.

### Why `verdict_v1.json` does not cover these

Deliberately. A vector encoding the current behaviour would freeze the defect as
the specification — the failure mode this repository has already recorded as
"tests encoding vulnerabilities as requirements". These rows belong in a vector
only once the rule below is decided, and then the vector pins the decision.

### Fix shape

Pick one rule and apply it in all three:

- **Preserve.** Keep `vaid_id`, `parent_vaid`, `issued_at` and `expires_at` as
  presented strings inside the signed projection, validating them separately.
  Rust stops normalizing; Python and TypeScript are already correct. Strictly
  honours ADR-0006 and makes Rust match the other two rather than the reverse.
- **Reject.** Have every implementation refuse any non-canonical spelling
  outright — lowercase hyphenated UUIDs and whole-second `Z` timestamps only.
  ADR-0006 permits this ("an implementation MAY refuse a document carrying
  members it does not recognise") provided the refusal is explicit. Narrower, and
  it makes E.6 enforced rather than advisory.

Preserve is the smaller change and the one consistent with ADR-0006's stated
preference. Either way the duplicate-key rule needs stating explicitly, because
"whatever three JSON parsers happen to do" is not a specification.

Whichever is chosen, the fix belongs with a version bump: it changes which
documents verify.

---

## B8 — the Rust mint emits timestamps that fail the repo's own E.6 profile

**Status:** **fixed** 2026-08-11, ahead of and independently of B7, on the
reasoning that a reference mint emitting documents that fail the spec's own
timestamp predicate is a defect regardless of which B7 option is taken. Shipped
unreleased; needs a version bump to reach consumers.

It also **decided** B7: it is the reason the "reject non-canonical forms" option
would have invalidated the reference mint's own output.
**Observed:** 2026-08-11, minting a root VAID through `MintService::mint_root`
and inspecting the serialized document.
**Affects:** `crates/vaid-mint` (the mint side, not the verifier).

### What breaks

The Rust issuer timestamps documents with `Utc::now()` and truncates nowhere.
`chrono`'s `Serialize for DateTime<Utc>` emits sub-second precision whenever the
value has any, so a freshly minted document carries:

```
issued_at  = "2026-08-11T08:04:18.165623Z"
expires_at = "2026-08-12T08:04:18.165623Z"
```

`docs/spec/encoding.md` E.6 specifies whole-second RFC 3339 in UTC with a literal
`Z`. The document above does not match it, and `has_conforming_timestamps`
returns `false` for it — the repository's own predicate, applied to the
repository's own reference mint.

The other two mints truncate explicitly and are conforming: Python formats with
`strftime("%Y-%m-%dT%H:%M:%SZ")`, TypeScript routes through
`utcWholeSecondRfc3339`. Rust is the only one that does not, and it is the one
whose language makes the omission invisible — nothing in the type system marks
`Utc::now()` as carrying more precision than the profile allows.

### How it presents

It does not, today. A Rust-minted document verifies everywhere: Rust signs over
the sub-second form and Python and TypeScript canonicalize the presented string
verbatim, so all three agree. The defect is silent precisely because the
verifiers are permissive about a form the spec says they should not accept.

### Why it decides B7

Under B7's **reject** option — every implementation refuses non-whole-second
timestamps — every document this mint has ever produced stops verifying, in every
implementation including Rust's own. That is not a migration; it is the reference
mint invalidating its own output. Reject only becomes tenable if this is fixed
first *and* no already-issued Rust-minted document needs to keep verifying.

Under B7's **preserve** option nothing here changes, because preserve leaves
permissive timestamp handling exactly as it is.

### Fix, as landed

Clock reads that may reach a signed document go through a named
`issuer::whole_second_now()` rather than a bare `.trunc_subsecs(0)` at each call
site — the omission being prevented is invisible, so the remedy is to make a
clock read that is *not* that one visibly not that one. `attest_delegation` also
truncates the caller's `expires_at`: the profile is a property of the signed
bytes rather than of who chose the value, and truncation only ever moves an
expiry earlier by under a second, which is the safe direction.

`Vaid::has_conforming_timestamps` was implemented as part of this — see B11; it
had been announced in the crate's changelog and never written, which is why Rust
had no way to ask the question at all.

Gates added in all three languages, asserting the serialized string directly as
well as the predicate (so a new predicate is not checked with a new predicate)
and carrying a negative control that requires the sub-second form to be rejected.
Verified to fire: reverting the one-line change turns them red and leaves every
other suite green.

Nothing frozen moves. Every vector supplies fixed whole-second timestamps
(verified: no vector in the tree carries a sub-second or offset timestamp), so no
digest changes and no vector is re-frozen. It changes the bytes *future* mints
produce, which is a behaviour change deserving a version bump but not a wire
change.

The durable half is a test asserting `has_conforming_timestamps` on a
freshly-minted document in each language. It is a one-line assertion that nobody
had written, which is why a non-conforming mint shipped.

---

## B9 — `is_expired` takes an evaluation instant in one implementation and not the others

**Status:** open. Recorded rather than fixed: aligning it is an API change, and
which direction to align is a design decision.
**Observed:** 2026-08-11, while writing `verdict_v1.json`.
**Affects:** `crates/vaid-mint`, `python/vaid-mint`, `typescript/vaid-mint`.

### What breaks

The three expiry predicates do not have the same shape:

| implementation | signature |
|---|---|
| TypeScript | `isExpired(vaid, now = new Date())` — accepts an instant |
| Rust | `Vaid::is_expired(&self)` — reads the wall clock, no parameter |
| Python | `is_expired(vaid)` — reads the wall clock, no parameter |

A caller can ask TypeScript "was this expired at time T". The other two can only
be asked "is this expired now". Behaviour agrees whenever the default is used, so
nothing currently gives a wrong answer.

### Why it matters, and what it already cost

It is a **testability** defect more than a correctness one, and it constrained
`verdict_v1.json` directly. A conformance vector cannot pin a verdict against a
chosen instant, because two of the three implementations are structurally unable
to be given one. Expiry is therefore pinned by *distance* instead — cases use a
timestamp two decades past and nine centuries hence — which works but cannot
express the case that actually matters: a document expiring at a boundary, and
whether the comparison is inclusive or exclusive at exactly `expires_at`.

That boundary is untested in all three implementations, and untestable across
them while this asymmetry stands. Rust and Python use `>` against the wall clock;
whether TypeScript agrees at the exact millisecond of expiry is unverified.

`verify_vaid_standing` deliberately does **not** forward TypeScript's parameter,
so the graded verdict does not widen the asymmetry — but it does not close it
either.

### Fix shape

Add an optional instant to Rust and Python, defaulting to now, so all three take
the same argument. Additive in all three: no existing call site changes. Then
vector the boundary case, which is the point of doing it.

The alternative — removing the parameter from TypeScript — is smaller but wrong:
it deletes the only implementation's ability to answer the question, to buy
symmetry.

---

## B10 — the structural parse gate is a hand-written mirror of a Rust struct, and nothing checks it still mirrors

**Status:** open. Introduced knowingly alongside `verdict_v1.json`; recorded here
because the weakness is in the design, not in the current contents.
**Observed:** 2026-08-11, on writing the gate.
**Affects:** `python/vaid-mint` (`_REQUIRED_MEMBERS`), `typescript/vaid-mint`
(`REQUIRED_MEMBERS`).

### What breaks

Rust's `Vaid` is a typed struct, so "is this JSON a VAID document at all" is a
question `serde` answers for free. Python and TypeScript hand their verifiers a
plain map and have no such gate, so one was written: a table of required members
and their types, in each of the two languages, mirroring the Rust struct
field-for-field.

**Nothing verifies that the mirrors still match the struct.** Add a field to
`Vaid` and Rust starts requiring it while Python and TypeScript keep accepting
documents without it. The two languages diverge from the reference silently, and
the failure is an *absence* — a member nobody listed — which no directory walk,
no type check and no existing conformance vector can see.

### How it presents

As a fresh instance of B7: the three implementations return different verdicts on
the same bytes, with the untyped two accepting what Rust rejects. It would be
found the way B7 was found — by differential probe — rather than by any check.

### The honest caveat this places on `verdict_v1.json`

The malformed-input cases in that vector currently agree across all three
implementations. That agreement is **constructed, not discovered**: the Python and
TypeScript gates were written to mirror Rust's behaviour, so the vector confirms
a mirror was built correctly rather than establishing that three independent
implementations happened to converge.

That is a materially weaker claim than the vector's other cases, where the
authenticity check order was already identical in all three before anything was
written, and the agreement was observed rather than arranged. Both kinds of case
live in one file and the file does not distinguish them; this entry is where the
distinction is recorded.

### Fix shape

Derive the required-member set instead of restating it — emit it from the Rust
struct at build time into a small JSON manifest, vendor that alongside the
vectors, and have the Python and TypeScript gates read it. The existing
freeze/`cmp` machinery then covers it for free, and adding a field to `Vaid`
becomes a change all three see at once.

Failing that, the minimum is a check that the three member lists are the same
set — which catches drift without catching type drift, and is strictly better
than the nothing that guards it now.

---

## B11 — a changelog "Added" entry is not evidence the thing was added, and nothing checks

**Status:** open. The instance found is fixed; the class is not.
**Observed:** 2026-08-11, while fixing B8.
**Affects:** every package in the repository.

### What breaks

`crates/vaid-mint/CHANGELOG.md` announces, under a released version:

> ### Added — `has_conforming_timestamps`
>
> `is_expired` stays **total** and never panics. `has_conforming_timestamps` is
> the new explicit `encoding.md` E.6 profile check…

The function did not exist in the Rust crate. Python and TypeScript both
implemented it; Rust's changelog described it as though Rust had. A consumer
reading the crate's own release notes would have believed the API was there, and
`cargo add vaid-mint` would have given them a crate without it.

### Why it is worse than a documentation slip

It is the direct reason B8 survived. `has_conforming_timestamps` is precisely the
predicate that answers "does this document meet E.6", and B8 was the mint failing
E.6. Rust could not ask the question, so nothing in Rust asked it — and the
changelog said the question was answerable, which is the kind of statement that
stops anyone checking.

This is the same shape as the repository's other masked-green findings: a
declaration and the thing declared are two different objects, and comparing
declarations to each other proves nothing about either. `verify-internal-versions`
already exists on exactly that reasoning, for version numbers. Nothing does it for
API claims.

### How it presents

It does not. Nothing fails. The gap is an **absence** — a function nobody wrote —
and absences are invisible to every check that walks what exists. The only reason
this one surfaced is that someone went looking for the predicate in order to use
it.

### Fix shape

A check that every `### Added — \`symbol\`` heading in a changelog names something
the package actually exports, per language: Rust via the public API surface,
Python via `__all__`, TypeScript via the package entry point. Heading text is
already structured enough to parse, and the check fails closed on a heading it
cannot resolve.

Bounded honestly: it can only cover claims written in that form, so it catches the
"Added — `symbol`" case and not prose claiming a behaviour. That is still the
common case and still strictly more than the nothing that guards it now.

---

## B12 — the release workflow packaged an npm workspace member before installing it

**Status:** **fixed** 2026-08-11, unreleased. Blocked the first 0.7.0 attempt.

**Correction to the first draft of this entry.** It said "neither job runs
`npm ci`". That was wrong, and wrong in a way worth recording: `preflight` *had*
the install all along, in a step that ran **after** the dry-run, and `publish`
installs correctly inside its own `run:` block and was never broken. The defect is
one misordered step in one job — an **ordering** error, not an absence. The
correct fix was to move an existing step, not to add a new one; the first attempt
at this fix added a duplicate install to both jobs and would have papered over the
real shape.
**Observed:** 2026-08-11, run `31478285695` for tag `npm-vaid-mint-v0.7.0` — the
first attempt to release an npm **workspace** package through this workflow.
**Affects:** `.github/workflows/release.yml`, both the `preflight` and `publish`
jobs, for every package under `typescript/`.

### What breaks

`preflight` ran `npm publish --dry-run` **before** its `npm build + test` step —
the step that runs `npm ci --prefix typescript && npm run build --prefix typescript`.
The install existed; it simply came second.

`vaid-mint`'s `prepublishOnly` is `npm run build && npm test`, so packaging
compiles the package. With no `node_modules` there is no `typescript`, no
`@types/node`, and no linked `vaid-pop`:

```
src/attestation.ts(78,66): error TS2307: Cannot find module 'vaid-pop'
src/bin/conformance.ts(5,1): error TS2591: Cannot find name 'process'
```

`vaid-pop` also needs to have been **built**, not merely linked: `vaid-mint`
consumes its type declarations from `dist/`, which is why CI runs
`npm ci --prefix typescript && npm run build --prefix typescript` before anything
else. The release workflow does neither.

### Why it took until now to surface

`vaid-skill` is the only npm package this workflow has ever published, and it
lives at `skill/` outside the workspace with no compile step in its publish path.
Every packaging assumption that holds for it fails for a workspace package that
builds. The workflow was proven on the easy case and generalised without being
re-proven.

### The good news, and it is not small

It failed **closed**, at preflight, with `publish: skipped`. The reporting was
exact:

> NOT RELEASED — vaid-mint@0.7.0 never reached the registry. This is the SAFE
> failure. The version is NOT burned. Fix the cause below, then re-tag the same
> version.

That is the structural fix from B2/B3 working as designed and being exercised for
the first time. The historical failures ran the dry-run *inside* verify-artifact,
after publishing; this one runs it in preflight, before. A version number was not
consumed and the same tag can be re-cut.

### Fix, as landed

`npm build + test` moved to immediately **before** the dry-run in `preflight`. One
step relocated; no step added, and `publish` untouched because it was already
correct. Building and testing before packaging is also the right order on its own
terms: prove it compiles and its suite passes, then prove it packages.

The durable half is a new invariant in `verify-release-workflow.mjs`: **in any job
that packages, an install must appear, and appear before the first packaging
step.** Ordering, not mere presence — presence was already satisfied by the broken
version, so a presence check would have passed it.

Proven to fire in both directions, and against the real defect: run against the
unfixed workflow it reports *"job `preflight` runs `npm ci` AFTER it packages"*;
with the step deleted it reports *"packages without ever running `npm ci`"*; with
the fix in place it is green.

One trap found while writing it: matching `npm publish` naively also matches the
step's `- name:` line, which necessarily precedes the `run:` block that installs —
so the check reported that `publish` installs after it packages, the exact opposite
of what that job does. Step names are now excluded on both sides. Same lesson as
the comment-stripping already in that file: something that *mentions* a command is
not the command.

Bounded honestly: the invariant cannot tell whether the install covers the right
directory, only that packaging is preceded by one. That is the error that actually
occurred; a wrong `--prefix` is a different check.

---

## B14 — the Rust and Python publish legs depend on secrets that do not exist, and had never been run

**Status:** **CLOSED** 2026-08-11. Trusted publishers configured on crates.io and
PyPI; both tags re-cut at `95aebba` and both legs published green through OIDC with
no stored secret anywhere. **0.7.0 is live on all three registries** and registry
parity is green on `main`. The three legs are now all *proven*, not assumed — which
is the condition B14 said had never held.

Re-cut at `95aebba` rather than at `b8b29c8`, because Actions runs the workflow
from the ref the tag points at: tagging the older commit would have run the old
token-based workflow and failed identically. Package bytes are unchanged between
the two commits (verified: `git diff` over `crates/ python/ typescript/ skill/` is
empty), so the artifact is the same either way.

**Each leg had a trap of its own, both shaped exactly like npm's version floor —
a failure indistinguishable from the credential being wrong:**

- **crates.io.** `cargo publish` cannot do OIDC at all; it only ever reads
  `CARGO_REGISTRY_TOKEN`. Configuring the publisher and expecting cargo to find it
  fails with *"please provide a non-empty token"* — the same message an absent
  secret produces, i.e. the same message this entry was opened for.
  `rust-lang/crates-io-auth-action` mints the token and cargo consumes it.
- **PyPI.** twine *does* exchange OIDC natively, but only when it finds **no**
  credential. A set-but-empty `TWINE_PASSWORD` — which is what a missing secret
  expands to — satisfies its credential lookup, so it never attempts the exchange
  and PyPI answers 403: identical to a missing or mismatched publisher. Removing
  those two env lines is what enables trusted publishing. twine >= 6.1.0 is
  required (trusted publishing landed 2025-01-17) and the floor is now asserted,
  mirroring npm's.
**Observed:** 2026-08-11, runs `31480913884` (rust) and `31480913945` (python).
**Affects:** `.github/workflows/release.yml`, the `publish` job.

### What breaks

The `publish` job authenticates each ecosystem differently:

| ecosystem | credential | result |
|---|---|---|
| npm | trusted publishing (OIDC), **no secret** | **published** |
| rust | `secrets.CARGO_REGISTRY_TOKEN` | `please provide a non-empty token` |
| python | `secrets.PYPI_API_TOKEN` via `TWINE_PASSWORD` | `403 Forbidden from upload.pypi.org` |

Checked directly: `repos/.../environments/release/secrets` and
`repos/.../actions/secrets` are **both empty**. Neither token exists at either
scope. Rust received an empty string and said so plainly; Python sent an empty
password and PyPI answered 403, which reads as a permissions problem rather than
as a missing secret — the same misdirection B3 recorded for npm's `ENEEDAUTH`.

npm succeeded for exactly the reason the other two failed: it is the only leg that
needs no stored credential.

### Why this survived every check

Because no check can see it. `verify-release-workflow.mjs` asserts the workflow's
*structure*; a secret's existence is repository state, not file content. And the
Rust and Python legs had **never run** — the workflow's only prior executions were
three `vaid-skill` npm tags. B3 recorded "the release workflow has no npm
credential, and had never run", fixed npm, and closed. The other two legs were
left in the same condition and the entry did not say so, so "the release workflow
works" was established for one ecosystem and assumed for three.

That is the same shape as B12 one layer up: proven on the case that was exercised,
generalised without being re-proven.

### The failure was safe, again

Both legs stopped at `publish` with `verify-artifact: skipped`, and both reported:

> NOT RELEASED — vaid-mint@0.7.0 never reached the registry. This is the SAFE
> failure. The version is NOT burned. Fix the cause below, then re-tag the same
> version.

`0.7.0` is unclaimed on both registries. No re-numbering is needed.

### Fix shape

1. Add `CARGO_REGISTRY_TOKEN` and `PYPI_API_TOKEN` to the `release` environment —
   or, better and matching npm, move both to **trusted publishing**: crates.io and
   PyPI both support OIDC now, which removes the stored credential rather than
   supplying one. That also removes the failure mode where a token expires
   silently between releases.
2. Re-run the two failed `publish` jobs, or delete and re-cut
   `rust-vaid-mint-v0.7.0` and `python-vaid-mint-v0.7.0`. The commit is correct
   (`b8b29c8`) and the version is not burned, so nothing else changes.

The durable half is harder than B12's and worth stating rather than pretending
otherwise: a check cannot prove a token is *valid* without spending it. What it
**can** assert is that every ecosystem in `release-map.json` has a publish path
whose credential is either OIDC or a named secret that exists — presence, not
validity. That would have caught this, and it is the honest bound.

### The wider point

A release path is not "working" until every leg has run. Three ecosystems, one
proven, and the two unproven ones failed on the first attempt — which is the
expected rate for anything never exercised, not bad luck.

---

## B15 — the PyPI release carries no provenance attestation

**Status:** **fixed in the workflow** 2026-08-11, and **unproven until the next
release** — proving it needs a version to publish, and cutting one solely to
demonstrate a fix is not a reason to burn a version number. Verify at source on
the next release, not from the JSON pointer.

**Correction to the first draft of this entry**, in the same class as B12's: the
conclusion was right and one line of the evidence was not. It cited
`/pypi/{pkg}/{version}/json → provenance: null` as proof. That field is null for
**every package on PyPI** — measured against cryptography, pydantic, urllib3,
attrs, rich, packaging and build, all of which return null, and cryptography
demonstrably *does* attest. It proves nothing either way. The load-bearing
evidence is the **integrity endpoint**, which was also cited and is the real
signal: 404 `No provenance available` for vaid-mint, HTTP 200 with a full bundle
for cryptography.
**Observed:** 2026-08-11, immediately after `vaid-mint` 0.7.0 published to PyPI
through trusted publishing.
**Affects:** `.github/workflows/release.yml`, the Python publish step.

### What breaks

The package published, through OIDC, with no stored credential — and with **no PEP
740 attestation**. Measured at source rather than inferred:

```
pypi.org/integrity/vaid-mint/0.7.0/<file>/provenance  →  404 No provenance available
pypi.org/integrity/cryptography/50.0.0/<file>/provenance → 200, 1 attestation, pyca/cryptography
```

(The JSON API's `provenance` key is null for both and for every other package
checked; it is not the signal. See the status note above.)

Trusted publishing and attestation are **two different things**, and having the
first does not give you the second. `twine upload` does not generate attestations
unless asked (`--attestations`); `pypa/gh-action-pypi-publish` generates them by
default, which is why this is easy to assume.

### Why it matters here more than for most projects

The other two legs have provenance a third party can check:

| registry | what a consumer can verify | |
|---|---|---|
| npm | full SLSA v1 attestation, signed, naming repo, workflow, ref and **source commit** | ✓ |
| crates.io | `trustpub_data` recording provider, repository, `run_id` and `sha`; `published_by: null` | ✓ |
| PyPI | nothing | ✗ |

This repository's entire argument is that a claim should be settled by running
something rather than by reading a page. "This artifact was built from this commit
by this workflow" is exactly such a claim, and on PyPI it currently rests on
trusting the release notes.

### Fix, as landed — and `--attestations` alone is a NO-OP

The fix shape first written here was wrong, and wrong in the way that matters:
**`twine upload --attestations` does not generate anything.** twine only
*discovers* adjacent `{dist}.*.attestation` files and uploads them; generation is
deliberately kept out of twine. Shipping the flag by itself would have looked like
a fix, changed nothing, and left the gap with a closed ticket over it.

What landed is generation plus upload:

```
python -m pip install ... pypi-attestations
python -m pypi_attestations sign <dir>/dist/*
twine upload --attestations <dir>/dist/*
```

`pypi_attestations sign` uses the workflow's **ambient OIDC identity** — the same
`id-token: write` trusted publishing already requires — so it adds no credential
and no new trust relationship. PyPI rejects an attestation whose identity is not a
configured Trusted Publisher, so this cannot succeed unless the publisher is the
one already configured.

`pypa/gh-action-pypi-publish` would do both by default, and was still declined: it
would replace the build, `twine check`, floor assertion and directory handling —
all now understood — with one opaque step, to save two lines.

The durable half landed in `verify-artifact`, the Python counterpart of
`npm audit signatures`: for every file PyPI lists, query the integrity endpoint and
require at least one attestation. Proven in both directions before shipping —
vaid-mint 0.7.0 fails it, naming both files; cryptography 50.0.0 passes across all
46 of its files.

It runs **after** publish, so it fails a release rather than preventing one. That
is the right trade: the alternative is not checking, which is what this entry was.
`release-outcome.mjs` already separates a published-but-unverified release from an
unpublished one, so the report stays accurate.

### 2026-08-12 — the fix is now guarded, and still unproven

Re-audited. The workflow steps above are on `main` and correct; nothing about the
status changed. **PyPI has still never published an attestation for this project** —
`pypi.org/integrity/vaid-mint/0.7.0/<file>/provenance` returns 404 for both files
today, because 0.7.0 published at 11:11 and the fix landed at 15:57. It stays
unproven until a release carries it, and no release was cut to demonstrate it.

What was added is the missing durable half. The generation step had **no check over
it**: `verify-release-workflow.mjs` asserted `npm audit signatures` for npm and
nothing at all for PyPI, so `pypi_attestations sign` could be deleted, or reordered
after the upload, or `--attestations` dropped, and every check would stay green
until the next release silently republished the original defect. Invariant 8 now
asserts all three plus the integrity-endpoint check in `verify-artifact`, and each
was **mutation-tested** — the four corresponding edits were applied to `release.yml`
one at a time and each produced a distinct failure.

That check needed correcting once before it was right, in this file's recurring
way: the first draft matched `/twine upload/` anywhere, which also matches the words
"or twine uploaded without --attestations" inside `verify-artifact`'s **own B15
error message**. It reported that the verify job publishes to PyPI, on a workflow
that is correct. Third instance of mistaking a command's NAME for the command — see
the comment-stripping note and invariant 6's `- name:` note. The matchers are now
anchored to the start of a line.

The stale claim in `release.yml`'s header was also removed. It read "NOT ENABLED:
Rust and Python have no equivalent here … PyPI attestations need Trusted Publishing
(OIDC) instead of the API token this workflow uses" — untrue in both halves since
2026-08-11, sitting above a file that does exactly what it says is not done. That
is the failure this entry and B16 both circle: **a comment cannot hold a property.**
It is replaced by a per-registry statement of what each one actually proves,
including that crates.io's `trustpub_data` is registry-attested build metadata
rather than a signed statement a consumer can check without trusting the registry.

---

## B16 — enable "require trusted publishing for all new versions" on crates.io and PyPI

**Status:** open, and **deliberately not done yet**. Recorded as a follow-up at the
repository owner's instruction.
**Raised:** 2026-08-11, once 0.7.0 had published successfully through trusted
publishing on both registries.

### What this is

Both registries can be set to **refuse** any upload that does not come through a
trusted publisher, which removes API tokens as a publishing route entirely. Right
now the tokens are merely unused: the workflow references none, and
`verify-release-workflow.mjs` invariant 7 stops it referencing one again. But a
human with a token could still publish by hand, and so could anyone who obtained
one.

### Why it is not done in the same breath as the migration

Because a fallback should not be removed in the moment you might need it. The
trusted-publishing path had, at the time of writing, published exactly once per
registry. One success is evidence that it works; it is not yet evidence that it
keeps working across a toolchain bump, an action update, or a registry-side change
to the OIDC contract. Turning off the alternative while the replacement has a
sample size of one converts any future failure from "publish the other way and
investigate" into "cannot publish at all".

This is the same discipline the release workflow already applies to itself —
`release-outcome.mjs` distinguishes *not established* from *failed* — applied to
an operational decision rather than to a report.

### When to do it

After the next release publishes cleanly through trusted publishing on all three
registries. That is the second data point, and it is also the point at which any
per-release configuration drift would have shown itself.

### What to enter — corrected 2026-08-12, and the two registries are NOT symmetric

The paragraph this replaces said "Both settings live beside the publisher
configuration that is already in place: crates.io under the crate's Trusted
Publishing settings, PyPI under the project's Publishing settings." **The PyPI half
of that sentence describes a setting that does not exist.** It was written from the
reasonable assumption that a registry offering trusted publishing also offers a way
to require it. Only one of the two does.

**crates.io — the setting exists.** A per-crate `trustpub_only` boolean, shipped
via rust-lang/crates.io#12361. It is a checkbox on the crate settings page and also
`PATCH /api/v1/crates/{name}` with body `{"crate":{"trustpub_only":true}}`. It
defaults to false and is **publicly readable**, unauthenticated, so live state can
be confirmed rather than assumed:

```
curl -sS https://crates.io/api/v1/crates/vaid-mint | jq .crate.trustpub_only
```

Measured 2026-08-12 — `vaid-mint`, `vaid-pop` and `vaid-client` are all **false**.

**PyPI — no such setting exists.** There is no per-project switch to reject
token-authenticated uploads once a trusted publisher is configured; the docs treat
tokens and trusted publishers as coexisting, and the request for it
(pypi/warehouse#17260, which proposes auto-revoking *unused* tokens rather than
refusing them) is still open. The nearest available action is therefore different
in kind: **delete the project-scoped API tokens** from the PyPI account, which
removes the route instead of refusing it. That cannot be verified from the registry
side the way crates.io can — absence of a token is not a public fact — so the check
is a human reading the account's token list.

### What blocks the crates.io half

Not a decision — a credential. The stored `~/.cargo/credentials.toml` token is
scoped `publish-update` and returns **403 `this token does not have the required
permissions`** on the PATCH. `trustpub_only` needs either cookie auth (the web UI)
or a non-legacy token carrying the `trustpub` scope plus a matching crate scope.

### Do not enable this on `vaid-pop` or `vaid-client` yet

B16's own reasoning, applied per crate rather than per registry. The
trusted-publishing evidence is **`vaid-mint` only** — it is the one crate 0.7.0
published, and crates.io records `trustpub_data` for it naming run `31485249456`.
`vaid-pop` (0.2.1) and `vaid-client` (0.1.0) both predate the migration and have
**never published through this workflow at all**. Whether either has a trusted
publisher configured is not readable with the credential on hand.

Enabling `trustpub_only` on a crate whose publisher config has never been exercised
does not remove a fallback — it removes the *only* path, and the failure would
appear at the next release as the same "cannot publish" that B14 spent a day
diagnosing. Enable `vaid-mint` first; enable the other two only after each has
published once through the workflow, or after its config has been read back from
the crates.io UI.

---

## B17 — the release environment's approval gate cannot be approved from the GitHub UI

**Status:** open, and **worked around** on every release so far. The workaround is
not obvious and should not have to be rediscovered.
**Observed:** twice, on both 0.7.0 attempts — runs `31480913884` / `31480913945` /
`31480914087`, then `31485249456` / `31485249478`.
**Affects:** anyone releasing this repository.

### What breaks

The `publish` job is gated on the `release` environment, whose reviewer is the
`solara-associates` account. Approving through the GitHub web UI **does not
register**: the run stays `waiting` and
`GET /actions/runs/{id}/pending_deployments` continues to return the pending
entry. Observed twice, on separate releases, more than ten minutes after
approving, and once after a further 90-second wait.

The cause is not established. What *is* established is that the API route works
and the UI route did not, on both occasions.

### The workaround, exactly

```bash
ENVID=$(gh api repos/solara-associates/vaid/actions/runs/$RUN/pending_deployments \
          -q '.[0].environment.id')

echo "{\"environment_ids\":[$ENVID],\"state\":\"approved\",\"comment\":\"...\"}" \
  | gh api -X POST repos/solara-associates/vaid/actions/runs/$RUN/pending_deployments --input -
```

**`environment_ids` must be a real JSON array of integers.** The obvious `gh api`
form is wrong and fails unhelpfully:

```
gh api -X POST .../pending_deployments -f "environment_ids[]=$ENVID" -f state=approved
  → HTTP 422: For 'items', "19439529798" is not an integer.
```

`-f` sends every value as a string, and the endpoint rejects a stringified id. So
the payload has to be built as JSON and piped through `--input -`. That is the
whole trick, and it is the reason this entry exists rather than a one-line note.

### Check the commit before approving

Related, and sharper than it sounds: a release may have **more than one run
pending for the same tag** if the tags were re-cut while earlier runs were waiting.
That happened here — two full sets of runs, on different commits, both showing
`vaid-mint-v0.7.0`, one of them from a commit whose vector was two cases short.
Nothing in the UI distinguishes them.

Always confirm what you are approving:

```bash
gh run list --workflow=release.yml --limit 6 \
  --json databaseId,headBranch,headSha,status
```

and cancel the stale runs before approving the current ones. A publish cannot be
taken back.

### Fix shape

Diagnose the UI failure first — it may be an account/permission quirk rather than
anything about this repository, and if so the finding belongs upstream rather than
here. Until then the API route is the release procedure, and it should be written
into `CONTRIBUTING.md` beside the tag instructions rather than living only in a
backlog entry, because the person who needs it is mid-release when they need it.

---

## B18 — claims-register freshness is a timer, not a verification, so `main` reddens on a schedule

**Status:** open, and **not yet due** — which is the reason to decide it now rather
than under the deadline. Scoped 2026-08-12 at the repository owner's request; no
implementation.
**Observed:** `docs/claims-register.json` holds one claim,
`framework-governance-demonstrated`, `date_last_verified: 2026-07-28`. At the time
of writing that is 15 days old, against a 60-day WARN and a 90-day FAIL budget:
**45 days to amber, 75 to red**, then again every 90 days after each date bump,
indefinitely.
**Affects:** `scripts/verify-claims.mjs`, `docs/claims-register.json`, and the
`capabilities` CI job that runs them.

### What breaks

Nothing yet, and that is the point. `verify-claims.mjs` fails a claim whose
`date_last_verified` is missing, or older than its budget. The date is **hand-set**.
So the check measures *how long ago someone typed a date*, not whether the claim is
still true. It goes red on a timer whether or not anything changed, and it goes
green the moment the date is edited whether or not anything was re-run.

That gives the pressure an obvious release valve: when it reddens and blocks
unrelated work, the cheap move is to bump the date. The check then **certifies
staleness while reporting freshness** — the same masked-green shape as B11 (a
changelog claiming an API nobody wrote) and B14 ("the release workflow works",
established for one ecosystem and assumed for three). A check whose easiest
repair is a lie is a check that will eventually be repaired that way.

### A second gap, underneath

`verify-claims.mjs` requires `verified_artifact` to be a **non-empty string**. It
never resolves it. The one claim's artifact and evidence are:

```
forge-agents/harness/artifacts/phase1e-conformance-2026-07-28.md
forge-agents/harness/phase1e_adk_conformance.py
```

Both are **absent from this repository and always will be** — they live in
`forge-agents`. The register points across a repo boundary and nothing checks the
pointers land. That is the load-bearing-file-with-no-home pattern one level up:
the reference is committed here, the referent is somewhere this repo cannot see,
and no check can tell the difference between a valid path and a typo.

### The split that decides whether this is automatable

Claims fall into three kinds, and the register currently applies one 90-day rule
to all of them.

**A — verifiable from public artifacts, no credentials.** Registry parity,
packaged firewalls run from clean installs, conformance vectors, provenance at
source (`npm audit signatures`, the PyPI integrity endpoint, crates.io
`trustpub_data`). This repository already does every one of these in CI. A
scheduled workflow can re-run them and **derive** the date from the run, so it can
never be stale-but-green. Fully automatable, no secrets, no human.

**B — needs operator credentials against private infrastructure.** The current
claim: its verifier is a Cloud Run job execution in `synthera-substrate-prod` /
`europe-west1`, at a `forge-agents` SHA, writing an artifact in that repository.
Re-running it requires GCP credentials into a private project and a harness this
repository does not contain.

Automatable in principle by federating this repo's CI into that project — but that
grants this repository the ability to execute jobs in the substrate, which is a
trust decision and SYNTHERA's to make, not this repo's. **The cheaper shape is to
invert it:** let the job run on a schedule *where the credentials already are*, and
publish a dated artifact that this repository **fetches and verifies**. Producing
becomes someone else's problem; consuming is category A.

**C — irreducibly human.** Claims about meaning rather than mechanism. The current
claim contains one: *"one governance layer, not one per framework."* Running the
harness is mechanical; whether its output demonstrates that sentence is judgement.
No schedule closes that, and pretending otherwise is how a green check comes to
stand for an assertion nobody re-read.

### What would have to change

**Store a verification, not a date.** Each claim carries the command that
establishes it plus what makes its result still valid. Then:

- **A** derives its date from a run; a hand-edited date becomes impossible rather
  than merely discouraged.
- **B** consumes a dated artifact from the environment that owns the credentials,
  and the check verifies the fetched artifact — which is A again.
- **C** is *marked as human*: a named person, its own budget, and arguably outside
  the blocking gate entirely, because a timer on a judgement call blocks work
  without improving the judgement.

Resolving `verified_artifact` is a separate, smaller fix and worth doing either
way: in-repo paths must exist; cross-repo references need a form the checker can
follow (a URL it can fetch, or a digest it can compare) rather than a string it
merely confirms is non-empty.

### Why decide it now

There is exactly **one** claim, so the register is as cheap to restructure as it
will ever be, and 45 days before anything goes amber. The awkwardness is that the
single claim is category **B** — the hardest kind — so the first instance
demonstrates none of the easy path, and building only for it would produce
machinery shaped entirely around the exception.

The decision this entry exists to force: **whether the register is a gate or a
record.** As a gate it must be derivable, which means category C claims do not
belong in it. As a record it can hold all three kinds, and the CI job checks only
the derivable ones. Both are defensible; the current design is the third option —
gate everything, derive nothing — and that is the one that reddens on a timer and
teaches people to edit the date.
