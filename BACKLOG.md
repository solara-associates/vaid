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
