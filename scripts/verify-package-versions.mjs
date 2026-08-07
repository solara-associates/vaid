// Registry-parity check — every publishable package's IN-REPO version must be
// PUBLISHED on its registry, INDEPENDENT of any capability claim.
//
// Why this exists: the capabilities verification check only validates versions a
// *capability* names. A package can be version-bumped in-repo and never published,
// and nothing catches it — exactly what happened with python vaid-pop (repo 0.2.0
// while PyPI served 0.1.0). Repo and registry disagreeing silently is precisely the
// class of drift the manifest exists to prevent.
//
// It asserts the in-repo version EXISTS on the registry — NOT that it equals the
// latest. A repo legitimately sits at a version that is about to be published; the
// release gate (CONTRIBUTING) makes bump-and-publish near-atomic, so "bumped on main
// but not yet published" SHOULD be red until you publish. That is the point.
//
// Opt-out for a package not meant for a public registry:
//   - Rust (Cargo.toml [package]):   publish = false            (Cargo-native)
//   - Python (pyproject [project]):  classifier "Private :: Do Not Upload"
//   - npm (package.json):            "private": true            (npm-native)
//
// A WAIVER (see WAIVERS below) is a different thing from an opt-out, and mixing
// them up would be a lie in the repository: an opt-out says "never publishing
// this", a waiver says "publishing this is the plan, and the block is a decision
// no pull request can make." Marking the TypeScript packages `"private": true`
// to get a green tick would delete the intent to publish them from the repo.
//
// Fails LOUD, fails CLOSED on network — same posture as verify-capabilities.mjs.
//
// Run: node scripts/verify-package-versions.mjs   (also wired into CI)

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const UA = { 'User-Agent': 'solara-vaid-registry-parity-check' };
const TODAY = new Date().toISOString().slice(0, 10);

/* -------------------------------- waivers -------------------------------- */
//
// POSTURE, same as the substrate's `.cargo/audit.toml`: a waiver states what
// blocks it, who can unblock it, and what makes it VOID. It is never "this does
// not matter" — it is "this is red for a stated reason, and here is the reason."
//
// Enforced in BOTH directions, so a waiver cannot rot quietly:
//   · waived + not published  -> WAIVED   (the expected state)
//   · waived + PUBLISHED      -> FAILURE  (stale waiver; delete it)
//   · waiver past `expires`   -> FAILURE  (re-decide, do not drift)
//   · waiver matching nothing -> FAILURE  (dead waiver; delete it)
// No waivers. The TypeScript packages were waived here from 2026-08-03 until they
// were published to npm later the same day; the waiver's published-but-waived
// check fired on the next run and named itself as stale, which is what removed it.
// Keep the empty list rather than deleting the mechanism — the enforcement below
// is what makes a future waiver honest.
const WAIVERS = [];

// Keyed by name+registry: `vaid-pop` also exists as a crate and a PyPI package,
// and this waiver is about the npm ones only. Keying on the bare name would
// silently waive the published Rust and Python packages too.
const WAIVED = new Map();
for (const w of WAIVERS) for (const n of w.names) WAIVED.set(`${w.registry}:${n}`, w);

/* ---------------------------- registry scope ----------------------------- */
//
// THE DECLARED MATRIX of (registry, package) pairs this repository intends to
// exist. Everything else in this file discovers packages by walking `crates/`,
// `python/` and `typescript/`; this is the only place that states what SHOULD be
// there.
//
// Why it exists: discovery-by-directory cannot distinguish "we decided not to
// build this" from "nobody built this and nobody noticed". PyPI `vaid-client` was
// the live instance — `python/vaid-client/` does not exist, so the loop below
// never produced a package, so no check ever had an opinion. It was not a
// suppressed failure or a waived one; it was NOT A SUBJECT. An opt-out marker
// cannot help either: the marker lives in a manifest, and the manifest is what is
// missing. Absence had no representation in the repo at all, and reading the
// green tick as "all packages published" was reasonable and wrong.
//
// So: absence must now be STATED to be legal.
//
// Enforced in BOTH directions, so neither half can rot quietly:
//   · declared applicable + directory exists   -> checked normally
//   · declared applicable + NO directory       -> FAILURE (vanished or never built)
//   · declared not-applicable + NO directory   -> OK, reason printed every run
//   · declared not-applicable + DIRECTORY      -> FAILURE (stale; delete the entry)
//   · directory with NO declaration            -> FAILURE (undeclared package)
//   · manifest name ≠ declared name            -> FAILURE (renamed under the radar)
//
// `applicable: false` is a THIRD thing, distinct from both an opt-out and a waiver,
// and conflating them would put a lie in the repository:
//   · opt-out (`publish = false`, `"private": true`, `Private :: Do Not Upload`)
//       — the package EXISTS and we will never publish it.
//   · waiver  — the package EXISTS, publishing it is the plan, and a decision no
//       pull request can make is blocking it.
//   · applicable: false — the package DOES NOT EXIST and is not planned. There is
//       no artifact, no manifest, and nothing to publish.
// Using an opt-out here would require inventing `python/vaid-client/` just to mark
// it private, which would assert a Python implementation exists. It does not.
const REGISTRY_SCOPE = [
  { registry: 'crates.io', dir: 'crates/vaid-mint',      name: 'vaid-mint' },
  { registry: 'crates.io', dir: 'crates/vaid-pop',       name: 'vaid-pop' },
  { registry: 'crates.io', dir: 'crates/vaid-client',    name: 'vaid-client' },

  { registry: 'pypi',      dir: 'python/vaid-mint',      name: 'vaid-mint' },
  { registry: 'pypi',      dir: 'python/vaid-pop',       name: 'vaid-pop' },
  { registry: 'pypi',      dir: 'python/vaid-langchain', name: 'vaid-langchain' },
  {
    registry: 'pypi',
    dir: 'python/vaid-client',
    name: 'vaid-client',
    applicable: false,
    reason:
      'Python has no separate client package: the request signer ships INSIDE vaid-pop as ' +
      '`vaid_pop.signer.RequestSigner` (python/vaid-pop/vaid_pop/signer.py), which is why ' +
      'python/vaid-pop/README.md calls vaid-client "(Rust)" — the cross-language peer, not a ' +
      'missing sibling. vaid-client is a TWO-language package by design (Rust + TypeScript). ' +
      'No doc, README or site page instructs `pip install vaid-client` (verified 2026-08-07), ' +
      'so nothing is currently broken by its absence. To make this entry go away, build a real ' +
      'Python vaid-client — do NOT delete the entry to silence the check.',
  },

  { registry: 'npm',       dir: 'typescript/vaid-mint',   name: 'vaid-mint' },
  { registry: 'npm',       dir: 'typescript/vaid-pop',    name: 'vaid-pop' },
  { registry: 'npm',       dir: 'typescript/vaid-client', name: 'vaid-client' },
];

const SCOPE_BY_DIR = new Map(REGISTRY_SCOPE.map((s) => [s.dir, s]));

/* --------------------------- release tag parity --------------------------- */
//
// The SECOND assertion this script makes, and the one that closes a blind spot in
// verify-vector-freeze.mjs rather than duplicating it.
//
// That check compares each vector against the release tag FOR THE PACKAGE'S CURRENT
// VERSION. It therefore protects only the version the repo sits at right now: a
// release that ships untagged and is then superseded is never checked by it, and the
// gap closes silently when the next release is tagged. That is not hypothetical —
// vaid-pop 0.2.0 shipped untagged, its vectors sat in that check's "NOT CHECKED"
// list, and the gap was closed by 0.2.1 being tagged rather than by anyone noticing.
//
// The failure mode is an UNTAGGED PUBLISH, not an unchecked history, so this asserts
// exactly that: every version on the registry has a tag. It fires at the moment the
// publish happens, when the commit is still obvious. Recovering it afterwards means
// archaeology — reading .cargo_vcs_info.json out of a .crate, or matching an sdist's
// bytes against every commit, which is what backfilling the six pre-0.2 releases took.
//
// Deciding NOT to enumerate tags in verify-vector-freeze.mjs instead was deliberate:
// that check is offline by design ("cannot be affected by an outage"), and comparing
// today's vector against every historical tag would fail on legitimate re-freezes —
// mint_v1.json moved at the ADR-0004 v3 break, correctly.
//
// YANKED VERSIONS STILL REQUIRE A TAG. Yanked means "exists but must not resolve",
// not "never happened"; the tag is what makes it auditable afterwards.

/** Every tag in the repository. Fails CLOSED: without tags this cannot assert. */
let TAGS;
try {
  TAGS = new Set(
    execFileSync('git', ['tag', '--list'], { cwd: fileURLToPath(ROOT), encoding: 'utf8' })
      .split('\n').map((s) => s.trim()).filter(Boolean),
  );
} catch (e) {
  console.error(`✗ RELEASE TAG PARITY FAILED — cannot list git tags (failing closed): ${e.message}`);
  console.error('  In CI this usually means a shallow checkout. Use `fetch-depth: 0`.');
  process.exit(1);
}

const ECO = { 'crates.io': 'rust', pypi: 'python', npm: 'npm' };

/**
 * The release tag for one published version, using the same three forms
 * verify-vector-freeze.mjs resolves — most specific first, ecosystem form as the
 * fallback. Kept identical on purpose: two checks disagreeing about what a release
 * tag looks like would be worse than either being absent.
 */
function releaseTagFor(eco, name, version) {
  for (const t of [`${eco}-${name}-v${version}`, `${eco}-v${version}`, `v${version}`]) {
    if (TAGS.has(t)) return t;
  }
  return null;
}

/** Every version published on a registry, newest-first order not guaranteed. */
async function publishedVersions(registry, name) {
  const url =
    registry === 'crates.io' ? `https://crates.io/api/v1/crates/${name}`
    : registry === 'pypi'    ? `https://pypi.org/pypi/${name}/json`
    : registry === 'npm'     ? `https://registry.npmjs.org/${name}`
    : null;
  if (!url) throw new Error(`unknown registry '${registry}'`);
  let res;
  try { res = await fetch(url, { headers: UA }); }
  catch (e) { throw new Error(`network error fetching ${url}: ${e.message}`); }
  // A package with nothing published yet is not an error here; the parity check
  // above is what reports "bumped but not released".
  if (res.status === 404) return [];
  if (res.status !== 200) throw new Error(`unexpected HTTP ${res.status} from ${registry} for ${name}`);
  const j = await res.json();
  if (registry === 'crates.io') return j.versions.map((v) => v.num);
  if (registry === 'pypi') return Object.keys(j.releases);
  return Object.keys(j.versions);
}

const failures = [];
const notes = [];
const waived = [];
const waiversHit = new Set();

const sectionText = (toml, header) => {
  const m = toml.match(new RegExp(`\\[${header}\\]([\\s\\S]*?)(?=\\n\\[|$)`));
  return m ? m[1] : '';
};
const strField = (sec, key) => {
  const m = sec.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, 'm'));
  return m ? m[1] : null;
};
const boolField = (sec, key) => {
  const m = sec.match(new RegExp(`^\\s*${key}\\s*=\\s*(true|false)\\b`, 'm'));
  return m ? m[1] === 'true' : null;
};

async function isPublished(registry, name, version) {
  const url =
    registry === 'crates.io' ? `https://crates.io/api/v1/crates/${name}/${version}`
    : registry === 'pypi'    ? `https://pypi.org/pypi/${name}/${version}/json`
    : registry === 'npm'     ? `https://registry.npmjs.org/${name}/${version}`
    : null;
  if (!url) throw new Error(`unknown registry '${registry}'`);
  let res;
  try { res = await fetch(url, { headers: UA }); }
  catch (e) { throw new Error(`network error fetching ${url}: ${e.message}`); }
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  throw new Error(`unexpected HTTP ${res.status} from ${registry} for ${name}@${version}`);
}

// Resolve a crate version, including [package] version.workspace = true.
function crateVersion(sec, toml) {
  const literal = strField(sec, 'version');
  if (literal) return literal;
  if (/^\s*version\.workspace\s*=\s*true/m.test(sec) || /^\s*version\s*=\s*\{\s*workspace\s*=\s*true/m.test(sec)) {
    try {
      const root = readFileSync(fileURLToPath(new URL('Cargo.toml', ROOT)), 'utf8');
      return strField(sectionText(root, 'workspace\\.package'), 'version');
    } catch { return null; }
  }
  return null;
}

const pkgs = [];
const cratesDir = fileURLToPath(new URL('crates/', ROOT));
if (existsSync(cratesDir)) for (const d of readdirSync(cratesDir)) {
  const f = fileURLToPath(new URL(`crates/${d}/Cargo.toml`, ROOT));
  if (!existsSync(f)) continue;
  const t = readFileSync(f, 'utf8');
  const sec = sectionText(t, 'package');
  const name = strField(sec, 'name');
  if (!name) continue;
  pkgs.push({ dir: `crates/${d}`, registry: 'crates.io', name, version: crateVersion(sec, t), skip: boolField(sec, 'publish') === false });
}
const pyDir = fileURLToPath(new URL('python/', ROOT));
if (existsSync(pyDir)) for (const d of readdirSync(pyDir)) {
  const f = fileURLToPath(new URL(`python/${d}/pyproject.toml`, ROOT));
  if (!existsSync(f)) continue;
  const t = readFileSync(f, 'utf8');
  const sec = sectionText(t, 'project');
  const name = strField(sec, 'name');
  if (!name) continue;
  pkgs.push({ dir: `python/${d}`, registry: 'pypi', name, version: strField(sec, 'version'), skip: /Private :: Do Not Upload/.test(t) });
}
// TypeScript packages. A third implementation not covered here is exactly how the
// repo/registry drift this check exists to catch would reappear in a new language.
const tsDir = fileURLToPath(new URL('typescript/', ROOT));
if (existsSync(tsDir)) for (const d of readdirSync(tsDir)) {
  const f = fileURLToPath(new URL(`typescript/${d}/package.json`, ROOT));
  if (!existsSync(f)) continue;
  let pkg;
  try { pkg = JSON.parse(readFileSync(f, 'utf8')); }
  catch (e) { failures.push(`  ✗ [typescript/${d}] package.json is not parseable: ${e.message}`); continue; }
  if (!pkg.name) continue;
  pkgs.push({ dir: `typescript/${d}`, registry: 'npm', name: pkg.name, version: pkg.version, skip: pkg.private === true });
}

/* ------------------- scope declaration, both directions ------------------- */
//
// Runs BEFORE any registry call: a tree that disagrees with its own declaration
// makes the registry answer meaningless, the same reason verify-internal-versions
// runs before this script in CI.

const notApplicable = [];
const foundDirs = new Set(pkgs.map((p) => p.dir));

// Direction 1 — TREE → DECLARATION. A package nobody declared.
for (const p of pkgs) {
  const s = SCOPE_BY_DIR.get(p.dir);
  if (!s) {
    failures.push(
      `  ✗ [${p.dir}] ${p.name} (${p.registry}) exists in the tree but is NOT in REGISTRY_SCOPE` +
      ` — every package must be declared. Add it, so a future reader can tell an intended` +
      ` package from one that drifted in.`,
    );
    continue;
  }
  if (s.name !== p.name) {
    failures.push(
      `  ✗ [${p.dir}] manifest name '${p.name}' ≠ declared name '${s.name}' in REGISTRY_SCOPE` +
      ` — a rename that only half-landed. Fix whichever is wrong.`,
    );
  }
  if (s.applicable === false) {
    failures.push(
      `  ✗ [${p.dir}] is declared applicable:false ("does not exist"), but the directory IS present` +
      ` — the declaration is STALE. An implementation now exists: DELETE the entry and publish it` +
      ` (this is the success path).`,
    );
  }
}

// Direction 2 — DECLARATION → TREE. A declaration asserting something about nothing.
for (const s of REGISTRY_SCOPE) {
  const present = foundDirs.has(s.dir);
  if (s.applicable === false) {
    if (!s.reason) {
      failures.push(`  ✗ [${s.dir}] declared applicable:false with NO reason — an unexplained absence is the defect this check exists to prevent`);
    } else if (!present) {
      notApplicable.push(s);
    }
    // present && applicable:false is already reported in direction 1.
    continue;
  }
  if (!present) {
    failures.push(
      `  ✗ [${s.dir}] ${s.name} (${s.registry}) is DECLARED in REGISTRY_SCOPE but has no readable` +
      ` manifest in the tree — either it was deleted/renamed (fix the declaration) or its manifest` +
      ` is unparseable (fix the manifest). Failing closed: this is exactly how PyPI vaid-client went` +
      ` unnoticed, as an absence with no representation.`,
    );
  }
}

for (const p of pkgs) {
  if (p.skip) { notes.push(`  · [${p.dir}] ${p.name} — opt-out marker present, not checked`); continue; }
  if (!p.version) { failures.push(`  ✗ [${p.dir}] ${p.name}: could not read a literal version (dynamic/unresolved) — cannot verify parity (failing closed)`); continue; }
  const waiver = WAIVED.get(`${p.registry}:${p.name}`);
  try {
    const live = await isPublished(p.registry, p.name, p.version);
    if (waiver) {
      waiversHit.add(waiver);
      // A waiver that has come true is a waiver that must go.
      if (live) {
        failures.push(`  ✗ [${p.dir}] ${p.name} ${p.version} IS published on ${p.registry}, but is still waived — the waiver is stale, DELETE it from WAIVERS (this is the success path)`);
      } else if (TODAY > waiver.expires) {
        failures.push(`  ✗ [${p.dir}] ${p.name} ${p.version} is waived, but the waiver EXPIRED on ${waiver.expires} — re-decide and renew or resolve, do not drift`);
      } else {
        waived.push({ ...p, waiver });
      }
      continue;
    }
    if (!live)
      failures.push(`  ✗ [${p.dir}] ${p.name} ${p.version} is NOT published on ${p.registry} — repo bumped but not released`);
  } catch (e) {
    failures.push(`  ✗ [${p.dir}] could not verify (failing closed): ${e.message}`);
  }
}

// ── release tag parity ──────────────────────────────────────────────────────
for (const p of pkgs) {
  if (p.skip) continue;
  const eco = ECO[p.registry];
  try {
    const versions = await publishedVersions(p.registry, p.name);
    const untagged = versions.filter((v) => releaseTagFor(eco, p.name, v) === null).sort();
    if (untagged.length) {
      failures.push(
        `  ✗ [${p.dir}] ${p.name}: published on ${p.registry} but NOT TAGGED: ${untagged.join(', ')}` +
        ` — tag the release commit as ${eco}-${p.name}-v<version> (or ${eco}-v<version>).` +
        ` An untagged release cannot be frozen, diffed or audited, and the commit gets` +
        ` harder to identify the longer it waits.`,
      );
    } else if (versions.length) {
      notes.push(`  · [${p.dir}] ${p.name} — ${versions.length} published version(s), all tagged`);
    }
  } catch (e) {
    failures.push(`  ✗ [${p.dir}] could not verify release tags (failing closed): ${e.message}`);
  }
}

// A waiver naming a package that no longer exists is dead text asserting
// something about nothing. Fail, so it gets deleted rather than read as cover.
for (const w of WAIVERS) {
  if (!waiversHit.has(w)) {
    failures.push(`  ✗ waiver [${w.registry}: ${w.names.join(', ')}] matched no package in the tree — dead waiver, DELETE it`);
  }
}

if (notes.length) console.log('Notes:\n' + notes.join('\n'));

// Declared absences print in full, every run, with the reason. The whole point of
// the declaration is that the absence is VISIBLE — printing it only when something
// breaks would recreate the silence it replaced.
console.log(`\nNOT APPLICABLE — ${notApplicable.length} (registry, package) pair(s) declared not to exist:`);
if (notApplicable.length === 0) console.log('  (none)');
for (const s of notApplicable.sort((a, b) => a.dir.localeCompare(b.dir))) {
  console.log(`  · ${s.registry}: ${s.name} — no implementation at ${s.dir}`);
  console.log(`      ${s.reason.replace(/(.{1,86})(\s|$)/g, '$1\n      ').trimEnd()}`);
}

// Waivers print in full, every run, with reason and expiry. A waiver nobody
// reads is a waiver nobody re-decides.
console.log(`\nWAIVED — ${waived.length} package(s) red for a stated reason no PR can clear:`);
if (waived.length === 0) console.log('  (none)');
for (const p of waived.sort((a, b) => a.dir.localeCompare(b.dir))) {
  console.log(`  ! [${p.dir}] ${p.name} ${p.version} — ${p.registry} — ${p.waiver.reason}`);
  console.log(`      blocked on: ${p.waiver.blockedOn}`);
  console.log(`      expires:    ${p.waiver.expires} (void early if published)`);
}

if (failures.length) {
  console.error(`\n✗ REGISTRY PARITY FAILED — the tree disagrees with REGISTRY_SCOPE, an in-repo version is not on its registry, or a published release has no tag:\n${failures.join('\n')}\n`);
  process.exit(1);
}
console.log(`\n✓ scope declaration — ${REGISTRY_SCOPE.length} declared pair(s): ${REGISTRY_SCOPE.length - notApplicable.length} present in the tree, ${notApplicable.length} declared not-applicable. No undeclared packages.`);
console.log(`✓ registry parity — ${pkgs.filter((p) => !p.skip).length} package(s) checked: ${pkgs.filter((p) => !p.skip).length - waived.length} published, ${waived.length} waived.`);
console.log('✓ release tag parity — every published version has a release tag.');
