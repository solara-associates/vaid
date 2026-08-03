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
const WAIVERS = [
  {
    // ── The TypeScript implementation, awaiting its first npm release ────────
    // The third conforming implementation is complete and vector-green in-repo;
    // what is missing is the release, not the code. These are deliberately NOT
    // `"private": true` — publishing them is the plan.
    //
    // BLOCKED ON: the publishing-identity decision (which npm account/org owns
    // the namespace, under what name). The owner's decision alone; not a code
    // change, and no PR against this repository can clear it. The same decision
    // blocks crates.io and PyPI in the `synthera` repo, where an
    // identically-shaped waiver exists.
    //
    // VOID WHEN: any of them is published (the waiver then fails and must be
    // deleted — that is the success path), or on the expiry below.
    names: ['vaid-client', 'vaid-mint', 'vaid-pop'],
    registry: 'npm',
    reason: 'third conforming implementation, complete and vector-green, awaiting first npm release',
    blockedOn: 'publishing identity (owner decision — not clearable by any PR)',
    // Aligned with the substrate's .cargo/audit.toml waivers so the whole
    // estate's waivers come up for re-decision on one date.
    expires: '2026-10-30',
  },
];

// Keyed by name+registry: `vaid-pop` also exists as a crate and a PyPI package,
// and this waiver is about the npm ones only. Keying on the bare name would
// silently waive the published Rust and Python packages too.
const WAIVED = new Map();
for (const w of WAIVERS) for (const n of w.names) WAIVED.set(`${w.registry}:${n}`, w);

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

// A waiver naming a package that no longer exists is dead text asserting
// something about nothing. Fail, so it gets deleted rather than read as cover.
for (const w of WAIVERS) {
  if (!waiversHit.has(w)) {
    failures.push(`  ✗ waiver [${w.registry}: ${w.names.join(', ')}] matched no package in the tree — dead waiver, DELETE it`);
  }
}

if (notes.length) console.log('Notes:\n' + notes.join('\n'));

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
  console.error(`\n✗ REGISTRY PARITY FAILED — an in-repo version is not on its registry:\n${failures.join('\n')}\n`);
  process.exit(1);
}
console.log(`\n✓ registry parity — ${pkgs.filter((p) => !p.skip).length} package(s) checked: ${pkgs.filter((p) => !p.skip).length - waived.length} published, ${waived.length} waived.`);
