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
// Fails LOUD, fails CLOSED on network — same posture as verify-capabilities.mjs.
//
// Run: node scripts/verify-package-versions.mjs   (also wired into CI)

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const UA = { 'User-Agent': 'solara-vaid-registry-parity-check' };
const failures = [];
const notes = [];

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
  try {
    if (!(await isPublished(p.registry, p.name, p.version)))
      failures.push(`  ✗ [${p.dir}] ${p.name} ${p.version} is NOT published on ${p.registry} — repo bumped but not released`);
  } catch (e) {
    failures.push(`  ✗ [${p.dir}] could not verify (failing closed): ${e.message}`);
  }
}

if (notes.length) console.log('Notes:\n' + notes.join('\n'));
if (failures.length) {
  console.error(`\n✗ REGISTRY PARITY FAILED — an in-repo version is not on its registry:\n${failures.join('\n')}\n`);
  process.exit(1);
}
console.log(`\n✓ registry parity — ${pkgs.filter((p) => !p.skip).length} package(s), every in-repo version is published on its registry.`);
