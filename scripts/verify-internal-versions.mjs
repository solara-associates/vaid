// Internal version-agreement check — every package must agree WITH ITSELF about
// what version it is.
//
// Why this exists: `verify-package-versions.mjs` validates a package's manifest
// version against its REGISTRY. Nothing validated a package against ITSELF, and
// the gap was real — python `vaid-mint` shipped `pyproject.toml = 0.2.0` while
// `vaid_mint/__init__.py` said `__version__ = "0.1.3"`, so a consumer inspecting
// the installed package's own version constant was told the wrong answer, and both
// the registry-parity check and the capabilities check passed. CONTRIBUTING has
// required these to agree since the first release; nothing enforced it.
//
// Per package, up to three sources must agree:
//   1. the MANIFEST version   — Cargo.toml / pyproject.toml / package.json
//   2. the CODE constant      — Python `__version__` (Rust uses CARGO_PKG_VERSION,
//                               so it has no second source and cannot drift; npm
//                               packages likewise have no separate constant)
//   3. the CHANGELOG top entry — the first `## [x.y.z]` heading, where a
//                               CHANGELOG.md exists
//
// A source that does not exist for a language is NOT a failure — it is reported as
// a note. Inventing a second source of truth where a language has one would create
// the very drift this check exists to catch.
//
// Purely local: no network, so unlike the registry checks this one cannot be
// affected by an outage and is safe to run offline. Fails LOUD.
//
// Run: node scripts/verify-internal-versions.mjs   (also wired into CI)

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const failures = [];
const notes = [];
const checked = [];

const abs = (p) => fileURLToPath(new URL(p, ROOT));
const read = (p) => readFileSync(abs(p), 'utf8');

const sectionText = (toml, header) => {
  const m = toml.match(new RegExp(`\\[${header}\\]([\\s\\S]*?)(?=\\n\\[|$)`));
  return m ? m[1] : '';
};
const strField = (sec, key) => {
  const m = sec.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, 'm'));
  return m ? m[1] : null;
};

/** The first `## [x.y.z]` heading in a changelog — the version it most recently documents. */
function changelogTopVersion(dir) {
  const path = `${dir}/CHANGELOG.md`;
  if (!existsSync(abs(path))) return null;
  const m = read(path).match(/^##\s*\[?v?(\d+\.\d+\.\d+[^\]\s]*)\]?/m);
  return m ? m[1] : { unparseable: true };
}

/** Python `__version__ = "x.y.z"` in the package's `__init__.py`. */
function pythonCodeVersion(dir, moduleName) {
  const path = `${dir}/${moduleName}/__init__.py`;
  if (!existsSync(abs(path))) return null;
  const m = read(path).match(/^__version__\s*=\s*["']([^"']+)["']/m);
  return m ? m[1] : { unparseable: true };
}

const packages = [];

// ── Rust: manifest + changelog. No code constant — Rust reads CARGO_PKG_VERSION
//    from the manifest at compile time, so there is nothing that can disagree.
const cratesDir = abs('crates/');
if (existsSync(cratesDir)) for (const d of readdirSync(cratesDir)) {
  const dir = `crates/${d}`;
  if (!existsSync(abs(`${dir}/Cargo.toml`))) continue;
  const toml = read(`${dir}/Cargo.toml`);
  const sec = sectionText(toml, 'package');
  const name = strField(sec, 'name');
  if (!name) continue;
  let manifest = strField(sec, 'version');
  if (!manifest && /^\s*version\.workspace\s*=\s*true/m.test(sec)) {
    manifest = strField(sectionText(read('Cargo.toml'), 'workspace\\.package'), 'version');
  }
  packages.push({
    dir, name, manifest,
    code: null, codeSource: 'n/a (Rust uses CARGO_PKG_VERSION)',
    changelog: changelogTopVersion(dir),
  });
}

// ── Python: manifest + __version__ + changelog.
const pyDir = abs('python/');
if (existsSync(pyDir)) for (const d of readdirSync(pyDir)) {
  const dir = `python/${d}`;
  if (!existsSync(abs(`${dir}/pyproject.toml`))) continue;
  const sec = sectionText(read(`${dir}/pyproject.toml`), 'project');
  const name = strField(sec, 'name');
  if (!name) continue;
  const moduleName = name.replace(/-/g, '_');
  packages.push({
    dir, name, manifest: strField(sec, 'version'),
    code: pythonCodeVersion(dir, moduleName), codeSource: `${moduleName}/__init__.py __version__`,
    changelog: changelogTopVersion(dir),
  });
}

// ── TypeScript: manifest + changelog. package.json IS the code's version source
//    (a consumer imports it), so there is no separate constant to drift.
const tsDir = abs('typescript/');
if (existsSync(tsDir)) for (const d of readdirSync(tsDir)) {
  const dir = `typescript/${d}`;
  if (!existsSync(abs(`${dir}/package.json`))) continue;
  let pkg;
  try { pkg = JSON.parse(read(`${dir}/package.json`)); }
  catch (e) { failures.push(`  ✗ [${dir}] package.json is not parseable: ${e.message}`); continue; }
  if (!pkg.name || pkg.private === true) continue;
  packages.push({
    dir, name: pkg.name, manifest: pkg.version,
    code: null, codeSource: 'n/a (package.json is the single source)',
    changelog: changelogTopVersion(dir),
  });
}

for (const p of packages) {
  if (!p.manifest) {
    failures.push(`  ✗ [${p.dir}] ${p.name}: could not read a literal manifest version (failing closed)`);
    continue;
  }

  const sources = [['manifest', p.manifest]];

  if (p.code === null) {
    notes.push(`  · [${p.dir}] ${p.name} — no code-level version constant: ${p.codeSource}`);
  } else if (p.code.unparseable) {
    failures.push(`  ✗ [${p.dir}] ${p.name}: ${p.codeSource} exists but its value could not be parsed (failing closed)`);
    continue;
  } else {
    sources.push([p.codeSource, p.code]);
  }

  if (p.changelog === null) {
    // A CHANGELOG is REQUIRED, unlike the code constant above. The distinction is
    // not arbitrary: a language either has a second version constant or it does not,
    // and inventing one would manufacture drift. Every language can carry a
    // changelog, so an absent one is a gap rather than a property of the ecosystem.
    //
    // This was a note until every package had one. It stayed a note long enough for
    // six published packages to acquire none between them, which is the argument for
    // the change: a note is a finding nobody is obliged to clear, and it was not
    // cleared. Turning it on before the files existed would only have made main red,
    // so the files landed first and this went on against a green tree.
    failures.push(
      `  ✗ [${p.dir}] ${p.name}: no CHANGELOG.md — a published package must record ` +
        `what changed. Add one whose top heading is "## [${p.manifest}]".`,
    );
    continue;
  } else if (p.changelog.unparseable) {
    failures.push(`  ✗ [${p.dir}] ${p.name}: CHANGELOG.md has no parseable "## [x.y.z]" heading (failing closed)`);
    continue;
  } else {
    sources.push(['CHANGELOG.md top entry', p.changelog]);
  }

  const distinct = [...new Set(sources.map(([, v]) => v))];
  if (distinct.length > 1) {
    failures.push(
      `  ✗ [${p.dir}] ${p.name} disagrees with ITSELF about its version:\n` +
        sources.map(([label, v]) => `      ${label.padEnd(34)} = ${v}`).join('\n'),
    );
  } else {
    checked.push(`  ✓ [${p.dir}] ${p.name} ${p.manifest} — ${sources.length} source(s) agree`);
  }
}

if (notes.length) console.log('Notes:\n' + notes.join('\n'));

if (failures.length) {
  console.error(
    `\n✗ INTERNAL VERSION AGREEMENT FAILED — a package contradicts itself:\n${failures.join('\n')}\n\n` +
      `Every source a consumer might read must say the same thing. See CONTRIBUTING.md.\n`,
  );
  process.exit(1);
}
console.log(`\n${checked.join('\n')}`);
console.log(`\n✓ internal version agreement — ${packages.length} package(s), each self-consistent.`);
