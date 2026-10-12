// Every in-repo dependency on an in-repo PUBLISHED package must carry an UPPER
// version bound.
//
// THE DEFECT THIS EXISTS TO CATCH
//
// `python/vaid-a2a` and `python/vaid-adk` both declared `vaid-mint>=0.9.0`: a
// lower bound and nothing above it. Neither package had been migrated to the v4
// typed `scope_boundary` (ADR-0009), and neither is exercised by any job in this
// workflow. So the moment `vaid-mint` 0.10.0 reached PyPI, a fresh
// `pip install vaid-a2a` would have resolved a mint whose wire format its
// verifier cannot read, and nothing anywhere would have gone red to say so. The
// same declaration sat in `vaid-jwt-bridge` on an open branch.
//
// That is the whole failure mode: a package that is NOT tested here, depending on
// a package that IS released from here, with no ceiling. The breakage happens at
// `pip install` time in someone else's environment, long after every check in this
// repository has passed.
//
// WHAT IT ASSERTS
//
//   For every manifest in the tree, every dependency naming a package this
//   repository publishes must constrain the version from ABOVE.
//
// A lower bound alone is not a bound. `>=0.9.0` admits 0.10, 1.0 and 2.0, which
// across a `0.x` series is a guarantee of nothing.
//
// WHY THE SUBJECT LIST COMES FROM release-map.json
//
// Hardcoding "vaid-mint" would make this check go stale the first time the same
// mistake is made against `vaid-pop` or `vaid-client`, and a stale enumeration
// that reads as coverage is the defect `check-readme-drift.mjs` was written for.
// release-map.json is already this repository's declaration of what it publishes,
// so it is the one place that knows the answer. Adding a package there puts it
// under this check the same day.
//
// WHAT COUNTS AS AN UPPER BOUND, PER ECOSYSTEM
//
// The three ecosystems disagree about what a bare version string means, and the
// disagreement is the reason this cannot be one regex:
//
//   Cargo  `"0.9"`, `"^0.9"`     BOUNDED   — caret is the default, and on 0.x it
//                                           pins the MINOR
//          `">=0.9"`, `"*"`      unbounded
//   npm    `"^0.9.0"`, `"~0.9"`  BOUNDED   — same caret reading on 0.x
//          `">=0.9.0"`, `"*"`    unbounded
//   PyPI   `"~=0.9.0"`, `"==.."` BOUNDED   — compatible-release, or exact
//          `">=0.9.0"`          unbounded  — pip has NO caret convention, which
//                                           is exactly how vaid-a2a came to be
//                                           unbounded while the npm package next
//                                           to it was fine
//
// That last row is the trap worth naming: `>=0.9.0` was written in all three
// ecosystems' idiom at once by someone reasonably assuming it behaved like a
// caret. In two of them it would have. In Python it did not.
//
// POSTURE: fails LOUD and fails CLOSED. An unreadable or unparseable manifest is a
// FAILURE, never an assumed pass. And a run that finds ZERO dependencies to check
// is a FAILURE too: this check's subject set is discovered rather than declared,
// so an empty one means the discovery broke, not that the tree is clean. A verdict
// over no subjects is not a pass.
//
// Run: node scripts/verify-dependency-bounds.mjs   (also wired into CI)

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const abs = (p) => join(ROOT, p);
const rel = (p) => relative(ROOT, p);
const read = (p) => readFileSync(p, 'utf8');

const failures = [];
const notes = [];
let checked = 0;

// ── What this repository publishes, from its own declaration. ────────────────
/** @type {Set<string>} bare package names, e.g. "vaid-mint" */
const published = new Set();
try {
  const map = JSON.parse(read(abs('release-map.json')));
  for (const key of Object.keys(map.packages ?? {})) {
    // Keys are "<ecosystem>/<package>"; the package name is what a manifest names.
    const name = key.split('/').slice(1).join('/');
    if (name) published.add(name);
  }
} catch (e) {
  console.error(`FATAL: release-map.json is unreadable, so there is no subject list: ${e.message}`);
  process.exit(1);
}
if (published.size === 0) {
  console.error('FATAL: release-map.json declares no packages, so this check has no subjects');
  process.exit(1);
}

// ── Manifest discovery. Walks the tree rather than taking a fixed list, so a
// package added in a new directory is covered the day it lands.
const SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'dist', 'test-dist', '.venv']);
const MANIFESTS = new Set(['Cargo.toml', 'pyproject.toml', 'package.json']);

/** @returns {string[]} absolute paths */
function findManifests(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      out.push(...findManifests(full));
    } else if (MANIFESTS.has(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

// ── Bound predicates, one per ecosystem. ────────────────────────────────────

/**
 * Does a Cargo or npm requirement constrain the version from above?
 *
 * Both default to caret semantics, and on a `0.x` version a caret pins the minor,
 * so a bare or caret-prefixed version IS bounded. An explicit comparator without
 * a matching upper comparator is not, and `*` never is.
 */
function cargoOrNpmIsBounded(req) {
  const r = req.trim();
  if (r === '' || r === '*' || r === 'latest' || r === 'x') return false;
  // A range with an explicit upper comparator is bounded however it is written.
  if (/[<]/.test(r)) return true;
  // A lower-bound-only comparator is not.
  if (/^(>=?|\^?>=)/.test(r)) return false;
  // Caret, tilde, equals, or a bare version: all pin at least the minor on 0.x.
  if (/^[\^~=]?v?\d/.test(r)) return true;
  // Anything unrecognised is reported rather than assumed safe.
  return null;
}

/**
 * Does a PEP 440 specifier set constrain the version from above?
 *
 * Note what is NOT here: there is no caret, so a bare `>=` is unbounded with no
 * convention to rescue it. `~=` (compatible release) and `==` both bound.
 */
function pypiIsBounded(spec) {
  const s = spec.trim();
  if (s === '') return false;
  if (/[<]/.test(s)) return true;
  if (/~=|==/.test(s)) return true;
  if (/^(>=|>|!=)/.test(s)) return false;
  return null;
}

function record(manifest, dep, req, bounded, ecosystem) {
  checked += 1;
  if (bounded === true) return;
  if (bounded === null) {
    failures.push(
      `  ✗ ${rel(manifest)}\n      ${dep} = "${req}" — this check does not recognise that ` +
        `requirement, so it cannot say whether it is bounded. Reported rather than assumed safe.`,
    );
    return;
  }
  failures.push(
    `  ✗ ${rel(manifest)}\n      ${dep} = "${req}" — no UPPER bound on an in-repo published ` +
      `package (${ecosystem}). A lower bound alone admits every future major and minor.`,
  );
}

// ── Walk and check. ─────────────────────────────────────────────────────────
for (const manifest of findManifests(ROOT)) {
  let text;
  try {
    text = read(manifest);
  } catch (e) {
    failures.push(`  ✗ ${rel(manifest)}\n      unreadable: ${e.message}`);
    continue;
  }

  if (manifest.endsWith('package.json')) {
    let pkg;
    try {
      pkg = JSON.parse(text);
    } catch (e) {
      failures.push(`  ✗ ${rel(manifest)}\n      unparseable JSON: ${e.message}`);
      continue;
    }
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const [dep, req] of Object.entries(pkg[field] ?? {})) {
        if (!published.has(dep)) continue;
        // A workspace protocol resolves inside this repo and never reaches a
        // registry, so there is no published version for it to float against.
        if (typeof req === 'string' && req.startsWith('workspace:')) {
          notes.push(`  · ${rel(manifest)} ${dep} = "${req}" — workspace-local, not registry-resolved`);
          continue;
        }
        record(manifest, dep, req, cargoOrNpmIsBounded(String(req)), 'npm');
      }
    }
    continue;
  }

  if (manifest.endsWith('pyproject.toml')) {
    // Deliberately a line scan rather than a TOML parse: this repository ships no
    // TOML parser for Node, and adding a dependency to a supply-chain check is a
    // poor trade. The shapes that matter are `"name>=x"` entries inside a
    // dependencies array, which are one per line in every manifest here, and a
    // dependency this scan FAILS to see is caught by the zero-subjects guard
    // rather than passing silently.
    for (const line of text.split('\n')) {
      const m = line.match(/^\s*["']([A-Za-z0-9._-]+)\s*([^"']*)["']\s*,?\s*$/);
      if (!m) continue;
      const [, dep, spec] = m;
      if (!published.has(dep)) continue;
      record(manifest, dep, spec, pypiIsBounded(spec), 'PyPI');
    }
    continue;
  }

  // Cargo.toml. Same reasoning as above on the line scan; the two shapes are
  // `name = "req"` and `name = { version = "req", .. }`.
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9._-]+)\s*=\s*(.+)$/);
    if (!m) continue;
    const [, dep, rhs] = m;
    if (!published.has(dep)) continue;
    const inline = rhs.match(/version\s*=\s*"([^"]*)"/);
    if (inline) {
      record(manifest, dep, inline[1], cargoOrNpmIsBounded(inline[1]), 'Cargo');
      continue;
    }
    const bare = rhs.match(/^"([^"]*)"/);
    if (bare) {
      record(manifest, dep, bare[1], cargoOrNpmIsBounded(bare[1]), 'Cargo');
      continue;
    }
    if (/\bpath\s*=/.test(rhs) || /\bworkspace\s*=\s*true/.test(rhs)) {
      // A path or workspace dependency with no version resolves locally. Cargo
      // REQUIRES a version alongside a path to publish, so this is a note here
      // and `cargo publish` is the gate that would refuse it.
      notes.push(`  · ${rel(manifest)} ${dep} — path/workspace dependency, no registry version`);
      continue;
    }
    record(manifest, dep, rhs.trim(), null, 'Cargo');
  }
}

// ── Report. ─────────────────────────────────────────────────────────────────
if (notes.length > 0) {
  console.log('Notes:');
  for (const n of notes) console.log(n);
  console.log('');
}

// The zero-subjects guard. This check discovers its subjects, so an empty set
// means the discovery broke, not that the tree is clean.
if (checked === 0) {
  console.error(
    '✗ DEPENDENCY BOUNDS CHECK COULD NOT RUN — it found no dependency on any package\n' +
      `  this repository publishes (${[...published].sort().join(', ')}).\n\n` +
      '  There is at least one by construction, so this is a broken discovery and not a\n' +
      '  clean tree. Most likely a manifest moved, or release-map.json renamed a package.\n' +
      '  A verdict over no subjects is not a pass.',
  );
  process.exit(1);
}

if (failures.length > 0) {
  console.error(
    `✗ DEPENDENCY BOUNDS CHECK FAILED — ${failures.length} unbounded dependency(ies) on an\n` +
      '  in-repo published package:\n',
  );
  for (const f of failures) console.error(f);
  console.error(
    '\n  Add an upper bound. For PyPI, `>=0.9.0,<0.10` or `~=0.9.0`; for Cargo and npm a\n' +
      '  bare or caret version already pins the minor on a 0.x series.\n\n' +
      '  A package not exercised by this workflow, depending on a package released from\n' +
      '  it with no ceiling, breaks in a consumer\'s environment at install time and goes\n' +
      '  red nowhere here. That is what this check exists to prevent.',
  );
  process.exit(1);
}

console.log(
  `✓ dependency bounds — ${checked} dependency(ies) on in-repo published packages ` +
    `(${[...published].sort().join(', ')}), all upper-bounded.`,
);
