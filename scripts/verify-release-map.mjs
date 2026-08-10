/**
 * Does `release-map.json` still describe this repository?
 *
 * The map fixed BACKLOG B2 — the release workflow deriving a package's directory
 * from its ECOSYSTEM, so the first npm package that lived somewhere other than
 * `typescript/<pkg>` could not be released and was published by hand three times.
 *
 * A map is only better than a hardcoded `case` if it cannot silently go stale, and
 * the stale failure here is the same shape as the one it replaced: a package
 * exists, nothing references it, and the gap is invisible until someone tags a
 * release and the workflow refuses. That refusal is correct but arrives at the
 * worst moment — after a version bump, a changelog and a tag.
 *
 * So this asserts both directions:
 *
 *   1. **Every entry points at a real package.** The directory exists, carries the
 *      right manifest, and that manifest's NAME matches the key. A map entry that
 *      names a directory whose package is called something else would publish the
 *      wrong thing under the right tag.
 *   2. **Every publishable package has an entry.** Discovered by walking the
 *      manifests actually in the tree, not from a second list — see
 *      `absence-has-no-representation`: a list of things to check cannot notice
 *      something that was never added to it.
 *
 * And, for npm, that each entry declares how a consumer verifies the published
 * artifact. `resolve` enforces that too, but at tag time; here it is caught in the
 * PR that adds the package.
 *
 * Run: node scripts/verify-release-map.mjs
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MAP = JSON.parse(readFileSync(join(ROOT, 'release-map.json'), 'utf8'));

const problems = [];
const note = (m) => problems.push(m);

/** Manifest name for a directory, per ecosystem, or null if there is none. */
function manifestName(eco, dir) {
  const abs = join(ROOT, dir);
  try {
    if (eco === 'npm') return JSON.parse(readFileSync(join(abs, 'package.json'), 'utf8')).name ?? null;
    if (eco === 'rust') {
      const t = readFileSync(join(abs, 'Cargo.toml'), 'utf8');
      return t.match(/^\s*\[package\][\s\S]*?^\s*name\s*=\s*"([^"]+)"/m)?.[1] ?? null;
    }
    if (eco === 'python') {
      const t = readFileSync(join(abs, 'pyproject.toml'), 'utf8');
      return t.match(/^\s*\[project\][\s\S]*?^\s*name\s*=\s*"([^"]+)"/m)?.[1] ?? null;
    }
  } catch {
    return null;
  }
  return null;
}

// --- 1. every entry resolves to the package it claims -------------------------
const entries = Object.entries(MAP.packages ?? {});
if (entries.length === 0) note('release-map.json lists no packages');

for (const [key, cfg] of entries) {
  const [eco, pkg] = key.split('/');
  if (!['rust', 'python', 'npm'].includes(eco)) {
    note(`${key}: "${eco}" is not a known ecosystem`);
    continue;
  }
  if (!cfg?.dir) {
    note(`${key}: no "dir"`);
    continue;
  }
  if (!existsSync(join(ROOT, cfg.dir))) {
    note(`${key}: dir "${cfg.dir}" does not exist`);
    continue;
  }
  const name = manifestName(eco, cfg.dir);
  if (name === null) {
    note(`${key}: no readable manifest in "${cfg.dir}"`);
  } else if (name !== pkg) {
    // The dangerous case: a right-looking tag publishing the wrong package.
    note(`${key}: "${cfg.dir}" holds a package called "${name}", not "${pkg}"`);
  }
  if (eco === 'npm' && !cfg.verify_bin && !cfg.verify_cmd) {
    note(`${key}: declares neither verify_bin nor verify_cmd — a published artifact nobody checks is not a release`);
  }
  if (eco === 'npm' && cfg.npm_workspace_root && !existsSync(join(ROOT, cfg.npm_workspace_root, 'package.json'))) {
    note(`${key}: npm_workspace_root "${cfg.npm_workspace_root}" has no package.json`);
  }
}

// --- 2. every publishable package in the tree has an entry --------------------
// Walked from the tree so a package added in a new location is caught here rather
// than at tag time.
const found = [];

for (const [eco, root, manifest] of [
  ['rust', 'crates', 'Cargo.toml'],
  ['python', 'python', 'pyproject.toml'],
  ['npm', 'typescript', 'package.json'],
]) {
  const abs = join(ROOT, root);
  if (!existsSync(abs)) continue;
  for (const d of readdirSync(abs, { withFileTypes: true })) {
    if (!d.isDirectory() || d.name === 'node_modules') continue;
    if (existsSync(join(abs, d.name, manifest))) found.push([eco, `${root}/${d.name}`]);
  }
}

// npm packages living outside `typescript/` are exactly the case that produced B2,
// so they are discovered rather than assumed: any top-level directory with a
// package.json that is not the workspace root or a tooling folder counts.
const IGNORE = new Set(['node_modules', 'typescript', 'scripts', 'examples', 'docs', 'target', 'demo']);
for (const d of readdirSync(ROOT, { withFileTypes: true })) {
  if (!d.isDirectory() || d.name.startsWith('.') || IGNORE.has(d.name)) continue;
  if (existsSync(join(ROOT, d.name, 'package.json'))) found.push(['npm', d.name]);
}

for (const [eco, dir] of found) {
  const name = manifestName(eco, dir);
  if (!name) continue;
  const key = `${eco}/${name}`;
  const cfg = MAP.packages?.[key];
  if (!cfg) {
    note(
      `${dir} holds ${eco} package "${name}" with no release-map.json entry — it cannot be released by the workflow. ` +
        `This is the BACKLOG B2 shape: add "${key}" with its dir${eco === 'npm' ? ', npm_workspace_root and verify_bin/verify_cmd' : ''}.`,
    );
  } else if (cfg.dir !== dir) {
    note(`${key}: map says "${cfg.dir}" but the package is at "${dir}"`);
  }
}

if (problems.length > 0) {
  console.error('\n✗ RELEASE MAP CHECK FAILED\n');
  for (const p of problems) console.error(`  · ${p}`);
  console.error('\n  release-map.json is what lets the release workflow find a package.');
  console.error('  A package missing from it cannot be released except by hand — which is');
  console.error('  how vaid-skill 0.1.0, 0.1.1 and 0.1.2 went out unsigned.\n');
  process.exit(1);
}

console.log(`✓ release map — ${entries.length} entries, each resolving to the package it names`);
console.log(`✓ every publishable package found in the tree (${found.length}) has an entry`);
