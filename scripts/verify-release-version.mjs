// Release-version positive control — proves the version this release claims is the
// version its executable sites actually carry.
//
// Why this exists, specifically: `vaid-mint 0.9.0` was prepared on a branch cut
// while 0.8.0 was still unreleased, so BOTH sides of the eventual rebase set the
// same literal `0.8.0` in every manifest. Identical content merges without a
// conflict, and the result is one version number over two independent breaking
// changesets — with no marker anywhere that a resolution happened. Every other
// check in this repository passed over that state:
//
//   - verify-internal-versions.mjs  compares the sites to EACH OTHER, so a uniform
//                                   wrong answer is a unanimous one.
//   - verify-package-versions.mjs   compares to the REGISTRY, and 0.8.0 IS
//                                   published — so a tree stuck at 0.8.0 looks
//                                   more correct than a correctly bumped one.
//
// Both of those are agreement checks. Neither has an independent statement of what
// the version is SUPPOSED to be, so neither can fail on the mis-resolution. This
// check supplies that statement, and it is deliberately a hand-written literal
// below: a constant derived from any file the bump also edits would be fed by the
// thing it checks, and would pass over exactly the defect it exists to catch.
//
// The cost is one line to edit per release, by hand, in this file. That is the
// point — it is the single place where a human states the intended version, and
// everything else is measured against it rather than against itself.
//
// Local, no network. Fails LOUD.
//
// Run: node scripts/verify-release-version.mjs   (also wired into CI)

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// ── The intended version of the vaid-mint release on this branch. HAND-WRITTEN.
//    Do not derive this from a manifest, a lockfile, a changelog or a tag.
const EXPECTED = '0.9.0';

const ROOT = new URL('../', import.meta.url);
const read = (p) => readFileSync(fileURLToPath(new URL(p, ROOT)), 'utf8');

const failures = [];
const checked = [];

/** Each site is read with a pattern narrow enough that it cannot match a neighbour. */
const sites = [
  {
    label: 'crates/vaid-mint/Cargo.toml  [package] version',
    read: () => {
      const sec = read('crates/vaid-mint/Cargo.toml').match(/\[package\]([\s\S]*?)(?=\n\[|$)/);
      return sec && sec[1].match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    },
  },
  {
    label: 'python/vaid-mint/pyproject.toml  [project] version',
    read: () => {
      const sec = read('python/vaid-mint/pyproject.toml').match(/\[project\]([\s\S]*?)(?=\n\[|$)/);
      return sec && sec[1].match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    },
  },
  {
    label: 'typescript/vaid-mint/package.json  .version',
    read: () => JSON.parse(read('typescript/vaid-mint/package.json')).version,
  },
  {
    label: 'python/vaid-mint/vaid_mint/__init__.py  __version__',
    read: () => read('python/vaid-mint/vaid_mint/__init__.py').match(/^__version__\s*=\s*["']([^"']+)["']/m)?.[1],
  },
  {
    label: 'Cargo.lock  [[package]] name = "vaid-mint"',
    read: () => read('Cargo.lock').match(/\[\[package\]\]\nname = "vaid-mint"\nversion = "([^"]+)"/)?.[1],
  },
  {
    label: 'typescript/package-lock.json  vaid-mint entries',
    read: () => {
      const lock = JSON.parse(read('typescript/package-lock.json'));
      const vs = new Set();
      for (const [path, node] of Object.entries(lock.packages ?? {})) {
        if (path === 'vaid-mint' || path.endsWith('/vaid-mint')) {
          if (node?.version) vs.add(node.version);
        }
      }
      if (vs.size === 0) return null;
      // Every entry for the package must agree, or the lockfile itself is split.
      return vs.size === 1 ? [...vs][0] : `MULTIPLE: ${[...vs].sort().join(', ')}`;
    },
  },
];

for (const site of sites) {
  let got;
  try {
    got = site.read();
  } catch (e) {
    failures.push(`  ✗ ${site.label}\n      could not be read (failing closed): ${e.message}`);
    continue;
  }
  if (!got) {
    failures.push(`  ✗ ${site.label}\n      no version found at this site (failing closed)`);
  } else if (got !== EXPECTED) {
    failures.push(`  ✗ ${site.label}\n      expected ${EXPECTED}, found ${got}`);
  } else {
    checked.push(`  ✓ ${site.label} = ${got}`);
  }
}

// The CHANGELOG top entry is checked too — not as a version source (that is
// verify-internal-versions' job) but because a release whose notes are headed with
// the PREVIOUS version is the same mis-resolution wearing prose.
for (const dir of ['crates/vaid-mint', 'python/vaid-mint', 'typescript/vaid-mint']) {
  const top = read(`${dir}/CHANGELOG.md`).match(/^##\s*\[?v?(\d+\.\d+\.\d+[^\]\s]*)\]?/m)?.[1];
  if (top !== EXPECTED) {
    failures.push(`  ✗ ${dir}/CHANGELOG.md top entry\n      expected ## [${EXPECTED}], found ${top ?? '(none parseable)'}`);
  } else {
    checked.push(`  ✓ ${dir}/CHANGELOG.md top entry = ${top}`);
  }
}

if (failures.length) {
  console.error(
    `\n✗ RELEASE VERSION MISMATCH — this branch states ${EXPECTED}, and these sites do not:\n` +
      `${failures.join('\n')}\n\n` +
      `If ${EXPECTED} is wrong, change EXPECTED in scripts/verify-release-version.mjs and nothing else.\n` +
      `If it is right, the sites above were missed — most likely by a merge or rebase in which\n` +
      `both sides carried the SAME older version, which produces no conflict to notice.\n`,
  );
  process.exit(1);
}

console.log(`\n${checked.join('\n')}`);
console.log(`\n✓ release version — ${checked.length} site(s) all read ${EXPECTED}.`);
