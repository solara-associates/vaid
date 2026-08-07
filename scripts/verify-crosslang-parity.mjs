// Cross-language version-skew REPORT — when two implementations of the same
// package name disagree on MAJOR.MINOR, say so. Advisory: this NEVER fails.
//
// Why this exists: three checks already guard versions, and none of them can see
// this axis at all.
//   · verify-internal-versions.mjs — one package against ITSELF (manifest vs code
//     constant vs changelog). Per package.
//   · verify-package-versions.mjs  — one package against ITS OWN registry, keyed
//     `ECO = { 'crates.io': rust, pypi: python, npm: npm }`. Never compares the
//     Rust `vaid-pop` to the Python `vaid-pop`.
//   · verify-vector-freeze.mjs     — a frozen vector against the release tag for
//     the version it shipped under. Per package.
// So `vaid-pop` sitting at 0.2.1 / 0.2.0 / 0.3.0 across crates.io / PyPI / npm is
// invisible to every check in the repo. It was found by hand on 2026-08-07.
//
// WHY THIS WARNS RATHER THAN FAILS. Independent versioning is stated policy
// (CONTRIBUTING, "Releasing and version tags"): the implementations are separate
// hand-written codebases, not builds of one another, so their numbers legitimately
// diverge and a shared number is a coincidence. Making skew fatal would block
// exactly the releases the policy exists to allow — `vaid-mint` 0.4.2 and
// `vaid-pop` 0.2.1 were deliberate Rust-only patches, and 0.4.2 was REVERTED on
// Python and TypeScript before publishing precisely because only Rust had changed.
// A check that turned those into red would teach people to bump for tidiness,
// which is the failure this repo already decided against.
//
// So the deliverable is NOTICING, not blocking. Byte agreement is asserted at the
// conformance vector, never at the version number — all three `vaid-pop` artifacts
// reproduce digest `ee474ba87d703ebe…` today despite three different numbers. If
// you want to know whether two languages AGREE, run their packaged firewalls; this
// script only tells you whether they LOOK like they agree.
//
// Read a warning here as a question, not a defect: "is this skew still the
// deliberate one?" If yes, nothing to do.
//
// Purely local: no network, no git. Cannot be affected by an outage.
// ALWAYS exits 0 — including on its own internal errors, which are reported as
// warnings too. A advisory check that fails the build is not advisory.
//
// Run: node scripts/verify-crosslang-parity.mjs   (also wired into CI)

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = new URL('../', import.meta.url);
const abs = (p) => fileURLToPath(new URL(p, ROOT));

// Parsers duplicated from the sibling verify-*.mjs scripts, deliberately: each
// check in this directory is standalone and offline-runnable, and a shared module
// would couple an advisory report to two gating checks. They are ~6 lines.
const sectionText = (toml, header) => {
  const m = toml.match(new RegExp(`\\[${header}\\]([\\s\\S]*?)(?=\\n\\[|$)`));
  return m ? m[1] : '';
};
const strField = (sec, key) => {
  const m = sec.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, 'm'));
  return m ? m[1] : null;
};

const warnings = [];

/** Resolve a crate version, including `version.workspace = true`. */
function crateVersion(sec) {
  const literal = strField(sec, 'version');
  if (literal) return literal;
  if (/^\s*version\.workspace\s*=\s*true/m.test(sec) || /^\s*version\s*=\s*\{\s*workspace\s*=\s*true/m.test(sec)) {
    try {
      return strField(sectionText(readFileSync(abs('Cargo.toml'), 'utf8'), 'workspace\\.package'), 'version');
    } catch { return null; }
  }
  return null;
}

/* ------------------------------- discovery ------------------------------- */

/** [{ language, registry, dir, name, version }] for every package in the tree. */
function discover() {
  const out = [];
  const scan = (subdir, manifest, language, registry, parse) => {
    const d = abs(`${subdir}/`);
    if (!existsSync(d)) return;
    for (const entry of readdirSync(d)) {
      const f = abs(`${subdir}/${entry}/${manifest}`);
      if (!existsSync(f)) continue;
      try {
        const parsed = parse(readFileSync(f, 'utf8'));
        if (parsed?.name) out.push({ language, registry, dir: `${subdir}/${entry}`, ...parsed });
      } catch (e) {
        // An unreadable manifest is a warning, never a failure — see the header.
        warnings.push(`  ! [${subdir}/${entry}] could not read ${manifest}: ${e.message}`);
      }
    }
  };

  scan('crates', 'Cargo.toml', 'rust', 'crates.io', (t) => {
    const sec = sectionText(t, 'package');
    return { name: strField(sec, 'name'), version: crateVersion(sec) };
  });
  scan('python', 'pyproject.toml', 'python', 'pypi', (t) => {
    const sec = sectionText(t, 'project');
    return { name: strField(sec, 'name'), version: strField(sec, 'version') };
  });
  scan('typescript', 'package.json', 'typescript', 'npm', (t) => {
    const p = JSON.parse(t);
    return { name: p.name, version: p.version };
  });
  return out;
}

/* -------------------------------- report --------------------------------- */

// MAJOR.MINOR is the comparison unit on purpose. A patch is the one release shape
// the policy explicitly blesses as single-language (`vaid-pop` 0.2.1, Rust-only),
// so comparing full versions would warn on every deliberate patch and train people
// to ignore the output. A MINOR divergence is the one worth a second look.
const minorOf = (v) => {
  const m = String(v ?? '').match(/^(\d+)\.(\d+)\./);
  return m ? `${m[1]}.${m[2]}` : null;
};

const pkgs = discover();

const byName = new Map();
for (const p of pkgs) {
  if (!byName.has(p.name)) byName.set(p.name, []);
  byName.get(p.name).push(p);
}

const aligned = [];
const diverged = [];
const single = [];

for (const [name, impls] of [...byName].sort(([a], [b]) => a.localeCompare(b))) {
  impls.sort((a, b) => a.language.localeCompare(b.language));
  if (impls.length === 1) { single.push({ name, impls }); continue; }

  const unresolved = impls.filter((i) => minorOf(i.version) === null);
  if (unresolved.length) {
    warnings.push(
      `  ! ${name}: could not parse a MAJOR.MINOR for ` +
      unresolved.map((i) => `${i.language} (${i.version ?? 'no version'})`).join(', ') +
      ' — skew not assessed for this package',
    );
    continue;
  }

  const minors = new Set(impls.map((i) => minorOf(i.version)));
  (minors.size === 1 ? aligned : diverged).push({ name, impls, minors });
}

const line = (i) => `${i.language}/${i.registry} ${i.version}`;

console.log(`Cross-language version skew — ${byName.size} package name(s), ${pkgs.length} implementation(s).`);
console.log('ADVISORY: independent versioning is policy; skew below is not, by itself, a defect.\n');

if (diverged.length) {
  console.log(`⚠ SKEW — ${diverged.length} package(s) whose implementations differ on MAJOR.MINOR:`);
  for (const { name, impls, minors } of diverged) {
    console.log(`  ⚠ ${name} — minors ${[...minors].sort().join(' vs ')}`);
    for (const i of impls) console.log(`      · ${i.dir.padEnd(24)} ${line(i)}`);
    console.log('        → deliberate? then nothing to do. Unintended? the artifacts still');
    console.log('          agree or not INDEPENDENTLY of this — run each packaged firewall.');
  }
  console.log('');
}

if (aligned.length) {
  console.log(`✓ ALIGNED — ${aligned.length} package(s) agree on MAJOR.MINOR:`);
  for (const { name, impls } of aligned) {
    console.log(`  ✓ ${name} — ${impls.map(line).join(', ')}`);
  }
  console.log('');
}

if (single.length) {
  console.log(`· SINGLE-LANGUAGE — ${single.length} package(s) with one implementation, nothing to compare:`);
  for (const { name, impls } of single) console.log(`  · ${name} — ${impls.map(line).join('')}`);
  console.log('');
}

if (warnings.length) console.log(`Could not assess:\n${warnings.join('\n')}\n`);

// Deliberately unconditional. See the header: this check reports, it does not gate.
console.log(
  diverged.length
    ? `⚠ ${diverged.length} package(s) show cross-language skew — reported, NOT failing (advisory check).`
    : '✓ no cross-language MAJOR.MINOR skew.',
);
process.exit(0);
