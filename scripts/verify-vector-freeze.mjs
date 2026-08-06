// Frozen-vector freeze check — a conformance vector's digest MUST NOT change
// under a version that has already been released.
//
// THE DEFECT THIS EXISTS TO CATCH
//
// On 2026-08-03 `crates/vaid-mint` was found carrying VAID v3 — trust_domain,
// kernel_key_thumbprint, VAID_SIG_VERSION_V3, and a re-frozen `mint_v1` whose
// digest had moved from a5d73cf4… to eef6c92f… — while its manifest still said
// `0.2.0`, which is also what crates.io was serving. A consumer running
// `cargo add vaid-mint` got a v2 crate; the repository contained v3; and the
// wire contract had changed underneath an unchanged version number.
//
// Nothing caught it. The Python twin was caught, but only by accident: Python
// has a hand-written `__version__` that someone had bumped to 0.3.0 while
// leaving the manifest at 0.2.0, so `verify-internal-versions` saw two
// declarations disagree. Rust has no such second declaration — `CARGO_PKG_VERSION`
// is GENERATED from the manifest and therefore cannot disagree with it — so in
// Rust the manifest and the CHANGELOG both said `0.2.0`, they AGREED, and the
// check passed. Two declarations agreeing tells you nothing about whether either
// is right.
//
// That is the hole this closes: every other check compares DECLARATIONS to each
// other. This one compares the FROZEN WIRE CONTRACT to the version it was
// released under.
//
// WHAT IT ASSERTS
//
//   For each package, if a git tag exists for the version currently in its
//   manifest — i.e. that exact version was released — then every conformance
//   vector under that package MUST still hash to what it hashed at that tag.
//
// A changed digest under an already-released version means a wire break shipped
// without a version bump. If the manifest version has NO release tag, the
// version is in flight (bumped, not yet released) and changing vectors is
// exactly what a pre-release is for — that case is PASS, and registry parity
// covers the "bumped but not published" half.
//
// WHY NOT THE OBVIOUS ALTERNATIVES — all three were tried against the real
// 2026-08-03 history before this was written. A successor should not have to
// re-derive this.
//
//   1. "Declared version == what the registry serves."
//      USELESS — it is GREEN in exactly the failure case. At the defect commit
//      the repo said 0.2.0 and crates.io said 0.2.0, so this check would have
//      agreed and reported success. It is the inverse of the needed signal, and
//      the opposite case (bumped-but-unpublished) is already covered by
//      verify-package-versions.mjs.
//
//   2. "Any source file changed since the last release tag."
//      TOO NOISY to enforce. Measured at the defect commit: it fires correctly
//      on vaid-mint (8 changed files) but ALSO on vaid-pop and vaid-client,
//      where the only changes were rustfmt reformatting — whitespace and line
//      wrapping, zero semantic content. Two false positives out of three
//      packages. A check that cries wolf twice per three releases gets muted,
//      and a muted check is worse than no check.
//
//   3. "Public-API diff (e.g. cargo public-api)."
//      Would have caught this one (VAID_SIG_VERSION_V2 removed, two fields
//      added) and would NOT have fired on the formatting-only crates, so it is
//      strictly better than (2). Rejected anyway on two grounds: it is blind to
//      a pure behaviour change behind an unchanged signature — swapping a hash
//      or changing canonicalization keeps every type identical and breaks every
//      consumer — and for a cryptographic standard that is precisely the
//      dangerous case. It also adds a toolchain dependency per language.
//
// Vectors have none of those weaknesses. They are machine-generated, never
// reformatted, and a digest is exactly the thing a consumer's implementation is
// pinned to. If it moves, the contract moved.
//
// POSTURE: fails LOUD and fails CLOSED. An unreadable vector, unparseable JSON,
// a missing digest field, or a git command that will not run is a FAILURE, never
// an assumed pass — the same posture as the other checks in this job. The one
// deliberate non-failure is "no release tag for this version", which is a
// reported NOTE, because it is a real and common state rather than an error.
//
// Run: node scripts/verify-vector-freeze.mjs   (also wired into CI)

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

const failures = [];
const notes = [];
const checked = [];

/** The field every frozen vector in this repo carries. */
const DIGEST_FIELD = 'digest_sha256_hex';

// Build output, not source. `test-dist/` holds copies emitted by the TypeScript
// build; checking them would double-report every TS vector and, worse, compare a
// generated artifact against a tag that may predate the build layout.
const SKIP_DIRS = new Set(['node_modules', 'target', 'test-dist', 'dist', '.git']);

/* ------------------------------- git access ------------------------------ */

function git(args) {
  return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

let TAGS;
try {
  TAGS = new Set(git(['tag', '--list']).split('\n').map((s) => s.trim()).filter(Boolean));
} catch (e) {
  // Fail closed: without tags this check cannot make its assertion, and silently
  // passing would be indistinguishable from "everything is fine".
  console.error(`✗ VECTOR FREEZE CHECK FAILED — cannot list git tags (failing closed): ${e.message}`);
  console.error('  In CI this usually means the checkout has no tags. Use `fetch-depth: 0`.');
  process.exit(1);
}

/** Read a path as it was at `tag`, or null if it did not exist there. */
function readAtTag(tag, relPath) {
  try {
    return git(['show', `${tag}:${relPath}`]);
  } catch {
    return null; // absent at that tag — a new vector, handled by the caller
  }
}

/* ------------------------------- discovery ------------------------------- */

/** Every `*.json` under a `vectors/` directory inside `dir`. */
function findVectors(dir, found = []) {
  let entries;
  try {
    entries = readdirSync(join(ROOT, dir), { withFileTypes: true });
  } catch {
    return found;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name) || e.name.startsWith('.')) continue;
      findVectors(join(dir, e.name), found);
    } else if (e.name.endsWith('.json') && dir.split('/').includes('vectors')) {
      found.push(join(dir, e.name));
    }
  }
  return found;
}

const sectionText = (toml, header) => {
  const m = toml.match(new RegExp(`\\[${header}\\]([\\s\\S]*?)(?=\\n\\[|$)`));
  return m ? m[1] : '';
};
const strField = (sec, key) => {
  const m = sec.match(new RegExp(`^\\s*${key}\\s*=\\s*"([^"]*)"`, 'm'));
  return m ? m[1] : null;
};

/** Packages: (dir, name, version, ecosystem). Mirrors verify-internal-versions. */
function discoverPackages() {
  const pkgs = [];
  const scan = (parent, manifest, eco) => {
    const abs = join(ROOT, parent);
    if (!existsSync(abs)) return;
    for (const d of readdirSync(abs)) {
      const rel = join(parent, d);
      const mf = join(ROOT, rel, manifest);
      if (!existsSync(mf)) continue;
      let name = null;
      let version = null;
      const text = readFileSync(mf, 'utf8');
      if (manifest === 'package.json') {
        try {
          const j = JSON.parse(text);
          name = j.name;
          version = j.version;
        } catch (e) {
          failures.push(`  ✗ [${rel}] package.json is not parseable (failing closed): ${e.message}`);
          continue;
        }
      } else {
        const sec = sectionText(text, manifest === 'Cargo.toml' ? 'package' : 'project');
        name = strField(sec, 'name');
        version = strField(sec, 'version');
        if (!version && /^\s*version\s*(\.workspace|=\s*\{\s*workspace)/m.test(sec)) {
          version = strField(sectionText(readFileSync(join(ROOT, 'Cargo.toml'), 'utf8'), 'workspace\\.package'), 'version');
        }
      }
      if (name && version) pkgs.push({ dir: rel, name, version, eco });
    }
  };
  scan('crates', 'Cargo.toml', 'rust');
  scan('python', 'pyproject.toml', 'python');
  scan('typescript', 'package.json', 'npm');
  return pkgs;
}

/**
 * The release tag for this package at this version, most specific first.
 *
 * The tag scheme is per-ECOSYSTEM, not per-package (see CONTRIBUTING.md, which
 * says as much and calls it misleading) — `rust-v0.2.0` tags a Rust release,
 * with `python-vaid-pop-v0.2.0` as the one per-package exception. So the most
 * specific form is tried first and the ecosystem form is the fallback.
 */
function releaseTagFor(pkg) {
  for (const t of [`${pkg.eco}-${pkg.name}-v${pkg.version}`, `${pkg.eco}-v${pkg.version}`, `v${pkg.version}`]) {
    if (TAGS.has(t)) return t;
  }
  return null;
}

/* -------------------------------- checking ------------------------------- */

/**
 * What this vector is frozen ON.
 *
 * Most vectors PIN BYTES: they carry a self-declared `digest_sha256_hex`, and the
 * freeze compares that value across the release tag. That is the original
 * contract and it is unchanged.
 *
 * A PREDICATE vector (`scope_v1.json`, ADR-0005) pins VERDICTS, not bytes.
 * Containment is computed over a document and never appears inside one, so there
 * is nothing to digest and the field is deliberately absent.
 *
 * This function used to fail closed on a missing digest, on the reasoning that a
 * vector without one "cannot be frozen". For a predicate vector that reasoning
 * inverts: refusing to freeze it leaves it UNPROTECTED, which is the opposite of
 * failing closed. So it is frozen on the SHA-256 of its own file bytes instead —
 * a strictly stronger pin than the declared-digest one, since it catches any
 * change to the file at all, including to the cases themselves.
 *
 * Fail-closed is preserved everywhere it was load-bearing: unparseable JSON still
 * fails, and a vector that HAS a digest is still compared on it, so a byte-pinning
 * vector that silently lost its digest field cannot slip through as a content
 * hash — the `then` side would still carry one and the mismatch in freeze MODE is
 * reported.
 */
function freezeKeyOf(text, label) {
  let j;
  try {
    j = JSON.parse(text);
  } catch (e) {
    failures.push(`  ✗ ${label}: not parseable JSON (failing closed): ${e.message}`);
    return undefined;
  }
  const d = j[DIGEST_FIELD];
  if (typeof d === 'string' && d.length > 0) {
    return { mode: 'declared-digest', value: d };
  }
  return {
    mode: 'content-hash',
    value: createHash('sha256').update(text, 'utf8').digest('hex'),
  };
}

const packages = discoverPackages();

for (const pkg of packages) {
  const vectors = findVectors(pkg.dir);
  if (vectors.length === 0) continue;

  const tag = releaseTagFor(pkg);
  if (!tag) {
    // No tag for this version. Two different situations share this shape, and
    // this check (deliberately offline) cannot tell them apart:
    //
    //   (a) genuinely in flight — bumped, not yet released. Correct to skip;
    //       changing vectors before a release is what a pre-release is for, and
    //       verify-package-versions.mjs covers "bumped but not published".
    //   (b) released but never tagged — a tag-hygiene gap. Its vectors are
    //       UNPROTECTED by this check.
    //
    // COVERAGE OF THIS CHECK IS THEREFORE BOUNDED BY TAG HYGIENE. That is
    // stated loudly rather than hidden, because a check reporting "✓" over a
    // set it never examined is the exact masked-green defect this repo keeps
    // finding. Tag every release (CONTRIBUTING.md: merge → tag → publish) and
    // this list shrinks to only (a).
    //
    // Backfilling a tag for (b) requires knowing the exact published commit.
    // Guessing it would create a FALSE baseline — worse than no baseline, since
    // it would report ✓ against a comparison point that was never released.
    notes.push(`  · [${pkg.dir}] ${pkg.name} ${pkg.version} — no release tag, so its ${vectors.length} vector(s) are NOT checked (either in flight, or released-but-untagged)`);
    continue;
  }

  for (const v of vectors) {
    const label = `[${v}] (${pkg.name} ${pkg.version}, released as ${tag})`;
    let nowText;
    try {
      nowText = readFileSync(join(ROOT, v), 'utf8');
    } catch (e) {
      failures.push(`  ✗ ${label}: unreadable (failing closed): ${e.message}`);
      continue;
    }
    const now = freezeKeyOf(nowText, label);
    if (now === undefined) continue;

    const thenText = readAtTag(tag, v);
    if (thenText === null) {
      notes.push(`  · ${v} — new since ${tag}; nothing frozen to compare`);
      continue;
    }
    const then = freezeKeyOf(thenText, `${label} at ${tag}`);
    if (then === undefined) continue;

    // A vector that changed which thing it is frozen ON is a defect in itself: a
    // byte-pinning vector that lost its digest would otherwise silently downgrade
    // to a content hash and compare clean against nothing.
    if (now.mode !== then.mode) {
      failures.push(
        `  ✗ ${v}\n` +
        `      freeze MODE changed under an already-released version\n` +
        `        at ${tag}: ${then.mode}\n` +
        `        now:        ${now.mode}\n` +
        `      A vector may not change how it is pinned without a version bump.`,
      );
      continue;
    }

    if (now.value !== then.value) {
      const what = now.mode === 'declared-digest' ? 'digest' : 'content hash';
      failures.push(
        `  ✗ ${v}\n` +
        `      ${what} CHANGED under an already-released version — this is a wire-contract break shipped without a version bump\n` +
        `        at ${tag}: ${then.value}\n` +
        `        now:        ${now.value}\n` +
        `      ${pkg.name} is still ${pkg.version}. Bump it (and publish), or revert the vector.`,
      );
    } else {
      checked.push({ v, pkg, tag, mode: now.mode });
    }
  }
}

/* ------------------------------- reporting ------------------------------- */

console.log(`Discovered ${packages.length} package(s); checked ${checked.length} frozen vector(s) against their release tags.`);
for (const c of checked.sort((a, b) => a.v.localeCompare(b.v))) {
  console.log(`  ✓ ${c.v} — unchanged since ${c.tag}${c.mode === 'content-hash' ? ' (content hash — predicate vector)' : ''}`);
}
if (notes.length) {
  console.log(`\nNOT CHECKED — ${notes.length} (named, never silently skipped):`);
  for (const n of notes.sort()) console.log(n);
  console.log('  Coverage is bounded by tag hygiene: an untagged release cannot be frozen.');
}

if (failures.length) {
  console.error(`\n✗ VECTOR FREEZE CHECK FAILED — ${failures.length} problem(s):\n${failures.join('\n')}\n`);
  console.error('A frozen vector is what a consumer pins to. If its digest moves, the contract moved,');
  console.error('and every implementation built against the released version is now wrong.');
  process.exit(1);
}

console.log(`\n✓ vector freeze — ${checked.length} vector(s) unchanged under their released versions, ${notes.length} not checked (see above).`);
