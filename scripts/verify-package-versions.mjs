// Registry-parity check — every publishable package's IN-REPO version must be
// PUBLISHED on its registry, INDEPENDENT of any capability claim.
//
// Why this exists: the capabilities verification check only validates versions a
// *capability* names. A package can be version-bumped in-repo and never published,
// and nothing catches it — exactly what happened with python vaid-pop (repo 0.2.0
// while PyPI served 0.1.0). Repo and registry disagreeing silently is precisely the
// class of drift the manifest exists to prevent.
//
// WHAT "PARITY" MEANS HERE, and it changed in #84. It used to assert that the
// in-repo version EXISTS on the registry, full stop — so a version bumped and not
// yet published was red, deliberately. That reasoning holds on `main` AFTER a
// release and breaks when the same check is a REQUIRED MERGE CHECK, because then
// the check needs the publish, the publish needs a tag, the tag needs the merge,
// and the merge needs the check. #82 sat blocked in exactly that loop, and was
// merged only by removing this context from the required list for 50 seconds.
//
// The two states the old rule collapsed are distinguished by the RELEASE TAG, which
// is already the signal `verify-vector-freeze.mjs` uses, in the same direction, for
// the same reason. A version is "released" when a tag says so — not when someone
// edited a manifest:
//
//   in-repo version HAS a release tag, and IS on the registry   -> pass
//   in-repo version HAS a release tag, NOT on the registry      -> FAIL, half-released
//   in-repo version has NO tag, NOT on the registry, and is
//     NEWER than every published version                        -> note, in flight
//   in-repo version has NO tag, NOT on the registry, and is NOT
//     newer than everything published                           -> FAIL, stale bump
//   in-repo version has NO tag but IS on the registry           -> FAIL (tag parity,
//     the second pass below, which checks EVERY published version and not only this one)
//
// The last two rows are not in #84's table and are the reason this is not simply a
// loosening. "No tag and not published" would otherwise be an unconditional pass,
// which is a hole big enough to drive the original defect through: python vaid-pop
// sat in-repo at 0.2.0 while PyPI served 0.1.0. That case HAD a tag, so row 2 still
// catches it — but a typo'd or reverted manifest need not have one, and a version
// that is not ahead of the registry is not a pending release by any reading. So
// "in flight" must MEAN in flight: strictly ahead of everything published.
//
// What is genuinely given up: a bump that is never released is now a note rather
// than a failure, until something else moves. That loss is real, bounded, and was
// argued in #84 — the next release catches it, and verify-crosslang-parity.mjs
// already reports skew between the three languages.
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

/* --------------------------- the parity verdict --------------------------- */
//
// PURE, and exported, so the four states above can be exercised against fixed
// fixtures with no network and no git. The self-check below does exactly that, and
// runs BEFORE any registry call: a classifier that is broken makes every verdict it
// produces meaningless, however green they look.

/**
 * Compare two x.y.z versions. A prerelease suffix (`1.2.0-rc1`) is ordered just
 * BELOW its release, which is the conservative direction here: it keeps a
 * prerelease from counting as "newer than everything published" on its own.
 */
export function cmpSemver(a, b) {
  const parse = (v) => {
    const [core, pre] = String(v).split('-', 2);
    const n = core.split('.').map((x) => Number(x));
    return { n, pre: pre ?? null };
  };
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < 3; i++) {
    const x = pa.n[i] ?? 0, y = pb.n[i] ?? 0;
    if (!Number.isFinite(x) || !Number.isFinite(y)) return NaN; // unparseable: caller fails closed
    if (x !== y) return x - y;
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === null) return 1;   // release > its prerelease
  if (pb.pre === null) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

/**
 * The verdict for ONE package, given only facts: the in-repo version, every version
 * the registry serves, and whether a release tag exists for the in-repo version.
 *
 * Returns `{ verdict, detail }`. `verdict` is one of:
 *   'published'    — released and present. Pass.
 *   'half-released'— tagged as released, absent from the registry. FAIL.
 *   'in-flight'    — untagged, unpublished, strictly ahead of everything published. Note.
 *   'stale-bump'   — untagged, unpublished, NOT ahead of what is published. FAIL.
 *   'unorderable'  — a version here could not be compared. FAIL, closed.
 */
export function classifyParity({ version, published, tagged }) {
  const live = published.includes(version);
  if (live) return { verdict: 'published', detail: null };
  if (tagged) {
    return {
      verdict: 'half-released',
      detail:
        `is TAGGED as released but is NOT on the registry — the release half-happened.` +
        ` Either the publish failed (re-run it) or the tag is wrong (delete it).` +
        ` This is the state the check exists for: a tag asserts a release that is not there.`,
    };
  }
  for (const v of published) {
    const c = cmpSemver(version, v);
    if (Number.isNaN(c)) {
      return {
        verdict: 'unorderable',
        detail: `cannot be ordered against published version '${v}' (failing closed)`,
      };
    }
    if (c <= 0) {
      return {
        verdict: 'stale-bump',
        detail:
          `is not published and has no release tag, but it is NOT ahead of ${v}, which IS` +
          ` published — so this is not a release in flight. A pending release is strictly` +
          ` newer than everything on the registry; this is a downgrade, a typo or a revert.`,
      };
    }
  }
  return { verdict: 'in-flight', detail: null };
}

/* ------------------------------- self-check ------------------------------- */
//
// Five fixtures with known verdicts. These are the POSITIVE CONTROL for the change
// in #84: the loosening is only safe if the cases it must still catch are proven to
// fail, so three of the five MUST be failures. Fixed inputs, no network, no git.
function selfCheck() {
  const problems = [];
  const P = ['0.1.0', '0.2.0'];
  const cases = [
    // The #84 deadlock: the case that had to stop failing.
    { name: 'untagged bump ahead of the registry', args: { version: '0.3.0', published: P, tagged: false }, want: 'in-flight' },
    // The original defect this check was built for. vaid-pop sat at 0.2.0 in-repo
    // while PyPI served 0.1.0, and it was TAGGED. It must still fail.
    { name: 'tagged but absent from the registry', args: { version: '0.3.0', published: P, tagged: true }, want: 'half-released' },
    // The hole the loosening would open if "no tag" alone were a pass. The version
    // must be one the registry does NOT serve — a version it does serve is 'published'
    // by definition, which is a different row and proves nothing about this one.
    { name: 'untagged, unpublished, BEHIND the registry', args: { version: '0.1.5', published: P, tagged: false }, want: 'stale-bump' },
    // A prerelease is ordered below its release, so it is not "ahead of everything".
    { name: 'untagged prerelease of an already-published version', args: { version: '0.2.0-rc1', published: P, tagged: false }, want: 'stale-bump' },
    // The mirror of the case above, and NOT symmetric with it: here the in-repo
    // version is the RELEASE and the registry has only its prerelease, so the repo
    // IS strictly ahead. Without this fixture the `pa.pre === null` branch of
    // cmpSemver is never exercised and a mutant that collapses it to 0 survives —
    // which would turn a legitimate rc-to-release promotion into a 'stale-bump' red.
    { name: 'untagged release ahead of its own published prerelease', args: { version: '0.2.0', published: ['0.1.0', '0.2.0-rc1'], tagged: false }, want: 'in-flight' },
    // The ordinary green state.
    { name: 'released and present', args: { version: '0.2.0', published: P, tagged: true }, want: 'published' },
  ];
  for (const c of cases) {
    const got = classifyParity(c.args).verdict;
    if (got !== c.want) problems.push(`fixture '${c.name}' expected '${c.want}', classifier said '${got}'`);
  }
  // A never-published package's first release is in flight, not a stale bump.
  if (classifyParity({ version: '0.1.0', published: [], tagged: false }).verdict !== 'in-flight')
    problems.push("fixture 'first release, nothing published yet' did not classify as in-flight");
  return problems;
}

const selfCheckProblems = selfCheck();
if (selfCheckProblems.length) {
  console.error('✗ SELF-CHECK FAILED — the parity classifier is broken, so its verdict on this tree means nothing:');
  for (const p of selfCheckProblems) console.error(`  · ${p}`);
  process.exit(2);
}
console.log('✓ self-check — parity classifier agrees with all seven fixed fixtures (three must-fail, four must-pass).');

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
  // PyPI: read `releases`, NEVER `info.version`.
  //
  // `info.version` is served through a CDN that can lag the upload by minutes,
  // and it lags in the direction that matters: immediately after publishing
  // vaid-mint 0.6.0 it was observed still reporting 0.5.0 while `releases`
  // already listed 0.6.0 and `/pypi/vaid-mint/0.6.0/json` returned 200. A check
  // reading `info.version` would have reported "bumped but not released" for a
  // release that was live, and the correct response to THAT is to retry, not to
  // investigate a publish that already succeeded.
  //
  // `releases` is the full set and is the authoritative answer to the only
  // question this check asks: is this version present at all.
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

// The registry is asked ONCE per package and the answer is reused by both passes
// below. Two calls asking the same registry the same question is two chances to be
// rate-limited into a failing-closed red for no added assurance.
for (const p of pkgs) {
  if (p.skip) continue;
  try {
    p.published = await publishedVersions(p.registry, p.name);
  } catch (e) {
    p.fetchError = e.message;
  }
}

const inFlight = [];

for (const p of pkgs) {
  if (p.skip) { notes.push(`  · [${p.dir}] ${p.name} — opt-out marker present, not checked`); continue; }
  if (!p.version) { failures.push(`  ✗ [${p.dir}] ${p.name}: could not read a literal version (dynamic/unresolved) — cannot verify parity (failing closed)`); continue; }
  if (p.fetchError) { failures.push(`  ✗ [${p.dir}] could not verify (failing closed): ${p.fetchError}`); continue; }
  const waiver = WAIVED.get(`${p.registry}:${p.name}`);
  const live = p.published.includes(p.version);
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

  const tag = releaseTagFor(ECO[p.registry], p.name, p.version);
  const { verdict, detail } = classifyParity({ version: p.version, published: p.published, tagged: tag !== null });

  if (verdict === 'published') continue;
  if (verdict === 'in-flight') {
    // NOT a pass in disguise: it is stated, every run, with what would clear it.
    inFlight.push({ ...p });
    continue;
  }
  failures.push(`  ✗ [${p.dir}] ${p.name} ${p.version} (${p.registry}) ${detail}${tag ? ` Tag: ${tag}.` : ''}`);
}

// ── release tag parity ──────────────────────────────────────────────────────
for (const p of pkgs) {
  if (p.skip) continue;
  const eco = ECO[p.registry];
  try {
    if (p.fetchError) throw new Error(p.fetchError);
    const versions = p.published;
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

// IN FLIGHT prints in full, every run. This is the state #84 moved from red to
// green, and the whole argument for that move is that it stays VISIBLE: a release
// that is prepared and never shipped must be readable off a green run, or the
// loosening becomes the silence it replaced. Each line says what would clear it.
console.log(`\nIN FLIGHT — ${inFlight.length} package(s) bumped, not yet released (no tag, ahead of the registry):`);
if (inFlight.length === 0) console.log('  (none)');
for (const p of inFlight.sort((a, b) => a.dir.localeCompare(b.dir))) {
  const max = p.published.length ? p.published.slice().sort(cmpSemver).pop() : '(nothing published)';
  console.log(`  → [${p.dir}] ${p.name} ${p.version} — ${p.registry} serves up to ${max}`);
  console.log(`      Clears when ${p.name} ${p.version} is published AND tagged ${ECO[p.registry]}-${p.name}-v${p.version}.`);
  console.log(`      Until then this is NOT evidence of a release; it is evidence of an intention.`);
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
const checkedCount = pkgs.filter((p) => !p.skip).length;
console.log(`✓ registry parity — ${checkedCount} package(s) checked: ${checkedCount - waived.length - inFlight.length} released and present, ${inFlight.length} in flight, ${waived.length} waived.`);
console.log('✓ release tag parity — every published version has a release tag.');
