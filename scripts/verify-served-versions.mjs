#!/usr/bin/env node
//
// verify-served-versions.mjs — the served text may not name a version the
// registries contradict.
//
// WHY THIS EXISTS. `docs/capabilities.json` is SERVED on /capabilities and
// vendored by the site, so its `status_text` is published copy, not an internal
// note. Twice now a release has left a sentence in it asserting something the
// registries disprove: "every published vaid-mint (0.2.0 through 0.7.0 ...)"
// became false the moment 0.8.0 was published, and "Fail-closed by default is
// unpublished 0.8.0 work" became false in the other direction when 0.8.0 shipped
// without it. Both were caught by a human reading carefully, and a third occasion
// is certain. This check reads those sentences against the registries instead.
//
// WHAT IT ASSERTS. For every x.y.z token in `status_text` and `landed_in`, the
// claim the surrounding sentence makes about that version must agree with what is
// actually published:
//
//   * publication-asserting sentence  -> the version MUST be published
//   * absence-asserting sentence      -> the version MUST NOT be published
//   * "X through Y", publication-asserting -> Y MUST be the MAXIMUM published
//     version for that package (this is the rule that catches a range the next
//     release silently extends past)
//   * a sentence matching both classes, or neither, is a FAILURE, not a skip. A
//     version nobody makes a claim about has no reason to be in served copy.
//
// FAIL CLOSED. A registry lookup that errors or times out is a failure, not a
// pass — the same precedent verify-capabilities.mjs sets in its own catch.
//
// POSITIVE CONTROL. Before reading the manifest it self-checks its classifier
// against two fixed fixture sentences, one that must FAIL and one that must
// PASS, and exits 2 if either verdict comes back wrong. Without it, a classifier
// whose regexes stop matching reports a clean manifest and reads exactly like a
// correct one.
//
// USAGE
//   node scripts/verify-served-versions.mjs                    # 0 = agrees with the registries
//   node scripts/verify-served-versions.mjs --self-check       # 2 = the checker itself is broken
//   node scripts/verify-served-versions.mjs --manifest <path>  # e.g. the site's vendored copy

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const UA = { 'User-Agent': 'solara-associates/vaid verify-served-versions' };
const HERE = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const SELF_CHECK_ONLY = argv.includes('--self-check');
const manifestIdx = argv.indexOf('--manifest');
const MANIFEST = manifestIdx >= 0 && argv[manifestIdx + 1]
  ? resolve(argv[manifestIdx + 1])
  : resolve(HERE, '..', 'docs', 'capabilities.json');

// Every package that can be named in served copy, and where it is published.
// A package published in several ecosystems is "published at version V" if V is
// present on ANY of them: the sentences here speak of "vaid-mint", not of one
// language's build of it.
const PACKAGES = {
  'vaid-mint':      [['crates.io', 'vaid-mint'], ['pypi', 'vaid-mint'], ['npm', 'vaid-mint']],
  'vaid-pop':       [['crates.io', 'vaid-pop'], ['pypi', 'vaid-pop'], ['npm', 'vaid-pop']],
  'vaid-client':    [['crates.io', 'vaid-client'], ['npm', 'vaid-client']],
  'vaid-langchain': [['pypi', 'vaid-langchain']],
  'vaid-skill':     [['npm', 'vaid-skill']],
};
const DEFAULT_PACKAGE = 'vaid-mint';

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
  if (res.status === 404) return [];
  if (res.status !== 200) throw new Error(`unexpected HTTP ${res.status} from ${registry} for ${name}`);
  const j = await res.json();
  if (registry === 'crates.io') return j.versions.map((v) => v.num);
  // PyPI: read `releases`, never `info.version` — the latter is CDN-cached and
  // lags the upload, in the direction that would report a live release missing.
  if (registry === 'pypi') return Object.keys(j.releases);
  return Object.keys(j.versions);
}

const cmpSemver = (a, b) => {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
};

/** Split prose into sentences WITHOUT splitting inside an x.y.z token. */
export function sentences(text) {
  return text
    .split(/(?<=[.;:])\s+(?=[A-Z(“"'])/)
    .map((s) => s.trim())
    .filter(Boolean);
}

const PUBLICATION_RE = /\b(published|publishes|shipped|ships|serves|serving|install(?:s|ed|able)?|(?:on|to)\s+(?:crates\.io|PyPI|npm)|(?:crates\.io|PyPI|npm)\s+re-?release|re-?released|available\s+on|release[ds]?\s+(?:as|on|to)|gained|landed|introduced|arrived)\b/i;
const ABSENCE_RE = /\b(unpublished|unmerged|not\s+(?:yet\s+)?published|no\s+published|never\s+published|only\s+on|exists\s+only|planned|prepared|in\s+flight|unreleased)\b/i;

/**
 * 'publication' | 'absence' | 'ambiguous' | 'none'
 *
 * A sentence matching BOTH classes is 'ambiguous' and fails. That is deliberate
 * and it is what keeps the broad verbs above safe: widening the publication set
 * can only turn a silent pass into a loud failure, never the reverse.
 */
export function classify(sentence) {
  const pub = PUBLICATION_RE.test(sentence);
  const abs = ABSENCE_RE.test(sentence);
  if (pub && abs) return 'ambiguous';
  if (pub) return 'publication';
  if (abs) return 'absence';
  return 'none';
}

/** Which package is this sentence talking about? */
function packageFor(sentence, fallback) {
  const named = Object.keys(PACKAGES).filter((p) => sentence.includes(p));
  // Longest match wins so "vaid-mint" is not shadowed by a shorter sibling.
  if (named.length) return named.sort((a, b) => b.length - a.length)[0];
  return fallback || DEFAULT_PACKAGE;
}

const VERSION_RE = /\b(\d+\.\d+\.\d+)\b/g;
const RANGE_RE = /\b(\d+\.\d+\.\d+)\s+through\s+(\d+\.\d+\.\d+)\b/gi;

/**
 * Check one sentence against a resolver. Returns an array of failure strings.
 * `resolve(pkg)` -> { set: Set<string>, max: string|null }
 */
export function checkSentence(sentence, resolvePkg, where, fallbackPkg, forcedKind) {
  const out = [];
  const versions = [...sentence.matchAll(VERSION_RE)].map((m) => m[1]);
  if (!versions.length) return out;

  // `landed_in` is a STRUCTURED claim, not prose: the field means "this shipped
  // in version X". Classifying its bare text ("vaid-mint 0.4.0") as making no
  // claim would fail every entry in the file for a claim the schema is making.
  const kind = forcedKind ?? classify(sentence);
  if (kind === 'ambiguous' || kind === 'none') {
    out.push(`${where}: sentence names ${versions.join(', ')} but its claim is ${kind === 'ambiguous'
      ? 'BOTH publication- and absence-asserting'
      : 'NEITHER publication- nor absence-asserting'} — a version in served copy must make a checkable claim.\n    "${sentence}"`);
    return out;
  }

  const pkg = packageFor(sentence, fallbackPkg);
  const { set, max } = resolvePkg(pkg);

  for (const v of versions) {
    const isPub = set.has(v);
    if (kind === 'publication' && !isPub) {
      out.push(`${where}: asserts ${pkg} ${v} is published; it is NOT on any registry.\n    "${sentence}"`);
    }
    if (kind === 'absence' && isPub) {
      out.push(`${where}: asserts ${pkg} ${v} is NOT published; it IS published.\n    "${sentence}"`);
    }
  }

  if (kind === 'publication') {
    for (const m of sentence.matchAll(RANGE_RE)) {
      const top = m[2];
      if (max && cmpSemver(top, max) !== 0) {
        out.push(`${where}: range "${m[1]} through ${top}" for ${pkg} claims to cover what is published, but the maximum published version is ${max}.\n    "${sentence}"`);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------- self-check
//
// Two fixtures with known verdicts, run against a FIXED resolver so the control
// does not depend on the network or on today's registry state.
const FIXTURE_RESOLVER = () => ({ set: new Set(['0.7.0', '0.8.0']), max: '0.8.0' });

function selfCheck() {
  const problems = [];

  const mustFail = 'Fail-closed by default is unpublished 0.7.0 work.';
  const failVerdict = checkSentence(mustFail, FIXTURE_RESOLVER, 'self-check', 'vaid-mint');
  if (failVerdict.length === 0) {
    problems.push('fixture that MUST FAIL came back clean — the absence-assertion classifier is not matching.');
  }

  const mustPass = 'vaid-mint 0.8.0 is published on crates.io, PyPI and npm.';
  const passVerdict = checkSentence(mustPass, FIXTURE_RESOLVER, 'self-check', 'vaid-mint');
  if (passVerdict.length !== 0) {
    problems.push(`fixture that MUST PASS reported a failure — the checker is over-firing:\n    ${passVerdict.join('\n    ')}`);
  }

  return problems;
}

// --------------------------------------------------------------------- main
const problems = selfCheck();
if (problems.length) {
  console.error('✗ SELF-CHECK FAILED — the checker itself is broken, so its verdict on the manifest means nothing:');
  for (const p of problems) console.error(`  · ${p}`);
  process.exit(2);
}
console.log('✓ self-check — classifier agrees with both fixed fixtures (one must-fail, one must-pass).');
if (SELF_CHECK_ONLY) process.exit(0);

let manifest;
try {
  manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
} catch (e) {
  console.error(`✗ could not read manifest ${MANIFEST}: ${e.message}`);
  process.exit(1);
}
const caps = manifest.capabilities ?? manifest;

// Resolve every package the manifest could name, ONCE, failing closed.
const resolved = new Map();
try {
  for (const [pkg, targets] of Object.entries(PACKAGES)) {
    const all = new Set();
    for (const [registry, name] of targets) {
      for (const v of await publishedVersions(registry, name)) all.add(v);
    }
    const sorted = [...all].filter((v) => /^\d+\.\d+\.\d+$/.test(v)).sort(cmpSemver);
    resolved.set(pkg, { set: all, max: sorted.length ? sorted[sorted.length - 1] : null });
  }
} catch (e) {
  // Fail CLOSED: an inability to verify is a failure, not a pass.
  console.error(`✗ registry lookup failed, so nothing here is verified (failing closed): ${e.message}`);
  process.exit(1);
}

const resolvePkg = (pkg) => resolved.get(pkg) ?? { set: new Set(), max: null };

const failures = [];
let sentencesChecked = 0;
let versionsChecked = 0;

for (const cap of caps) {
  const id = cap.id ?? '<no id>';
  const fallback = typeof cap.landed_in === 'string'
    ? packageFor(cap.landed_in, DEFAULT_PACKAGE)
    : DEFAULT_PACKAGE;

  for (const field of ['status_text', 'landed_in']) {
    const text = cap[field];
    if (typeof text !== 'string' || !text) continue;
    for (const s of sentences(text)) {
      const vs = (s.match(VERSION_RE) || []).length;
      if (!vs) continue;
      sentencesChecked += 1;
      versionsChecked += vs;
      failures.push(...checkSentence(
        s, resolvePkg, `[${id}] ${field}`, fallback,
        field === 'landed_in' ? 'publication' : undefined,
      ));
    }
  }
}

console.log(`\nManifest: ${MANIFEST}`);
for (const [pkg, { max }] of resolved) {
  console.log(`  · ${pkg} — max published: ${max ?? '(nothing published)'}`);
}
console.log(`\nChecked ${versionsChecked} version token(s) across ${sentencesChecked} sentence(s).`);

if (failures.length) {
  console.error(`\n✗ served text contradicts the registries — ${failures.length} problem(s):\n`);
  for (const f of failures) console.error(`  · ${f}\n`);
  process.exit(1);
}
console.log('\n✓ every version named in served copy agrees with the registries.');
