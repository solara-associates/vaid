/**
 * Does README.md still describe this repository?
 *
 * It stopped, comprehensively, and nothing noticed. At the point this check was
 * written the README said TypeScript was "not on npm yet" (it had been for a
 * week), said "two languages" in several places (there were three), named "all
 * five" frozen vectors (there were nine), told readers the Rust conformance check
 * needed a repo checkout (an installable binary had shipped), and carried version
 * numbers that were several releases stale.
 *
 * Every one of those sentences was true when written. That is the whole problem:
 * a stale enumeration does not error, does not fail a test, and reads exactly like
 * a current one. Nothing in this repo watched the README, so it drifted for months
 * while every other check stayed green.
 *
 * ## What this fails on
 *
 *   VERSION  A hardcoded version number anywhere in the file. Point at the
 *            registries (badges resolve live) or at docs/capabilities.json
 *            instead. Hardcoded versions in prose is a recorded defect class here.
 *   PAIR     Prose naming >=2 but <all members of a set, within one sentence.
 *   COUNT    A counting word ("two", "both", "all five") near a noun belonging to
 *            a set, where the number no longer matches the set size.
 *   VECTORS  A cross-language vector that exists in the tree but is named nowhere
 *            in the README — the "all five" failure, which is a missing ROW rather
 *            than a wrong word and which no prose scan would catch.
 *
 * ## Set membership is DERIVED, not listed
 *
 * A second hardcoded list would drift the same way the first one did. So the sets
 * come from the tree:
 *
 *   · languages and registries  <- release-map.json, which the release workflow
 *                                  already depends on, so it cannot be forgotten
 *   · cross-language vectors    <- the vector files actually present in the
 *                                  reference crates
 *
 * Add a tenth vector and every stale sentence here fails on the next run without
 * anyone editing this file. That is the point.
 *
 * A fourth LANGUAGE is the one case that needs a hand: ecosystem keys have to be
 * translated to a language and registry name, and that table lives here. An
 * ecosystem this file cannot translate HALTS the check rather than being skipped —
 * see the guard below for why silently narrowing the set was the worse option.
 *
 * SUPPRESSION REQUIRES A REASON. An `allow` entry needs a substring and a written
 * justification. A bare exemption is not expressible, because an escape hatch
 * without a reason becomes noise and then gets muted.
 *
 * Run: node scripts/check-readme-drift.mjs
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = 'README.md';

// ── legitimate exemptions, each with a reason ────────────────────────────────
const ALLOW = [
  {
    contains: 'Contributor Covenant 2.1',
    why: 'The version of an external document we adopted. It is a proper noun, not a claim about anything published from this repo, and it must not track our releases.',
  },
  {
    contains: 'RFC 8785',
    why: 'An RFC number, not a version.',
  },
  {
    contains: 'Apache-2.0',
    why: 'A licence identifier.',
  },
  {
    contains: 'RFC 3339',
    why: 'An RFC number, not a version.',
  },
  {
    contains: 'the reference request signer, in Rust and TypeScript',
    why: "Correct as a subset. `vaid-client` genuinely exists in two languages: Python's request signer lives inside `vaid-pop` rather than in a separate package. The sentence immediately says so, and completing the list here would make it FALSE — there is no Python vaid-client to install. This is the case the check must not force.",
  },
];

// ── sets, derived ────────────────────────────────────────────────────────────
const ECO_TO_LANGUAGE = { rust: 'Rust', python: 'Python', npm: 'TypeScript' };
const ECO_TO_REGISTRY = { rust: 'crates.io', python: 'PyPI', npm: 'npm' };

const map = JSON.parse(readFileSync(join(ROOT, 'release-map.json'), 'utf8'));
const ecos = [...new Set(Object.keys(map.packages ?? {}).map((k) => k.split('/')[0]))];

// An ecosystem present in release-map.json but absent from the two tables above was
// silently discarded by the `.filter(Boolean)` below, and the derived sets kept their
// old size. A fourth language could therefore ship while every "three languages"
// sentence in the README still passed — this file's own defect class, reappearing
// inside the checker that exists to catch it. Verified before fixing: adding a `go/`
// entry to release-map.json left the languages set at three and the check green.
//
// Fail closed instead, on the same principle the packaged conformance firewall
// settled on — a check that cannot see the whole set must never report PASS. These
// two tables are the one place a new ecosystem has to be taught, and skipping that
// step now halts the check rather than quietly narrowing it.
const untranslated = ecos.filter((e) => !ECO_TO_LANGUAGE[e] || !ECO_TO_REGISTRY[e]);
if (untranslated.length > 0) {
  console.error(
    `✗ README DRIFT CHECK CANNOT RUN — release-map.json names ecosystem(s) this ` +
      `check cannot translate: ${untranslated.join(', ')}`,
  );
  console.error(
    '\n  Add them to ECO_TO_LANGUAGE and ECO_TO_REGISTRY in scripts/check-readme-drift.mjs.',
  );
  console.error(
    '  Until then the derived sets would be too small, and every sentence naming',
  );
  console.error(
    '  the old number of languages or registries would pass while being wrong.\n',
  );
  process.exit(1);
}

/** The cross-language vectors, from the reference crates rather than a list. */
function crossLanguageVectors() {
  const names = new Set();
  for (const c of ['vaid-pop', 'vaid-mint', 'vaid-client']) {
    const dir = join(ROOT, 'crates', c, 'tests', 'vectors');
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir)) if (f.endsWith('_v1.json')) names.add(f);
  }
  return [...names].sort();
}

const SETS = {
  languages: {
    members: ecos.map((e) => ECO_TO_LANGUAGE[e]).filter(Boolean),
    // `JavaScript` and `Node` are how TypeScript gets named in passing.
    aliases: { TypeScript: ['TypeScript', 'JavaScript', 'Node.js'] },
    nouns: 'language|languages|SDK|SDKs|implementation|implementations|signer|signers|verifier|verifiers|reference',
  },
  registries: {
    members: ecos.map((e) => ECO_TO_REGISTRY[e]).filter(Boolean),
    aliases: { npm: ['npm', 'npmjs.com'], PyPI: ['PyPI', 'pypi.org'] },
    nouns: 'registry|registries|package manager|package managers|ecosystem|ecosystems',
    // Registry NAMES are self-identifying — "crates.io" and "PyPI" are not words
    // that turn up by accident — so naming two of them is signal enough without a
    // nearby noun. Requiring one missed the exact original defect: "Published on
    // crates.io and PyPI", written before npm existed, has no such noun in it.
    nounOptional: true,
  },
  // COUNT only — membership is enforced by the VECTORS check below, which names
  // them. This exists because "all five frozen vectors" was one of the original
  // defects and no set covered a count of vectors at all.
  vectors: {
    members: crossLanguageVectors(),
    countOnly: true,
    nouns: 'vector|vectors',
  },
};


// ── scan ─────────────────────────────────────────────────────────────────────
const raw = readFileSync(join(ROOT, TARGET), 'utf8');
const lines = raw.split('\n');
const findings = [];
const usedAllows = new Set();

/**
 * Prose joined into paragraphs, each remembering the line it started on.
 *
 * Markdown hard-wraps, so a sentence routinely spans lines. Scanning line by line
 * splits "Rust, Python and\nTypeScript" into a line naming two of three and reports
 * it as an incomplete list — a false positive that would train a reader to ignore
 * this check, which is worse than not having it.
 *
 * This is not a hypothetical failure mode: the same line-based assumption produced
 * two wrong results earlier the same day, once in a Playwright selector and once in
 * a grep over published docs. Sentence-level checks must operate on sentences.
 */
const paragraphs = [];
{
  let buf = [];
  let start = 0;
  let inFence = false;
  lines.forEach((line, i) => {
    if (/^\s*```/.test(line)) inFence = !inFence;
    // Fenced code is scanned line-wise for versions, but never for prose
    // enumerations — a shell snippet is not a sentence.
    if (inFence || /^\s*\|/.test(line)) {
      if (buf.length) { paragraphs.push({ text: buf.join(' '), line: start + 1 }); buf = []; }
      return;
    }
    if (line.trim() === '') {
      if (buf.length) { paragraphs.push({ text: buf.join(' '), line: start + 1 }); buf = []; }
      return;
    }
    if (buf.length === 0) start = i;
    buf.push(line.trim());
  });
  if (buf.length) paragraphs.push({ text: buf.join(' '), line: start + 1 });
}

const exempt = (line) => {
  for (const a of ALLOW) {
    if (line.includes(a.contains)) {
      usedAllows.add(a.contains);
      return true;
    }
  }
  return false;
};

// VERSION — the rule that this file exists to hold.
// Matched on X.Y.Z so licence identifiers and RFC numbers do not trip it; those
// that still would are exempted above, with reasons.
const SEMVER = /\b\d+\.\d+\.\d+\b/;
lines.forEach((line, i) => {
  // Badge URLs legitimately contain package names and query strings but never a
  // pinned version — they resolve live, which is the whole point of using them.
  if (/img\.shields\.io/.test(line)) return;
  const m = line.match(SEMVER);
  if (m && !exempt(line)) {
    findings.push({
      kind: 'VERSION',
      line: i + 1,
      detail: `hardcoded version "${m[0]}"`,
      text: line.trim(),
      fix: 'Point at the registry badge or docs/capabilities.json. A number written here goes stale silently and reads exactly like a current one.',
    });
  }
});

// PAIR — naming some of a set but not all of it, in one sentence.
for (const [setName, set] of Object.entries(SETS)) {
  if (set.countOnly) continue;
  const nounRe = new RegExp(`\\b(${set.nouns})\\b`, 'i');
  const present = (sentence, member) =>
    (set.aliases?.[member] ?? [member]).some((a) =>
      new RegExp(`\\b${a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(sentence),
    );

  paragraphs.forEach(({ text, line: lineNo }) => {
    if (exempt(text)) return;
    for (const sentence of text.split(/(?<=[.!?;])\s+/)) {
      if (!set.nounOptional && !nounRe.test(sentence)) continue;
      const named = set.members.filter((m) => present(sentence, m));
      if (named.length >= 2 && named.length < set.members.length) {
        findings.push({
          kind: 'PAIR',
          line: lineNo,
          detail: `names ${named.length} of ${set.members.length} "${setName}" (${named.join(', ')}) — missing ${set.members.filter((m) => !named.includes(m)).join(', ')}`,
          text: sentence.trim(),
          fix: 'Complete the list, or add an allow entry with a reason if naming a subset is deliberate here.',
        });
      }
    }
  });
}

// COUNT — a counting word that no longer matches the set size.
const WORD = { two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10, both: 2 };
for (const [setName, set] of Object.entries(SETS)) {
  const nounRe = new RegExp(`\\b(${set.nouns})\\b`, 'i');
  paragraphs.forEach(({ text: line, line: lineNo }) => {
    if (exempt(line)) return;
    for (const [word, n] of Object.entries(WORD)) {
      // The counting word must MODIFY a set noun, not merely sit near one.
      // Proximity alone is far too loose: "both" is the ordinary English word for
      // two of anything, so "ADR-0005 and ADR-0006 are both cases where every
      // implementation agreed" tripped a languages finding about two ADRs. A check
      // that cries wolf on correct prose gets muted, and a muted check is worse
      // than no check.
      //
      // ONE filler word, so "both reference SDKs" and "three published SDKs"
      // match while "both cases where every implementation..." does not. Three was
      // enough to reach across a clause boundary into an unrelated noun.
      const re = new RegExp(`\\b${word}\\b(?:\\s+\\w+)?\\s+(?:${set.nouns})\\b`, 'i');
      if (!re.test(line)) continue;
      if (n !== set.members.length) {
        findings.push({
          kind: 'COUNT',
          line: lineNo,
          detail: `"${word}" (${n}) beside a "${setName}" noun, but there are ${set.members.length}`,
          text: line.trim(),
          fix: `Say ${Object.keys(WORD).find((k) => WORD[k] === set.members.length) ?? set.members.length}, or reword so no count is asserted.`,
        });
      }
    }
  });
}

// STALE-CLAIM — prose asserting something is NOT available yet.
//
// The set checks cannot reach this: "TypeScript is not on npm yet" enumerates
// nothing and counts nothing, and it was the single most misleading sentence in
// the old README — it had been on npm for a week.
//
// The shape is recognisable even though the content is not. A sentence saying
// something is unavailable is true only until it ships, and nobody revisits it at
// that moment because shipping is a different piece of work in a different repo.
// So the idioms are flagged and must be justified rather than merely written.
// Availability belongs in the live badges and docs/capabilities.json, which cannot
// say "not yet" after the fact.
const STALE_CLAIM = [
  /\bnot (?:on|published to) (?:npm|crates\.io|pypi)\b/i,
  /\bnot yet (?:published|available|on)\b/i,
  /\bwaits? on the (?:npm|crates|pypi) publish\b/i,
  /\bcoming soon\b/i,
  /\bbecause they are not on\b/i,
  /\bonly (?:provable|verifiable) from a checkout\b/i,
];
paragraphs.forEach(({ text, line: lineNo }) => {
  if (exempt(text)) return;
  for (const re of STALE_CLAIM) {
    const m = text.match(re);
    if (m) {
      findings.push({
        kind: 'STALE-CLAIM',
        line: lineNo,
        detail: `asserts unavailability: "${m[0]}"`,
        text: text.trim(),
        fix: 'A "not yet" is true only until it ships, and nobody comes back to it then. Let the live badges and docs/capabilities.json say what is available, or add an allow entry with a reason.',
      });
    }
  }
});

// VECTORS — a cross-language vector the README never mentions. This is the
// missing-ROW shape, which reading does not catch.
const vectors = crossLanguageVectors();
const missing = vectors.filter((v) => !raw.includes(v));
if (missing.length > 0) {
  findings.push({
    kind: 'VECTORS',
    line: 0,
    detail: `${missing.length} cross-language vector(s) exist in the tree but are named nowhere in ${TARGET}: ${missing.join(', ')}`,
    text: '(absent — nothing to quote)',
    fix: 'Add them to the vector table. A vector nobody documents is one an implementer will not know to reproduce.',
  });
}

// A dead exemption silences nothing and hides that it silences nothing.
for (const a of ALLOW) {
  if (!usedAllows.has(a.contains)) {
    findings.push({
      kind: 'ALLOW',
      line: 0,
      detail: `allow entry matches nothing: "${a.contains}"`,
      text: a.why,
      fix: 'Delete it.',
    });
  }
}

// ── report ───────────────────────────────────────────────────────────────────
console.log(`Scanned ${TARGET} (${lines.length} lines).`);
console.log(`  languages: ${SETS.languages.members.join(', ')}`);
console.log(`  registries: ${SETS.registries.members.join(', ')}`);
console.log(`  cross-language vectors: ${vectors.length}`);

if (findings.length === 0) {
  console.log(`\n✓ ${TARGET} — no stale enumerations, no hardcoded versions, every vector named.`);
  process.exit(0);
}

console.error(`\n✗ README DRIFT CHECK FAILED — ${findings.length} finding(s):\n`);
for (const f of findings) {
  console.error(`  [${f.kind}] ${TARGET}${f.line ? `:${f.line}` : ''}`);
  console.error(`      ${f.detail}`);
  console.error(`      ${f.text.slice(0, 150)}`);
  console.error(`      FIX: ${f.fix}\n`);
}
console.error('A sentence that names some of a set must name all of it, and a version');
console.error('number written here goes stale silently. Set membership is derived from');
console.error('release-map.json and the vector files, so nothing needs updating twice.\n');
process.exit(1);
