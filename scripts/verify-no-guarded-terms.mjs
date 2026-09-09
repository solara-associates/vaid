#!/usr/bin/env node
//
// Guarded-term check: refuse a diff that ADDS a term from the estate's redaction
// list, without ever storing that list in this repository.
//
// WHY IT IS HASHED, AND NOT A GREP
// --------------------------------
// The estate holds a name-to-euphemism mapping at
// `_meta-solara docs/archive/purge-2026-08-23/syn-replacements.txt`. Nothing has
// ever consulted it, which is how `synthera-site-redesign` had a term reintroduced
// 48 hours after being purged. The obvious fix — commit that list and grep added
// lines against it — is unusable HERE, because this repository is PUBLIC: the list
// IS the exposure, and a mapping is strictly worse to publish than a bare mention.
// A plaintext checker would also match itself.
//
// So the list is committed as SALTED SHA-256 of normalised terms. This file
// tokenises added lines, builds 1..ngram_max n-grams, hashes each with the same
// salt, and compares. No term is ever present in this repository, in this script,
// in the config, or in the failure output.
//
// WHAT THIS IS AND IS NOT
// -----------------------
// The salt is COMMITTED, because a fork's pull request gets no secrets and a check
// that silently skips on the traffic it most needs to see is worse than none.
// A committed salt makes this OBFUSCATION, NOT SECRECY: anyone with this repo and a
// dictionary of first names and company names can brute-force the entries offline,
// cheaply. That is accepted. The threat model is US reintroducing a name by
// accident — the ICP document, the untracked draft, the pasted paragraph — not an
// adversary trying to recover the list. It buys: the list is not readable, not
// greppable, and not indexable, and the check cannot match itself.
//
// FAILURE OUTPUT NAMES THE FILE AND LINE AND NEVER THE TERM. If it printed the
// match, the CI log of a PUBLIC repository would publish exactly what the check
// exists to keep out — a finding recorded in the medium it describes.
//
// Usage:  node scripts/verify-no-guarded-terms.mjs <base-ref>
// Exits 0 if no added line contains a guarded term, 1 otherwise, 2 on a
// self-check failure (see below).

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

const CONFIG = '.github/name-guard/terms.sha256.json';

const cfg = JSON.parse(readFileSync(CONFIG, 'utf8'));
if (cfg.algorithm !== 'sha256') {
  console.error(`FATAL: unsupported algorithm ${cfg.algorithm}`);
  process.exit(2);
}
const NGRAM_MAX = cfg.ngram_max ?? 3;
const ENTRIES = new Set(cfg.entries);

const hash = (s) =>
  createHash('sha256').update(cfg.salt, 'hex').update(' ').update(s, 'utf8').digest('hex');

const normalizeTokens = (line) =>
  line.normalize('NFKD').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);

// Every 1..NGRAM_MAX contiguous n-gram of a line, joined by single spaces.
// Punctuation is a token boundary, not a character, which is what makes a term
// reachable from the same entry when it appears hyphenated ("<term>-facing"),
// inside an address ("<term>@example.com"), or in a slug. Deliberately NO example
// is spelled out here: an earlier draft of this comment used a real term as the
// illustration, and this check caught it on its own first run.
function* ngrams(tokens) {
  for (let n = 1; n <= NGRAM_MAX; n++) {
    for (let i = 0; i + n <= tokens.length; i++) {
      yield [n, tokens.slice(i, i + n).join(' ')];
    }
  }
}

// SELF-CHECK — the positive control, shipped inside the change.
//
// An empty result from this script is indistinguishable from a script that scanned
// nothing: a base ref that resolved to HEAD, a diff filtered down to zero lines, a
// config that parsed to zero entries. Every one of those exits 0 and prints
// nothing, which reads as PASSED. So before trusting the silence, prove the
// instrument fires: synthesise a line whose hash IS a known entry and confirm the
// matcher catches it, and confirm a control line does not.
//
// It cannot use a real term (that would put one in this file), so it proves the
// MECHANISM against a synthetic entry it constructs itself: a positive that must
// fire at the right n-gram width, and a control line that must not fire at all.
{
  if (ENTRIES.size === 0) {
    console.error(`FATAL: ${CONFIG} has zero entries — the check would pass vacuously.`);
    process.exit(2);
  }
  // The matcher must fire on a hash it is given, and must not fire otherwise.
  // Verified against a SYNTHETIC entry so that no guarded term appears here.
  const synthetic = 'zzselfcheckzz probe token';
  const tmp = new Set([hash(synthetic)]);
  const hits = [...ngrams(normalizeTokens(`prefix ${synthetic} suffix`))].filter(([, g]) =>
    tmp.has(hash(g))
  );
  if (hits.length !== 1 || hits[0][0] !== 3) {
    console.error('FATAL: self-check failed - the n-gram matcher did not fire on a known hash.');
    console.error('       Refusing to report a clean result from an unproved instrument.');
    process.exit(2);
  }
  const negative = [...ngrams(normalizeTokens('an ordinary sentence with no probe'))].filter(
    ([, g]) => tmp.has(hash(g))
  );
  if (negative.length !== 0) {
    console.error('FATAL: self-check failed - the matcher fired on a control line.');
    process.exit(2);
  }
}

const baseRef = process.argv[2];
if (!baseRef) {
  console.error('usage: node scripts/verify-no-guarded-terms.mjs <base-ref>');
  process.exit(2);
}

let mergeBase;
try {
  mergeBase = execFileSync('git', ['merge-base', baseRef, 'HEAD'], { encoding: 'utf8' }).trim();
} catch {
  console.error(`FATAL: cannot resolve a merge base with ${baseRef}.`);
  console.error('       The workflow needs fetch-depth: 0 and the base ref fetched.');
  process.exit(2);
}

if (mergeBase === execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim()) {
  console.log(`No commits ahead of ${baseRef} (merge base is HEAD). Nothing added to scan.`);
  process.exit(0);
}

// --unified=0 so only genuinely added lines appear, not context.
const diff = execFileSync(
  'git',
  ['diff', '--unified=0', '--no-color', '--no-renames', `${mergeBase}..HEAD`],
  { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }
);

let file = null;
let lineNo = 0;
let scannedLines = 0;
const findings = [];

for (const raw of diff.split('\n')) {
  if (raw.startsWith('+++ b/')) {
    file = raw.slice(6);
    continue;
  }
  if (raw.startsWith('+++ /dev/null')) {
    file = null;
    continue;
  }
  const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
  if (hunk) {
    lineNo = Number(hunk[1]);
    continue;
  }
  if (!raw.startsWith('+') || raw.startsWith('+++')) continue;
  if (file === null) continue;

  const content = raw.slice(1);
  scannedLines++;
  const seen = new Set();
  for (const [n, gram] of ngrams(normalizeTokens(content))) {
    const h = hash(gram);
    if (ENTRIES.has(h) && !seen.has(h)) {
      seen.add(h);
      // id is a prefix of a hash already published in the config: it identifies
      // WHICH entry matched, for the fixer, without disclosing WHAT matched.
      findings.push({ file, line: lineNo, n, id: h.slice(0, 12) });
    }
  }
  lineNo++;
}

console.log(`Scanned ${scannedLines} added line(s) against ${ENTRIES.size} guarded entries.`);

if (findings.length === 0) {
  console.log('OK: no added line contains a guarded term.');
  process.exit(0);
}

console.error('');
console.error(`FAIL: ${findings.length} added line(s) contain a guarded term.`);
console.error('');
console.error('The term is deliberately NOT printed. This repository is public and its');
console.error('workflow logs are public, so naming the match here would publish exactly');
console.error('what this check exists to keep out.');
console.error('');
for (const f of findings) {
  console.error(`  ${f.file}:${f.line}  guarded term (n=${f.n}, entry ${f.id})`);
}
console.error('');
console.error('To resolve: open each line above and replace the client, prospect, partner');
console.error('or employer name on it with the role. The mapping is the RHS of');
console.error('`docs/archive/purge-2026-08-23/syn-replacements.txt` in the private');
console.error('`solara` (_meta-solara) repository. Do not add the term to any allowlist,');
console.error('and do not paste the term into the pull request while asking about it.');
console.error('');
console.error('Background: docs/findings/the-refs-a-rewrite-cannot-reach-and-the-two-');
console.error('attestations-that-bind-it.md, same repository.');
process.exit(1);
