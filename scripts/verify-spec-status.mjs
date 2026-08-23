/**
 * Does the specification still describe this implementation?
 *
 * It stopped, in the one section whose whole job is to say so, and nothing
 * noticed for four weeks and five minor versions.
 *
 * `docs/spec/revocation.md` R.6 "Implementation status" is a two-column table
 * headed by version numbers, one of them marked "(current)". It read
 * "0.1.2 (current) | 0.2 (planned)" while `crates/vaid-mint` was at 0.7.0, and
 * stated in bold that the shipped seam did not satisfy R.4 — for a seam that had
 * been replaced at 0.2.0 — with deployment advice for a version nobody could
 * install. Every word of it was true on 2026-07-27. That is the whole problem.
 *
 * ## Why this drifted when capabilities.json cannot
 *
 * This repository publishes version-bearing status claims on two surfaces, and it
 * guarded exactly one of them:
 *
 *   docs/capabilities.json   TWO checks — a byte-match drift check across every
 *                            vendored copy, and verify-capabilities.mjs, which
 *                            fails when a `shipped` capability's version is not
 *                            published on its registry.
 *   docs/spec/*.md           None.
 *
 * So one surface could not go stale without turning a build red, and the other
 * could only go stale. That is not carelessness by whoever last edited R.6; it is
 * the predictable output of leaving a structured claim to human diligence because
 * it happens to be written in Markdown. The README has had its own guard since
 * check-readme-drift.mjs — which bans hardcoded versions outright. The spec cannot
 * take that rule, because historical statements ("until 0.5.0 no vector policed
 * it") are legitimate there and do not age. What ages is a claim about NOW.
 *
 * ## What this fails on
 *
 *   CURRENT   A version marked "(current)" in any docs/spec/*.md table header that
 *             does not match crates/vaid-mint/Cargo.toml. This is the instance
 *             that drifted, and the check is deliberately written against the
 *             MARKER rather than against R.6 by name: a "(current)" claim added to
 *             any future spec section is covered the day it is written, without
 *             anyone remembering to extend this file.
 *
 *   LANDED    A "landed in <package> <version>" claim in the spec that contradicts
 *             docs/capabilities.json. The manifest already records which release a
 *             capability shipped in and is itself registry-checked, so the spec is
 *             checked AGAINST it rather than being trusted alongside it.
 *
 * Neither rule bans version numbers from the spec. Historical claims are the point
 * of a spec's status section; they are also the only kind that stays true.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

const SPEC_DIR = 'docs/spec';
const MINT_MANIFEST = 'crates/vaid-mint/Cargo.toml';
const CAPABILITIES = 'docs/capabilities.json';

const failures = [];
let landedChecked = 0;

// The reference version. crates/vaid-mint is the source of truth for what the
// reference implementation IS; the registries are checked separately by
// verify-package-versions.mjs, so this check does not need the network.
const manifest = readFileSync(MINT_MANIFEST, 'utf8');
const mintVersion = manifest.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!mintVersion) {
  console.error(`FATAL: no version found in ${MINT_MANIFEST}`);
  process.exit(1);
}

const capabilities = JSON.parse(readFileSync(CAPABILITIES, 'utf8'));
// id -> the release a capability landed in, e.g. "vaid-mint 0.2.0".
const landedIn = new Map(
  capabilities.capabilities.filter((c) => c.landed_in).map((c) => [c.id, c.landed_in]),
);

const specFiles = readdirSync(SPEC_DIR).filter((f) => f.endsWith('.md'));

// Markdown prose here is hard-wrapped, so "landed in\n`vaid-mint` 0.2.0" is one
// claim split across two lines. Every rule below therefore scans the WHOLE file
// with \s+ between words and derives the line number from the match offset. A
// per-line regex would silently never fire on exactly the claims worth checking —
// a rule that cannot match is worse than no rule, because it reads as coverage.
const lineOf = (text, index) => text.slice(0, index).split('\n').length;
const excerpt = (text, index) => {
  const start = text.lastIndexOf('\n', index) + 1;
  const end = text.indexOf('\n', index);
  return text.slice(start, end === -1 ? undefined : end).trim();
};

for (const file of specFiles) {
  const path = join(SPEC_DIR, file);
  const text = readFileSync(path, 'utf8');

  // CURRENT — any "(current...)" marker attached to a version number. Matches
  // both "0.1.2 (current)" and "0.2 onward (current: 0.7.0)", taking the version
  // the marker actually asserts as current in each case.
  const CURRENT_RE = /(\d+\.\d+(?:\.\d+)?)\s*\(current\)|\(current:\s*(\d+\.\d+(?:\.\d+)?)\s*\)/g;
  for (const m of text.matchAll(CURRENT_RE)) {
    const claimed = m[1] ?? m[2];
    if (claimed !== mintVersion) {
      failures.push(
        `CURRENT  ${path}:${lineOf(text, m.index)}\n` +
          `         spec claims current version ${claimed}, ${MINT_MANIFEST} says ${mintVersion}\n` +
          `         ${excerpt(text, m.index)}`,
      );
    }
  }

  // LANDED — "landed in vaid-mint 0.2.0" style claims, checked against the
  // manifest that already knows the answer and is itself registry-checked.
  const LANDED_RE = /landed\s+in\s+`?(vaid-[a-z]+)`?\s+(\d+\.\d+(?:\.\d+)?)/gi;
  for (const m of text.matchAll(LANDED_RE)) {
    const [, pkg, version] = m;
    const claim = `${pkg} ${version}`;
    const known = [...new Set(landedIn.values())].filter((v) => v.startsWith(`${pkg} `)).sort();
    if (known.length && !known.includes(claim)) {
      failures.push(
        `LANDED   ${path}:${lineOf(text, m.index)}\n` +
          `         spec says "${claim}"; ${CAPABILITIES} records ${known.join(', ')} for ${pkg}\n` +
          `         ${excerpt(text, m.index)}`,
      );
    }
    landedChecked += 1;
  }
}

// A rule that matched nothing is not a passing rule, it is an absent one. The
// spec is expected to carry at least one "landed in <package> <version>" claim;
// if it stops, this check has quietly lost its second half and should say so.
if (landedChecked === 0) {
  console.error(
    `\nFATAL: the LANDED rule matched no claims in ${SPEC_DIR}. Either the spec no\n` +
      `longer states which release a capability landed in, or the phrasing moved and\n` +
      `this rule no longer recognises it. Silent non-matching reads as coverage.\n`,
  );
  process.exit(1);
}

if (failures.length) {
  console.error(
    `\nSpecification status claims disagree with the implementation ` +
      `(${failures.length} ${failures.length === 1 ? 'claim' : 'claims'}):\n`,
  );
  for (const f of failures) console.error(`${f}\n`);
  console.error(
    `A version-bearing claim in the spec that is neither generated nor checked is a\n` +
      `claim with no owner. Update the claim, or drop the "(current)" marker if the\n` +
      `statement is historical — historical claims do not age and are not checked.\n`,
  );
  process.exit(1);
}

console.log(
  `Spec status claims OK — "(current)" markers across ${specFiles.length} spec ` +
    `file(s) agree with ${MINT_MANIFEST} (${mintVersion}), and ${landedChecked} ` +
    `"landed in" claim(s) agree with ${CAPABILITIES}.`,
);
