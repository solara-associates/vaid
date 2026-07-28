// Claims-register FRESHNESS check — proves each prose claim in
// docs/claims-register.json has been verified recently ENOUGH, and that a set
// verification date is actually backed by evidence.
//
// This checks FRESHNESS, not TRUTH. It does not re-run any conformance harness or
// re-prove a claim; it asserts only that someone/something verified it, recorded
// who and with what artifact, and did so within the allowed window. Truth remains
// a human review item at release (see docs/adr/0002-capabilities-manifest.md). A
// green run means "the claim's verification is fresh and backed," not "the claim
// is true".
//
// Policy (see ADR-0002):
//  - date_last_verified missing/null                 -> FAIL (an unverified claim
//    in the register is unsupported; a null that passes silently is the very hole
//    the register exists to close).
//  - date set but `verifier` or `verified_artifact` empty -> FAIL (a date with no
//    backing is worse than null).
//  - age >= FAIL budget (default 90 days, or per-claim `max_age_days`) -> FAIL.
//  - age >= WARN budget (two-thirds of the FAIL budget; 60 for the default) -> WARN.
//  - otherwise OK.
//
// Fails LOUDLY and fails CLOSED: an unreadable/unparseable register, a malformed
// date, or a malformed override is a hard failure, never a silent pass. Same
// posture as verify-capabilities.mjs.
//
// Run: node scripts/verify-claims.mjs   (also wired into CI)

import { readFileSync } from 'node:fs';

const REGISTER = new URL('../docs/claims-register.json', import.meta.url);

const DEFAULT_FAIL_DAYS = 90;
const WARN_FRACTION = 2 / 3; // WARN budget = two-thirds of the FAIL budget (60 at 90)
const DAY_MS = 86_400_000;

const failures = [];
const warnings = [];
const oks = [];
const fail = (id, msg) => failures.push(`  ✗ [${id}] ${msg}`);
const warn = (id, msg) => warnings.push(`  ! [${id}] ${msg}`);

// UTC midnight "today" so the age is a whole-day count independent of runner TZ.
const now = new Date();
const todayUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());

// Strict YYYY-MM-DD -> UTC-midnight epoch; anything else throws (fail closed).
function parseDate(id, s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s))
    throw new Error(`date_last_verified is not a YYYY-MM-DD string: ${JSON.stringify(s)}`);
  const [y, m, d] = s.split('-').map(Number);
  const t = Date.UTC(y, m - 1, d);
  const back = new Date(t);
  if (back.getUTCFullYear() !== y || back.getUTCMonth() !== m - 1 || back.getUTCDate() !== d)
    throw new Error(`date_last_verified is not a real calendar date: ${s}`);
  return t;
}

let register;
try {
  register = JSON.parse(readFileSync(REGISTER));
} catch (e) {
  console.error(`\n✗ CLAIMS FRESHNESS CHECK FAILED — cannot read/parse claims-register.json (failing closed): ${e.message}\n`);
  process.exit(1);
}

for (const claim of register.claims || []) {
  const id = claim.id || '(no id)';
  try {
    // per-claim FAIL budget override, validated
    let failDays = DEFAULT_FAIL_DAYS;
    if (claim.max_age_days !== undefined) {
      if (typeof claim.max_age_days !== 'number' || !Number.isFinite(claim.max_age_days) || claim.max_age_days <= 0)
        throw new Error(`max_age_days override must be a positive number, got ${JSON.stringify(claim.max_age_days)}`);
      failDays = claim.max_age_days;
    }
    const warnDays = Math.round(failDays * WARN_FRACTION);

    // null / missing date is a hard fail — no silent pass.
    if (claim.date_last_verified === null || claim.date_last_verified === undefined) {
      fail(id, `date_last_verified is null — claim is in the register but never verified (unsupported)`);
      continue;
    }

    // a set date must be backed by who verified it and with what.
    const backingMissing = [];
    if (typeof claim.verifier !== 'string' || claim.verifier.trim() === '') backingMissing.push('verifier');
    if (typeof claim.verified_artifact !== 'string' || claim.verified_artifact.trim() === '') backingMissing.push('verified_artifact');
    if (backingMissing.length)
      fail(id, `date_last_verified is set but ${backingMissing.join(' and ')} ${backingMissing.length > 1 ? 'are' : 'is'} empty — a date with no backing is worse than null`);

    const t = parseDate(id, claim.date_last_verified);
    const ageDays = Math.floor((todayUTC - t) / DAY_MS);

    if (ageDays >= failDays) {
      fail(id, `stale: last verified ${claim.date_last_verified} (${ageDays}d ago) ≥ FAIL budget ${failDays}d — re-verify`);
    } else if (ageDays >= warnDays) {
      warn(id, `ageing: last verified ${claim.date_last_verified} (${ageDays}d ago) ≥ WARN ${warnDays}d, < FAIL ${failDays}d`);
    } else if (backingMissing.length === 0) {
      oks.push(`  ✓ [${id}] fresh: verified ${claim.date_last_verified} (${ageDays}d ago), within ${warnDays}d`);
    }
  } catch (e) {
    // Fail CLOSED: inability to evaluate is a failure, not a pass.
    fail(id, `could not evaluate (failing closed): ${e.message}`);
  }
}

if (oks.length) console.log(oks.join('\n'));
if (warnings.length) console.warn(`\nWarnings (ageing, not yet failing):\n${warnings.join('\n')}`);

if (failures.length) {
  console.error(`\n✗ CLAIMS FRESHNESS CHECK FAILED:\n${failures.join('\n')}\n`);
  process.exit(1);
}
console.log(`\n✓ claims-register.json freshness verified — ${(register.claims || []).length} claim(s), all fresh and backed.`);
