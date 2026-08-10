/**
 * What actually happened in this release, stated so nobody has to work it out.
 *
 * ## Why this replaced four lines of bash
 *
 * `release-complete` used to loop over the job results and `exit 1` on the FIRST
 * one that was not `success`. That is correct — it fails a partial release — and it
 * is close to useless at the moment you need it, because the only question anyone
 * has when a release goes red is:
 *
 *   **Is the artifact on the registry, and did anything verify it?**
 *
 * The old output could not answer either half. It named one failed stage, stopped,
 * and printed a generic "if publish succeeded the version is burned — check the
 * registry by hand". On 2026-08-10 that cost twenty minutes of not knowing whether
 * a published `vaid-skill` 0.1.3 had been verified. It had not: `verify-artifact`
 * died on its first step and skipped the consumer install, the declared verify
 * command and `npm audit signatures`, while the package sat live on npm.
 *
 * ## What it does now
 *
 * 1. Reports **every** stage, not just the first bad one.
 * 2. **Asks the registry** whether the version is actually published, rather than
 *    inferring it from a job result. Reading state beats reading exit codes: a
 *    `publish` job can fail after the upload succeeds, and a `success` can precede
 *    a registry that has not caught up.
 * 3. Names the outcome as one of four operationally distinct states, and says what
 *    was NOT proven in each — because "partial" is not an instruction.
 *
 * The states, and what each one asks of a human:
 *
 *   RELEASED     everything ran. Nothing to do.
 *   UNVERIFIED   the artifact IS on the registry and nothing checked it. The
 *                dangerous one: the version is burned, so it cannot be re-tagged,
 *                and it is live for consumers while unproven. Verify it by hand,
 *                now, and decide whether to deprecate.
 *   NOT-RELEASED nothing reached the registry. The version is NOT burned; fix and
 *                re-tag. This is the safe failure and should be visibly distinct.
 *   UNKNOWN      the registry could not be reached. Fails closed and says which
 *                question is unanswered, rather than guessing either way.
 *
 * Run standalone (used by release.yml, and testable):
 *   node scripts/release-outcome.mjs --eco npm --pkg vaid-skill --version 0.1.3 \
 *     --results "resolve=success preflight=success publish=success verify-artifact=failure"
 */

const arg = (name, fallback = '') => {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};

const ECO = arg('eco');
const PKG = arg('pkg');
const VERSION = arg('version');
const REF = arg('ref', '(no ref)');
const RESULTS = arg('results');
/** Skip the network in tests; the registry answer is then supplied directly. */
const FORCE_PUBLISHED = arg('force-published');

const stages = RESULTS.trim()
  .split(/\s+/)
  .filter(Boolean)
  .map((kv) => {
    const [name, result] = kv.split('=');
    return { name, result };
  });

if (stages.length === 0) {
  console.error('::error::release-outcome: no --results given; cannot report an outcome.');
  process.exit(1);
}

const by = (n) => stages.find((s) => s.name === n)?.result ?? 'missing';
const failed = stages.filter((s) => s.result !== 'success');

/** What each stage would have established, so its absence can be named. */
const ESTABLISHES = {
  resolve: 'which package and version this tag refers to',
  preflight: 'that the manifest matches the tag, the package is self-consistent, the conformance suites pass, and the package can even be packaged',
  publish: 'that the artifact reached the registry',
  'verify-artifact': 'that the PUBLISHED artifact installs cleanly, passes its declared consumer check, and carries a provenance attestation',
};

// ── is it actually on the registry? ──────────────────────────────────────────
const REGISTRY = {
  npm: (p, v) => `https://registry.npmjs.org/${p}/${v}`,
  rust: (p, v) => `https://crates.io/api/v1/crates/${p}/${v}`,
  python: (p, v) => `https://pypi.org/pypi/${p}/${v}/json`,
};

async function isPublished() {
  if (FORCE_PUBLISHED === 'yes') return true;
  if (FORCE_PUBLISHED === 'no') return false;
  const url = REGISTRY[ECO]?.(PKG, VERSION);
  if (!url) return null;
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'vaid-release-outcome' } });
    if (res.status === 200) return true;
    if (res.status === 404) return false;
    return null;
  } catch {
    return null;
  }
}

const published = await isPublished();

// ── report ───────────────────────────────────────────────────────────────────
const line = (s = '') => console.log(s);
line();
line(`  release ${REF}`);
line(`  package ${PKG} ${VERSION} (${ECO})`);
line();
line('  stage             result');
for (const s of stages) {
  const mark = s.result === 'success' ? '✓' : s.result === 'skipped' ? '·' : '✗';
  line(`   ${mark} ${s.name.padEnd(16)} ${s.result}`);
}
line();
line(
  `  registry          ${
    published === true
      ? `${PKG}@${VERSION} IS PUBLISHED`
      : published === false
        ? `${PKG}@${VERSION} is NOT on the registry`
        : 'COULD NOT BE REACHED'
  }`,
);
line();

if (failed.length === 0 && published === true) {
  line(`  RELEASED — published and verified from a clean install.`);
  process.exit(0);
}

// Everything below is a failure; the question is which kind.
const notEstablished = failed.map((s) => `      · ${s.name} (${s.result}) — did not establish ${ESTABLISHES[s.name] ?? 'its stage'}`);

const err = (m) => console.error(m);

if (published === null) {
  err(`::error::UNKNOWN — the ${ECO} registry could not be reached, so whether ${PKG}@${VERSION} is live is UNANSWERED.`);
  err(`::error::Do not re-tag until you have checked by hand. Re-tagging a version that did publish cannot work; the number is spent.`);
  err(`::error::Not established by this run:`);
  notEstablished.forEach(err);
  process.exit(1);
}

if (published === true && by('verify-artifact') !== 'success') {
  err(`::error::UNVERIFIED RELEASE — ${PKG}@${VERSION} IS LIVE ON THE REGISTRY AND NOTHING CHECKED IT.`);
  err(`::error::This is the state that needs a human now, not later. The version is burned: it cannot be un-published or re-tagged.`);
  err(`::error::Consumers can install it. Nothing has established that what they get is correct.`);
  err(`::error::Not established by this run:`);
  notEstablished.forEach(err);
  err(`::error::Do this: install ${PKG}@${VERSION} into an empty directory, run its declared check from release-map.json, and run \`npm audit signatures\` (npm) to confirm the attestation. If it does not hold up, deprecate the version.`);
  process.exit(1);
}

if (published === true) {
  err(`::error::PARTIAL RELEASE — ${PKG}@${VERSION} is live and verified, but a stage did not succeed.`);
  err(`::error::The artifact is on the registry; the version is burned and cannot be re-tagged.`);
  notEstablished.forEach(err);
  process.exit(1);
}

err(`::error::NOT RELEASED — ${PKG}@${VERSION} never reached the registry. This is the SAFE failure.`);
err(`::error::The version is NOT burned. Fix the cause below, then re-tag the same version.`);
err(`::error::Not established by this run:`);
notEstablished.forEach(err);
process.exit(1);
