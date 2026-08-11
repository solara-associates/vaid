/**
 * Structural invariants of `release.yml` that a step landing in the wrong job
 * would silently break.
 *
 * ## The bug this exists for
 *
 * The `npm publish --dry-run` preflight step was inserted by an edit whose anchor
 * (`- name: Set up Python`) appears in THREE jobs, and the edit was not bounded to
 * the first match. So the step was added to `preflight` (correct), `publish`
 * (harmless but pointless) and `verify-artifact` (fatal).
 *
 * `verify-artifact` deliberately does not check out the repository — it verifies
 * the PUBLISHED artifact from a clean consumer install, which is the whole point of
 * the job. So `cd skill` failed with `No such file or directory`, the job died on
 * its first step, and **every real verification in it was skipped**: the consumer
 * install, the declared verify command, and `npm audit signatures`.
 *
 * The release still published. What was lost was the proof that what published is
 * any good — and `release-complete` reported a partial release, correctly, without
 * being able to say which half was missing.
 *
 * ## The invariants
 *
 *   1. `verify-artifact` MUST NOT check out the repository. Verifying the published
 *      artifact against the repo it came from proves nothing about what a consumer
 *      receives, which is the one thing that job is for.
 *   2. Consequently, no step in `verify-artifact` may reference a repo path
 *      (`$DIR`, `$WS`, `./crates`, `./skill`, …). Such a reference is either dead
 *      or a step that belongs in another job.
 *   3. The `npm publish --dry-run` gate belongs in `preflight` exactly once —
 *      before anything is permanent, mirroring `cargo publish --dry-run`.
 *   4. Every job that runs `npm publish` (real or dry-run) must first install an
 *      npm new enough for trusted publishing, or it fails ENEEDAUTH in a way that
 *      reads as a missing secret.
 *
 * Run: node scripts/verify-release-workflow.mjs
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FILE = '.github/workflows/release.yml';
const raw = readFileSync(join(ROOT, FILE), 'utf8');
const lines = raw.split('\n');

/**
 * Steps grouped by job, without a YAML dependency.
 *
 * Scoped to AFTER the top-level `jobs:` key — `on: push:` is also a 2-space key,
 * and treating it as a job put workflow triggers in the same namespace as real
 * jobs. Comment lines are stripped, because a comment MENTIONING a command is not
 * the command: `# ... why \`npm publish --prefix\` reached production` made this
 * check report that verify-artifact publishes.
 */
const jobs = new Map();
{
  let job = null;
  let inJobs = false;
  for (const line of lines) {
    if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
    if (!inJobs) continue;
    if (/^[a-z]/.test(line)) break; // a new top-level key ends the jobs block
    const m = line.match(/^  ([a-z][a-z0-9-]*):\s*$/);
    if (m) {
      job = m[1];
      jobs.set(job, []);
      continue;
    }
    if (job && !/^\s*#/.test(line)) jobs.get(job).push(line);
  }
}

const problems = [];
const body = (j) => (jobs.get(j) ?? []).join('\n');

// 1 + 2. verify-artifact is a CONSUMER. It has no repo and must not act like it.
if (!jobs.has('verify-artifact')) {
  problems.push('no `verify-artifact` job — the published artifact is verified by nobody');
} else {
  const v = body('verify-artifact');
  if (/uses:\s*actions\/checkout/.test(v)) {
    problems.push(
      'verify-artifact checks out the repository. It must verify the PUBLISHED artifact from a clean ' +
        'install; checking it against the repo it was built from proves nothing a consumer cares about.',
    );
  }
  for (const ref of ['$DIR', '${DIR}', '$WS', '${WS}']) {
    if (v.includes(ref)) {
      problems.push(
        `verify-artifact references ${ref}, a path in the checkout it does not have. ` +
          'That step either belongs in another job or is dead — this is exactly how the dry-run step ' +
          'landed here and killed the job before any verification ran.',
      );
    }
  }
  if (!/npm audit signatures/.test(v)) {
    problems.push('verify-artifact does not run `npm audit signatures` — the attestation would be assumed rather than proven');
  }
}

// 3. release-complete is only a gate if it runs when an upstream job did not.
if (!jobs.has('release-complete')) {
  problems.push('no `release-complete` job — a partial release would report no failure at all');
} else {
  const rc = body('release-complete');
  if (!/if:\s*always\(\)/.test(rc)) {
    problems.push(
      '`release-complete` lacks `if: always()`. Without it the job is SKIPPED whenever an upstream job ' +
        'fails or is cancelled — so the exact runs it exists to catch are the runs it does not run on, ' +
        'and a release that published without verifying would report no failure.',
    );
  }
  if (!/release-outcome\.mjs/.test(rc)) {
    problems.push('`release-complete` does not run release-outcome.mjs — it would report that something failed without saying whether the artifact is live or whether anything checked it');
  }
  for (const need of ['resolve', 'preflight', 'publish', 'verify-artifact']) {
    if (!new RegExp(`${need}=\\$\\{\\{\\s*needs\\.${need}\\.result`).test(rc)) {
      problems.push(`\`release-complete\` does not pass ${need}'s result to the reporter — that stage's outcome would be invisible in the summary`);
    }
  }
}

// 4. The dry-run gate belongs in preflight, exactly once.
const dryRunJobs = [...jobs.keys()].filter((j) => body(j).includes('npm publish --dry-run'));
if (dryRunJobs.length !== 1 || dryRunJobs[0] !== 'preflight') {
  problems.push(
    `\`npm publish --dry-run\` should appear in \`preflight\` and nowhere else; found in: ${dryRunJobs.join(', ') || '(nowhere)'}. ` +
      'Before anything is permanent is the only place it is worth anything.',
  );
}

// 4b. The dry-run PACKS the package, which runs its prepack lifecycle (`npm run
// build && npm test` for every workspace member here). If nothing has installed
// node_modules by then, `tsc` cannot resolve a sibling workspace package or
// @types/node, and the dry-run fails with "Cannot find module 'vaid-pop'" — a
// message that reads as a defect in the package rather than as a missing install.
//
// npm-vaid-mint-v0.7.0 failed exactly this way, in `preflight`. It had never fired
// before because vaid-skill, the only package previously released here, is
// standalone and installs its own dependencies inside its own step; vaid-mint is
// the first workspace member to go through, and workspace members are precisely
// the ones whose build needs a sibling. Ordering, not presence, is the invariant —
// both steps existed, in the wrong order.
//
// Checked in EVERY job that packages, not just the one that failed. `publish`
// already installs before `npm publish` and always has, so it is currently
// correct — but only by nobody having reordered it, which is exactly the state
// `preflight` was in until a tag proved otherwise. An invariant that covers only
// the job that has already broken cannot stop the same defect appearing in the
// job that has not.
for (const j of [...jobs.keys()]) {
  // Step NAMES must not count. `- name: npm publish` sorts before the `npm ci`
  // inside that same step's script, which reported the publish job as broken when
  // it is correct. What is being ordered is commands, not labels — so compare only
  // the lines that run something.
  const b = (jobs.get(j) ?? []).filter((l) => !/^\s*-?\s*name:/.test(l)).join('\n');
  // `npm publish --dry-run` contains `npm publish`, so match packaging generally.
  const iPack = b.search(/npm publish/);
  if (iPack < 0) continue;
  const iInstall = b.search(/npm ci --prefix/);
  const label = b.includes('npm publish --dry-run') ? 'npm publish --dry-run' : 'npm publish';
  if (iInstall < 0) {
    problems.push(
      `job \`${j}\` runs \`${label}\` but never runs \`npm ci\` — packaging runs the package's ` +
        'prepack build against node_modules that do not exist, so it fails on unresolvable sibling ' +
        "packages and @types/node. A workspace member's build needs a built sibling, not just a linked one.",
    );
  } else if (iInstall > iPack) {
    problems.push(
      `job \`${j}\` installs the npm workspace AFTER \`${label}\`. Packaging runs the prepack build ` +
        'first, so it fails on unresolvable sibling packages and @types/node. Both steps are present ' +
        'and the order is the bug — move the install above it.',
    );
  }
}

// 5. Anything that publishes needs an npm that can do OIDC.
for (const j of [...jobs.keys()]) {
  const b = body(j);
  if (!/npm publish/.test(b)) continue;
  if (!/npm install -g npm@/.test(b)) {
    problems.push(
      `job \`${j}\` runs \`npm publish\` without first installing an npm new enough for trusted publishing. ` +
        'The runner ships npm 10, which has no OIDC support and fails ENEEDAUTH — a message that reads as a missing secret.',
    );
  }
}

if (problems.length > 0) {
  console.error(`\n✗ RELEASE WORKFLOW STRUCTURE CHECK FAILED\n`);
  for (const p of problems) console.error(`  · ${p}\n`);
  process.exit(1);
}

console.log(`✓ ${FILE} — verify-artifact is checkout-free and proves the attestation;`);
console.log(`  the publish dry-run gate is in preflight only; every publishing job upgrades npm.`);
