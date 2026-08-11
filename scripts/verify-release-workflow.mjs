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

// 6. Packaging a workspace member requires an install FIRST, in the same job.
//
// THE DEFECT THIS EXISTS TO CATCH (BACKLOG B12)
//
// `npm publish` and `npm publish --dry-run` both PACKAGE the package, and packaging
// runs its `prepublishOnly`. For every package under `typescript/` that is
// `npm run build && npm test`, which needs `node_modules` to exist and needs the
// workspace siblings BUILT — `vaid-mint` reads `vaid-pop`'s type declarations out of
// `dist/`, so a symlink alone is not enough.
//
// Neither job installed anything. The 0.7.0 npm release died at preflight on
// `Cannot find module 'vaid-pop'` and `Cannot find name 'process'`, having compiled
// the package against an empty tree.
//
// It stayed hidden because `vaid-skill` — the only npm package this workflow had
// ever published — lives outside the workspace and has no compile step in its
// publish path. The workflow was proven on the case that needs none of this and
// generalised without being re-proven.
//
// WHAT IS ASSERTED: in any job that packages, an install must appear, and appear
// BEFORE the first packaging step. Order is the whole point — an install after the
// pack is an install that ran too late, and it would satisfy a mere-presence check.
//
// BOUNDED HONESTLY: this cannot tell whether the install covers the right
// directory, only that packaging is preceded by one. That is the ordering error
// that actually occurred; a wrong `--prefix` is a different check.
{
  // A step's `- name:` is excluded on both sides. `- name: npm publish` is a
  // LABEL, not a command, and it necessarily precedes the `run:` block that
  // installs — so matching it made this check report that `publish` installs after
  // it packages, which is the opposite of what that job does. The same trap as the
  // comment-stripping above: something that MENTIONS a command is not the command.
  const isName = (l) => /^\s*-?\s*name:/.test(l);
  const packaging = (l) => /npm publish/.test(l) && !isName(l);
  const installing = (l) => /npm ci\b/.test(l) && !isName(l);
  for (const [job, jobLines] of jobs) {
    const packIdx = jobLines.findIndex(packaging);
    if (packIdx === -1) continue;
    const installIdx = jobLines.findIndex(installing);
    if (installIdx === -1) {
      problems.push(
        `job \`${job}\` packages (\`npm publish\`) without ever running \`npm ci\`. ` +
          'Packaging runs `prepublishOnly`, which for a workspace member compiles the ' +
          'package — with no `node_modules` it dies on a missing module, not on anything ' +
          'to do with publishing. See BACKLOG B12.',
      );
      continue;
    }
    if (installIdx > packIdx) {
      problems.push(
        `job \`${job}\` runs \`npm ci\` AFTER it packages. An install that follows the ` +
          'pack is an install that ran too late; the pack already compiled against an ' +
          'empty tree.',
      );
    }
  }
}

if (problems.length > 0) {
  console.error(`\n✗ RELEASE WORKFLOW STRUCTURE CHECK FAILED\n`);
  for (const p of problems) console.error(`  · ${p}\n`);
  process.exit(1);
}

console.log(`✓ ${FILE} — verify-artifact is checkout-free and proves the attestation;`);
console.log(`  the publish dry-run gate is in preflight only; every publishing job upgrades npm`);
console.log(`  and installs before it packages.`);
