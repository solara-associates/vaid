// Capabilities VERIFICATION check — proves docs/capabilities.json matches reality,
// not merely that copies of it agree (that is the separate drift check).
//
// Rules (see docs/adr/0002-capabilities-manifest.md):
//  - status "shipped" with a package version  -> that version MUST be published on
//    its registry (crates.io / PyPI / npm). Fail if not.
//  - status "shipped" with no published package -> MUST carry a repo_ref (a file
//    path that exists, or a merged PR). Fail if it does not resolve.
//  - status "roadmap"/"planned" blocked on a PR -> that PR MUST still be OPEN. A
//    capability blocked on a MERGED/closed PR is a status that should have flipped.
//  - blocked_on {type:"decision"} has no automated check (human-owned) — reported.
//
// Fails LOUDLY on any mismatch, and fails CLOSED on network failure (never passes
// without verifying). Same posture as the conformance-vector checks.
//
// Run: node scripts/verify-capabilities.mjs   (also wired into CI)

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const UA = { 'User-Agent': 'solara-vaid-capabilities-check' };
const MANIFEST = new URL('../docs/capabilities.json', import.meta.url);
const REPO_ROOT = new URL('../', import.meta.url);

const failures = [];
const notes = [];
const fail = (id, msg) => failures.push(`  ✗ [${id}] ${msg}`);

// Fetch that fails CLOSED: a thrown error or an unexpected status is a hard failure
// for the caller, never a silent pass.
async function fetchStatus(url) {
  let res;
  try {
    res = await fetch(url, { headers: UA });
  } catch (e) {
    throw new Error(`network error fetching ${url}: ${e.message}`);
  }
  return res.status;
}

async function registryPublished(reg, pkg, version) {
  const url =
    reg === 'crates.io' ? `https://crates.io/api/v1/crates/${pkg}/${version}`
    : reg === 'pypi'     ? `https://pypi.org/pypi/${pkg}/${version}/json`
    : reg === 'npm'      ? `https://registry.npmjs.org/${pkg}/${version}`
    : null;
  if (!url) throw new Error(`unknown registry '${reg}'`);
  const s = await fetchStatus(url);
  if (s === 200) return true;
  if (s === 404) return false;
  // Any other status (5xx, rate-limit, redirect) — cannot confirm -> fail closed.
  throw new Error(`unexpected HTTP ${s} from ${reg} for ${pkg}@${version}`);
}

async function prState(repo, number) {
  let res;
  try {
    res = await fetch(`https://api.github.com/repos/${repo}/pulls/${number}`, {
      headers: { ...UA, Accept: 'application/vnd.github+json' },
    });
  } catch (e) {
    throw new Error(`network error fetching PR ${repo}#${number}: ${e.message}`);
  }
  if (res.status !== 200) throw new Error(`unexpected HTTP ${res.status} for PR ${repo}#${number}`);
  const j = await res.json();
  return { state: j.state, merged: Boolean(j.merged_at) };
}

const manifest = JSON.parse(readFileSync(MANIFEST));

for (const cap of manifest.capabilities) {
  const id = cap.id;
  try {
    if (cap.status === 'shipped') {
      const versioned = (cap.packages || []).filter((p) => p.version);
      if (versioned.length > 0) {
        for (const p of versioned) {
          const ok = await registryPublished(p.registry, p.package, p.version);
          if (!ok) fail(id, `claims shipped, but ${p.package}@${p.version} is NOT published on ${p.registry}`);
        }
      } else if (cap.repo_ref) {
        if (cap.repo_ref.path) {
          if (!existsSync(fileURLToPath(new URL(cap.repo_ref.path, REPO_ROOT))))
            fail(id, `shipped repo_ref path does not exist: ${cap.repo_ref.path}`);
        } else if (cap.repo_ref.pr) {
          const { merged } = await prState(cap.repo_ref.pr.repo, cap.repo_ref.pr.number);
          if (!merged) fail(id, `shipped, but repo_ref PR #${cap.repo_ref.pr.number} is not merged`);
        } else {
          fail(id, `shipped repo_ref must have a path or pr`);
        }
      } else {
        fail(id, `status shipped but no published package version and no repo_ref to verify`);
      }
    } else if (cap.status === 'roadmap' || cap.status === 'planned') {
      const b = cap.blocked_on;
      if (b && b.type === 'pr') {
        const { state, merged } = await prState(b.repo, b.number);
        if (merged || state !== 'open')
          fail(id, `status ${cap.status} blocked on ${b.repo}#${b.number}, but that PR is ${merged ? 'MERGED' : state} — status should have flipped`);
      } else if (b && b.type === 'decision') {
        notes.push(`  · [${id}] ${cap.status}, blocked on decision: ${b.ref} (human-owned; no automated check)`);
      } else {
        notes.push(`  · [${id}] ${cap.status} with no verifiable blocker`);
      }
    } else {
      fail(id, `unknown status '${cap.status}'`);
    }
  } catch (e) {
    // Fail CLOSED: an inability to verify is a failure, not a pass.
    fail(id, `could not verify (failing closed): ${e.message}`);
  }
}

if (notes.length) console.log('Notes:\n' + notes.join('\n'));

if (failures.length) {
  console.error(`\n✗ CAPABILITIES VERIFICATION FAILED — the manifest does not match reality:\n${failures.join('\n')}\n`);
  process.exit(1);
}
console.log(`\n✓ capabilities.json verified against reality — ${manifest.capabilities.length} capabilities, all consistent.`);
