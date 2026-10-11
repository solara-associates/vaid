#!/usr/bin/env node
/**
 * The verdicts this implementation returns for an UNRECOGNISED scope-boundary
 * kind, as JSON, for cross-language comparison (spec S.10, ADR-0009).
 *
 * Mirror of the Rust `emit_unknown_scope_kind_verdict` example and the Python
 * `emit_unknown_scope_kind_verdict.py`; `scripts/unknown_scope_kind_agreement.sh`
 * runs all three and diffs the output. See the Rust example for why this exists as
 * well as the per-language vector assertions.
 *
 * Run from `typescript/vaid-mint`, after `npm run build`:
 *
 *     node scripts/emit-unknown-scope-kind-verdict.mjs
 */

import { readFileSync } from 'node:fs';

import { scopeAttenuationReason } from '../dist/mint.js';
import { RevocationStatus } from '../dist/revocation.js';
import { verifyVaidStandingFromJson, isVerdictValid } from '../dist/verify.js';

const vector = (name) =>
  JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8'));

const verdict = vector('verdict_v1.json');
const kinds = vector('scope_kinds_v1.json');
const kernelPk = Uint8Array.from(
  verdict.ed25519.kernel_public_key_hex.match(/../g).map((b) => parseInt(b, 16)),
);

// The STANDING surface: an authentic, unexpired, unrevoked document whose boundary
// names a kind no v4 verifier recognises.
const standing = [];
for (const c of verdict.cases) {
  if (c.expected_reason !== 'unknown_scope_kind') continue;
  if (c.document_json === undefined) continue;
  const got = verifyVaidStandingFromJson(kernelPk, c.document_json, RevocationStatus.NotRevoked);
  standing.push({ case: c.name, reason: got, valid: isVerdictValid(got) });
}

// The ATTENUATION surface: an unreadable kind on either side of a hop.
const attenuation = [];
for (const c of kinds.attenuation_cases) {
  if (c.expected_reason !== 'unknown_scope_kind') continue;
  attenuation.push({
    case: c.name,
    reason: scopeAttenuationReason(c.parent_scope, c.child_scope),
  });
}

// A refusal over zero inputs is not a reading. Asserted here rather than only in
// the shell script, so an emitter that silently found nothing cannot be diffed
// against another that also found nothing and report agreement.
if (standing.length === 0) {
  throw new Error('verdict_v1.json carries no unknown_scope_kind standing case');
}
if (attenuation.length === 0) {
  throw new Error('scope_kinds_v1.json carries no unknown_scope_kind attenuation case');
}

// Keys sorted, matching the other two emitters, so a diff shows a verdict
// difference rather than a serializer difference.
const sortKeys = (value) =>
  Array.isArray(value)
    ? value.map(sortKeys)
    : value && typeof value === 'object'
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((k) => [k, sortKeys(value[k])]),
        )
      : value;

process.stdout.write(
  `${JSON.stringify(
    sortKeys({
      surface: 'unknown scope kind (spec S.10, ADR-0009)',
      standing,
      attenuation,
    }),
    null,
    2,
  )}\n`,
);
