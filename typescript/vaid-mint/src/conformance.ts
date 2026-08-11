/**
 * Packaged cross-language mint conformance check — the firewall, shipped in the
 * tarball. TypeScript mirror of `vaid_mint.conformance` (Python) and the Rust
 * `tests/mint_conformance.rs` gate.
 *
 * A consumer who has only `npm install vaid-mint` can prove the mint they
 * installed reproduces the frozen cross-language VAID-document vector
 * byte-for-byte:
 *
 * ```console
 * $ npx vaid-mint-conformance      # exit 0 = PASS, 1 = BLOCKER
 * ```
 *
 * Two vectors are bundled with the package and both are checked:
 *
 * - `vectors/mint_v1.json` — the signed VAID document.
 * - `vectors/mint_pop_v1.json` — the `MintPopPayload` a holder signs to prove it
 *   controls the BYO key it registers at mint. Frozen later than the others: it
 *   was the one signed structure with no artifact holding the implementations to
 *   it (`docs/spec/encoding.md` E.11), and it is the only vector carrying a JSON
 *   `null` (E.7).
 *
 * The Rust and Python gates assert the identical vectors; a repo-level drift check
 * proves every copy is byte-identical, so Rust output == Python output ==
 * TypeScript output == vector.
 *
 * Per Decision B this proves self-consistency WITHIN this repo, NOT conformance
 * against the managed authority's VAID format.
 */

import { readdirSync, readFileSync } from 'node:fs';

import {
  canonicalize,
  canonicalizeToString,
  canonicalRequestSigningBytes,
  ed25519PublicKey,
  ed25519Sign,
  ed25519Verify,
  fromHex,
  numbersToBytes,
  sha256,
  toHex,
  verifySignedPayload,
} from 'vaid-pop';

import {
  canonicalVaidSigningBytes,
  computeLineageHash,
  SCOPE_SEPARATORS,
  scopeContains,
  type Vaid,
} from './document.js';
import {
  canonicalAttestationSigningBytes,
  verifyAttestationAuthenticity,
  type ConsentAttestation,
} from './attestation.js';
import { PresentedBundle, verifyChain } from './chain.js';
import { scopeAttenuatesWithin } from './mint.js';
import { RevocationStatus } from './revocation.js';
import {
  isVerdictValid,
  VaidVerdict,
  verifyVaidStandingFromJson,
} from './verify.js';
import { buildMintPopPayload, type MintPopPayload } from './mintTypes.js';
import { verifyVaidAuthenticity } from './verify.js';

/** A cross-language byte-identity divergence — a hard BLOCKER. */
export class ConformanceError extends Error {
  override readonly name = 'ConformanceError';
}

/** The shape of the frozen mint vector, as far as these checks read it. */
export interface MintVector {
  digest_sha256_hex: string;
  ed25519: {
    kernel_private_key_seed_hex: string;
    kernel_public_key_hex: string;
    signature_hex: string;
  };
  /** A real UNSIGNED VAID document (snake_case), with `kernel_signature` empty. */
  input: Vaid;
}

/** The shape of the frozen mint-PoP vector, as far as these checks read it. */
export interface MintPopVector {
  digest_sha256_hex: string;
  ed25519: {
    private_key_seed_hex: string;
    public_key_hex: string;
    signature_hex: string;
  };
  /** A real camelCase `MintPopPayload`. */
  input: MintPopPayload;
}

/** One hop of the frozen chain vector. */
export interface ChainVectorEntry {
  _role: string;
  digest_sha256_hex: string;
  signature_hex: string;
  document: Vaid;
}

/** `chain_v1.json` — the frozen chain presentation and its expected walk. */
export interface ChainVector {
  digest_sha256_hex: string;
  ed25519: {
    kernel_private_key_seed_hex: string;
    kernel_public_key_hex: string;
    kernel_key_thumbprint: string;
  };
  chain: ChainVectorEntry[];
  expected: { _comment?: string; assembled_lineage: string[]; verification: string };
}

/** `attestation_v1.json` — the frozen consent attestation. */
export interface AttestationVector {
  digest_sha256_hex: string;
  signature_hex: string;
  ed25519: { kernel_private_key_seed_hex: string; kernel_public_key_hex: string };
  attestation: ConsentAttestation;
}

// `../vectors` resolves to the package's vectors/ directory from both `src/`
// (running from source) and `dist/` (installed).
function loadVectorFile<T>(name: string): T {
  return JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), 'utf8')) as T;
}

/** The mint conformance vector bundled with the installed package. */
export function loadVector(): MintVector {
  return loadVectorFile<MintVector>('mint_v1.json');
}

/** The mint proof-of-possession vector bundled with the installed package. */
export function loadMintPopVector(): MintPopVector {
  return loadVectorFile<MintPopVector>('mint_pop_v1.json');
}

function assertHex(label: string, got: string, want: string): void {
  if (got !== want) {
    throw new ConformanceError(
      `${label} diverged from the frozen vector — BLOCKER\n  got    = ${got}\n  vector = ${want}`,
    );
  }
}

/**
 * JCS (with `kernel_signature` nulled) + SHA-256 over the VAID document == the
 * frozen digest.
 */
export function checkDocumentDigest(v: MintVector): void {
  const digest = canonicalVaidSigningBytes(v.input);
  assertHex('TypeScript VAID-document digest', toHex(digest), v.digest_sha256_hex);
  if (digest.length !== 32) {
    throw new ConformanceError(`digest must be 32 bytes, got ${digest.length}`);
  }
}

/**
 * From the frozen kernel seed, the kernel derives the frozen public key and signs
 * the digest to the frozen signature byte-for-byte.
 */
export function checkKernelSignature(v: MintVector): void {
  const seed = fromHex(v.ed25519.kernel_private_key_seed_hex);
  assertHex('kernel public key', toHex(ed25519PublicKey(seed)), v.ed25519.kernel_public_key_hex);

  const signature = ed25519Sign(canonicalVaidSigningBytes(v.input), seed);
  assertHex('TypeScript kernel signature', toHex(signature), v.ed25519.signature_hex);
  if (signature.length !== 64) {
    throw new ConformanceError(`signature must be 64 bytes, got ${signature.length}`);
  }
}

/**
 * The derived `lineage_hash` in the document equals
 * `computeLineageHash(parent_vaid, agent_id)` — proves the derivation, not just a
 * stored field.
 */
export function checkLineageHash(v: MintVector): void {
  const recomputed = computeLineageHash(v.input.parent_vaid, v.input.agent_id);
  assertHex('recomputed lineage_hash', recomputed, v.input.lineage_hash);
}

/** `vaid_id` is derived from `agent_id` — the same UUID. */
export function checkVaidIdEqualsAgentId(v: MintVector): void {
  if (v.input.vaid_id !== v.input.agent_id) {
    throw new ConformanceError(
      `vaid_id must equal agent_id — BLOCKER\n  vaid_id  = ${v.input.vaid_id}\n  agent_id = ${v.input.agent_id}`,
    );
  }
}

/**
 * The frozen signed document verifies against the frozen kernel PUBLIC key
 * alone — the surface a third party actually holds. The digest and signature
 * checks above prove the signer; this proves the verifier agrees with it.
 */
export function checkPublicKeyOnlyVerification(v: MintVector): void {
  const signed: Vaid = {
    ...v.input,
    kernel_signature: Array.from(fromHex(v.ed25519.signature_hex)),
  };
  if (!verifyVaidAuthenticity(fromHex(v.ed25519.kernel_public_key_hex), signed)) {
    throw new ConformanceError(
      'the frozen mint vector does not verify under its kernel public key alone — BLOCKER',
    );
  }
}

/**
 * The `MintPopPayload` gate (`docs/spec/encoding.md` E.11).
 *
 * Rebuilds the payload through {@link buildMintPopPayload} — the single
 * constructor both holder and mint use — rather than reading `input` back, so this
 * proves the code path that actually runs at mint emits these bytes, not merely
 * that an object round-trips.
 *
 * Also asserts the two properties this vector exists to pin: `parentVaid` is a
 * PRESENT JSON `null` (E.7 — an omitted key is a different key set and a different
 * digest), and the signature verifies against the key the payload REGISTERS, which
 * is the whole semantic content of proof-of-possession.
 */
export function checkMintPop(v: MintPopVector): void {
  const seed = fromHex(v.ed25519.private_key_seed_hex);
  const registered = ed25519PublicKey(seed);
  assertHex('holder public key', toHex(registered), v.ed25519.public_key_hex);

  const payload = buildMintPopPayload(
    {
      agentClass: 'runner',
      version: '1.0.0',
      tenantId: 'aifactory',
      parentVaid: null,
      scopeBoundary: ['data.aifactory'],
      capabilitySet: ['read'],
      publicKeyDer: registered,
    },
    {
      publicKeyDer: registered,
      nonce: '0123456789abcdef0123456789abcdef',
      issuedAt: '2026-06-04T12:00:00Z',
    },
  );
  // Compare CANONICALLY, not with JSON.stringify: key order is exactly what JCS
  // makes irrelevant, and the frozen vector's keys are sorted while a constructor
  // emits declaration order. An order-sensitive comparison here would report a
  // divergence that does not exist — and, worse, could be "fixed" by reordering
  // the struct, which changes nothing about the bytes.
  const canonicalPayload = canonicalizeToString(payload);
  if (canonicalPayload !== canonicalizeToString(v.input)) {
    throw new ConformanceError(
      "the mint's own PoP payload constructor diverged from the frozen vector — BLOCKER\n" +
        `  got    = ${canonicalPayload}\n  vector = ${canonicalizeToString(v.input)}`,
    );
  }

  // E.7: a present null, not an omitted key.
  if (!('parentVaid' in v.input) || v.input.parentVaid !== null) {
    throw new ConformanceError(
      'parentVaid must be a PRESENT JSON null in this vector — encoding.md E.7',
    );
  }
  const { parentVaid: _omitted, ...without } = v.input;
  if (toHex(canonicalRequestSigningBytes(without)) === v.digest_sha256_hex) {
    throw new ConformanceError(
      'omitting parentVaid MUST change the digest — otherwise E.7 is untested',
    );
  }

  const digest = canonicalRequestSigningBytes(payload);
  assertHex('TypeScript mint-PoP digest', toHex(digest), v.digest_sha256_hex);
  assertHex('TypeScript mint-PoP signature', toHex(ed25519Sign(digest, seed)), v.ed25519.signature_hex);

  // The PoP semantic: it must verify against the key it REGISTERS.
  const signature = fromHex(v.ed25519.signature_hex);
  if (!verifySignedPayload(payload, Uint8Array.from(payload.publicKeyDer), signature)) {
    throw new ConformanceError(
      'the frozen PoP must verify against the registered key — BLOCKER',
    );
  }
  if (verifySignedPayload({ ...payload, capabilitySet: ['read', 'write'] }, registered, signature)) {
    throw new ConformanceError(
      'a captured PoP must not be replayable to mint a higher-privilege VAID',
    );
  }
}

/** `chain_v1.json` — the WALK: per-hop digests and signatures, the contract digest
 * over the whole frozen chain, and the verdict a third party reaches. */
export function checkChain(v: ChainVector): void {
  const seed = fromHex(v.ed25519.kernel_private_key_seed_hex);

  for (const entry of v.chain) {
    const digest = canonicalVaidSigningBytes(entry.document);
    assertHex(`chain hop ${entry._role} digest`, toHex(digest), entry.digest_sha256_hex);
    assertHex(
      `chain hop ${entry._role} signature`,
      toHex(ed25519Sign(digest, seed)),
      entry.signature_hex,
    );
  }

  const { _comment: _dropped, ...expected } = v.expected;
  void _dropped; // prose is documentation, not contract
  assertHex(
    'chain contract digest',
    toHex(sha256(canonicalize({ chain: v.chain, expected }))),
    v.digest_sha256_hex,
  );

  const docs = v.chain.map((e) => ({
    ...e.document,
    kernel_signature: Array.from(fromHex(e.signature_hex)),
  }));
  const verdict = verifyChain(
    fromHex(v.ed25519.kernel_public_key_hex),
    docs[docs.length - 1]!,
    new PresentedBundle(docs),
  );
  if (verdict !== v.expected.verification) {
    throw new ConformanceError(
      `chain verdict '${verdict}' != frozen '${v.expected.verification}' — the ` +
        'installed verifier disagrees with the frozen walk',
    );
  }
}

/** `attestation_v1.json` — canonicalization, signature, and that the frozen
 * signature verifies as authentic. */
export function checkAttestation(v: AttestationVector): void {
  const digest = canonicalAttestationSigningBytes(v.attestation);
  assertHex('attestation digest', toHex(digest), v.digest_sha256_hex);

  const seed = fromHex(v.ed25519.kernel_private_key_seed_hex);
  assertHex('attestation signature', toHex(ed25519Sign(digest, seed)), v.signature_hex);

  const signed = {
    ...v.attestation,
    signature: Array.from(fromHex(v.signature_hex)),
  };
  if (!verifyAttestationAuthenticity(fromHex(v.ed25519.kernel_public_key_hex), signed)) {
    throw new ConformanceError('the frozen attestation must verify as authentic');
  }
}

/** A round-trip verification vector: signed documents plus expected verdicts. */
interface RoundtripVector {
  ed25519: { kernel_public_key_hex: string };
  cases: { name: string; why: string; document: Record<string, unknown>; expected_valid: boolean }[];
}

/**
 * Check the round-trip verification vector (ADR-0006).
 *
 * Verify-only: it pins a VERDICT OVER GIVEN BYTES rather than bytes over a given
 * input, which is the only shape that catches cross-implementation disagreement.
 * It also asserts the vector still DISCRIMINATES — a dropping implementation must
 * fail it in both directions — so it cannot decay into cases every implementation
 * passes regardless of behaviour.
 */
export function checkRoundtrip(v: RoundtripVector): void {
  if (v.cases.length === 0) throw new ConformanceError('roundtrip vector carries no cases');
  const pub = fromHex(v.ed25519.kernel_public_key_hex);
  for (const c of v.cases) {
    const got = ed25519Verify(
      numbersToBytes(c.document.kernel_signature as number[]),
      canonicalVaidSigningBytes(c.document as never),
      pub,
    );
    if (got !== c.expected_valid) {
      throw new ConformanceError(
        `roundtrip case "${c.name}": got ${got}, expected ${c.expected_valid} — ${c.why}`,
      );
    }
    // The requirement behind the verdict: canonicalization must be a function of
    // the input, so parsing and re-serializing must reproduce what was presented.
    const back = JSON.parse(JSON.stringify(c.document));
    if (JSON.stringify(Object.keys(back).sort()) !== JSON.stringify(Object.keys(c.document).sort())) {
      throw new ConformanceError(`roundtrip case "${c.name}" did not round-trip its key set`);
    }
  }
  let falseNegative = false;
  let falseAccept = false;
  for (const c of v.cases) {
    const dropped: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(c.document)) if (!k.startsWith('x_')) dropped[k] = val;
    const got = ed25519Verify(
      numbersToBytes(c.document.kernel_signature as number[]),
      sha256(canonicalize({ ...dropped, kernel_signature: null })),
      pub,
    );
    if (got !== c.expected_valid) {
      if (c.expected_valid) falseNegative = true;
      else falseAccept = true;
    }
  }
  if (!falseNegative || !falseAccept) {
    throw new ConformanceError(
      'the roundtrip vector no longer catches a dropping implementation in both ' +
        'directions — its discriminating power has been weakened',
    );
  }
}

/** A scope-containment vector: a predicate table, with no digest and no signature. */
interface ScopeVector {
  rule: { separators: string[] };
  cases: { boundary: string[]; resource: string; expected: boolean; why: string }[];
}

/**
 * Check the scope-containment vector (spec S.3, ADR-0005).
 *
 * The only checker here that verifies a PREDICATE rather than bytes. Containment
 * is computed over a document and never appears inside one, so there is no digest
 * to reproduce and no signature to re-derive — what must agree across languages is
 * the verdict on every case.
 *
 * It also asserts the vector still disagrees with bare prefix matching in at least
 * five places. Without that, a future edit could quietly reduce the vector to cases
 * both rules accept, leaving a green firewall that no longer covers the
 * sibling-capture bug the vector exists for.
 */
export function checkScope(v: ScopeVector): void {
  if (v.cases.length === 0) {
    throw new ConformanceError('scope vector carries no cases');
  }
  for (const c of v.cases) {
    const got = scopeContains(c.boundary, c.resource);
    if (got !== c.expected) {
      throw new ConformanceError(
        `scope containment mismatch: boundary=${JSON.stringify(c.boundary)} ` +
          `resource=${JSON.stringify(c.resource)} expected=${c.expected} got=${got} — ${c.why}`,
      );
    }
  }
  if (!v.cases.some((c) => c.expected) || !v.cases.some((c) => !c.expected)) {
    throw new ConformanceError('scope vector must exercise both outcomes');
  }
  const disagreements = v.cases.filter(
    (c) =>
      c.boundary.length > 0 &&
      c.boundary.some((s) => c.resource.startsWith(s)) !== c.expected,
  ).length;
  if (disagreements < 5) {
    throw new ConformanceError(
      `scope vector must pin the sibling-capture regression class; only ${disagreements} ` +
        'case(s) disagree with bare prefix matching',
    );
  }
  const declared = [...SCOPE_SEPARATORS];
  if (JSON.stringify(declared) !== JSON.stringify(v.rule.separators)) {
    throw new ConformanceError(
      `separator set mismatch: implementation ${JSON.stringify(declared)} != ` +
        `vector ${JSON.stringify(v.rule.separators)}`,
    );
  }
}

/** A graded-verdict vector: predicate cases over two surfaces, no digest. */
interface VerdictVector {
  reasons: { standing: string[]; attenuation: string[] };
  ed25519: { kernel_public_key_hex: string };
  cases: {
    name: string;
    why: string;
    surface: 'standing' | 'attenuation';
    document_json?: string;
    revocation?: string;
    parent_scope?: string[];
    child_scope?: string[];
    expected_valid: boolean;
    expected_reason: string;
  }[];
}

/**
 * Check the negative-path vector (`verdict_v1.json`).
 *
 * The other checkers here ask "does the installed mint produce the same bytes as
 * everyone else". This one asks "does it REFUSE the same way, and say the same
 * thing about why". The happy-path vectors cannot answer that: they only ever
 * exercise documents that work.
 *
 * It asserts the REASON, not just the boolean. Three implementations that reject
 * the same document for three different reasons agree on every boolean and
 * disagree about what happened — and an `npm install` consumer whose build
 * disagrees with the vector on a reason has a mint that will log, alert and retry
 * differently from every other deployment.
 *
 * It also refuses to pass a vector that has lost its teeth: no positive control on
 * either surface, a single refusal reason across every negative case, or a
 * vocabulary that has drifted from {@link VaidVerdict} are all BLOCKERs. A green
 * firewall over a vector that asserts nothing is the masked-green defect this
 * package keeps finding.
 */
export function checkVerdict(v: VerdictVector): void {
  if (!v.cases || v.cases.length === 0) {
    throw new ConformanceError('verdict vector carries no cases');
  }
  const kernelPk = Uint8Array.from(
    (v.ed25519.kernel_public_key_hex.match(/../g) ?? []).map((h) => parseInt(h, 16)),
  );
  const revocationStates: Record<string, RevocationStatus> = {
    not_revoked: RevocationStatus.NotRevoked,
    revoked: RevocationStatus.Revoked,
    unavailable: RevocationStatus.Unavailable,
  };

  const positives: Record<string, number> = { standing: 0, attenuation: 0 };
  const negatives: Record<string, number> = { standing: 0, attenuation: 0 };
  const refusalReasons = new Set<string>();
  const exercised = new Set<string>();

  for (const c of v.cases) {
    let reason: string;
    let valid: boolean;
    if (c.surface === 'standing') {
      if (typeof c.document_json !== 'string') {
        throw new ConformanceError(`standing case "${c.name}" has no document_json`);
      }
      const state = revocationStates[c.revocation ?? ''];
      if (state === undefined) {
        throw new ConformanceError(
          `standing case "${c.name}" names unknown revocation state ${JSON.stringify(c.revocation)}`,
        );
      }
      const verdict = verifyVaidStandingFromJson(kernelPk, c.document_json, state);
      reason = verdict;
      valid = isVerdictValid(verdict);
    } else if (c.surface === 'attenuation') {
      const ok = scopeAttenuatesWithin(c.parent_scope ?? [], c.child_scope ?? []);
      reason = ok ? 'attenuated' : 'scope_escalation';
      valid = ok;
    } else {
      throw new ConformanceError(
        `verdict case "${c.name}" names unknown surface ${JSON.stringify(c.surface)}`,
      );
    }

    if (reason !== c.expected_reason) {
      throw new ConformanceError(
        `verdict case "${c.name}": reason "${reason}" != frozen "${c.expected_reason}" — ` +
          `${c.why}\n  A reason mismatch is a divergence even where the boolean agrees: ` +
          'this build and the vector disagree about WHAT HAPPENED.',
      );
    }
    if (valid !== c.expected_valid) {
      throw new ConformanceError(
        `verdict case "${c.name}": valid=${valid}, frozen ${c.expected_valid} — ${c.why}`,
      );
    }

    if (c.expected_valid) positives[c.surface]! += 1;
    else {
      negatives[c.surface]! += 1;
      refusalReasons.add(reason);
    }
    exercised.add(c.expected_reason);
  }

  // The vector must still have teeth. Each of these is a way it could be edited
  // into something that passes for every implementation regardless of behaviour.
  if (positives.standing === 0 || positives.attenuation === 0) {
    throw new ConformanceError(
      'the verdict vector has lost a positive control (standing and attenuation each ' +
        'need one) — an implementation that refused every input would pass it',
    );
  }
  if (negatives.standing === 0 || negatives.attenuation === 0) {
    throw new ConformanceError(
      'the verdict vector has lost a negative case on one of its surfaces — an ' +
        'implementation that accepted every input would pass it',
    );
  }
  if (refusalReasons.size < 2) {
    throw new ConformanceError(
      `every refusing case expects the same reason (${JSON.stringify([...refusalReasons])}) — ` +
        'a boolean-only implementation would pass this vector, so the reason assertions ' +
        'would be checking nothing',
    );
  }

  // Vocabulary agreement, both directions: a reason the vector declares that this
  // build cannot return means the vector was written against a different
  // implementation; a verdict this build can return that the vector never names is
  // a state shipping unchecked.
  const declared = new Set(v.reasons.standing);
  const implemented = new Set<string>(Object.values(VaidVerdict));
  const onlyVector = [...declared].filter((r) => !implemented.has(r));
  const onlyImpl = [...implemented].filter((r) => !declared.has(r));
  if (onlyVector.length > 0 || onlyImpl.length > 0) {
    throw new ConformanceError(
      "the verdict vector's standing vocabulary and this build's VaidVerdict disagree\n" +
        `  only in the vector:         ${JSON.stringify(onlyVector)}\n` +
        `  only in the implementation: ${JSON.stringify(onlyImpl)}`,
    );
  }
  const allDeclared = [...declared, ...v.reasons.attenuation];
  const unexercised = allDeclared.filter((r) => !exercised.has(r));
  if (unexercised.length > 0) {
    throw new ConformanceError(
      `reason(s) declared by the vector but exercised by no case: ${JSON.stringify(unexercised)} ` +
        '— a state with no case behind it is a claim with no evidence',
    );
  }
}

/**
 * Every vector this firewall knows how to check, by filename.
 *
 * The firewall ENUMERATES what actually ships and dispatches through this table
 * rather than naming a fixed set, and it fails in BOTH directions — see
 * {@link run}. Adding a vector to the package without adding it here is a hard
 * failure, by design.
 */
export const VECTOR_CHECKS: Record<string, (v: never) => void> = {
  'mint_v1.json': (v: MintVector) => {
    checkDocumentDigest(v);
    checkKernelSignature(v);
    checkLineageHash(v);
    checkVaidIdEqualsAgentId(v);
    checkPublicKeyOnlyVerification(v);
  },
  'mint_pop_v1.json': (v: MintPopVector) => checkMintPop(v),
  'chain_v1.json': (v: ChainVector) => checkChain(v),
  'attestation_v1.json': (v: AttestationVector) => checkAttestation(v),
  'scope_v1.json': (v: ScopeVector) => checkScope(v),
  'roundtrip_v1.json': (v: RoundtripVector) => checkRoundtrip(v),
  'verdict_v1.json': (v: VerdictVector) => checkVerdict(v),
} as Record<string, (v: never) => void>;

/**
 * Every `.json` vector actually present in the INSTALLED package.
 *
 * Read from the package rather than from a list in this file: a list is what
 * silently stops matching reality.
 */
export function bundledVectorNames(): string[] {
  const dir = new URL('../vectors/', import.meta.url);
  return readdirSync(dir)
    .filter((n) => n.endsWith('.json'))
    .sort();
}

/**
 * Run the firewall over every vector the installed package ships.
 *
 * Fails in BOTH directions, because each direction hides a different defect:
 *
 * - a vector PRESENT in the package with no entry in {@link VECTOR_CHECKS} is a
 *   hard failure. This is the defect that motivated the change: the firewall named
 *   a fixed set, so a release whose entire purpose was a new vector passed a check
 *   that never looked at it. Silence there is indistinguishable from coverage.
 * - a vector NAMED in {@link VECTOR_CHECKS} but ABSENT from the package is also a
 *   hard failure — a checker that quietly checks nothing is the same masked-green
 *   defect wearing the other hat.
 *
 * It cannot verify a vector nobody has written a checker for; nothing can. What it
 * guarantees is that such a vector cannot ship *quietly* — the firewall goes red
 * until someone says what the vector means.
 */
export function run(): Record<string, VectorSummary> {
  const present = bundledVectorNames();
  const known = Object.keys(VECTOR_CHECKS).sort();

  const unchecked = present.filter((n) => !known.includes(n));
  if (unchecked.length > 0) {
    throw new ConformanceError(
      `vector(s) ship in this package but no firewall check covers them: ${unchecked.join(', ')}` +
        ' — add a checker to VECTOR_CHECKS. A shipped-but-unchecked vector makes a' +
        ' PASS mean less than it appears to.',
    );
  }

  const missing = known.filter((n) => !present.includes(n));
  if (missing.length > 0) {
    throw new ConformanceError(
      `firewall expects vector(s) that are not in this package: ${missing.join(', ')}` +
        ' — the packaging dropped them, or the check is stale.',
    );
  }

  const results: Record<string, VectorSummary> = {};
  for (const name of present) {
    const vector = loadVectorFile<VectorSummary>(name);
    VECTOR_CHECKS[name]!(vector as never);
    results[name] = vector;
  }
  return results;
}

/**
 * What a vector reports about itself in the firewall's output.
 *
 * `digest_sha256_hex` is optional because not every vector pins bytes: a
 * predicate vector (`scope_v1.json`) pins verdicts, and has nothing to digest.
 * Reporting it as an empty digest would read as a missing value rather than an
 * inapplicable one.
 */
interface VectorSummary {
  digest_sha256_hex?: string;
  cases?: unknown[];
}

/** One output line's worth of evidence that this vector was actually checked. */
function describeVector(v: VectorSummary): string {
  if (v.digest_sha256_hex !== undefined) return v.digest_sha256_hex;
  if (v.cases !== undefined) return `${v.cases.length} case(s) — predicate vector, no digest`;
  return 'checked';
}

export function main(): number {
  let result: Record<string, VectorSummary>;
  try {
    result = run();
  } catch (error) {
    console.error(
      `CROSS-LANGUAGE MINT FIREWALL: MISMATCH — BLOCKER\n${(error as Error).message}`,
    );
    return 1;
  }
  const names = Object.keys(result).sort();
  console.log(
    `CROSS-LANGUAGE MINT FIREWALL: PASS — installed mint == ${names.length} frozen ` +
      'vector(s), byte-for-byte',
  );
  // Every vector is named with its digest. The COUNT is the point: a release that
  // adds a vector visibly adds a line here, so "did the firewall look at the thing
  // this release was about" is answerable from the output alone.
  for (const name of names) {
    console.log(`  ${name.padEnd(22)} ${describeVector(result[name]!)}`);
  }
  return 0;
}
