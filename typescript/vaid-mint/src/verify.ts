/**
 * Standalone, public-key-only verification of a VAID document. TypeScript mirror
 * of the Rust `vaid_mint::verify`.
 *
 * {@link ReferenceIssuer.verifyVaid} can only be called by a party holding a
 * `ReferenceIssuer`, and every issuer constructor needs the kernel **private**
 * key. An Ed25519 signature needs only the **public** key to verify, so this
 * module exposes what the issuer method trapped inside itself: a third party
 * holding just the issuer's kernel public key can confirm a VAID document is
 * authentic — no issuer instance, no private key.
 *
 * ## Scope: authenticity, not standing
 *
 * {@link verifyVaidAuthenticity} answers "was this document genuinely issued
 * under this key, and is it internally consistent" — the signature-scheme
 * version, the kernel Ed25519 signature over the canonical document, and the
 * consistency of `lineage_hash`. It deliberately does **not**:
 *
 * - check **expiry** — a temporal concern; call {@link isExpired} separately if
 *   the caller cares about validity now;
 * - consult **revocation** — this is the load-bearing decision. A resolver-less
 *   verifier answers authenticity; gating that on a lineage/revocation lookup the
 *   verifier cannot perform would make every third-party verification fail
 *   closed, rebuilding the R.4.2 problem in a new place. Revocation status is
 *   reported on a separate path ({@link ReferenceIssuer.revocationStatus}) or not
 *   at all here.
 */

import { ed25519Verify, numbersToBytes } from 'vaid-pop';
import { isValidTrustDomain, kernelKeyThumbprint } from './issuerIdentity.js';

import {
  canonicalVaidSigningBytes,
  computeLineageHash,
  isExpired,
  VAID_SIG_VERSION_V3,
  type Vaid,
} from './document.js';
import { RevocationStatus } from './revocation.js';

/**
 * Recompute `lineage_hash` from the document's own `parent_vaid` and `agent_id`
 * (via {@link computeLineageHash}) and compare. Catches an inconsistent
 * `lineage_hash` **explicitly**, rather than relying on it being incidentally
 * covered by the kernel signature — so a caller can check lineage integrity on
 * its own, and so a mint that signs a malformed `lineage_hash` is caught here.
 */
export function verifyLineageHash(vaid: Vaid): boolean {
  if (typeof vaid.agent_id !== 'string') return false;
  return computeLineageHash(vaid.parent_vaid ?? null, vaid.agent_id) === vaid.lineage_hash;
}

/**
 * Verify a VAID document's **authenticity** against an issuer's kernel **public**
 * key (raw 32-byte Ed25519). No issuer instance, no private key.
 *
 * This answers *authenticity* — "genuinely issued under this key, and internally
 * consistent" — **not** *standing* ("valid and unrevoked right now"). A `true`
 * result does not mean the VAID is currently usable; it means it is real.
 *
 * **Checks (all must hold for `true`):**
 * - the signature-scheme version is current;
 * - `lineage_hash` is internally consistent ({@link verifyLineageHash});
 * - the kernel Ed25519 signature is valid over the canonical document under
 *   `kernelPublicKey`.
 *
 * **Does NOT check — the caller must handle these separately:**
 * - **expiry** — call {@link isExpired}; an expired-but-signed VAID returns
 *   `true` here;
 * - **revocation** — evaluate a {@link RevocationCheck} (or, in the reference,
 *   {@link ReferenceIssuer.revocationStatus}) on a separate path. Revocation is
 *   deliberately *not* consulted here — see the module docs.
 *
 * A malformed key, a bad signature, or any tampered signed field is `false`,
 * never a throw.
 */
export function verifyVaidAuthenticity(kernelPublicKey: Uint8Array, vaid: Vaid): boolean {
  // Expressed in terms of the graded verdict rather than duplicating its
  // branches. Two parallel implementations of the same check are two things that
  // can drift; this way the boolean IS the graded verdict, read narrowly, and a
  // future edit cannot change one without changing the other.
  return isVerdictValid(verifyVaidAuthenticityGraded(kernelPublicKey, vaid));
}

/* ────────────────────────── the graded verdict ─────────────────────────── */

/**
 * Why a VAID was or was not honoured — the reason alongside the boolean. Mirror
 * of the Rust `vaid_mint::verify::VaidVerdict` and the Python `VaidVerdict`.
 *
 * ## Why a boolean was not enough
 *
 * `false` collapses "this document is forged" into "I could not reach a
 * revocation list". Both are refusals; only one is an accusation. A caller that
 * cannot tell them apart cannot log the difference, cannot alert on the
 * difference, and cannot retry the one that is worth retrying.
 *
 * ## Two rules inherited from decisions this repo has already made
 *
 * 1. **"I could not determine this" is its own state.** It is
 *    {@link VaidVerdict.Indeterminate}, and it is never folded into a negative.
 *    The same rule already governs {@link RevocationStatus.Unavailable}, the
 *    four-valued {@link ChainVerification}, and the packaged firewall's refusal to
 *    report PASS over zero vectors.
 * 2. **Fail closed on ambiguity.** {@link VaidVerdict.Indeterminate} is not valid:
 *    {@link isVerdictValid} is true for {@link VaidVerdict.Valid} and nothing
 *    else. Unavailable never reads as usable.
 *
 * ## Additive
 *
 * Nothing here changes an existing verdict or an existing signature.
 * {@link verifyVaidAuthenticity} keeps its exact signature and its exact
 * behaviour — it is now *defined as*
 * `isVerdictValid(verifyVaidAuthenticityGraded(..))`, the same function read
 * narrowly rather than a second copy of it.
 *
 * ## The states are the ones the vectors distinguish
 *
 * Each member is reachable by at least one case in `verdict_v1.json`. A state no
 * vector can produce would be a claim with no evidence behind it, so there are
 * none: candidates no case could separate were merged rather than kept for
 * symmetry with anyone else's list.
 *
 * The value of each member is its stable wire string — the vocabulary the vector
 * is written in, and the thing three implementations must agree on. Two
 * implementations that reject the same document for *different* reasons disagree
 * even though their booleans match, and that is only visible if the reason has a
 * name both of them spell the same way.
 */
export const VaidVerdict = {
  /**
   * Authentic, unexpired, and revocation was consulted and reported clean. The
   * only member for which {@link isVerdictValid} is true.
   */
  Valid: 'valid',
  /**
   * The bytes are not a VAID document: truncated, not JSON, a required member
   * absent, or a member of the wrong type. Nothing downstream was evaluated
   * because there was nothing to evaluate.
   */
  Unparseable: 'unparseable',
  /**
   * Parsed, but the signature-scheme discriminant is not the current one. A v2
   * document reaches this; so does a forged document with no `sig_version`.
   */
  UnsupportedSigVersion: 'unsupported_sig_version',
  /**
   * Parsed, but `trust_domain` is not a well-formed DNS-shaped name (ADR-0004).
   * The document names an issuer nobody can look up.
   */
  MalformedTrustDomain: 'malformed_trust_domain',
  /**
   * The document's `kernel_key_thumbprint` does not correspond to the key it is
   * being verified against — the v3 key-commitment check. This is the verdict for
   * a document signed by a non-kernel key that also rewrote the thumbprint to
   * match its own: the signature is internally consistent, and it is the *wrong
   * issuer*. Distinct from {@link VaidVerdict.Inauthentic}, which is the same
   * forgery that left the thumbprint alone.
   */
  IssuerMismatch: 'issuer_mismatch',
  /**
   * `lineage_hash` does not recompute from the document's own `parent_vaid` and
   * `agent_id`. Caught explicitly rather than incidentally via the signature, so
   * a document whose mint signed a malformed lineage is named as such.
   */
  LineageInconsistent: 'lineage_inconsistent',
  /**
   * The kernel signature does not verify over the presented bytes. Payload
   * tampered, signature tampered, or signed by a key that is not the one the
   * document commits to. This is the accusation; everything above it is a
   * structural complaint.
   */
  Inauthentic: 'inauthentic',
  /**
   * Authentic, and past `expires_at`. Checked *after* authenticity on purpose: a
   * forged expired document is {@link VaidVerdict.Inauthentic}, not
   * {@link VaidVerdict.Expired} — the more serious reason wins, because "expired"
   * invites a renewal that would hand a forger a fresh document.
   */
  Expired: 'expired',
  /** Authentic and unexpired, but some VAID in its lineage is revoked (R.4.4). */
  Revoked: 'revoked',
  /**
   * Standing could not be determined: the revocation store could not be
   * consulted, or the lineage could not be completely assembled. **Not** a
   * negative and **not** a positive — the third state, reported as itself. Fails
   * closed: {@link isVerdictValid} is false.
   */
  Indeterminate: 'indeterminate',
} as const;

export type VaidVerdict = (typeof VaidVerdict)[keyof typeof VaidVerdict];

/**
 * True for {@link VaidVerdict.Valid} alone.
 *
 * This is the fail-closed rule in one line: every other verdict, including
 * {@link VaidVerdict.Indeterminate}, is not usable. A caller that only wants the
 * boolean gets exactly the pre-existing behaviour.
 */
export function isVerdictValid(verdict: VaidVerdict): boolean {
  return verdict === VaidVerdict.Valid;
}

/**
 * Parse a wire string back to a verdict, or `null` if it names no known state.
 *
 * `null` rather than a fallback member: an unrecognised reason code is not a
 * verdict, and silently mapping it to one would let a vector naming a state this
 * build does not have report agreement it never established.
 */
export function verdictFromCode(code: string): VaidVerdict | null {
  const known = Object.values(VaidVerdict) as string[];
  return known.includes(code) ? (code as VaidVerdict) : null;
}

const isByteList = (v: unknown): boolean =>
  Array.isArray(v) && v.every((b) => typeof b === 'number' && Number.isInteger(b) && b >= 0 && b <= 255);

const isStringList = (v: unknown): boolean =>
  Array.isArray(v) && v.every((s) => typeof s === 'string');

const HEX8_4_4_4_12 = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
/**
 * The UUID spellings a VAID member may be *presented* in.
 *
 * Deliberately permissive, and deliberately matched to the other two: Rust's
 * `Uuid::parse_str` and Python's `uuid.UUID()` both accept the hyphenated, braced,
 * `urn:uuid:` and hyphenless forms in either case. A stricter grammar here would
 * mean TypeScript reporting UNPARSEABLE where the other two report INAUTHENTIC —
 * the same refusal for a different stated reason, which is exactly the divergence
 * class `verdict_v1.json` exists to catch.
 *
 * Accepting a non-canonical spelling is not the same as honouring it. The document
 * is canonicalized over the bytes as presented (ADR-0006 Req. 3), so a `vaid_id`
 * rewritten into an equivalent spelling after signing changes the signed bytes and
 * the signature fails. Parsing permissively and verifying strictly is what puts
 * that refusal on the signature, where it belongs and where it is the same in all
 * three, rather than on three separately-written grammars.
 */
const UUID_RE = new RegExp(
  `^(?:${HEX8_4_4_4_12}|\\{${HEX8_4_4_4_12}\\}|urn:uuid:${HEX8_4_4_4_12}|[0-9a-fA-F]{32})$`,
);
const isUuid = (v: unknown): boolean => typeof v === 'string' && UUID_RE.test(v);

/**
 * Does `json` contain a repeated member name inside any single object, at any
 * depth?
 *
 * **Why this is checked explicitly rather than left to the parser (spec E.7a,
 * BACKLOG B7).** The three languages disagree, silently. `serde` refuses a
 * repeated struct field; `JSON.parse` and `json.loads` both keep the LAST
 * occurrence and discard the earlier ones without a word. So
 * `{"sig_version": 3, "sig_version": 2}` was read as `2` here and declined
 * outright by Rust — one implementation refusing to parse a document the others
 * called authentic.
 *
 * Last-wins is the dangerous half. A signed document is a statement about a
 * specific byte string; silently choosing one of two competing values for a member
 * and verifying the result means the reader and the signer may disagree about what
 * was signed, with nothing in the verdict to indicate it. The safe direction is the
 * one that refuses.
 *
 * Scans the raw text because that is the only place the evidence survives — by the
 * time `JSON.parse` has returned, the duplicate is gone.
 */
export function hasDuplicateMemberNames(json: string): boolean {
  // One set of seen names per open object; `null` marks an open array, which has
  // no member names of its own but must still be tracked so that a string inside
  // it is never mistaken for a key.
  const stack: Array<Set<string> | null> = [];
  let i = 0;
  while (i < json.length) {
    const c = json[i]!;
    if (c === '{') {
      stack.push(new Set());
      i += 1;
    } else if (c === '[') {
      stack.push(null);
      i += 1;
    } else if (c === '}' || c === ']') {
      stack.pop();
      i += 1;
    } else if (c === '"') {
      const scanned = scanJsonString(json, i);
      // Unterminated string: not our error to report. Whatever parses this next
      // will refuse it, and claiming "duplicate" here would be the wrong reason.
      if (scanned === null) return false;
      const [text, next] = scanned;
      let j = next;
      while (j < json.length && /\s/.test(json[j]!)) j += 1;
      if (j < json.length && json[j] === ':') {
        const seen = stack[stack.length - 1];
        if (seen instanceof Set) {
          if (seen.has(text)) return true;
          seen.add(text);
        }
      }
      i = next;
    } else {
      i += 1;
    }
  }
  return false;
}

/**
 * Read a JSON string starting at `start` (the opening quote), returning its
 * decoded-enough text and the index just past the closing quote.
 *
 * "Decoded enough" means escapes are consumed so they cannot hide a quote, and
 * `\uXXXX` is left as written: two member names differing only by escaping are the
 * same name to a conforming parser, but treating them as different here can only
 * MISS a duplicate, never invent one — and missing leaves the existing parsers in
 * charge rather than overruling them.
 */
function scanJsonString(json: string, start: number): [string, number] | null {
  let out = '';
  let i = start + 1;
  while (i < json.length) {
    const c = json[i]!;
    if (c === '"') return [out, i + 1];
    if (c === '\\') {
      if (i + 1 >= json.length) return null;
      out += c + json[i + 1]!;
      i += 2;
    } else {
      out += c;
      i += 1;
    }
  }
  return null;
}

/**
 * The structural contract a VAID document must satisfy to be *parseable at all*,
 * as distinct from *valid*.
 *
 * This mirrors, member for member, the Rust `Vaid` struct — which is a typed
 * struct, so in Rust this gate is serde's and costs nothing to state. TypeScript
 * and Python hand their verifiers a plain object, which has no such gate, so
 * without this table the three implementations would answer *different questions*
 * about malformed input and a conformance vector comparing them would compare
 * nothing. Keeping it as data rather than a hand-rolled sequence of `if`
 * statements is what makes it reviewable against the struct it mirrors.
 */
const REQUIRED_MEMBERS: ReadonlyArray<readonly [string, (v: unknown) => boolean]> = [
  ['vaid_id', isUuid],
  ['agent_id', isUuid],
  ['agent_class', (v) => typeof v === 'string'],
  ['version', (v) => typeof v === 'string'],
  ['tenant_id', (v) => typeof v === 'string'],
  // Timestamps must be STRINGS, not necessarily readable ones. A document whose
  // expiry cannot be parsed still has an identity; "cannot be shown to be
  // unexpired" is a verdict (`isExpired` fails closed), not a parse failure. Rust
  // now holds these as presented strings for the same reason.
  ['issued_at', (v) => typeof v === 'string'],
  ['expires_at', (v) => typeof v === 'string'],
  ['public_key_der', isByteList],
  ['kernel_signature', isByteList],
  ['scope_boundary', isStringList],
  ['lineage_hash', (v) => typeof v === 'string'],
  ['capability_set', isStringList],
  ['trust_domain', (v) => typeof v === 'string'],
  ['kernel_key_thumbprint', (v) => typeof v === 'string'],
];

/**
 * Parse JSON **text** into a VAID document, or `null` if the bytes are not one.
 * Mirror of Rust's `serde_json::from_str::<Vaid>`.
 *
 * Structure only — this says nothing about whether the document is authentic,
 * unexpired or unrevoked. It answers the strictly earlier question: is there a
 * document here to have an opinion about?
 *
 * Unknown members are **preserved**, not dropped (ADR-0006): a verifier
 * canonicalizes the document it was *presented*, and an additive extension is
 * inside the signed bytes. This function is a gate, never a filter.
 *
 * `sig_version` is deliberately optional and defaults to `0`, matching the Rust
 * field's `#[serde(default)]`: a pre-v3 or forged document with the member
 * missing must parse cleanly and then be *rejected at verify* as
 * {@link VaidVerdict.UnsupportedSigVersion}, rather than being reported as
 * unparseable. The two failures are different accusations and a caller is
 * entitled to tell them apart.
 *
 * `parent_vaid` is optional and nullable, matching `Option<VaidId>`: absent and
 * present-null both mean "root".
 */
export function parseVaidDocument(documentJson: string): Vaid | null {
  // Checked FIRST and on the raw text: every parser here resolves a duplicate
  // before returning, so this is the only point at which the evidence exists.
  if (hasDuplicateMemberNames(documentJson)) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(documentJson);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const document = parsed as Record<string, unknown>;
  for (const [member, isWellTyped] of REQUIRED_MEMBERS) {
    if (!(member in document) || !isWellTyped(document[member])) return null;
  }
  const sigVersion = document.sig_version ?? 0;
  if (typeof sigVersion !== 'number' || !Number.isInteger(sigVersion)) return null;
  // Bounded to a byte because the Rust field is `u8`. Without this, `sig_version:
  // 999` is Unparseable in Rust and UnsupportedSigVersion here — the booleans
  // agree, the reasons do not, and that is exactly the divergence class this
  // mirror exists to prevent. Found by differential probe, not by review.
  if (sigVersion < 0 || sigVersion > 255) return null;
  const parent = document.parent_vaid;
  if (parent !== undefined && parent !== null && !isUuid(parent)) return null;
  return document as unknown as Vaid;
}

/**
 * Graded {@link verifyVaidAuthenticity}: the same checks, in the same order,
 * saying which one refused.
 *
 * The branch order is **load-bearing and unchanged** — `sig_version`,
 * `trust_domain`, thumbprint, `lineage_hash`, signature. It is not the only
 * defensible order, but it is the order all three implementations already had,
 * and reordering it here would silently change which reason a document gets while
 * leaving every boolean identical. That is precisely the class of divergence
 * `verdict_v1.json` exists to catch, so this function must not introduce one.
 *
 * Never returns {@link VaidVerdict.Expired}, {@link VaidVerdict.Revoked} or
 * {@link VaidVerdict.Indeterminate}: authenticity is not standing. Use
 * {@link verifyVaidStanding} for that.
 */
export function verifyVaidAuthenticityGraded(
  kernelPublicKey: Uint8Array,
  vaid: Vaid,
): VaidVerdict {
  if (vaid.sig_version !== VAID_SIG_VERSION_V3) return VaidVerdict.UnsupportedSigVersion;
  if (!isValidTrustDomain(vaid.trust_domain)) return VaidVerdict.MalformedTrustDomain;
  // The v3 key-commitment check: does the document's thumbprint CORRESPOND to
  // the key we were handed? Without it a caller could verify a document against a
  // key the document never named, and "verified under some key we hold" is a
  // verdict nobody can audit. Ordered before the signature check — one hash is
  // cheaper than an Ed25519 verification already known to fail.
  if (vaid.kernel_key_thumbprint !== kernelKeyThumbprint(kernelPublicKey)) {
    return VaidVerdict.IssuerMismatch;
  }
  if (!verifyLineageHash(vaid)) return VaidVerdict.LineageInconsistent;
  try {
    return ed25519Verify(
      numbersToBytes(vaid.kernel_signature),
      canonicalVaidSigningBytes(vaid),
      kernelPublicKey,
    )
      ? VaidVerdict.Valid
      : VaidVerdict.Inauthentic;
  } catch {
    // A structurally malformed document (e.g. a non-array signature field) is a
    // verification result, not a fault — matching the Rust and Python mirrors.
    return VaidVerdict.Inauthentic;
  }
}

/**
 * The full standing verdict: authenticity, then expiry, then revocation.
 *
 * Revocation is **passed in**, not looked up. This module still performs no
 * resolution — gating third-party verification on a lookup the verifier cannot do
 * is the R.4.2 problem, and adding a graded return is not a licence to rebuild it.
 * The caller assembles the lineage ({@link assembleLineage}) and consults its
 * {@link RevocationCheck}; this function says what the answer means. An incomplete
 * assembly is {@link RevocationStatus.Unavailable}, which arrives here as
 * {@link VaidVerdict.Indeterminate}.
 *
 * ## Order, and why it is this one
 *
 * 1. **Authenticity.** A document that is not real has no standing to discuss. A
 *    forgery that happens to be expired is reported as a forgery.
 * 2. **Expiry.** Determinable from the document alone. Checked before revocation
 *    so that a definite answer is never displaced by
 *    {@link VaidVerdict.Indeterminate} — reporting "I could not tell" about a
 *    document we can positively see has expired discards information we hold.
 * 3. **Revocation.** The only input that can be unavailable, so it is last.
 *
 * Expiry uses {@link isExpired}. Its `now` parameter is deliberately **not**
 * forwarded: the Rust and Python twins have no such parameter, so accepting one
 * here would make this function answerable to an input the other two cannot be
 * given, and a conformance vector could pin a verdict in one language that the
 * other two are structurally unable to reproduce. Callers who want to evaluate
 * expiry at a chosen instant call {@link isExpired} directly.
 */
export function verifyVaidStanding(
  kernelPublicKey: Uint8Array,
  vaid: Vaid,
  revocation: RevocationStatus,
): VaidVerdict {
  const authenticity = verifyVaidAuthenticityGraded(kernelPublicKey, vaid);
  if (!isVerdictValid(authenticity)) return authenticity;
  if (isExpired(vaid)) return VaidVerdict.Expired;
  if (revocation === RevocationStatus.NotRevoked) return VaidVerdict.Valid;
  if (revocation === RevocationStatus.Revoked) return VaidVerdict.Revoked;
  return VaidVerdict.Indeterminate;
}

/**
 * {@link verifyVaidStanding} over JSON **text**, so that "these bytes are not a
 * VAID" is a *verdict* rather than a throw the caller has to catch.
 *
 * This exists for a cross-language reason as much as an ergonomic one. Rust's
 * `Vaid` is a typed struct, so a truncated or structurally invalid document
 * cannot even be constructed — the failure happens at deserialization, before any
 * verifier sees it. TypeScript and Python hand their verifiers a plain object,
 * which has no such gate. Without a shared entry point that starts from *text*,
 * the three implementations would be answering different questions about
 * malformed input, and a conformance vector comparing them would be comparing
 * nothing.
 *
 * Parse failure is {@link VaidVerdict.Unparseable} — a refusal, never a throw.
 */
export function verifyVaidStandingFromJson(
  kernelPublicKey: Uint8Array,
  documentJson: string,
  revocation: RevocationStatus,
): VaidVerdict {
  const document = parseVaidDocument(documentJson);
  if (document === null) return VaidVerdict.Unparseable;
  return verifyVaidStanding(kernelPublicKey, document, revocation);
}
