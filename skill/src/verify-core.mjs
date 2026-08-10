/**
 * The shared verification core: one implementation of "what does this VAID
 * actually establish", used by both the `vaid verify` CLI and the public
 * browser verify page.
 *
 * It is one module because the alternative is two, and two verifiers drift. The
 * page and the CLI must not be able to disagree about the same bytes — that is
 * the whole proposition being sold.
 *
 * ## Everything here is a wrapper
 *
 * No cryptography, no canonicalization and no attenuation logic is implemented in
 * this file. `verifyVaidAuthenticity`, `verifyChainAt`, `isExpired`,
 * `kernelKeyThumbprint` and `isSpecialUseTrustDomain` all come from the published
 * `vaid-mint` package, which is byte-locked to the Rust and Python mints by the
 * cross-language conformance vectors. A reimplementation here would be a fourth
 * implementation with no vector holding it in line.
 *
 * ## The verdict is plural on purpose
 *
 * A VAID answers several independent questions and they fail independently. A
 * single boolean forces them into one channel, and the collapse always runs the
 * same direction: the cryptographic check passes, so the artifact is reported
 * "valid", and the parts nobody checked ride along inside that word.
 *
 * So {@link verifyEnvelope} returns a list of named findings, each with its own
 * state, plus a headline derived from them. Four of the findings are checks that
 * ran. One — revocation — is a check that did **not** run and cannot, and it is
 * in the same list rather than in a footnote, because a reader who skips the
 * footnote is exactly the reader the footnote is for.
 */

import {
  isExpired,
  isSpecialUseTrustDomain,
  kernelKeyThumbprint,
  PresentedBundle,
  verifyChainAt,
  verifyVaidAuthenticity,
  KernelKeyMap,
  ChainVerification,
  AttestationBundle,
} from 'vaid-mint';
import { parseEnvelope, EnvelopeError } from './envelope.mjs';

/** Outcome of one named check. */
export const Finding = {
  /** The check ran and passed. */
  Pass: 'pass',
  /** The check ran and failed. The VAID is rejected. */
  Fail: 'fail',
  /** The check ran, did not fail, but establishes less than it appears to. */
  Caveat: 'caveat',
  /** The check did not run, and this build cannot make it run. Never success. */
  NotChecked: 'not_checked',
};

/** The single word at the top of the result. Derived, never set directly. */
export const Headline = {
  /** Authentic, in date, issuer identity bound, authority contained. */
  Valid: 'valid',
  /** Authentic and in date, but something is established less firmly than it looks. */
  ValidWithCaveats: 'valid_with_caveats',
  /** Genuinely issued, but past `expires_at`. Real, not usable. */
  Expired: 'expired',
  /** Not accepted. Forged, tampered, signed by an unaccepted key, or unverifiable. */
  Rejected: 'rejected',
  /** Not a VAID envelope at all. No cryptographic claim was reached. */
  Malformed: 'malformed',
};

const THUMBPRINT_PREFIX = 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:';

function b64urlToBytes(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Turn the published trust anchor into a thumbprint → raw-32-key map, **re-running
 * the publisher's own check on the way**.
 *
 * The anchor file says of itself that the origin serving it is untrusted and that
 * a consumer must recompute each key's RFC 7638 thumbprint and check it equals the
 * map key it was filed under. This does exactly that, client-side, on every load.
 * A publisher that ships a file telling consumers to recompute, in a verifier that
 * does not recompute, is asking for a check it never runs itself.
 *
 * Fails closed: any key that does not hash to its own map key takes the whole
 * anchor down rather than being skipped, because a corrupted anchor with one good
 * key left in it is indistinguishable from a targeted substitution.
 */
export function loadAnchor(anchorDoc) {
  const keys = anchorDoc?.keys;
  if (!keys || typeof keys !== 'object' || Object.keys(keys).length === 0) {
    throw new Error('trust anchor has no keys — a trust anchor with no keys is not a trust anchor');
  }
  const map = new Map();
  for (const [claimed, jwk] of Object.entries(keys)) {
    if (!claimed.startsWith(THUMBPRINT_PREFIX)) {
      throw new Error(`trust anchor: ${claimed} is not an RFC 9278 sha-256 thumbprint URI`);
    }
    if (jwk?.kty !== 'OKP' || jwk?.crv !== 'Ed25519' || typeof jwk?.x !== 'string') {
      throw new Error(`trust anchor: ${claimed} is not an Ed25519 OKP JWK`);
    }
    const key = b64urlToBytes(jwk.x);
    if (key.length !== 32) {
      throw new Error(`trust anchor: ${claimed} does not hold a 32-byte Ed25519 key`);
    }
    // The recomputation. `kernelKeyThumbprint` is vaid-mint's, i.e. the same
    // function a verifier runs against the document — so anchor and document are
    // compared through one implementation, not two that could disagree.
    const actual = kernelKeyThumbprint(key);
    if (actual !== claimed) {
      throw new Error(
        `trust anchor is corrupt: a key filed under ${claimed} actually hashes to ${actual}. ` +
          'Anyone following the documented procedure would reject it. Failing closed.',
      );
    }
    map.set(claimed, { key, jwk, meta: jwk });
  }
  return map;
}

function finding(id, label, state, detail) {
  return { id, label, state, detail };
}

/**
 * Verify an envelope against a loaded anchor at an explicit instant.
 *
 * `now` is a parameter rather than a wall-clock read because expiry makes the
 * verdict time-dependent, and a verdict a test cannot reproduce is a verdict
 * nobody can audit.
 */
export function verifyEnvelope(input, anchor, now = new Date()) {
  let parsed;
  try {
    parsed = parseEnvelope(input);
  } catch (e) {
    if (e instanceof EnvelopeError) {
      return {
        headline: Headline.Malformed,
        summary: 'Not a VAID.',
        detail: e.message,
        findings: [],
        vaid: null,
        chain: [],
      };
    }
    throw e;
  }

  const { vaid, chain, bare } = parsed;
  const findings = [];

  // --- 1. Which key does this document say signed it, and do we accept it? ----
  // This is the trust decision and it comes first. Everything after it is
  // arithmetic; this is the only step where a human's judgement is encoded.
  const claimedTp = vaid.kernel_key_thumbprint;
  const entry = typeof claimedTp === 'string' ? anchor.get(claimedTp) : undefined;
  if (!entry) {
    findings.push(
      finding(
        'key',
        'Signing key',
        Finding.Fail,
        typeof claimedTp === 'string'
          ? `The document names kernel key ${claimedTp}, which is not in this verifier's trust anchor. ` +
              'It may be perfectly genuine — signed by someone this page does not vouch for. Refusing rather than guessing.'
          : 'The document names no kernel key (no `kernel_key_thumbprint`), so there is nothing to look up. ' +
              'Documents minted before ADR-0034 omit this field and cannot be matched to a published key.',
      ),
    );
    return assemble(findings, vaid, chain, bare);
  }
  // Where the accepted key came from changes what accepting it means, so the two
  // are worded apart. A key WE publish is one a reader can cross-check against
  // another channel; a key the reader added themselves is their own trust
  // decision, and describing it as "published in the trust anchor" would credit
  // us with a guarantee we never made.
  const local = entry.meta.$local === true;
  const provenance = local
    ? 'Signed under a kernel key YOU supplied out of band, not one published by us. ' +
      'Its thumbprint was recomputed from the key itself before it was accepted, so it cannot have been ' +
      'filed under a thumbprint that is not its own — but whether that key is really the sender\'s is your ' +
      'judgement, resting on the channel you got it from.'
    : `Signed under a kernel key published in the trust anchor` +
      `${entry.meta.key_id ? ` (${entry.meta.key_id}` : ''}` +
      `${entry.meta.key_id && entry.meta.deployment ? `, ${entry.meta.deployment}` : ''}` +
      `${entry.meta.key_id ? ')' : ''}. ` +
      "That key's thumbprint was recomputed from the key itself, not taken on the document's word.";

  findings.push(finding('key', 'Signing key', Finding.Pass, provenance));

  // --- 2. Authenticity, and attenuation if a chain was presented -------------
  if (chain.length > 0) {
    const result = verifyChainAt(
      new KernelKeyMap([entry.key]),
      vaid,
      new PresentedBundle(chain),
      new AttestationBundle(),
      now,
    );
    findings.push(chainFinding(result, chain.length));
    if (result !== ChainVerification.Attenuated) return assemble(findings, vaid, chain, bare);
  } else {
    const authentic = verifyVaidAuthenticity(entry.key, vaid);
    findings.push(
      finding(
        'authenticity',
        'Signature',
        authentic ? Finding.Pass : Finding.Fail,
        authentic
          ? 'The Ed25519 signature is valid over the canonical document, and `lineage_hash` is internally consistent. ' +
              'Every signed field is exactly as issued.'
          : 'The signature does not verify under the named key. The document has been altered since it was signed, ' +
              'or it was never signed by that key.',
      ),
    );
    if (!authentic) return assemble(findings, vaid, chain, bare);

    if (vaid.parent_vaid) {
      // A delegated leaf presented alone. Authentic, but its authority is
      // unchecked — kept apart from the authentic-root case, because "no chain
      // needed" and "chain not supplied" look identical in a boolean.
      findings.push(
        finding(
          'attenuation',
          'Delegated authority',
          Finding.Caveat,
          'This VAID names a parent, but no ancestor documents were presented alongside it, so there is no way ' +
            'to confirm its authority is contained within its parent\'s. Attenuation is UNVERIFIABLE here — ' +
            'which is not the same as satisfied. Ask the sender to present the full chain.',
        ),
      );
    }
  }

  // --- 3. Expiry -------------------------------------------------------------
  const expired = isExpired(vaid, now);
  findings.push(
    finding(
      'expiry',
      'Validity window',
      expired ? Finding.Fail : Finding.Pass,
      expired
        ? `Expired at ${vaid.expires_at}. The document is genuine; it is no longer in date.`
        : `In date until ${vaid.expires_at}.`,
    ),
  );

  // --- 4. Issuer identity ----------------------------------------------------
  // A conforming verifier SHOULD NOT bind a trust bundle to an RFC 6761
  // special-use name. Reporting this as a pass because the signature checked out
  // would be the exact conflation this module exists to avoid.
  const td = vaid.trust_domain;
  if (typeof td === 'string' && isSpecialUseTrustDomain(td)) {
    findings.push(
      finding(
        'issuer',
        'Issuer identity',
        Finding.Caveat,
        `\`trust_domain\` is \`${td}\`, an RFC 6761 special-use name. It is the deliberate default for a ` +
          'deployment whose issuer identity has not been configured, so that being unconfigured is VISIBLE rather ' +
          'than quietly claiming a real one. A conforming verifier SHOULD NOT bind a trust bundle to such a name. ' +
          'The signature is established; WHO the issuer is, as a named party, is not.',
      ),
    );
  } else {
    findings.push(
      finding('issuer', 'Issuer identity', Finding.Pass, `Issued under trust domain \`${td}\`.`),
    );
  }

  // --- 5. The check that did not run -----------------------------------------
  findings.push(revocationFinding());

  return assemble(findings, vaid, chain, bare);
}

/**
 * Revocation, always present and always {@link Finding.NotChecked}.
 *
 * This is not a limitation of this verifier that a better one would fix. There is
 * no published revocation list to consult: the open reference mint's revocation is
 * in-memory and dies with the process, and durable revocation is the closed
 * product. An offline verifier could not reach a list even if one existed, and
 * this page is offline by construction.
 *
 * It is a constant rather than a computed value so that no code path can ever
 * report it as satisfied.
 */
function revocationFinding() {
  return finding(
    'revocation',
    'Revocation',
    Finding.NotChecked,
    'NOT CHECKED, and this verifier cannot check it. There is no published revocation list to consult — the open ' +
      "reference mint's revocation list is in-memory and does not survive its own process. A VAID that passes every " +
      'check above may still have been revoked by its issuer, and nothing here would show it. Treat this verdict as ' +
      '"genuinely issued and in date", never as "currently authorised".',
  );
}

function chainFinding(result, depth) {
  const presented = `${depth} ancestor document${depth === 1 ? '' : 's'} presented`;
  switch (result) {
    case ChainVerification.Attenuated:
      return finding(
        'attenuation',
        'Delegation chain',
        Finding.Pass,
        `${presented}. Every document is authentic, the chain assembles to a root, and authority is contained at ` +
          'every hop: scope and capabilities never widen going down the chain.',
      );
    case ChainVerification.Inauthentic:
      return finding(
        'attenuation',
        'Delegation chain',
        Finding.Fail,
        `${presented}, but one of them — or the leaf — failed signature verification. Nothing further was checked.`,
      );
    case ChainVerification.Unverifiable:
      return finding(
        'attenuation',
        'Delegation chain',
        Finding.Fail,
        `${presented}, but the chain does not assemble: an ancestor named by a signed \`parent_vaid\` was not ` +
          'presented, or assembly hit a cycle or the depth bound. This means attenuation is UNVERIFIABLE — never ' +
          'that it is satisfied.',
      );
    case ChainVerification.NotAttenuated:
      return finding(
        'attenuation',
        'Delegation chain',
        Finding.Fail,
        `${presented}. The chain is complete and authentic, but a child claims authority its parent does not hold. ` +
          'This is a delegation that escalates rather than narrows.',
      );
    case ChainVerification.ConsentExpired:
      return finding(
        'attenuation',
        'Delegation chain',
        Finding.Fail,
        `${presented}. A hop crossing kernel keys carries a consent attestation that is authentic but outside its ` +
          'validity window. The parent really did consent; the consent has lapsed and needs renewing.',
      );
    default:
      return finding('attenuation', 'Delegation chain', Finding.Fail, `Unrecognised chain result: ${result}`);
  }
}

function assemble(findings, vaid, chain, bare) {
  // Revocation is appended on every path that got far enough to have a verdict at
  // all, including rejections — a reader who sees REJECTED should still not come
  // away thinking revocation was among the reasons.
  if (!findings.some((f) => f.id === 'revocation')) findings.push(revocationFinding());

  const failed = findings.filter((f) => f.state === Finding.Fail);
  const caveats = findings.filter((f) => f.state === Finding.Caveat);

  let headline;
  let summary;
  if (failed.length === 0) {
    headline = caveats.length > 0 ? Headline.ValidWithCaveats : Headline.Valid;
    summary = caveats.length > 0 ? 'Genuine and in date, with caveats.' : 'Genuine and in date.';
  } else if (failed.length === 1 && failed[0].id === 'expiry') {
    // Expiry alone is its own headline. "Rejected" would read as forged, and
    // telling someone their real credential is fake sends them to the wrong fix.
    headline = Headline.Expired;
    summary = 'Genuine, but expired.';
  } else {
    headline = Headline.Rejected;
    summary = failed[0].id === 'key' ? 'Signed by a key this verifier does not accept.' : 'Not accepted.';
  }

  return {
    headline,
    summary,
    detail: null,
    findings,
    vaid,
    chain,
    presentedBare: bare,
  };
}
