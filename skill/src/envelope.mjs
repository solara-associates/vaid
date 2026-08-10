/**
 * The **VAID envelope**: the wire form of a VAID that a human can copy out of a
 * terminal, paste into a chat message, and have someone else check.
 *
 * A signed VAID document is JSON with a 64-element signature array. Pasted raw it
 * is ~1 KB of multi-line JSON that every chat client, ticket tracker and mail
 * agent is free to reflow — and reflowing it is not cosmetic, because the
 * signature is computed over canonical bytes. An artifact that only survives
 * inside the CLI that produced it cannot leave the machine, so the credential
 * never reaches a second party and the whole loop is one-ended.
 *
 * So the envelope is one line, one token, no whitespace:
 *
 *     vaid1:<base64url(JSON)>
 *
 * `base64url` (RFC 4648 §5, unpadded) because it is the largest alphabet that is
 * safe in a URL fragment, a shell argument, a YAML scalar and a Markdown span
 * without escaping — the four places this actually gets pasted.
 *
 * It is deliberately **not** compressed. Compression would buy ~40% and cost the
 * property that matters more: anyone can run `base64 -d` on the payload and read
 * the document with no tooling from us. The envelope must be inspectable by
 * someone who does not trust us enough to install our code.
 *
 * ## What is inside
 *
 * ```json
 * { "v": 1, "vaid": <leaf document>, "chain": [<ancestor documents>] }
 * ```
 *
 * `chain` carries the ancestors for ADR-0003 detached chain presentation, so a
 * delegated (attenuated) VAID can be checked end to end by a third party who
 * holds nothing but the published kernel key. It is omitted for a root.
 *
 * Nothing else. In particular the envelope carries **no key material and no
 * thumbprint of its own**: the leaf already commits to `kernel_key_thumbprint`
 * inside its signed bytes, and a second, unsigned copy beside it would be a field
 * an attacker controls that looks like one they do not.
 */

export const ENVELOPE_PREFIX = 'vaid1:';
export const ENVELOPE_VERSION = 1;

/** Thrown for input that is not a well-formed envelope. Never for a bad verdict. */
export class EnvelopeError extends Error {
  constructor(message) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function toBase64Url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa is present in Node >= 16 and in every browser, so this module stays free
  // of `node:buffer` and can be bundled for the browser untouched.
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(s) {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Pack a leaf document and its presented ancestors into a single-line envelope.
 *
 * `chain` is the ancestor documents in any order; {@link PresentedBundle} keys
 * them by their own `vaid_id`, so order carries no meaning and is not relied on.
 */
export function packEnvelope(vaid, chain = []) {
  if (!vaid || typeof vaid !== 'object') throw new EnvelopeError('no VAID document to pack');
  const body = { v: ENVELOPE_VERSION, vaid };
  if (chain.length > 0) body.chain = chain;
  const json = JSON.stringify(body);
  return ENVELOPE_PREFIX + toBase64Url(new TextEncoder().encode(json));
}

/**
 * Parse an envelope back into `{ vaid, chain }`.
 *
 * Accepts three inputs on purpose, because a human pasting a credential does not
 * reliably paste exactly what was printed:
 *
 * - a `vaid1:` token, with any surrounding whitespace or newlines a mail client
 *   may have inserted **inside** it (they are stripped before decoding — the
 *   token's alphabet excludes whitespace, so this cannot change its meaning);
 * - a bare envelope JSON object (`{"v":1,"vaid":…}`);
 * - a bare VAID document, which is treated as a root with no presented chain.
 *
 * The third is what someone gets by copying a document out of a log, and
 * refusing it would send them away believing their credential is malformed when
 * it is merely undressed.
 */
export function parseEnvelope(input) {
  if (typeof input !== 'string') throw new EnvelopeError('expected a string');
  const trimmed = input.trim();
  if (trimmed === '') throw new EnvelopeError('nothing to parse');

  if (trimmed.startsWith(ENVELOPE_PREFIX)) {
    const token = trimmed.slice(ENVELOPE_PREFIX.length).replace(/\s+/g, '');
    if (token === '' || !B64URL_RE.test(token)) {
      throw new EnvelopeError('the vaid1: token is not valid base64url');
    }
    let json;
    try {
      json = new TextDecoder().decode(fromBase64Url(token));
    } catch {
      throw new EnvelopeError('the vaid1: token did not decode');
    }
    return normalise(parseJson(json));
  }

  if (trimmed.startsWith('{')) return normalise(parseJson(trimmed));

  throw new EnvelopeError('not a vaid1: token and not JSON');
}

function parseJson(s) {
  try {
    return JSON.parse(s);
  } catch (e) {
    throw new EnvelopeError(`not parseable JSON: ${e.message}`);
  }
}

function normalise(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new EnvelopeError('expected a JSON object');
  }
  // An envelope announces itself with `v`. Anything else is read as a bare
  // document, so a copied-out-of-a-log VAID still works.
  if (obj.v === undefined && obj.vaid === undefined) {
    return { vaid: obj, chain: [], bare: true };
  }
  if (obj.v !== ENVELOPE_VERSION) {
    throw new EnvelopeError(
      `envelope version ${JSON.stringify(obj.v)} is not supported (this build reads v${ENVELOPE_VERSION})`,
    );
  }
  if (!obj.vaid || typeof obj.vaid !== 'object' || Array.isArray(obj.vaid)) {
    throw new EnvelopeError('envelope has no "vaid" document');
  }
  const chain = obj.chain ?? [];
  if (!Array.isArray(chain)) throw new EnvelopeError('envelope "chain" is not an array');
  for (const d of chain) {
    if (!d || typeof d !== 'object' || Array.isArray(d)) {
      throw new EnvelopeError('envelope "chain" holds something that is not a VAID document');
    }
  }
  return { vaid: obj.vaid, chain, bare: false };
}
