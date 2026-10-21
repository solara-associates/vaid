/**
 * Parsing a kernel public key the user supplies, in any of the forms a VAID
 * trust anchor is reasonably published in: raw hex, raw base64/base64url, or a
 * single JWK object (the shape docs/kernel-keys.json uses) — pasted directly,
 * or picked out of a fetched .well-known/vaid-keys.json map by thumbprint.
 */
import { kernelKeyThumbprint } from 'vaid-mint';

export interface ParsedKey {
  publicKey: Uint8Array;
  thumbprint: string;
}

function base64UrlToBytes(s: string): Uint8Array | null {
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function hexToBytes(s: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length % 2 !== 0) return null;
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Parse one key out of free-form pasted text: a bare hex/base64(url) string, or
 * a JWK object `{ "kty": "OKP", "crv": "Ed25519", "x": "..." }`.
 */
export function parsePastedKey(input: string): ParsedKey | null {
  const trimmed = input.trim();
  if (trimmed === '') return null;

  if (trimmed.startsWith('{')) {
    try {
      const jwk = JSON.parse(trimmed);
      if (jwk && jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') {
        const bytes = base64UrlToBytes(jwk.x);
        if (bytes && bytes.length === 32) return { publicKey: bytes, thumbprint: kernelKeyThumbprint(bytes) };
      }
    } catch {
      // fall through to the bare-string forms below
    }
    return null;
  }

  const hexBytes = hexToBytes(trimmed);
  if (hexBytes && hexBytes.length === 32) {
    return { publicKey: hexBytes, thumbprint: kernelKeyThumbprint(hexBytes) };
  }

  const b64Bytes = base64UrlToBytes(trimmed);
  if (b64Bytes && b64Bytes.length === 32) {
    return { publicKey: b64Bytes, thumbprint: kernelKeyThumbprint(b64Bytes) };
  }

  return null;
}

/**
 * Pick keys out of a fetched vaid-keys.json / synthera-kernel-keys.json document
 * (the docs/kernel-keys.json shape: a thumbprint-keyed map of JWKs).
 */
export function parseKeysDocument(json: unknown): ParsedKey[] {
  if (typeof json !== 'object' || json === null) return [];
  const keys = (json as Record<string, unknown>).keys;
  if (typeof keys !== 'object' || keys === null) return [];
  const out: ParsedKey[] = [];
  for (const [mapThumbprint, value] of Object.entries(keys as Record<string, unknown>)) {
    if (typeof value !== 'object' || value === null) continue;
    const jwk = value as Record<string, unknown>;
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') continue;
    const bytes = base64UrlToBytes(jwk.x);
    if (!bytes || bytes.length !== 32) continue;
    const derivedThumbprint = kernelKeyThumbprint(bytes);
    // The map key is a claim; only keys whose OWN derived thumbprint matches the
    // map key they are filed under are trustworthy (docs/trust-anchor.md) — a
    // JWK filed under a thumbprint that is not its own is not an anchor, it is a
    // mislabelled key, and must not be offered as a match for anything.
    if (derivedThumbprint !== mapThumbprint) continue;
    out.push({ publicKey: bytes, thumbprint: derivedThumbprint });
  }
  return out;
}
