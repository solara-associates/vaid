/**
 * Imported first, and for its side effect only. `vaid-mint`'s `issuerIdentity.ts`
 * calls Node's `Buffer` as a bare global — `Buffer.from(bytes).toString("base64url")`
 * and `Buffer.byteLength(s, "utf8")` — with no import of its own, so its absence
 * is only noticed at the call site, not at bundle time.
 *
 * This is a minimal shim covering exactly those two calls, not a general Buffer
 * polyfill: the widely-used `buffer` npm package was tried first and does not
 * support `"base64url"` as a `toString` encoding (only `"base64"`), so it throws
 * on the one call this package actually makes. Browser `btoa`/`TextEncoder`
 * cover both calls directly.
 */
function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const MinimalBuffer = {
  from(bytes: Uint8Array): { toString(encoding: string): string } {
    return {
      toString(encoding: string): string {
        if (encoding === 'base64url') return toBase64Url(bytes);
        throw new Error(`node-crypto-shim Buffer: unsupported encoding ${encoding}`);
      },
    };
  },
  byteLength(s: string, encoding: string): number {
    if (encoding !== 'utf8' && encoding !== 'utf-8') {
      throw new Error(`node-crypto-shim Buffer.byteLength: unsupported encoding ${encoding}`);
    }
    return new TextEncoder().encode(s).length;
  },
};

(globalThis as unknown as { Buffer: typeof MinimalBuffer }).Buffer = MinimalBuffer;
