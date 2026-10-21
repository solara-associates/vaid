/**
 * The published `vaid-mint` 0.11.0 package imports Node's `node:crypto` directly
 * in `issuerIdentity.ts` (`kernelKeyThumbprint`), even though its sibling
 * `vaid-pop` already ships a browser-safe SHA-256 (`@noble/hashes`) for exactly
 * this reason. That one function is not actually browser-portable as published.
 *
 * This shim substitutes a `createHash("sha256")` with the same
 * `.update(bytes).digest()` shape, backed by `vaid-pop`'s own `sha256`, so the
 * published package runs unmodified in a browser build. It is NOT a private
 * fork of vaid-mint: no vaid-mint source is copied or changed, only the one
 * Node builtin it reaches for is substituted at bundle time (esbuild `--alias`).
 * See the PR description for the upstream issue this should become.
 */
import { sha256 } from 'vaid-pop';

class BrowserHash {
  #algorithm: string;
  #chunks: Uint8Array[] = [];

  constructor(algorithm: string) {
    if (algorithm !== 'sha256') {
      throw new Error(`node-crypto-shim: unsupported digest algorithm ${algorithm}`);
    }
    this.#algorithm = algorithm;
  }

  update(data: Uint8Array | string): this {
    this.#chunks.push(typeof data === 'string' ? new TextEncoder().encode(data) : data);
    return this;
  }

  digest(): Uint8Array {
    const total = this.#chunks.reduce((n, c) => n + c.length, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const c of this.#chunks) {
      merged.set(c, offset);
      offset += c.length;
    }
    return sha256(merged);
  }
}

export function createHash(algorithm: string): BrowserHash {
  return new BrowserHash(algorithm);
}
