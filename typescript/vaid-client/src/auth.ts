/**
 * Proof-of-possession request signing — the TypeScript client-side transport.
 * Mirror of the Rust `vaid_client::auth`.
 *
 * The glue that assembles `(method, path, body)` into the canonical
 * {@link RequestAuthPayload}, signs it, and emits the four `x-synthera-*`
 * headers. The canonicalization and the Ed25519 sign/verify live in `vaid-pop`;
 * this module never reimplements JCS, so the bytes stay identical to a conforming
 * verifier by construction.
 *
 * Two signing strategies, for two key custodies:
 *
 * - {@link RequestSigner} — holds a raw Ed25519 private seed (the agent-key case:
 *   a tenant that holds its own private key).
 * - {@link PortRequestSigner} — defers signing to an {@link OperatorSigningPort}
 *   (the external-key-store case: the key never leaves its keystore). The port
 *   receives the already-canonical 32-byte digest, never the payload and never
 *   the key.
 */

import {
  canonicalRequestSigningBytes,
  ed25519Sign,
  HEADER_NONCE,
  HEADER_SIGNATURE,
  HEADER_TIMESTAMP,
  HEADER_VAID,
  randomHex,
  sha256Hex,
  toBase64,
  utcWholeSecondRfc3339,
  type Ed25519Seed,
  type RequestAuthPayload,
  type Rfc3339Utc,
  type TenantId,
  type VaidId,
} from 'vaid-pop';

/** Errors constructing a signer or producing headers. */
export class PopError extends Error {
  override readonly name: string = 'PopError';
}

/**
 * The supplied VAID document JSON could not be parsed for the snake_case
 * `vaid_id` / `tenant_id` identity fields the payload binds.
 */
export class InvalidVaidError extends PopError {
  override readonly name = 'InvalidVaidError';
}

/** The {@link OperatorSigningPort} failed to sign the digest. */
export class SigningError extends PopError {
  override readonly name = 'SigningError';
}

/**
 * The four PoP headers for one signed request. Property order is irrelevant — a
 * verifier reads them by name.
 */
export interface PopHeaders {
  /** `x-synthera-vaid` — base64(JSON of the VAID document). */
  vaid: string;
  /** `x-synthera-timestamp` — whole-second RFC 3339 `…Z`. */
  timestamp: Rfc3339Utc;
  /** `x-synthera-nonce` — fresh per-request 128-bit nonce, lowercase hex. */
  nonce: string;
  /** `x-synthera-signature` — base64(raw 64-byte Ed25519 signature). */
  signature: string;
}

/** The four `(header-name, value)` pairs, ready to attach to a request. */
export function popHeaderPairs(headers: PopHeaders): Array<[string, string]> {
  return [
    [HEADER_VAID, headers.vaid],
    [HEADER_TIMESTAMP, headers.timestamp],
    [HEADER_NONCE, headers.nonce],
    [HEADER_SIGNATURE, headers.signature],
  ];
}

/** The same four headers as a plain object, e.g. for `fetch`'s `headers`. */
export function popHeaderRecord(headers: PopHeaders): Record<string, string> {
  return Object.fromEntries(popHeaderPairs(headers));
}

/**
 * An external signing port: the private key never leaves its keystore. The port
 * is handed the already-canonical 32-byte digest.
 */
export interface OperatorSigningPort {
  /** Sign the 32-byte canonical digest, returning the raw 64-byte signature. */
  sign(canonicalBytes: Uint8Array): Promise<Uint8Array>;
  /** The raw 32-byte Ed25519 public key this port signs under. */
  publicKey(): Promise<Uint8Array>;
}

/** Options for the deterministic signing variants (conformance vectors, tests). */
export interface SignOptions {
  /** Defaults to now, truncated to the whole second. */
  now?: Date;
  /** Defaults to a fresh 128-bit random hex nonce. */
  nonce?: string;
}

/**
 * The request-binding identity shared by both signing strategies: the VAID header
 * (base64 of the document) plus the `vaid_id`/`tenant_id` the payload binds.
 * Parsed once from the minted VAID document JSON.
 */
class PopIdentity {
  readonly #vaidHeader: string;
  readonly #vaidId: VaidId;
  readonly #tenantId: TenantId;

  private constructor(vaidHeader: string, vaidId: VaidId, tenantId: TenantId) {
    this.#vaidHeader = vaidHeader;
    this.#vaidId = vaidId;
    this.#tenantId = tenantId;
  }

  /**
   * Parse identity out of the minted VAID document JSON.
   *
   * A VAID document is snake_case (the Rust `Vaid` has no serde rename), unlike
   * the camelCase `RequestAuthPayload`. Extract identity by snake_case keys.
   */
  static fromVaidJson(vaidJson: string | Uint8Array): PopIdentity {
    const text =
      typeof vaidJson === 'string' ? vaidJson : new TextDecoder().decode(vaidJson);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (error) {
      throw new InvalidVaidError(`invalid VAID document JSON: ${(error as Error).message}`);
    }
    const document = parsed as Record<string, unknown>;
    const vaidId = document?.['vaid_id'];
    const tenantId = document?.['tenant_id'];
    if (typeof vaidId !== 'string' || typeof tenantId !== 'string') {
      throw new InvalidVaidError(
        'VAID document missing required snake_case fields `vaid_id` and `tenant_id`',
      );
    }
    // A verifier re-deserializes the VAID by field and recomputes its own
    // canonical bytes, so carrying the document bytes verbatim is correct.
    const header = toBase64(new TextEncoder().encode(text));
    return new PopIdentity(header, vaidId, tenantId);
  }

  /**
   * Build the canonical payload + the whole-second timestamp string for a
   * request. The timestamp is normalized so the header value and the value inside
   * the signed payload are the same string — a whole-second `…Z` round-trips
   * through chrono-serde to itself, the fixed point a verifier relies on.
   */
  payload(
    method: string,
    path: string,
    body: Uint8Array,
    now: Date,
    nonce: string,
  ): { payload: RequestAuthPayload; timestamp: Rfc3339Utc } {
    const timestamp = utcWholeSecondRfc3339(now);
    return {
      timestamp,
      payload: {
        vaidId: this.#vaidId,
        method: method.toUpperCase(),
        path,
        bodySha256: sha256Hex(body),
        tenantId: this.#tenantId,
        timestamp,
        clientNonce: nonce,
      },
    };
  }

  headers(timestamp: Rfc3339Utc, nonce: string, signature: Uint8Array): PopHeaders {
    return { vaid: this.#vaidHeader, timestamp, nonce, signature: toBase64(signature) };
  }
}

/**
 * Signs requests with a raw agent key — the holder-custody case (a tenant that
 * holds its own Ed25519 private key).
 */
export class RequestSigner {
  readonly #identity: PopIdentity;
  readonly #seed: Ed25519Seed;

  /** Construct from the minted VAID document JSON and the agent's private seed. */
  constructor(vaidJson: string | Uint8Array, seed: Ed25519Seed) {
    if (seed.length !== 32) {
      throw new PopError(`Ed25519 private seed must be 32 bytes, got ${seed.length}`);
    }
    this.#identity = PopIdentity.fromVaidJson(vaidJson);
    this.#seed = seed;
  }

  /**
   * Produce the four PoP headers for `(method, path, body)`.
   *
   * `path` MUST be the on-the-wire request target **including any query
   * string** — the convention pinned by the `pathquery_v1.json` vector. Signing
   * path-only would leave the query outside the signature and tamperable.
   *
   * `options.now` / `options.nonce` are injectable for deterministic tests and
   * conformance vectors; they default to the current whole UTC second and a fresh
   * 128-bit random nonce.
   */
  signHeaders(
    method: string,
    path: string,
    body: Uint8Array = new Uint8Array(),
    options: SignOptions = {},
  ): PopHeaders {
    const now = options.now ?? new Date();
    const nonce = options.nonce ?? randomHex(16);
    const { payload, timestamp } = this.#identity.payload(method, path, body, now, nonce);
    // Reuse the shared primitive: canonicalize + sign in one call.
    const signature = ed25519Sign(canonicalRequestSigningBytes(payload), this.#seed);
    return this.#identity.headers(timestamp, nonce, signature);
  }
}

/**
 * Signs requests by deferring the digest signature to an
 * {@link OperatorSigningPort} — the external-key-store case, where the private
 * key never leaves its keystore.
 */
export class PortRequestSigner {
  readonly #identity: PopIdentity;
  readonly #port: OperatorSigningPort;

  /** Construct from the minted VAID document JSON and an operator-signing port. */
  constructor(vaidJson: string | Uint8Array, port: OperatorSigningPort) {
    this.#identity = PopIdentity.fromVaidJson(vaidJson);
    this.#port = port;
  }

  /** As {@link RequestSigner.signHeaders}, with the signature produced by the port. */
  async signHeaders(
    method: string,
    path: string,
    body: Uint8Array = new Uint8Array(),
    options: SignOptions = {},
  ): Promise<PopHeaders> {
    const now = options.now ?? new Date();
    const nonce = options.nonce ?? randomHex(16);
    const { payload, timestamp } = this.#identity.payload(method, path, body, now, nonce);
    // Canonicalize here (shared primitive), then hand only the digest to the port.
    const digest = canonicalRequestSigningBytes(payload);
    let signature: Uint8Array;
    try {
      signature = await this.#port.sign(digest);
    } catch (error) {
      throw new SigningError(`operator signing port failed: ${(error as Error).message}`);
    }
    if (signature.length !== 64) {
      throw new SigningError(
        `operator signing port returned ${signature.length} bytes, expected a raw 64-byte Ed25519 signature`,
      );
    }
    return this.#identity.headers(timestamp, nonce, signature);
  }
}
