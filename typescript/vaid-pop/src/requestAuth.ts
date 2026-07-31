/**
 * Per-request authentication payload + authenticated principal (stateless signed
 * request proof-of-possession) — the TypeScript mirror of the Rust
 * `vaid_pop::request_auth`.
 *
 * A caller signs each request with its VAID private key over the canonical bytes
 * of a {@link RequestAuthPayload}; a verifier recomputes the same payload and
 * verifies the signature against the caller's VAID public key via
 * {@link verifySignedPayload}. On success it derives a {@link Principal} **from
 * the cryptographically verified VAID**, never from a body-asserted identity.
 *
 * These types are pure and transport-agnostic: the HTTP carrier (headers), body
 * buffering, and replay cache live in the calling service. They live here so a
 * holder and a conforming verifier derive the *exact same* signed bytes from one
 * definition.
 */

/**
 * A VAID identifier. A UUID in its canonical lowercase hyphenated string form —
 * the shape Rust's `VaidId(Uuid)` and Python's `str` both put on the wire.
 */
export type VaidId = string;

/** A tenant identifier. */
export type TenantId = string;

/**
 * Whole-second RFC 3339 with `Z`, e.g. `"2026-06-04T12:00:00Z"`.
 *
 * This is the chrono-serde fixed point. A verifier parses the timestamp into a
 * `DateTime<Utc>` and re-serializes it when it recomputes the canonical bytes; a
 * whole-second `…Z` string parses and re-serializes to itself, so the client's
 * signed-payload timestamp matches the server's. Sub-second precision would risk
 * a re-serialization mismatch, so this package only ever emits whole seconds —
 * see {@link utcWholeSecondRfc3339}.
 */
export type Rfc3339Utc = string;

/**
 * Reserved tenant id for the bootstrapped control-plane operator. The operator
 * is authenticated by exactly the same per-request PoP as any tenant; it is
 * *distinguished* by carrying this reserved tenant. A principal whose `tenantId`
 * equals this resolves to the highest-privilege role, off this constant
 * ({@link isOperator}) rather than any body field.
 */
export const OPERATOR_TENANT_ID = 'synthera-control-plane';

/**
 * Capability marker placed in the operator VAID's `capability_set` at bootstrap.
 * Belt-and-suspenders alongside the reserved tenant: it makes the control-plane
 * grant visible in the VAID itself.
 */
export const CONTROL_PLANE_CAPABILITY = 'synthera:control-plane';

/**
 * HTTP header carrying the full presented VAID, base64(JSON). The VAID is
 * self-verifying via its signature, so no server-side VAID store is needed to
 * authenticate a request.
 */
export const HEADER_VAID = 'x-synthera-vaid';
/** HTTP header carrying the client-asserted RFC 3339 timestamp (freshness). */
export const HEADER_TIMESTAMP = 'x-synthera-timestamp';
/** HTTP header carrying the per-request client nonce (replay distinctness). */
export const HEADER_NONCE = 'x-synthera-nonce';
/**
 * HTTP header carrying the base64 Ed25519 signature over the canonical
 * {@link RequestAuthPayload} bytes.
 */
export const HEADER_SIGNATURE = 'x-synthera-signature';

/**
 * The exact payload a holder signs per request. Binds the request material so a
 * captured signature cannot be lifted onto a different request or replayed:
 *
 * - `method` + `path` + `bodySha256` bind the verb, route, and exact body — a
 *   signature for `POST /a {body X}` is useless for `POST /b` or `{body Y}`;
 * - `tenantId` binds cross-tenant intent — and a verifier reconstructs it from
 *   the **verified VAID's** tenant, so a caller can only ever produce a valid
 *   signature for its own tenant;
 * - `timestamp` + `clientNonce` give freshness and replay distinctness.
 *
 * The field set is exactly these seven — no more, no less. The names are
 * camelCase, matching the Rust struct's `#[serde(rename_all = "camelCase")]`;
 * JCS sorts keys, so declaration order is irrelevant, but the names are not.
 */
export interface RequestAuthPayload {
  vaidId: VaidId;
  method: string;
  /**
   * The on-the-wire request target, **including the query string** — not
   * path-only. Signing path-only would leave the query outside the signature and
   * therefore tamperable; the convention is pinned by the frozen
   * `pathquery_v1.json` vector.
   */
  path: string;
  /** Lowercase hex of `SHA-256(request_body)`. */
  bodySha256: string;
  tenantId: TenantId;
  timestamp: Rfc3339Utc;
  clientNonce: string;
}

/** Build the seven-field canonical payload. */
export function buildRequestAuthPayload(fields: RequestAuthPayload): RequestAuthPayload {
  return {
    vaidId: fields.vaidId,
    method: fields.method,
    path: fields.path,
    bodySha256: fields.bodySha256,
    tenantId: fields.tenantId,
    timestamp: fields.timestamp,
    clientNonce: fields.clientNonce,
  };
}

/**
 * An authenticated principal. Produced ONLY after a VAID verifies (signature +
 * unexpired + unrevoked) and its key signs the request. Both fields are derived
 * from the **verified VAID**, never from a body-asserted `tenantId`, so a
 * handler never trusts a body-asserted identity.
 */
export interface Principal {
  vaidId: VaidId;
  tenantId: TenantId;
}

/**
 * True iff this principal is the bootstrapped control-plane operator — i.e. its
 * (cryptographically verified) VAID carries the reserved
 * {@link OPERATOR_TENANT_ID}. A caller uses this to grant the highest-privilege
 * role without consulting any body-asserted field.
 */
export function isOperator(principal: Principal): boolean {
  return principal.tenantId === OPERATOR_TENANT_ID;
}

/**
 * Whole-second UTC RFC 3339 with `Z` — the {@link Rfc3339Utc} fixed point.
 *
 * `Date.prototype.toISOString` always emits milliseconds, which would put a
 * sub-second component into the signed bytes that a chrono verifier would
 * re-serialize differently. Truncating to the second here is the reason the
 * client's timestamp and the server's recomputation agree.
 */
export function utcWholeSecondRfc3339(now: Date = new Date()): Rfc3339Utc {
  return `${new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString().slice(0, 19)}Z`;
}
