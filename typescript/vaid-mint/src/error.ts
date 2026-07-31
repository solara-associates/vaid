/**
 * Mint errors — TypeScript mirror of the Rust `vaid_mint::error`.
 *
 * Three distinguishable failure classes, because a caller must be able to tell an
 * authorization refusal from a cryptographic one: `Unauthorized` is a policy
 * decision, `Identity` is a key/proof failure, `Audit` is a failed write that
 * (per the closed invariant "a mint that cannot be recorded fails") fails the
 * mint.
 */

/** Base class for every mint failure. */
export class MintError extends Error {
  override readonly name: string = 'MintError';
}

/** The caller may not do this — an authorization or attenuation refusal. */
export class UnauthorizedError extends MintError {
  override readonly name = 'UnauthorizedError';
}

/** A key, signature, or proof-of-possession failure. */
export class IdentityError extends MintError {
  override readonly name = 'IdentityError';
}

/** The audit sink refused or failed the write, so the mint fails. */
export class AuditError extends MintError {
  override readonly name = 'AuditError';
}
