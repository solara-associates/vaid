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

/**
 * A mint was constructed with an invalid configuration value (e.g.
 * `maxDelegationDepth`). Raised at construction, before any request is served,
 * so a misconfigured mint never starts minting.
 */
export class ConfigError extends MintError {
  override readonly name = 'ConfigError';
}

/**
 * A document is not shaped like a VAID: not an object, or `vaid_id` /
 * `parent_vaid` is missing or the wrong type. Thrown by
 * {@link requireVaidShape} in `document.ts`. Distinct from
 * {@link VaidVerdict.Unparseable}, which is the graceful verdict
 * `verifyVaidStandingFromJson` returns for JSON **text** that is not a VAID:
 * this is thrown by the functions that take an already-parsed object and
 * would otherwise fail with a bare `TypeError` deep inside lineage assembly.
 */
export class MalformedDocumentError extends MintError {
  override readonly name = 'MalformedDocumentError';
}

/**
 * A VAID verified as {@link VaidVerdict.Valid}, but does not belong to the
 * caller presenting it: at least one field of the `ExpectedCaller` passed to
 * `verifyVaidStandingBound` did not match the document's own. Thrown rather
 * than folded into {@link VaidVerdict}: that type's vocabulary is the
 * conformance surface `verdict_v1.json` pins across all three
 * implementations, and caller binding is a property of the request the
 * document arrived on, not of the document itself.
 */
export class CallerMismatchError extends MintError {
  override readonly name = 'CallerMismatchError';
}
