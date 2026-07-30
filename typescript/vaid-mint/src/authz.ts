/**
 * Root-mint authorization seam — TypeScript mirror of the Rust
 * `vaid_mint::authz`.
 *
 * `mintRoot` issues a root VAID. In the closed managed authority that path is
 * operator-gated; this open reference does NOT carry that gate — but the absence
 * is made VISIBLE as a seam, exactly like the audit sink, rather than silently
 * missing.
 *
 * {@link AuthorizationGate} is the seam; {@link PermitAll} is the default. A
 * production deployment supplies a real gate to
 * `MintService.withAuthorization(...)`. `mintChild` is deliberately NOT routed
 * through this gate — its authorization IS the intrinsic attenuation check.
 */

import { UnauthorizedError } from './error.js';
import type { VaidSeed } from './mintTypes.js';

/**
 * The root-mint authorization seam. Throw {@link UnauthorizedError} to deny;
 * return to permit.
 */
export interface AuthorizationGate {
  authorizeRootMint(seed: VaidSeed): Promise<void>;
}

/**
 * The default gate: permits every root mint.
 *
 * This is a REFERENCE-IMPLEMENTATION CHOICE, not a security recommendation. With
 * `PermitAll` in place, anyone who can reach the mint can issue a root VAID; a
 * production deployment should supply a real {@link AuthorizationGate}.
 */
export class PermitAll implements AuthorizationGate {
  async authorizeRootMint(): Promise<void> {
    // Intentionally permits everything — see the class docs.
  }
}

/** A gate that denies every root mint — the negative reference/testing gate. */
export class DenyAll implements AuthorizationGate {
  async authorizeRootMint(): Promise<void> {
    throw new UnauthorizedError('root mint denied by gate');
  }
}
