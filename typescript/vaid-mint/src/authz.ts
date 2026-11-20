/**
 * Root-mint authorization seam — TypeScript mirror of the Rust
 * `vaid_mint::authz`.
 *
 * `mintRoot` issues a root VAID. In the closed managed authority that path is
 * operator-gated; this open reference does NOT carry that gate — but the absence
 * is made VISIBLE as a seam, exactly like the audit sink, rather than silently
 * missing.
 *
 * {@link AuthorizationGate} is the seam; {@link DenyAll} is the default — **deny
 * by default**. A production deployment supplies a real gate to
 * `new MintService(..., authz)`. {@link InsecurePermitAll} is the explicit,
 * clearly-named opt-in for local self-hosting, tests and demos — never for
 * production. `mintChild` is deliberately NOT routed through this gate — its
 * authorization IS the intrinsic attenuation check.
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
 * The default gate: denies every root mint.
 *
 * `mintRoot` has no authority to check against out of the box, so the safe
 * default is to issue nothing until a real {@link AuthorizationGate} is
 * supplied to `new MintService(..., authz)`. For local self-hosting, tests, or
 * demos that intentionally want every root mint to succeed, opt in explicitly
 * with {@link InsecurePermitAll}.
 */
export class DenyAll implements AuthorizationGate {
  async authorizeRootMint(): Promise<void> {
    throw new UnauthorizedError(
      'root mint denied: no AuthorizationGate configured (deny-by-default). ' +
        'Construct MintService with a real gate, or opt into InsecurePermitAll ' +
        'for tests/demos only',
    );
  }
}

/**
 * An explicit, clearly-named opt-in that permits every root mint.
 *
 * **INSECURE. For tests and local demos only — never use in production.**
 * Anyone who can reach a mint constructed with this gate can issue a root VAID.
 * A production deployment must supply a real {@link AuthorizationGate} to
 * `new MintService(..., authz)` instead.
 */
export class InsecurePermitAll implements AuthorizationGate {
  async authorizeRootMint(): Promise<void> {
    // Intentionally permits everything — see the class docs.
  }
}
