/**
 * Standalone, public-key-only verification of a VAID document. TypeScript mirror
 * of the Rust `vaid_mint::verify`.
 *
 * {@link ReferenceIssuer.verifyVaid} can only be called by a party holding a
 * `ReferenceIssuer`, and every issuer constructor needs the kernel **private**
 * key. An Ed25519 signature needs only the **public** key to verify, so this
 * module exposes what the issuer method trapped inside itself: a third party
 * holding just the issuer's kernel public key can confirm a VAID document is
 * authentic — no issuer instance, no private key.
 *
 * ## Scope: authenticity, not standing
 *
 * {@link verifyVaidAuthenticity} answers "was this document genuinely issued
 * under this key, and is it internally consistent" — the signature-scheme
 * version, the kernel Ed25519 signature over the canonical document, and the
 * consistency of `lineage_hash`. It deliberately does **not**:
 *
 * - check **expiry** — a temporal concern; call {@link isExpired} separately if
 *   the caller cares about validity now;
 * - consult **revocation** — this is the load-bearing decision. A resolver-less
 *   verifier answers authenticity; gating that on a lineage/revocation lookup the
 *   verifier cannot perform would make every third-party verification fail
 *   closed, rebuilding the R.4.2 problem in a new place. Revocation status is
 *   reported on a separate path ({@link ReferenceIssuer.revocationStatus}) or not
 *   at all here.
 */

import { ed25519Verify, numbersToBytes } from 'vaid-pop';

import {
  canonicalVaidSigningBytes,
  computeLineageHash,
  VAID_SIG_VERSION_V2,
  type Vaid,
} from './document.js';

/**
 * Recompute `lineage_hash` from the document's own `parent_vaid` and `agent_id`
 * (via {@link computeLineageHash}) and compare. Catches an inconsistent
 * `lineage_hash` **explicitly**, rather than relying on it being incidentally
 * covered by the kernel signature — so a caller can check lineage integrity on
 * its own, and so a mint that signs a malformed `lineage_hash` is caught here.
 */
export function verifyLineageHash(vaid: Vaid): boolean {
  if (typeof vaid.agent_id !== 'string') return false;
  return computeLineageHash(vaid.parent_vaid ?? null, vaid.agent_id) === vaid.lineage_hash;
}

/**
 * Verify a VAID document's **authenticity** against an issuer's kernel **public**
 * key (raw 32-byte Ed25519). No issuer instance, no private key.
 *
 * This answers *authenticity* — "genuinely issued under this key, and internally
 * consistent" — **not** *standing* ("valid and unrevoked right now"). A `true`
 * result does not mean the VAID is currently usable; it means it is real.
 *
 * **Checks (all must hold for `true`):**
 * - the signature-scheme version is current;
 * - `lineage_hash` is internally consistent ({@link verifyLineageHash});
 * - the kernel Ed25519 signature is valid over the canonical document under
 *   `kernelPublicKey`.
 *
 * **Does NOT check — the caller must handle these separately:**
 * - **expiry** — call {@link isExpired}; an expired-but-signed VAID returns
 *   `true` here;
 * - **revocation** — evaluate a {@link RevocationCheck} (or, in the reference,
 *   {@link ReferenceIssuer.revocationStatus}) on a separate path. Revocation is
 *   deliberately *not* consulted here — see the module docs.
 *
 * A malformed key, a bad signature, or any tampered signed field is `false`,
 * never a throw.
 */
export function verifyVaidAuthenticity(kernelPublicKey: Uint8Array, vaid: Vaid): boolean {
  if (vaid.sig_version !== VAID_SIG_VERSION_V2) return false;
  if (!verifyLineageHash(vaid)) return false;
  try {
    return ed25519Verify(
      numbersToBytes(vaid.kernel_signature),
      canonicalVaidSigningBytes(vaid),
      kernelPublicKey,
    );
  } catch {
    // A structurally malformed document (e.g. a non-array signature field) is a
    // verification result, not a fault — matching the Rust and Python mirrors.
    return false;
  }
}
