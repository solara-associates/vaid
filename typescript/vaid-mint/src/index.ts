/**
 * # vaid-mint
 *
 * The open, self-hostable **reference mint** for the VAID (Verifiable Agent
 * Identity) standard, in TypeScript: mint a root VAID
 * ({@link MintService.mintRoot}) and mint attenuated child VAIDs
 * ({@link MintService.mintChild}), where a child's authority is always a subset
 * of its parent's (`child ⊆ parent`).
 *
 * This is the open engine of a HashiCorp-Vault-style split; the managed
 * authority (KMS-backed keys, the *durable, hash-chained* audit-of-record, and
 * *durable* revocation) is the closed product and is deliberately NOT here.
 * Revocation has a pluggable seam here — three-state and lineage-aware
 * ({@link RevocationCheck}, injected via
 * {@link ReferenceIssuer.withRevocationCheck}), specified in
 * `docs/spec/revocation.md` R.4 and failing closed when status is unavailable —
 * with a non-durable in-memory default, and VAID expiry (TTL) is hard-enforced at
 * verification. What stays commercial is durable, restart-surviving revocation
 * itself.
 *
 * Proof-of-possession reuses the `vaid-pop` primitive verbatim. Byte-identity of
 * the signed VAID document with the Rust and Python mints is locked by the
 * vendored cross-language vector `vectors/mint_v1.json`.
 *
 * Per Decision B this is self-consistent WITHIN this repo (Rust == Python ==
 * TypeScript), NOT byte-conformant against the managed authority's VAID format.
 *
 * ```ts
 * import { InMemoryAudit, MintService, ReferenceIssuer } from 'vaid-mint';
 *
 * const issuer = ReferenceIssuer.ephemeral(24);
 * const mint = new MintService(issuer, new InMemoryAudit());
 * const { vaid } = await mint.mintRoot({
 *   seed: {
 *     agentClass: 'orchestrator',
 *     version: '1.0.0',
 *     tenantId: 'acme',
 *     scopeBoundary: ['data.acme'],
 *     capabilitySet: ['read'],
 *   },
 * });
 * console.assert(issuer.verifyVaid(vaid));
 * ```
 */

export {
  InMemoryAudit,
  NoopAudit,
  type AuditEntry,
  type AuditSink,
} from './audit.js';

export { DenyAll, PermitAll, type AuthorizationGate } from './authz.js';

export {
  buildUnsignedVaidDocument,
  canonicalVaidSigningBytes,
  computeLineageHash,
  hasCapability,
  isExpired,
  hasConformingTimestamps,
  isInScope,
  VAID_SIG_VERSION_V3,
  type AgentClass,
  type AgentId,
  type Rfc3339Utc,
  type TenantId,
  type Vaid,
  type VaidId,
} from './document.js';

export { AuditError, IdentityError, MintError, UnauthorizedError } from './error.js';

export {
  DEFAULT_VAID_TTL_HOURS,
  ReferenceIssuer,
  type IssueAttributes,
  type VaidIssuer,
} from './issuer.js';

export {
  capsAttenuate,
  MINT_POP_FRESHNESS_SECS,
  MintService,
  mintPopTimestamp,
  scopeAttenuates,
  tenantAttenuates,
} from './mint.js';

export {
  buildMintPopPayload,
  type MintPop,
  type MintPopPayload,
  type MintVaidRequest,
  type MintVaidResponse,
  type VaidSeed,
} from './mintTypes.js';

export {
  assembleLineage,
  InMemoryRevocationList,
  MAX_LINEAGE_DEPTH,
  parentResolutionOf,
  parentResolutionRoot,
  parentResolutionUnknown,
  RevocationStatus,
  type LineageResolver,
  type ParentResolution,
  type RevocationCheck,
} from './revocation.js';

export { verifyLineageHash, verifyVaidAuthenticity } from './verify.js';

export {
  ChainVerification,
  KernelKeyMap,
  PresentedBundle,
  SingleKernelKey,
  isAttenuated,
  verifyChain,
  verifyChainAt,
  verifyChainWith,
  type KernelKeyResolver,
} from './chain.js';

export {
  ATTESTATION_VERSION,
  AttestationBundle,
  buildUnsignedAttestation,
  canonicalAttestationSigningBytes,
  isCurrent,
  verifyAttestationAuthenticity,
  type ConsentAttestation,
} from './attestation.js';

export {
  kernelKeyThumbprint,
  isValidTrustDomain,
  isSpecialUseTrustDomain,
  THUMBPRINT_URI_PREFIX,
  TRUST_DOMAIN_MAX_LEN,
  TRUST_DOMAIN_MAX_LABEL_LEN,
} from "./issuerIdentity.js";
