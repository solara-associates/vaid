#!/usr/bin/env node
/**
 * Generates the four "Try an example" fixtures for the standalone verify page,
 * using the published `vaid-mint` package only (no private copy).
 *
 * Each fixture is a JSON file under ../samples/ with the shape:
 *   {
 *     "label": "...",
 *     "kernelPublicKeyHex": "<32-byte Ed25519 public key, hex>",
 *     "documents": [root, ...ancestors, leaf]   // root-first
 *   }
 *
 * Run: node scripts/generate-samples.mjs   (from docs/verify/)
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  buildUnsignedVaidDocument,
  canonicalVaidSigningBytes,
  computeLineageHash,
  kernelKeyThumbprint,
  prefixEntry,
} from 'vaid-mint';
import { ed25519PublicKey, ed25519Sign, toHex } from 'vaid-pop';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SAMPLES_DIR = join(__dirname, '..', 'samples');

const TRUST_DOMAIN = 'vaid.example';

/**
 * A single kernel keypair every sample is signed under, so one pasted key
 * verifies all of them. Fixed, not random: this script is re-run in CI to
 * confirm the committed samples are still what it produces, so its output
 * must be reproducible byte for byte.
 */
const kernelSeed = new Uint8Array(32).fill(7);
const kernelPublicKey = ed25519PublicKey(kernelSeed);
const kernelPublicKeyHex = toHex(kernelPublicKey);

let nextId = 1;
function vid() {
  const hex = String(nextId++).padStart(32, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Build and kernel-sign a VAID document directly (bypassing `MintService`'s
 * attenuation checks), the same technique the package's own
 * `test/chain_verification.test.ts` uses to construct authentic-but-adversarial
 * chains for the negative conformance cases below.
 */
function signDocument({ agentClass, tenantId, parentVaid, scope, caps, issuedAt, expiresAt }) {
  const agentId = vid();
  const unsigned = buildUnsignedVaidDocument({
    vaidId: agentId,
    agentId,
    agentClass,
    version: '1.0.0',
    tenantId,
    issuedAt,
    expiresAt,
    publicKeyDer: Array.from({ length: 32 }, (_, i) => i),
    parentVaid,
    scopeBoundary: scope.map(prefixEntry),
    lineageHash: computeLineageHash(parentVaid, agentId),
    capabilitySet: caps,
    trustDomain: TRUST_DOMAIN,
    kernelKeyThumbprint: kernelKeyThumbprint(kernelPublicKey),
  });
  const signature = ed25519Sign(canonicalVaidSigningBytes(unsigned), kernelSeed);
  return { ...unsigned, kernel_signature: Array.from(signature) };
}

const FAR_FUTURE = '2099-01-01T00:00:00Z';
const PAST = '2024-01-01T00:00:00Z';
const NOW_ISH = '2026-01-01T00:00:00Z';

function write(filename, label, documents) {
  const body = { label, kernelPublicKeyHex, documents };
  writeFileSync(join(SAMPLES_DIR, filename), JSON.stringify(body, null, 2) + '\n');
  console.log(`wrote samples/${filename} (${documents.length} document(s))`);
}

// ── 1. A valid two-hop chain: root -> delegate -> leaf, every hop contained ──
{
  const root = signDocument({
    agentClass: 'orchestrator',
    tenantId: 'acme',
    parentVaid: null,
    scope: ['data.acme'],
    caps: ['read', 'write'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  const mid = signDocument({
    agentClass: 'infra-agent',
    tenantId: 'acme',
    parentVaid: root.vaid_id,
    scope: ['data.acme.deploy'],
    caps: ['read', 'write'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  const leaf = signDocument({
    agentClass: 'infra-agent-sub',
    tenantId: 'acme',
    parentVaid: mid.vaid_id,
    scope: ['data.acme.deploy.us-east'],
    caps: ['read'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  write('valid-two-hop.json', 'A valid two-hop chain', [root, mid, leaf]);
}

// ── 2. Scope widens: the child claims MORE than its parent held ──────────────
{
  const root = signDocument({
    agentClass: 'orchestrator',
    tenantId: 'acme',
    parentVaid: null,
    scope: ['data.acme.sales'],
    caps: ['read'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  // Not minted through MintService (which would refuse this): signed directly,
  // so it is authentic but was never legitimately delegated.
  const leaf = signDocument({
    agentClass: 'runaway-agent',
    tenantId: 'acme',
    parentVaid: root.vaid_id,
    scope: ['data.acme'], // wider than the parent's data.acme.sales
    caps: ['read'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  write('scope-widens.json', 'Scope widens partway down the chain', [root, leaf]);
}

// ── 3. Expired credential: the leaf's own validity window has passed ─────────
{
  const root = signDocument({
    agentClass: 'orchestrator',
    tenantId: 'acme',
    parentVaid: null,
    scope: ['data.acme'],
    caps: ['read'],
    issuedAt: PAST,
    expiresAt: FAR_FUTURE,
  });
  const leaf = signDocument({
    agentClass: 'batch-job-agent',
    tenantId: 'acme',
    parentVaid: root.vaid_id,
    scope: ['data.acme.reports'],
    caps: ['read'],
    issuedAt: PAST,
    expiresAt: PAST, // already lapsed
  });
  write('expired-credential.json', 'An expired credential', [root, leaf]);
}

// ── 4. Tampered byte: a valid chain, with one byte of a signature flipped ────
{
  const root = signDocument({
    agentClass: 'orchestrator',
    tenantId: 'acme',
    parentVaid: null,
    scope: ['data.acme'],
    caps: ['read', 'write'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  const leaf = signDocument({
    agentClass: 'infra-agent-sub',
    tenantId: 'acme',
    parentVaid: root.vaid_id,
    scope: ['data.acme.deploy'],
    caps: ['read'],
    issuedAt: NOW_ISH,
    expiresAt: FAR_FUTURE,
  });
  const tamperedLeaf = {
    ...leaf,
    kernel_signature: leaf.kernel_signature.map((b, i) => (i === 0 ? b ^ 0x01 : b)),
  };
  write('tampered-byte.json', 'A tampered byte', [root, tamperedLeaf]);
}

console.log(`kernel public key (hex, shared by every sample): ${kernelPublicKeyHex}`);
