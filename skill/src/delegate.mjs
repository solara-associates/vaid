/**
 * Minting an attenuated child, including the part the reference mint requires and
 * a caller is easy to catch out by.
 *
 * `MintService.mintChild` is always **BYO-key**: a delegated child must register a
 * holder key it controls, and prove control with a proof-of-possession signature
 * over the canonical mint-PoP payload. Calling `mintChild` the way you call
 * `mintRoot` fails with `IdentityError: BYO-key required`, which is the mint
 * refusing to issue a delegated identity to a key nobody demonstrated they hold.
 *
 * That requirement is correct and this module does not work around it — it
 * generates the child's holder keypair, signs the PoP with it, and keeps the
 * private half so the child can later authenticate requests with `vaid-client`. A
 * delegated VAID whose holder key was thrown away is a credential nobody can use.
 */

import { buildMintPopPayload, mintPopTimestamp } from 'vaid-mint';
import { ed25519PublicKey, randomEd25519Seed, randomHex, signPayload } from 'vaid-pop';

/**
 * Mint an attenuated child of `parent` through `svc`, returning the VAID and the
 * holder seed that was registered for it.
 *
 * The caller owns storing the seed. It is returned rather than persisted here so
 * that this module stays free of the filesystem and can be tested without one.
 */
export async function mintAttenuatedChild(svc, parent, seedInput) {
  const holderSeed = randomEd25519Seed();
  const publicKeyDer = ed25519PublicKey(holderSeed);

  const seed = {
    ...seedInput,
    parentVaid: parent.vaid_id,
    publicKeyDer,
  };

  // Nonce and timestamp are the mint's replay and freshness guards. 16 bytes is
  // the ≥128 random bits the spec asks for; the timestamp must be whole-second
  // UTC or the mint rejects it before it looks at the signature.
  const nonce = randomHex(16);
  const issuedAt = mintPopTimestamp();
  const payload = buildMintPopPayload(seed, { publicKeyDer, nonce, issuedAt });
  const signature = signPayload(payload, holderSeed);

  const { vaid } = await svc.mintChild({ seed, pop: { nonce, issuedAt, signature } }, parent);

  return { vaid, holderSeed, publicKeyDer };
}
