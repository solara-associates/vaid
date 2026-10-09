# A2A extension test vectors

Deterministic test vectors for `docs/a2a/v1/extension.md`, used by the
reference verifier (`python/vaid-a2a/`). Each `NN-name.json` file has:

- `description` — what the vector exercises, in plain language.
- `trust_config` — the `trustedIssuers` list a verifier under test should be
  configured with before running this vector (mirrors the extension's
  `AgentCard` `params.trustedIssuers`, §2 of the spec), carrying the raw
  `kernelPublicKey` for each accepted issuer, not a bare thumbprint.
- `requested_action` — the action the incoming A2A message is asking to
  perform, for the "action within leaf scope" check (spec §5 step 5).
- `verification_time` — the RFC 3339 UTC instant (`Z` suffix) a verifier MUST
  evaluate this vector at. A verifier must never substitute its own wall
  clock: these vectors are pinned by distance from fixed `issued_at` /
  `expires_at` values (see `generate_vectors.py`), and evaluating at a
  different instant than the one recorded here is not running the vector as
  published.
- `inputs.leaf` — the VAID document that would travel under the extension's
  `/vaid` metadata key.
- `inputs.chain` — the ancestor VAID documents that would travel under
  `/vaidChain`, in no particular order.
- `revoked_vaid_ids` — the `vaid_id`s a test harness should mark revoked in
  its `RevocationCheck` before running this vector. Empty means nothing is
  revoked.
- `expected_result` — `"pass"` or `"fail"`.
- `expected_error_code` — one of the codes below, or `null` on a pass.

## Error codes used here

These are the reference verifier's internal reason codes (see
`a2a/python/vaid_a2a/verifier.py`), chosen to match the vocabulary
`vaid_mint.verify.VaidVerdict` and `vaid_mint.chain.ChainVerification` already
use, not a new taxonomy:

| code | meaning |
|---|---|
| `not_attenuated` | a hop's scope, capabilities, tenant or expiry is not contained by its parent's |
| `expired` | the leaf (or an ancestor) has passed its own `expires_at` |
| `revoked` | some VAID in the lineage is revoked (R.4.4) |
| `out_of_scope` | the chain attenuates correctly, but the requested action is outside the leaf's own `scope_boundary` |
| `issuer_mismatch` | the document is signed by a kernel key the verifier's `trust_config` does not list |

## The test key

Vectors `01` through `05` and `07` through `11` are signed by a single fixed,
**test-only** Ed25519 kernel key, generated from the 32-byte seed `bytes([0x42]) * 32` — see
`generate_vectors.py`. Its raw public key, base64url-encoded (the value each
vector's own `trust_config.trustedIssuers[0].kernelPublicKey` already
carries, per spec §2 — a verifier derives the thumbprint from this, never
from a bare thumbprint supplied separately) is:

```
IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI
```

which derives to thumbprint
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:nEArpjG3kYMcxbdzInyGlBEYQUw7RfAfe3Tw1fZvAA0`.

Vector `06` is deliberately signed by a **second**, different test-only key
(seed `bytes([0x99]) * 32`, public key `My6-jSfLcyOzpAHBwTtd1kvMwOEOzaHCtdEaA3eaheU`,
thumbprint
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:wEnpSYrYOONNWTAK44zUMPY0sU44L_FJ_pXbXdkxFZs`)
that a verifier configured with only the `01`-`05` trust config has never been
told to trust — that is the point of the vector.

**This key is test-only.** Its private material is a fixed, published byte
pattern (`0x42` repeated 32 times); it exists so these vectors are
byte-reproducible, never for any purpose requiring secrecy.

## Reproducing

```sh
cd vaid   # repo root
PYTHONPATH=python/vaid-mint python3 docs/a2a/v1/vectors/generate_vectors.py
```

Regenerating is deterministic: the script fixes the kernel key, every
`vaid_id` (via a small-integer-to-UUID helper), and every timestamp, so a
fresh run reproduces the existing `*.json` files byte for byte. There is
nothing to "update" here short of deliberately changing a vector's shape.

Requires `vaid-mint`'s runtime dependencies (`cryptography`, `rfc8785`,
`vaid-pop`) importable — e.g. from an editable install:
`pip install -e python/vaid-pop -e python/vaid-mint`.
