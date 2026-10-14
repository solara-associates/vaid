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
| `unknown_scope_kind` | some presented document carries a `scope_boundary` entry of a `kind` this verifier does not recognise, so the boundary is refused rather than evaluated from the entries it could read (ADR-0009 S.10) |
| `issuer_mismatch` | the document's issuer is not trusted **for the trust domain it claims**: either the signing kernel key is not in the verifier's `trust_config` at all (vector `06`), or it is in it but bound to a different `trustDomain` than the document claims (vector `12`) |

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

Vectors `06` and `12` are both signed by a **second**, different test-only key
(seed `bytes([0x99]) * 32`, public key `My6-jSfLcyOzpAHBwTtd1kvMwOEOzaHCtdEaA3eaheU`,
thumbprint
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:wEnpSYrYOONNWTAK44zUMPY0sU44L_FJ_pXbXdkxFZs`).
They use it for opposite purposes, and must not be collapsed into one another:

- In `06` that key is **not in the trust config at all**, so a verifier has
  never been told to trust it. That is the point of the vector.
- In `12` it **is** in the trust config, bound to a second trust domain
  (`other.example`), and the document it signs claims `vaid.example` instead.
  `12` is therefore the only vector whose `trust_config` lists **two**
  issuers, and it has to be: with a single trusted issuer there is no other
  domain for a key to be misbound against, so the defect it covers
  (GHSA-hfjh-v2x2-r58v) is invisible. Both keys are legitimately trusted and
  neither is compromised; a verifier that resolves a kernel key by
  `kernel_key_thumbprint` alone finds a trusted key, verifies the signature
  against it, and **passes** — one issuer's key vouching for another
  issuer's identity. Refusing it requires carrying the pairing
  `trustedIssuers` declares (spec §2.1) and comparing a document's claimed
  `trust_domain` against the domain bound to the key that signed it, never
  the other way round (spec §5 step 1).

  Which key signs `12` and which domain it claims are both load-bearing:
  swapping either makes the vector pass, so a verifier cannot satisfy it by
  refusing everything. Vector `01` is the standing positive control for that.

**This key is test-only.** Its private material is a fixed, published byte
pattern (`0x42` repeated 32 times); it exists so these vectors are
byte-reproducible, never for any purpose requiring secrecy.

## Vectors 13 and 14: forward compatibility and no privilege via an unused field

Requested by an outside implementer who ran the published 0.1.1 conformance
set 12/12 clean (a2aproject/A2A#2028), as the two fixture kinds that set left
untested. Both are signed by the same fixed `0x42` test kernel key as 01-05
and 07-11; neither introduces a new error code.

- **`13-unknown-scope-kind-future-compat.json`** — a ROOT leaf (no parent, no
  presented chain) whose `scope_boundary` carries a `prefix` entry that
  matches `requested_action`, plus an `amount_limit` entry of a kind this
  verifier does not recognise. Spec §5 step 2a / ADR-0009 S.10 require the
  WHOLE boundary refused, `unknown_scope_kind`, even though the other entry
  would have matched on its own. It is a root deliberately: per-hop
  attenuation (step 4) only runs where there is a parent, so a root is the
  one shape where step 2a is the only thing standing between this boundary
  and an ALLOW.
- **`14-no-privilege-via-unused-field.json`** — a correctly signed, properly
  attenuated two-hop chain carrying an extra top-level field,
  `x_elevated_scope_boundary`, shaped like a WIDER `scope_boundary`
  (`data.acme`) than the real one (`data.acme.orders`). The signature covers
  the extra field (ADR-0006: an unrecognised document member is preserved,
  not dropped, before canonicalizing), so the document is authentic, not
  inauthentic. `requested_action` (`data.acme.customers`) is outside the
  REAL `scope_boundary` but inside the fabricated one. The expected verdict
  — `out_of_scope` — is exactly what this chain gets with the extra field
  absent: nothing in spec §5's verification order ever reads a field named
  anything but `scope_boundary` for this check, so the extra field buys the
  holder nothing.

Both are exercised against deliberately careless verifiers in
`python/vaid-a2a/tests/test_vector_positive_controls.py` — one that ignores
unknown scope kinds, one that unions the extra field into the scope check —
and both careless verifiers wrongly ALLOW; only the real verifier reaches the
vector's recorded verdict. Without that, "the vector passes the reference
verifier" would be the only evidence either vector is discriminating at all.

## Implementations that agree

Outside implementers who have run this vector set against their own
verifier and agreed to be listed:

| implementation | vector set / version | result | report |
|---|---|---|---|
| [giskard09/argentum-core](https://github.com/giskard09/argentum-core) | 0.1.1, then main / 0.2.0 | 12/12, then 14/14 (all verdicts and error codes matching) | [a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028#issuecomment-6125938510) |
| [aeoess/Agent Passport System](https://github.com/a2aproject/A2A/issues/2028#issuecomment-6148659932) | 0.1.1, sig_version 3 vectors only (01-12) | 12/12 | [aps-conformance-suite @ 1a25e5f](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/1a25e5fc4b002c1eaec46db4cfd9e36822a8cac4/interop/vaid-a2a-0.1.1-cleanroom-ca6077a2) |

Two conditions apply to the Agent Passport System row above, as agreed in
[a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028#issuecomment-6148659932):

- **Scope.** The result covers only the 12 `sig_version` 3 vectors in
  vaid-a2a 0.1.1. It does not cover `sig_version` 4, and it does not cover
  vectors 13 and 14.
- **Independence.** Vectors 01 to 06 were checked by a clean-room verifier
  written from the spec, importing nothing from VAID, so those results are
  independent. Vectors 07 to 12 came from Agent Passport System's own
  proposals and report, so the results on those vectors are the author's own
  runs, not independent checks.

If you run these vectors against your own implementation, open a PR or
issue with your results and we will add you here.

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
