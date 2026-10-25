# s442: property-level interop run against the AAT -02 JWS test suite

This is a draft, for review. It records one run of VAID's native delegation
chain/verification API against the AAT (`draft-niyikiza-oauth-attenuating-agent-tokens`,
-02 reading) JWS test vector suite published at `tenuo-ai/tenuo`
(`tests/vectors/aat-jws-vectors.json`).

- Suite SHA-256: `2a3e607c9821a23e6190158cbb42a78273ee5833334b98b76f2e64867ca37929`
  (`draft-niyikiza-oauth-attenuating-agent-tokens-02`, 227 vectors)
- Implementation: `vaid-mint` (Rust), Apache-2.0, this repository, commit at
  which this was run (see the harness's git history)
- Harness: `crates/vaid-mint/examples/aat_interop_harness.rs`
- Result: **agree 12, differ 0, skipped 215, missing 0**

## What this run is

This is a **property-level** run, not a byte-level JWS conformance run. The
harness does not parse a JWS compact string and does not implement any part of
AAT's Section 8 algorithm. For every vector it can faithfully express, it
builds a **native VAID delegation chain** (real `Vaid` documents, really
Ed25519-signed by a kernel keypair the harness generates for the run) whose
structure mirrors the AAT scenario, and calls VAID's real, unmodified public
verifier:

- `vaid_mint::chain::verify_chain_at`
- `Vaid::has_capability`
- `Vaid::is_expired_at`
- `vaid_mint::verify::verify_vaid_standing_from_json` (one vector, for the
  duplicate-JSON-member check)

No verdict in `s442-results.json` was copied from the suite's own
`expected.verdict`. Where AAT tests a construct VAID's model has no analogue
for, the harness emits `"SKIP"` with a specific, per-scenario reason rather
than guessing.

## Why most of the suite is SKIP

AAT's wire format is a chain of JWS tokens where **each hop is signed by the
previous hop's own holder key** (`cnf.jwk`), carries a rich per-argument
constraint algebra (`all`/`any`/`one_of`/`not_one_of`/`exact`, closed-world
argument checking against a tool call), JOSE headers, and byte-level JSON
number-admissibility/canonicalization rules.

VAID's delegation model is structurally different: **one issuer's kernel key
signs every hop** of a chain (`KernelKeyResolver` selects a verifying key by
key thumbprint only), and attenuation narrows a flat `capability_set` list and
a resource-prefix `scope_boundary`, with no per-argument constraint map, no
JOSE header, and no del_depth/del_max_depth claim tracked at verify time.

That gap is the dominant finding of this run. It is not a bug in either
implementation -- it is two different trust models for the same problem
(attenuating delegation), and translating the groups below would mean
inventing a VAID check that does not exist:

| AAT group(s) | Topic | Why unrepresentable |
|---|---|---|
| J.2 | duplicate jti / cycle detection | `PresentedBundle` dedupes a repeated id (last-write-wins); VAID's real cycle detection only fires on an actual parent-pointer cycle |
| J.4, J.12, J.20, J.21 | holder-of-key chain signing, par_hash, multiple trust anchors | VAID has one kernel key per chain, selected by thumbprint only; no per-hop distinct signer, no anchor-by-issuer-identity selection |
| J.6 | per-invocation audience-bound PoP | VAID's PoP is a mint-time BYO-key proof, not a per-call presentation |
| J.7, J.14 (parts), J.27 (parts) | JOSE header rules | VAID's wire format carries no JOSE header |
| J.8, J.9 (parts), J.22 | per-argument constraint maps / closed-world argument checking | `capability_set` is a flat string list; VAID evaluates no tool-call arguments |
| J.10 | del_depth/del_max_depth consistency | VAID carries no such field; its only depth concept is mint-time issuer policy |
| J.11, J.15-J.19, J.26 | the AAT check-predicate algebra and its subsumption table | VAID has no constraint-predicate language at all |
| J.13 (parts) | iat ordering / MAX_IAT_SKEW / zero-lifetime bounds | `verify_chain_at` checks only expiry attenuation, never iat ordering or skew |
| J.23.2, J.23.3 | MAX_TOKEN_SIZE / MAX_CHAIN_SIZE | VAID defines no byte-size cap anywhere in its verification surface |
| J.24 | JWS claim type/number admissibility | the harness builds native `Vaid` documents; it parses no AAT JWS bytes |
| J.25 | `authorization_details` entries of other types | VAID's document has no "entries"/"type" concept; `capability_set` is the sole grant list |

The full, per-group reason text is in the harness source and is reproduced
verbatim in each `SKIP` entry of `s442-results.json`.

## What DID get a real verdict (12 vectors, 0 disagreements)

| Vector | Scenario | VAID mechanism exercised | Verdict (agrees with suite) |
|---|---|---|---|
| J.1 | minimal valid root (root == leaf) | `verify_chain_at` -> `Attenuated`, `has_capability` | PERMIT |
| J.3 | valid 3-level chain | `verify_chain_at` across 3 hops | PERMIT |
| J.5 | expired root | `is_expired_at` at the presented `now` | DENY |
| J.9.3 | tool dropped before the leaf | `Vaid::has_capability` | DENY |
| J.9.4 | prefix presentation of a valid chain | an intermediate hop presented as its own leaf | PERMIT |
| J.9.6 | tool named only by a claim VAID has no concept of | `has_capability` (the claim is simply never read) | DENY |
| J.13 | derived exp beyond parent's exp | `verify_chain_at`'s `expiry_attenuates` | DENY |
| J.13.c | derived token expired, parent still valid | composed `is_expired_at` (leaf expiry is deliberately NOT part of `verify_chain_at` itself; VAID's own module docs say to check it separately) | DENY |
| J.14 | one bit flipped in the root signature | `verify_vaid_authenticity` -> `Inauthentic` | DENY |
| J.23.1 | empty chain (zero tokens presented) | no leaf exists to call any verifier with; DENY by construction | DENY |
| J.23.4 | duplicate member name in the signed claims | `has_duplicate_member_names` via `verify_vaid_standing_from_json` | DENY |
| J.27.1 | unrecognized claims are ignored | round-tripped through `Vaid`'s `#[serde(flatten)] unknown_fields`, re-signed, still verifies | PERMIT |

## The three vectors added at VAID's own suggestion

- **J.9.6** ran to a real verdict (DENY, agrees).
- **J.21.22** and **J.21.23** (the second-trust-anchor vectors) both came out
  SKIP. VAID's `KernelKeyResolver` trait resolves a verifying key by key
  thumbprint alone (`crates/vaid-mint/src/chain.rs`, `resolve_key`); nothing in
  `verify_vaid_authenticity_graded` (`crates/vaid-mint/src/verify.rs`)
  cross-checks a document's `trust_domain` against the specific trust anchor
  whose key verified the signature -- `trust_domain` is checked only for
  well-formedness. These two vectors turn on exactly that cross-check (RFC
  8725 Section 3.8), which VAID's resolver model does not implement, so there
  is no VAID code path to run them against. This is flagged here because
  these are vectors the suite exists, in part, to exercise.

## Reproducing this run

```
cargo run -p vaid-mint --example aat_interop_harness -- \
  <path-to-tenuo-checkout>/tests/vectors/aat-jws-vectors.json \
  results.json
python3 ietf/vectors/compare_results.py results.json   # from inside the tenuo checkout
```
