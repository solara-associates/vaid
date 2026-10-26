# s442: property-level interop run against the AAT -02 JWS test suite

This is a draft, for review. It records two runs of VAID's native delegation
chain/verification API against the AAT (`draft-niyikiza-oauth-attenuating-agent-tokens`,
-02 reading) JWS test vector suite published at `tenuo-ai/tenuo`
(`tests/vectors/aat-jws-vectors.json`). The second run follows up on a
maintainer-provided mapping from VAID's own 14 hand-written interop vectors to
this suite, and corrects the first run's tendency to SKIP a vector whenever
AAT's own token *format* had no VAID counterpart, instead of checking whether
the *property* the vector tests does.

- Suite SHA-256: `2a3e607c9821a23e6190158cbb42a78273ee5833334b98b76f2e64867ca37929`
  (`draft-niyikiza-oauth-attenuating-agent-tokens-02`, 227 vectors)
- Implementation: `vaid-mint` (Rust), Apache-2.0, this repository
- Harness: `crates/vaid-mint/examples/aat_interop_harness.rs`
- Result: **agree 22, differ 0, skipped 205, missing 0** (first run: agree 12,
  skipped 215)

## What this run is

This is a **property-level** run, not a byte-level JWS conformance run. The
harness does not parse a JWS compact string and does not implement any part of
AAT's Section 8 algorithm. For every vector it can faithfully express, it
builds a **native VAID delegation chain** (real `Vaid` documents, really
Ed25519-signed by kernel keypairs the harness generates for the run) whose
structure mirrors the AAT scenario's underlying *property*, not its wire
format, and calls VAID's real, unmodified public verifier:

- `vaid_mint::chain::verify_chain_at`
- `Vaid::has_capability`
- `Vaid::is_expired_at`
- `vaid_mint::verify::verify_vaid_authenticity_graded` and
  `vaid_mint::document::boundary_is_evaluable` (composed directly, with the
  vector's own `now`, for the unknown-scope-kind vectors -- see below)
- `vaid_mint::verify::verify_vaid_standing_from_json` (one vector, for the
  duplicate-JSON-member check)

No verdict in `s442-results.json` was copied from the suite's own
`expected.verdict`. Where AAT tests a construct VAID's model genuinely has no
analogue for, after checking VAID's full surface (vaid-mint, vaid-pop, and the
a2a/adk/jwt-bridge integration packages), the harness emits `"SKIP"` with a
specific, per-scenario reason rather than guessing.

## The maintainer's mapping, and what it corrected

VAID's own hand-written interop vectors (`docs/a2a/v1/vectors/*.json`) map to
this suite as follows (all "same" = VAID's and AAT's expected verdicts agree):

| VAID vector | AAT id(s) | Note |
|---|---|---|
| 01 valid two-hop chain | J.3 | |
| 02 child scope wider than parent | J.11, J.19.11 | one property, two AAT predicate kinds |
| 03 expired leaf | J.13.c | |
| 05 action outside leaf scope | J.9.3, J.26.1 | |
| 06 unknown root key | J.14.c | |
| 08 capability not in parent | J.11.b | |
| 10 child outlives parent | J.13 | |
| 11 unrestricted child | J.19.15 | |
| 12 trust domain not bound to signing key | J.21.22 | added to the suite at VAID's suggestion |
| 13 unknown scope kind | J.8.3, J.8.5 | |
| 14 no privilege via unused field | J.9.6 | added to the suite at VAID's suggestion |
| 04 revocation, 07 prefix, 09 tenant | (none) | no AAT counterpart |

The first run SKIPped most of these because it read each AAT group
format-first ("AAT signs each hop with the holder's own key, VAID doesn't, so
SKIP the whole group") rather than asking what *property* the specific vector
tests. All 13 AAT ids in the table above now get a real, non-SKIP verdict from
this harness, and all 13 agree with the suite. The translations:

| AAT id(s) | VAID mechanism | Translation |
|---|---|---|
| J.3 | `verify_chain_at` over 3 hops | already present in the first run |
| J.11, J.19.11 | `scope_attenuates` (`ScopeEscalation`) | both AAT vectors assert "child claims authority the parent lacks" through a different predicate kind (`one_of` widened; a numeric `range` widened); VAID's one check for that property is scope-prefix containment, so the child's `scope_boundary` prefix is built as a non-sub-prefix of the parent's |
| J.13.c | composed `is_expired_at` | already present in the first run |
| J.9.3, J.26.1 | `Vaid::has_capability` | the leaf's `capability_set` never held the invoked tool; already present in the first run for J.9.3, extended to J.26.1 (same mechanism, same construction) |
| J.14.c | `verify_chain_at`'s key resolution | the document is self-consistent (its own `kernel_key_thumbprint` really does match the key that signed it) but that key is not in the verifier's trust set at all -- `Inauthentic`, for a different reason than J.14's bit-flip, which the harness already covered |
| J.11.b | `caps_attenuate` | the leaf requests a capability the parent never held, as opposed to J.9.3's "held, then dropped" |
| J.13 | `verify_chain_at`'s `expiry_attenuates` | already present in the first run |
| J.19.15 | `scope_attenuation_reason`'s empty-child guard | an empty (unrestricted) child `scope_boundary` under a non-empty (restricted) parent is `ScopeEscalation`, never `Attenuated` |
| J.21.22 | a trust-domain-bound key resolver, transliterated from the already-shipped fix | see "Resolving J.21.22" below |
| J.8.3, J.8.5 | `boundary_is_evaluable` / `UnknownScopeKind` | a `scope_boundary` entry of a kind outside `RECOGNISED_SCOPE_KINDS` fails closed at verify time, regardless of whether the invoked tool ever consults it (covers J.8.5's "not invoked" case too) |
| J.9.6 | `has_capability` | already present in the first run |

J.21.23 (the PERMIT-side sibling of J.21.22 -- a second trust anchor used
honestly) is not in the maintainer's table but was translated the same way, as
the natural positive control for the same mechanism; it also agrees (PERMIT).

## Resolving J.21.22: VAID's own vector 12 vs. the first run's "no analogue"

The first run reported J.21.22/J.21.23 as SKIP because of a real fact about
`vaid-mint`: `KernelKeyResolver::resolve_key` selects a verifying key by
thumbprint alone, and `verify_vaid_authenticity_graded` checks `trust_domain`
only for well-formedness, never against which trust anchor's key actually
verified the signature. Read on its own, that looked like it might mean VAID
cannot express -- or worse, is vulnerable to -- the exact issuer-confusion
property AAT's own J.21.22 and VAID's own hand-written vector 12 test.

It does not. VAID's own vector 12
(`docs/a2a/v1/vectors/12-trust-domain-not-bound-to-signing-key.json`) states
the property directly:

> Two legitimately trusted issuers, neither compromised. The leaf is signed,
> correctly, by the kernel key trusted for 'other.example', but claims
> trust_domain 'vaid.example' - the domain the OTHER trusted issuer's key is
> bound to. [...] A key is trusted for the trust domain trustedIssuers pairs
> it with, never for a domain a document claims, so this must be refused as
> issuer_mismatch.

`expected_result: "fail"`, `expected_error_code: "issuer_mismatch"`. Its own
`note` is explicit that this is a **known, already-fixed** class:
`GHSA-hfjh-v2x2-r58v`. `REPORT-307.md` in this repository is the fix
postmortem. The binding `vaid-mint`'s bare resolver does not carry (by
design -- see `mint.rs`'s `tenant_attenuates` docs: "the binding from a trust
domain to an authorized key set is out-of-band... and it lives outside this
crate") is implemented in the **integration layer**: `python/vaid-a2a/vaid_a2a/verifier.py`'s
`_TrustedIssuerMap`/`trust_domain_for` (binding each accepted key to exactly
one trust domain and returning `ISSUER_MISMATCH` on a mismatch), with the same
pattern shipped in `python/vaid-adk` and `python/vaid-jwt-bridge`.

So VAID does have a real analogue for J.21.22/J.21.23 -- it lives one layer
up from bare `vaid-mint`. This harness's second run transliterates that same
binding (a `TrustedIssuerMap` that checks `trust_domain_for(thumbprint) ==
doc.trust_domain()` before calling `verify_chain_at` at all) as a thin Rust
helper, and gets a real DENY for J.21.22 and a real PERMIT for J.21.23, both
agreeing with the suite.

**This is bucket (c), a harness translation error, not a VAID bug and not a
new security finding.** The advisory is old, already fixed, and already
public in this repository (`REPORT-307.md`, package `CHANGELOG.md`s, the
vector's own `note` field). It is not treated under this run's
security-disclosure rule for that reason.

## Why the rest of the suite is still SKIP

The remaining 205 SKIPs were re-examined the same way -- property first, not
format first -- against VAID's full surface (`vaid-mint`, `vaid-pop`, and the
a2a/adk/jwt-bridge packages), not just the chain/document API. None of them
turned up a further real VAID analogue; each reason below names the specific
construct that is actually missing, not a generic "unsupported":

| AAT group(s) | Topic | Why unrepresentable |
|---|---|---|
| J.2 | duplicate jti / cycle detection | not expressed in this pass; under review (see `BACKLOG.md`, "AAT interop hardening review") |
| J.4, J.12, J.20, J.21 (remainder) | holder-of-key chain signing, par_hash | VAID has one kernel key per chain; no per-hop distinct signer, no par_hash concept. (J.21.22/J.21.23 are the one sub-case with a real analogue, handled above.) |
| J.6 | per-invocation audience-bound PoP | VAID DOES have per-request proof of possession: `vaid-client` signs every request into the four `x-synthera-*` headers, via `vaid-pop`'s `RequestAuthPayload`/`sign_payload` primitives (`auth.rs`). This pass did not translate AAT's invocation-time PoP presentation (a fresh signature over the current holder's `cnf` key and an enforcement-point audience, bound to the specific tool call) into that model -- a gap in this pass's translation, not an absence of the mechanism in VAID |
| J.7, J.14 (parts), J.27 (parts) | JOSE header rules | VAID's wire format carries no JOSE header |
| J.8 (remainder), J.9 (parts), J.22 | per-argument constraint maps / closed-world argument checking | `capability_set` is a flat string list; VAID evaluates no tool-call arguments. (J.8.3/J.8.5's unrecognised-*kind* sub-case has a real analogue, handled above; the per-argument *value* algebra does not.) |
| J.10 | del_depth/del_max_depth consistency | VAID carries no such field; its only depth concept, `validate_max_delegation_depth`, is mint-time issuer policy, never re-derived at verify time |
| J.11 (remainder), J.15-J.19 (remainder), J.26 (remainder) | the AAT check-predicate algebra (`all`/`any`/`one_of`/`not_one_of`/`exact`) and its S4.5 subsumption table | VAID has no constraint-predicate language. (The widening/non-membership/empty-map instances in this range -- J.11, J.11.b, J.19.11, J.19.15, J.26.1 -- have real analogues via `scope_attenuates`/`caps_attenuate`, handled above; the richer set-algebra over named constraint values does not.) |
| J.13 (remainder) | iat ordering / MAX_IAT_SKEW / zero-lifetime bounds | not expressed in this pass; under review (see `BACKLOG.md`, "AAT interop hardening review") |
| J.23.2, J.23.3 | MAX_TOKEN_SIZE / MAX_CHAIN_SIZE | not expressed in this pass; under review (see `BACKLOG.md`, "AAT interop hardening review") |
| J.24 | JWS claim type/number admissibility | the harness builds native `Vaid` documents via `serde`; it parses no AAT JWS bytes, so there is no raw-claim-level check to run |
| J.25 | `authorization_details` entries of other types | VAID's document has no "entries"/"type" concept; `capability_set` is the sole grant list |

## What DID get a real verdict (22 vectors, 0 disagreements)

| Vector | Scenario | VAID mechanism exercised | Verdict (agrees with suite) |
|---|---|---|---|
| J.1 | minimal valid root (root == leaf) | `verify_chain_at` -> `Attenuated`, `has_capability` | PERMIT |
| J.3 | valid 3-level chain | `verify_chain_at` across 3 hops | PERMIT |
| J.5 | expired root | `is_expired_at` at the presented `now` | DENY |
| J.8.3 | unknown constraint_type, fail-closed at the leaf | `boundary_is_evaluable` -> `UnknownScopeKind` | DENY |
| J.8.5 | unknown constraint_type on a tool not invoked | `boundary_is_evaluable` -> `UnknownScopeKind` (same check, ignores which tool was called) | DENY |
| J.9.3 | tool dropped before the leaf | `Vaid::has_capability` | DENY |
| J.9.4 | prefix presentation of a valid chain | an intermediate hop presented as its own leaf | PERMIT |
| J.9.6 | tool named only by a claim VAID has no concept of | `has_capability` (the claim is simply never read) | DENY |
| J.11 | one_of widened (child scope wider than parent) | `scope_attenuates` -> `ScopeEscalation` | DENY |
| J.11.b | tool not present in parent at all | `caps_attenuate` | DENY |
| J.13 | derived exp beyond parent's exp | `verify_chain_at`'s `expiry_attenuates` | DENY |
| J.13.c | derived token expired, parent still valid | composed `is_expired_at` (leaf expiry is deliberately NOT part of `verify_chain_at` itself; VAID's own module docs say to check it separately) | DENY |
| J.14 | one bit flipped in the root signature | `verify_vaid_authenticity` -> `Inauthentic` | DENY |
| J.14.c | header-supplied / untrusted key is not used | key resolution finds no accepted key for the thumbprint -> `Inauthentic` | DENY |
| J.19.11 | derived numeric range widened | `scope_attenuates` -> `ScopeEscalation` (same mechanism as J.11) | DENY |
| J.19.15 | derived empty map under a closed parent | `scope_attenuation_reason`'s empty-child guard -> `ScopeEscalation` | DENY |
| J.21.22 | root `iss` names another trust anchor's issuer | transliterated trust-domain-bound resolver (see above) -> `issuer_mismatch`-equivalent DENY | DENY |
| J.21.23 | root signed honestly by the second trust anchor's key | same resolver, domain correctly bound | PERMIT |
| J.23.1 | empty chain (zero tokens presented) | no leaf exists to call any verifier with; DENY by construction | DENY |
| J.23.4 | duplicate member name in the signed claims | `has_duplicate_member_names` via `verify_vaid_standing_from_json` | DENY |
| J.26.1 | one_of rejects a value outside the set | `Vaid::has_capability` (same mechanism as J.9.3) | DENY |
| J.27.1 | unrecognized claims are ignored | round-tripped through `Vaid`'s `#[serde(flatten)] unknown_fields`, re-signed, still verifies | PERMIT |

## Possible VAID security issues

**None found.** Zero disagreements occurred in either run. The one
near-miss -- J.21.22's apparent "no analogue" in the first run -- resolved to
a harness translation error (see above), not a VAID defect: the binding AAT
and VAID's own vector 12 both require is already implemented and shipped in
VAID's a2a/adk/jwt-bridge integration layers, under an advisory
(`GHSA-hfjh-v2x2-r58v`) that is old, fixed, and already public in this
repository.

## Reproducing this run

```
cargo run -p vaid-mint --example aat_interop_harness -- \
  <path-to-tenuo-checkout>/tests/vectors/aat-jws-vectors.json \
  results.json
python3 ietf/vectors/compare_results.py results.json   # from inside the tenuo checkout
```
