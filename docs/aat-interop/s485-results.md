# s485: AAT -02 JWS interop run refreshed against the 229-vector suite

This refreshes [`s442-results.md`](s442-results.md) against the current AAT
(`draft-niyikiza-oauth-attenuating-agent-tokens`, -02 reading) JWS test vector
suite published at `tenuo-ai/tenuo` (`tests/vectors/aat-jws-vectors.json`),
which has grown from 227 to 229 vectors since the s442 run. The maintainer
(`aimable100`) independently reproduced the s442 result on
[tenuo-ai/tenuo#1001](https://github.com/tenuo-ai/tenuo/issues/1001) and asked
for a rerun against the current suite plus a PR adding VAID to
`ietf/vectors/INTEROP.md`. This is that rerun.

- Suite SHA-256: `b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b`
  (`draft-niyikiza-oauth-attenuating-agent-tokens-02`, 229 vectors), at
  `tenuo-ai/tenuo@ace40970046a6befdedce13e3cdbff4fe9b426b6`
- Implementation: `vaid-mint` (Rust) 0.11.0, Apache-2.0, this repository
- Harness: `crates/vaid-mint/examples/aat_interop_harness.rs` (unchanged from
  s442; see that file and [`s442-results.md`](s442-results.md) for what it
  does and does not do)
- Result: **agree 22, differ 0, skipped 207, missing 0**

## What changed since s442

Nothing in the harness or in VAID. The suite grew by two vectors (227 to
229); both land inside groups the s442 run already SKIPs for a named,
per-scenario reason (the predicate-algebra and JOSE/claim-type groups), so the
agree set is the same 22 vectors, with the same verdicts, as s442. The 22
agreements, the per-group SKIP reasons, the J.21.22/J.21.23 resolution, and
the "possible VAID security issues: none found" conclusion in
[`s442-results.md`](s442-results.md) all stand unchanged; this file only
updates the counts and the suite hash they were run against.

Full results: [`s485-results.json`](s485-results.json).

## Skip reasons by group (207 total)

| Group | Count | Why unrepresentable |
|---|---|---|
| J.11.c/d, J.15-J.19 (remainder) | 50 | AAT check-predicate algebra (`all`/`any`/`one_of`/`not_one_of`/`exact`) and its S4.5 subsumption table; VAID has no constraint-predicate language |
| J.12, J.20, J.21 (remainder), J.4 (remainder) | 43 | holder-of-key per-hop chain signing, `par_hash`; VAID has one kernel key per chain |
| J.22 | 23 | per-argument constraint maps / closed-world argument checking |
| J.8 (remainder) | 22 | per-argument constraint maps (same mechanism as J.22, different group) |
| J.7 | 15 | JOSE header rules; VAID's wire format carries no JOSE header |
| J.24 | 11 | JWS claim type/number admissibility; the harness builds native `Vaid` documents, it parses no raw JWS bytes |
| J.6 (remainder) | 11 | per-invocation audience-bound PoP presentation; VAID has per-request PoP but this pass did not translate AAT's presentation into it |
| J.25 | 10 | `authorization_details` entries of other types; VAID's document has no "entries"/"type" concept |
| J.10 | 6 | `del_depth`/`del_max_depth` consistency; VAID carries no such field |
| J.27 (remainder) | 5 | non-JCS-canonical byte attacks, same-holder-key derivation, `aud` array/mismatch, JOSE-header JWK shape |
| J.13 (remainder) | 4 | `iat` ordering / `MAX_IAT_SKEW` / zero-lifetime bounds |
| J.9 (remainder) | 3 | per-argument constraint maps (same mechanism as J.8/J.22) |
| J.23.2, J.23.3 | 2 | `MAX_TOKEN_SIZE`/`MAX_CHAIN_SIZE` byte-size limits; VAID defines no analogous cap |
| J.14.b | 1 | JOSE header rules (same mechanism as J.7) |
| J.2 | 1 | duplicate-`jti` cycle detection over a presented chain; VAID's dedup/cycle checks do not construct this scenario |

Per-vector reasons are in [`s485-results.json`](s485-results.json); the full
narrative (per-group detail, the J.21.22 resolution, the maintainer's 14
vector mapping) is in [`s442-results.md`](s442-results.md), unchanged.

## Possible VAID security issues

None found. Zero disagreements, zero missing, against either suite revision.

## Reproducing this run

```
cargo run -p vaid-mint --example aat_interop_harness -- \
  <path-to-tenuo-checkout>/tests/vectors/aat-jws-vectors.json \
  results.json
python3 ietf/vectors/compare_results.py results.json   # from inside the tenuo checkout
```
