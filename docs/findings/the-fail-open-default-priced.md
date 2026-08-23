# Flipping the reference revocation default, priced from the code

**Date:** 2026-08-23
**Repo:** `vaid`
**Status:** CLOSED 2026-08-23. **Decision taken by A. Smeyatsky: flip it.** Shipped
in `vaid-mint` 0.8.0 in all three languages, with `assuming_nothing_revoked()` landing
simultaneously and `with_revocation_check` removed in the same release. **Prepared,
not published** — the publish is gated on the decision owner. The measurement below
is what the decision was taken against and is left as written.
Original status: OPEN — a recommendation, not a change.
**Question asked:** does a fail-open default belong in our public package under our
name — and what does flipping it actually cost, read from the code rather than
assumed?
**Supersedes on this point:** the "argument each way" section of
`the-reference-revocation-default-is-documented-not-hidden.md`, which correctly
declined to take the decision and left the cost unmeasured.

---

## The premise is not in dispute

`InMemoryRevocationList::assume_nothing_revoked()` is the shipped default of
`ReferenceIssuer`. Its own docstring calls it *"a fail-open posture reached by
assumption."* It is **properly disclosed** — R.6 carries a titled note that names
the constructor, states the exact failure verbatim, argues its legitimacy under
R.4.6, explicitly disclaims it under R.4.5, and gives both remediations. This is not
a hidden defect, and the specification is better than the estate's summary of it.

The question is narrower and is a product question: a correctly-disclosed fail-open
default is still a fail-open default.

## What actually breaks — measured, not estimated

The flip is one line per language: `ReferenceIssuer`'s constructor builds
`InMemoryRevocationList::new()` (absent) instead of `assume_nothing_revoked()`.
Applied to all three implementations and the full suites run:

| | failures | class |
|---|---|---|
| Rust | 7 | 4 in `issuer`/`mint` unit tests, 3 in `revocation_seam` |
| Python | 5 | `test_revocation.py`, `test_mint_behavior.py` |
| TypeScript | 4 | `revocation_seam.test.ts`, `mint_behavior.test.ts` |

**VERIFIED**, by running it. Sixteen failures, and every one of them is the same
sentence: *a bare issuer no longer verifies what it just minted.* There is no second
failure mode.

> **Correction, 2026-08-23 (same day).** This table first read `Rust | 4` and
> "thirteen failures". The Rust figure was an undercount, and the cause is worth
> recording because it will recur: `cargo test --workspace` runs one binary per test
> target and prints a `failures:` block per binary, and the command used to count
> them (`sed -n '/^failures:$/,/^test result: FAILED/p'`) captures only the **first**
> block. Three failures in `tests/revocation_seam.rs` were therefore invisible, and
> only surfaced when the four in the lib binary were fixed and the next binary's
> block became the first. `grep -c '^test .* \.\.\. FAILED$'` counts all of them.
> The corrected figure changes no conclusion — the class is identical and the
> recommendation is unaffected — but a number that reached a document is a claim, and
> this one was wrong by three.

Four things did **not** break, and each one narrows the blast radius:

1. **Minting is untouched.** `MintService` never calls `verify_vaid` — the only
   occurrence in `mint.rs` is inside a test. **VERIFIED.** Issuance, attenuation and
   scope containment are unaffected.
2. **No conformance vector is affected.** Revocation is outside the conformance
   surface (R.1), and `verdict_v1.json` takes revocation status as an *input*
   (`revocation_states: ["not_revoked","revoked","unavailable"]`) rather than
   deriving it. `mint_conformance`, `chain_conformance` and `verdict_conformance`
   stayed green under the flip; `verify-vector-freeze` reports 32 vectors unchanged.
   **VERIFIED.**
3. **Authenticity is untouched.** `verify_vaid_authenticity` never consults
   revocation (R.7). Third-party, offline and cross-organisation verification —
   the portable property that is the point of a VAID — does not change. **VERIFIED.**
4. **`vaid-skill` is untouched.** The one downstream consumer inside this repository
   verifies authenticity and reports revocation as `NotChecked`; it never calls
   `verifyVaid`. Green under the flip. **VERIFIED.**

## What it costs commercially: measured at zero inside the estate

Swept every repository under `~/solara` for calls to the issuer method
`.verify_vaid(` / `.verifyVaid(` — 150 call sites outside `vaid` itself, in two
repositories, and **not one of them is `vaid-mint`'s `ReferenceIssuer`**:

- **`synthera`** (112 sites) — `synthera-kernel`'s own identity service. The
  workspace depends on `vaid-pop` only; `vaid-mint` is not a dependency of any
  synthera crate. The production mint shares no code with `vaid-mint`. **VERIFIED.**
- **`aifactory`** (a handful) — `aif-adapters-vaid`'s own method, which calls the
  substrate over HTTP (`POST /tools/call`). **VERIFIED.**
- **`forge-agents`** — **zero** issuer-method call sites. The agent templates state
  in their own requirements that what they call is `verify_vaid_authenticity` and
  `is_expired`. **VERIFIED.**

So the estate's exposure is nil, and the instinct that this "costs nothing
commercially" is correct — but for a reason worth stating precisely, because it cuts
the other way too: **nothing we run depends on `ReferenceIssuer::verify_vaid`.** The
population that would feel the flip is external self-hosters, whose size is not
observable from here. **OPEN.**

## The real cost, and it is the one R.6 already named

The quickstart. Every README in three languages, and every first thing an evaluator
types:

```rust
let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")?;
let vaid = mint.mint(...)?;
assert!(issuer.verify_vaid(&vaid));   // ← false, after the flip
```

R.6's stated argument against flipping is exactly this: it *"breaks first-run
experience for every new adopter and every quickstart — the exact usability the
current default was chosen to buy."* That argument is sound and the measurement
above does not weaken it. It is the whole cost.

It is also cheap to buy back, and buying it back is what turns this from a trade
into an improvement.

## Recommendation

**Flip it — but not on its own. Flip it together with a named one-line opt-in, or
not at all.**

The flip alone converts a silent fail-open into a broken quickstart, which is a
worse product for a better posture. The flip *plus* a named constructor converts a
silent fail-open into an **explicit** one:

```rust
let issuer = ReferenceIssuer::ephemeral(1, "vaid.example")?.assuming_nothing_revoked();
```

That is one line, it is self-describing at the call site, and it is strictly better
than today: the same posture, reached by naming it rather than by not thinking about
it. R.4.5 already demands exactly this discipline of fail-open — *"it MUST NOT be the
default"*, *"it MUST be named to state what it does"*. R.6 currently argues R.4.5
does not apply, because this is a development default rather than a verifier
setting. That argument is correct, and it is a **carve-out** — one that exists only
because the posture is a default. Remove the default and the carve-out is not needed,
which is a better place for the specification to be.

Precondition, and it is a hard one: **the one-line opt-in must land in the same
release as the flip.** Without it the only way back to the old behaviour is
constructing a `RevocationBackend` by hand with both halves, and a flip whose remedy
is four lines of boilerplate is not tolerable at any version.

Second precondition: **all three languages in the same release.** A default that is
fail-closed in Rust and fail-open in Python is worse than not flipping — it makes
the reference implementations disagree about a safety property while every
conformance vector still passes, which is precisely the class of divergence the
vectors exist to prevent and cannot see.

## Semver

`vaid-mint` is at **0.7.0** on all three registries, so "major" is not on the table
short of declaring 1.0. The real choice is 0.8.0-with-a-BREAKING-heading, or holding
it for 1.0.

**Recommendation: 0.8.0, marked BREAKING in all three changelogs.**

- **A default change is a breaking change**, whatever the version arithmetic says:
  `verify_vaid` returns `false` where it returned `true`, for the same inputs, with
  no signature change to signal it. It compiles clean and fails at runtime, which is
  the worse of the two failure shapes.
- **Pre-1.0, a minor bump is the conventional breaking vehicle in two of the three
  ecosystems.** Cargo treats `0.7 → 0.8` as incompatible; npm's `^0.7.0` resolves to
  `>=0.7.0 <0.8.0`. Neither picks it up automatically.
- **The third is ambiguous.** A Python pin of `~=0.7` admits `>=0.7,<1.0` and *would*
  pick up 0.8.0 silently; `~=0.7.0` would not. How downstreams actually pin is not
  observable from this repository — **OPEN** — so the release note must say this
  explicitly rather than relying on the convention holding.
- **Holding it for 1.0 is the worse trade.** It keeps a fail-open default in a
  published package for an indefinite period, in exchange for avoiding one loud minor
  bump on a package whose measured blast radius is one method's return value on a
  bare issuer.

Not a candidate: shipping the flip as a patch, or as a silent change inside a release
whose headline is something else.

## Migration note, as it should read

> **BREAKING — the reference issuer now fails closed out of the box.**
>
> `ReferenceIssuer` previously defaulted its revocation store to
> `assume_nothing_revoked()`: it vouched `NotRevoked` over an empty set, so a fresh
> issuer verified immediately. Because the store is non-durable it could not detect
> its own restart, so a VAID revoked before a restart verified clean afterwards.
> That is a fail-open posture, and it was the default.
>
> It is now **absent** by default: `revocation_status` reports `Unavailable` and
> `verify_vaid` returns `false` until revocation state has been loaded. Verification
> fails closed (R.4.5). **Minting, attenuation, scope containment and
> `verify_vaid_authenticity` are unchanged**, as are all conformance vectors —
> revocation is outside the conformance surface (R.1).
>
> You are affected only if you call `ReferenceIssuer::verify_vaid` or
> `revocation_status` on an issuer you have not given a revocation backend. Three
> ways forward, in order of preference:
>
> 1. **Inject a durable backend** — `with_revocation_backend(RevocationBackend::new(check, lineage))`.
>    Both halves are required; see R.4.6 for why one is not enough.
> 2. **Load your revocation state, then vouch.** An absent store answers
>    `Unavailable` and fails closed *until* the load completes, which is a
>    deliberate, brief, visible outage rather than a silent window of unrevoked
>    credentials.
> 3. **Keep the old behaviour explicitly** — `ReferenceIssuer::ephemeral(...)?.assuming_nothing_revoked()`.
>    Identical to the previous default. It is fine for local development and tests;
>    it is a fail-open posture, and this spelling says so at the call site.

## Outcome

Both recommendations were accepted as written, on 2026-08-23, including the hard
precondition: the flip and the named opt-in ship together, in one release, in all
three languages. The second breaking change — removing `with_revocation_check` — was
taken in the same release on the same argument: it is deprecated and still reaches the
half-state, and a deprecation window is a period during which the reachable failure
stays reachable.

Recorded for the next reader: the estate sweep found **zero** consumers of
`ReferenceIssuer::verify_vaid`, and the one in-repo consumer, `vaid-skill`, pins
`vaid-mint` at `^0.6.0` — which npm resolves to `>=0.6.0 <0.7.0`, so it currently
installs 0.6.0 and will not follow this release at all. **VERIFIED** by reading the
resolved `skill/node_modules/vaid-mint/package.json`. Moving the skill onto 0.8.0 is a
separate decision and a separate release.

## Marking

- Everything labelled **VERIFIED** above was run or read on `main` at the time of
  writing: the flip was applied to all three implementations, the three suites were
  run, the estate was swept, and the tree was restored.
- **OPEN**: the size and pinning habits of the external self-hoster population —
  the only group the flip actually reaches — are not observable from this
  repository.
- **OPEN**: whether to remove `with_revocation_check` in the same release. It is
  deprecated but still reaches the half-configuration; removing it is a second
  breaking change and would naturally travel with this one.
