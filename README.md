# Synthera VAID

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/vaid-mint?label=crates.io%20vaid-mint)](https://crates.io/crates/vaid-mint)
[![PyPI](https://img.shields.io/pypi/v/vaid-mint?label=PyPI%20vaid-mint)](https://pypi.org/project/vaid-mint/)
[![npm](https://img.shields.io/npm/v/vaid-mint?label=npm%20vaid-mint)](https://www.npmjs.com/package/vaid-mint)
[![Conformance: byte-for-byte](https://img.shields.io/badge/conformance-byte--for--byte-brightgreen.svg)](#three-languages-one-set-of-vectors)
<!-- The skills.sh badge counts the `solara.associates` SOURCE, not the vaid skill:
     skills.sh has no per-skill badge (…/api/badge/<source>/<skill> 404s). Identical
     today because that source publishes one skill; it stops being if we publish a
     second. The source is the hostname because install telemetry reports the
     .well-known origin — there is no solara-associates/vaid form to point at.
     The link is /site/<host>/<skill>. /skills/<...> is the GitHub-repo form and
     soft-404s for well-known sources: HTTP 200, with the title built from the URL
     you typed, so status and <title> both "pass" on the dead page. -->
[![skills.sh installs](https://img.shields.io/endpoint?url=https%3A%2F%2Fwww.skills.sh%2Fapi%2Fbadge%2Fsolara.associates)](https://www.skills.sh/site/solara.associates/vaid)

The open standard layer for verifiable agent-action identity (VAID).

A VAID is a portable identity bound to an action that an autonomous agent takes.
This repository defines how a VAID document and a VAID-bound request are
canonicalized and signed, and ships reference SDKs — in **Rust, Python and
TypeScript** — that produce and verify those signatures. It is the
interoperability contract: any client that follows it produces bytes that any
conforming verifier accepts, with no shared runtime and no network service in
between.

All three reference implementations reproduce the same frozen conformance vectors
byte-for-byte. That is the cross-language proof, made concrete — see
[Three languages, one set of vectors](#three-languages-one-set-of-vectors).

> **Version numbers are not written in this file, deliberately.** They went stale
> here repeatedly and a stale number reads exactly like a current one. The badges
> above resolve live from the registries; what is runnable today lives in
> [`docs/capabilities.json`](docs/capabilities.json), which CI fails on if it
> drifts from reality. `scripts/check-readme-drift.mjs` fails this file if a
> version is hardcoded back into it, or if it names some of the languages,
> registries or vectors without naming all of them.

## Check a VAID right now, with nothing installed

Someone sent you a VAID and you want to know if it is real.

**<https://solara.associates/vaid/verify>** — paste it in. The page is fully
client-side: it holds the published kernel key, makes no request when it verifies,
and works with the network switched off. Nothing is uploaded.

The verdict tells you what it establishes — authenticity, expiry, delegation
containment, issuer identity — and what it does not. **Revocation is never
checked**, because there is no published revocation list to consult and an offline
verifier could not reach one if there were. Read a pass as *genuinely issued and in
date*, never as *currently authorised*.

## Try it in five minutes

[![Open In Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/solara-associates/vaid/blob/main/examples/quickstart/quickstart.ipynb)

Mint a root identity, delegate a narrower one from it, verify the chain the way a
stranger would, then watch three denials with the reason for each: a resource
outside the scope boundary, an action with no capability behind it, and a child
trying to widen what its parent held. It finishes on a revoked document, denied
through the `RevocationCheck` seam while still being perfectly authentic.

Click the badge to run it in Colab with nothing installed, or locally in two lines:

```sh
pip install 'vaid-mint>=0.11,<0.12'
python examples/quickstart/quickstart.py
```

Nothing is written to disk, no key outlives the process, and no network call is
made once the package is installed. Both live in
[`examples/quickstart/`](examples/quickstart/) and run the same steps. The script
exits non-zero if any step stops behaving the way its own prose describes, and CI
runs it on every push, so it cannot rot into a tour that no longer works.

## Use it from a coding agent

```sh
npx vaid-skill
```

`vaid-skill` is an Agent Skill wrapping the published SDKs. It detects and installs
into **Claude Code, Codex, Cursor, Gemini CLI and GitHub Copilot**, and teaches the
agent four verbs and no more:

| verb | |
|---|---|
| `mint` | issue a VAID, or with `--parent` an attenuated child whose authority is a strict subset of yours |
| `present` | package one into the single line you send to someone |
| `verify` | check one you received, offline, against a pinned trust anchor |
| `revoke` | mark one revoked **on that machine only** — see below |

A minted VAID is a single `vaid1:` line, designed to be pasted into a chat message
and checked by whoever receives it — with `npx -p vaid-skill vaid verify`, on the
verify page, or by any conforming implementation. Details in
[`skill/README.md`](skill/README.md).

(`npx <name>` resolves `<name>` as a *package*, so reaching the `vaid` bin without
installing needs `-p`.)

## Evaluate the standard in 15 minutes

Everything below installs from **crates.io / PyPI / npm** — no repo checkout, no
server, no API key.

```sh
cargo add vaid-pop vaid-client vaid-mint                  # Rust
pip install vaid-pop 'vaid-mint~=X.Y' vaid-langchain      # Python, see below
npm install vaid-pop vaid-client vaid-mint                # TypeScript
```

**Pin `vaid-mint` on PyPI, substituting the current version for `X.Y` from the
badge above.** Of the three registries, crates.io and npm both read a `0.x` caret
as pinning the minor, so neither will cross a breaking `0.x` release on its own.
PyPI has no equivalent convention: a bare `vaid-mint`, or `vaid-mint>=` anything,
resolves straight onto the next breaking release without telling you. This package
does make breaking changes in `0.x` minor releases, which SemVer permits. Use `~=`
or `==`.

Then check the artifact you actually received, rather than taking this README's
word for it. **Each ecosystem ships a packaged conformance firewall**, so the check
runs against the installed package:

```sh
cargo install vaid-mint && vaid-mint-conformance        # crates.io
pip install vaid-mint && vaid-mint-conformance          # PyPI
npx -p vaid-mint vaid-mint-conformance                 # npm
```

Rust shipped its firewall as an installable binary in the release recorded in
[`crates/vaid-mint/CHANGELOG.md`](crates/vaid-mint/CHANGELOG.md); before that the
check needed a checkout, which made the reference implementation the only ecosystem
you could not verify in one command ([#22](https://github.com/solara-associates/vaid/issues/22)).

To certify **your own** implementation, take the vectors and reproduce their
digests and signatures. Matching bytes = conformant; a diff shows exactly where you
drifted.

**What is and isn't runnable today** lives in
[`docs/capabilities.json`](docs/capabilities.json) — not in this prose — because CI
fails if it drifts from reality.

**One thing is *not* reproducible from published packages:** governance
(identity and attenuated delegation) for the ADK and OpenAI adapters rested on a
dated 2026-07-28/29 run against the private substrate, and is currently withdrawn
from [`docs/claims-register.json`](docs/claims-register.json) pending a rerun,
because a fail-open bug in the exact code path the harness's denial checks
exercise was fixed in `forge-agents` after that run, and no rerun exists since.
The LangChain half of governance *is* reproducible from published packages: it is
what `vaid-langchain`'s own conformance tests, run from the PyPI install, directly
demonstrate.

## What this is

The byte-level standard, reference implementations in three languages, a reference
mint with delegation, an agent skill, a LangChain integration, and completion
records.

- **`vaid-pop`** — the proof-of-possession primitive, in all three languages. It
  defines one canonicalization path: RFC 8785 JSON Canonicalization Scheme (JCS),
  then SHA-256 over the canonical bytes, then a pure Ed25519 signature over the
  32-byte digest. It also defines the request payload that gets signed and the VAID
  identity types that payload binds. This is the byte-level specification, written
  as code.

- **`vaid-client`** — the reference request signer, in Rust and TypeScript. It
  turns a minted VAID document and a holder key into the signed headers a request
  carries, and reimplements none of the canonicalization. Python's request signer
  lives inside `vaid-pop` rather than in a separate package; that is a packaging
  choice, not a missing implementation.

- **`vaid-mint`** — the reference mint, in all three languages. It issues VAIDs and
  supports attenuated delegation, where a child's authority is always a subset of
  its parent's — scope, capabilities, tenant, and, since ADR-0007, lifetime: a
  child is clamped to its parent's expiry and cannot outlive it. All three enforce TTL at verification and expose a pluggable
  three-state, lineage-aware `RevocationCheck` seam
  ([`docs/spec/revocation.md`](docs/spec/revocation.md) R.4). Revoking a parent
  revokes its attenuated children, and verification fails closed when revocation
  status is unavailable.

- **`vaid-skill`** — the Agent Skill above ([`skill/`](skill/)), published on npm.
  A thin wrapper over the published SDKs; it implements no cryptography.

- **`vaid-langchain`** (Python) — a LangChain integration that signs requests using
  the VAID contract via an `httpx.Auth` adapter.

- **completion records** (`vaid-pop`) — a self-reported provenance record for what
  an agent claims it did. Single-tier assurance today: self-reported only, and the
  type's own documentation says so.

That is the entire open scope. There is no server, no database and no runtime to
stand up beyond the mint if you choose to self-host it.

## Third-party verification

The part worth understanding, because it is what the standard is *for*: a party who
holds nothing but a published public key can check a VAID, with no cooperation from
whoever issued it.

**Authenticity** — `verify_vaid_authenticity` answers *was this genuinely issued
under this key, and is it internally consistent*: the signature-scheme version, the
Ed25519 signature over the canonical document, and the consistency of
`lineage_hash`. It deliberately does not consult expiry or revocation, which are
separate questions with separate answers.

**Attenuation, by detached chain presentation**
([ADR-0003](docs/adr/0003-attenuation-verification-via-detached-chain.md)) — a leaf
carries its own scope and capabilities, not its ancestors', so authenticity alone
cannot answer *was this authority legitimately derived*. The presenter supplies the
ancestor documents alongside the leaf and the verifier walks them, checking scope,
capabilities, tenant and expiry at every hop, and refusing a chain whose root or
intermediate has already lapsed (`Expired`, ADR-0007). No new signed
field was needed: `parent_vaid` is already inside the canonical signing bytes, so
the chain is pinned by the signature that already exists.

The result is deliberately many-valued rather than boolean — `Attenuated`,
`Inauthentic`, `Unverifiable`, `NotAttenuated`, `Expired`, `ConsentExpired` —
because collapsing them is how a verifier reports *attenuation satisfied* when it
means *attenuation unverifiable*, or reports *you were never authorized* when it
means *this delegation has run out*.

**Cross-issuer delegation needs consent.** When a hop crosses kernel keys, the
child must present a **consent attestation** signed by the issuer that minted the
parent, for exactly that `(parent, child)` pair. Without it, an issuer holding its
own key could mint a document naming another issuer's root as its parent and have
it verify as attenuated, while that issuer delegated nothing. An attestation that is
authentic but outside its validity window returns `ConsentExpired`, kept distinct
because *renew the attestation* and *you were never authorized* are different
instructions.

**A verifier canonicalizes the bytes it was presented, not its own projection**
([ADR-0006](docs/adr/0006-verify-over-presented-bytes.md)). A verifier that parses a
document into its own struct and re-serializes silently drops any field it does not
know, so a valid document carrying an additive extension verifies as **invalid** —
the signature covered bytes the verifier never reconstructed. All three
implementations now canonicalize over the presented bytes, and `roundtrip_v1.json`
pins it.

**Scope containment is segment-bounded**
([ADR-0005](docs/adr/0005-segment-bounded-scope-containment.md)). Bare prefix
matching decided containment, so a boundary of `data.governance` contained
`data.governance-secret` — a sibling counted as a child. All three implementations
agreed, and all three were wrong; `scope_v1.json` pins the corrected matcher. The
release it landed in is in
[`crates/vaid-mint/CHANGELOG.md`](crates/vaid-mint/CHANGELOG.md); if you are below
it, scope containment is wider than you think.

## The spec, and where the surface stops

The vectors are the byte-level specification; the prose beside them says where the
conformance surface starts and stops.

- [`docs/spec/encoding.md`](docs/spec/encoding.md) is **normative and inside** the
  surface. It writes down the rules that decide the bytes — snake_case documents
  versus camelCase payloads, byte fields as arrays of numbers, `kernel_signature`
  nulled rather than deleted, whole-second RFC 3339 `Z` — each with the digest a
  wrong choice actually produces. It exists because those rules previously lived
  only in reference source, so a fourth implementer could not derive the bytes
  without reading Rust. They can now.
- [`docs/spec/scope.md`](docs/spec/scope.md) is normative: how scope containment is
  decided, over two reserved separators.
- [`docs/spec/revocation.md`](docs/spec/revocation.md) is **non-normative and
  outside** it. It specifies the `RevocationCheck` seam and states plainly that
  revocation sits outside the conformance surface
  ([ADR-0001](docs/adr/0001-revocation-outside-conformance-surface.md)).

## Delegation chain integrity: how VAID maps

A delegation chain is often described by ten properties a reader expects it to
hold. The table below maps each one onto VAID's actual fields, the functions
that check them, and the tests that prove it. "Carried and verified" means the
property has a field or a seam and code that enforces it, cited by file and
line. "Partially carried" names what is missing. Two of the ten are gaps today,
stated plainly rather than argued around.

| Property | Status | Where it lives |
|---|---|---|
| 1. Original principal | **Not carried today.** | There is no field naming who originally started the chain. The root VAID (the one whose `parent_vaid` is present-null, see [`document.rs:274-289`](crates/vaid-mint/src/document.rs)) stands in for it by convention (depth 0 in [`docs/spec/delegation.md`](docs/spec/delegation.md)), but nothing binds a human or external identity to that root beyond its own `agent_id`. An issuer that needs "who is accountable for this chain" has to keep that mapping itself, outside the document. |
| 2. Current agent identity | **Carried and verified.** | `agent_id` and `vaid_id` ([`document.rs:257-258`](crates/vaid-mint/src/document.rs)), bound into the kernel-signed bytes and checked by [`verify_vaid_authenticity`](crates/vaid-mint/src/verify.rs) (`verify.rs:79`). Tests: `document_verify.rs`, `mint_conformance.rs`. |
| 3. Delegated scope | **Carried and verified.** | `scope_boundary` ([`document.rs:290-293`](crates/vaid-mint/src/document.rs)), checked for containment by [`scope_attenuates`](crates/vaid-mint/src/mint.rs) / `scope_attenuates_within` (`mint.rs:86`, `mint.rs:103`) at mint time and again, independently, at verify time in [`verify_chain_at`](crates/vaid-mint/src/chain.rs). Tests: `child_scope_exceeding_parent_is_denied` (`mint.rs:293`), `child_exceeding_parent_scope_is_not_attenuated` (`chain_verification.rs:326`), `scope_conformance.rs`. |
| 4. Purpose | **Not carried today (the likely gap).** | VAID carries *what* a delegate may touch (`scope_boundary`) and *what it may do* (`capability_set`), never *why* the delegation was made. There is no "intended task" or declared-intent field anywhere in the document, the mint request, or the spec. A deployment that wants an auditable reason for each hop has to carry it outside VAID and correlate by `vaid_id`. |
| 5. Expiry | **Carried and verified.** | `expires_at` ([`document.rs:271`](crates/vaid-mint/src/document.rs)), read through `Vaid::is_expired` and never widened past the parent's: [`expiry_attenuates`](crates/vaid-mint/src/mint.rs) / `expiry_attenuates_within` (`mint.rs:251`, `mint.rs:258`) clamp a child's lifetime to its parent's at mint time, reported back via `expiry_bounded_by_parent` ([`mint_types.rs:97-116`](crates/vaid-mint/src/mint_types.rs)). Tests: `child_is_clamped_to_its_parents_expiry` (`mint.rs:952`), `delegating_from_an_already_expired_parent_is_refused` (`mint.rs:1019`), `chain_expiry_conformance.rs`. |
| 6. Parent delegation | **Carried and verified.** | `parent_vaid`, a present-but-possibly-null three-state field so a root is distinguishable from a document with the member stripped ([`document.rs:274-289`](crates/vaid-mint/src/document.rs), ADR-0006 Req. 3), plus `lineage_hash` checked by [`verify_lineage_hash`](crates/vaid-mint/src/verify.rs) (`verify.rs:92`). A third party reconstructs the chain from presented ancestor documents via [`PresentedBundle`](crates/vaid-mint/src/chain.rs) and [`assemble_lineage`](crates/vaid-mint/src/revocation.rs) (`revocation.rs:142`). Tests: `tampered_parent_vaid_is_inauthentic` (`chain_verification.rs:247`), `bundle_assembles_ordered_lineage_root_first` (`chain_verification.rs:601`). |
| 7. Revocation state | **Partially carried.** | Revocation is deliberately outside the signed document and outside the conformance surface ([ADR-0001](docs/adr/0001-revocation-outside-conformance-surface.md)): the [`RevocationCheck`](crates/vaid-mint/src/revocation.rs) seam is three-valued (`NotRevoked` / `Revoked` / `Unavailable`) and fails closed on `Unavailable` rather than defaulting to not-revoked. What is missing is anything in the VAID document itself; a verifier that does not wire up a revocation store sees no revocation state at all. The reference in-memory store is explicitly non-durable; [ADR-0008](docs/adr/0008-durable-revocation-is-two-stores-injected-as-one.md) covers a durable backend. Tests: `revoking_makes_a_store_available_and_reports_any_hop` (`revocation.rs:505`), `revocation_seam.rs`. |
| 8. Authority only narrows downstream (scope, capabilities, lifetime) | **Carried and verified.** | A child must be contained in its parent on all three axes or the mint refuses and the verifier reports `NotAttenuated`: [`scope_attenuates`](crates/vaid-mint/src/mint.rs), [`caps_attenuate`](crates/vaid-mint/src/mint.rs) (`mint.rs:217`), [`expiry_attenuates`](crates/vaid-mint/src/mint.rs) (`mint.rs:251`). Tests: `child_caps_exceeding_parent_are_denied` (`mint.rs:333`), `child_exceeding_parent_capabilities_is_not_attenuated` (`chain_verification.rs:370`). |
| 9. Each hop validates independently, never trusting the previous agent | **Carried and verified.** | [`verify_chain_at`](crates/vaid-mint/src/chain.rs) authenticates every presented document (leaf and each ancestor) against the kernel key that actually signed it, and recomputes containment at every hop rather than accepting a leaf's claim about its lineage. A forged or widened claim introduced mid-chain is caught even when the leaf and the other hops are untouched. Tests: `mid_chain_scope_escalation_is_not_attenuated` (`chain_verification.rs:347`), `tampered_parent_vaid_is_inauthentic` (`chain_verification.rs:247`). |
| 10. Revoking the root invalidates the whole chain | **Carried and verified.** | `RevocationStatus` is computed over the *whole assembled lineage*, not the leaf alone: revoked if any id anywhere in the chain is revoked ([`revocation.rs:92-96`](crates/vaid-mint/src/revocation.rs)). This only holds if the lineage assembles completely: an unresolvable ancestor fails closed to `Unavailable` rather than silently checking only the leaf. Test: `revoking_makes_a_store_available_and_reports_any_hop` (`revocation.rs:505-514`), which revokes a root id directly and shows the leaf's lineage comes back `Revoked`. |

**Revocation trade-offs.** A live revocation check gives a verifier the newest
answer, at the cost of a lookup the verifier cannot always make: when the store
is unreachable, VAID's reference seam reports `Unavailable` and verification
fails closed, so an outage in the revocation path denies traffic rather than
silently approving it. Short-lived credentials move the trade-off the other
way: a VAID's lifetime is clamped to never outlive its parent's at mint time
(property 5 above), so a compromised or no-longer-wanted delegate's authority
expires on its own, without needing a live check at all, at the cost of
however long its remaining TTL is. VAID is built to support both: a deployment
can run live checks for the hops it wants to kill immediately, lean on short
expiries for the ones it doesn't, or do both at once. Neither one is forced,
and R.4.5 of [`docs/spec/revocation.md`](docs/spec/revocation.md) is explicit
that a fail-open posture may be configured, but a deployment has to ask for it
by name; it is never the default.

## What it does

### Sign and verify directly with the primitive

```rust
use chrono::Utc;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};

use vaid_pop::VaidId;
use vaid_pop::request_auth::RequestAuthPayload;
use vaid_pop::vaid_pop::{sign_payload, verify_signed_payload};

// The payload binds body_sha256, so it must be the lowercase hex SHA-256 of the
// exact request body bytes. The SDK below computes this for you; here it is shown
// explicitly so the primitive example binds a real body, not an empty string.
fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

// 1. Create a VAID identifier for the action, and hold an Ed25519 key.
let vaid = VaidId::new();
let rng = SystemRandom::new();
let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

// 2. Describe the request this VAID is authorizing.
let request_body = br#"{"task":"summarize the Q3 report"}"#;
let payload = RequestAuthPayload {
    vaid_id: vaid,
    method: "POST".into(),
    path: "/v1/agents/execute".into(),
    body_sha256: hex_sha256(request_body),
    tenant_id: "acme".into(),
    timestamp: Utc::now(),
    client_nonce: "a-fresh-per-request-nonce".into(),
};

// 3. Sign: JCS, then SHA-256, then Ed25519 over the digest.
let signature = sign_payload(&payload, &key);

// 4. Verify against the holder's public key.
let verified = verify_signed_payload(&payload, key.public_key().as_ref(), &signature);
assert!(verified);
```

### Produce request headers with the SDK

For the common case of authenticating an HTTP request, the SDK takes the minted
VAID document and your key and returns the headers to attach. It hashes the body,
generates a fresh nonce, and stamps a current timestamp for you.

```rust
use ring::signature::Ed25519KeyPair;
use vaid_client::RequestSigner;

let signer = RequestSigner::from_vaid_json(vaid_document_json, key)?;
let headers = signer.sign_headers("POST", "/v1/agents/execute", request_body)?;

// headers.into_pairs() yields, in order:
//   x-synthera-vaid, x-synthera-timestamp, x-synthera-nonce, x-synthera-signature
for (name, value) in headers.into_pairs() {
    request.set_header(name, value);
}
```

A runnable version is in `crates/vaid-client/examples/emit_pop.rs`.

## Three languages, one set of vectors

The frozen vectors are the single source of truth. Each implementation vendors a
byte-identical copy and reproduces the same digests and the same Ed25519
signatures from the same fixed inputs.

The cross-language set:

| vector | pins |
|---|---|
| `operator_pop_v1.json` | the request proof-of-possession path |
| `mint_v1.json` | the signed VAID document |
| `mint_pop_v1.json` | the mint-time proof-of-possession |
| `chain_v1.json` | detached chain presentation |
| `chain_expiry_v1.json` | expiry containment — a child may not outlive its parent, and a lapsed ancestor is not attenuation |
| `attestation_v1.json` | cross-issuer consent attestations |
| `scope_v1.json` | segment-bounded scope containment |
| `scope_kinds_v1.json` | the typed scope boundary — and that an unrecognised boundary kind is refused rather than skipped |
| `roundtrip_v1.json` | verification over presented bytes |
| `verdict_v1.json` | the negative path — which failure, not just that one occurred |
| `pathquery_v1.json` | path-with-query canonicalization |
| `completion_v1.json` | completion records |

Every vector above `verdict_v1.json` pins a success, and `chain_expiry_v1.json`
carries its own positive controls for the same reason. That leaves a gap those
vectors cannot close: they prove the implementations agree on documents that
*work*, and say nothing about whether they agree on documents that do not. A
verifier accepting an expired VAID in one language and rejecting it in another is
a worse defect than a mint mismatch, and it would pass every one of them.

`verdict_v1.json` closes it, and asserts the **reason** rather than the verdict.
Implementations that reject the same document for different reasons agree on every
boolean while disagreeing about what happened — one reports a forgery, another an
unreachable revocation list — and only a reason-level assertion can see it. The
same vector pins that "could not determine" stays its own answer instead of
collapsing into either a pass or an accusation.

A CI drift job `cmp`s every language's copy of each and runs each gate, so a
divergence fails the build rather than being discovered by a consumer. Byte
agreement is asserted at the vectors, **never at the version number** — the three
implementations version independently, and a fix lands only in the language that
had the defect.

Independent implementations agreeing byte-for-byte is a stronger statement the more
of them there are: a narrow agreement can hide a shared assumption no author
questioned. That is not hypothetical here — ADR-0005 and ADR-0006 above are both
cases where every implementation agreed and every implementation was wrong, caught
by a vector rather than by review.

## Where the open scope stops

Some things a production deployment needs are not in this repository. It is more
useful to say exactly which than to gesture at a boundary:

- **A policy language** for expressing what a VAID is permitted to do. The standard
  binds an action to an identity and decides scope containment; whether a given scope
  *should* have been granted is a layer above it.
- **Durable, restart-surviving infrastructure** — a hash-chained audit ledger,
  durable revocation state, KMS-backed kernel keys.

The second is a statement about durability, not about capability, and the difference
is worth stating precisely because the blanket version is falsifiable by reading this
repo:

- **Audit** — the *seam* is here and Apache-2.0: the `AuditSink` interface with
  in-memory and no-op implementations in every language. What is absent is the
  **durable, hash-chained ledger**, not the ability to audit.
- **Revocation** — likewise: the `RevocationCheck` seam ships here with a
  non-durable in-memory default, and VAID expiry is hard-enforced at verification.
  A self-hoster can wire their own backend without patching the SDK. What is absent
  is **durable, restart-surviving** revocation.

  Durable revocation is **two** stores, not one: the revoked set *and* the lineage
  resolver, and durable **lineage resolution** is as much a host-application
  responsibility as the revoked set. Persist only the revoked set and every
  *delegated* credential fails closed after a restart — its ancestry can no longer
  be assembled, which is `Unavailable`, which fails closed (R.4.2/R.4.5) — while
  every *root* credential keeps verifying, because a root needs no resolution. The
  behaviour is correct and the outage is total for delegation and invisible for
  roots. `RevocationBackend` takes both halves and has no single-half constructor,
  so this cannot be reached by omitting an argument.

  The reference default **fails closed**: a bare issuer's revocation store is
  *absent*, reports `Unavailable`, and verification is refused until state is loaded
  (R.4.5). An earlier default vouched "nothing is revoked" over an empty set — a
  fail-open posture that, being non-durable, could not detect its own restart. That
  posture is still available, by name, as `assuming_nothing_revoked()`, because
  R.4.5 permits fail-open as a configuration and forbids it as a default.
  Authenticity verification is unaffected: it never consults revocation (R.7). See
  each package's CHANGELOG for which release this changed in.

The reference mint proves the shape of delegation and attenuation. Running a mint in
production means supplying those durable pieces yourself, and nothing in the standard
requires you to obtain them from any particular source — a conforming deployment is
one that reproduces the vectors, whoever built it.

## Contributing & community

VAID is an interoperability contract, so the bar is concrete: any change must keep
all three reference SDKs reproducing the frozen vectors byte-for-byte.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — dev setup, the conformance bar, and how
  to propose standard-affecting changes.
- **[BACKLOG.md](BACKLOG.md)** — known defects and deferred work, with what breaks
  and why it has not been done.
- **[SECURITY.md](SECURITY.md)** — report vulnerabilities privately
  (`info@solara.associates`); please don't open public issues for them.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright © 2026 solara.associates.
