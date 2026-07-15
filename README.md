# Synthera VAID

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![SDKs: Rust + Python](https://img.shields.io/badge/SDKs-Rust%20%2B%20Python-orange.svg)](#what-this-is)
[![Conformance: byte-for-byte](https://img.shields.io/badge/conformance-byte--for--byte-brightgreen.svg)](#two-languages-one-vector)

The open standard layer for verifiable agent-action identity (VAID).

A VAID is a portable identity bound to an action that an autonomous agent takes.
This repository defines how a VAID-bound request is canonicalized and signed, and
ships reference SDKs — in **Rust and Python** — that produce and verify those
signatures. It is the interoperability contract: any client that follows it
produces bytes that any conforming verifier accepts, with no shared runtime and
no network service in between. Both reference SDKs reproduce the same frozen
conformance vector byte-for-byte — that is the cross-language proof, made
concrete (see [Two languages, one vector](#two-languages-one-vector)).

## What this is

The byte-level standard, reference implementations in two languages, a reference mint with delegation, a LangChain integration, and completion records:

- **`vaid-pop`** (Rust, `crates/vaid-pop`) is the proof-of-possession (PoP)
  primitive. It defines one canonicalization path: RFC 8785 JSON Canonicalization
  Scheme (JCS), then SHA-256 over the canonical bytes, then a pure Ed25519
  signature over the 32-byte digest. It also defines the request payload that gets
  signed and the VAID identity types that payload binds. This is the byte-level
  specification, written as code.

- **`vaid-client`** (Rust, `crates/vaid-client`) is the reference SDK built on
  that primitive. It turns a minted VAID document and a holder key into the four
  signed headers a request carries, and it does not reimplement any of the
  canonicalization. It depends only on `vaid-pop`.

- **`vaid-pop`** (Python, `python/vaid-pop`) is the Python reference signer — the
  single Python definition of the same PoP contract. It mirrors the Rust
  canonicalization path exactly (RFC 8785 JCS → SHA-256 → pure Ed25519) and is
  locked to the same frozen vector. It depends only on `cryptography` and
  `rfc8785`, nothing else.

- **`vaid-mint`** (Rust + Python, `crates/vaid-mint`, `python/vaid-mint`) is the reference mint. It issues VAIDs, supports attenuated delegation (`mint_child`, where a child's authority is always a subset of its parent's), and documents its trust model plainly. The **Rust crate README** (`crates/vaid-mint`) reflects the current 0.1.2 state — TTL enforced at verification and a pluggable `RevocationCheck` seam. The **Python package** (`python/vaid-mint`) has not yet caught up: it remains on 0.1.1 with the original advisory-only expiry and no seam, pending [issue #1](https://github.com/solara-associates/vaid/issues/1). Read the README that matches the implementation you're using for what's durable and what isn't.

- **`vaid-langchain`** (Python, `python/vaid-langchain`) is a LangChain integration that signs requests using the VAID contract via an `httpx.Auth` adapter.

- **completion records** (`vaid-pop`, `completion_v1.json` vector) — a self-reported provenance record for what an agent claims it did. Single-tier assurance today: self-reported only, and the type's own documentation says so.

That is the entire open scope. There is no server, no database, and no runtime to
stand up beyond the mint if you choose to self-host it. You add the Rust crates to a Cargo project, or `pip install` the Python packages, and call them.

## What it does

A developer can create a VAID identifier, sign a request against it, and verify
that signature, standalone, using only these crates.

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
VAID document and your key and returns the four headers to attach. It hashes the
body, generates a fresh nonce, and stamps a current timestamp for you.

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

A runnable version of this path is in
`crates/vaid-client/examples/emit_pop.rs`.

### Proof that the bytes are portable

The signing path is pinned by a frozen test vector,
`crates/vaid-client/tests/vectors/operator_pop_v1.json`. The conformance test
reproduces that vector's exact SHA-256 digest and its exact Ed25519 signature from
the fixed inputs. That is the interoperability guarantee made concrete: an
independent implementation that hits the same vector is byte-compatible with this
one.

```
cargo test
```

The conformance suite and the primitive's own round-trip and tamper-rejection
tests run with nothing else present.

## Two languages, one vector

The frozen vector `crates/vaid-client/tests/vectors/operator_pop_v1.json` is the
single source of truth. The Python reference signer under `python/vaid-pop`
vendors a byte-identical copy of it and reproduces the **same SHA-256 digest and
the same Ed25519 signature** from the same fixed inputs — proven from the
installed package, with no repo checkout required:

```
cd python/vaid-pop
pip install .
vaid-pop-conformance        # PASS = installed signer == frozen vector, byte-for-byte
```

So the interoperability guarantee is not a claim about a spec document — it is two
independent implementations, in two languages, with no shared runtime, hitting the
same bytes. The Rust `cargo test` above and the Python `vaid-pop-conformance`
assert against the same vector; the repo's `pop-conformance` CI job runs both and
fails on any divergence. That is the standard, proven.

## What is deliberately not here

This repository is the standard, its reference signer, a reference mint, a LangChain integration, and completion records. Two things remain closed and commercial:

- The policy language for expressing what a VAID is permitted to do.
- The hosted authority that runs a mint in production — KMS-backed kernel keys, an audit-of-record, durable hash-chained revocation, and a policy/mesh/federation control plane.

The reference mint here proves the shape of delegation and attenuation; it is not that hosted authority. Revocation is the seam worth naming plainly rather than filing under "commercial": **both reference SDKs** now have a pluggable `RevocationCheck` seam — additive, with an in-memory default, and with VAID expiry (TTL) hard-enforced at verification (1-hour default) — so a self-hoster can wire their own revocation backend in either language without patching the SDK. What stays commercial is *durable* revocation itself: both ship the seam, not a durable, restart-surviving hash-chained store.

**Release status differs by language, and the distinction matters if you install from a package registry:** the Rust crate has this on crates.io as `vaid-mint` 0.1.2. The Python port has landed **in this repository** (`python/vaid-mint`, version 0.1.2) but is **not yet published to PyPI — the latest PyPI release is still 0.1.1**, which has the original advisory-only expiry and no seam. Until the 0.1.2 sdist/wheel is published ([issue #1](https://github.com/solara-associates/vaid/issues/1)), Python consumers get the seam by installing from source, not from `pip install vaid-mint`. See `crates/vaid-mint`'s and `python/vaid-mint`'s own trust-model documentation for exactly what's durable, what isn't, and how to mitigate it if you're running this in production today.

## The commercial boundary

The production control plane is a separate commercial product and is not in this
repository. That product provides the hosted VAID authority that issues and
revokes identities, the policy engine that decides what each VAID may do, the
federation layer that routes action across tenants, the enforcement mesh that
applies those decisions at call time, and the audit-of-record that retains a
verifiable history. None of that is required to use what is here, and none of it
is included here. This repository stands on its own as the open standard.

## Contributing & community

VAID is an interoperability contract, so the bar for contributions is concrete:
any change must keep both reference SDKs reproducing the frozen conformance vector
byte-for-byte.

- **[CONTRIBUTING.md](CONTRIBUTING.md)** — dev setup (Rust + Python), the
  conformance bar, and how to propose standard-affecting changes.
- **[SECURITY.md](SECURITY.md)** — report vulnerabilities privately
  (`info@solara.associates`); please don't open public issues for them.
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — Contributor Covenant 2.1.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright © 2026 solara.associates.
