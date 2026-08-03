# The trust anchor: obtaining a key you can check

A VAID is signed by an issuing deployment's **kernel key**. To verify one you need
that key. This document is where you get it, and — more importantly — how you
check that what you got is the right thing.

## The published anchor

**Solara production substrate**, as of 2026-08-03:

```
thumbprint  urn:ietf:params:oauth:jwk-thumbprint:sha-256:VwvbN9yIguAset99AdeZyud7ZBHV5CcQa7zZML5ZQds
key_id      6cd3ef32-1712-4d87-84e0-ff88927c5556
created_at  2026-06-23T08:16:41Z
public x    INjJhHXQUsJyHMJn1uObwqoskkZjMy8WDWeRAM6xRmc   (Ed25519, base64url, unpadded)
```

The key material is served as JSON at:

- `https://solara.associates/.well-known/synthera-kernel-keys.json`
- `docs/kernel-keys.json` in this repository (canonical; the served copy is
  vendored from it and drift-checked in CI)

## The thumbprint in a document is **not** an anchor

VAID v3 documents carry a `kernel_key_thumbprint` field. **That field anchors
nothing on its own.** It is *self-asserted*: an attacker mints their own document,
signs it with their own key, and stamps their own key's thumbprint into it. Every
internal check passes. The document is perfectly self-consistent and entirely
unauthorized.

The in-document thumbprint becomes an anchor **only when compared against an
independently published copy** — one obtained through a channel the document's
author does not control. That comparison is the entire trust decision. Everything
else in this document is logistics.

This distinction is the single easiest thing to lose. A verifier that checks the
document's thumbprint against the document's own key has verified that a number
equals itself.

## The origin is untrusted by design

The JSON above is served from an ordinary static file on an ordinary web server.
**Do not trust it because it arrived over HTTPS from a domain you recognise.**

That is not a caveat about our hosting — it is the design. Publishing a *key*
would require an authenticated channel, because a substituted key is
undetectable. Publishing a **commitment to a key** — a thumbprint — does not,
because a substituted key fails the hash comparison. The commitment is small
enough to publish in prose, in three places, in a git history, in a release note.

So:

- **The hash is what makes the fetch safe.** The transport is not.
- HTTPS here prevents casual tampering and nothing more. If the CDN, the DNS, or
  the origin were fully compromised, the thumbprint comparison still catches a
  substituted key.
- Consequently the key JSON can be mirrored, cached, vendored into your build,
  or emailed to you, and it is exactly as safe. **Vendoring it is encouraged.**

## What a verifier should do

1. **Pin the thumbprint** at build time, as a constant, from a channel you trust —
   this document, the release notes, or the repository history. Not from the JSON.
2. Fetch (or read a vendored copy of) the key JSON.
3. **Recompute** the RFC 7638 JWK thumbprint of the key and check it equals both
   the map key it was listed under **and** your pinned constant.
4. **Fail closed on mismatch.** Do not fall back to a cached key, do not proceed
   with an unverified key, do not warn and continue. A key that fails this check
   is not a degraded key; it is somebody else's key.
5. Only then pass it to `verify_vaid_authenticity`.

Step 4 is the one that gets softened under delivery pressure. The posture to copy
is the substrate's own `OperatorSigningPort`, which refuses to start rather than
degrade to a stale or absent key.

## Rotation

The JSON is a **map keyed by thumbprint**, not a single current key, so rotation
adds an entry and changes no format. A verifier checking a document minted last
year needs the key that was current *then*, so old keys stay published with
`status` marking them superseded rather than being deleted.

Look a key up **by the thumbprint you are checking**, not by "the current key".

## Scope — what this does and does not establish

Publishing this anchor makes a substrate-signed document's **signature**
verifiable by a third party. It does **not** make a substrate document verifiable
by the open standard's verifiers: per ADR-0034 the substrate's document carries an
additional `external_identity` field and versions its `sig_version`
independently, so the two documents are deliberately not interchangeable. The
identity *fields* converged; the *documents* did not.

Those are two different claims and they are tracked separately in the claims
register. Do not read this page as establishing the second.
