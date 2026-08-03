# Release notes

## 2026-08-03 — the kernel signing key is published

VAID verifiers can now obtain the Solara production substrate's kernel public key
and, more importantly, **check that what they obtained is the right key.**

### The anchor

```
thumbprint  urn:ietf:params:oauth:jwk-thumbprint:sha-256:VwvbN9yIguAset99AdeZyud7ZBHV5CcQa7zZML5ZQds
key_id      6cd3ef32-1712-4d87-84e0-ff88927c5556
created_at  2026-06-23T08:16:41Z
public x    INjJhHXQUsJyHMJn1uObwqoskkZjMy8WDWeRAM6xRmc   (Ed25519, base64url, unpadded)
```

This thumbprint is published in **three independent channels** so a reader can
cross-check without having to trust any one of them:

1. this file,
2. `docs/trust-anchor.md` and `docs/kernel-keys.json` in this repository,
3. `https://solara.associates/.well-known/synthera-kernel-keys.json` and the
   published page behind it.

Channels 1 and 2 are served by GitHub; channel 3 by our own origin. If they
disagree, **do not proceed** — that disagreement is the signal the design exists
to produce.

### The in-document thumbprint is self-asserted

VAID v3 documents carry a `kernel_key_thumbprint` field. **It anchors nothing on
its own.** An attacker mints a document, signs it with their own key, and stamps
their own key's thumbprint into it; every internal check passes and the document
is entirely unauthorized.

The field becomes an anchor **only when compared against an independently
published copy** — such as the one above. That comparison is the whole trust
decision.

### The origin is untrusted by design

The JSON is a static file on an ordinary web server. Do not trust it because it
arrived over HTTPS from a domain you recognise. **Recompute the thumbprint and
compare it against a value you got from a different channel.** The hash is what
makes the fetch safe; the transport is not.

This is why the anchor could be published at all without new infrastructure:
publishing a *key* needs an authenticated channel, because a substituted key is
undetectable. Publishing a *commitment* to a key does not, because a substituted
key fails the comparison.

Mirror it, cache it, vendor it into your build — it is exactly as safe.

### Scope

This makes a substrate-signed document's **signature** third-party verifiable. It
does **not** make substrate documents verifiable by this standard's verifiers: per
ADR-0034 the substrate's document carries an extra `external_identity` field and
versions `sig_version` independently, so the two are deliberately not
interchangeable. Two separate claims, tracked separately.

Procedure, including what to do on mismatch: `docs/trust-anchor.md`.
