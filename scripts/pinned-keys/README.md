# Pinned kernel public keys

This directory holds **public** Ed25519 kernel keys, pinned in version control so
that `scripts/verify-evidence-bundle.mjs` can cross-check the key it fetches live
from a substrate's `GET /kernel/public-key` against a copy the substrate does not
control at verification time.

Public keys are not secrets. Nothing in this directory is sensitive, and nothing
private belongs here — a file holding a `d` member (a JWK private key) or a seed
is a defect, not a configuration choice.

## Why a pin at all

An evidence bundle carries its own signature and names its own `key_id`. If the
verifier took the signing key from inside the bundle, or from only the endpoint
run by the party being audited, then a producer able to re-sign a tampered bundle
would also be able to hand over the key that verifies it. The pin is the second,
independent source: to pass the cross-check, a substitution has to survive both
the live endpoint **and** a reviewed commit in this public repository.

## What the verifier does with it

| State of this directory | What `verify-evidence-bundle.mjs` reports |
| :- | :- |
| exactly one `*.json`, and `--kernel-url` given, and they agree | `✓ PASS` — two independent sources agree |
| exactly one `*.json`, and `--kernel-url` given, and they disagree | `✗ FAIL` — loudly, and **no** signature check under either key |
| exactly one `*.json`, no `--kernel-url` | `· NOT CHECKED` — only one source; signature still checked under it; exit 3 |
| no `*.json` here | `· NOT CHECKED` — nothing to cross-check against; exit 3 |
| more than one `*.json` | `· NOT CHECKED` — pass `--pinned-key` to name one; it will not guess |

A missing pin is never a silent skip and never a pass. The exit code cannot be 0
while the cross-check is unperformed.

## Adding or rotating a pin

A pin is a trust decision, so it is made the way trust decisions are made here:
**by pull request, reviewed by a human who obtained the key over a channel other
than the endpoint being pinned.**

1. Obtain the key out of band — from the deployment's release record, or from
   `docs/kernel-keys.json` in this repo, not by curling the endpoint and
   committing whatever came back. Curling the endpoint and pinning the answer
   pins whatever an attacker served; it is a cross-check against itself.
2. Recompute the RFC 7638 thumbprint of the key and check it equals the
   `thumbprint` you are filing it under. The verifier recomputes this on every
   run and refuses a key filed under a thumbprint that is not its own, so a
   mistake here fails the check rather than weakening it.
3. Add one file named for the deployment, e.g.
   `synthera-substrate-prod.json`, in the shape of
   `example-substrate-kernel-key.json.example`.
4. In the PR, say **where you got the key** and **which deployment** it belongs
   to. A pin whose provenance is not recorded cannot be reviewed later, and an
   unreviewable pin is the hole the pin exists to close.

Rotation is an **added** file or a replaced one, with the old thumbprint named in
the commit message. Never edit a key's bytes in place without saying so: a silent
edit is indistinguishable from the substitution this directory defends against.

## Relationship to `skill/trust-anchor.json` and `docs/kernel-keys.json`

Those two files are the published trust anchor for **VAID documents**, and CI
holds them byte-identical (`skill/scripts/check-anchor.mjs`). They are used by
`verify-evidence-bundle.mjs` for step (e), the VAIDs inside
`delegation_chain`.

This directory is for the key that signs the **bundle manifest itself** — a
different artefact with a different signer, which may or may not turn out to be
the same key. It is kept separate so that discovering they are the same key is a
finding someone records, rather than an assumption baked in by sharing a file.

As of this directory's creation no evidence-bundle signing key has been confirmed
with the substrate team, so no `*.json` is pinned yet and the cross-check reports
`NOT CHECKED`. That is the correct state: an unconfirmed pin would make the
verifier reject genuine bundles, and a pin copied from the endpoint would make the
cross-check meaningless.
