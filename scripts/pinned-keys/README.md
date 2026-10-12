# Pinned kernel public keys

This directory holds **public** Ed25519 kernel keys, pinned in version control.
It is **one of the two independent static publications** of the substrate's
signing key that `scripts/verify-evidence-bundle.mjs` cross-checks against each
other. The other is a static JSON asset on the UAB product's own public site
(`--site-key-url`). Neither is inside the bundle being verified, and neither
depends on the other.

Public keys are not secrets. Nothing in this directory is sensitive, and nothing
private belongs here — a file holding a `d` member (a JWK private key) or a seed
is a defect, not a configuration choice.

## Why a pin at all

An evidence bundle carries its own signature and names its own `key_id`. If the
verifier took the signing key from inside the bundle, or from any single place
controlled by the party being audited, then a producer able to re-sign a tampered
bundle would also be able to hand over the key that verifies it. This pin is one
of two publishers: to pass the cross-check, a substitution has to survive **a
reviewed commit in this public repository and a deploy of the UAB site's static
asset**.

The substrate's own live `GET /kernel/public-key` is *not* part of that pair. Its
Cloud Run service stays behind IAM by deliberate product decision, so an external
auditor can never reach it; it is available only as an optional third
cross-check for Solara operators (`--kernel-url`), and its absence is the normal
case.

## What the verifier does with it

The cross-check is gated on **this pin and the UAB site asset**, so the table
below is in terms of those two:

| State of this directory | With the site asset reachable | With it not reachable |
| :- | :- | :- |
| exactly one `*.json`, keys agree | `✓ PASS` — two independent publications agree | `· NOT CHECKED` — *cross-check incomplete*; signature still checked under the pin; exit 3 |
| exactly one `*.json`, keys disagree | `✗ FAIL` — loudly, and **no** signature check under either key | — |
| no `*.json` here | `· NOT CHECKED` — only one publisher; exit 3 | `· NOT CHECKED` — no key at all; nothing to verify the signature with; exit 3 |
| more than one `*.json` | `· NOT CHECKED` — pass `--pinned-key` to name one; it will not guess | same |

If `--kernel-url` is also given it is a third vote: it must agree, or the run
fails loudly even when the two static publications agreed with each other. There
is no majority vote.

A missing pin is never a silent skip and never a pass. The exit code cannot be 0
while the cross-check is unperformed.

## Adding or rotating a pin

A pin is a trust decision, so it is made the way trust decisions are made here:
**by pull request, reviewed by a human who obtained the key over a channel other
than the endpoint being pinned.**

1. Obtain the key out of band — from the deployment's release record, or from
   `docs/kernel-keys.json` in this repo, not by curling a published copy and
   committing whatever came back. In particular, **do not pin what the UAB site
   serves**: that is the other half of this cross-check, and pinning its answer
   would collapse two publishers into one and leave the comparison checking a
   value against itself. The same applies to the substrate endpoint.
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
verifier reject genuine bundles, and a pin copied from another published copy
would make the cross-check meaningless.

Two things are therefore outstanding before the cross-check can pass for a real
bundle, and they are independent of each other:

1. a key pinned here, by reviewed PR, obtained out of band;
2. the UAB site publishing its static key asset, and
   `UAB_SITE_KEY_URL_PLACEHOLDER` in `verify-evidence-bundle.mjs` updated to its
   real URL.

Until both exist the verifier reports *cross-check incomplete* and exits 3. It
does not report a pass, and it does not report a failure.
