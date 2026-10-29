# `verify-evidence-bundle.mjs` — check an evidence bundle yourself, offline

An **evidence bundle** (`evidence-bundle/v1`) is a signed JSON file covering one
task or one period: who the actor was, the delegation chain behind its authority,
which policy version was in force, what was decided, and the audit entries that
were recorded. It is produced so that somebody outside Solara can check the record
without taking Solara's word for it.

This script is how you check it. It needs **no Solara account and no login**. The
only network access it makes is fetching the substrate's public signing key from
two public, unauthenticated locations, so that it never has to take that key from
inside the bundle it is checking — see
[the key cross-check](#the-key-cross-check-and-why-it-is-the-interesting-part).

## Check this script before you run it

The auditor-facing page publishes this file's SHA-256. Compare it with the copy
you are about to run:

```
shasum -a 256 scripts/verify-evidence-bundle.mjs
```

If the two differ, stop: either the page is stale or the copy you have is not the
copy that was published. The script lives in this public repository, not only on a
Solara server, so you can read it in full before running it — a verifier you have
to take on trust from the party being audited is not a verifier.

## Invocation

```
node scripts/verify-evidence-bundle.mjs <bundle.json> \
  [--site-key-url https://<uab-site>/kernel-key.json] \
  [--pinned-key <path>] \
  [--kernel-url https://<substrate-host>/kernel/public-key]   # operators only \
  [--trust-anchor <path>] \
  [--at <rfc3339>] \
  [--json]
```

Requires Node 20.19 or newer. Nothing to install for most of the run: steps 1, 2,
3, 4 and 6 below use only Node's own libraries. Step 5 needs the published VAID
SDK, and says so instead of guessing if it is absent:

```
npm install --prefix skill        # only needed for the delegation-chain step
```

The form an auditor runs:

```
node scripts/verify-evidence-bundle.mjs bundle.json \
  --site-key-url https://<uab-site>/kernel-key.json
```

That gives the full cross-check. You do **not** need `--kernel-url`, and you will
not be able to use it — see below.

## What it checks

| # | Check | Fails if |
| :- | :- | :- |
| 1 | **Bundle shape** | a required field is absent — reported *by name*, with no partial verdict over the fields that were present |
| 2 | **Content hash** | `content_hash` does not match a recomputation over the bundle's own canonical form |
| 3 | **Kernel key cross-check** | the key's two independent *static* publications disagree |
| 4 | **Manifest signature** | `signature.sig_b64` does not verify, under the cross-checked key, over the content hash |
| 5 | **Delegation chain** | any VAID in `delegation_chain` fails `vaid verify` |
| 6 | **Audit chain** | `prev_hash` does not link to the preceding `entry_hash`, or `seq` skips |

Each check reports its own line. A single boolean would collapse them, and the
collapse always runs the same direction: the cryptographic check passes, the
bundle is called "verified", and the parts nobody checked ride along inside that
word.

## Reading the output

Four states, and they are deliberately not interchangeable:

| | Meaning |
| :- | :- |
| `✓ PASS` | the check ran and passed |
| `✗ FAIL` | the check ran and failed. Do not rely on this bundle |
| `! CAVEAT` | the check ran, did not fail, and establishes less than it looks like it does |
| `· NOT CHECKED` | the check **did not run**. Not a pass, not a failure — a question this run could not answer |

Exit codes, so a script calling this one cannot mistake one state for another:

| Exit | Means |
| :- | :- |
| `0` | every check ran and none failed (caveats are possible — read them) |
| `1` | a check ran and **failed** |
| `2` | the script could not start: bad usage, or the file is unreadable |
| `3` | nothing failed, but a check **could not run**. Never read this as a pass |
| `4` | the input is not a well-formed `evidence-bundle/v1` |

**Exit 3 is the one to pay attention to.** It is what you get when the bundle
looks fine as far as the script could see, and part of the check did not happen —
most often because the kernel key could be obtained from only one of its two
publications.

## The key cross-check, and why it is the interesting part

The bundle's own signature is verified with the substrate's Ed25519 **kernel
public key**. Taking that key from inside the bundle would prove nothing: whoever
could re-sign a tampered bundle could also rewrite the key beside it. So the key
is obtained from two **separately published, independently reachable** static
sources, and trusted only if they agree:

1. **pinned** — a copy committed to this public repository, changed only by
   reviewed pull request (`scripts/pinned-keys/`, `--pinned-key`);
2. **site** — a plain static JSON asset published on the UAB product's own public
   site, served alongside the public `/evidence/verify` auditor page with no
   authentication and no IAM (`--site-key-url`).

Both are things you can fetch yourself, today, with no account. Both keys are
compared byte for byte and by their RFC 7638 thumbprints.

- They **agree** → `✓ PASS`, and the signature is checked under that key. For a
  substitution to get past this, someone would have to change both a reviewed
  commit in this public repo *and* a deployed asset on the UAB site.
- They **disagree** → `✗ FAIL`, loudly, and the signature is **not** checked under
  either. Which key is right is a human's decision — either the key was rotated
  and one publication is stale, or one of them is serving a key nobody reviewed —
  and the script will not quietly pick one.
- Only **one** is available → `· NOT CHECKED`, reported as *cross-check
  incomplete*. The signature is still checked under the key that was available, so
  the run still establishes that the bundle was signed by whoever holds that key.
  It does **not** establish that that party is the Solara substrate, because only
  one publisher vouched for it. Exit code 3.

A missing pinned key is never a silent skip. See
[`pinned-keys/README.md`](pinned-keys/README.md) for how pins are added and
rotated.

> **The `--site-key-url` default is the real staging site.** `UAB_SITE_KEY_URL_DEFAULT`,
> near the top of the script, now points at `synthera-uab-staging`'s deployed UAB
> site (session s502, 2026-10-29) — running without `--site-key-url` fetches it for
> real. Pass `--site-key-url` to point at a different deployment (a production URL,
> once one exists), and update the constant itself if the staging deployment moves.

### `--kernel-url`: for Solara's operators, not for you

The substrate's own live `GET /kernel/public-key` endpoint is available as an
**optional third cross-check** via `--kernel-url`. It is there for Solara's own
operations staff, and an external auditor is **not expected to use it**:

The substrate's Cloud Run service sits behind IAM and **stays there** — that is a
deliberate product decision, not a gap waiting to be closed. An anonymous auditor
therefore cannot reach that endpoint at all, which is precisely why the two
publications above, rather than this one, are what the cross-check is built on.

- `--kernel-url` **omitted** → normal, expected, and reported as such. The output
  says the live endpoint was not checked and why. This is **not** a degraded run
  and does not on its own stop the cross-check from passing.
- `--kernel-url` **given and agreeing** → a third independent vote, noted in the
  output.
- `--kernel-url` **given and disagreeing** → `✗ FAIL`, even if the two static
  publications agreed with each other. There is **no majority vote**: a source
  that contradicts the others is not outvoted, it is a reason to stop.

## Reproducing the content hash by hand

The point of `content_hash` is that you do not have to believe this script's
arithmetic. The canonical form is stated exactly in the script's header comment,
and with `jq` and `shasum` you can get the same number:

```
jq -S -c 'del(.content_hash, .signature)' bundle.json | tr -d '\n' | shasum -a 256
```

That should equal the bundle's `content_hash`, and equal what the script prints —
which it prints on a pass as well as a failure, so there is something to compare
against without re-running anything.

## Three things the script assumes

The script names these in its own output as well as in its header comment, so you
are never told something was confirmed when it was only assumed:

1. **What the signature covers.** Whether Ed25519 signed the hex `content_hash`
   string or its 32 raw bytes is not pinned by a published contract. Both are
   tried, and the one that verified is named. A forger needs the private key
   either way.
2. **The audit entry hash scheme.** `entry_hash` is assumed to be the SHA-256 of
   the canonical form of the entry with its own `entry_hash` removed. A mismatch
   is reported as `NOT CHECKED`, not `FAIL`, because the assumption is the
   script's rather than the substrate's. The *linkage* checks beside it —
   `prev_hash` chaining and `seq` continuity — do not depend on the hash function
   at all, so a real break in the chain is caught regardless.
3. **The published key documents' response shape.** Neither the UAB site asset
   nor the substrate endpoint has a shape pinned by a contract this repo can
   read, so both are parsed by the same defensive reader: several shapes are
   accepted, and an unrecognised one is reported with the field names that *were*
   present, so adding it is a one-line change.

## Why there is no `vaid evidence` command

There is deliberately no fifth `vaid` verb. The CLI has exactly four — `mint`,
`present`, `verify`, `revoke` — and its own source says the omissions are the
design: every extra verb is another surface that has to stay in step with a
standard whose value rests on three implementations agreeing byte for byte.

An evidence bundle is not a VAID. It is a report that *contains* VAIDs, with a
different trust model and a different signer, so it gets a different program.
`vaid verify` still does exactly one thing: verify a VAID envelope. This script
calls that same verification code — `verifyEnvelope` from
`skill/src/verify-core.mjs`, the one implementation shared by the CLI and the
public verify page — for each entry in `delegation_chain`, and does the
bundle-level work itself.

## What none of this tells you

**Revocation is not checked, and cannot be.** There is no published revocation
list to consult. A delegation chain that passes every check above may still have
been revoked by its issuer, and nothing here would show it. Read a clean result as
*"genuinely issued, in date, and unaltered since signing"* — never as *"currently
authorised"*.

A `policy_version` is **reported, not verified**: the script has no copy of the
named policy bundle to hash, so it cannot confirm the hash describes the policy
that was actually in force.
