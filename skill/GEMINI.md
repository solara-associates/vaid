<!-- BEGIN vaid-skill -->
<!-- Managed by vaid-skill. Edits inside this block are overwritten on reinstall. -->

# VAID — Verifiable Agent Identity

A VAID is a signed statement about an agent: its class, tenant, scope boundary,
capability set, validity window, and its parent in a delegation chain. It is
Ed25519-signed over canonical bytes, so anyone holding the issuer's **public** key
can check it with no network call, no credential from the issuer, and no
permission from anyone.

This skill is a thin wrapper over the published `vaid-mint` SDK. It implements no
cryptography of its own. The Rust, Python and TypeScript mints are locked
byte-for-byte to shared conformance vectors; anything this skill did differently
would be a bug in this skill.

## The four verbs

There are exactly four, and there is no fifth.

| verb | what it does |
|---|---|
| `mint` | issue a VAID (root, or an attenuated child of one you hold) |
| `present` | package a VAID you hold into the one-line form you send to someone |
| `verify` | check a VAID you received, offline, against a pinned trust anchor |
| `revoke` | mark a VAID revoked **on this machine only** — read the warning below |

```bash
npx -p vaid-skill vaid mint --class orchestrator --tenant acme --caps read,write --ttl 24
npx -p vaid-skill vaid verify 'vaid1:eyJ2IjoxL…'
```

`npx <name>` resolves `<name>` as a **package**, so `-p vaid-skill` is what makes
the `vaid` bin reachable without a local install. Once installed it is just
`vaid …`, and `npx vaid-skill` runs the installer.

## When to use this

**Mint** when this agent is about to act on behalf of a tenant and something
downstream will want to know who is asking. Mint *short*: the default TTL is 24
hours and shorter is better, because expiry is the only revocation that actually
works offline (see below).

**Mint a child** (`--parent`) when you are handing work to a sub-agent. A child's
authority is always a subset of its parent's — the mint refuses to widen scope or
capabilities, so a delegation chain can only narrow. This is the property worth
having: it means a compromised sub-agent cannot exceed what you gave it, and a
third party can *check* that, rather than take your word.

**Present** when a human or another system needs the credential. The output is
one line, and it is designed to survive being pasted into a chat message.

**Verify** whenever you receive a VAID. Never accept one because it "looks
right" — a VAID is JSON, and JSON is trivially forged. The signature is the only
thing that means anything.

## What a verdict actually establishes

`verify` returns several findings, not one boolean, because the questions fail
independently and collapsing them is how a verifier ends up reporting *valid*
when it means *the one thing I checked passed*.

It establishes:

- **Signing key** — the document names a kernel key that is in the pinned trust
  anchor, and that key's thumbprint was recomputed from the key itself rather
  than taken on the document's word.
- **Signature** — the Ed25519 signature is valid over the canonical document, and
  `lineage_hash` is internally consistent. Every signed field is exactly as issued.
- **Validity window** — whether it is past `expires_at`.
- **Delegation** — if ancestors were presented, that the chain assembles to a root
  and authority is contained at every hop. If a VAID names a parent but presents
  no ancestors, attenuation is **unverifiable**, which is not the same as satisfied.
- **Issuer identity** — whether `trust_domain` is a real name or an RFC 6761
  special-use one. A special-use name means the issuer deliberately has not been
  configured, and a conforming verifier must not bind a trust bundle to it.

It does **not** establish:

- **Revocation.** Never. There is no published revocation list to consult. The
  open reference mint's revocation is in-memory and does not survive its own
  process; durable revocation is not part of the open standard. A VAID that
  passes every check above may have been revoked by its issuer minutes ago and
  nothing here would show it.

Read a passing verdict as **"genuinely issued and in date"**. Do not read it as
"currently authorised". If you need the second, you need short TTLs — which is
why they are short.

## `revoke` does less than its name

`vaid revoke` writes to a file in `~/.vaid`. That is the whole effect. No third
party consults that file, the public verify page cannot see it, and the holder of
the VAID can keep presenting it everywhere else successfully. It is a note to
yourself.

If you need a revocation somebody else can observe, this tool does not do that,
and neither does the open standard. Shorten the TTL instead.

## Sending a VAID to someone

`mint` prints a single-line `vaid1:` envelope. It is unpadded base64url of a JSON
object holding the document and any presented ancestors — one token, no
whitespace, safe in a URL, a shell argument, a YAML scalar or a chat message. It
is deliberately not compressed, so anyone can decode it and read the document
without trusting our tooling:

```bash
# base64url is unpadded. `base64 -d` does not reject unpadded input — it silently
# drops the last partial group, handing back JSON short of its final brace. Pad first.
b=${ENVELOPE#vaid1:}; b=$(printf '%s' "$b" | tr '_-' '/+')
while [ $(( ${#b} % 4 )) -ne 0 ]; do b="$b="; done
printf '%s' "$b" | base64 -d | jq .
```

(The padding loop matters more than it looks. base64url is unpadded, and
`base64 -d` does **not** reject unpadded input — it accepts it and silently drops
the final partial group, returning JSON short of its last brace, with no error and
nothing on stderr. Without the loop the command only fully succeeds when the token
length happens to be a multiple of 4, so the failure presents as *your credential
is invalid JSON* when the credential is intact and the command is wrong.)

The recipient can check it three ways, and needs nothing from us for any of them:

1. Paste it into <https://solara.associates/vaid/verify> — a fully client-side
   page. Nothing is uploaded; it verifies with the network off.
2. `npx -p vaid-skill vaid verify '<the line>'`
3. Any implementation of the standard, in Rust, Python or TypeScript.

**Two channels, not one.** For a VAID minted by your own local issuer, the
recipient also needs your kernel public key, and it must reach them over a
channel you do not control the way you control the first. Sending the envelope
and the key down the same wire proves nothing: whoever can rewrite one can
rewrite the other. `mint` prints the key as a `<thumbprint>=<key>` line for
exactly this. (VAIDs minted by the Solara production substrate need none of
this — that key is already pinned in the anchor this skill ships.)

**`--trust` persists.** `vaid verify --trust '<tp>=<key>'` writes that key to
`~/.vaid/trusted-keys.json` and leaves it there: every later `vaid verify` on the
machine accepts that issuer, including runs with no `--trust` flag. That is a
standing trust decision, not a one-off. `vaid verify --trusted` lists everything
the machine has accepted and where it came from. The browser page keeps such keys
for the session only — persistent suits a CLI whose whole job is repeated
verification, session-only suits a page a stranger opens once.

## Agent guidance

- **Verify before acting on a presented VAID, not after.** The point of the
  credential is to gate the work.
- **Do not paste `~/.vaid/issuer.json` anywhere.** It is a private signing seed.
  Anyone holding it can mint VAIDs indistinguishable from yours.
- **Do not invent fields.** The document schema is fixed and signed; an extra key
  breaks the signature. If something is missing, it belongs in a proposal against
  the standard, not in a local patch.
- **Do not treat an expired VAID as forged.** `verify` reports `EXPIRED`
  separately from `REJECTED` on purpose — the fix for one is "renew", for the
  other "you were never authorised", and telling someone the wrong one sends them
  a long way in the wrong direction.
- **When reporting a verdict to a human, report the revocation caveat too.**
  Dropping it because it was not the interesting part is how a caveat stops
  existing.

## Reference

- Standard, specs and ADRs: <https://github.com/solara-associates/vaid>
- Trust anchor (published kernel keys):
  <https://solara.associates/.well-known/synthera-kernel-keys.json>
- SDKs: `vaid-mint`, `vaid-pop`, `vaid-client` on crates.io, PyPI and npm.

<!-- END vaid-skill -->
