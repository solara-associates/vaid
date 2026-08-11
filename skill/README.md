# vaid-skill

An Agent Skill for **VAID** — Verifiable Agent Identity. Mint, present, verify and
revoke short-lived, cryptographically signed agent credentials from Claude Code,
Codex, Cursor, Gemini CLI or Copilot — or from a plain terminal.

```bash
npx -p vaid-skill vaid mint --class orchestrator --tenant acme --caps read --ttl 24
npx -p vaid-skill vaid verify 'vaid1:eyJ2IjoxL…'
```

(`npx <name>` resolves `<name>` as a **package**, so reaching a bin whose name is
not the package name needs `-p`. Once installed, it is just `vaid`.)

Install into whichever agents you have:

```bash
npx vaid-skill            # install into every agent detected here
npx vaid-skill --global   # your home directory instead of this project
npx vaid-skill --dry-run  # print the plan, change nothing
```

## What a VAID is

A signed statement about an agent: its class, tenant, scope boundary, capability
set, validity window, and its parent in a delegation chain. Ed25519 over canonical
bytes, so anyone holding the issuer's **public** key can check it offline — no
network call, no account, no cooperation from the issuer.

A child's authority is always a subset of its parent's. The mint refuses to widen
scope or capabilities, and a third party can verify that containment rather than
take your word for it.

## This package is a wrapper

It implements no cryptography. Everything comes from the published
[`vaid-mint`](https://www.npmjs.com/package/vaid-mint) and
[`vaid-pop`](https://www.npmjs.com/package/vaid-pop) packages, whose Rust, Python
and TypeScript implementations are locked byte-for-byte to shared conformance
vectors. Anything this package did differently would be a bug in this package.

What it adds is three things the SDK deliberately leaves to a caller: the
single-line **envelope** that makes a VAID sendable, a **plural verdict** that
keeps authenticity, expiry, delegation, issuer identity and revocation apart, and
a **pinned trust anchor** so `verify` works with the network off.

## The envelope

`mint` prints one line:

```
vaid1:eyJ2IjoxLCJ2YWlkIjp7InNpZ192ZXJzaW9uIjozLCJ2YWlkX2lkIjoi…
```

Unpadded base64url of a JSON object holding the document and any presented
ancestors. One token, no whitespace, safe in a URL, a shell argument, a YAML
scalar or a chat message — the four places it actually gets pasted. It is
deliberately **not** compressed, so anyone can read it without our tooling:

```bash
# base64url is unpadded. `base64 -d` does not reject unpadded input — it silently
# drops the last partial group, handing back JSON short of its final brace. Pad first.
b=${ENVELOPE#vaid1:}; b=$(printf '%s' "$b" | tr '_-' '/+')
while [ $(( ${#b} % 4 )) -ne 0 ]; do b="$b="; done
printf '%s' "$b" | base64 -d | jq .
```

The recipient can check it three ways, needing nothing from us for any of them:

1. <https://solara.associates/vaid/verify> — fully client-side; works offline.
2. `npx -p vaid-skill vaid verify '<the line>'`
3. Any implementation of the standard.

## What `verify` establishes

Authenticity, expiry, delegation containment, and whether the issuer's
`trust_domain` is a real name or an RFC 6761 special-use one.

**Not revocation. Ever.** There is no published revocation list to consult — the
open reference mint's list is in-memory and does not survive its own process, and
durable revocation is not part of the open standard. A passing verdict means
*genuinely issued and in date*, never *currently authorised*. `verify` says so on
every run, including on rejections.

`vaid revoke` writes to a file in `~/.vaid` and that is its entire effect. No
third party consults it. If you need a revocation someone else can observe, this
tool does not do that; shorten the TTL instead.

## Two channels

A VAID minted by your own local issuer is signed by a key nobody else has. `mint`
prints that key as a `<thumbprint>=<key>` line — send it over a channel you do not
control the way you control the first. Sending both down one wire proves nothing:
whoever can rewrite the envelope can rewrite the key beside it.

VAIDs from the Solara production substrate need none of this; that key is already
pinned in the anchor this package ships (`trust-anchor.json`, byte-checked against
`docs/kernel-keys.json` in CI).

`--trust` **persists** to `~/.vaid/trusted-keys.json`, so every later `vaid verify`
on the machine accepts that issuer — a standing decision, not a one-off.
`vaid verify --trusted` lists what the machine has accepted, and where each key
came from, so it can be reviewed and withdrawn.

## Verbs

| verb | |
|---|---|
| `vaid mint` | `--class --tenant --scope --caps --ttl --parent --json --quiet` |
| `vaid present` | round-trips an envelope so a truncated paste fails here, not at the far end |
| `vaid verify` | `--trust '<tp>=<key>' --trusted --at <rfc3339> --json`; exit 0 accepted, 1 rejected/expired, 4 malformed |
| `vaid revoke` | `<vaid_id> --reason "…"` or `--list`; local only |

State lives in `~/.vaid` (`VAID_HOME` to override). `issuer.json` is a private
signing seed, created `0600`.

## Working in this directory: `main` is published

**Anything committed to `skill/` on `main` can reach a new user before it is
released.** This directory is not staged behind a version tag or a release branch.
Three channels read it, and two of them read `main` directly:

| channel | what it takes | when |
|---|---|---|
| npm (`vaid-skill`) | the published tarball | only on release |
| `.well-known` index → `npx skills add` | `skills/vaid/SKILL.md` at the vendored digest | on site deploy |
| Claude Code plugin marketplace | **whatever `.claude-plugin/` and `skills/` contain at `main` head** | nightly, automatically |

The marketplace catalog pins each plugin to a commit SHA and re-pins it as the
repository moves. Nothing declares which commit is a release: tags do not hold the
pin — entries declaring `v1.0.1` and `v0.1.0` are pinned to their default branch
instead — so the pin follows head. A fresh `/plugin install` clones at that pin.

So the rule is:

> **`skill/` on `main` should only ever carry shippable state.** Work in progress
> belongs on a branch until it is good enough for a stranger to install.

The operational consequence, stated so nobody has to discover it when CI turns red:

> **Any change to `skill/` on `main` needs a release tag to follow it, or the pin
> check goes red.** That includes documentation-only changes — a plugin install
> clones this whole directory, so a README edit is a change to what users receive.
> The check compares the git tree hash of `skill/` at the catalog's pin against the
> tree at `vaid-skill-v<version>`; any difference is a difference, and it does not
> care whether the change was cosmetic.
>
> That is the cost of not having a release branch, and it is the intended shape
> rather than a rough edge: it makes "`main` drifted past the release" a red X in
> `anchor-origin.yml` instead of something a user finds first. If a change to this
> directory is not worth tagging a release for, it is not worth landing on `main`.

Two things soften this, and neither removes it:

- `version` in `.claude-plugin/plugin.json` gates **updates for people who already
  installed** — they do not move until it is bumped. It does **nothing** for new
  installs, which take the pin regardless.
- A pin that advances to a commit where `skill/` is byte-identical is harmless. Only
  a *content* change to this directory can reach anyone.

The alternatives — a release branch, or splitting this directory into its own
repository — were considered and declined: they buy a guarantee at the cost of a
second release credential and a cross-repo synchronisation problem. Recorded so the
trade is revisited deliberately if this ever bites, rather than re-argued from
scratch. See vaid `BACKLOG.md` for the evidence behind the pin behaviour.

### Do not put this note in `SKILL.md`

`skills/vaid/SKILL.md` is a **digest-gated artifact**. Its bytes are hashed into
`https://solara.associates/.well-known/agent-skills/index.json`, and the `skills`
CLI refuses any artifact whose recomputed digest disagrees with the published one.
Editing that file — even to add a comment — invalidates the published digest until
the site index is re-vendored *and* redeployed. In the window between, the refusal is
silent: installers are told "no well-known skills found", with no checksum error and
nothing reported back to us (`BACKLOG.md` B4). Notes for humans go here; that file
changes only when the skill's behaviour does.

## Tests

```bash
npm test                  # verify core, with the negative controls
bash test/acceptance.sh   # end-to-end across process boundaries
node scripts/check-anchor.mjs
```

The negative cases are the point. A verifier that returns "valid" for everything
passes every happy-path test ever written, so each positive assertion is paired
with the mutation that must break it.

## Links

- Standard, specs and ADRs — <https://github.com/solara-associates/vaid>
- Trust anchor — <https://solara.associates/.well-known/synthera-kernel-keys.json>
- SDKs — `vaid-mint`, `vaid-pop`, `vaid-client` on crates.io, PyPI and npm

Apache-2.0.
