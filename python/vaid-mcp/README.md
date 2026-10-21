# vaid-mcp

An MCP server for the open [VAID](../../README.md) agent-identity standard.
Four tools, stdio transport, no setup required to try it.

This package implements no cryptography of its own. Every signature check,
chain walk, and scope comparison is performed by the published open-source
[`vaid-mint`](../vaid-mint) library. No tool here calls any Solara-internal
service, persists any key it is handed, or sends data anywhere except to a
`key_url` you explicitly pass in.

## Install

```sh
pip install vaid-mcp
```

(Not published yet. For now, from a checkout of this repo:)

```sh
pip install -e python/vaid-mint -e python/vaid-mcp
```

## Try it in under 5 minutes, no setup

Add it to an MCP client — for example, Claude Code:

```sh
claude mcp add vaid -- vaid-mcp
```

Then, in the client, ask it to call `mint_demo_chain_tool`. That mints a
throwaway two-hop VAID chain (a root plus one delegated child) with a
brand-new key that lives only for that one call, and hands you back:

- `chain` — the chain itself, ready to paste into the other tools
- `public_key_hex` — the key to verify it against

Paste both straight into `verify_chain`:

```json
{
  "chain": { "leaf": { ... }, "ancestors": [ { ... } ] },
  "public_key": "<public_key_hex from the demo>"
}
```

You should see `"verdict": "attenuated"` and `"is_valid": true` — the chain
is genuine, complete, and nothing in it exceeds what its parent allowed.

Now try `check_scope_tool` with the same `chain` and `public_key`, plus the
`resource` and `capability` the demo chain was minted with (both come back
in the demo's `try_next` hint) as `requested_action` / `resource` — it should
say `"permitted": true`. Ask for a capability the chain was not minted with
and it says `"permitted": false`, with a plain-English reason.

That is the whole loop: mint a demo chain, verify it, decode it, and check
what it is allowed to do, with no key management of your own.

## The four tools

- **`verify_chain`** — verify a pasted VAID delegation chain against a public
  key you supply directly, or a `key_url` pointing at a JSON file shaped like
  this repo's [`docs/kernel-keys.json`](../../docs/kernel-keys.json). Returns
  an overall verdict, a plain-English reason, and a per-hop breakdown.
- **`explain_vaid_tool`** — decode a single VAID into plain language: who it
  identifies, who delegated it, what it claims it may do and where, and
  until when. Performs no verification; everything it reports could be
  fabricated. Use `verify_chain` to find out whether it actually is.
- **`check_scope_tool`** — given a chain and a requested action and resource,
  say whether the leaf permits it, and why. If the chain itself does not
  verify, this refuses to answer permitted or denied at all, rather than
  guessing — an unverifiable chain is never treated as permissive.
- **`mint_demo_chain_tool`** — mint the throwaway demo chain described above.
  Every document it returns is genuinely signed and will pass `verify_chain`;
  the key behind it exists only for the one call that minted it.

## Using a real key, not the demo

For a chain minted by a real deployment, you need that deployment's kernel
public key through a channel you trust — never from the chain itself, which
can claim anything about its own signer. See
[`docs/trust-anchor.md`](../../docs/trust-anchor.md) for why, and either:

- pass the raw 32-byte Ed25519 public key as `public_key` (64 hex characters,
  or unpadded base64url), or
- pass `key_url`, an `https://` URL you control to a document shaped
  `{"keys": {"<thumbprint>": {"kty": "OKP", "crv": "Ed25519", "x": "..."}}}`.

`key_url` is the only network call any tool in this package makes, and it is
only ever made to the URL you gave it. It is hardened against being pointed
somewhere it should not go: only `https://` is accepted (no plain `http://`),
the resolved address is checked before every request — including each
redirect hop — and refused if it is loopback, private, link-local (which
covers cloud metadata endpoints like `169.254.169.254`), multicast, or
otherwise reserved, and the response is capped in size and bounded by a
timeout.

## What this is not

- Not a wrapper around SYNTHERA or any other Solara-internal service. It
  verifies the published open-source VAID standard, nothing else.
- Not a key management service. Nothing is persisted between calls.
- Not a production credential issuer. `mint_demo_chain_tool` exists only to
  let you try the other tools; treat everything it returns as disposable.

## Development

```sh
pip install -e python/vaid-mint -e 'python/vaid-mcp[test]'
pytest python/vaid-mcp/tests
vaid-mcp-conformance   # the packaged firewall release.yml runs against the published wheel
```
