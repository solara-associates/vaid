# DRAFT — not submitted

Prepared for the official MCP registry and community directories (e.g.
Smithery, mcp.so). Nothing here has been submitted; publishing needs Allan's
approval in the GitHub UI, same as a PyPI release of this package.

## Listing description (short, for a directory card)

> Verify, decode, and check permissions on VAID agent-identity delegation
> chains — four tools, no setup required to try one. Built on the
> open-source `vaid-mint` reference verifier (Apache-2.0); calls no
> external service except a `.well-known` key URL you supply yourself.

## Namespace

`io.github.solara-associates/vaid-mcp` — verified at publish time via GitHub
OAuth/OIDC membership in the `solara-associates` org, per the registry's
reverse-DNS namespace rule. No domain verification needed.

## Publishing, when approved

```sh
# one-time: authenticate as a solara-associates org member
mcp-publisher login github

# validate server.json against the schema, then publish
mcp-publisher validate server.json
mcp-publisher publish server.json
```

This requires `vaid-mcp` 0.1.0 to already be on PyPI (the `packages[0]`
entry in `server.json` names the PyPI package `mcp-publisher` will check
against). Do not run either command until Allan has approved the PyPI
release itself.
