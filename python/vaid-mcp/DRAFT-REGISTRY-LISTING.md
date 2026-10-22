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

`io.github.solara-associates/vaid-mcp` — the `io.github.<account>/*` form,
required by the registry for GitHub-based auth
([registry docs](https://modelcontextprotocol.io/registry/authentication)).
`mcp-publisher login github` runs a GitHub OAuth device-code flow; the
registry grants publish rights to whatever `io.github.<account>` namespace
that authenticated identity is authorized for. The docs don't spell out the
org-membership check beyond that — in practice it means: log in as a
`solara-associates` member (or org owner), and publishing under
`io.github.solara-associates/*` will fail at that step if the account isn't
one. No DNS/domain verification is needed for this path.

## Submission steps, confirmed against the current registry docs — NOT RUN

1. **Publish `vaid-mcp` 0.1.0 to PyPI first.** The registry's publish step
   does a live lookup against `https://pypi.org/pypi/vaid-mcp/json` and
   fetches the PyPI-rendered README to check for the required marker (next
   step) — it does not accept an unpublished package. This needs Allan's
   approval same as any release in this repo.
2. **README marker, already added** (`python/vaid-mcp/README.md` line 3):
   `<!-- mcp-name: io.github.solara-associates/vaid-mcp -->`. Must appear
   in the README exactly as rendered on PyPI, matching `server.json`'s
   `name` field.
3. **Authenticate:**
   ```sh
   mcp-publisher login github
   ```
   (device-code OAuth flow; the signed-in account must be a
   `solara-associates` member for the namespace below to be accepted.)
4. **Validate, then publish:**
   ```sh
   mcp-publisher validate server.json
   mcp-publisher publish server.json
   ```

Do not run any of steps 1, 3 or 4 until Allan has explicitly approved the
PyPI release and the registry submission separately — the PyPI publish is
itself the first irreversible step (a yanked PyPI release still occupies
the version number) and the registry publish references it directly.
