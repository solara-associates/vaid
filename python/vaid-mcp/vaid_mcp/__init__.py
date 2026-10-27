"""vaid-mcp — an MCP server exposing the open VAID standard as four tools.

Every cryptographic and attenuation check is performed by ``vaid_mint``
(the published open-source reference mint/verifier); this package only
shapes that into MCP tool calls with plain-English results. It calls no
Solara-internal service, persists no key it is handed, and sends no data
anywhere except to a ``.well-known`` key URL the caller itself supplies.
"""

__version__ = "0.1.0"
