"""vaid-langchain — LangChain request-signing adapter for the VAID standard.

Signs every outbound HTTP request an agent tool makes with a VAID proof-of-
possession, via a thin ``httpx.Auth`` seam:

    from vaid_pop import RequestSigner
    from vaid_langchain import make_vaid_tool

    signer = RequestSigner(vaid=my_vaid_doc, private_key=my_key)  # hand-provisioned
    tool = make_vaid_tool(signer, base_url="https://api.example.com")
    # give `tool` to a LangChain agent — its calls to the backend are VAID-signed.

The signing lives in :class:`VaidAuth` (an ``httpx.Auth``); the LangChain tool is
just a registration wrapper. :class:`VaidAuth` is usable standalone with any
``httpx`` client, LangChain not required. The signed request target is the
on-the-wire path + query (:func:`request_target`) — a security decision, see that
function's docs.
"""

from vaid_langchain._target import request_target
from vaid_langchain.auth import VaidAuth
from vaid_langchain.langchain_tool import make_vaid_tool

__all__ = ["VaidAuth", "make_vaid_tool", "request_target"]

__version__ = "0.1.0"
