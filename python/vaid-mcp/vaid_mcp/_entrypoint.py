"""Minimal entry-point classification (estate ADR-0002: every externally
reachable handler carries exactly one of @public or @privileged).

vaid-mcp has no actor model at all: every tool here is a pure function over
whatever the caller pasted in (a chain, a key, a URL) — there is no notion of
"which authenticated principal is calling" to require, because nothing a
tool does depends on one. So every tool is `@public`, and this package does
not define `@privileged` — adding a concept nothing here needs would be
speculative.
"""

from __future__ import annotations

from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable)


def public(fn: F) -> F:
    """Marks `fn` as a classified-public entry point. A no-op at runtime;
    its only job is to make the classification visible at the call site."""
    fn.__vaid_mcp_entrypoint__ = "public"  # type: ignore[attr-defined]
    return fn
