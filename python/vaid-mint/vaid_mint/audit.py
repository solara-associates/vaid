"""Audit seam — Python mirror of the Rust ``vaid_mint::audit``.

In the closed managed authority the mint writes every issuance to a durable,
hash-chained audit-of-record, and a write that does not audit is a failed mint.
That ledger is the commercial product. Here the seam is :class:`AuditSink`, with
:class:`InMemoryAudit` (captures entries) and :class:`NoopAudit` (discards).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass
class AuditEntry:
    event_type: str
    details: dict


@runtime_checkable
class AuditSink(Protocol):
    """The audit write seam. Raising fails the mint (the closed "writes that don't
    audit are rejected" invariant)."""

    def record(self, event_type: str, details: dict) -> None:
        ...


class InMemoryAudit:
    """Captures every entry in memory — the reference/testing sink."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, event_type: str, details: dict) -> None:
        self.entries.append(AuditEntry(event_type=event_type, details=details))

    def is_empty(self) -> bool:
        return not self.entries


class NoopAudit:
    """Discards every entry — for a self-hoster who accepts un-recorded mints."""

    def record(self, event_type: str, details: dict) -> None:
        return None
