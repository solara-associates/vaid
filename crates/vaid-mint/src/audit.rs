//! The audit seam — stubbed for the reference mint.
//!
//! In the closed managed authority the mint writes every issuance to a durable,
//! hash-chained audit-of-record, and a write that does not audit is a failed
//! mint. That durable ledger is part of the commercial product, not this open
//! engine. Here the seam is a trait, [`AuditSink`], with two reference
//! implementations a self-hoster can use as-is or replace:
//!
//! - [`InMemoryAudit`] — captures entries in memory (the template is the closed
//!   repo's test `CapturingAudit`); useful for tests and for inspecting what a
//!   mint recorded.
//! - [`NoopAudit`] — discards entries. For a self-hoster who has not yet wired a
//!   real sink and accepts un-recorded mints.
//!
//! A real deployment implements [`AuditSink`] over its own durable store. The
//! mint calls `record` after issuing and treats a returned error as a failed
//! mint, preserving the closed invariant "a mint that cannot be recorded fails".

use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::MintResult;

/// A recorded mint event: the event type (always `"vaid_minted"` here) and a
/// JSON detail payload describing what was minted.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub event_type: String,
    pub details: Value,
}

/// The audit write seam. A deployment backs this with its durable, hash-chained
/// ledger; the reference provides in-memory and no-op implementations.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Record a mint event. Returning `Err` fails the mint (the closed
    /// "writes that don't audit are rejected" invariant).
    async fn record(&self, event_type: &str, details: Value) -> MintResult<()>;
}

/// Captures every entry in memory. The reference/testing sink.
#[derive(Default)]
pub struct InMemoryAudit {
    entries: Mutex<Vec<AuditEntry>>,
}

impl InMemoryAudit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded entries.
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().expect("audit lock not poisoned").clone()
    }

    /// Number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("audit lock not poisoned").len()
    }

    /// True if nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl AuditSink for InMemoryAudit {
    async fn record(&self, event_type: &str, details: Value) -> MintResult<()> {
        self.entries.lock().expect("audit lock not poisoned").push(AuditEntry {
            event_type: event_type.to_string(),
            details,
        });
        Ok(())
    }
}

/// Discards every entry. For a self-hoster who accepts un-recorded mints until a
/// real sink is wired.
#[derive(Default)]
pub struct NoopAudit;

#[async_trait]
impl AuditSink for NoopAudit {
    async fn record(&self, _event_type: &str, _details: Value) -> MintResult<()> {
        Ok(())
    }
}
