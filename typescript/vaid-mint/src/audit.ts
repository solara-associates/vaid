/**
 * The audit seam — stubbed for the reference mint. TypeScript mirror of the Rust
 * `vaid_mint::audit`.
 *
 * In the closed managed authority the mint writes every issuance to a durable,
 * hash-chained audit-of-record, and a write that does not audit is a failed mint.
 * That durable ledger is part of the commercial product, not this open engine.
 * Here the seam is an interface, {@link AuditSink}, with two reference
 * implementations a self-hoster can use as-is or replace:
 *
 * - {@link InMemoryAudit} — captures entries in memory; useful for tests and for
 *   inspecting what a mint recorded.
 * - {@link NoopAudit} — discards entries. For a self-hoster who has not yet wired
 *   a real sink and accepts un-recorded mints.
 *
 * A real deployment implements {@link AuditSink} over its own durable store. The
 * mint calls `record` after issuing and treats a rejected promise as a failed
 * mint, preserving the closed invariant "a mint that cannot be recorded fails".
 */

/**
 * A recorded mint event: the event type (always `"vaid_minted"` here) and a JSON
 * detail payload describing what was minted.
 */
export interface AuditEntry {
  eventType: string;
  details: Record<string, unknown>;
}

/**
 * The audit write seam. A deployment backs this with its durable, hash-chained
 * ledger; the reference provides in-memory and no-op implementations.
 */
export interface AuditSink {
  /**
   * Record a mint event. Rejecting fails the mint (the closed "writes that don't
   * audit are rejected" invariant).
   */
  record(eventType: string, details: Record<string, unknown>): Promise<void>;
}

/** Captures entries in memory, for tests and for inspecting what a mint recorded. */
export class InMemoryAudit implements AuditSink {
  #entries: AuditEntry[] = [];

  async record(eventType: string, details: Record<string, unknown>): Promise<void> {
    this.#entries.push({ eventType, details });
  }

  /** A copy of the recorded entries, oldest first. */
  entries(): readonly AuditEntry[] {
    return [...this.#entries];
  }

  get length(): number {
    return this.#entries.length;
  }

  isEmpty(): boolean {
    return this.#entries.length === 0;
  }

  clear(): void {
    this.#entries = [];
  }
}

/** Discards entries. For a self-hoster who accepts un-recorded mints. */
export class NoopAudit implements AuditSink {
  async record(): Promise<void> {
    // Intentionally empty.
  }
}
