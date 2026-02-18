/**
 * openclaw-air-trust — Audit Ledger
 *
 * Tamper-evident action log using HMAC-SHA256 chaining.
 * Each entry includes the hash of the previous entry, creating
 * a blockchain-style chain. Modifying any entry breaks the chain.
 *
 * Supports local persistence and non-blocking forwarding to
 * the AIR Blackbox gateway.
 */

import { createHmac, createHash, randomBytes, randomUUID } from 'crypto';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';
import {
  AuditEntry,
  AuditLedgerConfig,
  ChainVerification,
  RiskLevel,
} from './types';

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export class AuditLedger {
  private entries: AuditEntry[] = [];
  private secret: Buffer;
  private lastHash: string = GENESIS_HASH;
  private sequence: number = 0;
  private config: AuditLedgerConfig;
  private gatewayUrl?: string;
  private gatewayKey?: string;

  constructor(
    config: AuditLedgerConfig,
    gatewayUrl?: string,
    gatewayKey?: string
  ) {
    this.config = config;
    this.gatewayUrl = gatewayUrl;
    this.gatewayKey = gatewayKey;

    // Load or generate HMAC key
    const keyPath = config.localPath.replace(/\.json$/, '') + '.key';
    if (existsSync(keyPath)) {
      this.secret = Buffer.from(readFileSync(keyPath, 'utf-8').trim(), 'hex');
    } else {
      this.secret = randomBytes(32);
      this.ensureDir(keyPath);
      writeFileSync(keyPath, this.secret.toString('hex'), { mode: 0o600 });
    }

    // Load existing chain
    this.loadChain();
  }

  /**
   * Append an action to the audit chain.
   * Returns the signed entry.
   */
  append(params: {
    action: string;
    toolName?: string;
    riskLevel: RiskLevel;
    consentRequired: boolean;
    consentGranted?: boolean;
    dataTokenized: boolean;
    injectionDetected: boolean;
    metadata?: Record<string, unknown>;
  }): AuditEntry {
    this.sequence++;

    const entry: AuditEntry = {
      id: randomUUID(),
      sequence: this.sequence,
      hash: '', // computed below
      prevHash: this.lastHash,
      signature: '', // computed below
      timestamp: new Date().toISOString(),
      action: params.action,
      toolName: params.toolName,
      riskLevel: params.riskLevel,
      consentRequired: params.consentRequired,
      consentGranted: params.consentGranted,
      dataTokenized: params.dataTokenized,
      injectionDetected: params.injectionDetected,
      metadata: params.metadata ?? {},
    };

    // Compute content hash (everything except hash, signature, prevHash)
    const contentForHash = JSON.stringify({
      id: entry.id,
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      action: entry.action,
      toolName: entry.toolName,
      riskLevel: entry.riskLevel,
      consentRequired: entry.consentRequired,
      consentGranted: entry.consentGranted,
      dataTokenized: entry.dataTokenized,
      injectionDetected: entry.injectionDetected,
      metadata: entry.metadata,
    });
    entry.hash = createHash('sha256').update(contentForHash).digest('hex');

    // HMAC signature chains this entry to the previous one
    const sigPayload = `${entry.sequence}|${entry.id}|${entry.hash}|${entry.prevHash}`;
    entry.signature = createHmac('sha256', this.secret)
      .update(sigPayload)
      .digest('hex');

    this.lastHash = entry.hash;
    this.entries.push(entry);

    // Trim if over max
    if (this.config.maxEntries > 0 && this.entries.length > this.config.maxEntries) {
      this.entries = this.entries.slice(-this.config.maxEntries);
    }

    // Persist locally
    this.saveChain();

    // Non-blocking forward to gateway
    if (this.config.forwardToGateway && this.gatewayUrl) {
      this.forwardEntry(entry).catch(() => {
        // Silent fail — gateway forwarding is best-effort
      });
    }

    return entry;
  }

  /**
   * Verify the integrity of the entire chain.
   * Walks entries in order, checking prevHash linkage and HMAC signatures.
   */
  verify(): ChainVerification {
    if (this.entries.length === 0) {
      return { valid: true, totalEntries: 0 };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (const entry of this.entries) {
      // Check prevHash linkage
      if (entry.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          brokenAtSequence: entry.sequence,
          brokenAtId: entry.id,
          reason: `prevHash mismatch at sequence ${entry.sequence}`,
        };
      }

      // Recompute content hash
      const contentForHash = JSON.stringify({
        id: entry.id,
        sequence: entry.sequence,
        timestamp: entry.timestamp,
        action: entry.action,
        toolName: entry.toolName,
        riskLevel: entry.riskLevel,
        consentRequired: entry.consentRequired,
        consentGranted: entry.consentGranted,
        dataTokenized: entry.dataTokenized,
        injectionDetected: entry.injectionDetected,
        metadata: entry.metadata,
      });
      const computedHash = createHash('sha256').update(contentForHash).digest('hex');

      if (entry.hash !== computedHash) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          brokenAtSequence: entry.sequence,
          brokenAtId: entry.id,
          reason: `Content hash mismatch at sequence ${entry.sequence}`,
        };
      }

      // Verify HMAC signature
      const sigPayload = `${entry.sequence}|${entry.id}|${entry.hash}|${entry.prevHash}`;
      const expectedSig = createHmac('sha256', this.secret)
        .update(sigPayload)
        .digest('hex');

      if (entry.signature !== expectedSig) {
        return {
          valid: false,
          totalEntries: this.entries.length,
          brokenAtSequence: entry.sequence,
          brokenAtId: entry.id,
          reason: `Signature mismatch at sequence ${entry.sequence}`,
        };
      }

      expectedPrevHash = entry.hash;
    }

    return { valid: true, totalEntries: this.entries.length };
  }

  /** Get the N most recent entries */
  getRecent(n: number = 50): AuditEntry[] {
    return this.entries.slice(-n);
  }

  /** Export all entries */
  export(): AuditEntry[] {
    return [...this.entries];
  }

  /** Chain stats */
  stats(): {
    totalEntries: number;
    chainValid: boolean;
    earliest?: string;
    latest?: string;
  } {
    const verification = this.verify();
    return {
      totalEntries: this.entries.length,
      chainValid: verification.valid,
      earliest: this.entries[0]?.timestamp,
      latest: this.entries[this.entries.length - 1]?.timestamp,
    };
  }

  // ─── Private Methods ────────────────────────────────────────

  private loadChain(): void {
    if (existsSync(this.config.localPath)) {
      try {
        const raw = readFileSync(this.config.localPath, 'utf-8');
        const data = JSON.parse(raw);
        this.entries = data.entries ?? [];
        this.sequence = data.sequence ?? 0;
        this.lastHash = data.lastHash ?? GENESIS_HASH;
      } catch {
        // Corrupted file — start fresh
        this.entries = [];
        this.sequence = 0;
        this.lastHash = GENESIS_HASH;
      }
    }
  }

  private saveChain(): void {
    this.ensureDir(this.config.localPath);
    const data = {
      entries: this.entries,
      sequence: this.sequence,
      lastHash: this.lastHash,
      savedAt: new Date().toISOString(),
    };
    writeFileSync(this.config.localPath, JSON.stringify(data, null, 2));
  }

  private async forwardEntry(entry: AuditEntry): Promise<void> {
    if (!this.gatewayUrl) return;
    const url = `${this.gatewayUrl}/v1/audit`;
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.gatewayKey ? { Authorization: `Bearer ${this.gatewayKey}` } : {}),
      },
      body: JSON.stringify(entry),
    });
  }

  private ensureDir(filePath: string): void {
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }
}
