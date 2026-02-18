import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { AuditLedger } from '../audit-ledger';
import { AuditLedgerConfig } from '../types';

function makeConfig(dir: string): AuditLedgerConfig {
  return {
    enabled: true,
    localPath: join(dir, 'ledger.json'),
    forwardToGateway: false,
    maxEntries: 100,
  };
}

describe('AuditLedger', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'air-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('append creates entries with incrementing sequence', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    const e1 = ledger.append({
      action: 'tool_call', toolName: 'fs_read', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });
    const e2 = ledger.append({
      action: 'tool_call', toolName: 'exec', riskLevel: 'critical',
      consentRequired: true, consentGranted: true, dataTokenized: false, injectionDetected: false,
    });

    expect(e1.sequence).toBe(1);
    expect(e2.sequence).toBe(2);
    expect(e1.id).not.toBe(e2.id);
  });

  test('chain links entries via prevHash', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    const e1 = ledger.append({
      action: 'test1', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });
    const e2 = ledger.append({
      action: 'test2', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });

    expect(e1.prevHash).toBe('0000000000000000000000000000000000000000000000000000000000000000');
    expect(e2.prevHash).toBe(e1.hash);
  });

  test('verify returns valid for untampered chain', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    for (let i = 0; i < 5; i++) {
      ledger.append({
        action: `action_${i}`, riskLevel: 'low',
        consentRequired: false, dataTokenized: false, injectionDetected: false,
      });
    }

    const result = ledger.verify();
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBe(5);
  });

  test('verify returns valid for empty chain', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    const result = ledger.verify();
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBe(0);
  });

  test('entries have deterministic HMAC signatures', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    const e1 = ledger.append({
      action: 'test', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });

    expect(e1.signature).toBeTruthy();
    expect(e1.signature.length).toBe(64); // SHA-256 hex
    expect(e1.hash.length).toBe(64);
  });

  test('getRecent returns last N entries', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    for (let i = 0; i < 10; i++) {
      ledger.append({
        action: `action_${i}`, riskLevel: 'low',
        consentRequired: false, dataTokenized: false, injectionDetected: false,
      });
    }

    const recent = ledger.getRecent(3);
    expect(recent.length).toBe(3);
    expect(recent[0].action).toBe('action_7');
    expect(recent[2].action).toBe('action_9');
  });

  test('export returns all entries', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    for (let i = 0; i < 5; i++) {
      ledger.append({
        action: `action_${i}`, riskLevel: 'low',
        consentRequired: false, dataTokenized: false, injectionDetected: false,
      });
    }

    const all = ledger.export();
    expect(all.length).toBe(5);
  });

  test('stats returns correct summary', () => {
    const ledger = new AuditLedger(makeConfig(tmpDir));
    ledger.append({
      action: 'first', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });
    ledger.append({
      action: 'last', riskLevel: 'high',
      consentRequired: true, consentGranted: true, dataTokenized: false, injectionDetected: false,
    });

    const s = ledger.stats();
    expect(s.totalEntries).toBe(2);
    expect(s.chainValid).toBe(true);
    expect(s.earliest).toBeTruthy();
    expect(s.latest).toBeTruthy();
  });

  test('persists and reloads chain from disk', () => {
    const config = makeConfig(tmpDir);
    const ledger1 = new AuditLedger(config);
    ledger1.append({
      action: 'persisted', riskLevel: 'low',
      consentRequired: false, dataTokenized: false, injectionDetected: false,
    });

    // Create new instance — should reload from disk
    const ledger2 = new AuditLedger(config);
    const stats = ledger2.stats();
    expect(stats.totalEntries).toBe(1);
    expect(stats.chainValid).toBe(true);
  });

  test('maxEntries trims old entries', () => {
    const config = makeConfig(tmpDir);
    config.maxEntries = 5;
    const ledger = new AuditLedger(config);

    for (let i = 0; i < 10; i++) {
      ledger.append({
        action: `action_${i}`, riskLevel: 'low',
        consentRequired: false, dataTokenized: false, injectionDetected: false,
      });
    }

    const all = ledger.export();
    expect(all.length).toBe(5);
    expect(all[0].action).toBe('action_5');
  });
});
