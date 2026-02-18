import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { ConsentGate } from '../consent-gate';
import { AuditLedger } from '../audit-ledger';
import { ConsentGateConfig, AuditLedgerConfig, PluginContext } from '../types';

function makeLedger(dir: string): AuditLedger {
  return new AuditLedger({
    enabled: true,
    localPath: join(dir, 'ledger.json'),
    forwardToGateway: false,
    maxEntries: 100,
  });
}

function makeConfig(): ConsentGateConfig {
  return {
    enabled: true,
    alwaysRequire: ['deploy', 'exec'],
    neverRequire: ['fs_read', 'search'],
    timeoutMs: 2000,
    riskThreshold: 'high',
  };
}

function makeCtx(): PluginContext {
  return {
    sessionId: 'test-session',
    sendMessage: jest.fn().mockResolvedValue(undefined),
  };
}

describe('ConsentGate', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'air-test-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  test('classifyRisk returns correct levels for known tools', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    expect(gate.classifyRisk('exec')).toBe('critical');
    expect(gate.classifyRisk('fs_write')).toBe('high');
    expect(gate.classifyRisk('send_email')).toBe('medium');
    expect(gate.classifyRisk('fs_read')).toBe('low');
    expect(gate.classifyRisk('unknown_tool')).toBe('low');
  });

  test('classifyRisk matches partial tool names', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    expect(gate.classifyRisk('run_shell_command')).toBe('critical');
    expect(gate.classifyRisk('my_deploy_tool')).toBe('high');
  });

  test('requiresConsent respects neverRequire list', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    expect(gate.requiresConsent('fs_read')).toBe(false);
    expect(gate.requiresConsent('search')).toBe(false);
  });

  test('requiresConsent respects alwaysRequire list', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    expect(gate.requiresConsent('deploy')).toBe(true);
    expect(gate.requiresConsent('exec')).toBe(true);
  });

  test('requiresConsent uses risk threshold for unlisted tools', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    // High threshold — critical and high should require consent
    expect(gate.requiresConsent('shell')).toBe(true);     // critical
    expect(gate.requiresConsent('fs_write')).toBe(true);   // high
    expect(gate.requiresConsent('send_email')).toBe(false); // medium (below high threshold)
  });

  test('intercept sends consent message and blocks on timeout', async () => {
    const gate = new ConsentGate(
      { ...makeConfig(), timeoutMs: 100 },
      makeLedger(tmpDir)
    );
    const ctx = makeCtx();

    const result = await gate.intercept(
      { toolName: 'exec', args: { cmd: 'rm -rf /' }, sessionId: 'test', timestamp: new Date().toISOString() },
      ctx
    );

    expect(result.blocked).toBe(true);
    expect(ctx.sendMessage).toHaveBeenCalledTimes(1);
    const message = (ctx.sendMessage as jest.Mock).mock.calls[0][0];
    expect(message).toContain('Consent Required');
    expect(message).toContain('exec');
  });

  test('intercept allows tool when consent not required', async () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    const ctx = makeCtx();

    const result = await gate.intercept(
      { toolName: 'fs_read', args: { path: '/tmp' }, sessionId: 'test', timestamp: new Date().toISOString() },
      ctx
    );

    expect(result.blocked).toBe(false);
    expect(ctx.sendMessage).not.toHaveBeenCalled();
  });

  test('handleResponse resolves pending consent', async () => {
    const gate = new ConsentGate(
      { ...makeConfig(), timeoutMs: 5000 },
      makeLedger(tmpDir)
    );
    const ctx = makeCtx();

    // Start intercept in background
    const interceptPromise = gate.intercept(
      { toolName: 'exec', args: {}, sessionId: 'test', timestamp: new Date().toISOString() },
      ctx
    );

    // Extract consent ID from the message
    await new Promise((r) => setTimeout(r, 50));
    const message = (ctx.sendMessage as jest.Mock).mock.calls[0][0] as string;
    const idMatch = message.match(/approve\s+([a-f0-9-]+)/);
    expect(idMatch).toBeTruthy();

    // Approve it
    const handled = gate.handleResponse(idMatch![1], true);
    expect(handled).toBe(true);

    const result = await interceptPromise;
    expect(result.blocked).toBe(false);
  });

  test('formatConsentMessage includes risk and tool info', () => {
    const gate = new ConsentGate(makeConfig(), makeLedger(tmpDir));
    const message = gate.formatConsentMessage({
      id: 'test-id-123',
      toolName: 'exec',
      toolArgs: { command: 'echo hello' },
      riskLevel: 'critical',
      reason: 'test',
      status: 'pending',
      createdAt: new Date().toISOString(),
    });

    expect(message).toContain('CRITICAL');
    expect(message).toContain('exec');
    expect(message).toContain('echo hello');
    expect(message).toContain('test-id-123');
  });
});
