/**
 * openclaw-air-trust — Main Plugin Entry Point
 *
 * Registers all trust layer hooks with OpenClaw:
 * - before_tool_call  → ConsentGate (approval) + DataVault (tokenize args)
 * - after_tool_call   → AuditLedger (log result)
 * - llm_input         → DataVault (tokenize context) + InjectionDetector
 * - llm_output        → AuditLedger (log LLM response)
 * - message_received  → InjectionDetector (scan user/external messages)
 *
 * Usage:
 *   import { createAirTrustPlugin } from 'openclaw-air-trust';
 *   const plugin = createAirTrustPlugin({ enabled: true, ... });
 *   // Register with OpenClaw's plugin system
 */

import { homedir } from 'os';
import { join } from 'path';
import {
  AirTrustConfig,
  ToolCallEvent,
  ToolCallResult,
  ToolResultEvent,
  LlmEvent,
  MessageEvent,
  PluginContext,
} from './types';
import { AuditLedger } from './audit-ledger';
import { ConsentGate } from './consent-gate';
import { DataVault } from './data-vault';
import { InjectionDetector } from './injection-detector';

// ─── Default Configuration ───────────────────────────────────

const DEFAULT_CONFIG: AirTrustConfig = {
  enabled: true,
  consentGate: {
    enabled: true,
    alwaysRequire: ['exec', 'spawn', 'shell', 'deploy'],
    neverRequire: ['fs_read', 'search', 'query'],
    timeoutMs: 30_000,
    riskThreshold: 'high',
  },
  auditLedger: {
    enabled: true,
    localPath: join(homedir(), '.openclaw', 'air-trust', 'audit-ledger.json'),
    forwardToGateway: false,
    maxEntries: 10_000,
  },
  vault: {
    enabled: true,
    categories: ['api_key', 'credential', 'pii'],
    customPatterns: [],
    forwardToGateway: false,
    ttlMs: 24 * 60 * 60 * 1000, // 24 hours
  },
  injectionDetection: {
    enabled: true,
    sensitivity: 'medium',
    blockThreshold: 0.8,
    logDetections: true,
  },
};

// ─── Plugin Interface ────────────────────────────────────────

export interface AirTrustPlugin {
  name: string;
  version: string;

  /** Hook: called before each tool call */
  beforeToolCall: (event: ToolCallEvent, ctx: PluginContext) => Promise<ToolCallResult>;

  /** Hook: called after each tool call completes */
  afterToolCall: (event: ToolResultEvent) => Promise<void>;

  /** Hook: called before content is sent to the LLM */
  onLlmInput: (event: LlmEvent) => Promise<{ content: string; blocked: boolean }>;

  /** Hook: called after LLM responds */
  onLlmOutput: (event: LlmEvent) => Promise<void>;

  /** Hook: called when a message is received (from user or external) */
  onMessageReceived: (event: MessageEvent) => Promise<{ blocked: boolean; reason?: string }>;

  /** Handle a user consent response */
  handleConsentResponse: (consentId: string, approved: boolean) => boolean;

  /** Get audit chain stats */
  getAuditStats: () => ReturnType<AuditLedger['stats']>;

  /** Verify chain integrity */
  verifyChain: () => ReturnType<AuditLedger['verify']>;

  /** Export audit entries */
  exportAudit: () => ReturnType<AuditLedger['export']>;

  /** Get vault stats */
  getVaultStats: () => ReturnType<DataVault['stats']>;
}

// ─── Factory ─────────────────────────────────────────────────

export function createAirTrustPlugin(
  userConfig?: Partial<AirTrustConfig>
): AirTrustPlugin {
  const config: AirTrustConfig = {
    ...DEFAULT_CONFIG,
    ...userConfig,
    consentGate: { ...DEFAULT_CONFIG.consentGate, ...userConfig?.consentGate },
    auditLedger: { ...DEFAULT_CONFIG.auditLedger, ...userConfig?.auditLedger },
    vault: { ...DEFAULT_CONFIG.vault, ...userConfig?.vault },
    injectionDetection: {
      ...DEFAULT_CONFIG.injectionDetection,
      ...userConfig?.injectionDetection,
    },
  };

  // Initialize components
  const ledger = new AuditLedger(
    config.auditLedger,
    config.gatewayUrl,
    config.gatewayKey
  );
  const consentGate = new ConsentGate(config.consentGate, ledger);
  const vault = new DataVault(config.vault, config.gatewayUrl, config.gatewayKey);
  const injectionDetector = new InjectionDetector(config.injectionDetection);

  // Start periodic vault cleanup
  const cleanupInterval = setInterval(() => vault.cleanup(), 60 * 60 * 1000); // hourly
  // Prevent interval from keeping the process alive
  if (cleanupInterval.unref) cleanupInterval.unref();

  return {
    name: 'air-trust',
    version: '0.1.0',

    // ─── before_tool_call ──────────────────────────────────
    async beforeToolCall(
      event: ToolCallEvent,
      ctx: PluginContext
    ): Promise<ToolCallResult> {
      if (!config.enabled) return { blocked: false };

      // 1. Tokenize sensitive data in tool args
      let modifiedArgs = event.args;
      let dataTokenized = false;

      if (config.vault.enabled) {
        const argsStr = JSON.stringify(event.args);
        const tokenized = vault.tokenize(argsStr);
        if (tokenized.tokenized) {
          modifiedArgs = JSON.parse(tokenized.result);
          dataTokenized = true;
        }
      }

      // 2. Check consent gate
      if (config.consentGate.enabled) {
        const consentResult = await consentGate.intercept(
          { ...event, args: modifiedArgs },
          ctx
        );
        if (consentResult.blocked) {
          return consentResult;
        }
      }

      // 3. Log the tool call
      if (config.auditLedger.enabled) {
        ledger.append({
          action: 'tool_call',
          toolName: event.toolName,
          riskLevel: consentGate.classifyRisk(event.toolName),
          consentRequired: consentGate.requiresConsent(event.toolName),
          consentGranted: true,
          dataTokenized,
          injectionDetected: false,
          metadata: { sessionId: event.sessionId },
        });
      }

      return {
        blocked: false,
        modifiedArgs: dataTokenized ? modifiedArgs : undefined,
      };
    },

    // ─── after_tool_call ───────────────────────────────────
    async afterToolCall(event: ToolResultEvent): Promise<void> {
      if (!config.enabled || !config.auditLedger.enabled) return;

      ledger.append({
        action: 'tool_result',
        toolName: event.toolName,
        riskLevel: consentGate.classifyRisk(event.toolName),
        consentRequired: false,
        dataTokenized: false,
        injectionDetected: false,
        metadata: {
          durationMs: event.durationMs,
          sessionId: event.sessionId,
        },
      });
    },

    // ─── llm_input ─────────────────────────────────────────
    async onLlmInput(
      event: LlmEvent
    ): Promise<{ content: string; blocked: boolean }> {
      if (!config.enabled) return { content: event.content, blocked: false };

      let content = event.content;
      let dataTokenized = false;
      let injectionDetected = false;

      // 1. Tokenize sensitive data before it reaches the LLM
      if (config.vault.enabled) {
        const tokenized = vault.tokenize(content);
        if (tokenized.tokenized) {
          content = tokenized.result;
          dataTokenized = true;
        }
      }

      // 2. Check for injection patterns
      if (config.injectionDetection.enabled) {
        const result = injectionDetector.scan(content);
        if (result.detected) {
          injectionDetected = true;

          if (config.injectionDetection.logDetections && config.auditLedger.enabled) {
            ledger.append({
              action: 'injection_detected',
              riskLevel: result.score >= 0.8 ? 'critical' : result.score >= 0.5 ? 'high' : 'medium',
              consentRequired: false,
              dataTokenized,
              injectionDetected: true,
              metadata: {
                score: result.score,
                patterns: result.patterns,
                blocked: result.blocked,
                source: 'llm_input',
              },
            });
          }

          if (result.blocked) {
            return { content: '', blocked: true };
          }
        }
      }

      return { content, blocked: false };
    },

    // ─── llm_output ────────────────────────────────────────
    async onLlmOutput(event: LlmEvent): Promise<void> {
      if (!config.enabled || !config.auditLedger.enabled) return;

      ledger.append({
        action: 'llm_output',
        riskLevel: 'none',
        consentRequired: false,
        dataTokenized: false,
        injectionDetected: false,
        metadata: {
          model: event.model,
          contentLength: event.content.length,
          sessionId: event.sessionId,
        },
      });
    },

    // ─── message_received ──────────────────────────────────
    async onMessageReceived(
      event: MessageEvent
    ): Promise<{ blocked: boolean; reason?: string }> {
      if (!config.enabled) return { blocked: false };

      // Check for injection in incoming messages
      if (config.injectionDetection.enabled) {
        const result = injectionDetector.scan(event.content);

        if (result.detected) {
          if (config.injectionDetection.logDetections && config.auditLedger.enabled) {
            ledger.append({
              action: 'injection_detected',
              riskLevel: result.score >= 0.8 ? 'critical' : result.score >= 0.5 ? 'high' : 'medium',
              consentRequired: false,
              dataTokenized: false,
              injectionDetected: true,
              metadata: {
                score: result.score,
                patterns: result.patterns,
                blocked: result.blocked,
                source: `message_${event.role}`,
              },
            });
          }

          if (result.blocked) {
            return {
              blocked: true,
              reason: `Prompt injection detected (score: ${result.score.toFixed(2)}, patterns: ${result.patterns.join(', ')})`,
            };
          }
        }
      }

      // Handle consent responses
      if (event.role === 'user') {
        const approveMatch = event.content.match(/^approve\s+([a-f0-9-]+)/i);
        const rejectMatch = event.content.match(/^reject\s+([a-f0-9-]+)/i);

        if (approveMatch) {
          consentGate.handleResponse(approveMatch[1], true);
        } else if (rejectMatch) {
          consentGate.handleResponse(rejectMatch[1], false);
        }
      }

      return { blocked: false };
    },

    // ─── Public API ────────────────────────────────────────

    handleConsentResponse(consentId: string, approved: boolean): boolean {
      return consentGate.handleResponse(consentId, approved);
    },

    getAuditStats() {
      return ledger.stats();
    },

    verifyChain() {
      return ledger.verify();
    },

    exportAudit() {
      return ledger.export();
    },

    getVaultStats() {
      return vault.stats();
    },
  };
}

// ─── Exports ─────────────────────────────────────────────────

export { AuditLedger } from './audit-ledger';
export { ConsentGate } from './consent-gate';
export { DataVault } from './data-vault';
export { InjectionDetector } from './injection-detector';
export * from './types';
