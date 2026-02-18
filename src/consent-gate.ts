/**
 * openclaw-air-trust — Consent Gate
 *
 * Intercepts destructive or sensitive tool calls and holds them
 * pending user approval. Classifies tools by risk level and
 * sends approval requests through OpenClaw's messaging channel.
 *
 * Flow:
 * 1. before_tool_call fires
 * 2. ConsentGate checks if tool requires consent
 * 3. If yes: sends approval message, waits for response
 * 4. If approved: tool executes normally
 * 5. If rejected/timeout: tool call is blocked
 * 6. All decisions are logged to the audit ledger
 */

import { randomUUID } from 'crypto';
import {
  ConsentGateConfig,
  ConsentRequest,
  RiskLevel,
  RISK_ORDER,
  ToolCallEvent,
  ToolCallResult,
  PluginContext,
} from './types';
import { AuditLedger } from './audit-ledger';

/** Default risk classification for common tool patterns */
const TOOL_RISK_MAP: Record<string, RiskLevel> = {
  // Critical — arbitrary code execution
  exec: 'critical',
  spawn: 'critical',
  shell: 'critical',
  run_command: 'critical',
  execute: 'critical',

  // High — filesystem writes, destructive actions
  fs_write: 'high',
  fs_delete: 'high',
  file_write: 'high',
  file_delete: 'high',
  apply_patch: 'high',
  rm: 'high',
  rmdir: 'high',
  git_push: 'high',
  deploy: 'high',

  // Medium — communication, network
  send_email: 'medium',
  email_send: 'medium',
  sessions_send: 'medium',
  slack_send: 'medium',
  http_request: 'medium',
  api_call: 'medium',

  // Low — reads, queries
  fs_read: 'low',
  file_read: 'low',
  search: 'low',
  query: 'low',
};

export class ConsentGate {
  private config: ConsentGateConfig;
  private ledger: AuditLedger;
  private pendingRequests: Map<string, {
    request: ConsentRequest;
    resolve: (approved: boolean) => void;
  }> = new Map();

  constructor(config: ConsentGateConfig, ledger: AuditLedger) {
    this.config = config;
    this.ledger = ledger;
  }

  /**
   * Classify risk level for a tool.
   */
  classifyRisk(toolName: string): RiskLevel {
    // Exact match first
    if (TOOL_RISK_MAP[toolName]) return TOOL_RISK_MAP[toolName];

    // Partial match — check if tool name contains any risk keyword
    const lower = toolName.toLowerCase();
    for (const [pattern, level] of Object.entries(TOOL_RISK_MAP)) {
      if (lower.includes(pattern)) return level;
    }

    return 'low';
  }

  /**
   * Check if a tool call requires consent.
   */
  requiresConsent(toolName: string): boolean {
    // Explicit never-require list
    if (this.config.neverRequire.includes(toolName)) return false;

    // Explicit always-require list
    if (this.config.alwaysRequire.includes(toolName)) return true;

    // Risk threshold check
    const risk = this.classifyRisk(toolName);
    return RISK_ORDER[risk] >= RISK_ORDER[this.config.riskThreshold];
  }

  /**
   * Intercept a tool call. If consent is needed, block until approved.
   * Returns a ToolCallResult indicating whether the call should proceed.
   */
  async intercept(
    event: ToolCallEvent,
    ctx: PluginContext
  ): Promise<ToolCallResult> {
    if (!this.requiresConsent(event.toolName)) {
      return { blocked: false };
    }

    const risk = this.classifyRisk(event.toolName);

    const request: ConsentRequest = {
      id: randomUUID(),
      toolName: event.toolName,
      toolArgs: event.args,
      riskLevel: risk,
      reason: `Tool "${event.toolName}" classified as ${risk} risk`,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    // Send approval message to user
    const message = this.formatConsentMessage(request);
    await ctx.sendMessage(message);

    // Wait for approval with timeout
    const approved = await this.waitForApproval(request);

    // Update request status (timeout is set inside waitForApproval)
    const wasTimeout = request.status === 'timeout';
    if (!wasTimeout) {
      request.status = approved ? 'approved' : 'rejected';
    }
    request.resolvedAt = new Date().toISOString();

    // Log to audit ledger
    this.ledger.append({
      action: `consent_${request.status}`,
      toolName: event.toolName,
      riskLevel: risk,
      consentRequired: true,
      consentGranted: approved,
      dataTokenized: false,
      injectionDetected: false,
      metadata: {
        consentId: request.id,
        toolArgs: event.args,
      },
    });

    if (!approved) {
      return {
        blocked: true,
        reason: `Tool call rejected: ${wasTimeout ? 'approval timed out' : 'user rejected'}`,
      };
    }

    return { blocked: false };
  }

  /**
   * Handle a user response to a consent request.
   * Call this when the user sends "approve <id>" or "reject <id>".
   */
  handleResponse(consentId: string, approved: boolean): boolean {
    const pending = this.pendingRequests.get(consentId);
    if (!pending) return false;

    pending.resolve(approved);
    this.pendingRequests.delete(consentId);
    return true;
  }

  /**
   * Format a human-readable consent message.
   */
  formatConsentMessage(request: ConsentRequest): string {
    const riskEmoji: Record<RiskLevel, string> = {
      critical: '\u{1F6A8}',
      high: '\u{26A0}\u{FE0F}',
      medium: '\u{1F7E1}',
      low: '\u{1F7E2}',
      none: '\u{2705}',
    };

    const emoji = riskEmoji[request.riskLevel];
    const argsSummary = Object.entries(request.toolArgs)
      .map(([k, v]) => `  ${k}: ${JSON.stringify(v)}`)
      .join('\n');

    return [
      `${emoji} **AIR Trust — Consent Required**`,
      ``,
      `Tool: \`${request.toolName}\``,
      `Risk: **${request.riskLevel.toUpperCase()}**`,
      ``,
      `Arguments:`,
      argsSummary || '  (none)',
      ``,
      `Reply \`approve ${request.id}\` to allow`,
      `Reply \`reject ${request.id}\` to block`,
      ``,
      `Auto-rejects in ${Math.round(this.config.timeoutMs / 1000)}s`,
    ].join('\n');
  }

  // ─── Private ────────────────────────────────────────────────

  private waitForApproval(request: ConsentRequest): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      // Store resolver so handleResponse can call it
      this.pendingRequests.set(request.id, { request, resolve });

      // Auto-reject on timeout
      setTimeout(() => {
        if (this.pendingRequests.has(request.id)) {
          request.status = 'timeout';
          this.pendingRequests.delete(request.id);
          resolve(false);
        }
      }, this.config.timeoutMs);
    });
  }
}
