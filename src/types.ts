/**
 * openclaw-air-trust — Type definitions
 *
 * Interfaces for the AIR trust layer plugin for OpenClaw.
 * Covers config, audit chain entries, consent gating, data vault,
 * and OpenClaw hook event shapes.
 */

// ─── Plugin Configuration ────────────────────────────────────────

export interface AirTrustConfig {
  /** Enable/disable the entire trust layer */
  enabled: boolean;

  /** AIR gateway URL for forwarding audit records */
  gatewayUrl?: string;

  /** API key for the AIR gateway */
  gatewayKey?: string;

  /** Consent gate settings */
  consentGate: ConsentGateConfig;

  /** Audit ledger settings */
  auditLedger: AuditLedgerConfig;

  /** Data vault settings */
  vault: VaultConfig;

  /** Injection detection settings */
  injectionDetection: InjectionDetectionConfig;
}

export interface ConsentGateConfig {
  enabled: boolean;
  /** Tools that always require approval before execution */
  alwaysRequire: string[];
  /** Tools that never need approval */
  neverRequire: string[];
  /** Timeout in ms before auto-rejecting a pending consent */
  timeoutMs: number;
  /** Risk levels that trigger consent */
  riskThreshold: RiskLevel;
}

export interface AuditLedgerConfig {
  enabled: boolean;
  /** Local file path for persisting the chain */
  localPath: string;
  /** Forward entries to AIR gateway */
  forwardToGateway: boolean;
  /** Maximum entries to keep in memory */
  maxEntries: number;
}

export interface VaultConfig {
  enabled: boolean;
  /** Categories of sensitive data to detect */
  categories: string[];
  /** Custom regex patterns */
  customPatterns: TokenizationPattern[];
  /** Forward tokens to AIR vault */
  forwardToGateway: boolean;
  /** TTL in ms for stored tokens (default 24h) */
  ttlMs: number;
}

export interface InjectionDetectionConfig {
  enabled: boolean;
  /** Sensitivity: low, medium, high */
  sensitivity: 'low' | 'medium' | 'high';
  /** Block messages that score above threshold */
  blockThreshold: number;
  /** Log detections to audit ledger */
  logDetections: boolean;
}

// ─── Risk Levels ─────────────────────────────────────────────────

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'none';

export const RISK_ORDER: Record<RiskLevel, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

// ─── Audit Chain ─────────────────────────────────────────────────

export interface AuditEntry {
  /** Unique ID for this entry */
  id: string;
  /** Monotonic sequence number */
  sequence: number;
  /** SHA-256 hash of the entry content */
  hash: string;
  /** Hash of the previous entry (empty string for genesis) */
  prevHash: string;
  /** HMAC-SHA256 signature */
  signature: string;
  /** ISO timestamp */
  timestamp: string;
  /** What happened */
  action: string;
  /** Tool name if applicable */
  toolName?: string;
  /** Risk level of the action */
  riskLevel: RiskLevel;
  /** Whether consent was required */
  consentRequired: boolean;
  /** Whether consent was granted */
  consentGranted?: boolean;
  /** Was sensitive data detected and tokenized */
  dataTokenized: boolean;
  /** Was a prompt injection detected */
  injectionDetected: boolean;
  /** Free-form metadata */
  metadata: Record<string, unknown>;
}

export interface ChainVerification {
  valid: boolean;
  totalEntries: number;
  brokenAtSequence?: number;
  brokenAtId?: string;
  reason?: string;
}

// ─── Consent Gate ────────────────────────────────────────────────

export interface ConsentRequest {
  id: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  riskLevel: RiskLevel;
  reason: string;
  status: 'pending' | 'approved' | 'rejected' | 'timeout';
  createdAt: string;
  resolvedAt?: string;
}

// ─── Data Vault ──────────────────────────────────────────────────

export interface TokenizationPattern {
  name: string;
  category: string;
  regex: RegExp;
  replacement?: string;
}

export interface VaultToken {
  tokenId: string;
  category: string;
  createdAt: string;
  expiresAt: string;
  /** The original value — stored locally only, never sent to LLM */
  originalValue: string;
}

// ─── Injection Detection ─────────────────────────────────────────

export interface InjectionResult {
  detected: boolean;
  score: number;
  patterns: string[];
  blocked: boolean;
}

// ─── OpenClaw Hook Events ────────────────────────────────────────

export interface ToolCallEvent {
  toolName: string;
  args: Record<string, unknown>;
  sessionId: string;
  timestamp: string;
}

export interface ToolCallResult {
  /** If true, the tool call is blocked */
  blocked: boolean;
  /** Reason for blocking (shown to agent) */
  reason?: string;
  /** Modified args (if the vault tokenized anything) */
  modifiedArgs?: Record<string, unknown>;
}

export interface ToolResultEvent {
  toolName: string;
  args: Record<string, unknown>;
  result: unknown;
  durationMs: number;
  sessionId: string;
  timestamp: string;
}

export interface LlmEvent {
  role: 'input' | 'output';
  content: string;
  model?: string;
  sessionId: string;
  timestamp: string;
}

export interface MessageEvent {
  role: 'user' | 'assistant' | 'system';
  content: string;
  sessionId: string;
  timestamp: string;
}

export interface PluginContext {
  sessionId: string;
  sendMessage: (content: string) => Promise<void>;
}
