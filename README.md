# openclaw-air-trust

**EU AI Act compliance infrastructure for OpenClaw TypeScript agents.** Drop-in trust layer that adds tamper-evident audit logging, PII tokenization, consent-based tool gating, and prompt injection detection — making your TypeScript agent stack compliant with Articles 9, 10, 11, 12, 14, and 15 of the EU AI Act.

> The EU AI Act enforcement date for high-risk AI systems is **August 2, 2026**. See the [full compliance mapping](./docs/eu-ai-act-compliance.md) for article-by-article coverage.

[![CI](https://github.com/airblackbox/trust-openclaw/actions/workflows/ci.yml/badge.svg)](https://github.com/airblackbox/trust-openclaw/actions)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## What It Does

This plugin adds four trust capabilities to any OpenClaw agent:

| Capability | What It Does | OpenClaw Hook |
|---|---|---|
| **Audit Ledger** | HMAC-SHA256 tamper-evident chain of every action | `before_tool_call`, `after_tool_call`, `llm_output` |
| **Consent Gate** | Blocks destructive tools until user approves | `before_tool_call` |
| **Data Vault** | Tokenizes API keys, PII, credentials before they reach the LLM | `before_tool_call`, `llm_input` |
| **Injection Detector** | Scores inbound messages for prompt injection patterns | `message_received`, `llm_input` |

Every action is signed and chained. Modify any record and the chain breaks — you can prove exactly what your agent did, when, and whether a human approved it.

## Install

```bash
npm install openclaw-air-trust
```

## Quick Start

```typescript
import { createAirTrustPlugin } from 'openclaw-air-trust';

const trust = createAirTrustPlugin({
  enabled: true,
  consentGate: {
    enabled: true,
    alwaysRequire: ['exec', 'deploy', 'shell'],
    neverRequire: ['fs_read', 'search'],
    timeoutMs: 30000,
    riskThreshold: 'high',
  },
  injectionDetection: {
    enabled: true,
    sensitivity: 'medium',
    blockThreshold: 0.8,
    logDetections: true,
  },
});

// Register with OpenClaw's hook system
registerHook('before_tool_call', trust.beforeToolCall);
registerHook('after_tool_call', trust.afterToolCall);
registerHook('llm_input', trust.onLlmInput);
registerHook('llm_output', trust.onLlmOutput);
registerHook('message_received', trust.onMessageReceived);
```

## How It Works

### Audit Ledger

Every tool call, LLM interaction, consent decision, and injection detection gets appended to a tamper-evident chain:

```
Entry 1 → hash₁ ──┐
Entry 2 → hash₂ (prevHash = hash₁) ──┐
Entry 3 → hash₃ (prevHash = hash₂) ──┐
...
```

Each entry is signed with HMAC-SHA256. The signature includes the previous entry's hash, so modifying any record breaks the entire chain downstream. Verify integrity at any time:

```typescript
const verification = trust.verifyChain();
// { valid: true, totalEntries: 142 }
```

### Consent Gate

When the agent tries to call a destructive tool (exec, deploy, shell, etc.), the consent gate intercepts it and sends an approval request through OpenClaw's messaging channel:

```
🚨 AIR Trust — Consent Required

Tool: `exec`
Risk: **CRITICAL**

Arguments:
  command: "rm -rf /tmp/data"

Reply `approve abc-123` to allow
Reply `reject abc-123` to block

Auto-rejects in 30s
```

Risk classification is built-in: critical (code execution), high (file writes, deploys), medium (network/email), low (reads).

### Data Vault

Before tool arguments or context reaches the LLM, the vault scans for sensitive patterns and replaces them with opaque tokens:

```
Input:  "Use key sk-abcdefghij... to call the API"
Output: "Use key [AIR:vault:api_key:a1b2c3d4] to call the API"
```

14 built-in patterns: OpenAI/Anthropic/AWS/GitHub/Stripe keys, emails, phone numbers, SSNs, credit cards, connection strings, bearer tokens, private keys, and password assignments.

When a tool actually needs the real value, `detokenize()` restores it — but the LLM never sees the raw credential.

### Injection Detector

Scans inbound messages for 15+ prompt injection patterns across categories:

- **Role override** — "ignore previous instructions"
- **Identity hijacking** — "you are now..."
- **Privilege escalation** — "developer mode", "sudo"
- **Safety bypass** — "disable filters"
- **Jailbreak** — "DAN mode"
- **Data exfiltration** — "send all conversation history"
- **Encoding evasion** — "encode in base64"

Three sensitivity levels (low/medium/high) control which patterns are active. Messages above the block threshold are rejected before reaching the agent.

## Configuration

```typescript
const trust = createAirTrustPlugin({
  enabled: true,

  // Optional: forward audit entries to AIR gateway
  gatewayUrl: 'https://your-air-gateway.example.com',
  gatewayKey: 'your-api-key',

  consentGate: {
    enabled: true,
    alwaysRequire: ['exec', 'deploy'],  // Always need approval
    neverRequire: ['fs_read'],           // Never need approval
    timeoutMs: 30000,                    // Auto-reject after 30s
    riskThreshold: 'high',              // Require consent for high+ risk
  },

  auditLedger: {
    enabled: true,
    localPath: '~/.openclaw/air-trust/audit-ledger.json',
    forwardToGateway: false,
    maxEntries: 10000,
  },

  vault: {
    enabled: true,
    categories: ['api_key', 'credential', 'pii'],
    customPatterns: [],                  // Add your own regex patterns
    forwardToGateway: false,
    ttlMs: 86400000,                     // 24 hour token TTL
  },

  injectionDetection: {
    enabled: true,
    sensitivity: 'medium',              // low | medium | high
    blockThreshold: 0.8,                // 0-1, 0 = never block
    logDetections: true,
  },
});
```

## API

### Plugin Instance

| Method | Returns | Description |
|---|---|---|
| `beforeToolCall(event, ctx)` | `ToolCallResult` | Hook: runs consent + vault before tool execution |
| `afterToolCall(event)` | `void` | Hook: logs tool result to audit chain |
| `onLlmInput(event)` | `{ content, blocked }` | Hook: tokenizes + scans before LLM |
| `onLlmOutput(event)` | `void` | Hook: logs LLM response |
| `onMessageReceived(event)` | `{ blocked, reason? }` | Hook: scans messages for injection |
| `handleConsentResponse(id, approved)` | `boolean` | Resolve a pending consent request |
| `getAuditStats()` | Stats object | Chain length, validity, time range |
| `verifyChain()` | Verification result | Walk chain and check integrity |
| `exportAudit()` | `AuditEntry[]` | Export all chain entries |
| `getVaultStats()` | Stats object | Token counts by category |

### Individual Components

Each component can be used standalone:

```typescript
import { AuditLedger, ConsentGate, DataVault, InjectionDetector } from 'openclaw-air-trust';
```

## EU AI Act Compliance

| EU AI Act Article | Requirement | AIR Feature |
|---|---|---|
| Art. 9 | Risk management | ConsentGate risk classification |
| Art. 10 | Data governance | DataVault PII tokenization |
| Art. 11 | Technical documentation | Full call graph audit logging |
| Art. 12 | Record-keeping | HMAC-SHA256 tamper-evident chain |
| Art. 14 | Human oversight | Consent-based tool blocking |
| Art. 15 | Robustness & security | InjectionDetector + multi-layer defense |

See [docs/eu-ai-act-compliance.md](./docs/eu-ai-act-compliance.md) for the full article-by-article mapping.

## AIR Blackbox Ecosystem

| Package | Framework | Install |
|---|---|---|
| `air-langchain-trust` | LangChain / LangGraph | `pip install air-langchain-trust` |
| `air-crewai-trust` | CrewAI | `pip install air-crewai-trust` |
| `air-openai-agents-trust` | OpenAI Agents SDK | `pip install air-openai-agents-trust` |
| `air-autogen-trust` | Microsoft AutoGen | `pip install air-autogen-trust` |
| `openclaw-air-trust` | TypeScript / Node.js | `npm install openclaw-air-trust` |
| `air-compliance` | Compliance checker CLI | `pip install air-compliance` |
| Gateway | Any HTTP agent | `docker pull ghcr.io/airblackbox/gateway:main` |

## Development

```bash
git clone https://github.com/airblackbox/trust-openclaw.git
cd trust-openclaw
npm install
npm run build
npm test
```

## License

Apache-2.0
