/**
 * openclaw-air-trust — Data Vault
 *
 * Detects sensitive data (API keys, PII, credentials) in tool
 * arguments and LLM context, replaces them with opaque tokens.
 * Original values are stored locally and optionally forwarded
 * to the AIR vault for centralized management.
 *
 * Token format: [AIR:vault:category:tokenId]
 */

import { randomUUID } from 'crypto';
import { TokenizationPattern, VaultConfig, VaultToken } from './types';

/** Built-in patterns for common sensitive data */
const BUILTIN_PATTERNS: TokenizationPattern[] = [
  {
    name: 'OpenAI API Key',
    category: 'api_key',
    regex: /sk-[A-Za-z0-9]{20,}/g,
  },
  {
    name: 'Anthropic API Key',
    category: 'api_key',
    regex: /sk-ant-[A-Za-z0-9\-]{20,}/g,
  },
  {
    name: 'AWS Access Key',
    category: 'api_key',
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    name: 'GitHub Token',
    category: 'api_key',
    regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
  },
  {
    name: 'Stripe Key',
    category: 'api_key',
    regex: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
  },
  {
    name: 'Bearer Token',
    category: 'credential',
    regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g,
  },
  {
    name: 'Private Key Block',
    category: 'credential',
    regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g,
  },
  {
    name: 'Connection String',
    category: 'credential',
    regex: /(?:mongodb|postgres|mysql|redis):\/\/[^\s"']+/g,
  },
  {
    name: 'Email Address',
    category: 'pii',
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  {
    name: 'Phone Number',
    category: 'pii',
    regex: /(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
  },
  {
    name: 'SSN',
    category: 'pii',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    name: 'Credit Card',
    category: 'pii',
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,
  },
  {
    name: 'Password in URL',
    category: 'credential',
    regex: /(?<=:\/\/[^:]+:)[^@\s]+(?=@)/g,
  },
  {
    name: 'Generic Secret Assignment',
    category: 'credential',
    regex: /(?:password|secret|token|api_key|apikey)\s*[:=]\s*["']?[A-Za-z0-9\-._~+/]{8,}["']?/gi,
  },
];

export class DataVault {
  private config: VaultConfig;
  private tokens: Map<string, VaultToken> = new Map();
  private patterns: TokenizationPattern[];
  private gatewayUrl?: string;
  private gatewayKey?: string;

  constructor(config: VaultConfig, gatewayUrl?: string, gatewayKey?: string) {
    this.config = config;
    this.gatewayUrl = gatewayUrl;
    this.gatewayKey = gatewayKey;

    // Combine built-in patterns with custom ones
    this.patterns = [
      ...BUILTIN_PATTERNS.filter((p) =>
        config.categories.length === 0 || config.categories.includes(p.category)
      ),
      ...config.customPatterns,
    ];
  }

  /**
   * Scan text for sensitive data and replace with vault tokens.
   * Returns the tokenized text and whether any replacements were made.
   */
  tokenize(text: string): { result: string; tokenized: boolean; count: number } {
    let result = text;
    let count = 0;

    for (const pattern of this.patterns) {
      // Reset regex lastIndex for global patterns
      pattern.regex.lastIndex = 0;

      result = result.replace(pattern.regex, (match) => {
        const tokenId = randomUUID().slice(0, 8);
        const fullToken = `[AIR:vault:${pattern.category}:${tokenId}]`;

        // Store the original value
        const vaultToken: VaultToken = {
          tokenId,
          category: pattern.category,
          createdAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + this.config.ttlMs).toISOString(),
          originalValue: match,
        };
        this.tokens.set(tokenId, vaultToken);

        // Non-blocking forward to gateway
        if (this.config.forwardToGateway && this.gatewayUrl) {
          this.forwardToken(vaultToken).catch(() => {});
        }

        count++;
        return fullToken;
      });
    }

    return { result, tokenized: count > 0, count };
  }

  /**
   * Replace vault tokens back with original values.
   * Used when the tool actually needs the real value (e.g., to make an API call).
   */
  detokenize(text: string): string {
    return text.replace(
      /\[AIR:vault:([^:]+):([^\]]+)\]/g,
      (_match, _category, tokenId) => {
        const token = this.tokens.get(tokenId);
        if (token) return token.originalValue;
        return _match; // Leave as-is if token not found
      }
    );
  }

  /** Vault stats */
  stats(): { totalTokens: number; byCategory: Record<string, number> } {
    const byCategory: Record<string, number> = {};
    for (const token of this.tokens.values()) {
      byCategory[token.category] = (byCategory[token.category] ?? 0) + 1;
    }
    return { totalTokens: this.tokens.size, byCategory };
  }

  /** Clean up expired tokens */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    for (const [id, token] of this.tokens.entries()) {
      if (new Date(token.expiresAt).getTime() < now) {
        this.tokens.delete(id);
        removed++;
      }
    }
    return removed;
  }

  // ─── Private ────────────────────────────────────────────────

  private async forwardToken(token: VaultToken): Promise<void> {
    if (!this.gatewayUrl) return;
    const url = `${this.gatewayUrl}/v1/vault/store`;
    // Forward only the token ID and category — never the original value
    await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.gatewayKey ? { Authorization: `Bearer ${this.gatewayKey}` } : {}),
      },
      body: JSON.stringify({
        tokenId: token.tokenId,
        category: token.category,
        createdAt: token.createdAt,
        expiresAt: token.expiresAt,
      }),
    });
  }
}
