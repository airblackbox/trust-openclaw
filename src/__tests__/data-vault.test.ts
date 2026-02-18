import { DataVault } from '../data-vault';
import { VaultConfig } from '../types';

function makeConfig(): VaultConfig {
  return {
    enabled: true,
    categories: ['api_key', 'credential', 'pii'],
    customPatterns: [],
    forwardToGateway: false,
    ttlMs: 24 * 60 * 60 * 1000,
  };
}

describe('DataVault', () => {
  test('tokenizes OpenAI API keys', () => {
    const vault = new DataVault(makeConfig());
    const { result, tokenized, count } = vault.tokenize(
      'My key is sk-abcdefghijklmnopqrstuvwxyz1234'
    );

    expect(tokenized).toBe(true);
    expect(count).toBeGreaterThanOrEqual(1);
    expect(result).toContain('[AIR:vault:');
    expect(result).not.toContain('sk-abcdefghij');
  });

  test('tokenizes multiple sensitive values in one string', () => {
    const vault = new DataVault(makeConfig());
    const input = 'Key: sk-abcdefghijklmnopqrstuvwxyz1234 Email: user@example.com';
    const { result, tokenized, count } = vault.tokenize(input);

    expect(tokenized).toBe(true);
    expect(count).toBeGreaterThanOrEqual(2);
    expect(result).not.toContain('sk-abcdefghij');
    expect(result).not.toContain('user@example.com');
  });

  test('tokenizes AWS access keys', () => {
    const vault = new DataVault(makeConfig());
    const { result, tokenized } = vault.tokenize('AWS key: AKIAIOSFODNN7EXAMPLE');

    expect(tokenized).toBe(true);
    expect(result).toContain('[AIR:vault:');
    expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  test('tokenizes GitHub tokens', () => {
    const vault = new DataVault(makeConfig());
    const { result, tokenized } = vault.tokenize(
      'Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn'
    );

    expect(tokenized).toBe(true);
    expect(result).not.toContain('ghp_');
  });

  test('tokenizes SSN patterns', () => {
    const vault = new DataVault(makeConfig());
    const { result, tokenized } = vault.tokenize('SSN: 123-45-6789');

    expect(tokenized).toBe(true);
    expect(result).toContain('[AIR:vault:pii:');
    expect(result).not.toContain('123-45-6789');
  });

  test('tokenizes connection strings', () => {
    const vault = new DataVault(makeConfig());
    const { result, tokenized } = vault.tokenize(
      'DB: postgres://user:pass@host:5432/db'
    );

    expect(tokenized).toBe(true);
    expect(result).not.toContain('postgres://');
  });

  test('detokenize restores values for single-category tokens', () => {
    const vault = new DataVault(makeConfig());
    // Use a value that only matches one pattern (email = pii only)
    const original = 'Contact: user@example.com';
    const { result } = vault.tokenize(original);

    expect(result).toContain('[AIR:vault:pii:');
    const restored = vault.detokenize(result);
    expect(restored).toBe(original);
  });

  test('leaves non-sensitive text unchanged', () => {
    const vault = new DataVault(makeConfig());
    const input = 'Hello, this is a normal message with no secrets.';
    const { result, tokenized, count } = vault.tokenize(input);

    expect(tokenized).toBe(false);
    expect(count).toBe(0);
    expect(result).toBe(input);
  });

  test('stats tracks token counts by category', () => {
    const vault = new DataVault(makeConfig());
    // Use values that match single patterns to get predictable counts
    vault.tokenize('user@example.com');        // pii only
    vault.tokenize('123-45-6789');             // pii (SSN)
    vault.tokenize('AKIAIOSFODNN7EXAMPLE');    // api_key (AWS)

    const stats = vault.stats();
    expect(stats.totalTokens).toBeGreaterThanOrEqual(3);
    expect(stats.byCategory['pii']).toBeGreaterThanOrEqual(2);
  });

  test('cleanup removes expired tokens', async () => {
    const config = makeConfig();
    config.ttlMs = 1; // 1ms TTL
    const vault = new DataVault(config);

    vault.tokenize('user@example.com');

    // Wait for token to expire
    await new Promise((r) => setTimeout(r, 50));
    const removed = vault.cleanup();
    expect(removed).toBeGreaterThanOrEqual(1);
    expect(vault.stats().totalTokens).toBe(0);
  });

  test('respects category filter', () => {
    const config = makeConfig();
    config.categories = ['api_key']; // Only detect API keys
    const vault = new DataVault(config);

    const { tokenized } = vault.tokenize('user@example.com');
    expect(tokenized).toBe(false); // Email is PII, not api_key
  });
});
