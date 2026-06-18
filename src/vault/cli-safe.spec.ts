import { assertCliSafe } from './cli-safe';

describe('assertCliSafe (argument-injection guard)', () => {
  it('accepts normal secret/group identifiers', () => {
    expect(assertCliSafe('ANTHROPIC_API_KEY')).toBe('ANTHROPIC_API_KEY');
    expect(assertCliSafe('ai-providers', 'group')).toBe('ai-providers');
    expect(assertCliSafe('db.url_2')).toBe('db.url_2');
  });

  it('rejects values that begin with a dash (flag injection)', () => {
    expect(() => assertCliSafe('--vault')).toThrow(/argument-injection/);
    expect(() => assertCliSafe('-X', 'secret key')).toThrow(/secret key/);
  });

  it('rejects empty or non-string values', () => {
    expect(() => assertCliSafe('')).toThrow();
    // @ts-expect-error testing runtime guard
    expect(() => assertCliSafe(undefined)).toThrow();
  });

  it('rejects control characters', () => {
    expect(() => assertCliSafe('bad\nkey')).toThrow(/control characters/);
    expect(() => assertCliSafe('tab\tkey')).toThrow(/control characters/);
  });
});
