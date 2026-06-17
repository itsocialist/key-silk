/**
 * TUI unit tests — tuiInject handler
 *
 * Strategy: mock enquirer's prompt, vault, audit, and the injection/template
 * modules, then call tuiInject directly to verify the inject flow writes
 * secrets to the target .env and handles edge cases correctly.
 *
 * Prompt call sequence for the happy path (no templates, gitignored):
 *   1. { group }       — select group
 *   2. { keyScope }    — "All keys in group" | "Select individual keys"
 *   3. { targetPath }  — destination .env path
 *   4. { overwrite }   — overwrite existing keys?
 *
 * Additional prompts inserted when:
 *   - keyScope === 'Select individual keys' → { selectedKeys } multiselect
 *   - templates available                  → { useTemplate } + optional { tmplName }
 *   - target not gitignored                → { proceed } safety confirm
 *
 * Coverage:
 *   tuiInject — happy path (all keys) writes secrets to target .env
 *   tuiInject — individual key selection injects only chosen keys
 *   tuiInject — empty selection aborts without writing
 *   tuiInject — no secrets → early return, no prompt shown
 *   tuiInject — no groups → warns and returns
 *   tuiInject — gitignore warning aborts when user declines
 *   tuiInject — gitignore warning proceeds when user confirms
 *   tuiInject — overwrite flag passed through to injectSecrets
 *   tuiInject — template content passed through when selected
 *   tuiInject — values map cleared after injection (memory scrub)
 *
 * checkGitignore:
 *   — returns false without hanging when given a relative path and no .gitignore
 */

// ── Module mocks (hoisted before imports by Jest) ──────────────────────────

jest.mock('enquirer', () => ({
  prompt: jest.fn(),
}));

jest.mock('./injection/dotenv-writer', () => ({
  injectSecrets:  jest.fn().mockResolvedValue(1),
  checkGitignore: jest.fn().mockResolvedValue(true),
}));

jest.mock('./injection/template-loader', () => ({
  listTemplates: jest.fn().mockResolvedValue([]),
  loadTemplate:  jest.fn().mockResolvedValue('# Template content\n'),
}));

// ── Imports ────────────────────────────────────────────────────────────────

import { tuiInject } from './tui';
import { checkGitignore } from './injection/dotenv-writer';
import { VaultBackend, SecretMetadata } from './vault/vault';
import { AuditLogger } from './audit/logger';
import { ServerConfig } from './config/config';
import { prompt } from 'enquirer';
import { injectSecrets } from './injection/dotenv-writer';
import { listTemplates, loadTemplate } from './injection/template-loader';
import { promises as fs } from 'fs';
import * as path from 'path';

// ── Typed mock handles ─────────────────────────────────────────────────────

const mockPrompt         = prompt         as jest.MockedFunction<typeof prompt>;
const mockInjectSecrets  = injectSecrets  as jest.MockedFunction<typeof injectSecrets>;
const mockCheckGitignore = checkGitignore as jest.MockedFunction<typeof checkGitignore>;
const mockListTemplates  = listTemplates  as jest.MockedFunction<typeof listTemplates>;
const mockLoadTemplate   = loadTemplate   as jest.MockedFunction<typeof loadTemplate>;

// ── Shared helpers ─────────────────────────────────────────────────────────

function makeSecret(overrides: Partial<SecretMetadata> = {}): SecretMetadata {
  return {
    key:       'API_KEY',
    type:      'api_key',
    groups:    ['backend'],
    createdAt: new Date().toISOString(),
    rotatedAt: new Date().toISOString(),
    ...overrides,
  };
}

function makeMockVault(): jest.Mocked<VaultBackend> {
  return {
    initialize:      jest.fn().mockResolvedValue(undefined),
    isReady:         jest.fn().mockReturnValue(true),
    listGroups:      jest.fn().mockResolvedValue([]),
    listSecrets:     jest.fn().mockResolvedValue([]),
    getSecretValues: jest.fn().mockResolvedValue(new Map<string, string>()),
    addSecret:       jest.fn().mockResolvedValue(undefined),
    removeSecret:    jest.fn().mockResolvedValue(undefined),
    rotateSecret:    jest.fn().mockResolvedValue(undefined),
    upsertGroup:     jest.fn().mockResolvedValue(undefined),
    removeGroup:     jest.fn().mockResolvedValue(undefined),
    close:           jest.fn().mockResolvedValue(undefined),
  } as jest.Mocked<VaultBackend>;
}

function makeMockAudit(): jest.Mocked<AuditLogger> {
  return {
    log:   jest.fn().mockResolvedValue(undefined),
    query: jest.fn().mockResolvedValue([]),
  } as unknown as jest.Mocked<AuditLogger>;
}

const BASE_CONFIG: ServerConfig = {
  vaultBackend:          'encrypted-file',
  vaultPath:             '/tmp/test.enc',
  auditLogPath:          '/tmp/test-audit.log',
  transport:             'stdio',
  ssePort:               3100,
  autoApprove:           false,
  approvalPolicies:      [],
  templateDir:           '/tmp/templates',
  backupOnWrite:         true,
  onePasswordVault:      'Development',
  expirationWarningDays: 7,
};

// ── tuiInject ──────────────────────────────────────────────────────────────

describe('tuiInject', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    jest.clearAllMocks();
    mockListTemplates.mockResolvedValue([]);
    mockCheckGitignore.mockResolvedValue(true);
    mockInjectSecrets.mockResolvedValue(1);
  });

  it('writes all group secrets to the target .env on the happy path', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    vault.getSecretValues.mockResolvedValue(new Map([['API_KEY', 'sk-abc123']]));

    // group → keyScope (all) → targetPath → overwrite
    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: false });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(vault.getSecretValues).toHaveBeenCalledWith(['API_KEY']);
    expect(mockInjectSecrets).toHaveBeenCalledWith(
      '/tmp/test.env',
      expect.any(Map),
      true,
      false,
      undefined
    );
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({
        action:     'inject',
        actor:      'human-tui',
        secretKeys: ['API_KEY'],
        approved:   true,
        targetPath: '/tmp/test.env',
      })
    );
  });

  it('injects only the individually selected keys', async () => {
    vault.listSecrets.mockResolvedValue([
      makeSecret({ key: 'API_KEY' }),
      makeSecret({ key: 'DB_PASS' }),
      makeSecret({ key: 'STRIPE_KEY' }),
    ]);
    vault.getSecretValues.mockResolvedValue(new Map([['API_KEY', 'sk-abc'], ['STRIPE_KEY', 'sk-stripe']]));

    // group → keyScope (individual) → selectedKeys → targetPath → overwrite
    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'Select individual keys' })
      .mockResolvedValueOnce({ selectedKeys: ['API_KEY', 'STRIPE_KEY'] })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: false });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(vault.getSecretValues).toHaveBeenCalledWith(['API_KEY', 'STRIPE_KEY']);
    expect(mockInjectSecrets).toHaveBeenCalledWith(
      '/tmp/test.env',
      expect.any(Map),
      true,
      false,
      undefined
    );
    expect(audit.log).toHaveBeenCalledWith(
      expect.objectContaining({ secretKeys: ['API_KEY', 'STRIPE_KEY'] })
    );
  });

  it('aborts without writing when individual selection is empty', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);

    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'Select individual keys' })
      .mockResolvedValueOnce({ selectedKeys: [] });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockInjectSecrets).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('returns early without prompting when vault has no secrets', async () => {
    vault.listSecrets.mockResolvedValue([]);

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockInjectSecrets).not.toHaveBeenCalled();
  });

  it('returns early when no secrets belong to any group', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ groups: [] })]);

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockPrompt).not.toHaveBeenCalled();
    expect(mockInjectSecrets).not.toHaveBeenCalled();
  });

  it('aborts injection when target is not gitignored and user declines', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    mockCheckGitignore.mockResolvedValue(false);

    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: false })
      .mockResolvedValueOnce({ proceed: false });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockInjectSecrets).not.toHaveBeenCalled();
    expect(audit.log).not.toHaveBeenCalled();
  });

  it('proceeds with injection when not gitignored but user confirms', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    vault.getSecretValues.mockResolvedValue(new Map([['API_KEY', 'sk-abc123']]));
    mockCheckGitignore.mockResolvedValue(false);

    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: false })
      .mockResolvedValueOnce({ proceed: true });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockInjectSecrets).toHaveBeenCalledWith(
      '/tmp/test.env',
      expect.any(Map),
      true,
      false,
      undefined
    );
  });

  it('passes overwrite: true to injectSecrets when user selects overwrite', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    vault.getSecretValues.mockResolvedValue(new Map([['API_KEY', 'val']]));

    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: true });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockInjectSecrets).toHaveBeenCalledWith(
      '/tmp/test.env',
      expect.any(Map),
      true,
      true,
      undefined
    );
  });

  it('loads and passes template content when user selects a template', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    vault.getSecretValues.mockResolvedValue(new Map([['API_KEY', 'val']]));
    mockListTemplates.mockResolvedValue(['service.env.tmpl']);
    mockLoadTemplate.mockResolvedValue('# Service template\nSERVICE_URL=http://localhost\n');

    // group → keyScope → targetPath → useTemplate → tmplName → overwrite
    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ useTemplate: true })
      .mockResolvedValueOnce({ tmplName: 'service.env.tmpl' })
      .mockResolvedValueOnce({ overwrite: false });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(mockLoadTemplate).toHaveBeenCalledWith(BASE_CONFIG.templateDir, 'service.env.tmpl');
    expect(mockInjectSecrets).toHaveBeenCalledWith(
      '/tmp/test.env',
      expect.any(Map),
      true,
      false,
      '# Service template\nSERVICE_URL=http://localhost\n'
    );
  });

  it('clears the values map after injection to scrub secrets from memory', async () => {
    const valuesMap = new Map([['API_KEY', 'sk-secret']]);
    vault.listSecrets.mockResolvedValue([makeSecret()]);
    vault.getSecretValues.mockResolvedValue(valuesMap);

    mockPrompt
      .mockResolvedValueOnce({ group: 'backend' })
      .mockResolvedValueOnce({ keyScope: 'All keys in group' })
      .mockResolvedValueOnce({ targetPath: '/tmp/test.env' })
      .mockResolvedValueOnce({ overwrite: false });

    await tuiInject(vault, audit, BASE_CONFIG);

    expect(valuesMap.size).toBe(0);
  });
});

// ── checkGitignore — relative path regression ──────────────────────────────

describe('checkGitignore — relative path', () => {
  const TEST_DIR = path.join('/tmp', `mcp-tui-test-${Date.now()}`);

  beforeEach(async () => {
    await fs.mkdir(TEST_DIR, { recursive: true });
    // Change working directory into the isolated temp dir so relative paths
    // resolve there and don't accidentally find the project's own .gitignore.
    process.chdir(TEST_DIR);
  });

  afterEach(async () => {
    process.chdir(path.join(__dirname, '..'));
    try { await fs.rm(TEST_DIR, { recursive: true, force: true }); } catch {}
  });

  it('returns false without hanging when no .gitignore exists and path is relative', async () => {
    // Unmock dotenv-writer for this describe block so we test the real implementation.
    jest.unmock('./injection/dotenv-writer');
    const { checkGitignore: realCheck } = jest.requireActual('./injection/dotenv-writer') as typeof import('./injection/dotenv-writer');

    const result = await realCheck('.env');
    expect(result).toBe(false);
  });
});
