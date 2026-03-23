/**
 * AppServer unit tests — all 7 MCP tool handlers
 *
 * Strategy: inject mock VaultBackend + AuditLogger, mock the approval and
 * dotenv-writer modules, then call private handler methods directly via
 * (server as any).handleXxx(args) — a standard TypeScript testing pattern
 * that avoids requiring a live MCP transport.
 *
 * Coverage:
 *   secret_list_groups  — 2 tests
 *   secret_list         — 5 tests
 *   secret_inject       — 7 tests
 *   secret_remove       — 4 tests
 *   secret_rotate       — 4 tests
 *   secret_audit        — 3 tests
 *   secret_expiring     — 4 tests
 */

// ── Module mocks (hoisted before imports by Jest) ──────────────────────────

jest.mock('./approval/approval', () => ({
  requestApproval: jest.fn(),
}));

jest.mock('./injection/dotenv-writer', () => ({
  injectSecrets:   jest.fn().mockResolvedValue(1),
  checkGitignore:  jest.fn().mockResolvedValue(true),
}));

jest.mock('./injection/template-loader', () => ({
  loadTemplate:   jest.fn().mockResolvedValue('# Template\n'),
  listTemplates:  jest.fn().mockResolvedValue([]),
}));

// Spread requireActual so only createReadStream/createWriteStream are
// replaced; everything else (fs.promises used by vault, etc.) stays real.
jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  createReadStream:  jest.fn(),
  createWriteStream: jest.fn(),
}));

jest.mock('readline', () => ({
  createInterface: jest.fn(),
}));

// ── Imports ────────────────────────────────────────────────────────────────

import { AppServer } from './server';
import { VaultBackend, SecretMetadata } from './vault/vault';
import { AuditLogger } from './audit/logger';
import { ServerConfig } from './config/config';
import { requestApproval } from './approval/approval';
import { injectSecrets, checkGitignore } from './injection/dotenv-writer';
import * as fs from 'fs';
import * as readline from 'readline';

// ── Typed mock handles ─────────────────────────────────────────────────────

const mockRequestApproval  = requestApproval  as jest.MockedFunction<typeof requestApproval>;
const mockInjectSecrets    = injectSecrets    as jest.MockedFunction<typeof injectSecrets>;
const mockCheckGitignore   = checkGitignore   as jest.MockedFunction<typeof checkGitignore>;
const mockCreateReadStream  = fs.createReadStream  as jest.Mock;
const mockCreateWriteStream = fs.createWriteStream as jest.Mock;
const mockCreateInterface   = readline.createInterface as jest.Mock;

// ── Shared test helpers ────────────────────────────────────────────────────

function makeSecret(overrides: Partial<SecretMetadata> = {}): SecretMetadata {
  return {
    key:        'TEST_KEY',
    type:       'api_key',
    groups:     ['backend'],
    createdAt:  new Date().toISOString(),
    rotatedAt:  new Date().toISOString(),
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

// ── secret_list_groups ─────────────────────────────────────────────────────

describe('AppServer — secret_list_groups', () => {
  let vault: jest.Mocked<VaultBackend>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    server = new AppServer(vault, makeMockAudit(), BASE_CONFIG);
  });

  it('returns a formatted group summary with secretCount', async () => {
    vault.listGroups.mockResolvedValue([
      { name: 'backend',  description: 'Backend secrets',  secrets: ['DB_URL', 'REDIS_URL'] },
      { name: 'frontend', description: 'Frontend secrets', secrets: ['NEXT_PUBLIC_API'] },
    ]);

    const result = await (server as any).handleListGroups();
    const groups = JSON.parse(result.content[0].text);

    expect(groups).toHaveLength(2);
    expect(groups[0]).toEqual({ name: 'backend',  description: 'Backend secrets',  secretCount: 2 });
    expect(groups[1]).toEqual({ name: 'frontend', description: 'Frontend secrets', secretCount: 1 });
  });

  it('returns an empty array when no groups exist', async () => {
    vault.listGroups.mockResolvedValue([]);

    const result = await (server as any).handleListGroups();
    const groups = JSON.parse(result.content[0].text);

    expect(groups).toEqual([]);
  });
});

// ── secret_list ────────────────────────────────────────────────────────────

describe('AppServer — secret_list', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    server = new AppServer(vault, audit, BASE_CONFIG);
  });

  it('returns metadata only — value field must never appear', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'API_KEY' })]);

    const result = await (server as any).handleListSecrets({});
    const secrets = JSON.parse(result.content[0].text);

    expect(secrets).toHaveLength(1);
    expect(secrets[0].key).toBe('API_KEY');
    expect(secrets[0].value).toBeUndefined();
  });

  it('passes filter args through to vault.listSecrets', async () => {
    vault.listSecrets.mockResolvedValue([]);

    await (server as any).handleListSecrets({ group: 'backend', type: 'api_key' });

    expect(vault.listSecrets).toHaveBeenCalledWith({ group: 'backend', type: 'api_key' });
  });

  it('logs the list action to the audit trail', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'MY_KEY' })]);

    await (server as any).handleListSecrets({});

    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action:    'list',
      actor:     'llm-request',
      secretKeys: ['MY_KEY'],
      approved:  true,
    }));
  });

  it('annotates secrets expiring within the warning window', async () => {
    const soonMs = Date.now() + 3 * 24 * 60 * 60 * 1000; // 3 days — inside 7-day window
    vault.listSecrets.mockResolvedValue([
      makeSecret({ key: 'NEAR_KEY', expiresAt: new Date(soonMs).toISOString() }),
    ]);

    const result = await (server as any).handleListSecrets({});
    const secrets = JSON.parse(result.content[0].text);

    expect(secrets[0]._warning).toMatch(/Expires in/);
  });

  it('marks already-expired secrets with 🔴 EXPIRED', async () => {
    const past = new Date(Date.now() - 1000).toISOString();
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'STALE_KEY', expiresAt: past })]);

    const result = await (server as any).handleListSecrets({});
    const secrets = JSON.parse(result.content[0].text);

    expect(secrets[0]._warning).toBe('🔴 EXPIRED');
  });
});

// ── secret_inject ──────────────────────────────────────────────────────────

describe('AppServer — secret_inject', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    jest.clearAllMocks();
    mockCheckGitignore.mockResolvedValue(true);
    mockInjectSecrets.mockResolvedValue(1);
    server = new AppServer(vault, audit, BASE_CONFIG);
  });

  it('resolves keys from groups, fetches values, and writes the .env file', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'DB_URL', groups: ['backend'] })]);
    vault.getSecretValues.mockResolvedValue(new Map([['DB_URL', 'postgres://localhost']]));
    mockRequestApproval.mockResolvedValue(['DB_URL']);

    const result = await (server as any).handleInject({
      groups: ['backend'],
      targetPath: '/project/.env',
    });

    expect(vault.getSecretValues).toHaveBeenCalledWith(['DB_URL']);
    expect(mockInjectSecrets).toHaveBeenCalled();
    expect(result.content[0].text).toContain('secrets written');
  });

  it('returns "no keys found" when the requested group contains no secrets', async () => {
    vault.listSecrets.mockResolvedValue([]);

    const result = await (server as any).handleInject({
      groups: ['nonexistent-group'],
      targetPath: '/project/.env',
    });

    expect(result.content[0].text).toBe('No keys found to inject.');
    expect(mockInjectSecrets).not.toHaveBeenCalled();
  });

  it('auto-approves and skips interactive prompt when policy matches', async () => {
    const config: ServerConfig = {
      ...BASE_CONFIG,
      autoApprove: true,
      approvalPolicies: [{ name: 'ci-policy', conditions: { groups: ['ci'] } }],
    };
    server = new AppServer(vault, audit, config);
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'CI_TOKEN', groups: ['ci'] })]);
    vault.getSecretValues.mockResolvedValue(new Map([['CI_TOKEN', 'tok']]));

    await (server as any).handleInject({ groups: ['ci'], targetPath: '/tmp/.env' });

    expect(mockRequestApproval).not.toHaveBeenCalled();
    expect(mockInjectSecrets).toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'inject', approvalMethod: 'policy',
    }));
  });

  it('falls back to interactive approval when autoApprove=false', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'K', groups: ['g'] })]);
    vault.getSecretValues.mockResolvedValue(new Map([['K', 'v']]));
    mockRequestApproval.mockResolvedValue(['K']);

    await (server as any).handleInject({ groups: ['g'], targetPath: '/tmp/.env' });

    expect(mockRequestApproval).toHaveBeenCalledWith(expect.objectContaining({
      targetPath: '/tmp/.env',
      keys: ['K'],
    }));
  });

  it('returns DENIED and logs when human denies approval', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'K', groups: ['g'] })]);
    mockRequestApproval.mockResolvedValue([]); // empty = denied

    const result = await (server as any).handleInject({ groups: ['g'], targetPath: '/tmp/.env' });

    expect(result.content[0].text).toContain('DENIED');
    expect(mockInjectSecrets).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });

  it('returns isError and logs deny when no TTY is available for approval', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'K', groups: ['g'] })]);
    mockRequestApproval.mockRejectedValue(new Error('No TTY available'));

    const result = await (server as any).handleInject({ groups: ['g'], targetPath: '/tmp/.env' });

    expect(result.isError).toBe(true);
    expect(mockInjectSecrets).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });

  it('appends a gitignore warning to the response when target is not gitignored', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'K', groups: ['g'] })]);
    vault.getSecretValues.mockResolvedValue(new Map([['K', 'v']]));
    mockRequestApproval.mockResolvedValue(['K']);
    mockCheckGitignore.mockResolvedValue(false); // not gitignored

    const result = await (server as any).handleInject({ groups: ['g'], targetPath: '/tmp/.env' });

    expect(result.content[0].text).toContain('WARNING');
    expect(result.content[0].text).toContain('gitignore');
  });
});

// ── secret_remove ──────────────────────────────────────────────────────────

describe('AppServer — secret_remove', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    jest.clearAllMocks();
    server = new AppServer(vault, audit, BASE_CONFIG);
  });

  it('returns isError when the key does not exist in the vault', async () => {
    vault.listSecrets.mockResolvedValue([]);

    const result = await (server as any).handleRemove({ key: 'MISSING_KEY' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('"MISSING_KEY" not found');
    expect(vault.removeSecret).not.toHaveBeenCalled();
  });

  it('removes the secret and logs to audit when approved', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'REMOVE_ME' })]);
    mockRequestApproval.mockResolvedValue(['REMOVE_ME']);

    const result = await (server as any).handleRemove({ key: 'REMOVE_ME' });

    expect(vault.removeSecret).toHaveBeenCalledWith('REMOVE_ME');
    expect(result.content[0].text).toContain('"REMOVE_ME" removed');
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'remove', approved: true,
    }));
  });

  it('returns DENIED and logs when human denies removal', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'KEY' })]);
    mockRequestApproval.mockResolvedValue([]);

    const result = await (server as any).handleRemove({ key: 'KEY' });

    expect(result.content[0].text).toContain('DENIED');
    expect(vault.removeSecret).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });

  it('returns isError and logs deny when no TTY available for approval', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'KEY' })]);
    mockRequestApproval.mockRejectedValue(new Error('No TTY'));

    const result = await (server as any).handleRemove({ key: 'KEY' });

    expect(result.isError).toBe(true);
    expect(vault.removeSecret).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });
});

// ── secret_rotate ──────────────────────────────────────────────────────────

describe('AppServer — secret_rotate', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    jest.clearAllMocks();
    server = new AppServer(vault, audit, BASE_CONFIG);
  });

  it('returns isError when the key does not exist in the vault', async () => {
    vault.listSecrets.mockResolvedValue([]);

    const result = await (server as any).handleRotate({ key: 'MISSING' });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('"MISSING" not found');
    expect(vault.rotateSecret).not.toHaveBeenCalled();
  });

  it('returns DENIED and logs when human denies rotation', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'ROTATE_ME' })]);
    mockRequestApproval.mockResolvedValue([]);

    const result = await (server as any).handleRotate({ key: 'ROTATE_ME' });

    expect(result.content[0].text).toContain('DENIED');
    expect(vault.rotateSecret).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });

  it('returns isError and logs deny when no TTY for approval', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'KEY' })]);
    mockRequestApproval.mockRejectedValue(new Error('No TTY'));

    const result = await (server as any).handleRotate({ key: 'KEY' });

    expect(result.isError).toBe(true);
    expect(vault.rotateSecret).not.toHaveBeenCalled();
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'deny', approved: false,
    }));
  });

  it('reads new value from /dev/tty, rotates secret, and logs to audit', async () => {
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'MY_KEY' })]);
    mockRequestApproval.mockResolvedValue(['MY_KEY']);

    // Wire up fake /dev/tty streams
    const mockTtyIn  = { destroy: jest.fn() };
    const mockTtyOut = { write: jest.fn(), end: jest.fn() };
    mockCreateReadStream.mockReturnValue(mockTtyIn as any);
    mockCreateWriteStream.mockReturnValue(mockTtyOut as any);

    // Make readline immediately answer with the new value
    mockCreateInterface.mockReturnValue({
      question: jest.fn((_msg: string, cb: (ans: string) => void) => cb('brand-new-value')),
      close:    jest.fn(),
    } as any);

    const result = await (server as any).handleRotate({ key: 'MY_KEY' });

    expect(vault.rotateSecret).toHaveBeenCalledWith('MY_KEY', 'brand-new-value');
    expect(result.content[0].text).toContain('"MY_KEY" rotated');
    expect(audit.log).toHaveBeenCalledWith(expect.objectContaining({
      action: 'rotate', approved: true,
    }));
  });
});

// ── secret_audit ───────────────────────────────────────────────────────────

describe('AppServer — secret_audit', () => {
  let vault: jest.Mocked<VaultBackend>;
  let audit: jest.Mocked<AuditLogger>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    audit = makeMockAudit();
    server = new AppServer(vault, audit, BASE_CONFIG);
  });

  it('returns sanitized audit entries as JSON', async () => {
    audit.query.mockResolvedValue([{
      timestamp:      '2024-01-01T00:00:00Z',
      action:         'inject',
      actor:          'llm-request',
      secretKeys:     ['API_KEY'],
      targetPath:     '/project/.env',
      approved:       true,
      approvalMethod: 'interactive',
    }]);

    const result = await (server as any).handleAudit({});
    const entries = JSON.parse(result.content[0].text);

    expect(entries).toHaveLength(1);
    expect(entries[0].action).toBe('inject');
    expect(entries[0].approved).toBe(true);
  });

  it('passes all filter args through to audit.query', async () => {
    audit.query.mockResolvedValue([]);

    await (server as any).handleAudit({
      secretKey: 'MY_KEY',
      action:    'inject',
      since:     '2024-01-01T00:00:00Z',
      limit:     10,
    });

    expect(audit.query).toHaveBeenCalledWith({
      secretKey: 'MY_KEY',
      action:    'inject',
      since:     '2024-01-01T00:00:00Z',
      limit:     10,
    });
  });

  it('defaults limit to 50 when not specified', async () => {
    audit.query.mockResolvedValue([]);

    await (server as any).handleAudit({});

    expect(audit.query).toHaveBeenCalledWith(expect.objectContaining({ limit: 50 }));
  });
});

// ── secret_expiring ────────────────────────────────────────────────────────

describe('AppServer — secret_expiring', () => {
  let vault: jest.Mocked<VaultBackend>;
  let server: AppServer;

  beforeEach(() => {
    vault = makeMockVault();
    server = new AppServer(vault, makeMockAudit(), BASE_CONFIG);
  });

  it('returns a "no expiring secrets" message when vault is clean', async () => {
    vault.listSecrets.mockResolvedValue([]);

    const result = await (server as any).handleExpiring({});

    expect(result.content[0].text).toContain('No secrets expiring');
  });

  it('uses withinDays from args when provided', async () => {
    vault.listSecrets.mockResolvedValue([]);

    await (server as any).handleExpiring({ withinDays: 30 });

    const callArg = vault.listSecrets.mock.calls[0][0]!;
    const thresholdMs = new Date(callArg.expiresBefore!).getTime();

    // Threshold should be approximately 30 days from now
    expect(thresholdMs).toBeGreaterThan(Date.now() + 29 * 24 * 60 * 60 * 1000);
    expect(thresholdMs).toBeLessThan(Date.now() + 31 * 24 * 60 * 60 * 1000);
  });

  it('falls back to config.expirationWarningDays (7) when withinDays not provided', async () => {
    vault.listSecrets.mockResolvedValue([]);

    await (server as any).handleExpiring({});

    const callArg = vault.listSecrets.mock.calls[0][0]!;
    const thresholdMs = new Date(callArg.expiresBefore!).getTime();

    expect(thresholdMs).toBeGreaterThan(Date.now() + 6 * 24 * 60 * 60 * 1000);
    expect(thresholdMs).toBeLessThan(Date.now() + 8 * 24 * 60 * 60 * 1000);
  });

  it('marks already-expired secrets with 🔴 EXPIRED status', async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    vault.listSecrets.mockResolvedValue([makeSecret({ key: 'OLD_KEY', expiresAt: past })]);

    const result = await (server as any).handleExpiring({});
    const expiring = JSON.parse(result.content[0].text);

    expect(expiring).toHaveLength(1);
    expect(expiring[0].key).toBe('OLD_KEY');
    expect(expiring[0].status).toBe('🔴 EXPIRED');
  });
});
