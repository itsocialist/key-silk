#!/usr/bin/env node
import { Command } from 'commander';
import { AuditLogger } from './audit/logger';
import { AppServer } from './server';
import { injectSecrets, checkGitignore } from './injection/dotenv-writer';
import { loadTemplate, listTemplates } from './injection/template-loader';
import { loadConfig, defaultConfig, ServerConfig } from './config/config';
import { createVault } from './vault/factory';
import { VaultBackend } from './vault/vault';
import { EncryptedFileVault } from './vault/encrypted-file';
import { runTUI } from './tui';
import { prompt } from 'enquirer';
import * as path from 'path';

const program = new Command();

function getPassphrase(): string {
  const p = process.env.MCP_VAULT_PASSPHRASE;
  if (!p) {
    console.error("FATAL: Set the MCP_VAULT_PASSPHRASE environment variable.");
    process.exit(1);
  }
  return p;
}

async function openVault(config: ServerConfig): Promise<VaultBackend> {
  const vault = createVault(config);
  const passphrase = config.vaultBackend === 'encrypted-file' ? getPassphrase() : undefined;
  await vault.initialize(passphrase);
  return vault;
}

program
  .name('key-silk')
  .description('🔐 Secure, human-in-the-loop secret management for AI-assisted development')
  .version('1.0.0');

// ── init ─────────────────────────────────────────────────────────
program
  .command('init')
  .description('Initialize a new vault')
  .option('-b, --backend <type>', 'Backend type: encrypted-file, onepassword, doppler', 'encrypted-file')
  .option('--vault <name>', '1Password vault name', 'Development')
  .option('--project <name>', 'Doppler project name')
  .option('--config <name>', 'Doppler config name', 'dev')
  .action(async (options) => {
    if (options.backend === 'encrypted-file') {
      const { passphrase } = await prompt<{ passphrase: string }>({
        type: 'password',
        name: 'passphrase',
        message: 'Enter a master passphrase for the new vault'
      });
      const config = defaultConfig();
      const vault = new EncryptedFileVault(config.vaultPath);
      await vault.initialize(passphrase);
      console.log(`✓ Vault initialized at ${config.vaultPath}`);
      await vault.close();
    } else if (options.backend === 'onepassword') {
      console.log(`✓ 1Password backend configured. Run 'op signin' to authenticate.`);
      console.log(`  Vault: ${options.vault}`);
    } else if (options.backend === 'doppler') {
      console.log(`✓ Doppler backend configured.`);
      console.log(`  Project: ${options.project || '(set MCP_DOPPLER_PROJECT)'}`);
      console.log(`  Config: ${options.config}`);
    }
  });

// ── add ──────────────────────────────────────────────────────────
program
  .command('add')
  .description('Add a new secret interactively')
  .argument('<key>', 'Key name (e.g., ANTHROPIC_API_KEY)')
  .option('-t, --type <type>', 'Secret type', 'api_key')
  .option('-g, --group <groups>', 'Comma-separated groups')
  .option('-d, --description <desc>', 'Human-readable description')
  .option('-e, --expires <date>', 'Expiration date (ISO 8601)')
  .action(async (key, options) => {
    const config = await loadConfig();
    const vault = await openVault(config);

    const { value } = await prompt<{ value: string }>({
      type: 'password',
      name: 'value',
      message: `Enter value for ${key}:`
    });

    await vault.addSecret({
      key,
      value,
      type: options.type,
      description: options.description,
      groups: options.group ? options.group.split(',') : [],
      createdAt: new Date().toISOString(),
      rotatedAt: new Date().toISOString(),
      expiresAt: options.expires
    });

    const logger = new AuditLogger(config.auditLogPath);
    await logger.log({ action: 'add', actor: 'human-direct', secretKeys: [key], approved: true, approvalMethod: 'interactive' });

    console.log(`✓ Secret "${key}" saved.`);
    await vault.close();
  });

// ── list ─────────────────────────────────────────────────────────
program
  .command('list')
  .alias('ls')
  .description('List secret metadata (never shows values)')
  .option('-g, --group <group>', 'Filter by group')
  .action(async (options) => {
    const config = await loadConfig();
    const vault = await openVault(config);
    const filter = options.group ? { group: options.group } : undefined;
    const list = await vault.listSecrets(filter);

    if (list.length === 0) {
      console.log('No secrets found.');
    } else {
      const now = Date.now();
      const warningMs = config.expirationWarningDays * 24 * 60 * 60 * 1000;
      console.table(list.map(s => {
        let status = '✓';
        if (s.expiresAt) {
          const remaining = new Date(s.expiresAt).getTime() - now;
          if (remaining <= 0) status = '🔴 EXPIRED';
          else if (remaining <= warningMs) status = `🟡 ${Math.ceil(remaining / 86400000)}d left`;
        }
        return {
          key: s.key,
          type: s.type,
          groups: s.groups.join(', '),
          rotated: s.rotatedAt ? new Date(s.rotatedAt).toLocaleDateString() : 'never',
          status,
          description: s.description || ''
        };
      }));
    }
    await vault.close();
  });

// ── groups ───────────────────────────────────────────────────────
program
  .command('groups')
  .description('List all secret groups')
  .action(async () => {
    const config = await loadConfig();
    const vault = await openVault(config);
    const groups = await vault.listGroups();

    if (groups.length === 0) {
      console.log('No groups defined.');
    } else {
      console.table(groups.map(g => ({
        name: g.name,
        description: g.description,
        secrets: g.secrets.join(', ')
      })));
    }
    await vault.close();
  });

// ── remove ───────────────────────────────────────────────────────
program
  .command('remove')
  .alias('rm')
  .description('Remove a secret from the vault')
  .argument('<key>', 'Secret key to remove')
  .action(async (key) => {
    const config = await loadConfig();
    const vault = await openVault(config);

    const existing = await vault.listSecrets();
    if (!existing.find(s => s.key === key)) {
      console.error(`Secret "${key}" not found.`);
      await vault.close();
      process.exit(1);
    }

    const { confirm } = await prompt<{ confirm: boolean }>({
      type: 'confirm',
      name: 'confirm',
      message: `Remove secret "${key}" permanently?`
    });

    if (!confirm) {
      console.log('Aborted.');
      await vault.close();
      return;
    }

    await vault.removeSecret(key);
    const logger = new AuditLogger(config.auditLogPath);
    await logger.log({ action: 'remove', actor: 'human-direct', secretKeys: [key], approved: true, approvalMethod: 'interactive' });

    console.log(`✓ Secret "${key}" removed.`);
    await vault.close();
  });

// ── rotate ───────────────────────────────────────────────────────
program
  .command('rotate')
  .description('Rotate (update the value of) an existing secret')
  .argument('<key>', 'Secret key to rotate')
  .action(async (key) => {
    const config = await loadConfig();
    const vault = await openVault(config);

    const existing = await vault.listSecrets();
    if (!existing.find(s => s.key === key)) {
      console.error(`Secret "${key}" not found.`);
      await vault.close();
      process.exit(1);
    }

    const { value } = await prompt<{ value: string }>({
      type: 'password',
      name: 'value',
      message: `Enter new value for ${key}:`
    });

    await vault.rotateSecret(key, value);
    const logger = new AuditLogger(config.auditLogPath);
    await logger.log({ action: 'rotate', actor: 'human-direct', secretKeys: [key], approved: true, approvalMethod: 'interactive' });

    console.log(`✓ Secret "${key}" rotated.`);
    await vault.close();
  });

// ── inject ───────────────────────────────────────────────────────
program
  .command('inject')
  .description('Inject secrets into a .env file')
  .requiredOption('-g, --group <group>', 'Group to inject')
  .requiredOption('--target <path>', 'Target .env file path')
  .option('--template <name>', 'Template name to use as base')
  .option('--overwrite', 'Overwrite existing keys', false)
  .action(async (options) => {
    const config = await loadConfig();
    const vault = await openVault(config);

    const secrets = await vault.listSecrets({ group: options.group });
    const keys = secrets.map(s => s.key);

    if (keys.length === 0) {
      console.log(`No secrets found in group "${options.group}".`);
      await vault.close();
      return;
    }

    const isGitignored = await checkGitignore(options.target);
    if (!isGitignored) {
      console.warn('⚠️  WARNING: Target .env path is NOT covered by a .gitignore — secrets may be committed!');
    }

    let templateContent: string | undefined;
    if (options.template) {
      templateContent = await loadTemplate(config.templateDir, options.template);
    }

    const values = await vault.getSecretValues(keys);
    const count = await injectSecrets(options.target, values, true, options.overwrite, templateContent);
    values.clear();

    const logger = new AuditLogger(config.auditLogPath);
    await logger.log({ action: 'inject', actor: 'human-direct', secretKeys: keys, approved: true, approvalMethod: 'interactive', targetPath: options.target });

    console.log(`✓ ${count} secrets written to ${options.target}`);
    await vault.close();
  });

// ── expiring ─────────────────────────────────────────────────────
program
  .command('expiring')
  .description('Show secrets expiring soon')
  .option('-d, --days <n>', 'Look-ahead in days', '7')
  .action(async (options) => {
    const config = await loadConfig();
    const vault = await openVault(config);

    const days = parseInt(options.days);
    const threshold = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    const expiring = await vault.listSecrets({ expiresBefore: threshold });

    if (expiring.length === 0) {
      console.log(`✓ No secrets expiring within ${days} days.`);
    } else {
      const now = Date.now();
      console.log(`⚠️  ${expiring.length} secret(s) expiring within ${days} days:\n`);
      for (const s of expiring) {
        const remaining = new Date(s.expiresAt!).getTime() - now;
        const daysLeft = Math.ceil(remaining / 86400000);
        const status = remaining <= 0 ? '🔴 EXPIRED' : `🟡 ${daysLeft} day(s) remaining`;
        console.log(`  ${s.key}  ${status}  (expires: ${s.expiresAt})`);
      }
    }
    await vault.close();
  });

// ── audit ────────────────────────────────────────────────────────
program
  .command('audit')
  .description('View the audit trail')
  .option('-k, --key <key>', 'Filter by secret key')
  .option('-a, --action <action>', 'Filter by action type')
  .option('-s, --since <date>', 'Only show entries after this date (ISO 8601)')
  .option('-l, --limit <n>', 'Max entries to show', '50')
  .action(async (options) => {
    const config = await loadConfig();
    const logger = new AuditLogger(config.auditLogPath);
    const entries = await logger.query({
      secretKey: options.key,
      action: options.action,
      since: options.since,
      limit: parseInt(options.limit)
    });

    if (entries.length === 0) {
      console.log('No audit entries found.');
    } else {
      console.table(entries.map(e => ({
        time: e.timestamp,
        action: e.action,
        actor: e.actor,
        keys: e.secretKeys.join(', '),
        approved: e.approved ? '✓' : '✗',
        target: e.targetPath || ''
      })));
    }
  });

// ── templates ────────────────────────────────────────────────────
program
  .command('templates')
  .description('List available .env templates')
  .action(async () => {
    const config = await loadConfig();
    const templates = await listTemplates(config.templateDir);
    if (templates.length === 0) {
      console.log('No templates found.');
    } else {
      console.log('Available templates:');
      for (const t of templates) {
        console.log(`  • ${t}`);
      }
    }
  });

// ── serve ────────────────────────────────────────────────────────
program
  .command('serve')
  .description('Start as an MCP server')
  .option('--transport <type>', 'Transport type: stdio or sse', 'stdio')
  .option('--port <port>', 'Port for SSE transport', '3100')
  .action(async (options) => {
    const config = await loadConfig();
    const vault = await openVault(config);
    const logger = new AuditLogger(config.auditLogPath);

    const server = new AppServer(vault, logger, config);
    const transport = (options.transport || config.transport) as 'stdio' | 'sse';
    await server.run(transport, parseInt(options.port || String(config.ssePort)));
  });

// ── tui (interactive dashboard) ──────────────────────────────────
program
  .command('tui')
  .description('Launch interactive terminal dashboard')
  .action(async () => {
    const config = await loadConfig();
    const vault = await openVault(config);
    const logger = new AuditLogger(config.auditLogPath);
    await runTUI(vault, logger, config);
    await vault.close();
  });

// If no command given, launch TUI
if (process.argv.length <= 2) {
  (async () => {
    try {
      const config = await loadConfig();
      const vault = await openVault(config);
      const logger = new AuditLogger(config.auditLogPath);
      await runTUI(vault, logger, config);
      await vault.close();
    } catch (err: any) {
      // If vault can't be opened (no passphrase, etc.), fall through to help
      program.parse();
    }
  })();
} else {
  program.parse();
}
