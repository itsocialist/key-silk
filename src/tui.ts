import chalk from 'chalk';
import { prompt } from 'enquirer';
import Table from 'cli-table3';
import { VaultBackend } from './vault/vault';
import { AuditLogger } from './audit/logger';
import { injectSecrets, checkGitignore } from './injection/dotenv-writer';
import { loadTemplate, listTemplates } from './injection/template-loader';
import { ServerConfig } from './config/config';

const BRAND = chalk.hex('#A78BFA'); // soft purple
const ACCENT = chalk.hex('#34D399'); // emerald
const WARN = chalk.hex('#FBBF24');  // amber
const DANGER = chalk.hex('#F87171'); // red
const DIM = chalk.dim;
const BOLD = chalk.bold;

function banner() {
  console.clear();
  console.log('');
  console.log(BRAND('  ╔═══════════════════════════════════════════╗'));
  console.log(BRAND('  ║') + BOLD('   🔐 Key Silk — Secret Manager            ') + BRAND('║'));
  console.log(BRAND('  ║') + DIM('   Secure secrets for AI development        ') + BRAND('║'));
  console.log(BRAND('  ╚═══════════════════════════════════════════╝'));
  console.log('');
}

function statusLine(vault: VaultBackend, config: ServerConfig) {
  const backend = config.vaultBackend;
  const indicator = vault.isReady() ? ACCENT('● connected') : DANGER('○ disconnected');
  console.log(DIM(`  Backend: ${backend}  │  ${indicator}  │  ${DIM(config.vaultPath)}`));
  console.log('');
}

type Action = 
  | 'list' | 'groups' | 'add' | 'remove' | 'rotate' 
  | 'inject' | 'expiring' | 'audit' | 'templates' | 'quit';

const MENU_CHOICES = [
  { name: 'list',      message: `${ACCENT('📋')}  List Secrets` },
  { name: 'groups',    message: `${ACCENT('📁')}  List Groups` },
  { name: 'add',       message: `${ACCENT('➕')}  Add Secret` },
  { name: 'remove',    message: `${DANGER('🗑️ ')} Remove Secret` },
  { name: 'rotate',    message: `${WARN('🔄')}  Rotate Secret` },
  { name: 'inject',    message: `${ACCENT('💉')}  Inject to .env` },
  { name: 'expiring',  message: `${WARN('⏰')}  Expiring Secrets` },
  { name: 'audit',     message: `${DIM('📜')}  Audit Trail` },
  { name: 'templates', message: `${DIM('📄')}  Templates` },
  { name: 'quit',      message: `${DIM('👋')}  Quit` },
];

export async function runTUI(vault: VaultBackend, audit: AuditLogger, config: ServerConfig) {
  let running = true;

  while (running) {
    banner();
    statusLine(vault, config);

    const { action } = await prompt<{ action: Action }>({
      type: 'select',
      name: 'action',
      message: 'What would you like to do?',
      choices: MENU_CHOICES,
    });

    console.log('');

    switch (action) {
      case 'list':
        await tuiListSecrets(vault, config);
        break;
      case 'groups':
        await tuiListGroups(vault);
        break;
      case 'add':
        await tuiAddSecret(vault, audit);
        break;
      case 'remove':
        await tuiRemoveSecret(vault, audit);
        break;
      case 'rotate':
        await tuiRotateSecret(vault, audit);
        break;
      case 'inject':
        await tuiInject(vault, audit, config);
        break;
      case 'expiring':
        await tuiExpiring(vault, config);
        break;
      case 'audit':
        await tuiAudit(audit);
        break;
      case 'templates':
        await tuiTemplates(config);
        break;
      case 'quit':
        running = false;
        break;
    }

    if (running) {
      await prompt({ type: 'input', name: '_', message: DIM('Press Enter to continue...') });
    }
  }

  console.log(DIM('\n  Goodbye. Your secrets are safe. 🔐\n'));
}

// ── List Secrets ─────────────────────────────────────────────────

async function tuiListSecrets(vault: VaultBackend, config: ServerConfig) {
  const secrets = await vault.listSecrets();
  if (secrets.length === 0) {
    console.log(DIM('  No secrets stored yet. Use "Add Secret" to get started.'));
    return;
  }

  const now = Date.now();
  const warningMs = config.expirationWarningDays * 24 * 60 * 60 * 1000;

  const table = new Table({
    head: ['Key', 'Type', 'Groups', 'Last Rotated', 'Status'].map(h => BOLD(h)),
    style: { head: [], border: ['dim'] },
    chars: { mid: '─', 'left-mid': '├', 'mid-mid': '┼', 'right-mid': '┤' },
  });

  for (const s of secrets) {
    let status = ACCENT('✓ Active');
    if (s.expiresAt) {
      const remaining = new Date(s.expiresAt).getTime() - now;
      if (remaining <= 0) status = DANGER('🔴 EXPIRED');
      else if (remaining <= warningMs) {
        const days = Math.ceil(remaining / 86400000);
        status = WARN(`🟡 ${days}d left`);
      }
    }

    table.push([
      BOLD(s.key),
      DIM(s.type),
      s.groups.join(', ') || DIM('none'),
      s.rotatedAt ? new Date(s.rotatedAt).toLocaleDateString() : DIM('never'),
      status,
    ]);
  }

  console.log(table.toString());
  console.log(DIM(`\n  ${secrets.length} secret(s) in vault`));
}

// ── List Groups ──────────────────────────────────────────────────

async function tuiListGroups(vault: VaultBackend) {
  const groups = await vault.listGroups();
  if (groups.length === 0) {
    console.log(DIM('  No groups defined yet.'));
    return;
  }

  const table = new Table({
    head: ['Group', 'Description', 'Secrets'].map(h => BOLD(h)),
    style: { head: [], border: ['dim'] },
  });

  for (const g of groups) {
    table.push([BRAND(g.name), g.description || DIM('—'), g.secrets.join(', ') || DIM('none')]);
  }

  console.log(table.toString());
}

// ── Add Secret ───────────────────────────────────────────────────

async function tuiAddSecret(vault: VaultBackend, audit: AuditLogger) {
  const answers = await prompt<{
    key: string;
    value: string;
    type: string;
    groups: string;
    description: string;
    expires: string;
  }>([
    { type: 'input', name: 'key', message: 'Secret key name', validate: (v: string) => v.length > 0 || 'Required' },
    { type: 'password', name: 'value', message: 'Secret value' },
    {
      type: 'select', name: 'type', message: 'Secret type',
      choices: ['api_key', 'client_id', 'client_secret', 'oauth_token', 'other']
    },
    { type: 'input', name: 'groups', message: 'Groups (comma-separated)', initial: '' },
    { type: 'input', name: 'description', message: 'Description (optional)', initial: '' },
    { type: 'input', name: 'expires', message: 'Expires (ISO 8601, or leave blank)', initial: '' },
  ]);

  await vault.addSecret({
    key: answers.key,
    value: answers.value,
    type: answers.type,
    groups: answers.groups ? answers.groups.split(',').map(g => g.trim()) : [],
    description: answers.description || undefined,
    createdAt: new Date().toISOString(),
    rotatedAt: new Date().toISOString(),
    expiresAt: answers.expires || undefined,
  });

  await audit.log({
    action: 'add', actor: 'human-tui', secretKeys: [answers.key],
    approved: true, approvalMethod: 'interactive'
  });

  console.log(ACCENT(`\n  ✓ Secret "${answers.key}" saved.`));
}

// ── Remove Secret ────────────────────────────────────────────────

async function tuiRemoveSecret(vault: VaultBackend, audit: AuditLogger) {
  const secrets = await vault.listSecrets();
  if (secrets.length === 0) {
    console.log(DIM('  No secrets to remove.'));
    return;
  }

  const { key } = await prompt<{ key: string }>({
    type: 'select',
    name: 'key',
    message: 'Select secret to remove',
    choices: secrets.map(s => ({
      name: s.key,
      message: `${s.key} ${DIM(`(${s.type}, ${s.groups.join(', ') || 'no groups'})`)}`
    }))
  });

  const { confirm } = await prompt<{ confirm: boolean }>({
    type: 'confirm',
    name: 'confirm',
    message: DANGER(`Permanently remove "${key}"?`)
  });

  if (!confirm) {
    console.log(DIM('  Aborted.'));
    return;
  }

  await vault.removeSecret(key);
  await audit.log({
    action: 'remove', actor: 'human-tui', secretKeys: [key],
    approved: true, approvalMethod: 'interactive'
  });

  console.log(ACCENT(`\n  ✓ Secret "${key}" removed.`));
}

// ── Rotate Secret ────────────────────────────────────────────────

async function tuiRotateSecret(vault: VaultBackend, audit: AuditLogger) {
  const secrets = await vault.listSecrets();
  if (secrets.length === 0) {
    console.log(DIM('  No secrets to rotate.'));
    return;
  }

  const { key } = await prompt<{ key: string }>({
    type: 'select',
    name: 'key',
    message: 'Select secret to rotate',
    choices: secrets.map(s => ({
      name: s.key,
      message: `${s.key} ${DIM(`(last rotated: ${new Date(s.rotatedAt).toLocaleDateString()})`)}`
    }))
  });

  const { value } = await prompt<{ value: string }>({
    type: 'password',
    name: 'value',
    message: `Enter new value for ${BOLD(key)}`
  });

  await vault.rotateSecret(key, value);
  await audit.log({
    action: 'rotate', actor: 'human-tui', secretKeys: [key],
    approved: true, approvalMethod: 'interactive'
  });

  console.log(ACCENT(`\n  ✓ Secret "${key}" rotated.`));
}

// ── Inject ───────────────────────────────────────────────────────

async function tuiInject(vault: VaultBackend, audit: AuditLogger, config: ServerConfig) {
  const secrets = await vault.listSecrets();
  if (secrets.length === 0) {
    console.log(DIM('  No secrets to inject.'));
    return;
  }

  // Collect group names
  const allGroups = new Set<string>();
  secrets.forEach(s => s.groups.forEach(g => allGroups.add(g)));

  if (allGroups.size === 0) {
    console.log(WARN('  No groups defined. Add secrets to groups first.'));
    return;
  }

  const { group } = await prompt<{ group: string }>({
    type: 'select',
    name: 'group',
    message: 'Select group to inject',
    choices: Array.from(allGroups)
  });

  const { targetPath } = await prompt<{ targetPath: string }>({
    type: 'input',
    name: 'targetPath',
    message: 'Target .env file path',
    initial: '.env'
  });

  // Template selection
  const templates = await listTemplates(config.templateDir);
  let templateContent: string | undefined;

  if (templates.length > 0) {
    const { useTemplate } = await prompt<{ useTemplate: boolean }>({
      type: 'confirm',
      name: 'useTemplate',
      message: 'Use a template as base?',
      initial: false
    });

    if (useTemplate) {
      const { tmplName } = await prompt<{ tmplName: string }>({
        type: 'select',
        name: 'tmplName',
        message: 'Select template',
        choices: templates
      });
      templateContent = await loadTemplate(config.templateDir, tmplName);
    }
  }

  const { overwrite } = await prompt<{ overwrite: boolean }>({
    type: 'confirm',
    name: 'overwrite',
    message: 'Overwrite existing keys?',
    initial: false
  });

  // Gitignore check
  const isGitignored = await checkGitignore(targetPath);
  if (!isGitignored) {
    console.log(WARN('\n  ⚠️  Target is NOT in .gitignore — secrets may be committed!'));
    const { proceed } = await prompt<{ proceed: boolean }>({
      type: 'confirm',
      name: 'proceed',
      message: DANGER('Continue anyway?'),
      initial: false
    });
    if (!proceed) {
      console.log(DIM('  Aborted.'));
      return;
    }
  }

  const groupSecrets = secrets.filter(s => s.groups.includes(group));
  const keys = groupSecrets.map(s => s.key);

  // Show what will be injected
  console.log(BOLD(`\n  Injecting ${keys.length} secret(s) to ${targetPath}:`));
  for (const k of keys) {
    console.log(DIM(`    • ${k}`));
  }
  console.log('');

  const values = await vault.getSecretValues(keys);
  const count = await injectSecrets(targetPath, values, true, overwrite, templateContent);
  values.clear();

  await audit.log({
    action: 'inject', actor: 'human-tui', secretKeys: keys,
    approved: true, approvalMethod: 'interactive', targetPath
  });

  console.log(ACCENT(`  ✓ ${count} secret(s) written to ${targetPath}`));
}

// ── Expiring ─────────────────────────────────────────────────────

async function tuiExpiring(vault: VaultBackend, config: ServerConfig) {
  const threshold = new Date(Date.now() + config.expirationWarningDays * 24 * 60 * 60 * 1000).toISOString();
  const expiring = await vault.listSecrets({ expiresBefore: threshold });

  if (expiring.length === 0) {
    console.log(ACCENT(`  ✓ No secrets expiring within ${config.expirationWarningDays} days.`));
    return;
  }

  const now = Date.now();
  const table = new Table({
    head: ['Key', 'Expires', 'Status'].map(h => BOLD(h)),
    style: { head: [], border: ['dim'] },
  });

  for (const s of expiring) {
    const remaining = new Date(s.expiresAt!).getTime() - now;
    const days = Math.ceil(remaining / 86400000);
    const status = remaining <= 0 ? DANGER('🔴 EXPIRED') : WARN(`🟡 ${days}d remaining`);
    table.push([BOLD(s.key), s.expiresAt!, status]);
  }

  console.log(table.toString());
  console.log(WARN(`\n  ⚠️  ${expiring.length} secret(s) need attention`));
}

// ── Audit Trail ──────────────────────────────────────────────────

async function tuiAudit(audit: AuditLogger) {
  const entries = await audit.query({ limit: 20 });

  if (entries.length === 0) {
    console.log(DIM('  No audit entries yet.'));
    return;
  }

  const table = new Table({
    head: ['Time', 'Action', 'Actor', 'Keys', ''].map(h => BOLD(h)),
    style: { head: [], border: ['dim'] },
  });

  for (const e of entries) {
    const actionColor = e.approved ? ACCENT : DANGER;
    table.push([
      DIM(new Date(e.timestamp).toLocaleString()),
      actionColor(e.action),
      DIM(e.actor),
      e.secretKeys.join(', '),
      e.approved ? ACCENT('✓') : DANGER('✗'),
    ]);
  }

  console.log(table.toString());
  console.log(DIM(`\n  Showing latest ${entries.length} entries`));
}

// ── Templates ────────────────────────────────────────────────────

async function tuiTemplates(config: ServerConfig) {
  const templates = await listTemplates(config.templateDir);

  if (templates.length === 0) {
    console.log(DIM('  No templates found.'));
    return;
  }

  console.log(BOLD('  Available .env Templates:\n'));
  for (const t of templates) {
    const name = t.replace('.env.tmpl', '').replace('.tmpl', '');
    console.log(`  ${ACCENT('•')} ${BOLD(name)} ${DIM(`(${t})`)}`);
  }
}
