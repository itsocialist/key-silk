import * as path from 'path';
import * as os from 'os';
import { promises as fs } from 'fs';

export type VaultType = 'encrypted-file' | 'onepassword' | 'doppler';

export interface ApprovalPolicy {
  name: string;
  conditions: {
    groups?: string[];           // Only auto-approve for these groups
    maxSecrets?: number;         // Only if N or fewer secrets requested
    targetPathPattern?: string;  // Glob pattern for allowed paths
    requireSameMachine?: boolean;
  };
}

export interface ServerConfig {
  vaultBackend: VaultType;
  vaultPath: string;
  auditLogPath: string;
  transport: 'stdio' | 'sse';
  ssePort: number;
  autoApprove: boolean;
  approvalPolicies: ApprovalPolicy[];
  templateDir: string;
  backupOnWrite: boolean;

  // 1Password backend config
  onePasswordVault: string;

  // Doppler backend config
  dopplerProject?: string;
  dopplerConfig?: string;

  // Expiration warning threshold (days)
  expirationWarningDays: number;
}

const DEFAULT_DIR = path.join(os.homedir(), '.mcp-secrets');

export function defaultConfig(): ServerConfig {
  return {
    vaultBackend: 'encrypted-file',
    vaultPath: path.join(DEFAULT_DIR, 'vault.enc'),
    auditLogPath: path.join(DEFAULT_DIR, 'audit.log'),
    transport: 'stdio',
    ssePort: 3100,
    autoApprove: false,
    approvalPolicies: [],
    templateDir: path.join(__dirname, '..', '..', 'templates'),
    backupOnWrite: true,
    onePasswordVault: 'Development',
    expirationWarningDays: 7,
  };
}

/**
 * Load configuration from environment variables and an optional config file.
 * Environment variables take precedence over file values.
 */
export async function loadConfig(): Promise<ServerConfig> {
  const config = defaultConfig();

  // Try loading config.json from the default dir
  const configPath = path.join(DEFAULT_DIR, 'config.json');
  try {
    const raw = await fs.readFile(configPath, 'utf8');
    const fileConfig = JSON.parse(raw);
    Object.assign(config, fileConfig);
  } catch {
    // No config file — use defaults
  }

  // Environment variable overrides
  if (process.env.MCP_VAULT_BACKEND) {
    config.vaultBackend = process.env.MCP_VAULT_BACKEND as VaultType;
  }
  if (process.env.MCP_VAULT_PATH) {
    config.vaultPath = process.env.MCP_VAULT_PATH;
  }
  if (process.env.MCP_AUDIT_LOG_PATH) {
    config.auditLogPath = process.env.MCP_AUDIT_LOG_PATH;
  }
  if (process.env.MCP_TRANSPORT) {
    config.transport = process.env.MCP_TRANSPORT as 'stdio' | 'sse';
  }
  if (process.env.MCP_SSE_PORT) {
    config.ssePort = parseInt(process.env.MCP_SSE_PORT, 10);
  }
  if (process.env.MCP_AUTO_APPROVE === 'true') {
    config.autoApprove = true;
  }
  if (process.env.MCP_TEMPLATE_DIR) {
    config.templateDir = process.env.MCP_TEMPLATE_DIR;
  }
  if (process.env.MCP_1PASSWORD_VAULT) {
    config.onePasswordVault = process.env.MCP_1PASSWORD_VAULT;
  }
  if (process.env.MCP_DOPPLER_PROJECT) {
    config.dopplerProject = process.env.MCP_DOPPLER_PROJECT;
  }
  if (process.env.MCP_DOPPLER_CONFIG) {
    config.dopplerConfig = process.env.MCP_DOPPLER_CONFIG;
  }
  if (process.env.MCP_EXPIRATION_WARNING_DAYS) {
    config.expirationWarningDays = parseInt(process.env.MCP_EXPIRATION_WARNING_DAYS, 10);
  }

  return config;
}
