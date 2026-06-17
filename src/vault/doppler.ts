import {
  VaultBackend,
  SecretEntry,
  SecretGroup,
  SecretFilter,
  SecretMetadata
} from './vault';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

/**
 * Doppler CLI/API vault backend.
 * Implements VaultBackend via the `doppler` CLI.
 *
 * Doppler "projects" and "configs" map to our secret groups.
 * Native rotation and audit trail — delegates to Doppler's versioning.
 */
export class DopplerVault implements VaultBackend {
  private project: string;
  private config: string;
  private initialized = false;

  constructor(project?: string, config?: string) {
    this.project = project || '';
    this.config = config || 'dev';
  }

  private async exec(args: string[]): Promise<string> {
    const baseArgs = [];
    if (this.project) baseArgs.push('--project', this.project);
    if (this.config) baseArgs.push('--config', this.config);

    try {
      const { stdout } = await execFileAsync('doppler', [...args, ...baseArgs], {
        timeout: 30_000,
        env: { ...process.env }
      });
      return stdout.trim();
    } catch (err: any) {
      throw new Error(`Doppler CLI error: ${err.stderr || err.message}`);
    }
  }

  async initialize(): Promise<void> {
    // Validate Doppler CLI is authenticated
    if (process.env.DOPPLER_TOKEN) {
      // Service token mode — no login needed
      this.initialized = true;
      return;
    }

    try {
      // Check for valid login session
      const raw = await execFileAsync('doppler', ['me', '--json'], { timeout: 10_000 });
      if (raw.stdout.includes('workplace')) {
        this.initialized = true;
      } else {
        throw new Error('Not authenticated');
      }
    } catch (err: any) {
      throw new Error(
        `Doppler CLI not authenticated. Run 'doppler login' or set DOPPLER_TOKEN. Details: ${err.message}`
      );
    }
  }

  isReady(): boolean {
    return this.initialized;
  }

  async listGroups(): Promise<SecretGroup[]> {
    this.ensureReady();
    // In Doppler, "configs" within a project serve as groups
    try {
      const raw = await execFileAsync('doppler', [
        'configs', '--project', this.project, '--json'
      ], { timeout: 15_000 });
      const configs = JSON.parse(raw.stdout) as any[];

      return configs.map((c: any) => ({
        name: c.name || c.slug,
        description: `Doppler config: ${c.name || c.slug} (${c.environment || 'unknown'})`,
        secrets: [] // Populated on demand via listSecrets
      }));
    } catch {
      // Fallback: return single group representing current config
      return [{
        name: this.config,
        description: `Doppler config: ${this.config}`,
        secrets: []
      }];
    }
  }

  async listSecrets(filter?: SecretFilter): Promise<SecretMetadata[]> {
    this.ensureReady();
    const raw = await this.exec(['secrets', '--json']);
    const secretsObj = JSON.parse(raw) as Record<string, any>;

    const entries: SecretMetadata[] = Object.entries(secretsObj).map(([key, data]) => ({
      key,
      description: undefined,
      type: 'other' as const,
      groups: [this.config],
      createdAt: new Date().toISOString(),
      rotatedAt: new Date().toISOString(),
      expiresAt: undefined,
      metadata: {
        project: this.project,
        config: this.config,
        // Doppler provides a `rawVisibility` field in some modes
        rawVisibility: typeof data === 'object' ? data.rawVisibility : undefined
      }
    }));

    if (filter?.group) {
      return entries.filter(e => e.groups.includes(filter.group!));
    }
    if (filter?.type) {
      return entries.filter(e => e.type === filter.type);
    }

    return entries;
  }

  async getSecretValues(keys: string[]): Promise<Map<string, string>> {
    this.ensureReady();
    const map = new Map<string, string>();

    // Fetch all secrets at once and extract the ones we need
    const raw = await this.exec(['secrets', '--json', '--no-read-env']);
    const all = JSON.parse(raw) as Record<string, any>;

    for (const key of keys) {
      if (all[key]) {
        const val = typeof all[key] === 'object' ? all[key].computed : String(all[key]);
        map.set(key, val);
      }
    }

    return map;
  }

  async addSecret(entry: SecretEntry): Promise<void> {
    this.ensureReady();
    await this.exec(['secrets', 'set', entry.key, entry.value]);
  }

  async removeSecret(key: string): Promise<void> {
    this.ensureReady();
    await this.exec(['secrets', 'delete', key, '--yes']);
  }

  async rotateSecret(key: string, newValue: string): Promise<void> {
    this.ensureReady();
    // Doppler versioning handles rotation natively
    await this.exec(['secrets', 'set', key, newValue]);
  }

  async upsertGroup(_group: SecretGroup): Promise<void> {
    // Doppler configs are managed via the dashboard or `doppler configs create`.
    // We don't auto-create configs from the tool — log a warning.
    console.warn('Doppler groups (configs) cannot be created via this tool. Use the Doppler dashboard.');
  }

  async removeGroup(_name: string): Promise<void> {
    console.warn('Doppler groups (configs) cannot be removed via this tool. Use the Doppler dashboard.');
  }

  async close(): Promise<void> {
    this.initialized = false;
  }

  private ensureReady() {
    if (!this.initialized) throw new Error('Doppler vault not initialized. Call initialize() first.');
  }
}
