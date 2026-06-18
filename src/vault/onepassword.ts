import {
  VaultBackend,
  SecretEntry,
  SecretGroup,
  SecretFilter,
  SecretMetadata
} from './vault';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { assertCliSafe } from './cli-safe';

const execFileAsync = promisify(execFile);

/**
 * 1Password CLI (`op`) vault backend.
 * Implements VaultBackend by shelling out to the `op` CLI.
 *
 * Security Note: No local encryption needed — 1Password handles it.
 * The `op` CLI must be installed and the user must be signed in.
 */
export class OnePasswordVault implements VaultBackend {
  private vaultName: string;
  private initialized = false;

  constructor(vaultName: string = 'Development') {
    this.vaultName = vaultName;
  }

  private async exec(args: string[]): Promise<string> {
    try {
      const { stdout } = await execFileAsync('op', args, {
        timeout: 30_000,
        env: { ...process.env }
      });
      return stdout.trim();
    } catch (err: any) {
      throw new Error(`1Password CLI error: ${err.stderr || err.message}`);
    }
  }

  async initialize(): Promise<void> {
    // Validate that `op` is available and authenticated
    try {
      await this.exec(['whoami', '--format', 'json']);
      this.initialized = true;
    } catch (err: any) {
      throw new Error(
        `1Password CLI not authenticated. Run 'op signin' first. Details: ${err.message}`
      );
    }
  }

  isReady(): boolean {
    return this.initialized;
  }

  async listGroups(): Promise<SecretGroup[]> {
    this.ensureReady();
    // 1Password "tags" map to our groups
    const raw = await this.exec([
      'item', 'list', '--vault', this.vaultName, '--format', 'json'
    ]);
    const items = JSON.parse(raw) as any[];

    // Collect unique tags
    const tagMap = new Map<string, string[]>();
    for (const item of items) {
      const tags: string[] = item.tags || [];
      for (const tag of tags) {
        if (!tagMap.has(tag)) tagMap.set(tag, []);
        tagMap.get(tag)!.push(item.title);
      }
    }

    return Array.from(tagMap.entries()).map(([name, secrets]) => ({
      name,
      description: `1Password tag: ${name}`,
      secrets
    }));
  }

  async listSecrets(filter?: SecretFilter): Promise<SecretMetadata[]> {
    this.ensureReady();
    const raw = await this.exec([
      'item', 'list', '--vault', this.vaultName, '--format', 'json'
    ]);
    let items = JSON.parse(raw) as any[];

    if (filter?.group) {
      items = items.filter((i: any) => (i.tags || []).includes(filter.group));
    }

    return items.map((item: any) => ({
      key: item.title,
      description: item.additional_information || undefined,
      type: this.mapCategory(item.category) as any,
      groups: item.tags || [],
      createdAt: item.created_at || new Date().toISOString(),
      rotatedAt: item.updated_at || new Date().toISOString(),
      expiresAt: undefined,
      metadata: { id: item.id, vault: this.vaultName }
    }));
  }

  async getSecretValues(keys: string[]): Promise<Map<string, string>> {
    this.ensureReady();
    const map = new Map<string, string>();
    for (const key of keys) {
      assertCliSafe(key, 'secret key');
      try {
        // Get the "password" or "credential" field value
        const value = await this.exec([
          'item', 'get', key, '--vault', this.vaultName,
          '--fields', 'label=credential', '--format', 'json'
        ]);
        const parsed = JSON.parse(value);
        map.set(key, parsed.value || '');
      } catch {
        // Try "password" field as fallback
        try {
          const value = await this.exec([
            'item', 'get', key, '--vault', this.vaultName,
            '--fields', 'label=password', '--format', 'json'
          ]);
          const parsed = JSON.parse(value);
          map.set(key, parsed.value || '');
        } catch {
          // Skip keys we can't resolve
        }
      }
    }
    return map;
  }

  async addSecret(entry: SecretEntry): Promise<void> {
    this.ensureReady();
    assertCliSafe(entry.key, 'secret key');
    entry.groups.forEach(g => assertCliSafe(g, 'group'));
    const tags = entry.groups.length > 0 ? ['--tags', entry.groups.join(',')] : [];
    await this.exec([
      'item', 'create',
      '--category', 'API Credential',
      '--title', entry.key,
      '--vault', this.vaultName,
      `credential=${entry.value}`,
      ...tags
    ]);
  }

  async removeSecret(key: string): Promise<void> {
    this.ensureReady();
    assertCliSafe(key, 'secret key');
    await this.exec(['item', 'delete', key, '--vault', this.vaultName]);
  }

  async rotateSecret(key: string, newValue: string): Promise<void> {
    this.ensureReady();
    assertCliSafe(key, 'secret key');
    await this.exec([
      'item', 'edit', key, '--vault', this.vaultName,
      `credential=${newValue}`
    ]);
  }

  async upsertGroup(group: SecretGroup): Promise<void> {
    this.ensureReady();
    assertCliSafe(group.name, 'group');
    // 1Password tags are applied per-item; we tag each listed secret
    for (const secretKey of group.secrets) {
      assertCliSafe(secretKey, 'secret key');
      try {
        await this.exec([
          'item', 'edit', secretKey, '--vault', this.vaultName,
          '--tags', group.name
        ]);
      } catch {
        // Item might not exist — skip
      }
    }
  }

  async removeGroup(_name: string): Promise<void> {
    // 1Password doesn't have a "delete tag" operation; tags are per-item.
    // This is a no-op; removing a group just means we stop filtering by tag.
  }

  async close(): Promise<void> {
    this.initialized = false;
  }

  private ensureReady() {
    if (!this.initialized) throw new Error('1Password vault not initialized. Call initialize() first.');
  }

  private mapCategory(category: string): string {
    const map: Record<string, string> = {
      'API_CREDENTIAL': 'api_key',
      'LOGIN': 'other',
      'PASSWORD': 'other',
    };
    return map[category] || 'other';
  }
}
