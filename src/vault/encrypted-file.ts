import {
  VaultBackend,
  VaultData,
  SecretEntry,
  SecretGroup,
  SecretFilter,
  SecretMetadata
} from './vault';
import { randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } from 'crypto';
import { promises as fs } from 'fs';
import * as path from 'path';

interface EncryptedPayload {
  version: 1;
  algorithm: 'aes-256-gcm';
  kdf: 'pbkdf2';
  kdfIterations: number;
  salt: string;    // base64
  iv: string;      // base64
  authTag: string; // base64
  ciphertext: string; // base64
}

const ITERATIONS = 600_000;
const KEY_LEN = 32;
const SALT_LEN = 32;
const IV_LEN = 12;

/**
 * AES-256-GCM encrypted-file vault.
 *
 * Security Note: this backend holds only the derived key in memory (scrubbed on
 * close), never the decrypted vault. Each operation decrypts on demand into a
 * local that goes out of scope immediately, so plaintext secret values are not
 * retained on the instance for the process lifetime. (JS strings still cannot be
 * explicitly zeroed — decrypted values may linger in the heap until GC — but
 * their lifetime is now one operation rather than the whole session.)
 */
export class EncryptedFileVault implements VaultBackend {
  private vaultPath: string;
  private isInitialized = false;
  private passphraseKey: Buffer | null = null; // scrubbed aggressively on close
  private currentSalt: Buffer | null = null;   // not secret; reused across saves

  constructor(vaultPath: string) {
    this.vaultPath = vaultPath;
  }

  private scrubMemory() {
    if (this.passphraseKey) {
      this.passphraseKey.fill(0);
      this.passphraseKey = null;
    }
    this.currentSalt = null;
  }

  private deriveKey(passphrase: string, salt: Buffer): Buffer {
    return pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LEN, 'sha256');
  }

  async initialize(passphrase?: string): Promise<void> {
    if (!passphrase) {
        throw new Error("Passphrase required to initialize EncryptedFileVault");
    }

    try {
      let fileContent: string;
      try {
        fileContent = await fs.readFile(this.vaultPath, 'utf8');
      } catch (err: any) {
        if (err.code === 'ENOENT') {
          // Initialize an empty vault.
          this.currentSalt = randomBytes(SALT_LEN);
          this.passphraseKey = this.deriveKey(passphrase, this.currentSalt);
          this.isInitialized = true;
          await this.saveData({ version: 1, secrets: [], groups: [] });
          return;
        }
        throw err;
      }

      const payload = JSON.parse(fileContent) as EncryptedPayload;
      if (payload.version !== 1) throw new Error("Unsupported vault version");

      this.currentSalt = Buffer.from(payload.salt, 'base64');
      this.passphraseKey = this.deriveKey(passphrase, this.currentSalt);

      // Validate the passphrase by decrypting once; discard the plaintext.
      this.decryptPayload(payload);
      this.isInitialized = true;
    } catch (e: any) {
      this.scrubMemory();
      throw new Error(`Failed to initialize vault: ${e.message}`);
    }
  }

  isReady(): boolean {
    return this.isInitialized && this.passphraseKey !== null && this.currentSalt !== null;
  }

  private ensureReady() {
    if (!this.isReady()) throw new Error("Vault is not initialized.");
  }

  private decryptPayload(payload: EncryptedPayload): VaultData {
    const iv = Buffer.from(payload.iv, 'base64');
    const authTag = Buffer.from(payload.authTag, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext, 'base64');

    const decipher = createDecipheriv('aes-256-gcm', this.passphraseKey!, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted) as VaultData;
  }

  // Decrypt the current vault on demand. The returned object is the caller's to
  // use transiently; it is not retained on the instance.
  private async loadData(): Promise<VaultData> {
    this.ensureReady();
    let fileContent: string;
    try {
      fileContent = await fs.readFile(this.vaultPath, 'utf8');
    } catch (err: any) {
      if (err.code === 'ENOENT') return { version: 1, secrets: [], groups: [] };
      throw err;
    }
    const payload = JSON.parse(fileContent) as EncryptedPayload;
    return this.decryptPayload(payload);
  }

  private async saveData(data: VaultData): Promise<void> {
    this.ensureReady();
    if (!this.passphraseKey || !this.currentSalt) throw new Error("Security Context lost.");

    const iv = randomBytes(IV_LEN);
    const plaintext = JSON.stringify(data);

    const cipher = createCipheriv('aes-256-gcm', this.passphraseKey, iv);

    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag().toString('base64');

    const payload: EncryptedPayload = {
      version: 1,
      algorithm: 'aes-256-gcm',
      kdf: 'pbkdf2',
      kdfIterations: ITERATIONS,
      salt: this.currentSalt.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag,
      ciphertext: encrypted
    };

    await fs.mkdir(path.dirname(this.vaultPath), { recursive: true });

    // Backup the previous vault before overwriting.
    try {
      await fs.copyFile(this.vaultPath, `${this.vaultPath}.bak`);
    } catch (err: any) {
      if (err.code !== 'ENOENT') throw err;
    }

    await fs.writeFile(this.vaultPath, JSON.stringify(payload, null, 2), { mode: 0o600, encoding: 'utf8' });
  }

  async listGroups(): Promise<SecretGroup[]> {
    const data = await this.loadData();
    return data.groups;
  }

  async listSecrets(filter?: SecretFilter): Promise<SecretMetadata[]> {
    const data = await this.loadData();
    let secrets = data.secrets;
    if (filter) {
      if (filter.group) {
        secrets = secrets.filter(s => s.groups.includes(filter.group!));
      }
      if (filter.type) {
        secrets = secrets.filter(s => s.type === filter.type);
      }
      if (filter.expiresBefore) {
        const threshold = new Date(filter.expiresBefore).getTime();
        secrets = secrets.filter(s => s.expiresAt && new Date(s.expiresAt).getTime() < threshold);
      }
    }

    // Metadata only — secret values are never returned here.
    return secrets.map(s => ({
      key: s.key,
      description: s.description,
      type: s.type,
      groups: s.groups,
      createdAt: s.createdAt,
      rotatedAt: s.rotatedAt,
      expiresAt: s.expiresAt,
      metadata: s.metadata,
    }));
  }

  async getSecretValues(keys: string[]): Promise<Map<string, string>> {
    const data = await this.loadData();
    const map = new Map<string, string>();
    for (const key of keys) {
      const secret = data.secrets.find(s => s.key === key);
      if (secret) {
        map.set(key, secret.value);
      }
    }
    return map;
  }

  async addSecret(entry: SecretEntry): Promise<void> {
    const data = await this.loadData();
    const existingIdx = data.secrets.findIndex(s => s.key === entry.key);
    if (existingIdx >= 0) {
      data.secrets[existingIdx] = entry;
    } else {
      data.secrets.push(entry);
    }
    await this.saveData(data);
  }

  async removeSecret(key: string): Promise<void> {
    const data = await this.loadData();
    data.secrets = data.secrets.filter(s => s.key !== key);
    await this.saveData(data);
  }

  async rotateSecret(key: string, newValue: string): Promise<void> {
    const data = await this.loadData();
    const secret = data.secrets.find(s => s.key === key);
    if (!secret) throw new Error("Secret not found");
    secret.value = newValue;
    secret.rotatedAt = new Date().toISOString();
    await this.saveData(data);
  }

  async upsertGroup(group: SecretGroup): Promise<void> {
    const data = await this.loadData();
    const existingIdx = data.groups.findIndex(g => g.name === group.name);
    if (existingIdx >= 0) {
      data.groups[existingIdx] = group;
    } else {
      data.groups.push(group);
    }
    await this.saveData(data);
  }

  async removeGroup(name: string): Promise<void> {
    const data = await this.loadData();
    data.groups = data.groups.filter(g => g.name !== name);
    await this.saveData(data);
  }

  async close(): Promise<void> {
    this.scrubMemory();
    this.isInitialized = false;
  }
}
