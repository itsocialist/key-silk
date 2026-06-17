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

export class EncryptedFileVault implements VaultBackend {
  private vaultPath: string;
  private data: VaultData | null = null;
  private isInitialized = false;
  private passphraseKey: Buffer | null = null; // Key should be scrubbed aggressively
  private currentSalt: Buffer | null = null; // Re-use salt across saves so we don't need the raw passphrase to re-derive

  constructor(vaultPath: string) {
    this.vaultPath = vaultPath;
  }

  private scrubMemory() {
    if (this.passphraseKey) {
      this.passphraseKey.fill(0);
      this.passphraseKey = null;
    }
  }

  private deriveKey(passphrase: string, salt: Buffer): Buffer {
    return pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LEN, 'sha256');
  }

  async initialize(passphrase?: string): Promise<void> {
    if (!passphrase) {
        throw new Error("Passphrase required to initialize EncryptedFileVault");
    }

    try {
      // Check if vault exists
      let fileContent: string;
      try {
        fileContent = await fs.readFile(this.vaultPath, 'utf8');
      } catch (err: any) {
        if (err.code === 'ENOENT') {
          // Initialize empty
          this.currentSalt = randomBytes(SALT_LEN);
          this.passphraseKey = this.deriveKey(passphrase, this.currentSalt);
          this.data = { version: 1, secrets: [], groups: [] };
          this.isInitialized = true;
          await this.save();
          return;
        }
        throw err;
      }

      const payload = JSON.parse(fileContent) as EncryptedPayload;
      if (payload.version !== 1) throw new Error("Unsupported vault version");

      this.currentSalt = Buffer.from(payload.salt, 'base64');
      const iv = Buffer.from(payload.iv, 'base64');
      const authTag = Buffer.from(payload.authTag, 'base64');
      const ciphertext = Buffer.from(payload.ciphertext, 'base64');

      this.passphraseKey = this.deriveKey(passphrase, this.currentSalt);

      const decipher = createDecipheriv('aes-256-gcm', this.passphraseKey, iv);
      decipher.setAuthTag(authTag);

      let decrypted = decipher.update(ciphertext, undefined, 'utf8');
      decrypted += decipher.final('utf8');

      this.data = JSON.parse(decrypted) as VaultData;
      this.isInitialized = true;
      decrypted = "";
    } catch (e: any) {
      this.scrubMemory();
      throw new Error(`Failed to initialize vault: ${e.message}`);
    }
  }

  isReady(): boolean {
    return this.isInitialized && this.data !== null && this.passphraseKey !== null;
  }

  private ensureReady() {
    if (!this.isReady()) throw new Error("Vault is not initialized.");
  }

  private async save() {
    this.ensureReady();
    if (!this.passphraseKey || !this.currentSalt) throw new Error("Security Context lost.");

    const iv = randomBytes(IV_LEN);
    const plaintext = JSON.stringify(this.data);
    
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

    // Ensure directory exists
    await fs.mkdir(path.dirname(this.vaultPath), { recursive: true });
    
    // Create backup file if exists (before writing)
    try {
      await fs.copyFile(this.vaultPath, `${this.vaultPath}.bak`);
    } catch (err: any) {
      if (err.code !== 'ENOENT') throw err;
    }

    await fs.writeFile(this.vaultPath, JSON.stringify(payload, null, 2), { mode: 0o600, encoding: 'utf8' });
  }

  async listGroups(): Promise<SecretGroup[]> {
    this.ensureReady();
    return this.data!.groups;
  }

  async listSecrets(filter?: SecretFilter): Promise<SecretMetadata[]> {
    this.ensureReady();
    let secrets = this.data!.secrets;
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
    this.ensureReady();
    const map = new Map<string, string>();
    for (const key of keys) {
      const secret = this.data!.secrets.find(s => s.key === key);
      if (secret) {
        map.set(key, secret.value);
      }
    }
    return map;
  }

  async addSecret(entry: SecretEntry): Promise<void> {
    this.ensureReady();
    const existingIdx = this.data!.secrets.findIndex(s => s.key === entry.key);
    if (existingIdx >= 0) {
      this.data!.secrets[existingIdx] = entry;
    } else {
      this.data!.secrets.push(entry);
    }
    await this.save();
  }

  async removeSecret(key: string): Promise<void> {
    this.ensureReady();
    this.data!.secrets = this.data!.secrets.filter(s => s.key !== key);
    await this.save();
  }

  async rotateSecret(key: string, newValue: string): Promise<void> {
    this.ensureReady();
    const secret = this.data!.secrets.find(s => s.key === key);
    if (!secret) throw new Error("Secret not found");
    secret.value = newValue;
    secret.rotatedAt = new Date().toISOString();
    await this.save();
  }

  async upsertGroup(group: SecretGroup): Promise<void> {
    this.ensureReady();
    const existingIdx = this.data!.groups.findIndex(g => g.name === group.name);
    if (existingIdx >= 0) {
      this.data!.groups[existingIdx] = group;
    } else {
      this.data!.groups.push(group);
    }
    await this.save();
  }

  async removeGroup(name: string): Promise<void> {
    this.ensureReady();
    this.data!.groups = this.data!.groups.filter(g => g.name !== name);
    await this.save();
  }

  async close(): Promise<void> {
    if (this.isReady()) {
      await this.save();
    }
    this.scrubMemory();
    this.data = null;
    this.isInitialized = false;
  }
}
