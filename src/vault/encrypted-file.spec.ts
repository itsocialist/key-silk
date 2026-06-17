import { EncryptedFileVault } from './encrypted-file';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

describe('EncryptedFileVault Engine', () => {
  const TEST_VAULT = path.join(__dirname, 'test.enc');
  const PASSPHRASE = 'test_passphrase_123!';

  afterEach(async () => {
    try {
      await fs.unlink(TEST_VAULT);
    } catch (e) {}
  });

  it('initializes a new vault successfully', async () => {
    const vault = new EncryptedFileVault(TEST_VAULT);
    await vault.initialize(PASSPHRASE);
    expect(vault.isReady()).toBe(true);

    const data = await fs.readFile(TEST_VAULT, 'utf8');
    const parsed = JSON.parse(data);
    expect(parsed.version).toBe(1);
    expect(parsed.algorithm).toBe('aes-256-gcm');
    expect(parsed.kdf).toBe('pbkdf2');
  });

  it('securely saves and retrieves secrets', async () => {
    let vault = new EncryptedFileVault(TEST_VAULT);
    await vault.initialize(PASSPHRASE);
    
    await vault.addSecret({
      key: 'TEST_KEY',
      value: 'SUPER_SECRET_VALUE',
      type: 'api_key',
      groups: ['test'],
      createdAt: new Date().toISOString(),
      rotatedAt: new Date().toISOString()
    });

    await vault.close();

    // Reopen vault
    vault = new EncryptedFileVault(TEST_VAULT);
    await vault.initialize(PASSPHRASE);
    
    // Test Metadata extraction
    const list = await vault.listSecrets();
    expect(list.length).toBe(1);
    expect(list[0].key).toBe('TEST_KEY');
    expect((list[0] as any).value).toBeUndefined(); // Crucial security constraint
    
    // Internal decryption retrieval
    const values = await vault.getSecretValues(['TEST_KEY']);
    expect(values.get('TEST_KEY')).toBe('SUPER_SECRET_VALUE');
  });
});
