import { VaultBackend } from './vault';
import { EncryptedFileVault } from './encrypted-file';
import { OnePasswordVault } from './onepassword';
import { DopplerVault } from './doppler';
import { ServerConfig, VaultType } from '../config/config';

/**
 * Factory function to create the appropriate vault backend.
 * All tools interact with the VaultBackend interface — never with a backend directly.
 * This makes 1Password, Doppler, and any future backend a drop-in replacement.
 */
export function createVault(config: ServerConfig): VaultBackend {
  switch (config.vaultBackend) {
    case 'encrypted-file':
      return new EncryptedFileVault(config.vaultPath);
    case 'onepassword':
      return new OnePasswordVault(config.onePasswordVault);
    case 'doppler':
      return new DopplerVault(config.dopplerProject, config.dopplerConfig);
    default:
      throw new Error(`Unknown vault backend: ${config.vaultBackend}`);
  }
}
