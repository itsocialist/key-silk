export interface SecretEntry {
  key: string;              // e.g., "ANTHROPIC_API_KEY"
  value: string;            // The actual secret value (NEVER returned to LLM)
  description?: string;     // Human-readable description
  type: "api_key" | "client_id" | "client_secret" | "oauth_token" | "other" | string;
  groups: string[];         // e.g., ["anthropic", "ai-providers"]
  createdAt: string;        // ISO 8601
  rotatedAt: string;        // ISO 8601 — last time value was updated
  expiresAt?: string;       // ISO 8601 — optional expiration
  metadata?: Record<string, string>;  // Freeform metadata
}

export interface SecretGroup {
  name: string;             // e.g., "anthropic", "hubspot-oauth", "stripe"
  description: string;
  secrets: string[];        // Array of secret keys belonging to this group
}

export interface VaultData {
  version: 1;
  secrets: SecretEntry[];
  groups: SecretGroup[];
}

export interface SecretFilter {
  group?: string;
  type?: SecretEntry["type"];
  expiresBefore?: string;  // ISO 8601 — find secrets expiring soon
}

export interface SecretMetadata {
  key: string;
  description?: string;
  type: SecretEntry["type"];
  groups: string[];
  createdAt: string;
  rotatedAt: string;
  expiresAt?: string;
  metadata?: Record<string, string>;
}

export interface VaultBackend {
  /** Initialize the backend (decrypt vault file, authenticate CLI, etc.) */
  initialize(passphrase?: string): Promise<void>;

  /** Check if the backend is initialized and ready */
  isReady(): boolean;

  /** List all secret groups with metadata */
  listGroups(): Promise<SecretGroup[]>;

  /**
   * List secrets matching optional filters. Returns METADATA ONLY — no values.
   * This is the method exposed to MCP tools.
   */
  listSecrets(filter?: SecretFilter): Promise<SecretMetadata[]>;

  /**
   * INTERNAL ONLY — retrieve actual secret values for injection.
   * Called by the injection layer (dotenv-writer), NEVER by MCP tool responses.
   * Returns a Map of key → plaintext value.
   */
  getSecretValues(keys: string[]): Promise<Map<string, string>>;

  /** Add or update a secret entry */
  addSecret(entry: SecretEntry): Promise<void>;

  /** Remove a secret by key */
  removeSecret(key: string): Promise<void>;

  /** Update a secret's value and bump rotatedAt timestamp */
  rotateSecret(key: string, newValue: string): Promise<void>;

  /** Create or update a secret group */
  upsertGroup(group: SecretGroup): Promise<void>;

  /** Remove a secret group (does not delete the secrets themselves) */
  removeGroup(name: string): Promise<void>;

  /** Flush any pending writes and clean up resources */
  close(): Promise<void>;
}
