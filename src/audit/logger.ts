import { promises as fs } from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';

export interface AuditEntry {
  timestamp: string;
  action: "list" | "inject" | "add" | "remove" | "rotate" | "deny" | string;
  actor: string;            // e.g., "llm-request", "human-direct"
  secretKeys: string[];
  targetPath?: string;
  approved: boolean;
  approvalMethod: "interactive" | "policy" | "denied" | "none";
  details?: string;
  // Tamper-evidence chain (added on write).
  prevHash?: string;
  hash?: string;
}

// Rotate the active log once it crosses this size (bytes). One rollover to .1.
const MAX_LOG_BYTES = 5_000_000;
const GENESIS = '0'.repeat(64);

/** Deterministic JSON with sorted keys, so hashes are reproducible. */
function stableStringify(obj: Record<string, any>): string {
  const keys = Object.keys(obj).sort();
  return JSON.stringify(obj, keys);
}

/**
 * Append-only audit log with a SHA-256 hash chain.
 *
 * Security Note: each entry stores the hash of the previous entry and a hash of
 * its own canonical content. Any edit, reorder, or deletion breaks the chain and
 * is detectable via verifyChain(). This makes "append-only" enforceable rather
 * than merely conventional. Files are written 0600.
 */
export class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  private hashEntry(entryWithoutHash: AuditEntry): string {
    const { hash, ...rest } = entryWithoutHash; // exclude self-hash; prevHash stays in
    return createHash('sha256').update(stableStringify(rest)).digest('hex');
  }

  private async lastHash(): Promise<string> {
    try {
      const content = await fs.readFile(this.logPath, 'utf8');
      const lines = content.trim().split('\n').filter(l => l.length > 0);
      if (lines.length === 0) return GENESIS;
      const last = JSON.parse(lines[lines.length - 1]) as AuditEntry;
      return last.hash || GENESIS;
    } catch (e: any) {
      if (e.code === 'ENOENT') return GENESIS;
      throw e;
    }
  }

  private async rotateIfNeeded(): Promise<void> {
    try {
      const stat = await fs.stat(this.logPath);
      if (stat.size >= MAX_LOG_BYTES) {
        await fs.rename(this.logPath, `${this.logPath}.1`);
      }
    } catch (e: any) {
      if (e.code !== 'ENOENT') throw e;
    }
  }

  async log(entry: Omit<AuditEntry, 'timestamp' | 'prevHash' | 'hash'>): Promise<void> {
    // Ensure directory exists
    await fs.mkdir(path.dirname(this.logPath), { recursive: true });

    // Carry the chain across rotation: read the prior hash before rotating.
    const prevHash = await this.lastHash();
    await this.rotateIfNeeded();

    const withChain: AuditEntry = {
      timestamp: new Date().toISOString(),
      ...entry,
      prevHash,
    };
    withChain.hash = this.hashEntry(withChain);

    const line = JSON.stringify(withChain) + '\n';
    // Append. 0o600 restricts to owner read/write.
    await fs.appendFile(this.logPath, line, { mode: 0o600, encoding: 'utf8' });
  }

  /**
   * Verify the hash chain of the active log. Returns the 1-based line number of
   * the first broken link (if any). A clean or missing log is considered ok.
   */
  async verifyChain(): Promise<{ ok: boolean; brokenAt?: number }> {
    let content: string;
    try {
      content = await fs.readFile(this.logPath, 'utf8');
    } catch (e: any) {
      if (e.code === 'ENOENT') return { ok: true };
      throw e;
    }
    const lines = content.trim().split('\n').filter(l => l.length > 0);
    let prev = GENESIS;
    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]) as AuditEntry;
      if (entry.prevHash !== prev) return { ok: false, brokenAt: i + 1 };
      const expected = this.hashEntry(entry);
      if (entry.hash !== expected) return { ok: false, brokenAt: i + 1 };
      prev = entry.hash;
    }
    return { ok: true };
  }

  async query(options: {
    secretKey?: string;
    action?: string;
    since?: string;
    limit?: number;
  }): Promise<AuditEntry[]> {
    try {
      const content = await fs.readFile(this.logPath, 'utf8');
      const lines = content.trim().split('\n').filter(l => l.length > 0);

      let entries: AuditEntry[] = lines.map(l => JSON.parse(l));

      if (options.since) {
        const sinceTime = new Date(options.since).getTime();
        entries = entries.filter(e => new Date(e.timestamp).getTime() >= sinceTime);
      }
      if (options.action) {
        entries = entries.filter(e => e.action === options.action);
      }
      if (options.secretKey) {
        entries = entries.filter(e => e.secretKeys.includes(options.secretKey!));
      }

      // Sort chronological descending (newest first)
      entries.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

      if (options.limit && options.limit > 0) {
        entries = entries.slice(0, options.limit);
      }

      return entries;
    } catch (e: any) {
      if (e.code === 'ENOENT') {
        return [];
      }
      throw e;
    }
  }
}
