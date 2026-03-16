import { promises as fs } from 'fs';
import * as path from 'path';

export interface AuditEntry {
  timestamp: string;
  action: "list" | "inject" | "add" | "remove" | "rotate" | "deny" | string;
  actor: string;            // e.g., "llm-request", "human-direct"
  secretKeys: string[];
  targetPath?: string;
  approved: boolean;
  approvalMethod: "interactive" | "policy" | "denied" | "none";
  details?: string;
}

export class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  async log(entry: Omit<AuditEntry, 'timestamp'>): Promise<void> {
    const fullEntry: AuditEntry = {
      timestamp: new Date().toISOString(),
      ...entry
    };

    const line = JSON.stringify(fullEntry) + '\n';
    
    // Ensure directory exists
    await fs.mkdir(path.dirname(this.logPath), { recursive: true });
    
    // Append to file. 0o600 restricts to owner read/write.
    await fs.appendFile(this.logPath, line, { mode: 0o600, encoding: 'utf8' });
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
