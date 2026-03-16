import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { VaultBackend } from "./vault/vault";
import { AuditLogger } from "./audit/logger";
import { requestApproval } from "./approval/approval";
import { evaluateAutoApproval } from "./approval/policies";
import { injectSecrets, checkGitignore } from "./injection/dotenv-writer";
import { loadTemplate, listTemplates } from "./injection/template-loader";
import { ServerConfig, ApprovalPolicy } from "./config/config";
import * as path from "path";

export class AppServer {
  private server: Server;
  private vault: VaultBackend;
  private audit: AuditLogger;
  private templateDir: string;
  private autoApprove: boolean;
  private approvalPolicies: ApprovalPolicy[];
  private expirationWarningDays: number;

  constructor(vault: VaultBackend, audit: AuditLogger, config: ServerConfig) {
    this.vault = vault;
    this.audit = audit;
    this.templateDir = config.templateDir;
    this.autoApprove = config.autoApprove;
    this.approvalPolicies = config.approvalPolicies;
    this.expirationWarningDays = config.expirationWarningDays;

    this.server = new Server(
      { name: "mcp-secret-server", version: "1.0.0" },
      { capabilities: { tools: {} } }
    );

    this.registerTools();
    this.registerHandlers();
  }

  private registerTools() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "secret_list_groups",
            description: "List all available secret groups with their descriptions and secret counts.",
            inputSchema: { type: "object", properties: {} }
          },
          {
            name: "secret_list",
            description: "List secrets within a group or all secrets. Returns metadata only — NO secret values are ever returned. Includes expiration warnings for secrets nearing their expiry date.",
            inputSchema: {
              type: "object",
              properties: {
                group: { type: "string", description: "Filter by group name" },
                type: { type: "string", description: "Filter by secret type" }
              }
            }
          },
          {
            name: "secret_inject",
            description: "Write requested secrets into a .env file at the specified path. Requires human approval (unless auto-approve policy matches). Returns only a confirmation message, never secret values.",
            inputSchema: {
              type: "object",
              properties: {
                keys: { type: "array", items: { type: "string" }, description: "Specific secret keys to inject" },
                groups: { type: "array", items: { type: "string" }, description: "Inject all secrets from these groups" },
                targetPath: { type: "string", description: "Absolute path to write .env file" },
                merge: { type: "boolean", description: "If true, merge with existing .env (default: true)" },
                overwrite: { type: "boolean", description: "If true, overwrite existing keys (default: false)" },
                template: { type: "string", description: "Optional template name to use as base" }
              },
              required: ["targetPath"]
            }
          },
          {
            name: "secret_remove",
            description: "Remove a secret from the vault. Requires human approval.",
            inputSchema: {
              type: "object",
              properties: {
                key: { type: "string", description: "The secret key to remove" }
              },
              required: ["key"]
            }
          },
          {
            name: "secret_rotate",
            description: "Rotate (update the value of) an existing secret. The new value is entered interactively on the terminal — never passed through the LLM.",
            inputSchema: {
              type: "object",
              properties: {
                key: { type: "string", description: "The secret key to rotate" }
              },
              required: ["key"]
            }
          },
          {
            name: "secret_audit",
            description: "Query the audit trail for secret access history.",
            inputSchema: {
              type: "object",
              properties: {
                secretKey: { type: "string", description: "Filter by specific secret key" },
                action: { type: "string", description: "Filter by action type (list, inject, add, remove, rotate, deny)" },
                since: { type: "string", description: "ISO 8601 timestamp — only entries after this time" },
                limit: { type: "number", description: "Max entries to return (default: 50)" }
              }
            }
          },
          {
            name: "secret_expiring",
            description: "List secrets that are expiring soon (within the configured warning threshold).",
            inputSchema: {
              type: "object",
              properties: {
                withinDays: { type: "number", description: "Number of days to look ahead (default: server config)" }
              }
            }
          }
        ]
      };
    });
  }

  private registerHandlers() {
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const toolName = request.params.name;
        const args = (request.params.arguments || {}) as any;

        switch (toolName) {
          case "secret_list_groups":
            return await this.handleListGroups();
          case "secret_list":
            return await this.handleListSecrets(args);
          case "secret_inject":
            return await this.handleInject(args);
          case "secret_remove":
            return await this.handleRemove(args);
          case "secret_rotate":
            return await this.handleRotate(args);
          case "secret_audit":
            return await this.handleAudit(args);
          case "secret_expiring":
            return await this.handleExpiring(args);
          default:
            return { isError: true, content: [{ type: "text" as const, text: `Unknown tool: ${toolName}` }] };
        }
      } catch (err: any) {
        return { isError: true, content: [{ type: "text" as const, text: `Error: ${err.message}` }] };
      }
    });
  }

  // ── Tool Handlers ──────────────────────────────────────────────

  private async handleListGroups() {
    const groups = await this.vault.listGroups();
    const summary = groups.map(g => ({
      name: g.name,
      description: g.description,
      secretCount: g.secrets.length,
    }));
    return { content: [{ type: "text" as const, text: JSON.stringify(summary, null, 2) }] };
  }

  private async handleListSecrets(args: any) {
    const secrets = await this.vault.listSecrets(args);

    // Annotate with expiration warnings
    const now = Date.now();
    const warningMs = this.expirationWarningDays * 24 * 60 * 60 * 1000;
    const annotated = secrets.map(s => {
      const result: any = { ...s };
      if (s.expiresAt) {
        const expiresMs = new Date(s.expiresAt).getTime();
        const remaining = expiresMs - now;
        if (remaining <= 0) {
          result._warning = '🔴 EXPIRED';
        } else if (remaining <= warningMs) {
          const daysLeft = Math.ceil(remaining / (24 * 60 * 60 * 1000));
          result._warning = `🟡 Expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''}`;
        }
      }
      return result;
    });

    await this.audit.log({
      action: 'list', actor: 'llm-request', secretKeys: secrets.map(s => s.key),
      approved: true, approvalMethod: 'none'
    });
    return { content: [{ type: "text" as const, text: JSON.stringify(annotated, null, 2) }] };
  }

  private async handleInject(args: any) {
    // Resolve keys from explicit list + groups
    let keysToInject = new Set<string>(args.keys || []);
    const allGroups = new Set<string>();

    if (args.groups) {
      const allSecrets = await this.vault.listSecrets();
      for (const s of allSecrets) {
        if (s.groups.some((g: string) => args.groups.includes(g))) {
          keysToInject.add(s.key);
          s.groups.forEach((g: string) => allGroups.add(g));
        }
      }
    }

    // Also collect groups from explicitly requested keys
    if (keysToInject.size > 0 && allGroups.size === 0) {
      const allSecrets = await this.vault.listSecrets();
      for (const s of allSecrets) {
        if (keysToInject.has(s.key)) {
          s.groups.forEach((g: string) => allGroups.add(g));
        }
      }
    }

    const finalKeys = Array.from(keysToInject);
    if (finalKeys.length === 0) {
      return { content: [{ type: "text" as const, text: 'No keys found to inject.' }] };
    }

    // Auto-approve evaluation
    let approvedKeys: string[] = [];
    let approvalMethod: 'interactive' | 'policy' | 'denied' = 'interactive';

    if (this.autoApprove) {
      const autoResult = evaluateAutoApproval(
        this.approvalPolicies,
        finalKeys,
        Array.from(allGroups),
        args.targetPath
      );

      if (autoResult.approved) {
        approvedKeys = finalKeys;
        approvalMethod = 'policy';
        await this.audit.log({
          action: 'inject', actor: 'llm-request', secretKeys: finalKeys,
          approved: true, approvalMethod: 'policy',
          details: `Auto-approved by policy: ${autoResult.policyName}`
        });
      }
    }

    // Fall back to interactive if not auto-approved
    if (approvedKeys.length === 0) {
      try {
        approvedKeys = await requestApproval({
          targetPath: args.targetPath,
          keys: finalKeys,
          merge: args.merge !== false,
          overwrite: !!args.overwrite
        });
      } catch {
        await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: finalKeys, approved: false, approvalMethod: 'denied', details: 'No TTY for approval' });
        return { isError: true, content: [{ type: "text" as const, text: 'Injection DENIED. Could not prompt human for approval (No TTY available).' }] };
      }
    }

    if (approvedKeys.length === 0) {
      await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: finalKeys, approved: false, approvalMethod: 'denied', details: 'Human denied' });
      return { content: [{ type: "text" as const, text: 'Injection DENIED by human.' }] };
    }

    // .gitignore safety check
    const isGitignored = await checkGitignore(args.targetPath);
    let gitWarning = '';
    if (!isGitignored) {
      gitWarning = ' ⚠️  WARNING: Target path is NOT covered by .gitignore — secrets may be committed!';
    }

    // Load template if requested
    let templateContent: string | undefined;
    if (args.template) {
      templateContent = await loadTemplate(this.templateDir, args.template);
    }

    // Security Note: getSecretValues is INTERNAL ONLY — values go directly to disk writer
    const values = await this.vault.getSecretValues(approvedKeys);
    const count = await injectSecrets(args.targetPath, values, args.merge !== false, !!args.overwrite, templateContent);
    values.clear(); // Scrub memory

    if (approvalMethod === 'interactive') {
      await this.audit.log({ action: 'inject', actor: 'llm-request', secretKeys: approvedKeys, approved: true, approvalMethod: 'interactive', targetPath: args.targetPath });
    }

    return {
      content: [{ type: "text" as const, text: `✓ ${count} secrets written to ${args.targetPath}${gitWarning}` }]
    };
  }

  private async handleRemove(args: any) {
    const key = args.key as string;
    const existing = await this.vault.listSecrets();
    const found = existing.find(s => s.key === key);
    if (!found) {
      return { isError: true, content: [{ type: "text" as const, text: `Secret "${key}" not found.` }] };
    }

    let approvedKeys: string[] = [];
    try {
      approvedKeys = await requestApproval({
        targetPath: '<vault removal>',
        keys: [key],
        merge: false,
        overwrite: false
      });
    } catch {
      await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: [key], approved: false, approvalMethod: 'denied', details: 'No TTY' });
      return { isError: true, content: [{ type: "text" as const, text: 'Removal DENIED. No TTY available.' }] };
    }

    if (approvedKeys.length === 0) {
      await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: [key], approved: false, approvalMethod: 'denied' });
      return { content: [{ type: "text" as const, text: `Removal of "${key}" DENIED by human.` }] };
    }

    await this.vault.removeSecret(key);
    await this.audit.log({ action: 'remove', actor: 'llm-request', secretKeys: [key], approved: true, approvalMethod: 'interactive' });
    return { content: [{ type: "text" as const, text: `✓ Secret "${key}" removed from vault.` }] };
  }

  private async handleRotate(args: any) {
    const key = args.key as string;
    const existing = await this.vault.listSecrets();
    const found = existing.find(s => s.key === key);
    if (!found) {
      return { isError: true, content: [{ type: "text" as const, text: `Secret "${key}" not found.` }] };
    }

    let approvedKeys: string[] = [];
    try {
      approvedKeys = await requestApproval({
        targetPath: `<rotate ${key}>`,
        keys: [key],
        merge: false,
        overwrite: false
      });
    } catch {
      await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: [key], approved: false, approvalMethod: 'denied', details: 'No TTY' });
      return { isError: true, content: [{ type: "text" as const, text: 'Rotation DENIED. No TTY available.' }] };
    }

    if (approvedKeys.length === 0) {
      await this.audit.log({ action: 'deny', actor: 'llm-request', secretKeys: [key], approved: false, approvalMethod: 'denied' });
      return { content: [{ type: "text" as const, text: `Rotation of "${key}" DENIED by human.` }] };
    }

    // Security Note: New value entered via /dev/tty — NEVER through the LLM
    const fs = await import('fs');
    const readline = await import('readline');
    let newValue: string;
    try {
      const ttyIn = fs.createReadStream('/dev/tty');
      const ttyOut = fs.createWriteStream('/dev/tty');
      const rl = readline.createInterface({ input: ttyIn, output: ttyOut });
      newValue = await new Promise<string>((resolve) => {
        ttyOut.write(`\nEnter new value for ${key}: `);
        rl.question('', (answer) => {
          rl.close();
          ttyIn.destroy();
          ttyOut.end();
          resolve(answer);
        });
      });
    } catch {
      return { isError: true, content: [{ type: "text" as const, text: 'Cannot read new value — no TTY.' }] };
    }

    await this.vault.rotateSecret(key, newValue);
    newValue = ''; // Scrub

    await this.audit.log({ action: 'rotate', actor: 'llm-request', secretKeys: [key], approved: true, approvalMethod: 'interactive' });
    return { content: [{ type: "text" as const, text: `✓ Secret "${key}" rotated. New rotatedAt timestamp recorded.` }] };
  }

  private async handleAudit(args: any) {
    const entries = await this.audit.query({
      secretKey: args.secretKey,
      action: args.action,
      since: args.since,
      limit: args.limit || 50
    });

    const sanitized = entries.map(e => ({
      timestamp: e.timestamp,
      action: e.action,
      actor: e.actor,
      secretKeys: e.secretKeys,
      targetPath: e.targetPath,
      approved: e.approved,
      approvalMethod: e.approvalMethod,
    }));

    return { content: [{ type: "text" as const, text: JSON.stringify(sanitized, null, 2) }] };
  }

  private async handleExpiring(args: any) {
    const days = args.withinDays || this.expirationWarningDays;
    const threshold = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    
    const expiring = await this.vault.listSecrets({ expiresBefore: threshold });
    
    if (expiring.length === 0) {
      return { content: [{ type: "text" as const, text: `No secrets expiring within ${days} days.` }] };
    }

    const now = Date.now();
    const annotated = expiring.map(s => {
      const expiresMs = new Date(s.expiresAt!).getTime();
      const remaining = expiresMs - now;
      const daysLeft = Math.ceil(remaining / (24 * 60 * 60 * 1000));
      return {
        key: s.key,
        type: s.type,
        groups: s.groups,
        expiresAt: s.expiresAt,
        status: remaining <= 0 ? '🔴 EXPIRED' : `🟡 ${daysLeft} day${daysLeft !== 1 ? 's' : ''} remaining`
      };
    });

    return { content: [{ type: "text" as const, text: JSON.stringify(annotated, null, 2) }] };
  }

  // ── Transport ──────────────────────────────────────────────────

  async run(transport?: 'stdio' | 'sse', port?: number) {
    if (transport === 'sse') {
      const http = await import('http');
      const httpServer = http.createServer(async (req, res) => {
        if (req.method === 'GET' && req.url === '/sse') {
          const sseTransport = new SSEServerTransport('/messages', res);
          await this.server.connect(sseTransport);
        } else if (req.method === 'POST' && req.url === '/messages') {
          let body = '';
          req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
          req.on('end', () => {
            res.writeHead(200);
            res.end('ok');
          });
        } else {
          res.writeHead(404);
          res.end('Not Found');
        }
      });
      const ssePort = port || 3100;
      httpServer.listen(ssePort, () => {
        console.error(`MCP Secret Server (SSE) listening on http://localhost:${ssePort}/sse`);
      });
    } else {
      const stdioTransport = new StdioServerTransport();
      await this.server.connect(stdioTransport);
    }
  }
}
