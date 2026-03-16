# 🔐 Key Silk — MCP Secret Server

**Secure, human-in-the-loop secret management for AI-assisted development.**

Key Silk is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that gives AI coding agents the ability to inject secrets into your projects — without ever exposing secret values to the LLM.

## The Problem

When AI coding assistants need API keys or credentials to set up a project, you're forced to paste secrets directly into the chat. Those secrets then live in:
- The LLM's context window  
- API logs and training pipelines  
- Chat history

**Key Silk eliminates this entirely.** Secrets are stored in a local encrypted vault and injected directly to `.env` files. The LLM only sees metadata (key names, groups, types) — never the values.

## How It Works

```
┌──────────────┐     metadata only      ┌──────────────┐
│   AI Agent   │ ◄──────────────────── │   MCP Server  │
│  (Claude,    │    "ANTHROPIC_API_KEY  │  (Key Silk)   │
│   Cursor,    │     exists in group    │               │
│   etc.)      │     'ai-providers'"    │               │
└──────┬───────┘                        └───────┬───────┘
       │                                        │
       │  "Please inject ai-providers            │
       │   into /project/.env"                  │
       │                                        │
       ▼                                        ▼
┌──────────────┐                        ┌──────────────┐
│   Human      │ ◄── approval prompt ── │  Encrypted   │
│   Terminal   │ ──── approved keys ──► │  Vault       │
└──────────────┘                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │  .env file   │
                                        │  (0600 perms)│
                                        └──────────────┘
```

**Key security guarantees:**
- 🔒 Secret values **never** enter the LLM context window
- ✋ Every injection requires **human approval** on your terminal
- 📋 Every operation is recorded in an **append-only audit log**
- 🔑 Vault encrypted with **AES-256-GCM** + **PBKDF2** (600K iterations)

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/itsocialist/key-silk.git
cd key-silk
npm install
npm run build
```

### 2. Initialize Your Vault

```bash
npx tsx src/index.ts init
# Enter a master passphrase when prompted
```

### 3. Add Secrets

```bash
export MCP_VAULT_PASSPHRASE="your-passphrase"

# Add an API key
npx tsx src/index.ts add ANTHROPIC_API_KEY -t api_key -g ai-providers

# Add a database URL
npx tsx src/index.ts add DATABASE_URL -t other -g infrastructure

# Add a secret with an expiration date
npx tsx src/index.ts add TEMP_TOKEN -t oauth_token -g temporary -e 2026-04-01T00:00:00Z
```

### 4. Inject Into a Project

```bash
npx tsx src/index.ts inject -g ai-providers --target /path/to/project/.env
```

### 5. Connect to Your AI Agent (MCP)

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "key-silk": {
      "command": "node",
      "args": ["/path/to/key-silk/dist/index.js", "serve"],
      "env": {
        "MCP_VAULT_PASSPHRASE": "your-passphrase"
      }
    }
  }
}
```

Now your AI agent can discover and inject secrets without ever seeing the values.

---

## CLI Reference

| Command | Description |
|---|---|
| `init [--backend <type>]` | Initialize a new vault (encrypted-file, onepassword, doppler) |
| `add <key> [options]` | Add a new secret interactively |
| `list\|ls [-g group]` | List secret metadata (never shows values) |
| `groups` | List all secret groups |
| `remove\|rm <key>` | Remove a secret from the vault |
| `rotate <key>` | Rotate (update) a secret's value |
| `inject -g <group> --target <path>` | Inject secrets to a `.env` file |
| `expiring [-d days]` | Show secrets expiring soon |
| `audit [-k key] [-a action]` | View the audit trail |
| `templates` | List available `.env` templates |
| `serve [--transport stdio\|sse]` | Start the MCP server |

### Add Options

```bash
npx tsx src/index.ts add <KEY> \
  -t, --type <type>         # api_key, client_id, client_secret, oauth_token, other
  -g, --group <groups>      # Comma-separated groups
  -d, --description <desc>  # Human-readable description
  -e, --expires <date>      # ISO 8601 expiration date
```

### Inject Options

```bash
npx tsx src/index.ts inject \
  -g, --group <group>       # Group to inject
  --target <path>           # Target .env file path
  --template <name>         # Template name (default, nextjs, node-api, etc.)
  --overwrite               # Overwrite existing keys
```

---

## MCP Tools

When running as an MCP server, Key Silk exposes these tools to AI agents:

| Tool | Description |
|---|---|
| `secret_list_groups` | List available secret groups |
| `secret_list` | List secrets (metadata only, with expiration warnings) |
| `secret_inject` | Inject secrets to `.env` (requires human approval) |
| `secret_remove` | Remove a secret (requires human approval) |
| `secret_rotate` | Rotate a secret (new value entered via terminal) |
| `secret_audit` | Query the audit trail |
| `secret_expiring` | List secrets nearing expiration |

**All tools enforce the security contract:** secret values are never returned in tool responses.

---

## Vault Backends

Key Silk supports three vault backends:

### Encrypted File (Default)
Local AES-256-GCM encrypted JSON file. No external dependencies.

```bash
npx tsx src/index.ts init --backend encrypted-file
```

### 1Password CLI
Delegates to your existing 1Password vault via the `op` CLI.

```bash
# Prerequisites: install 1Password CLI and authenticate
op signin

# Configure
export MCP_VAULT_BACKEND=onepassword
export MCP_1PASSWORD_VAULT=Development
```

### Doppler
Integrates with Doppler's secrets management platform.

```bash
# Prerequisites: install Doppler CLI and authenticate
doppler login

# Configure
export MCP_VAULT_BACKEND=doppler
export MCP_DOPPLER_PROJECT=my-project
export MCP_DOPPLER_CONFIG=dev
```

---

## Templates

Key Silk ships with `.env` templates for common project types:

| Template | Use Case |
|---|---|
| `default` | General-purpose starter |
| `anthropic-project` | Anthropic/Claude-focused projects |
| `node-api` | Express/Fastify API servers |
| `nextjs` | Next.js full-stack applications |
| `mcp-server` | MCP server projects |

```bash
# List available templates
npx tsx src/index.ts templates

# Inject using a template as the base
npx tsx src/index.ts inject -g ai-providers --target .env --template nextjs
```

---

## Configuration

Configure via environment variables or `~/.mcp-secrets/config.json`:

| Variable | Default | Description |
|---|---|---|
| `MCP_VAULT_PASSPHRASE` | — | Master passphrase (required for encrypted-file backend) |
| `MCP_VAULT_BACKEND` | `encrypted-file` | Backend type |
| `MCP_VAULT_PATH` | `~/.mcp-secrets/vault.enc` | Vault file location |
| `MCP_AUDIT_LOG_PATH` | `~/.mcp-secrets/audit.log` | Audit log location |
| `MCP_TRANSPORT` | `stdio` | MCP transport (stdio or sse) |
| `MCP_SSE_PORT` | `3100` | SSE transport port |
| `MCP_AUTO_APPROVE` | `false` | Enable auto-approve policies |
| `MCP_TEMPLATE_DIR` | `./templates` | Template directory |
| `MCP_EXPIRATION_WARNING_DAYS` | `7` | Expiration warning threshold |
| `MCP_1PASSWORD_VAULT` | `Development` | 1Password vault name |
| `MCP_DOPPLER_PROJECT` | — | Doppler project name |
| `MCP_DOPPLER_CONFIG` | `dev` | Doppler config environment |

---

## Auto-Approve Policies

For trusted environments, configure policies that skip interactive approval:

```json
{
  "autoApprove": true,
  "approvalPolicies": [
    {
      "name": "dev-local",
      "conditions": {
        "groups": ["dev-tools"],
        "maxSecrets": 3,
        "targetPathPattern": "/Users/*/projects/**/.env"
      }
    }
  ]
}
```

All conditions must match for auto-approval. Every auto-approved injection is still logged in the audit trail.

---

## Security Model

| Layer | Protection |
|---|---|
| **Encryption** | AES-256-GCM with PBKDF2 (600K iterations) |
| **File permissions** | `0600` on vault, `.env`, and audit files |
| **Memory** | Key buffers zeroed after use (`scrubMemory()`) |
| **LLM isolation** | `getSecretValues()` is internal-only; never exposed via MCP |
| **Approval** | Interactive TTY prompt via `/dev/tty` — works even under MCP stdio |
| **Audit** | Append-only JSON-lines log of every operation |
| **Backup** | Automatic `.bak` file created before every vault write |
| **Git safety** | `.gitignore` check warns if target `.env` is not excluded |

---

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npx tsx src/index.ts <command>

# Run tests
npm test

# Build for production
npm run build

# Run built version
node dist/index.js <command>
```

---

## License

MIT

---

Built with the [Model Context Protocol](https://modelcontextprotocol.io) SDK.
