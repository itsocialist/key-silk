# AGENTS.md

Guidance for AI coding agents (Claude Code, Cursor, Copilot, etc.) working in this
repository. Humans: see [README.md](README.md) for product usage.

## What this project is

**Key Silk** is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io)
server for secure, human-in-the-loop secret management. It lets AI agents inject
secrets into projects **without ever exposing secret values to the LLM** — the agent
sees only metadata (key names, groups, types, expiry); actual values live in an
encrypted vault and every injection requires terminal approval.

It ships three interfaces from one binary (`key-silk`): a CLI, an interactive TUI,
and a headless MCP server (`key-silk serve`).

## Setup, build, test, run

```bash
npm install            # install deps
npm run build          # tsc -> dist/  (the bin is dist/index.js)
npm run lint           # tsc --noEmit (typecheck only)
npm run dev -- <cmd>   # run from TS without building, e.g. npm run dev -- list
npm test               # Jest unit tests (74 tests, 8 suites)

# Python integration tests (drive the real built binary end-to-end)
python3 -m venv .venv && source .venv/bin/activate
pip install -r tests/requirements.txt
pytest -m key_silk     # 13 tests
```

**Always run `npm run build` and `npm test` before committing.** The MCP server and
TUI both depend on `dist/`, so a stale build silently ships old behavior.

## Architecture (`src/`)

| Path | Responsibility |
|---|---|
| `index.ts` | CLI entry (commander). No subcommand → launches TUI. |
| `server.ts` | MCP server — exposes 7 tools; enforces the no-values contract. |
| `tui.ts` | Interactive terminal dashboard. |
| `vault/` | Pluggable backends behind `VaultBackend` (`vault.ts`). `encrypted-file.ts` (default, AES-256-GCM), `onepassword.ts`, `doppler.ts`; `factory.ts` selects one from config. |
| `injection/` | `dotenv-writer.ts` (writes `.env`, 0600, `.gitignore` safety check), `template-loader.ts`. |
| `approval/` | `approval.ts` (interactive `/dev/tty` prompt), `policies.ts` (auto-approve rules). |
| `audit/` | `logger.ts` — append-only JSON-lines audit log. |
| `config/` | `config.ts` — env vars + `~/.mcp-secrets/config.json`. |

Tests live next to source as `*.spec.ts`.

## Security rules — NON-NEGOTIABLE

This is a security tool. Violating these is a correctness bug, not a style nit.

1. **Secret values must never enter the LLM context window.** MCP tools return
   metadata only. `getSecretValues()` is **internal-only** — it is called by the CLI
   inject path and the MCP server's disk writer, never returned in a tool response.
   Do not add an MCP tool that returns secret values.
2. **Scrub secrets from memory after use.** Key buffers are zeroed via
   `scrubMemory()` / `buffer.fill(0)` (see `vault/encrypted-file.ts`). Clear value
   `Map`s (`values.clear()`) after writing.
3. **Never commit secrets.** `*.enc`, `*.enc.bak`, `audit.log`, `/vault/`, and
   `.env*` are gitignored. The vault source lives in `src/vault/` and **is** tracked —
   the `/vault/` ignore is anchored so it only excludes the runtime data dir, not
   source. Do not loosen this.
4. **Human-in-the-loop is mandatory** for `secret_inject`, `secret_remove`, and
   `secret_rotate`. These pause for `[A]pprove / [D]eny` on the real terminal (via
   `/dev/tty`, so it works even under MCP stdio). Keep that path testable and intact.
5. **Document crypto boundaries.** When touching encryption, key derivation, or the
   approval/audit path, prefix explanatory comments with `Security Note:`.

## Conventions

- **Language:** TypeScript (strict, `tsc`). **Tests:** Jest (`ts-jest`). No lint/format
  tool beyond the typechecker.
- **Repo hygiene:** keep the repo root under 20 files — put code in `src/`, docs in
  `docs/`, scripts in `scripts/`. Runtime data goes in `~/.mcp-secrets/`, never the repo.
- **Commits:** present-tense, conventional-style prefixes (`feat:`, `fix:`, `test:`,
  `docs:`). Don't commit `dist/` (gitignored — built on demand).

## Gotchas

- A fresh clone **must** build with `src/vault/` present. If `npm run build` fails with
  missing `./vault/*` modules, the vault source got excluded from git again — check the
  `.gitignore` `/vault/` anchor.
- `key-silk serve` (MCP mode) is non-interactive: it needs `MCP_VAULT_PASSPHRASE` in
  the environment (no TTY to prompt). The CLI/TUI will prompt interactively instead.
