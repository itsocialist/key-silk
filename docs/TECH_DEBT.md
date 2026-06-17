# Tech Debt

Known shortcuts and deferred work. Each item notes the impact and a possible fix.

## Security

### Master passphrase stored in plaintext in MCP client config

**Status:** accepted (local-config storage) · **Severity:** medium

To run as an MCP server, `key-silk serve` needs `MCP_VAULT_PASSPHRASE` in its
environment. The standard wiring (Claude Desktop / Cursor / `claude mcp add`)
stores that value **in plaintext** in the client's config file
(e.g. `~/.claude.json`, `claude_desktop_config.json`). Anyone with read access to
that file can unlock the vault.

This is contrary to the spirit of the project (keep secret material out of
plaintext) but is currently the only zero-friction way to start the server
non-interactively.

**Possible fixes:**
- Read the passphrase from the OS keychain (macOS Keychain / libsecret / DPAPI)
  via a small launcher script the MCP config points at, instead of an inline env var.
- Support a `--passphrase-command` flag that shells out to a secret manager
  (`op read ...`, `pass ...`) at startup.
- Document a `chmod 600` recommendation for the client config as an interim
  mitigation.

## Testing

### Python integration suite not run in CI

**Status:** ✅ resolved · **Severity:** low

`pytest -m key_silk` now runs in CI (`.github/workflows/ci.yml`, `integration`
job) on every push/PR, alongside the Jest suite, dependency audit, and gitleaks
secret scan. Hooks installable via `./scripts/install-hooks.sh`.

## Hardening backlog

From the security review of the crypto, MCP boundary, approval, injection, and
dependency layers. Ordered by priority. (CI + secret-scanning, the first item
of that review, is done — see above.)

### 1. Dependency vulnerabilities

**Status:** ✅ resolved · **Severity:** high

`npm audit fix` cleared all high/critical advisories (path-to-regexp / picomatch
ReDoS, qs DoS). The CI `audit` job now runs `npm audit --audit-level=high` as a
**blocking** gate. Residual advisories (19 moderate, 1 low) are dev-only
(jest → babel chain) and do not trip the high+ gate — see item 11.

### 2. SSE transport unauthenticated & network-exposed (and half-broken)

**Status:** ✅ resolved · **Severity:** high

`server.ts run()` now binds to `127.0.0.1` by default, refuses to bind off-host
without `MCP_SSE_TOKEN` (enforced as a `Bearer` token on every request), and
routes `POST /messages` to the matching session's transport via
`handlePostMessage` (previously a no-op). Host override via `MCP_SSE_HOST`.

### 3. Auto-approve glob can bypass human review

**Status:** ✅ resolved · **Severity:** high

`matchGlob` now scans the pattern char-by-char, escaping every literal
metacharacter so `.env` matches only a literal `.env`. The target path is
canonicalized with `path.resolve` (collapsing `..`) before matching, closing the
traversal bypass. The unenforced `requireSameMachine` field was removed from the
policy type. Covered by regression tests in `policies.spec.ts`.

### 11. Residual moderate dev-dependency advisories

**Status:** open · **Severity:** low

19 moderate + 1 low advisories remain in the jest/babel dev-dependency chain.
They don't ship in the published package and don't trip the CI high+ gate.
**Fix:** bump jest/ts-jest when convenient (may be a breaking major).

### 4. Incomplete `.env` value escaping

**Status:** open · **Severity:** medium

`dotenv-writer.ts` escapes only `"`. Values with newlines, backslashes, or `$`
corrupt the file or inject extra env lines. **Fix:** escape `\`, `"`, and
newlines, or use a vetted dotenv serializer.

### 5. Argument injection in CLI backends

**Status:** open · **Severity:** medium

`onepassword.ts` / `doppler.ts` use `execFile` (no shell — good) but pass
LLM-influenceable key names as positional args, so a key like `--vault` or `-X`
could alter CLI behavior. **Fix:** insert `--` before positionals and validate
keys against `^[A-Za-z0-9_.-]+$`.

### 6. Decrypted vault held in memory; values never scrubbed

**Status:** open · **Severity:** medium

`scrubMemory()` zeroes only the derived key. The full decrypted vault lives in
`this.data` as plaintext JS strings for the server's lifetime, and JS strings
can't be zeroed — a gap vs. the project's "scrub secrets from memory" claim.
**Fix:** decrypt-on-demand to minimize lifetime; document the JS-string limit.

### 7. Audit log is "append-only" by convention only

**Status:** open · **Severity:** medium

Plain `appendFile`; anyone with file access can rewrite history undetectably, and
it grows unbounded. **Fix:** hash-chain entries (each includes the prior hash)
for tamper-evidence; add rotation.

### 8. No path validation on inject `targetPath`

**Status:** open · **Severity:** medium

`secret_inject` accepts any path from the LLM; only the human prompt guards it.
**Fix:** enforce absolute paths and optionally restrict to allowlisted roots.

### 9. No rekey / passphrase-change command

**Status:** open · **Severity:** low

Salt is reused across saves and the raw passphrase is discarded, so there's no
way to rotate the master passphrase. **Fix:** add a `rekey` command.

### 10. Backup `.bak` permissions not explicitly 0600

**Status:** open · **Severity:** low

`fs.copyFile` may not preserve `0600` on all platforms. **Fix:** `chmod 0600`
the `.bak` explicitly after copy. (Consider scrypt/argon2 over PBKDF2 — already
OWASP-OK at 600k, so low priority.)
