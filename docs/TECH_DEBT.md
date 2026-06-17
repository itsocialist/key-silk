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

### Python integration suite not run in CI / not verified on a clean machine

**Status:** open · **Severity:** low

`pytest -m key_silk` (13 tests) drives the real binary end-to-end but requires a
manual venv + `pip install -r tests/requirements.txt`. It is not part of an
automated pipeline, so regressions in the CLI surface could go unnoticed between
manual runs.

**Possible fix:** add a CI workflow that builds, runs `npm test`, then sets up a
venv and runs the pytest suite.
