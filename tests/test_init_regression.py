"""
TestInitRegression

Regression tests for `key-silk init`.

Bug: init originally called defaultConfig() which ignores MCP_VAULT_PATH,
causing it to always write to ~/.mcp-secrets/vault.enc regardless of the
env var.  Fix: changed to await loadConfig() in src/index.ts.
"""

import os
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from framework import autologger
from framework.cli_interface import CliInterface
from framework.vault_commands import VaultCommands

_DEFAULT_BINARY = str(TESTS_DIR.parent / "dist" / "index.js")
TEST_PASSPHRASE = "regression-test-passphrase"


def make_isolated_cli(vault_dir: Path) -> tuple:
    binary = os.environ.get("KEY_SILK_BINARY", _DEFAULT_BINARY)
    cli = CliInterface(
        binary=binary,
        env={
            "MCP_VAULT_PASSPHRASE": TEST_PASSPHRASE,
            "MCP_VAULT_PATH":       str(vault_dir / "vault.enc"),
            "MCP_AUDIT_LOG_PATH":   str(vault_dir / "audit.log"),
        },
    )
    return cli, VaultCommands(cli)


class TestInitRegression:

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_init_creates_vault_at_mcp_vault_path(self, tmp_path):
        """init must create the vault at MCP_VAULT_PATH, not the hardcoded default."""
        _cli, cmds = make_isolated_cli(tmp_path)
        cmds.init(TEST_PASSPHRASE)
        assert (tmp_path / "vault.enc").exists(), (
            f"Vault not found at MCP_VAULT_PATH={tmp_path / 'vault.enc'}. "
            f"init likely ignored the env var (regression of src/index.ts init bug)."
        )

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_vault_is_usable_after_init(self, tmp_path):
        """A freshly initialised vault must be openable and report no secrets."""
        _cli, cmds = make_isolated_cli(tmp_path)
        cmds.init(TEST_PASSPHRASE)
        cmds.list_secrets()
        assert cmds.succeeded(), "list failed after init — vault may not be valid."
        assert "No secrets found" in cmds.stdout(), (
            f"Expected empty vault after init. Got:\n{cmds.stdout()}"
        )

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_two_vaults_at_different_paths_are_independent(self, tmp_path):
        """Secrets added to vault A must not appear in vault B."""
        dir_a = tmp_path / "vault_a"
        dir_b = tmp_path / "vault_b"
        dir_a.mkdir()
        dir_b.mkdir()

        _cli_a, cmds_a = make_isolated_cli(dir_a)
        _cli_b, cmds_b = make_isolated_cli(dir_b)
        cmds_a.init(TEST_PASSPHRASE)
        cmds_b.init(TEST_PASSPHRASE)

        cmds_a.add_secret(key="VAULT_A_ONLY_KEY", value="secret", group="test")
        cmds_a.list_secrets()
        cmds_b.list_secrets()

        assert "VAULT_A_ONLY_KEY" in cmds_a.stdout()
        assert "VAULT_A_ONLY_KEY" not in cmds_b.stdout(), (
            "Secret from vault A must not bleed into vault B."
        )
