"""
Pytest fixtures for key-silk CLI integration tests.

Session-scoped vault
--------------------
A single encrypted vault is created once per pytest session inside a
temporary directory.  All tests share it.  Individual tests clean up
any secrets they add.

Environment isolation
---------------------
MCP_VAULT_PATH and MCP_AUDIT_LOG_PATH are pointed at the temp dir so
tests never touch the developer's real vault at ~/.mcp-secrets.
MCP_VAULT_PASSPHRASE is set so non-interactive commands don't prompt.

Binary resolution
-----------------
Defaults to dist/index.js relative to the repo root.
Override with the KEY_SILK_BINARY environment variable if needed.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

import pytest

# Ensure tests/framework is importable
TESTS_DIR = Path(__file__).parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from framework.cli_interface import CliInterface
from framework.vault_commands import VaultCommands
from framework.vault_tasks import VaultTasks
from framework.developer_role import DeveloperRole

# key-silk repo root (one level up from tests/)
_REPO_ROOT = TESTS_DIR.parent
_DEFAULT_BINARY = str(_REPO_ROOT / "dist" / "index.js")

TEST_PASSPHRASE = "test-passphrase-do-not-use-in-prod"


# ── Session fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def vault_dir():
    """Isolated temp directory for the test vault — cleaned up after the session."""
    tmp = tempfile.mkdtemp(prefix="key_silk_test_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def cli(vault_dir):
    """
    Session-scoped CliInterface configured with the test vault and passphrase.
    Initialises the vault once for the whole session.
    """
    binary = os.environ.get("KEY_SILK_BINARY", _DEFAULT_BINARY)
    env = {
        "MCP_VAULT_PASSPHRASE": TEST_PASSPHRASE,
        "MCP_VAULT_PATH":       os.path.join(vault_dir, "vault.enc"),
        "MCP_AUDIT_LOG_PATH":   os.path.join(vault_dir, "audit.log"),
    }
    interface = CliInterface(binary=binary, env=env)
    VaultCommands(interface).init(TEST_PASSPHRASE)
    yield interface


@pytest.fixture(scope="session")
def vault_tasks(cli):
    yield VaultTasks(cli)


@pytest.fixture(scope="session")
def developer(cli):
    yield DeveloperRole(cli)


# ── Function-scoped helpers ───────────────────────────────────────────────────

@pytest.fixture()
def tmp_env_dir():
    """Fresh temp directory for .env injection tests — cleaned up after each test."""
    tmp = tempfile.mkdtemp(prefix="key_silk_env_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture()
def tmp_template_dir():
    """Fresh temp directory for template files — cleaned up after each test."""
    tmp = tempfile.mkdtemp(prefix="key_silk_tmpl_")
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture()
def template_vault_tasks(vault_dir, tmp_template_dir):
    """
    Function-scoped VaultTasks with MCP_TEMPLATE_DIR set to a fresh temp dir.
    Yields (vault_tasks, template_dir) so the test can write template files
    before calling inject.
    """
    binary = os.environ.get("KEY_SILK_BINARY", _DEFAULT_BINARY)
    env = {
        "MCP_VAULT_PASSPHRASE": TEST_PASSPHRASE,
        "MCP_VAULT_PATH":       os.path.join(vault_dir, "vault.enc"),
        "MCP_AUDIT_LOG_PATH":   os.path.join(vault_dir, "audit.log"),
        "MCP_TEMPLATE_DIR":     tmp_template_dir,
    }
    interface = CliInterface(binary=binary, env=env)
    yield VaultTasks(interface), tmp_template_dir
