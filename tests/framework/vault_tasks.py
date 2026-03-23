"""
VaultTasks - Task module for key-silk vault workflows.

Composes VaultCommands into single domain operations.
Returns meaningful data so Roles and tests can make assertions.
NO assertions here — assertions live in tests.
"""

from typing import Optional

from framework.vault_commands import VaultCommands
from framework.cli_interface import CliInterface
from framework import autologger


class VaultTasks:
    """Task module for key-silk vault domain operations."""

    def __init__(self, cli: CliInterface):
        self.vault = VaultCommands(cli)

    # ── Setup ──────────────────────────────────────────────────────────────

    @autologger.automation_logger("Task")
    def initialise_vault(self, passphrase: str) -> bool:
        self.vault.init(passphrase)
        return self.vault.succeeded()

    # ── Secret management ──────────────────────────────────────────────────

    @autologger.automation_logger("Task")
    def add_secret(
        self,
        key: str,
        value: str,
        secret_type: str = "api_key",
        group: str = "test",
        description: str = "",
        expires: str = None,
    ) -> bool:
        self.vault.add_secret(
            key=key,
            value=value,
            secret_type=secret_type,
            group=group,
            description=description or None,
            expires=expires,
        )
        return self.vault.succeeded()

    @autologger.automation_logger("Task")
    def remove_secret(self, key: str) -> bool:
        self.vault.remove_secret(key)
        return self.vault.succeeded()

    @autologger.automation_logger("Task")
    def rotate_secret(self, key: str, new_value: str) -> bool:
        self.vault.rotate_secret(key, new_value)
        return self.vault.succeeded()

    # ── Read operations ────────────────────────────────────────────────────

    @autologger.automation_logger("Task")
    def list_secrets(self, group: str = None) -> str:
        self.vault.list_secrets(group=group)
        return self.vault.stdout()

    @autologger.automation_logger("Task")
    def list_groups(self) -> str:
        self.vault.list_groups()
        return self.vault.stdout()

    @autologger.automation_logger("Task")
    def secret_is_listed(self, key: str, group: str = None) -> bool:
        self.vault.list_secrets(group=group)
        return key in self.vault.stdout()

    @autologger.automation_logger("Task")
    def vault_is_empty(self) -> bool:
        self.vault.list_secrets()
        return "No secrets found" in self.vault.stdout()

    @autologger.automation_logger("Task")
    def get_expiring_output(self, days: int = 7) -> str:
        self.vault.expiring(days=days)
        return self.vault.stdout()

    @autologger.automation_logger("Task")
    def get_audit_output(
        self,
        key: str = None,
        action: str = None,
        limit: int = 50,
    ) -> str:
        self.vault.audit(key=key, action=action, limit=limit)
        return self.vault.stdout()

    @autologger.automation_logger("Task")
    def inject_secrets_to_env(
        self,
        group: str,
        target_path: str,
        overwrite: bool = True,
        template: str = None,
    ) -> bool:
        self.vault.inject_secrets(
            group=group, target=target_path, overwrite=overwrite, template=template
        )
        return self.vault.succeeded()

    @autologger.automation_logger("Task")
    def env_file_contains_key(self, env_path: str, key: str) -> bool:
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                return key in f.read()
        except FileNotFoundError:
            return False

    @autologger.automation_logger("Task")
    def env_file_entry_has_value(self, env_path: str, key: str, value: str) -> bool:
        """Return True if the .env file contains KEY="value" (quoted form)."""
        escaped = value.replace('"', '\\"')
        expected_line = f'{key}="{escaped}"'
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                return expected_line in f.read()
        except FileNotFoundError:
            return False

    @autologger.automation_logger("Task")
    def audit_contains_action(self, key: str, action: str, limit: int = 50) -> bool:
        output = self.get_audit_output(key=key, action=action, limit=limit)
        return key in output and action in output
