"""
DeveloperRole - Role module for key-silk vault workflows.

Orchestrates multi-step workflows by composing VaultTasks.
"""

from framework.cli_interface import CliInterface
from framework.vault_tasks import VaultTasks
from framework import autologger


class DeveloperRole:
    """Developer persona — orchestrates key-silk vault workflows."""

    @autologger.automation_logger("Role Constructor")
    def __init__(self, cli: CliInterface):
        self.cli = cli
        self.vault_tasks = VaultTasks(cli)

    @autologger.automation_logger("Role")
    def set_up_fresh_vault(self, passphrase: str) -> None:
        self.vault_tasks.initialise_vault(passphrase)

    @autologger.automation_logger("Role")
    def store_and_verify_secret(
        self,
        key: str,
        value: str,
        secret_type: str = "api_key",
        group: str = "test",
    ) -> None:
        self.vault_tasks.add_secret(key=key, value=value, secret_type=secret_type, group=group)
        self.vault_tasks.list_secrets()

    @autologger.automation_logger("Role")
    def remove_and_verify_gone(self, key: str) -> None:
        self.vault_tasks.remove_secret(key)
        self.vault_tasks.list_secrets()

    @autologger.automation_logger("Role")
    def inject_group_to_env_file(self, group: str, target_path: str) -> None:
        self.vault_tasks.inject_secrets_to_env(group=group, target_path=target_path)

    @autologger.automation_logger("Role")
    def review_audit_trail(self, key: str) -> None:
        self.vault_tasks.get_audit_output(key=key)
