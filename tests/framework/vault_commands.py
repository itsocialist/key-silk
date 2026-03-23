"""
VaultCommands - Command Object for key-silk vault operations.

Each method maps 1-to-1 with one key-silk CLI command.
Interactive commands (init, add, remove, rotate) use run_interactive().
Non-interactive commands use run() with the passphrase in MCP_VAULT_PASSPHRASE.
"""

import pexpect
from typing import Optional

from framework.cli_interface import CliInterface


class VaultCommands:
    """Command Objects for key-silk vault CLI."""

    def __init__(self, cli: CliInterface):
        self.cli = cli
        self._last_result: Optional[dict] = None

    # ── Non-interactive ────────────────────────────────────────────────────

    def list_secrets(self, group: Optional[str] = None) -> "VaultCommands":
        args = ["list"]
        if group:
            args += ["--group", group]
        self._last_result = self.cli.run(*args)
        return self

    def list_groups(self) -> "VaultCommands":
        self._last_result = self.cli.run("groups")
        return self

    def expiring(self, days: int = 7) -> "VaultCommands":
        self._last_result = self.cli.run("expiring", "--days", str(days))
        return self

    def audit(
        self,
        key: Optional[str] = None,
        action: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 50,
    ) -> "VaultCommands":
        args = ["audit", "--limit", str(limit)]
        if key:
            args += ["--key", key]
        if action:
            args += ["--action", action]
        if since:
            args += ["--since", since]
        self._last_result = self.cli.run(*args)
        return self

    def templates(self) -> "VaultCommands":
        self._last_result = self.cli.run("templates")
        return self

    def inject_secrets(
        self,
        group: str,
        target: str,
        template: Optional[str] = None,
        overwrite: bool = True,
    ) -> "VaultCommands":
        args = ["inject", "--group", group, "--target", target]
        if template:
            args += ["--template", template]
        if overwrite:
            args += ["--overwrite"]
        self._last_result = self.cli.run(*args)
        return self

    # ── Interactive (PTY) ──────────────────────────────────────────────────

    def init(self, passphrase: str) -> "VaultCommands":
        self._last_result = self.cli.run_interactive(
            args=["init"],
            interactions=[
                {"expect": "passphrase", "send": passphrase},
                {"expect": pexpect.EOF},
            ],
        )
        return self

    def add_secret(
        self,
        key: str,
        value: str,
        secret_type: str = "api_key",
        group: Optional[str] = None,
        description: Optional[str] = None,
        expires: Optional[str] = None,
    ) -> "VaultCommands":
        args = ["add", key, "--type", secret_type]
        if group:
            args += ["--group", group]
        if description:
            args += ["--description", description]
        if expires:
            args += ["--expires", expires]
        self._last_result = self.cli.run_interactive(
            args=args,
            interactions=[
                {"expect": f"Enter value for {key}", "send": value},
                {"expect": pexpect.EOF},
            ],
        )
        return self

    def remove_secret(self, key: str) -> "VaultCommands":
        self._last_result = self.cli.run_interactive(
            args=["remove", key],
            interactions=[
                {"expect": f'Remove secret "{key}"', "send": "y"},
                {"expect": pexpect.EOF},
            ],
        )
        return self

    def rotate_secret(self, key: str, new_value: str) -> "VaultCommands":
        self._last_result = self.cli.run_interactive(
            args=["rotate", key],
            interactions=[
                {"expect": f"Enter new value for {key}", "send": new_value},
                {"expect": pexpect.EOF},
            ],
        )
        return self

    # ── Result accessors ───────────────────────────────────────────────────

    def succeeded(self) -> bool:
        if self._last_result is None:
            return False
        return self._last_result.get("returncode", -1) == 0

    def stdout(self) -> str:
        if self._last_result is None:
            return ""
        return self._last_result.get("stdout", "")

    def output(self) -> str:
        if self._last_result is None:
            return ""
        return self._last_result.get("output", "")

    def contains(self, text: str) -> bool:
        return text in (self.stdout() + self.output())
