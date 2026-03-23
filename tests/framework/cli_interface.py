"""
CliInterface - subprocess + pexpect wrapper for CLI automation.

Drives the key-silk binary for integration testing.  Non-interactive commands
use subprocess; interactive commands (init, add, remove, rotate) use pexpect
to drive PTY prompts rendered by enquirer.

Environment variables set on the instance (MCP_VAULT_PASSPHRASE,
MCP_VAULT_PATH, etc.) are forwarded to every spawned process.
"""

import logging
import os
import subprocess
from typing import Dict, List, Optional

import pexpect


class CliInterface:
    """CLI process driver with logging, environment isolation, and PTY support."""

    DEFAULT_TIMEOUT = 30  # seconds

    def __init__(
        self,
        binary: str,
        env: Optional[Dict[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Args:
            binary:  Path to the CLI binary or dist/index.js.
                     If path ends in '.js', commands are prefixed with 'node'.
            env:     Extra environment variables merged over os.environ.
            timeout: Default pexpect timeout in seconds.
            logger:  Optional logger; a default is created if omitted.
        """
        self.binary = binary
        self.timeout = timeout
        self.logger = logger or logging.getLogger(self.__class__.__name__)

        self.env = dict(os.environ)
        if env:
            self.env.update(env)

        self._use_node = binary.endswith('.js')

    def run(self, *args: str) -> Dict:
        """Run a non-interactive command via subprocess."""
        cmd = self._build_cmd(*args)
        self.logger.info(f"[CLI] run: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, env=self.env)

        self.logger.debug(f"[CLI] stdout: {result.stdout.strip()}")
        if result.stderr.strip():
            self.logger.debug(f"[CLI] stderr: {result.stderr.strip()}")
        self.logger.info(f"[CLI] exit: {result.returncode}")

        return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}

    def run_interactive(
        self,
        args: List[str],
        interactions: List[Dict],
        timeout: Optional[int] = None,
    ) -> Dict:
        """
        Run a command that requires PTY prompts, driven by pexpect.

        Args:
            args:         Sub-command and flags as a list.
            interactions: Ordered list of {expect, send} dicts.
                          Use expect=pexpect.EOF to wait for process exit.
        """
        t = timeout if timeout is not None else self.timeout
        cmd = self._build_cmd(*args)
        self.logger.info(f"[CLI] run_interactive: {' '.join(cmd)}")

        child = pexpect.spawn(cmd[0], args=cmd[1:], env=self.env, encoding="utf-8", timeout=t)

        output_parts = []
        try:
            for step in interactions:
                expect_val = step["expect"]
                send_val = step.get("send")

                if expect_val is pexpect.EOF:
                    child.expect(pexpect.EOF)
                    output_parts.append(child.before or "")
                else:
                    child.expect(expect_val)
                    output_parts.append(child.before or "")
                    output_parts.append(child.after or "")
                    if send_val is not None:
                        child.sendline(send_val)

            child.wait()
        except pexpect.TIMEOUT:
            self.logger.error(f"[CLI] pexpect TIMEOUT after {t}s")
            child.terminate(force=True)
            raise
        except pexpect.EOF:
            output_parts.append(child.before or "")

        output = "".join(output_parts)
        returncode = child.exitstatus if child.exitstatus is not None else -1

        self.logger.debug(f"[CLI] output: {output.strip()}")
        self.logger.info(f"[CLI] exit: {returncode}")

        return {"output": output, "returncode": returncode}

    def _build_cmd(self, *args: str) -> List[str]:
        base = ["node", self.binary] if self._use_node else [self.binary]
        return base + list(args)
