"""
TestVaultLifecycle

Integration tests for the key-silk CLI via the 5-layer test architecture.
Each test follows the Arrange / Act / Assert pattern.
Tests share a session-scoped vault; secret keys are unique per test.

Coverage:
  1.  Empty vault reports 'No secrets found'
  2.  Adding a secret succeeds and the key appears in the listing
  3.  Removing a secret succeeds and the key disappears from the listing
  4.  Rotating a secret succeeds
  5.  inject writes secrets into a .env file with correct values
  6.  Audit log records 'add' and 'remove' events for a secret
  7.  Expiring command flags a secret whose expiry date is in the past
  8.  list --group returns only secrets tagged with that group
  9.  inject --overwrite replaces an existing key in the .env file
  10. inject --template preserves static template content
"""

import os
import pytest

from framework import autologger
from framework.developer_role import DeveloperRole
from framework.vault_tasks import VaultTasks


class TestVaultLifecycle:

    @pytest.fixture(autouse=True)
    def setup(self, developer, vault_tasks, tmp_env_dir):
        self.developer:   DeveloperRole = developer
        self.vault:       VaultTasks    = vault_tasks
        self.tmp_env_dir: str           = tmp_env_dir

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Empty vault
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_empty_vault_reports_no_secrets(self):
        """Empty vault should report 'No secrets found'."""
        output = self.vault.list_secrets()
        assert "No secrets found" in output, (
            f"Expected 'No secrets found' in empty vault output, got:\n{output}"
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Add a secret
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_add_secret_appears_in_listing(self):
        """After adding a secret it should appear in the vault listing."""
        key, value = "TEST_ADD_KEY", "super-secret-value"
        self.developer.store_and_verify_secret(key=key, value=value, secret_type="api_key", group="ci")
        assert self.vault.secret_is_listed(key), (
            f"Expected '{key}' to appear in the vault listing after add."
        )
        self.vault.remove_secret(key)

    # ──────────────────────────────────────────────────────────────────────────
    # 3. Remove a secret
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_remove_secret_disappears_from_listing(self):
        """After removing a secret it should no longer appear in the listing."""
        key = "TEST_REMOVE_KEY"
        self.vault.add_secret(key=key, value="temp-value", group="ci")
        assert self.vault.secret_is_listed(key), (
            f"Pre-condition failed: '{key}' should exist before removal."
        )
        self.developer.remove_and_verify_gone(key)
        assert not self.vault.secret_is_listed(key), (
            f"Expected '{key}' to be absent after removal."
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 4. Rotate a secret
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_rotate_secret_succeeds(self):
        """Rotating a secret should succeed and the key should remain listed."""
        key = "TEST_ROTATE_KEY"
        self.vault.add_secret(key=key, value="original-value", group="ci")
        rotated = self.vault.rotate_secret(key=key, new_value="rotated-value")
        assert rotated, f"Expected rotate to succeed for '{key}'."
        assert self.vault.secret_is_listed(key), (
            f"Expected '{key}' to remain in the vault after rotation."
        )
        self.vault.remove_secret(key)

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Inject secrets into a .env file
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_inject_writes_secret_to_env_file(self):
        """Inject should write KEY=\"value\" to the target .env file."""
        key          = "TEST_INJECT_KEY"
        secret_value = "injected-value-xyz-789"
        group        = "inject-test"
        target_env   = os.path.join(self.tmp_env_dir, ".env")

        self.vault.add_secret(key=key, value=secret_value, group=group)
        self.developer.inject_group_to_env_file(group=group, target_path=target_env)

        assert os.path.exists(target_env), f"Expected .env at {target_env}."
        assert self.vault.env_file_contains_key(target_env, key), (
            f"Expected '{key}' to appear in {target_env} after inject."
        )
        assert self.vault.env_file_entry_has_value(target_env, key, secret_value), (
            f"Expected {key}=\"{secret_value}\" in {target_env}."
        )
        self.vault.remove_secret(key)

    # ──────────────────────────────────────────────────────────────────────────
    # 6. Audit log
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_audit_log_records_add_and_remove(self):
        """Audit log should record both 'add' and 'remove' events."""
        key = "TEST_AUDIT_KEY"
        self.vault.add_secret(key=key, value="audit-value", group="ci")
        self.vault.remove_secret(key)
        self.developer.review_audit_trail(key)
        assert self.vault.audit_contains_action(key=key, action="add"), (
            f"Expected 'add' event for '{key}' in audit log."
        )
        assert self.vault.audit_contains_action(key=key, action="remove"), (
            f"Expected 'remove' event for '{key}' in audit log."
        )

    # ──────────────────────────────────────────────────────────────────────────
    # 7. Expiration warning
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_expiring_flags_past_expiry_secret(self):
        """A secret with a past expiry date should be flagged by `key-silk expiring`."""
        key       = "TEST_EXPIRED_KEY"
        past_date = "2020-01-01T00:00:00Z"
        self.vault.add_secret(key=key, value="expired-value", group="ci", expires=past_date)
        output = self.vault.get_expiring_output(days=1)
        assert key in output, f"Expected '{key}' in expiring output. Got:\n{output}"
        assert "EXPIRED" in output, f"Expected 'EXPIRED' status. Got:\n{output}"
        self.vault.remove_secret(key)

    # ──────────────────────────────────────────────────────────────────────────
    # 8. Group filtering
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_list_filtered_by_group_returns_only_matching_secrets(self):
        """list --group should return only secrets tagged with that group."""
        key_a, key_b = "TEST_FILTER_A_KEY", "TEST_FILTER_B_KEY"
        self.vault.add_secret(key=key_a, value="val-a", group="grp-alpha")
        self.vault.add_secret(key=key_b, value="val-b", group="grp-beta")

        output_alpha = self.vault.list_secrets(group="grp-alpha")
        output_beta  = self.vault.list_secrets(group="grp-beta")

        assert key_a in output_alpha and key_b not in output_alpha
        assert key_b in output_beta  and key_a not in output_beta

        self.vault.remove_secret(key_a)
        self.vault.remove_secret(key_b)

    # ──────────────────────────────────────────────────────────────────────────
    # 9. inject --overwrite
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_inject_overwrite_replaces_existing_key(self):
        """inject --overwrite should replace a pre-existing key in the .env file."""
        key        = "TEST_OVERWRITE_KEY"
        old_value  = "old-stale-value"
        new_value  = "new-fresh-value"
        group      = "overwrite-test"
        target_env = os.path.join(self.tmp_env_dir, ".env")

        with open(target_env, "w", encoding="utf-8") as f:
            f.write(f'{key}="{old_value}"\n')

        self.vault.add_secret(key=key, value=new_value, group=group)
        self.vault.inject_secrets_to_env(group=group, target_path=target_env, overwrite=True)

        assert self.vault.env_file_entry_has_value(target_env, key, new_value), (
            f"Expected {key}=\"{new_value}\" after overwrite inject."
        )
        assert not self.vault.env_file_entry_has_value(target_env, key, old_value), (
            f"Old value '{old_value}' should have been overwritten."
        )
        self.vault.remove_secret(key)

    # ──────────────────────────────────────────────────────────────────────────
    # 10. inject --template
    # ──────────────────────────────────────────────────────────────────────────

    @pytest.mark.key_silk
    @autologger.automation_logger("Test")
    def test_inject_with_template_preserves_structure(self, template_vault_tasks):
        """inject --template should use the template as the .env base."""
        tmpl_vault, tmpl_dir = template_vault_tasks

        key           = "TEST_TMPL_KEY"
        secret_value  = "tmpl-injected-val"
        group         = "tmpl-test"
        target_env    = os.path.join(self.tmp_env_dir, ".env")
        template_name = "ci-service"

        with open(os.path.join(tmpl_dir, f"{template_name}.env.tmpl"), "w", encoding="utf-8") as f:
            f.write("# CI Service configuration\n")
            f.write('STATIC_CONFIG_VAR="hardcoded-constant"\n')

        self.vault.add_secret(key=key, value=secret_value, group=group)
        tmpl_vault.inject_secrets_to_env(group=group, target_path=target_env, template=template_name)

        assert os.path.exists(target_env)
        assert self.vault.env_file_contains_key(target_env, "STATIC_CONFIG_VAR"), (
            "Expected static template variable to be preserved."
        )
        assert self.vault.env_file_entry_has_value(target_env, key, secret_value), (
            f"Expected {key}=\"{secret_value}\" to be injected."
        )
        self.vault.remove_secret(key)
