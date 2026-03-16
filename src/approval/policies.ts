import { ApprovalPolicy } from '../config/config';

/**
 * Evaluates whether a secret injection request qualifies for auto-approval
 * based on configured policies. All conditions in a policy must match.
 *
 * Security Note: Auto-approve is opt-in and disabled by default.
 * Policies are evaluated in order; the first matching policy wins.
 */
export function evaluateAutoApproval(
  policies: ApprovalPolicy[],
  secretKeys: string[],
  secretGroups: string[],
  targetPath: string
): { approved: boolean; policyName?: string } {
  if (policies.length === 0) {
    return { approved: false };
  }

  for (const policy of policies) {
    const { conditions } = policy;
    let matches = true;

    // Check group constraint
    if (conditions.groups && conditions.groups.length > 0) {
      const allGroupsAllowed = secretGroups.every(g => conditions.groups!.includes(g));
      if (!allGroupsAllowed) {
        matches = false;
      }
    }

    // Check max secrets constraint
    if (conditions.maxSecrets !== undefined) {
      if (secretKeys.length > conditions.maxSecrets) {
        matches = false;
      }
    }

    // Check target path pattern
    if (conditions.targetPathPattern) {
      if (!matchGlob(conditions.targetPathPattern, targetPath)) {
        matches = false;
      }
    }

    if (matches) {
      return { approved: true, policyName: policy.name };
    }
  }

  return { approved: false };
}

/**
 * Simple glob matching for target path patterns.
 * Supports:
 *   - `*` matches any sequence of non-/ characters
 *   - `**` matches any sequence of characters including /
 *   - `?` matches any single character
 */
function matchGlob(pattern: string, value: string): boolean {
  const regexStr = pattern
    .replace(/\*\*/g, '🔸') // placeholder to avoid double processing
    .replace(/\*/g, '[^/]*')
    .replace(/🔸/g, '.*')
    .replace(/\?/g, '.');
  const regex = new RegExp(`^${regexStr}$`);
  return regex.test(value);
}
