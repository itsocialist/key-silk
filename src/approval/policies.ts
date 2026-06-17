import { ApprovalPolicy } from '../config/config';
import * as path from 'path';

/**
 * Evaluates whether a secret injection request qualifies for auto-approval
 * based on configured policies. All conditions in a policy must match.
 *
 * Security Note: Auto-approve is opt-in and disabled by default.
 * Policies are evaluated in order; the first matching policy wins.
 * The target path is canonicalized (resolving `..`) before matching so a
 * traversal-laden path cannot satisfy a glob and then resolve elsewhere.
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

  const resolvedPath = path.resolve(targetPath);

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

    // Check target path pattern (against the canonicalized path)
    if (conditions.targetPathPattern) {
      if (!matchGlob(conditions.targetPathPattern, resolvedPath)) {
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
 * Glob matching for target path patterns.
 * Supports:
 *   - `*` matches any sequence of non-/ characters
 *   - `**` matches any sequence of characters including /
 *   - `?` matches any single character
 *
 * Security Note: literal characters are fully regex-escaped before the wildcards
 * are emitted. Without this, metacharacters in the pattern (e.g. the `.` in
 * `.env`) would match arbitrary input and could auto-approve unintended paths —
 * a bypass of the human approval gate, which auto-approve already skips.
 */
function matchGlob(pattern: string, value: string): boolean {
  // Scan the pattern char-by-char: emit regex for wildcards, escape everything
  // else as a literal so no literal metacharacter is ever treated as a wildcard.
  let regexStr = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        regexStr += '.*'; // ** — across path separators
        i++;
      } else {
        regexStr += '[^/]*'; // * — within a single path segment
      }
    } else if (c === '?') {
      regexStr += '.';
    } else {
      regexStr += c.replace(/[.*+?^${}()|[\]\\]/, '\\$&');
    }
  }
  return new RegExp(`^${regexStr}$`).test(value);
}
