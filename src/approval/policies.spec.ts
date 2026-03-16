import { evaluateAutoApproval } from './policies';
import { ApprovalPolicy } from '../config/config';

describe('Auto-Approve Policies', () => {
  const basePolicies: ApprovalPolicy[] = [
    {
      name: 'dev-safe',
      conditions: {
        groups: ['dev-tools'],
        maxSecrets: 3,
        targetPathPattern: '/Users/*/projects/**/.env'
      }
    },
    {
      name: 'any-small',
      conditions: {
        maxSecrets: 1
      }
    }
  ];

  it('approves when all conditions match', () => {
    const result = evaluateAutoApproval(
      basePolicies,
      ['TOOL_API_KEY'],
      ['dev-tools'],
      '/Users/dev/projects/my-app/.env'
    );
    expect(result.approved).toBe(true);
    expect(result.policyName).toBe('dev-safe');
  });

  it('rejects when group does not match', () => {
    const result = evaluateAutoApproval(
      basePolicies,
      ['PROD_KEY'],
      ['production'],
      '/Users/dev/projects/my-app/.env'
    );
    // First policy fails on group; second policy passes (maxSecrets: 1, 1 key)
    expect(result.approved).toBe(true);
    expect(result.policyName).toBe('any-small');
  });

  it('rejects when maxSecrets is exceeded', () => {
    const result = evaluateAutoApproval(
      [basePolicies[0]], // only 'dev-safe' with maxSecrets: 3
      ['A', 'B', 'C', 'D'],
      ['dev-tools'],
      '/Users/dev/projects/my-app/.env'
    );
    expect(result.approved).toBe(false);
  });

  it('rejects when target path does not match glob', () => {
    const result = evaluateAutoApproval(
      [basePolicies[0]],
      ['KEY'],
      ['dev-tools'],
      '/etc/passwd'
    );
    expect(result.approved).toBe(false);
  });

  it('returns not approved when no policies are configured', () => {
    const result = evaluateAutoApproval([], ['KEY'], ['g'], '/path');
    expect(result.approved).toBe(false);
  });

  it('matches first qualifying policy (order matters)', () => {
    const result = evaluateAutoApproval(
      basePolicies,
      ['SINGLE_KEY'],
      ['dev-tools'],
      '/Users/dev/projects/app/.env'
    );
    // Both policies could match, but 'dev-safe' is first
    expect(result.approved).toBe(true);
    expect(result.policyName).toBe('dev-safe');
  });
});
