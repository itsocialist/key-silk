import { AuditLogger } from './logger';
import { promises as fs } from 'fs';
import * as path from 'path';

describe('AuditLogger', () => {
  const TEST_LOG = path.join(__dirname, 'test-audit.log');

  afterEach(async () => {
    try {
      await fs.unlink(TEST_LOG);
    } catch (e) {}
  });

  it('securely appends logs and queries them', async () => {
    const logger = new AuditLogger(TEST_LOG);

    await logger.log({
      action: 'inject',
      actor: 'llm-request',
      secretKeys: ['TEST_API_KEY'],
      approved: true,
      approvalMethod: 'interactive',
      targetPath: '/dev/null'
    });

    await logger.log({
      action: 'deny',
      actor: 'llm-request',
      secretKeys: ['TEST_API_KEY'],
      approved: false,
      approvalMethod: 'denied'
    });

    const entries = await logger.query({});
    expect(entries.length).toBe(2);
    // Both entries present (order may vary when timestamps are identical)
    const actions = entries.map(e => e.action).sort();
    expect(actions).toEqual(['deny', 'inject']);

    const denyEntries = await logger.query({ action: 'deny' });
    expect(denyEntries.length).toBe(1);

    const specificKeyEntries = await logger.query({ secretKey: 'TEST_API_KEY' });
    expect(specificKeyEntries.length).toBe(2);
  });

  it('builds a verifiable hash chain', async () => {
    const logger = new AuditLogger(TEST_LOG);
    await logger.log({ action: 'add', actor: 'human-direct', secretKeys: ['A'], approved: true, approvalMethod: 'interactive' });
    await logger.log({ action: 'inject', actor: 'llm-request', secretKeys: ['A'], approved: true, approvalMethod: 'interactive' });
    await logger.log({ action: 'remove', actor: 'llm-request', secretKeys: ['A'], approved: true, approvalMethod: 'interactive' });

    const result = await logger.verifyChain();
    expect(result.ok).toBe(true);
  });

  it('detects tampering (edited entry breaks the chain)', async () => {
    const logger = new AuditLogger(TEST_LOG);
    await logger.log({ action: 'add', actor: 'human-direct', secretKeys: ['A'], approved: true, approvalMethod: 'interactive' });
    await logger.log({ action: 'deny', actor: 'llm-request', secretKeys: ['A'], approved: false, approvalMethod: 'denied' });

    // Tamper: flip the second entry's `approved` flag directly on disk.
    const raw = await fs.readFile(TEST_LOG, 'utf8');
    const lines = raw.trim().split('\n');
    const second = JSON.parse(lines[1]);
    second.approved = true; // forge approval, keep the old hash
    lines[1] = JSON.stringify(second);
    await fs.writeFile(TEST_LOG, lines.join('\n') + '\n');

    const result = await logger.verifyChain();
    expect(result.ok).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it('treats a missing log as ok', async () => {
    const logger = new AuditLogger(path.join(__dirname, 'does-not-exist.log'));
    expect((await logger.verifyChain()).ok).toBe(true);
  });
});
