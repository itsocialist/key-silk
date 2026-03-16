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
    // Should be sorted new -> old
    expect(entries[0].action).toBe('deny');
    expect(entries[1].action).toBe('inject');

    const denyEntries = await logger.query({ action: 'deny' });
    expect(denyEntries.length).toBe(1);

    const specificKeyEntries = await logger.query({ secretKey: 'TEST_API_KEY' });
    expect(specificKeyEntries.length).toBe(2);
  });
});
