/**
 * approval.spec.ts — unit tests for requestApproval()
 *
 * Three paths under test:
 *   TTY      — process.stdin.isTTY=true  → uses process.stdin/stdout directly
 *   /dev/tty — isTTY=false, /dev/tty ok  → opens explicit streams
 *   no-TTY   — isTTY=false, /dev/tty fails → throws
 *
 * Prompt choices:
 *   "Approve all"            → returns req.keys unchanged
 *   "Deny"                   → returns []
 *   "Select individual keys" → returns chosen subset (second prompt)
 */

// ── Module mocks (hoisted by Jest) ─────────────────────────────────────────

jest.mock('enquirer', () => ({ prompt: jest.fn() }));

jest.mock('fs', () => ({
  ...jest.requireActual('fs'),
  createReadStream:  jest.fn(),
  createWriteStream: jest.fn(),
}));

// ── Imports ────────────────────────────────────────────────────────────────

import { requestApproval, ApprovalRequest } from './approval';
import { prompt } from 'enquirer';
import * as fs from 'fs';

// ── Typed mock handles ─────────────────────────────────────────────────────

const mockPrompt            = prompt as jest.MockedFunction<typeof prompt>;
const mockCreateReadStream  = fs.createReadStream  as jest.Mock;
const mockCreateWriteStream = fs.createWriteStream as jest.Mock;

// Minimal fake TTY stream objects
const fakeTtyIn  = { destroy: jest.fn() };
const fakeTtyOut = { write:   jest.fn(), end: jest.fn() };

// ── Shared fixtures ────────────────────────────────────────────────────────

const BASE_REQ: ApprovalRequest = {
  targetPath: '/tmp/test.env',
  keys:       ['KEY_A', 'KEY_B', 'KEY_C'],
  merge:      true,
  overwrite:  false,
};

function setIsTTY(val: boolean): void {
  Object.defineProperty(process.stdin, 'isTTY', { value: val, configurable: true });
}

beforeEach(() => {
  jest.clearAllMocks();
  // Default: /dev/tty is accessible
  mockCreateReadStream.mockReturnValue(fakeTtyIn as any);
  mockCreateWriteStream.mockReturnValue(fakeTtyOut as any);
  // Suppress console.log noise from the approval banner on TTY path
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterAll(() => {
  setIsTTY(false);
  jest.restoreAllMocks();
});

// ── TTY path ────────────────────────────────────────────────────────────────

describe('requestApproval — TTY path (process.stdin.isTTY = true)', () => {
  beforeEach(() => setIsTTY(true));

  it('"Approve all" returns all requested keys', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Approve all' } as any);
    expect(await requestApproval(BASE_REQ)).toEqual(['KEY_A', 'KEY_B', 'KEY_C']);
  });

  it('"Deny" returns an empty array', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Deny' } as any);
    expect(await requestApproval(BASE_REQ)).toEqual([]);
  });

  it('"Select individual keys" returns only the chosen subset', async () => {
    mockPrompt
      .mockResolvedValueOnce({ action: 'Select individual keys' } as any)
      .mockResolvedValueOnce({ selected: ['KEY_A', 'KEY_C'] } as any);
    expect(await requestApproval(BASE_REQ)).toEqual(['KEY_A', 'KEY_C']);
  });

  it('does NOT open /dev/tty streams when stdin is already a TTY', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Deny' } as any);
    await requestApproval(BASE_REQ);
    expect(mockCreateReadStream).not.toHaveBeenCalled();
    expect(mockCreateWriteStream).not.toHaveBeenCalled();
  });
});

// ── /dev/tty path ───────────────────────────────────────────────────────────

describe('requestApproval — /dev/tty path (isTTY=false, /dev/tty accessible)', () => {
  beforeEach(() => setIsTTY(false));

  it('"Approve all" returns all keys', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Approve all' } as any);
    expect(await requestApproval(BASE_REQ)).toEqual(['KEY_A', 'KEY_B', 'KEY_C']);
  });

  it('"Deny" returns empty array', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Deny' } as any);
    expect(await requestApproval(BASE_REQ)).toEqual([]);
  });

  it('opens /dev/tty for both input and output', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Deny' } as any);
    await requestApproval(BASE_REQ);
    expect(mockCreateReadStream).toHaveBeenCalledWith('/dev/tty');
    expect(mockCreateWriteStream).toHaveBeenCalledWith('/dev/tty');
  });

  it('writes the approval banner to the /dev/tty output stream', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Deny' } as any);
    await requestApproval(BASE_REQ);
    const written = (fakeTtyOut.write as jest.Mock).mock.calls
      .map((c: any[]) => c[0] as string)
      .join('');
    expect(written).toContain('Secret Injection Request');
    expect(written).toContain('/tmp/test.env');
    expect(written).toContain('KEY_A');
  });

  it('destroys streams in the finally block after approval', async () => {
    mockPrompt.mockResolvedValueOnce({ action: 'Approve all' } as any);
    await requestApproval(BASE_REQ);
    expect(fakeTtyIn.destroy).toHaveBeenCalled();
    expect(fakeTtyOut.end).toHaveBeenCalled();
  });

  it('destroys streams even when the prompt throws', async () => {
    mockPrompt.mockRejectedValueOnce(new Error('prompt error'));
    await expect(requestApproval(BASE_REQ)).rejects.toThrow('prompt error');
    expect(fakeTtyIn.destroy).toHaveBeenCalled();
    expect(fakeTtyOut.end).toHaveBeenCalled();
  });
});

// ── no-TTY error path ────────────────────────────────────────────────────────

describe('requestApproval — no-TTY error path (/dev/tty inaccessible)', () => {
  beforeEach(() => setIsTTY(false));

  it('throws when /dev/tty cannot be opened', async () => {
    mockCreateReadStream.mockImplementationOnce(() => {
      throw new Error('ENOENT: /dev/tty');
    });
    await expect(requestApproval(BASE_REQ))
      .rejects.toThrow('No TTY available for human approval');
  });

  it('does not call prompt when /dev/tty is unavailable', async () => {
    mockCreateReadStream.mockImplementationOnce(() => {
      throw new Error('ENOENT: /dev/tty');
    });
    await expect(requestApproval(BASE_REQ)).rejects.toThrow();
    expect(mockPrompt).not.toHaveBeenCalled();
  });
});
