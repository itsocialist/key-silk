import { prompt } from 'enquirer';
import * as fs from 'fs';

export interface ApprovalRequest {
  targetPath: string;
  keys: string[];
  merge: boolean;
  overwrite: boolean;
}

export async function requestApproval(req: ApprovalRequest): Promise<string[]> {
  const isTTY = process.stdin.isTTY;
  let input = process.stdin as any;
  let output = process.stdout as any;
  
  // Standard MCP servers over stdio lose terminal access.
  // We bind to /dev/tty directly to force human-in-the-loop approval.
  if (!isTTY) {
    try {
      input = fs.createReadStream('/dev/tty');
      output = fs.createWriteStream('/dev/tty');
    } catch {
      throw new Error("No TTY available for human approval. Cannot safely inject secrets without confirmation.");
    }
  }

  const log = (msg: string) => {
    if (!isTTY) {
       output.write(msg + '\n');
    } else {
       console.log(msg);
    }
  };

  log('\n┌──────────────────────────────────────────────────┐');
  log('│  🔐 Secret Injection Request                     │');
  log('│                                                  │');
  log(`│  Target: ${req.targetPath.padEnd(41)}│`);
  log(`│  Merge mode: ${req.merge.toString().padEnd(37)}│`);
  log('│                                                  │');
  log('│  Secrets to inject:                              │');
  for (const key of req.keys) {
    log(`│   • ${(key).padEnd(45)}│`);
  }
  log('│                                                  │');
  log('└──────────────────────────────────────────────────┘\n');

  try {
    const { action } = await prompt<{ action: string }>({
      type: 'select',
      name: 'action',
      message: 'Action:',
      choices: ['Approve all', 'Deny', 'Select individual keys'],
      stdin: input,
      stdout: output
    } as any);

    if (action === 'Approve all') {
      return req.keys;
    } else if (action === 'Deny') {
      return [];
    } else {
      const { selected } = await prompt<{ selected: string[] }>({
        type: 'multiselect',
        name: 'selected',
        message: 'Select keys to inject',
        choices: req.keys,
        stdin: input,
        stdout: output
      } as any);
      return selected;
    }
  } finally {
    if (!isTTY) {
      // Destroys the streams to prevent hanging
      input.destroy();
      output.end();
    }
  }
}
