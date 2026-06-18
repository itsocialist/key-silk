/**
 * Security Note: the 1Password (`op`) and Doppler CLI backends receive secret
 * keys and group/tag names as positional arguments. We invoke them with
 * `execFile` (no shell), so shell metacharacters are inert — but a value that
 * begins with `-` could still be misparsed as a CLI flag (argument injection),
 * and control characters could corrupt the invocation. Some of these values are
 * influenceable by the LLM (e.g. the `key` passed to secret_remove / rotate /
 * inject), so we validate them before they ever reach a subprocess.
 */

// Control characters (C0 range 0x00-0x1f plus DEL 0x7f) — never valid in a name.
function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

export function assertCliSafe(value: string, kind: string = 'identifier'): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`Invalid ${kind}: must be a non-empty string.`);
  }
  if (value.startsWith('-')) {
    throw new Error(
      `Invalid ${kind} "${value}": must not start with '-' (argument-injection guard).`
    );
  }
  if (hasControlChar(value)) {
    throw new Error(`Invalid ${kind}: control characters are not allowed.`);
  }
  return value;
}
