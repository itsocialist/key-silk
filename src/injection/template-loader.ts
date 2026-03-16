import { promises as fs } from 'fs';
import * as path from 'path';

/**
 * Loads a .env template file from the templates directory.
 * Templates use the format:
 *   KEY_NAME=       # Description — placeholder for injection
 *   STATIC_KEY=static_value  # Hardcoded values are preserved
 */
export async function loadTemplate(
  templateDir: string,
  templateName: string
): Promise<string> {
  // Sanitize template name to prevent path traversal
  const safeName = path.basename(templateName);
  const candidates = [
    path.join(templateDir, `${safeName}.env.tmpl`),
    path.join(templateDir, `${safeName}.tmpl`),
    path.join(templateDir, safeName),
  ];

  for (const candidate of candidates) {
    try {
      return await fs.readFile(candidate, 'utf8');
    } catch {
      continue;
    }
  }

  throw new Error(`Template "${templateName}" not found in ${templateDir}. Searched: ${candidates.map(c => path.basename(c)).join(', ')}`);
}

/**
 * Lists all available templates in the templates directory.
 */
export async function listTemplates(templateDir: string): Promise<string[]> {
  try {
    const files = await fs.readdir(templateDir);
    return files.filter(f => f.endsWith('.tmpl') || f.endsWith('.env.tmpl'));
  } catch {
    return [];
  }
}
