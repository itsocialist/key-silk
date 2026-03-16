import { loadTemplate, listTemplates } from './template-loader';
import { promises as fs } from 'fs';
import * as path from 'path';

describe('Template Loader', () => {
  const TEMPLATE_DIR = path.join(__dirname, '__test_templates__');

  beforeEach(async () => {
    await fs.mkdir(TEMPLATE_DIR, { recursive: true });
    await fs.writeFile(path.join(TEMPLATE_DIR, 'default.env.tmpl'), '# Default\nNODE_ENV=development\n');
    await fs.writeFile(path.join(TEMPLATE_DIR, 'anthropic.env.tmpl'), '# Anthropic\nANTHROPIC_MODEL=claude-sonnet-4-20250514\n');
  });

  afterEach(async () => {
    try {
      await fs.rm(TEMPLATE_DIR, { recursive: true, force: true });
    } catch (e) {}
  });

  it('loads a template by name', async () => {
    const content = await loadTemplate(TEMPLATE_DIR, 'default');
    expect(content).toContain('# Default');
    expect(content).toContain('NODE_ENV=development');
  });

  it('loads template with .env.tmpl extension matching', async () => {
    const content = await loadTemplate(TEMPLATE_DIR, 'anthropic');
    expect(content).toContain('ANTHROPIC_MODEL');
  });

  it('throws when template not found', async () => {
    await expect(loadTemplate(TEMPLATE_DIR, 'nonexistent')).rejects.toThrow('not found');
  });

  it('prevents path traversal', async () => {
    await expect(loadTemplate(TEMPLATE_DIR, '../../../etc/passwd')).rejects.toThrow('not found');
  });

  it('lists all available templates', async () => {
    const templates = await listTemplates(TEMPLATE_DIR);
    expect(templates).toContain('default.env.tmpl');
    expect(templates).toContain('anthropic.env.tmpl');
    expect(templates.length).toBe(2);
  });
});
