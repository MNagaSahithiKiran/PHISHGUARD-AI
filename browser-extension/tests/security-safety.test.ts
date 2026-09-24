import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Defensive Extension Security & Privacy Guarantees', () => {
  const contentScriptPath = path.resolve(__dirname, '../src/content/content-script.ts');
  const contentScriptCode = fs.readFileSync(contentScriptPath, 'utf8');

  it('must NEVER query or read password input fields', () => {
    expect(contentScriptCode).not.toMatch(/type\s*=\s*['"]password['"]/i);
    expect(contentScriptCode).not.toMatch(/input\[type=['"]password['"]\]/i);
    expect(contentScriptCode).not.toMatch(/querySelector\(['"].*password.*['"]\)/i);
    expect(contentScriptCode).not.toMatch(/HTMLInputElement/i);
  });

  it('must NEVER register keylogger listeners (keydown, keypress, keyup)', () => {
    expect(contentScriptCode).not.toMatch(/addEventListener\(['"](keydown|keypress|keyup)['"]/i);
    expect(contentScriptCode).not.toMatch(/onkeydown|onkeypress|onkeyup/i);
  });

  it('must NEVER read or manipulate browser cookies', () => {
    expect(contentScriptCode).not.toMatch(/document\.cookie/i);
    expect(contentScriptCode).not.toMatch(/chrome\.cookies/i);
  });

  it('must NEVER access or extract form submission values', () => {
    expect(contentScriptCode).not.toMatch(/\.formData/i);
    expect(contentScriptCode).not.toMatch(/document\.forms/i);
    expect(contentScriptCode).not.toMatch(/\.value\b/i);
  });

  it('must sanitize domain and textual content against XSS before DOM insertion', () => {
    expect(contentScriptCode).toContain('escapeHtml');
  });
});
