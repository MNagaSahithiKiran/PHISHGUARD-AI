import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Manifest V3 Compliance & Least Privilege Verification', () => {
  const manifestPath = path.resolve(__dirname, '../manifest.json');
  const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestRaw);

  it('must comply with Manifest Version 3 standard', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBe('PhishGuard AI — Sentinel');
    expect(manifest.version).toBeDefined();
  });

  it('must only request minimal required permissions (least privilege)', () => {
    const allowedPermissions = ['activeTab', 'storage', 'notifications'];
    expect(manifest.permissions).toBeDefined();
    expect(manifest.permissions.sort()).toEqual(allowedPermissions.sort());

    // Disallowed high-risk permissions
    const forbiddenPermissions = [
      'cookies',
      'webRequest',
      'webRequestBlocking',
      'history',
      'bookmarks',
      'management',
      'debugger',
      'clipboardRead',
      'topSites',
    ];

    forbiddenPermissions.forEach((forbidden) => {
      expect(manifest.permissions).not.toContain(forbidden);
    });
  });

  it('must specify valid background service worker', () => {
    expect(manifest.background).toBeDefined();
    expect(manifest.background.service_worker).toBe('service-worker.js');
    expect(manifest.background.type).toBe('module');
  });

  it('must specify active popup and icon sizes', () => {
    expect(manifest.action).toBeDefined();
    expect(manifest.action.default_popup).toBe('popup.html');
    expect(manifest.icons['16']).toBe('icons/icon16.png');
    expect(manifest.icons['32']).toBe('icons/icon32.png');
    expect(manifest.icons['48']).toBe('icons/icon48.png');
    expect(manifest.icons['128']).toBe('icons/icon128.png');
  });

  it('must enforce a strict Content Security Policy (CSP)', () => {
    expect(manifest.content_security_policy).toBeDefined();
    const csp = manifest.content_security_policy.extension_pages;
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("'unsafe-eval'");
  });
});
