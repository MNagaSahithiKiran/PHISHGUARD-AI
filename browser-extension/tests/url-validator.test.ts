import { describe, it, expect } from 'vitest';
import { validateTargetUrl } from '../src/utils/url-validator';

describe('Target URL Validator & Protocol Safety', () => {
  it('accepts valid public HTTPS and HTTP URLs', () => {
    const httpsRes = validateTargetUrl('https://secure-bank.example.com/login');
    expect(httpsRes.isValid).toBe(true);
    expect(httpsRes.scheme).toBe('https:');
    expect(httpsRes.hostname).toBe('secure-bank.example.com');

    const httpRes = validateTargetUrl('http://insecure-phish.biz/verify');
    expect(httpRes.isValid).toBe(true);
    expect(httpRes.scheme).toBe('http:');
    expect(httpRes.hostname).toBe('insecure-phish.biz');
  });

  it('rejects internal Chrome and Chromium system schemes', () => {
    const chromeSettings = validateTargetUrl('chrome://settings');
    expect(chromeSettings.isValid).toBe(false);
    expect(chromeSettings.reason).toContain('chrome:');

    const chromeExt = validateTargetUrl('chrome-extension://abcdefghijklmnop/popup.html');
    expect(chromeExt.isValid).toBe(false);
    expect(chromeExt.reason).toContain('chrome-extension:');

    const edgeFlags = validateTargetUrl('edge://flags');
    expect(edgeFlags.isValid).toBe(false);
    expect(edgeFlags.reason).toContain('edge:');
  });

  it('rejects local file and privileged about: pages', () => {
    const aboutBlank = validateTargetUrl('about:blank');
    expect(aboutBlank.isValid).toBe(false);
    expect(aboutBlank.reason).toContain('about:');

    const localFile = validateTargetUrl('file:///C:/Users/test/passwords.txt');
    expect(localFile.isValid).toBe(false);
    expect(localFile.reason).toContain('file:');
  });

  it('rejects script execution schemes (javascript: and data:)', () => {
    const jsScheme = validateTargetUrl('javascript:alert(1)');
    expect(jsScheme.isValid).toBe(false);

    const dataScheme = validateTargetUrl('data:text/html,<h1>Test</h1>');
    expect(dataScheme.isValid).toBe(false);
  });

  it('handles invalid or empty URLs gracefully without crashing', () => {
    const emptyRes = validateTargetUrl('');
    expect(emptyRes.isValid).toBe(false);

    const garbageRes = validateTargetUrl('not a valid url at all');
    expect(garbageRes.isValid).toBe(false);
  });
});
