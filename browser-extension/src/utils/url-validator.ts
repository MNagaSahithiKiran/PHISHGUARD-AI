export interface URLValidationResult {
  isValid: boolean;
  sanitizedUrl: string;
  hostname: string;
  scheme: string;
  reason?: string;
}

export function validateTargetUrl(rawUrl?: string): URLValidationResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      isValid: false,
      sanitizedUrl: '',
      hostname: '',
      scheme: '',
      reason: 'No active URL provided.',
    };
  }

  const trimmed = rawUrl.trim();

  try {
    const parsed = new URL(trimmed);
    const scheme = parsed.protocol.toLowerCase();

    // Check scheme validity
    if (scheme !== 'http:' && scheme !== 'https:') {
      return {
        isValid: false,
        sanitizedUrl: trimmed,
        hostname: parsed.hostname || '',
        scheme,
        reason: `Unsupported page protocol '${scheme}'. Only public HTTP/HTTPS pages can be analyzed.`,
      };
    }

    // Check hostname presence
    if (!parsed.hostname) {
      return {
        isValid: false,
        sanitizedUrl: trimmed,
        hostname: '',
        scheme,
        reason: 'Target URL is missing a valid hostname.',
      };
    }

    return {
      isValid: true,
      sanitizedUrl: parsed.href,
      hostname: parsed.hostname,
      scheme,
    };
  } catch (err: any) {
    return {
      isValid: false,
      sanitizedUrl: trimmed,
      hostname: '',
      scheme: '',
      reason: 'Malformed URL structure.',
    };
  }
}
