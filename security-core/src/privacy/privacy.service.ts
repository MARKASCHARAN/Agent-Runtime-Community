import { Injectable, Logger } from '@nestjs/common';

export type DlpViolationResult = {
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  count: number;
};

/**
 * Data Loss Prevention (DLP) and Privacy Engine.
 * Scans agent payloads via regex to prevent data exfiltration and automatically
 * redacts sensitive information (PII, Secrets) from audit logs.
 */
@Injectable()
export class PrivacyService {
  private readonly logger = new Logger(PrivacyService.name);

  // Active DLP Patterns
  private readonly DLP_PATTERNS = {
    // HIGH Severity: Secrets and Keys that lead to immediate compromise
    AWS_SECRET_KEY: {
      regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
      severity: 'HIGH' as const,
    },
    AWS_ACCESS_KEY: {
      regex: /\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
      severity: 'HIGH' as const,
    },
    PRIVATE_KEY: {
      regex: /-----BEGIN PRIVATE KEY-----/g,
      severity: 'HIGH' as const,
    },
    JWT_TOKEN: {
      regex: /ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
      severity: 'HIGH' as const,
    },

    // MEDIUM Severity: PII
    CREDIT_CARD: {
      regex: /\b(?:\d[ -]*?){13,16}\b/g,
      severity: 'MEDIUM' as const,
    },
    SSN: {
      regex: /\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g,
      severity: 'MEDIUM' as const,
    },

    // LOW Severity: Contact Info
    EMAIL: {
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'LOW' as const,
    },
  };

  /**
   * Actively scans a payload for Data Loss Prevention (DLP) violations.
   * Returns an array of detected violations.
   */
  scanForViolations(data: any): DlpViolationResult[] {
    const stringified = typeof data === 'string' ? data : JSON.stringify(data);
    if (!stringified) return [];

    const violations: DlpViolationResult[] = [];

    for (const [type, config] of Object.entries(this.DLP_PATTERNS)) {
      const matches = stringified.match(config.regex);
      if (matches && matches.length > 0) {
        violations.push({
          type,
          severity: config.severity,
          count: matches.length,
        });
      }
    }

    return violations;
  }

  /**
   * Recursively redacts PII from an object or string for safe logging.
   */
  redact(data: any): any {
    if (typeof data === 'string') {
      let redactedStr = data;
      for (const [type, config] of Object.entries(this.DLP_PATTERNS)) {
        redactedStr = redactedStr.replace(config.regex, `[REDACTED_${type}]`);
      }
      return redactedStr;
    }

    if (Array.isArray(data)) {
      return data.map((item) => this.redact(item));
    }

    if (typeof data === 'object' && data !== null) {
      const redactedObj: any = {};
      for (const [key, value] of Object.entries(data)) {
        if (
          /secret|password|token|key/i.test(key) &&
          typeof value === 'string'
        ) {
          redactedObj[key] = '[REDACTED_KEY_MATCH]';
        } else {
          redactedObj[key] = this.redact(value);
        }
      }
      return redactedObj;
    }

    return data;
  }
}
