export class ContextManager {
  /**
   * Filters PII (Personal Identifiable Information) from strings or objects
   * before they are sent to an LLM context window.
   */
  static filter(data: any): any {
    if (typeof data === 'string') {
      let filtered = data;
      // Redact credit cards (simple heuristic)
      filtered = filtered.replace(/\b(?:\d[ -]*?){13,16}\b/g, '[REDACTED_CARD]');
      // Redact emails
      filtered = filtered.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[REDACTED_EMAIL]');
      // Redact SSN (simple heuristic)
      filtered = filtered.replace(/\b\d{3}[-.]?\d{2}[-.]?\d{4}\b/g, '[REDACTED_SSN]');
      return filtered;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.filter(item));
    }

    if (data !== null && typeof data === 'object') {
      const filteredObj: Record<string, any> = {};
      for (const [key, value] of Object.entries(data)) {
        filteredObj[key] = this.filter(value);
      }
      return filteredObj;
    }

    return data;
  }

  /**
   * Compresses large JSON payloads to fit within a specific size limit
   * by truncating excessively long string values (e.g., base64 images).
   */
  static compress(data: any, maxStringLength: number = 1000): any {
    if (typeof data === 'string') {
      if (data.length > maxStringLength) {
        return `${data.substring(0, maxStringLength)}... [TRUNCATED ${data.length - maxStringLength} CHARS]`;
      }
      return data;
    }

    if (Array.isArray(data)) {
      return data.map(item => this.compress(item, maxStringLength));
    }

    if (data !== null && typeof data === 'object') {
      const compressedObj: Record<string, any> = {};
      for (const [key, value] of Object.entries(data)) {
        compressedObj[key] = this.compress(value, maxStringLength);
      }
      return compressedObj;
    }

    return data;
  }
}
