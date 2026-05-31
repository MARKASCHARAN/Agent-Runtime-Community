import { ContextManager } from './context';

describe('ContextManager', () => {
  describe('filter', () => {
    it('should filter credit cards', () => {
      const data = 'Here is my card: 4111-1111-1111-1111';
      expect(ContextManager.filter(data)).toBe('Here is my card: [REDACTED_CARD]');
    });

    it('should filter emails', () => {
      const data = 'Contact me at admin@example.com please';
      expect(ContextManager.filter(data)).toBe('Contact me at [REDACTED_EMAIL] please');
    });

    it('should recursively filter objects', () => {
      const data = { user: { email: 'test@test.com' }, cards: ['1234-5678-9012-3456'] };
      const expected = { user: { email: '[REDACTED_EMAIL]' }, cards: ['[REDACTED_CARD]'] };
      expect(ContextManager.filter(data)).toEqual(expected);
    });
  });

  describe('compress', () => {
    it('should compress long strings', () => {
      const longString = 'a'.repeat(2000);
      const compressed = ContextManager.compress(longString, 1000);
      expect(compressed).toContain('a'.repeat(1000));
      expect(compressed).toContain('[TRUNCATED 1000 CHARS]');
    });

    it('should recursively compress objects', () => {
      const data = { image: 'b'.repeat(1500) };
      const compressed = ContextManager.compress(data, 1000);
      expect(compressed.image).toContain('[TRUNCATED 500 CHARS]');
    });
  });
});
