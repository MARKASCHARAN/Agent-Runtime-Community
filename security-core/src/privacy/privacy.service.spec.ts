import { Test, TestingModule } from '@nestjs/testing';
import { PrivacyService } from './privacy.service';

describe('PrivacyService', () => {
  let service: PrivacyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PrivacyService],
    }).compile();

    service = module.get<PrivacyService>(PrivacyService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('scanForViolations', () => {
    it('should detect AWS access keys as HIGH severity', () => {
      const payload = { data: 'my key is AKIAIOSFODNN7EXAMPLE' };
      const violations = service.scanForViolations(payload);

      expect(violations).toHaveLength(1);
      expect(violations[0]).toEqual({
        type: 'AWS_ACCESS_KEY',
        severity: 'HIGH',
        count: 1,
      });
    });

    it('should detect Credit Cards as MEDIUM severity', () => {
      const payload = 'Here is the card 4532 1234 5678 9012 for the payment';
      const violations = service.scanForViolations(payload);

      expect(violations).toHaveLength(1);
      expect(violations[0]).toEqual({
        type: 'CREDIT_CARD',
        severity: 'MEDIUM',
        count: 1,
      });
    });

    it('should return empty array for clean payloads', () => {
      const payload = { message: 'Hello world, just transferring 10 dollars' };
      const violations = service.scanForViolations(payload);
      expect(violations).toHaveLength(0);
    });

    it('should detect multiple violations across different severities', () => {
      const payload = {
        email: 'test@example.com',
        key: 'AKIAIOSFODNN7EXAMPLE',
      };
      const violations = service.scanForViolations(payload);
      
      expect(violations).toHaveLength(2);
      expect(violations.find(v => v.type === 'EMAIL')?.severity).toBe('LOW');
      expect(violations.find(v => v.type === 'AWS_ACCESS_KEY')?.severity).toBe('HIGH');
    });
  });

  describe('redact', () => {
    it('should mask PII strings based on regex', () => {
      const input = 'My email is test@example.com';
      const result = service.redact(input);
      expect(result).toBe('My email is [REDACTED_EMAIL]');
    });

    it('should mask dictionary keys that indicate secrets', () => {
      const input = {
        username: 'admin',
        password: 'super_secret_password_123',
        nested: {
          awsSecretKey: 'xyz',
        }
      };

      const result = service.redact(input);
      expect(result.password).toBe('[REDACTED_KEY_MATCH]');
      expect(result.nested.awsSecretKey).toBe('[REDACTED_KEY_MATCH]');
      expect(result.username).toBe('admin');
    });
  });
});
