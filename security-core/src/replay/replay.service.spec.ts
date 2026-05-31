import { Test, TestingModule } from '@nestjs/testing';
import { ReplayService } from './replay.service';
import { PrismaService } from '../prisma/prisma.service';
import { PrivacyService } from '../privacy/privacy.service';

const mockPrisma = {
  executionEvent: {
    create: jest.fn(),
    findMany: jest.fn(),
  },
};

const mockPrivacy = {
  redact: jest.fn().mockImplementation((data) => data),
};

describe('ReplayService', () => {
  let service: ReplayService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReplayService,
        { provide: PrismaService, useValue: mockPrisma },
        { provide: PrivacyService, useValue: mockPrivacy },
      ],
    }).compile();

    service = module.get<ReplayService>(ReplayService);
    jest.clearAllMocks();
  });

  describe('ingestEvent', () => {
    it('should create an execution event with redacted payload', async () => {
      mockPrivacy.redact.mockReturnValueOnce({ data: '[REDACTED]' });
      mockPrisma.executionEvent.create.mockResolvedValueOnce({ id: 'event_1' });

      const payload = { data: 'sensitive_ssn' };
      const result = await service.ingestEvent({
        replayCorrelationId: 'corr_1',
        eventType: 'PROMPT',
        payload,
        actorId: 'agent_1',
        projectId: 'proj_1',
      });

      expect(result).toEqual({ id: 'event_1' });
      expect(mockPrivacy.redact).toHaveBeenCalledWith(payload);
      expect(mockPrisma.executionEvent.create).toHaveBeenCalledWith({
        data: {
          replayCorrelationId: 'corr_1',
          eventType: 'PROMPT',
          payload: { data: '[REDACTED]' },
          actorId: 'agent_1',
          projectId: 'proj_1',
        },
      });
    });
  });

  describe('getTimeline & exportEvidence', () => {
    it('should retrieve events ordered by timeline', async () => {
      mockPrisma.executionEvent.findMany.mockResolvedValueOnce([
        { id: 'event_1', eventType: 'PROMPT' },
        { id: 'event_2', eventType: 'TOOL' },
        { id: 'event_3', eventType: 'OUTPUT' },
      ]);

      const result = await service.getTimeline('corr_1', 'proj_1');
      expect(result).toHaveLength(3);
      expect(mockPrisma.executionEvent.findMany).toHaveBeenCalledWith({
        where: { replayCorrelationId: 'corr_1', projectId: 'proj_1' },
        orderBy: { createdAt: 'asc' },
      });
    });

    it('should export evidence successfully', async () => {
      mockPrisma.executionEvent.findMany.mockResolvedValueOnce([
        { id: 'event_1', eventType: 'PROMPT' },
        { id: 'event_2', eventType: 'TOOL' },
      ]);

      const result = await service.exportEvidence('corr_1', 'proj_1');
      expect(result.correlationId).toBe('corr_1');
      expect(result.projectId).toBe('proj_1');
      expect(result.events).toHaveLength(2);
      expect(result.eventCount).toBe(2);
      expect(result.exportedAt).toBeDefined();
    });
  });
});
