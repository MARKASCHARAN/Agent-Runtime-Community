import { Test, TestingModule } from '@nestjs/testing';
import { McpTrustService } from './mcp-trust.service';
import { PrismaService } from '../prisma/prisma.service';

const mockPrisma = {
  mcpRegistry: {
    findMany: jest.fn(),
    findFirst: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
};

describe('McpTrustService', () => {
  let service: McpTrustService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        McpTrustService,
        { provide: PrismaService, useValue: mockPrisma },
      ],
    }).compile();

    service = module.get<McpTrustService>(McpTrustService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('verifyTool', () => {
    it('should return false if tool hash is missing', async () => {
      const result = await service.verifyTool('transfer_funds', undefined, 'proj_1');
      expect(result).toBe(false);
    });

    it('should return false if no matching tool is found in registry', async () => {
      mockPrisma.mcpRegistry.findFirst.mockResolvedValueOnce(null);
      
      const result = await service.verifyTool('transfer_funds', 'someHash', 'proj_1');
      expect(result).toBe(false);
      expect(mockPrisma.mcpRegistry.findFirst).toHaveBeenCalledWith({
        where: { name: 'transfer_funds', projectId: 'proj_1', status: 'APPROVED' }
      });
    });

    it('should return false if matching tool has different schema hash', async () => {
      mockPrisma.mcpRegistry.findFirst.mockResolvedValueOnce({ schemaHash: 'correctHash123' });
      
      const result = await service.verifyTool('transfer_funds', 'hackerHash999', 'proj_1');
      expect(result).toBe(false);
    });

    it('should return true if tool intent and hash match the APPROVED registry entry', async () => {
      mockPrisma.mcpRegistry.findFirst.mockResolvedValueOnce({ schemaHash: 'trustedHash456' });
      
      const result = await service.verifyTool('read_balance', 'trustedHash456', 'proj_1');
      expect(result).toBe(true);
    });
  });

  describe('revokeTool', () => {
    it('should update tool status to REVOKED', async () => {
      mockPrisma.mcpRegistry.update.mockResolvedValueOnce({ id: 'tool_1', status: 'REVOKED' });
      
      await service.revokeTool('tool_1', 'proj_1');
      expect(mockPrisma.mcpRegistry.update).toHaveBeenCalledWith({
        where: { id: 'tool_1' },
        data: { status: 'REVOKED' },
      });
    });
  });
});
