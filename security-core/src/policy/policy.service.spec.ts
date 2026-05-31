import { PolicyService } from './policy.service';
import { PrivacyService } from '../privacy/privacy.service';
import { McpTrustService } from '../mcp-trust/mcp-trust.service';
import { ThreatIntelService } from '../threat-intel/threat-intel.service';
import { AgentInventoryService } from '../agent-inventory/agent-inventory.service';

const mockPrisma = {
  policySet: {
    findFirst: jest.fn(),
    create: jest.fn(),
    findMany: jest.fn(),
    findUnique: jest.fn(),
  },
  policyDecision: {
    create: jest.fn().mockImplementation((args) => Promise.resolve({ id: 'decision-id', ...args.data })),
    findMany: jest.fn(),
    findUnique: jest.fn(),
    update: jest.fn(),
  },
  dlpViolation: {
    create: jest.fn(),
  }
};

const mockEvents = {
  emitApprovalRequired: jest.fn(),
  emitPolicyIntervention: jest.fn(),
};

const mockPrivacy = {
  scanForViolations: jest.fn().mockReturnValue([]),
  redact: jest.fn().mockImplementation((data) => data),
};

const mockAgentInventory = {
  getAgent: jest.fn().mockResolvedValue({ id: 'agent-1' }),
};

const mockThreatIntel = {
  recordThreat: jest.fn(),
};

const mockMcpTrust = {
  verifyTool: jest.fn().mockResolvedValue(true),
};

describe('PolicyService - Deep Testing', () => {
  let service: PolicyService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new PolicyService(
      mockPrisma as never, 
      mockEvents as never,
      mockPrivacy as never,
      mockAgentInventory as never,
      mockThreatIntel as never,
      mockMcpTrust as never
    );
  });

  describe('Condition Operators', () => {
    const setupRule = (operator: string, expectedValue: any, effect: any = 'DENY') => {
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: {
          combine: 'first-match',
          defaultOutcome: 'ALLOW',
          rules: [
            {
              id: 'rule-1',
              effect,
              actionIntent: 'ANY',
              conditions: [{ field: 'value', operator, value: expectedValue }],
            },
          ],
        },
      });
    };

    it('evaluates eq (equals)', async () => {
      setupRule('eq', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 99 } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });

    it('evaluates neq (not equals)', async () => {
      setupRule('neq', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 99 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });

    it('evaluates gt (greater than)', async () => {
      setupRule('gt', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 101 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });

    it('evaluates gte (greater than or equal)', async () => {
      setupRule('gte', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
    });

    it('evaluates lt (less than)', async () => {
      setupRule('lt', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 99 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });

    it('evaluates lte (less than or equal)', async () => {
      setupRule('lte', 100);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 100 } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
    });

    it('evaluates contains (substring)', async () => {
      setupRule('contains', 'malware');
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'install malware.exe' } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'install legit.exe' } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });

    it('evaluates regex', async () => {
      setupRule('regex', '^rm -rf');
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'rm -rf /' } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'echo rm -rf' } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW'); // does not start with rm -rf
    });

    it('evaluates in (array membership)', async () => {
      setupRule('in', ['admin', 'root']);
      const res1 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'root' } }, 'proj-1');
      expect(res1.outcome).toBe('DENY');
      
      const res2 = await service.evaluateAction({ policySetId: 'set', actionIntent: 'ANY', context: { value: 'user' } }, 'proj-1');
      expect(res2.outcome).toBe('ALLOW');
    });
  });

  describe('Combine Strategies', () => {
    it('deny-overrides returns DENY if any rule denies', async () => {
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: {
          combine: 'deny-overrides',
          defaultOutcome: 'ALLOW',
          rules: [
            { effect: 'ALLOW', actionIntent: 'ANY', conditions: [] },
            { effect: 'DENY', actionIntent: 'ANY', conditions: [{ field: 'x', operator: 'eq', value: 1 }] },
          ],
        },
      });

      const res = await service.evaluateAction({ policySetId: 'set-1', actionIntent: 'ANY', context: { x: 1 } }, 'proj-1');
      expect(res.outcome).toBe('DENY');
    });

    it('deny-overrides returns defaultOutcome if no rules match', async () => {
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: { combine: 'deny-overrides', defaultOutcome: 'ALLOW', rules: [] },
      });
      const res = await service.evaluateAction({ policySetId: 'set-1', actionIntent: 'ANY', context: {} }, 'proj-1');
      expect(res.outcome).toBe('ALLOW');
    });

    it('first-match stops evaluating after first match', async () => {
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: {
          combine: 'first-match',
          defaultOutcome: 'ALLOW',
          rules: [
            { effect: 'REQUIRE_APPROVAL', actionIntent: 'ANY', conditions: [{ field: 'x', operator: 'eq', value: 1 }] },
            { effect: 'DENY', actionIntent: 'ANY', conditions: [{ field: 'x', operator: 'eq', value: 1 }] },
          ],
        },
      });
      const res = await service.evaluateAction({ policySetId: 'set-1', actionIntent: 'ANY', context: { x: 1 } }, 'proj-1');
      expect(res.outcome).toBe('REQUIRE_APPROVAL'); // Matched first
    });
  });

  describe('Zero Trust & DLP Integrations', () => {
    it('returns DENY if MCP tool is unauthorized', async () => {
      mockMcpTrust.verifyTool.mockResolvedValueOnce(false);
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: { combine: 'first-match', defaultOutcome: 'ALLOW', rules: [] },
      });
      const res = await service.evaluateAction({ policySetId: 'set-1', actionIntent: 'some_tool', context: { toolHash: 'bad' } }, 'proj-1');
      expect(res.outcome).toBe('DENY');
      expect(JSON.stringify(res.decisionTrace)).toContain('Supply Chain Violation');
    });

    it('returns DENY if high severity DLP violation detected', async () => {
      mockPrivacy.scanForViolations.mockReturnValueOnce([{ type: 'AWS_KEY', severity: 'HIGH', count: 1 }]);
      mockPrisma.policySet.findUnique.mockResolvedValue({
        id: 'set-1',
        projectId: 'proj-1',
        rules: { combine: 'first-match', defaultOutcome: 'ALLOW', rules: [] },
      });
      const res = await service.evaluateAction({ policySetId: 'set-1', actionIntent: 'ANY', context: { data: 'secret' } }, 'proj-1');
      expect(res.outcome).toBe('DENY');
      expect(JSON.stringify(res.decisionTrace)).toContain('DLP Block');
    });
  });
});
