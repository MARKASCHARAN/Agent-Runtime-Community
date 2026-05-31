import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

describe('Security Regression (e2e)', () => {
  let app: INestApplication<App>;

  const mockPrisma = {
    agentToken: {
      findUnique: jest.fn().mockImplementation(({ where }) => {
        if (where.token === 'test-agent-1') {
          return Promise.resolve({
            token: 'test-agent-1',
            expiresAt: new Date(Date.now() + 3600000), // Not expired
            agentIdentity: {
              clientId: 'test-agent-1',
              projectId: 'proj_e2e',
              scopes: 'all',
            },
          });
        }
        return Promise.resolve(null);
      }),
    },
    webhookConfig: {
      findMany: jest.fn().mockResolvedValue([]),
    },
    agentIdentity: {
      findUnique: jest.fn().mockResolvedValue({
        clientId: 'test-agent-1',
        projectId: 'proj_e2e',
      }),
    },
    policySet: {
      findUnique: jest.fn().mockResolvedValue({
        id: 'set-1',
        projectId: 'proj_e2e',
        rules: { combine: 'first-match', defaultOutcome: 'ALLOW', rules: [] },
      }),
    },
    mcpRegistry: {
      findFirst: jest.fn().mockResolvedValue(null), // Simulate unregistered tool
    },
    policyDecision: {
      create: jest.fn().mockImplementation((args) => Promise.resolve({ id: 'decision_reg_1', ...args.data })),
    },
    dlpViolation: {
      create: jest.fn().mockResolvedValue({ id: 'violation_1' }),
    },
    agentRecord: {
      findUnique: jest.fn().mockResolvedValue({ id: 'agent_rec_1', role: 'test-role', status: 'ACTIVE' }),
    },
    role: {
      findUnique: jest.fn().mockResolvedValue({ id: 'role_1', riskScoreThreshold: 100 }),
    },
  };

  beforeAll(async () => {
    process.env.API_KEYS = 'test-key';
  });

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(PrismaService)
      .useValue(mockPrisma)
      .compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    jest.clearAllMocks();
  });

  it('[REG-001] Prevents execution of unverified MCP tools (Supply Chain Attack)', () => {
    return request(app.getHttpServer())
      .post('/policy/evaluate')
      .set('x-api-key', 'test-agent-1')
      .send({
        policySetId: 'set-1',
        actionIntent: 'malicious_tool',
        context: { toolHash: 'fake_hash' },
      })
      .expect(201)
      .then((res) => {
        expect(res.body.outcome).toBe('DENY');
        expect(JSON.stringify(res.body.decisionTrace)).toContain('Supply Chain Violation');
      });
  });

  it('[REG-002] Prevents data exfiltration of AWS keys via DLP', () => {
    return request(app.getHttpServer())
      .post('/policy/evaluate')
      .set('x-api-key', 'test-agent-1')
      .send({
        policySetId: 'set-1',
        actionIntent: 'transfer_memory',
        context: { data: 'Here is my key: AKIAIOSFODNN7EXAMPLE' }, // Standard AWS test key format
      })
      .expect(201)
      .then((res) => {
        expect(res.body.outcome).toBe('DENY');
        expect(JSON.stringify(res.body.decisionTrace)).toContain('DLP Block');
      });
  });

  afterAll(async () => {
    await app.close();
  });
});
