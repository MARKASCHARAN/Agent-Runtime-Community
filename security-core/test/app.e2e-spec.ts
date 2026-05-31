import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

describe('AppController (e2e)', () => {
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
        rules: {
          combine: 'first-match',
          defaultOutcome: 'ALLOW',
          rules: [
            {
              id: 'rule-deny-execute',
              effect: 'DENY',
              actionIntent: 'shell.execute',
              conditions: [],
            },
          ],
        },
      }),
    },
    policyDecision: {
      create: jest.fn().mockImplementation((args) => Promise.resolve({ id: 'decision_1', ...args.data })),
      findMany: jest.fn(),
    },
    mcpRegistry: {
      findFirst: jest.fn().mockResolvedValue({ id: 'mcp-1', status: 'ACTIVE', versionHash: 'valid_hash' }),
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

  it('/policy/evaluate (POST) - Valid Agent Token, Allowed Action', () => {
    return request(app.getHttpServer())
      .post('/policy/evaluate')
      .set('x-api-key', 'test-agent-1') // Agent token
      .send({
        policySetId: 'set-1',
        actionIntent: 'read_db',
        context: {},
      })
      .expect(201)
      .then((res) => {
        expect(res.body.outcome).toBe('ALLOW');
      });
  });

  it('/policy/evaluate (POST) - Valid Agent Token, Denied Action', () => {
    return request(app.getHttpServer())
      .post('/policy/evaluate')
      .set('x-api-key', 'test-agent-1')
      .send({
        policySetId: 'set-1',
        actionIntent: 'shell.execute',
        context: {},
      })
      .expect(201)
      .then((res) => {
        expect(res.body.outcome).toBe('DENY');
      });
  });

  it('/policy/evaluate (POST) - Unauthenticated', () => {
    return request(app.getHttpServer())
      .post('/policy/evaluate')
      .send({
        policySetId: 'set-1',
        actionIntent: 'read_db',
        context: {},
      })
      .expect(401);
  });

  afterAll(async () => {
    await app.close();
  });
});
