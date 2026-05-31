import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { App } from 'supertest/types';
import { AppModule } from './../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

describe('IdentityController (e2e)', () => {
  let app: INestApplication<App>;

  const mockPrisma = {
    agentToken: {
      findUnique: jest.fn().mockImplementation(({ where }) => {
        if (where.token === 'test-key') {
          return Promise.resolve({
            token: 'test-key',
            expiresAt: new Date(Date.now() + 3600000),
            agentIdentity: {
              clientId: 'test-key',
              projectId: 'test-project-1',
              scopes: 'all',
            },
          });
        }
        return Promise.resolve(null);
      }),
    },
    agentIdentity: {
      findUnique: jest.fn().mockResolvedValue({
        clientId: 'test-key',
        projectId: 'test-project-1',
      }),
    },
    agentRecord: {
      create: jest.fn().mockImplementation((args) => Promise.resolve({ id: 'new_agent_1', ...args.data })),
      findUnique: jest.fn().mockResolvedValue({
        id: 'agent_1',
        projectId: 'test-project-1',
        status: 'ACTIVE',
        role: { allowedIntents: '*' }
      }),
    },
    agentJitToken: {
      create: jest.fn().mockImplementation((args) => Promise.resolve({ id: 'token_1', ...args.data })),
      findUnique: jest.fn().mockResolvedValue({
        token: 'mocked_ephemeral_token',
        tool: 'stripe',
      }),
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

  it('/identity/register (POST) - should register a new agent identity', () => {
    return request(app.getHttpServer())
      .post('/identity/register')
      .set('x-api-key', 'test-key') 
      .set('x-project-id', 'test-project-1')
      .send({
        name: 'E2E Test Agent',
        description: 'Test Description',
      })
      .expect(201)
      .then((res) => {
        expect(res.body).toHaveProperty('id', 'new_agent_1');
        expect(res.body.name).toBe('E2E Test Agent');
        expect(res.body.status).toBe('ACTIVE');
      });
  });

  it('/identity/access (POST) - should dispense a JIT token', () => {
    return request(app.getHttpServer())
      .post('/identity/access')
      .set('x-api-key', 'test-key')
      .set('x-project-id', 'test-project-1')
      .send({
        actorId: 'agent_1',
        tool: 'stripe',
        scope: 'refunds'
      })
      .expect(201)
      .then((res) => {
        expect(res.body).toHaveProperty('token');
        expect(res.body).toHaveProperty('expiresAt');
        expect(typeof res.body.token).toBe('string');
      });
  });

  afterAll(async () => {
    await app.close();
  });
});
