import { ExecutionContext } from '@nestjs/common';
import { AuthGuard } from './auth.guard';

describe('AuthGuard', () => {
  const mockAgentAuth = {
    validateToken: jest.fn().mockResolvedValue(null),
  };
  let guard = new AuthGuard(mockAgentAuth as any);
  const originalApiKeys = process.env.API_KEYS;

  beforeEach(() => {
    guard = new AuthGuard(mockAgentAuth as never);
    jest.clearAllMocks();
    process.env.API_KEYS = 'dev-api-key';
  });

  afterAll(() => {
    process.env.API_KEYS = originalApiKeys;
  });

  it('accepts valid x-api-key and scoped headers', async () => {
    mockAgentAuth.validateToken.mockResolvedValueOnce({ clientId: 'agent-1', projectId: 'project-1' });

    const req: Record<string, unknown> = {
      headers: {
        'x-api-key': 'valid-agent-token',
        'x-project-id': 'project-1',
      },
    };

    const context = {
      switchToHttp: () => ({ getRequest: () => req }),
    } as ExecutionContext;

    expect(await guard.canActivate(context)).toBe(true);
    expect((req.auth as { projectId: string }).projectId).toBe('project-1');
  });

  it('rejects expired or invalid tokens', async () => {
    mockAgentAuth.validateToken.mockResolvedValueOnce(null);

    const req: Record<string, unknown> = {
      headers: {
        'x-api-key': 'expired-token',
        'x-project-id': 'project-1',
      },
    };

    const context = {
      switchToHttp: () => ({ getRequest: () => req }),
    } as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow('Invalid API credentials');
  });

  it('rejects tokens with mismatched project scope', async () => {
    mockAgentAuth.validateToken.mockResolvedValueOnce({ clientId: 'agent-1', projectId: 'project-2' });

    const req: Record<string, unknown> = {
      headers: {
        'x-api-key': 'valid-agent-token',
        'x-project-id': 'project-1', // Attempting to escalate to project-1
      },
    };

    const context = {
      switchToHttp: () => ({ getRequest: () => req }),
    } as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow('Project scope mismatch');
  });

  it('rejects missing project scope header', async () => {
    mockAgentAuth.validateToken.mockResolvedValueOnce(null);

    const req: Record<string, unknown> = {
      headers: {
        'x-api-key': 'dev-api-key',
      },
    };

    const context = {
      switchToHttp: () => ({ getRequest: () => req }),
    } as ExecutionContext;

    await expect(guard.canActivate(context)).rejects.toThrow(
      'x-project-id header is required',
    );
  });
});
