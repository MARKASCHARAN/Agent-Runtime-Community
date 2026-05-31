import { AgentRuntimeClient, ActionIntentPayload, RuntimeEnvelope } from './index';
import axios from 'axios';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;
mockedAxios.create.mockReturnValue(mockedAxios as any);

describe('AgentRuntimeClient', () => {
  let client: AgentRuntimeClient;
  const mockConfig = {
    projectId: 'proj_123',
    apiKey: 'secret_key',
    baseUrl: 'http://localhost:3000',
  };

  beforeEach(() => {
    client = new AgentRuntimeClient(mockConfig);
    jest.clearAllMocks();
  });

  it('should initialize with correct configuration', () => {
    expect(client).toBeInstanceOf(AgentRuntimeClient);
  });

  describe('evaluateAction', () => {
    it('should call the evaluate endpoint with correct payload', async () => {
      const mockResponse = { data: { outcome: 'ALLOW' } };
      mockedAxios.request.mockResolvedValueOnce(mockResponse);

      const action: ActionIntentPayload = {
        actionIntent: 'transfer_funds',
        context: { toolHash: 'abc123hash' },
      };
      const envelope: RuntimeEnvelope = {
        actorId: 'agent_01',
      };

      const result = await client.evaluateAction('policy_1', action, envelope);

      expect(result).toEqual({ outcome: 'ALLOW' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/policy/evaluate',
        data: {
          policySetId: 'policy_1',
          actionIntent: 'transfer_funds',
          context: { toolHash: 'abc123hash' },
          actorId: 'agent_01',
          executionEventId: undefined,
          simulate: undefined,
          traceId: undefined,
        }
      }));
    });

    it('should propagate errors from the API', async () => {
      mockedAxios.request.mockRejectedValueOnce(new Error('Network error'));
      await expect(client.evaluateAction('test', { actionIntent: 'test', context: {} }, { actorId: '1' }))
        .rejects
        .toThrow('Network error');
    });
  });

  describe('V3 Enterprise Resilience Methods', () => {
    it('should verify prompt', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { safe: true } });
      const result = await client.verifyPrompt('hello world');
      expect(result).toEqual({ safe: true });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/threat-intel/verify-prompt',
        data: { prompt: 'hello world' }
      }));
    });

    it('should create checkpoint', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { id: 'chk_1' } });
      const result = await client.createCheckpoint({ foo: 'bar' }, { actorId: 'agent_1' });
      expect(result).toEqual({ id: 'chk_1' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/memory/checkpoint',
        data: { agentId: 'agent_1', state: { foo: 'bar' } }
      }));
    });

    it('should rollback', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { foo: 'bar' } });
      const result = await client.rollback('chk_1');
      expect(result).toEqual({ foo: 'bar' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/memory/rollback/chk_1',
      }));
    });

    it('should request approval', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { outcome: 'REQUIRE_APPROVAL' } });
      const result = await client.requestApproval('policy_1', 'wire_transfer', { amount: 100 }, { actorId: 'agent_1' });
      expect(result).toEqual({ outcome: 'REQUIRE_APPROVAL' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/policy/decisions/request',
        data: { policySetId: 'policy_1', actionIntent: 'wire_transfer', context: { amount: 100 }, actorId: 'agent_1' }
      }));
    });

    it('should create distributed trace envelope', () => {
      const envelope = client.startDistributedTrace('parent_1', 'child_1', 'corr_1');
      expect(envelope).toEqual({
        actorId: 'child_1',
        correlationId: 'corr_1',
        parentTraceId: 'parent_1',
      });
    });

    it('should request JIT access token', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { token: 'ephemeral_xyz', expiresAt: '2026-05-31T00:00:00Z' } });
      const result = await client.requestAccess('stripe', 'refunds', { actorId: 'agent_1' });
      expect(result).toEqual({ token: 'ephemeral_xyz', expiresAt: '2026-05-31T00:00:00Z' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/identity/access',
        data: { tool: 'stripe', scope: 'refunds', actorId: 'agent_1' }
      }));
    });
  });

  describe('Admin API Methods', () => {
    it('should fetch agents via getAgents', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: [{ id: 'agent_1' }] });
      const result = await client.getAgents();
      expect(result).toEqual([{ id: 'agent_1' }]);
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'get',
        url: '/inventory/agents'
      }));
    });

    it('should suspend agent via suspendAgent', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: {} });
      await client.suspendAgent('agent_123');
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'patch',
        url: '/inventory/agents/agent_123/suspend'
      }));
    });

    it('should register identity via registerIdentity', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: { id: 'new_agent_1' } });
      const result = await client.registerIdentity({ name: 'Finance Agent' });
      expect(result).toEqual({ id: 'new_agent_1' });
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/identity/register',
        data: { name: 'Finance Agent' }
      }));
    });

    it('should resolve approvals', async () => {
      mockedAxios.request.mockResolvedValueOnce({ data: {} });
      await client.resolveApproval('decision_abc', 'APPROVE');
      expect(mockedAxios.request).toHaveBeenCalledWith(expect.objectContaining({
        method: 'post',
        url: '/policy/decisions/decision_abc/resolve',
        data: { action: 'APPROVE' }
      }));
    });
  });

});

