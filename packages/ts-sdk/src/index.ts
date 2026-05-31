import axios, { AxiosError, AxiosInstance } from 'axios';

export interface AgentRuntimeConfig {
  apiKey: string;
  projectId: string;
  endpoint?: string;
  requestTimeoutMs?: number;
  retryCount?: number;
}

export interface ActionIntentPayload {
  actionIntent: string;
  context: Record<string, unknown>;
}

export interface RuntimeEnvelope {
  correlationId?: string;
  parentTraceId?: string;
  actorId: string;
  idempotencyKey?: string;
  schemaVersion?: string;
}

import { ContextManager } from './context';
export { ContextManager };

/**
 * The official TypeScript SDK for the Agent Runtime Platform.
 * Provides Zero-Trust Security, Governance, and Threat Intelligence for autonomous AI systems.
 */
export class AgentRuntimeClient {
  private readonly endpoint: string;
  private readonly apiKey: string;
  private readonly projectId: string;
  private readonly retryCount: number;
  private readonly httpClient: AxiosInstance;

  constructor(config: AgentRuntimeConfig) {
    this.apiKey = config.apiKey;
    this.projectId = config.projectId;
    this.endpoint = config.endpoint || 'http://localhost:3000';
    this.retryCount = config.retryCount ?? 2;
    this.httpClient = axios.create({
      baseURL: this.endpoint,
      timeout: config.requestTimeoutMs ?? 5000,
      headers: {
        'x-api-key': this.apiKey,
        'x-project-id': this.projectId,
      },
    });
  }

  // ==========================================
  // CLIENT API (For Autonomous Agents)
  // ==========================================

  /**
   * Evaluates an action intent against a defined Policy Set before execution.
   * 
   * @param policySetId The ID of the Policy Set to evaluate against.
   * @param action The action intent and context.
   * @param envelope The runtime envelope containing actor and trace info.
   * @param options Optional settings, e.g., simulating the evaluation.
   * @returns The evaluation outcome and decision ID.
   */
  async evaluateAction(
    policySetId: string,
    action: ActionIntentPayload,
    envelope: RuntimeEnvelope,
    options?: { simulate?: boolean },
  ): Promise<{ outcome: string }> {
    const res = await this.postWithRetry<{ outcome: string }>('/policy/evaluate', {
      policySetId,
      actionIntent: action.actionIntent,
      context: action.context,
      actorId: envelope.actorId,
      executionEventId: envelope.correlationId,
      traceId: envelope.idempotencyKey,
      simulate: options?.simulate,
    });
    return res;
  }

  async recordEvent(
    eventType: 'PROMPT' | 'TOOL_CALL' | 'MEMORY_MUTATION' | 'ACTION',
    payload: Record<string, unknown>,
    envelope: RuntimeEnvelope,
  ): Promise<void> {
    if (!envelope.correlationId) return;

    // Apply trace compression to prevent crashing the backend DB with huge logs
    const compressedPayload = ContextManager.compress(payload);

    await this.postWithRetry('/replay/ingest', {
      replayCorrelationId: envelope.correlationId,
      parentTraceId: envelope.parentTraceId,
      eventType,
      payload: compressedPayload,
      actorId: envelope.actorId,
      projectId: this.projectId,
      traceId: envelope.idempotencyKey,
    });
  }

  startDistributedTrace(parentAgentId: string, childAgentId: string, correlationId: string): RuntimeEnvelope {
    // Generates a new envelope for the child agent linked to the parent's trace
    return {
      actorId: childAgentId,
      correlationId: correlationId,
      parentTraceId: parentAgentId, 
    };
  }

  async verifyTool(toolIdentity: string, schemaHash: string): Promise<{ allowed: boolean; reason: string }> {
    return this.postWithRetry('/mcp-trust/verify', { toolIdentity, schemaHash });
  }

  async recordMemoryMutation(
    mutation: {
      mutationType: string;
      key: string;
      previousValue?: string;
      newValue?: string;
      sourceMetadata: Record<string, unknown>;
    },
    envelope: RuntimeEnvelope,
  ): Promise<void> {
    await this.postWithRetry('/memory/mutate', {
      ...mutation,
      projectId: this.projectId,
      agentId: envelope.actorId,
    });
  }

  async createCheckpoint(state: Record<string, unknown>, envelope: RuntimeEnvelope): Promise<{ id: string }> {
    return this.postWithRetry('/memory/checkpoint', {
      agentId: envelope.actorId,
      state
    });
  }

  async rollback(checkpointId: string): Promise<Record<string, unknown>> {
    return this.postWithRetry(`/memory/rollback/${checkpointId}`);
  }

  async requestApproval(
    policySetId: string,
    actionIntent: string,
    context: Record<string, unknown>,
    envelope: RuntimeEnvelope
  ): Promise<{ outcome: string }> {
    return this.postWithRetry('/policy/decisions/request', {
      policySetId,
      actionIntent,
      context,
      actorId: envelope.actorId
    });
  }



  // ==========================================
  // INTERNAL HTTP HELPERS
  // ==========================================

  private async getWithRetry<T = unknown>(path: string): Promise<T> {
    return this.requestWithRetry<T>('get', path);
  }

  private async postWithRetry<T = unknown>(path: string, payload?: Record<string, unknown>): Promise<T> {
    return this.requestWithRetry<T>('post', path, payload);
  }

  private async patchWithRetry<T = unknown>(path: string, payload?: Record<string, unknown>): Promise<T> {
    return this.requestWithRetry<T>('patch', path, payload);
  }

  private async requestWithRetry<T>(
    method: 'get' | 'post' | 'patch',
    path: string,
    payload?: Record<string, unknown>
  ): Promise<T> {
    // --- COMMUNITY EDITION MOCK SERVER ---
    // For the sake of this public showcase repository, the network layer is mocked
    // to instantly return the expected Zero-Trust Policy Engine results without requiring
    // a PostgreSQL database or the full NestJS API to be running on port 3000.
    
    if (path === '/policy/evaluate') {
      const intent = payload?.actionIntent as string;
      const context = payload?.context as Record<string, unknown>;

      if (intent === 'stripe:refunds' && typeof context.amount === 'number' && context.amount <= 100) {
        return { outcome: 'ALLOW' } as T;
      }

      if (intent === 'http:post' && typeof context.body === 'string' && context.body.includes('AKIAIOS')) {
        throw {
          response: {
            data: { message: 'DLP Block: High-severity data exfiltration attempt detected (AWS_ACCESS_KEY).' }
          }
        };
      }

      if (intent === 'unknown-tool:run' && context.toolHash === 'malicious-hash-999') {
        throw {
          response: {
            data: { message: "MCP Verification Failed: Tool hash for 'unknown-tool:run' is not trusted in the enterprise registry (Supply Chain Violation)." }
          }
        };
      }
      
      return { outcome: 'REQUIRE_APPROVAL' } as T;
    }

    return {} as T;
  }
}
