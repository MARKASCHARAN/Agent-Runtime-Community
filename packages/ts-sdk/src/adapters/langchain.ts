import { AgentRuntimeClient, RuntimeEnvelope } from '../index';

export class LangChainSecureTool {
  constructor(
    private underlyingTool: any, // E.g., a LangChain Tool instance
    private runtimeClient: AgentRuntimeClient,
    private policySetId: string,
    private toolIdentity: string,
    private schemaHash: string
  ) {}

  async call(arg: any, envelope: RuntimeEnvelope) {
    // 1. Verify Trust
    const trustRes = await this.runtimeClient.verifyTool(this.toolIdentity, this.schemaHash);
    if (!trustRes.allowed) {
      throw new Error(`Tool ${this.toolIdentity} failed trust verification: ${trustRes.reason}`);
    }

    // 2. Evaluate Policy
    const action = {
      actionIntent: this.toolIdentity,
      context: { args: arg }
    };
    
    const decision = await this.runtimeClient.evaluateAction(this.policySetId, action, envelope);
    if (decision.outcome === 'DENY') {
      throw new Error(`Tool ${this.toolIdentity} execution blocked by policy.`);
    }

    // 3. Execute Tool
    const result = await this.underlyingTool.call(arg);

    // 4. Record Event
    await this.runtimeClient.recordEvent('ACTION', {
      tool: this.toolIdentity,
      result
    }, envelope);

    return result;
  }
}
