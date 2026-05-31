import { AgentRuntimeClient, RuntimeEnvelope } from '../index';

export class OpenAISecureWrapper {
  constructor(
    private openaiClient: any,
    private runtimeClient: AgentRuntimeClient,
    private policySetId: string,
    private envelope: RuntimeEnvelope
  ) {}

  get chat() {
    return {
      completions: {
        create: async (params: any, options?: any) => {
          const response = await this.openaiClient.chat.completions.create(params, options);
          
          if (response.choices && response.choices[0]?.message?.tool_calls) {
            for (const toolCall of response.choices[0].message.tool_calls) {
              const action = {
                actionIntent: toolCall.function.name,
                context: { arguments: toolCall.function.arguments }
              };
              
              const decision = await this.runtimeClient.evaluateAction(this.policySetId, action, this.envelope);
              
              if (decision.outcome === 'DENY') {
                throw new Error(`Action ${toolCall.function.name} blocked by runtime policy.`);
              } else if (decision.outcome === 'REQUIRE_APPROVAL') {
                console.warn(`WARN: Action ${toolCall.function.name} requires approval. Proceeding cautiously or pausing...`);
              }

              await this.runtimeClient.recordEvent('TOOL_CALL', {
                tool: toolCall.function.name,
                args: toolCall.function.arguments,
                decision
              }, this.envelope);
            }
          }
          
          return response;
        }
      }
    };
  }
}
