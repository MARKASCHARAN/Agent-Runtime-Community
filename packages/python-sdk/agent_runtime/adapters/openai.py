from ..client import AgentRuntimeClient, ActionIntentPayload, RuntimeEnvelope

class OpenAISecureWrapper:
    """
    Wraps an OpenAI client to intercept and evaluate tool calls before they are sent back
    to the user's execution loop. This acts as a robust Zero-Trust gateway for LLM outputs.
    
    Attributes:
        runtime (AgentRuntimeClient): The configured Agent Runtime client.
        policy_set_id (str): The ID of the policy set to evaluate intents against.
        envelope (RuntimeEnvelope): The current execution envelope for telemetry.
    """
    def __init__(self, openai_client, runtime_client: AgentRuntimeClient, policy_set_id: str, envelope: RuntimeEnvelope):
        """
        Initializes the wrapper around the OpenAI client.
        
        Args:
            openai_client: An instance of `openai.OpenAI` or `openai.AsyncOpenAI`.
            runtime_client (AgentRuntimeClient): The client used to communicate with the Agent Runtime backend.
            policy_set_id (str): The ID of the policy set used for this execution.
            envelope (RuntimeEnvelope): The distributed trace envelope representing this execution block.
        """
        self._client = openai_client
        self.runtime = runtime_client
        self.policy_set_id = policy_set_id
        self.envelope = envelope

    @property
    def chat(self):
        """
        Exposes the inner OpenAI `chat` attribute, wrapping `completions.create` to inject security checks.
        """
        class ChatWrapper:
            def __init__(self, chat, outer):
                self._chat = chat
                self.outer = outer

            @property
            def completions(self):
                class CompletionsWrapper:
                    def __init__(self, completions, outer):
                        self._completions = completions
                        self.outer = outer

                    def create(self, *args, **kwargs):
                        # 1. Call OpenAI to generate the response
                        response = self._completions.create(*args, **kwargs)
                        
                        # 2. Intercept and inspect generated tool calls
                        if response.choices and response.choices[0].message.tool_calls:
                            for tool_call in response.choices[0].message.tool_calls:
                                # Prepare the pre-execution security check payload
                                action = ActionIntentPayload(
                                    action_intent=tool_call.function.name,
                                    context={"arguments": tool_call.function.arguments}
                                )
                                
                                # Send the intent to the Zero-Trust Policy Engine
                                decision = self.outer.runtime.evaluate_action(self.outer.policy_set_id, action, self.outer.envelope)
                                
                                # Process the decision outcome (DENY, REQUIRE_APPROVAL, ALLOW)
                                if decision.get("outcome") == "DENY":
                                    raise PermissionError(f"Action {tool_call.function.name} blocked by runtime policy.")
                                elif decision.get("outcome") == "REQUIRE_APPROVAL":
                                    print(f"WARN: Action {tool_call.function.name} requires manual approval. Halting autonomous loop...")
                                
                                # Asynchronously log the tool call and decision for the Replay & Audit engine
                                self.outer.runtime.record_event("TOOL_CALL", {
                                    "tool": tool_call.function.name,
                                    "args": tool_call.function.arguments,
                                    "decision": decision
                                }, self.outer.envelope)

                        return response

                return CompletionsWrapper(self._chat.completions, self.outer)
        
        return ChatWrapper(self._client.chat, self)
