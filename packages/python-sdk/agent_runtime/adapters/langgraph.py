from typing import Any, Dict
from ..client import AgentRuntimeClient, ActionIntentPayload, RuntimeEnvelope

class ToolSecurityNode:
    """
    A LangGraph node wrapper that injects pre-execution security checks and MCP 
    (Model Context Protocol) trust verification before allowing the tool to execute.
    
    Attributes:
        tool_func (Callable): The underlying LangGraph tool function to execute if authorized.
        runtime (AgentRuntimeClient): The Agent Runtime client for policy evaluation.
        policy_set_id (str): The ID of the policy set to enforce.
        tool_identity (str): The logical identifier of the tool being executed.
        schema_hash (str): The cryptographic hash of the tool's source or schema for supply-chain validation.
    """
    def __init__(self, tool_func, runtime_client: AgentRuntimeClient, policy_set_id: str, tool_identity: str, schema_hash: str):
        """
        Initializes the ToolSecurityNode.
        
        Args:
            tool_func (Callable): The function representing the tool's execution logic.
            runtime_client (AgentRuntimeClient): The client for security interception.
            policy_set_id (str): The policy set identifier.
            tool_identity (str): The name/intent of the tool (e.g., 'stripe:refunds').
            schema_hash (str): The expected SHA256 hash of the tool implementation.
        """
        self.tool_func = tool_func
        self.runtime = runtime_client
        self.policy_set_id = policy_set_id
        self.tool_identity = tool_identity
        self.schema_hash = schema_hash

    def __call__(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the LangGraph node logic, intercepted by Zero-Trust checks.
        
        Args:
            state (Dict[str, Any]): The current state dictionary passed down by the LangGraph executor.
            
        Returns:
            Dict[str, Any]: The mutated state or execution result after the tool runs.
            
        Raises:
            SecurityError: If the tool hash fails verification in the Trust Registry (Supply Chain Attack).
            PermissionError: If the runtime policy engine explicitly denies the tool call.
        """
        # 1. Verify Tool Trust (MCP Supply Chain Defense)
        trust_res = self.runtime.verify_tool(self.tool_identity, self.schema_hash)
        if not trust_res.get("allowed", False):
            raise SecurityError(f"Tool {self.tool_identity} failed trust verification: {trust_res.get('reason')}")

        # 2. Evaluate Runtime Policy
        # Assuming the state dictionary contains an actor_id and the proposed tool_args.
        actor_id = state.get("actor_id", "langgraph-agent")
        envelope = RuntimeEnvelope(actor_id=actor_id)
        action = ActionIntentPayload(
            action_intent=self.tool_identity, 
            context={"args": state.get("tool_args", {})}
        )
        
        # Consult the Policy Engine
        decision = self.runtime.evaluate_action(self.policy_set_id, action, envelope)
        if decision.get("outcome") == "DENY":
            raise PermissionError(f"Tool {self.tool_identity} execution blocked by policy.")

        # 3. Execute underlying tool function
        result = self.tool_func(state)

        # 4. Record Execution Event (Audit Logging & Timeline Replay)
        self.runtime.record_event("ACTION", {
            "tool": self.tool_identity,
            "result": result
        }, envelope)

        return result

class SecurityError(Exception):
    """Raised when an MCP tool fails cryptographic trust verification."""
    pass
