import pytest
import httpx
from agent_runtime.client import AgentRuntimeClient, AgentRuntimeConfig, ActionIntentPayload, RuntimeEnvelope

@pytest.fixture
def config():
    return AgentRuntimeConfig(
        api_key="test-api-key",
        project_id="test-project",
        endpoint="http://test-endpoint"
    )

@pytest.fixture
def client(config):
    return AgentRuntimeClient(config)

@pytest.fixture
def envelope():
    return RuntimeEnvelope(actor_id="agent-123", correlation_id="corr-456", idempotency_key="idemp-789")

def test_client_initialization(client, config):
    assert client.config == config
    assert client.headers["x-api-key"] == "test-api-key"
    assert client.headers["x-project-id"] == "test-project"

def test_evaluate_action_success(client, envelope, httpx_mock):
    httpx_mock.add_response(json={"outcome": "ALLOW"})
    
    action = ActionIntentPayload(action_intent="read_data", context={"key": "value"})
    response = client.evaluate_action(policy_set_id="policy-1", action=action, envelope=envelope)
    
    assert response == {"outcome": "ALLOW"}
    request = httpx_mock.get_request()
    assert request is not None
    assert str(request.url) == "http://test-endpoint/policy/evaluate"
    assert request.headers["x-api-key"] == "test-api-key"

def test_evaluate_action_retry_on_500(client, envelope, httpx_mock):
    httpx_mock.add_response(status_code=500)
    httpx_mock.add_response(json={"outcome": "ALLOW"})
    
    action = ActionIntentPayload(action_intent="read_data", context={})
    response = client.evaluate_action(policy_set_id="policy-1", action=action, envelope=envelope)
    
    assert response == {"outcome": "ALLOW"}
    assert len(httpx_mock.get_requests()) == 2

def test_evaluate_action_no_retry_on_400(client, envelope, httpx_mock):
    httpx_mock.add_response(status_code=400, json={"error": "bad request"})
    
    action = ActionIntentPayload(action_intent="read_data", context={})
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.evaluate_action(policy_set_id="policy-1", action=action, envelope=envelope)
    
    assert exc_info.value.response.status_code == 400
    assert len(httpx_mock.get_requests()) == 1

def test_record_event_success(client, envelope, httpx_mock):
    httpx_mock.add_response(json={"success": True})
    
    client.record_event(event_type="test_event", payload={"data": "test"}, envelope=envelope)
    
    request = httpx_mock.get_request()
    assert request is not None
    assert str(request.url) == "http://test-endpoint/replay/ingest"

def test_record_event_skips_without_correlation_id(client, httpx_mock):
    env_no_corr = RuntimeEnvelope(actor_id="agent-123")
    client.record_event(event_type="test_event", payload={"data": "test"}, envelope=env_no_corr)
    
    assert len(httpx_mock.get_requests()) == 0

def test_verify_tool(client, httpx_mock):
    httpx_mock.add_response(json={"verified": True})
    
    response = client.verify_tool(tool_identity="tool-1", schema_hash="hash123")
    assert response == {"verified": True}
    
    request = httpx_mock.get_request()
    assert request is not None
    assert str(request.url) == "http://test-endpoint/mcp-trust/verify"

def test_record_memory_mutation(client, envelope, httpx_mock):
    httpx_mock.add_response(json={"success": True})
    
    client.record_memory_mutation(
        mutation_type="create",
        key="key1",
        source_metadata={"meta": "data"},
        new_value="val1",
        envelope=envelope
    )
    
    request = httpx_mock.get_request()
    assert request is not None
    assert str(request.url) == "http://test-endpoint/memory/mutate"
