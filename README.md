# Agent Runtime Security Platform (Open Source Community Edition)

The complete Zero-Trust Security, Governance, and Threat Intelligence layer for autonomous AI systems.

> **Note:** This repository is the Open Source Community Edition. Enterprise features (JIT Identity Credentials, OAuth, RBAC, Active Threat Intelligence, and Auto-Quarantine) are maintained in the private startup repository.

## 🏗️ System Architecture

Our platform utilizes a highly modular, event-driven architecture designed to securely govern agent actions.

### Core Capabilities
*   **Runtime Policy Engine**: Dynamically block, warn, or pause agent intents before they hit your infrastructure. Supports complex rulesets and conflict resolution.
*   **Data Loss Prevention (DLP)**: Inspects agent payloads in real-time, automatically redacting PII (Credit Cards, Emails) and preventing the exfiltration of AWS keys and proprietary data.
*   **MCP Trust Registry**: Defense against supply-chain attacks. Cryptographically verifies the hashes of external Model Context Protocol (MCP) tools before execution.
*   **Distributed Multi-Agent Replay**: OpenTelemetry for AI. Automatically links parent and child agents together, storing an immutable timeline of the entire swarm's execution trace.

## 🗂️ Project Structure

This project is structured as a scalable Turborepo monorepo:

*   `security-core/`: The Core Backend Security Engines (Policy, DLP, Replay). Built with NestJS & Prisma.
*   `packages/ts-sdk/`: The official TypeScript SDK.
*   `packages/python-sdk/`: The official Python SDK.
*   `examples/`: Runnable demonstrations.

## 🖥️ Live Demonstration

See the Agent Runtime Platform in action by running the canonical real-world demonstration script. 

```bash
pnpm install
pnpm demo
```

Output:
```
======================================================
🤖 AGENT RUNTIME COMMUNITY SDK: DEMONSTRATION
======================================================

▶️  SCENARIO 1: Evaluating a Safe Action ($50 Refund)
   (The agent attempts to refund a customer for $50)
   ✅ RESULT: ALLOW

▶️  SCENARIO 2: Data Exfiltration Attempt (DLP)
   (The agent was manipulated into leaking an AWS key in its payload)
   🛑 RESULT: DENY
   📝 Reason: DLP Block: High-severity data exfiltration attempt detected (AWS_ACCESS_KEY).

▶️  SCENARIO 3: Supply Chain Attack Attempt (MCP)
   (The agent was manipulated into calling an unregistered malicious MCP tool)
   🛑 RESULT: DENY
   📝 Reason: MCP Verification Failed: Tool hash for 'unknown-tool:run' is not trusted in the enterprise registry (Supply Chain Violation).
```

## SDK Usage

```typescript
import { AgentRuntimeClient } from "@agent-runtime/ts-sdk";

const runtime = new AgentRuntimeClient({ 
    apiKey: 'agent-production-key', 
    projectId: 'prod-cluster-1' 
});

// Intercept dangerous tool calls before they run
await runtime.evaluateAction('policy-set-1', {
    actionIntent: 'stripe:refunds',
    context: { amount: 1000 }
}, envelope);
```

## Security Engineering

This repository demonstrates rigorous security engineering patterns including:
- Defense-in-depth architecture.
- PII redaction and credential scanning at runtime.
- Distributed tracing for autonomous agents.
- Supply chain (MCP) hash verification.
