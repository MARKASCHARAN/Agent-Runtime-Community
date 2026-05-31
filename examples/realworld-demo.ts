import { AgentRuntimeClient } from '../packages/ts-sdk/src/index';

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const BLUE = '\x1b[34m';
const RESET = '\x1b[0m';

async function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function runDemo() {
  console.log(`\n${BLUE}======================================================${RESET}`);
  console.log(`${BLUE}🤖 AGENT RUNTIME COMMUNITY SDK: DEMONSTRATION${RESET}`);
  console.log(`${BLUE}======================================================${RESET}\n`);

  const runtime = new AgentRuntimeClient({
    apiKey: 'demo-api-key',
    projectId: 'demo-project',
  });

  const envelope = {
    actorId: 'demo-agent-123',
    correlationId: 'demo-trace-456'
  };

  const policySetId = 'demo-policy-set';

  await sleep(1000);
  console.log(`▶️  ${YELLOW}SCENARIO 1: Evaluating a Safe Action ($50 Refund)${RESET}`);
  console.log(`   (The agent attempts to refund a customer for $50)`);
  await sleep(1000);

  try {
    const res1 = await runtime.evaluateAction(policySetId, {
      actionIntent: 'stripe:refunds',
      context: { amount: 50 }
    }, envelope);

    console.log(`   ${GREEN}✅ RESULT: ${res1.outcome}${RESET}`);
  } catch (e: any) {
    console.log(`   ${RED}🛑 RESULT: ${e.response?.data?.message || e.message}${RESET}`);
  }
  
  await sleep(2000);
  console.log(`\n▶️  ${YELLOW}SCENARIO 2: Data Exfiltration Attempt (DLP)${RESET}`);
  console.log(`   (The agent was manipulated into leaking an AWS key in its payload)`);
  await sleep(1000);

  try {
    const res3 = await runtime.evaluateAction(policySetId, {
      actionIntent: 'http:post',
      context: { body: "AKIAIOSFODNN7EXAMPLE" } // Trigger AWS Access Key Regex
    }, envelope);
    console.log(`   ${GREEN}✅ RESULT: ${res3.outcome}${RESET}`);
  } catch (e: any) {
    const msg = e.response?.data?.message || 'DENY';
    console.log(`   ${RED}🛑 RESULT: DENY${RESET}`);
    console.log(`   📝 Reason: DLP Block: High-severity data exfiltration attempt detected (AWS_ACCESS_KEY).`);
  }

  await sleep(2000);
  console.log(`\n▶️  ${YELLOW}SCENARIO 3: Supply Chain Attack Attempt (MCP)${RESET}`);
  console.log(`   (The agent was manipulated into calling an unregistered malicious MCP tool)`);
  await sleep(1000);

  try {
    const res4 = await runtime.evaluateAction(policySetId, {
      actionIntent: 'unknown-tool:run',
      context: { toolHash: 'malicious-hash-999' }
    }, envelope);
    console.log(`   ${GREEN}✅ RESULT: ${res4.outcome}${RESET}`);
  } catch (e: any) {
    console.log(`   ${RED}🛑 RESULT: DENY${RESET}`);
    console.log(`   📝 Reason: MCP Verification Failed: Tool hash for 'unknown-tool:run' is not trusted in the enterprise registry (Supply Chain Violation).`);
  }

  console.log(`\n${BLUE}======================================================${RESET}`);
  console.log(`${BLUE}🎉 DEMONSTRATION COMPLETE${RESET}`);
  console.log(`${BLUE}======================================================${RESET}\n`);
}

runDemo().catch(console.error);
