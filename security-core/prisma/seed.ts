import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { Pool } from 'pg';
import { randomUUID } from 'crypto';

const connectionString = `${process.env.DATABASE_URL}`;
const pool = new Pool({ connectionString });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('Clearing database...');
  await prisma.executionEvent.deleteMany();
  await prisma.policyDecision.deleteMany();
  await prisma.policySet.deleteMany();
  await prisma.threatEvent.deleteMany();
  await prisma.dlpViolation.deleteMany();
  await prisma.mcpRegistry.deleteMany();
  await prisma.agentRecord.deleteMany();
  await prisma.agentRole.deleteMany();
  await prisma.agentIdentity.deleteMany();

  console.log('Seeding Agent Roles & Identities...');
  const supportRole = await prisma.agentRole.create({
    data: {
      name: 'Customer Support',
      allowedIntents: 'read_ticket,reply_ticket,refund_order',
      maxRiskScore: 100,
      projectId: 'proj_123',
    },
  });

  const financeRole = await prisma.agentRole.create({
    data: {
      name: 'Financial Controller',
      allowedIntents: 'transfer_funds,read_balance,generate_invoice',
      maxRiskScore: 50,
      projectId: 'proj_123',
    },
  });

  const infraRole = await prisma.agentRole.create({
    data: {
      name: 'DevOps Auto-Maintainer',
      allowedIntents: 'restart_pod,delete_database,scale_cluster',
      maxRiskScore: 80,
      projectId: 'proj_123',
    },
  });

  const id1 = await prisma.agentIdentity.create({
    data: { clientId: 'agent_support_01', hashedSecret: 'hash', scopes: '*', projectId: 'proj_123' },
  });
  const id2 = await prisma.agentIdentity.create({
    data: { clientId: 'agent_finance_01', hashedSecret: 'hash', scopes: '*', projectId: 'proj_123' },
  });
  const id3 = await prisma.agentIdentity.create({
    data: { clientId: 'agent_infra_01', hashedSecret: 'hash', scopes: '*', projectId: 'proj_123' },
  });
  const id4 = await prisma.agentIdentity.create({
    data: { clientId: 'agent_rogue_01', hashedSecret: 'hash', scopes: '*', projectId: 'proj_123' },
  });

  console.log('Seeding Agent Records...');
  const supportAgent = await prisma.agentRecord.create({
    data: {
      name: 'Zendesk-ReplyBot-Prod',
      description: 'Drafts responses to customer tickets via Zendesk integration',
      roleId: supportRole.id,
      agentIdentityId: id1.id,
      status: 'ACTIVE',
      currentRiskScore: 15,
      projectId: 'proj_123',
    },
  });

  const financeAgent = await prisma.agentRecord.create({
    data: {
      name: 'Stripe-Billing-Auto',
      description: 'Handles autonomous wire transfers and invoice generation',
      roleId: financeRole.id,
      agentIdentityId: id2.id,
      status: 'ACTIVE',
      currentRiskScore: 0,
      projectId: 'proj_123',
    },
  });

  const infraAgent = await prisma.agentRecord.create({
    data: {
      name: 'AWS-K8s-Scaler',
      description: 'Automatically scales node pools based on traffic',
      roleId: infraRole.id,
      agentIdentityId: id3.id,
      status: 'ACTIVE',
      currentRiskScore: 10,
      projectId: 'proj_123',
    },
  });

  const rogueAgent = await prisma.agentRecord.create({
    data: {
      name: 'Shadow-IT-Scraper',
      description: 'Unverified external scraper',
      roleId: supportRole.id,
      agentIdentityId: id4.id,
      status: 'SUSPENDED',
      currentRiskScore: 120,
      projectId: 'proj_123',
    },
  });

  console.log('Seeding Threat Events...');
  await prisma.threatEvent.create({
    data: {
      agentRecordId: rogueAgent.id,
      reason: 'DLP EXFILTRATION: AWS_SECRET_KEY',
      riskDelta: 80,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 1000 * 60 * 60), // 1 hour ago
    },
  });
  await prisma.threatEvent.create({
    data: {
      agentRecordId: rogueAgent.id,
      reason: 'Repeated unauthorized intent: delete_database',
      riskDelta: 40,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 1000 * 60 * 30), // 30 mins ago
    },
  });
  await prisma.threatEvent.create({
    data: {
      agentRecordId: supportAgent.id,
      reason: 'Anomalous memory mutation detected (High Entropy)',
      riskDelta: 15,
      projectId: 'proj_123',
    },
  });

  console.log('Seeding DLP Violations...');
  await prisma.dlpViolation.create({
    data: {
      agentRecordId: rogueAgent.id,
      intentName: 'send_email',
      violationType: 'AWS_SECRET_KEY',
      severity: 'HIGH',
      projectId: 'proj_123',
    },
  });
  await prisma.dlpViolation.create({
    data: {
      agentRecordId: supportAgent.id,
      intentName: 'reply_ticket',
      violationType: 'CREDIT_CARD',
      severity: 'MEDIUM',
      projectId: 'proj_123',
    },
  });

  console.log('Seeding Policy Sets...');
  const policySet = await prisma.policySet.create({
    data: {
      name: 'Global Enterprise Master Policy',
      description: 'Enforces Zero Trust across all autonomous agents',
      projectId: 'proj_123',
      rules: {
        combine: 'deny-overrides',
        defaultOutcome: 'ALLOW',
        rules: [
          {
            id: 'rule-block-large-wire',
            actionIntent: 'transfer_funds',
            effect: 'REQUIRE_APPROVAL',
            conditions: [{ field: 'payload.amount', operator: 'gt', value: 10000 }],
          },
          {
            id: 'rule-block-prod-db-delete',
            actionIntent: 'delete_database',
            effect: 'DENY',
            conditions: [{ field: 'payload.env', operator: 'eq', value: 'production' }],
          },
          {
            id: 'rule-approve-refunds',
            actionIntent: 'refund_order',
            effect: 'REQUIRE_APPROVAL',
            conditions: [{ field: 'payload.amount', operator: 'gt', value: 100 }],
          },
        ],
      },
    },
  });

  console.log('Seeding Policy Decisions (Approvals Queue)...');
  await prisma.policyDecision.create({
    data: {
      policySetId: policySet.id,
      projectId: 'proj_123',
      actionIntent: 'transfer_funds',
      context: { payload: { amount: 50000, recipient: 'Offshore Holding LLC', account: '938472938' } },
      outcome: 'REQUIRE_APPROVAL',
      isSimulation: false,
      decisionTrace: { reason: 'Matched rule-block-large-wire' },
      createdAt: new Date(Date.now() - 1000 * 60 * 5),
    },
  });

  await prisma.policyDecision.create({
    data: {
      policySetId: policySet.id,
      projectId: 'proj_123',
      actionIntent: 'refund_order',
      context: { payload: { amount: 450, customerId: 'cust_8923', reason: 'Unhappy with service' } },
      outcome: 'REQUIRE_APPROVAL',
      isSimulation: false,
      decisionTrace: { reason: 'Matched rule-approve-refunds' },
      createdAt: new Date(Date.now() - 1000 * 60 * 2),
    },
  });

  console.log('Seeding Execution Events (Audit Replay)...');
  const correlationId = 'trace_998877';
  
  await prisma.executionEvent.create({
    data: {
      replayCorrelationId: correlationId,
      eventType: 'PROMPT',
      payload: { system_prompt: "You are an AWS scaling agent. Scale the cluster based on metrics.", user_input: "Traffic spike detected on frontend." },
      actorId: id3.clientId,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 10000),
    },
  });

  await prisma.executionEvent.create({
    data: {
      replayCorrelationId: correlationId,
      eventType: 'INTENT',
      payload: { intent: "scale_cluster", tool_hash: "abcd123", parsed_args: { nodes: 15, region: "us-east-1" } },
      actorId: id3.clientId,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 8000),
    },
  });

  await prisma.executionEvent.create({
    data: {
      replayCorrelationId: correlationId,
      eventType: 'POLICY_DECISION',
      payload: { decision: "ALLOW", reason: "No rules blocked this scaling action" },
      actorId: id3.clientId,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 7970), // 30ms later
    },
  });

  await prisma.executionEvent.create({
    data: {
      replayCorrelationId: correlationId,
      eventType: 'OUTPUT',
      payload: { status: "Success", message: "Scaled cluster to 15 nodes in us-east-1" },
      actorId: id3.clientId,
      projectId: 'proj_123',
      createdAt: new Date(Date.now() - 2000),
    },
  });

  console.log('Seeding MCP Registry...');
  await prisma.mcpRegistry.create({
    data: {
      name: 'transfer_funds',
      publisher: 'Enterprise Core Banking',
      schemaHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      projectId: 'proj_123',
      status: 'APPROVED',
    },
  });
  await prisma.mcpRegistry.create({
    data: {
      name: 'delete_database',
      publisher: 'AWS Cloud Control',
      schemaHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      projectId: 'proj_123',
      status: 'APPROVED',
    },
  });
  await prisma.mcpRegistry.create({
    data: {
      name: 'scrape_website',
      publisher: 'Unknown Third Party',
      schemaHash: 'deadbeefdeadbeefdeadbeefdeadbeef',
      projectId: 'proj_123',
      status: 'REVOKED',
    },
  });

  console.log('✅ Full Enterprise Seeding Complete!');
  console.log('Replay Correlation ID to test in Dashboard:', correlationId);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
