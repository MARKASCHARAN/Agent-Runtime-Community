import { Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { EventsGateway } from '../events/events.gateway';
import {
  CreatePolicySetDto,
  EvaluateActionDto,
  PolicyOutcome,
  PolicyRuleDto,
  PolicyRulesDto,
} from './policy.dto';
import { assertProjectScope } from '../common/project-scope';

interface RuleConditionTrace {
  field: string;
  operator: string;
  expected: unknown;
  actual: unknown;
  matched: boolean;
}

export interface RuleTrace {
  id: string;
  effect: PolicyOutcome;
  matched: boolean;
  conditions: RuleConditionTrace[];
}

interface EvaluationResult {
  outcome: PolicyOutcome;
  matchedRuleIds: string[];
  trace: RuleTrace[];
}

import { PrivacyService } from '../privacy/privacy.service';
import { McpTrustService } from '../mcp-trust/mcp-trust.service';

/**
 * The Core Zero-Trust Policy Engine.
 * Evaluates autonomous agent actions against configured Policy Sets, Role-Based Access Controls (RBAC),
 * Data Loss Prevention (DLP) rules, and MCP Supply Chain Trust before permitting execution.
 */
@Injectable()
export class PolicyService {
  constructor(
    private prisma: PrismaService,
    private eventsGateway: EventsGateway,
    private privacy: PrivacyService,
    private mcpTrust: McpTrustService,
  ) {}

  async createPolicySet(data: CreatePolicySetDto) {
    const latestPolicy = await this.prisma.policySet.findFirst({
      where: { projectId: data.projectId, name: data.name },
      orderBy: { version: 'desc' },
    });

    return this.prisma.policySet.create({
      data: {
        name: data.name,
        description: data.description,
        projectId: data.projectId,
        rules: data.rules as unknown as Prisma.InputJsonValue,
        version: (latestPolicy?.version ?? 0) + 1,
      },
    });
  }

  async getPolicySets(projectId: string) {
    return this.prisma.policySet.findMany({
      where: { projectId },
      orderBy: { updatedAt: 'desc' },
    });
  }

  async getPolicySet(id: string, scopedProjectId: string) {
    const policy = await this.prisma.policySet.findUnique({
      where: { id },
    });
    if (!policy) throw new NotFoundException('PolicySet not found');
    assertProjectScope(scopedProjectId, policy.projectId);
    return policy;
  }

  /**
   * The primary Zero-Trust evaluation method.
   * Intercepts an agent's proposed action and runs it through a gauntlet of security checks:
   * 1. DLP Scan (Data Exfiltration Prevention)
   * 2. MCP Trust Verification (Supply Chain Attacks)
   * 3. Kill Switch & RBAC Checks
   * 4. Dynamic Policy Rules Engine
   * 
   * @param data The evaluation payload including the intent, context, and actor.
   * @param scopedProjectId The active project context to prevent cross-tenant evaluation.
   * @returns A PolicyDecision object containing the ALLOW, DENY, or REQUIRE_APPROVAL outcome.
   */
  async evaluateAction(data: EvaluateActionDto, scopedProjectId: string) {
    const policySet = await this.prisma.policySet.findUnique({
      where: { id: data.policySetId },
    });

    if (!policySet) {
      throw new NotFoundException('PolicySet not found');
    }

    assertProjectScope(scopedProjectId, policySet.projectId);

    // Phase 2: Agent Governance (Kill Switch & RBAC)
    let preEvaluationOutcome: PolicyOutcome | null = null;
    let preEvaluationReason = '';

    // Phase 5: Active Data Loss Prevention (DLP)
    const dlpViolations = this.privacy.scanForViolations(data.context);
    const highSeverityViolation = dlpViolations.find(
      (v) => v.severity === 'HIGH',
    );

    if (highSeverityViolation) {
      preEvaluationOutcome = 'DENY';
      preEvaluationReason = `DLP Block: High-severity data exfiltration attempt detected (${highSeverityViolation.type}).`;
    }

    // Phase 4: Zero Trust MCP Verification
    if (
      !preEvaluationOutcome &&
      data.context &&
      typeof data.context.toolHash === 'string'
    ) {
      const isTrusted = await this.mcpTrust.verifyTool(
        data.actionIntent,
        data.context.toolHash,
        scopedProjectId,
      );
      if (!isTrusted) {
        preEvaluationOutcome = 'DENY';
        preEvaluationReason = `MCP Verification Failed: Tool hash for '${data.actionIntent}' is not trusted in the enterprise registry (Supply Chain Violation).`;
      }
    }



    const normalizedRules = policySet.rules as unknown as PolicyRulesDto;
    const traceId = data.traceId ?? randomUUID();

    let evaluation: EvaluationResult;
    if (preEvaluationOutcome) {
      evaluation = {
        outcome: preEvaluationOutcome,
        matchedRuleIds: ['intrinsic-rbac'],
        trace: [
          {
            id: 'intrinsic-rbac',
            effect: preEvaluationOutcome,
            matched: true,
            conditions: [
              {
                field: 'agent.role',
                operator: 'intrinsic',
                expected: 'allowed',
                actual: preEvaluationReason,
                matched: false,
              },
            ],
          },
        ],
      };
    } else {
      evaluation = this.evaluateRules(
        data.actionIntent,
        data.context,
        normalizedRules,
      );
    }

    const decisionTrace = {
      combine: normalizedRules.combine ?? 'first-match',
      defaultOutcome: normalizedRules.defaultOutcome ?? 'ALLOW',
      matchedRuleIds: evaluation.matchedRuleIds,
      trace: evaluation.trace,
      traceId,
      simulated: Boolean(data.simulate),
      evaluatedAt: new Date().toISOString(),
    };

    if (data.simulate) {
      return {
        simulated: true,
        policySetId: data.policySetId,
        projectId: policySet.projectId,
        actionIntent: data.actionIntent,
        outcome: evaluation.outcome,
        decisionTrace,
      };
    }

    const decision = await this.prisma.policyDecision.create({
      data: {
        policySetId: data.policySetId,
        projectId: policySet.projectId,
        actionIntent: data.actionIntent,
        context: this.privacy.redact(data.context) as Prisma.InputJsonValue,
        outcome: evaluation.outcome,
        decisionTrace: decisionTrace as unknown as Prisma.InputJsonValue,
        traceId,
        isSimulation: false,
        executionEventId: data.executionEventId,
      },
    });

    if (decision.outcome === 'REQUIRE_APPROVAL') {
      this.eventsGateway.emitApprovalRequired(decision);
    }

    this.eventsGateway.emitPolicyIntervention(decision);

    return decision;
  }

  async getDecisions(policySetId: string, scopedProjectId: string) {
    const policySet = await this.getPolicySet(policySetId, scopedProjectId);
    return this.prisma.policyDecision.findMany({
      where: { policySetId, projectId: policySet.projectId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async requestApproval(data: { actionIntent: string, context: any, projectId: string, actorId: string, policySetId: string }) {
    const traceId = randomUUID();
    const decision = await this.prisma.policyDecision.create({
      data: {
        policySetId: data.policySetId,
        projectId: data.projectId,
        actionIntent: data.actionIntent,
        context: this.privacy.redact(data.context) as Prisma.InputJsonValue,
        outcome: 'REQUIRE_APPROVAL',
        decisionTrace: { reason: 'Explicit manual approval requested by Agent SDK' } as unknown as Prisma.InputJsonValue,
        traceId,
        isSimulation: false,
      },
    });

    this.eventsGateway.emitApprovalRequired(decision);
    this.eventsGateway.emitPolicyIntervention(decision);

    return decision;
  }

  async getPendingApprovals(policySetId: string, scopedProjectId: string) {
    const policySet = await this.getPolicySet(policySetId, scopedProjectId);
    return this.prisma.policyDecision.findMany({
      where: {
        policySetId,
        projectId: policySet.projectId,
        outcome: 'REQUIRE_APPROVAL',
      },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Resolves a pending Human-in-the-loop approval.
   * Modifies the pending REQUIRE_APPROVAL decision into either ALLOW or DENY based on human input.
   * 
   * @param decisionId The ID of the pending decision.
   * @param resolution The final verdict ('ALLOW' or 'DENY').
   * @param actorId The ID of the admin resolving the decision.
   * @param scopedProjectId The project scope for security validation.
   */
  async resolveApproval(
    decisionId: string,
    resolution: 'ALLOW' | 'DENY',
    actorId: string,
    scopedProjectId: string,
  ) {
    const decision = await this.prisma.policyDecision.findUnique({
      where: { id: decisionId },
    });

    if (!decision) {
      throw new NotFoundException('Policy decision not found');
    }

    assertProjectScope(scopedProjectId, decision.projectId);

    return this.prisma.policyDecision.update({
      where: { id: decisionId },
      data: {
        outcome: resolution,
        resolvedBy: actorId,
        resolvedAt: new Date(),
      },
    });
  }

  private evaluateRules(
    actionIntent: string,
    context: Record<string, unknown>,
    policyRules: PolicyRulesDto,
  ): EvaluationResult {
    const rules = policyRules?.rules ?? [];
    const activeRules = rules
      .filter((rule) => rule.enabled !== false)
      .filter(
        (rule) => !rule.actionIntent || rule.actionIntent === actionIntent,
      );

    const trace: RuleTrace[] = [];
    const matchedRules: PolicyRuleDto[] = [];

    for (const [index, rule] of activeRules.entries()) {
      const conditionTrace = rule.conditions.map((condition) => {
        const actual = this.getPathValue(context, condition.field);
        const matched = this.matchesCondition(
          actual,
          condition.operator,
          condition.value,
        );
        return {
          field: condition.field,
          operator: condition.operator,
          expected: condition.value,
          actual,
          matched,
        };
      });

      const matched = conditionTrace.every((condition) => condition.matched);
      if (matched) {
        matchedRules.push(rule);
      }

      trace.push({
        id: rule.id ?? `${rule.effect.toLowerCase()}-${index + 1}`,
        effect: rule.effect,
        matched,
        conditions: conditionTrace,
      });
    }

    const matchedRuleIds = trace
      .filter((entry) => entry.matched)
      .map((entry) => entry.id);
    const combine = policyRules.combine ?? 'first-match';
    const defaultOutcome = policyRules.defaultOutcome ?? 'ALLOW';

    let outcome: PolicyOutcome = defaultOutcome;

    if (combine === 'deny-overrides') {
      if (matchedRules.some((rule) => rule.effect === 'DENY')) outcome = 'DENY';
      else if (matchedRules.some((rule) => rule.effect === 'REQUIRE_APPROVAL'))
        outcome = 'REQUIRE_APPROVAL';
      else if (matchedRules.some((rule) => rule.effect === 'WARN'))
        outcome = 'WARN';
      else if (matchedRules.some((rule) => rule.effect === 'ALLOW'))
        outcome = 'ALLOW';
    } else if (combine === 'approval-overrides') {
      if (matchedRules.some((rule) => rule.effect === 'REQUIRE_APPROVAL'))
        outcome = 'REQUIRE_APPROVAL';
      else if (matchedRules.some((rule) => rule.effect === 'DENY'))
        outcome = 'DENY';
      else if (matchedRules.some((rule) => rule.effect === 'WARN'))
        outcome = 'WARN';
      else if (matchedRules.some((rule) => rule.effect === 'ALLOW'))
        outcome = 'ALLOW';
    } else {
      const firstMatch = matchedRules.at(0);
      if (firstMatch) {
        outcome = firstMatch.effect;
      }
    }

    return { outcome, matchedRuleIds, trace };
  }

  private getPathValue(source: Record<string, unknown>, path: string): unknown {
    return path.split('.').reduce<unknown>((acc, key) => {
      if (acc && typeof acc === 'object' && key in acc) {
        return (acc as Record<string, unknown>)[key];
      }
      return undefined;
    }, source);
  }

  private matchesCondition(
    actual: unknown,
    operator: string,
    expected: unknown,
  ): boolean {
    switch (operator) {
      case 'eq':
        return actual === expected;
      case 'neq':
        return actual !== expected;
      case 'in':
        return Array.isArray(expected) ? expected.includes(actual) : false;
      case 'not_in':
        return Array.isArray(expected) ? !expected.includes(actual) : false;
      case 'contains':
        return Array.isArray(actual)
          ? actual.includes(expected)
          : typeof actual === 'string' && typeof expected === 'string'
            ? actual.includes(expected)
            : false;
      case 'gt':
        return (
          typeof actual === 'number' &&
          typeof expected === 'number' &&
          actual > expected
        );
      case 'gte':
        return (
          typeof actual === 'number' &&
          typeof expected === 'number' &&
          actual >= expected
        );
      case 'lt':
        return (
          typeof actual === 'number' &&
          typeof expected === 'number' &&
          actual < expected
        );
      case 'lte':
        return (
          typeof actual === 'number' &&
          typeof expected === 'number' &&
          actual <= expected
        );
      case 'exists':
        return expected ? actual !== undefined : actual === undefined;
      case 'regex':
        return typeof actual === 'string' && typeof expected === 'string'
          ? new RegExp(expected).test(actual)
          : false;
      default:
        return false;
    }
  }
}
