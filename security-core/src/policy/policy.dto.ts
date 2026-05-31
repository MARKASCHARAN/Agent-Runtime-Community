import { Type } from 'class-transformer';
import {
  IsArray,
  IsBoolean,
  IsEnum,
  IsObject,
  IsOptional,
  IsString,
  ValidateNested,
} from 'class-validator';

export const POLICY_OUTCOMES = [
  'ALLOW',
  'DENY',
  'WARN',
  'REQUIRE_APPROVAL',
] as const;
export type PolicyOutcome = (typeof POLICY_OUTCOMES)[number];

const RULE_OPERATORS = [
  'eq',
  'neq',
  'in',
  'not_in',
  'contains',
  'gt',
  'gte',
  'lt',
  'lte',
  'exists',
  'regex',
] as const;

type RuleOperator = (typeof RULE_OPERATORS)[number];

export class RuleConditionDto {
  @IsString()
  field!: string;

  @IsEnum(RULE_OPERATORS)
  operator!: RuleOperator;

  @IsOptional()
  value?: unknown;
}

export class PolicyRuleDto {
  @IsOptional()
  @IsString()
  id?: string;

  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @IsOptional()
  @IsString()
  actionIntent?: string;

  @IsEnum(POLICY_OUTCOMES)
  effect!: PolicyOutcome;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => RuleConditionDto)
  conditions!: RuleConditionDto[];
}

export class PolicyRulesDto {
  @IsOptional()
  @IsEnum(['first-match', 'deny-overrides', 'approval-overrides'])
  combine?: 'first-match' | 'deny-overrides' | 'approval-overrides';

  @IsOptional()
  @IsEnum(POLICY_OUTCOMES)
  defaultOutcome?: PolicyOutcome;

  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PolicyRuleDto)
  rules!: PolicyRuleDto[];
}

export class CreatePolicySetDto {
  @IsString()
  name!: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsString()
  projectId!: string;

  @ValidateNested()
  @Type(() => PolicyRulesDto)
  rules!: PolicyRulesDto;
}

export class EvaluateActionDto {
  @IsString()
  policySetId!: string;

  @IsString()
  actionIntent!: string;

  @IsObject()
  context!: Record<string, unknown>;

  @IsOptional()
  @IsString()
  actorId?: string;

  @IsOptional()
  @IsString()
  executionEventId?: string;

  @IsOptional()
  @IsBoolean()
  simulate?: boolean;

  @IsOptional()
  @IsString()
  traceId?: string;
}

export class ResolveApprovalDto {
  @IsEnum(['ALLOW', 'DENY'])
  resolution!: 'ALLOW' | 'DENY';
}
