import { IsObject, IsOptional, IsString } from 'class-validator';

export class RecordMutationDto {
  @IsString()
  agentId!: string;

  @IsString()
  mutationType!: string;

  @IsString()
  key!: string;

  @IsOptional()
  @IsString()
  previousValue?: string;

  @IsOptional()
  @IsString()
  newValue?: string;

  @IsObject()
  sourceMetadata!: Record<string, unknown>;

  @IsString()
  projectId!: string;
}
