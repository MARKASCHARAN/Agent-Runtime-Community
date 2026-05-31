import { IsObject, IsString } from 'class-validator';

export class IngestEventDto {
  @IsString()
  replayCorrelationId!: string;

  @IsString()
  eventType!: string;

  @IsObject()
  payload!: Record<string, unknown>;

  @IsString()
  actorId!: string;

  @IsString()
  projectId!: string;

  parentTraceId?: string;
}
