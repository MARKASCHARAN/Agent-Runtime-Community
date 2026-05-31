import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { EventsGateway } from '../events/events.gateway';

@Injectable()
export class MemoryService {
  constructor(
    private prisma: PrismaService,
    private eventsGateway: EventsGateway,
  ) {}

  async recordMutation(data: {
    agentId: string;
    mutationType: string;
    key: string;
    previousValue?: string;
    newValue?: string;
    sourceMetadata: Record<string, unknown>;
    projectId: string;
  }) {
    let anomalyScore = 0.0;
    if (
      data.mutationType === 'OVERWRITE' &&
      data.previousValue &&
      data.newValue
    ) {
      if (Math.abs(data.newValue.length - data.previousValue.length) > 1000) {
        anomalyScore = 0.8;
      }
    }

    const mutation = await this.prisma.memoryMutation.create({
      data: {
        agentId: data.agentId,
        mutationType: data.mutationType,
        key: data.key,
        previousValue: data.previousValue,
        newValue: data.newValue,
        sourceMetadata: data.sourceMetadata as Prisma.InputJsonValue,
        anomalyScore,
        projectId: data.projectId,
      },
    });

    if (anomalyScore > 0.5) {
      this.eventsGateway.emitMemoryAnomaly(mutation);
    }

    return mutation;
  }

  async getMutations(agentId: string, projectId: string) {
    return this.prisma.memoryMutation.findMany({
      where: { agentId, projectId },
      orderBy: { createdAt: 'desc' },
    });
  }

  async createCheckpoint(data: { agentId: string, state: Record<string, unknown>, projectId: string }) {
    return this.prisma.agentCheckpoint.create({
      data: {
        agentId: data.agentId,
        state: data.state as Prisma.InputJsonValue,
        projectId: data.projectId
      }
    });
  }

  async rollback(checkpointId: string, projectId: string) {
    const checkpoint = await this.prisma.agentCheckpoint.findUnique({
      where: { id: checkpointId }
    });
    
    if (!checkpoint) {
      throw new Error('Checkpoint not found');
    }
    if (checkpoint.projectId !== projectId) {
      throw new Error('Unauthorized');
    }

    // In a real implementation, this would emit an event to the agent engine to physically revert its context
    // For now, we return the state so the SDK can return it to the agent.
    return checkpoint;
  }
}
