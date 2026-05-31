import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

import { PrivacyService } from '../privacy/privacy.service';

@Injectable()
export class ReplayService {
  constructor(
    private prisma: PrismaService,
    private privacy: PrivacyService,
  ) {}

  async ingestEvent(data: {
    replayCorrelationId: string;
    eventType: string;
    payload: Record<string, unknown>;
    actorId: string;
    projectId: string;
    parentTraceId?: string;
  }) {
    return this.prisma.executionEvent.create({
      data: {
        replayCorrelationId: data.replayCorrelationId,
        eventType: data.eventType,
        payload: this.privacy.redact(data.payload) as Prisma.InputJsonValue,
        actorId: data.actorId,
        projectId: data.projectId,
        parentTraceId: data.parentTraceId,
      },
    });
  }

  async getTimeline(replayCorrelationId: string, projectId: string) {
    return this.prisma.executionEvent.findMany({
      where: { replayCorrelationId, projectId },
      orderBy: { createdAt: 'asc' },
    });
  }

  async exportEvidence(replayCorrelationId: string, projectId: string) {
    const events = await this.getTimeline(replayCorrelationId, projectId);

    return {
      correlationId: replayCorrelationId,
      projectId,
      exportedAt: new Date().toISOString(),
      eventCount: events.length,
      events,
    };
  }
}
