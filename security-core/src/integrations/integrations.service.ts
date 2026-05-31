import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class IntegrationsService {
  private readonly logger = new Logger(IntegrationsService.name);

  constructor(private prisma: PrismaService) {}

  async dispatchWebhook(projectId: string, eventType: string, payload: any) {
    const webhooks = await this.prisma.webhookConfig.findMany({
      where: { projectId },
    });

    const targetWebhooks = webhooks.filter(
      (w) => w.events.includes(eventType) || w.events.includes('*'),
    );

    for (const webhook of targetWebhooks) {
      this.logger.log(`Dispatching ${eventType} to ${webhook.url}`);
      try {
        await fetch(webhook.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-webhook-secret': webhook.secret,
          },
          body: JSON.stringify({
            event: eventType,
            data: payload,
            timestamp: new Date().toISOString(),
          }),
        });
      } catch (err) {
        this.logger.error(`Failed to dispatch to ${webhook.url}`, err);
      }
    }
  }
}
