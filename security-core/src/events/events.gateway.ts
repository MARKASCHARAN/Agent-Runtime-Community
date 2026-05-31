import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayInit,
} from '@nestjs/websockets';
import { Server } from 'socket.io';

import { IntegrationsService } from '../integrations/integrations.service';

@WebSocketGateway({ cors: true })
export class EventsGateway implements OnGatewayInit {
  @WebSocketServer()
  server: Server;

  constructor(private integrations: IntegrationsService) {}

  afterInit() {
    console.log('WebSocket Gateway Initialized');
  }

  emitAlert(payload: any) {
    this.server.emit('runtime.alert', payload);
  }

  emitPolicyIntervention(payload: any) {
    this.server.emit('policy.intervention', payload);
    this.integrations.dispatchWebhook(
      payload.projectId || 'default',
      'POLICY_DECISION',
      payload,
    );
  }

  emitApprovalRequired(payload: any) {
    this.server.emit('approval.required', payload);
    this.integrations.dispatchWebhook(
      payload.projectId || 'default',
      'REQUIRE_APPROVAL',
      payload,
    );
  }

  emitMemoryAnomaly(payload: any) {
    this.server.emit('memory.anomaly', payload);
    this.integrations.dispatchWebhook(
      payload.projectId || 'default',
      'MEMORY_ANOMALY',
      payload,
    );
  }

  emitReplayReady(payload: any) {
    this.server.emit('replay.ready', payload);
  }
}
