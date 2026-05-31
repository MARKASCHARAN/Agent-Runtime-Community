import { Body, Controller, Get, Param, Post, Req } from '@nestjs/common';
import { ReplayService } from './replay.service';
import { IngestEventDto } from './replay.dto';
import type { AuthenticatedRequest } from '../auth/auth-context';
import { assertProjectScope } from '../common/project-scope';

@Controller('replay')
export class ReplayController {
  constructor(private readonly replayService: ReplayService) {}

  @Post('ingest')
  async ingestEvent(
    @Body() body: IngestEventDto,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    assertProjectScope(scopedProjectId, body.projectId);
    return this.replayService.ingestEvent(body);
  }

  @Get('timeline/:correlationId')
  async getTimeline(
    @Param('correlationId') correlationId: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    return this.replayService.getTimeline(correlationId, scopedProjectId);
  }

  @Get('export/:correlationId')
  async exportEvidence(
    @Param('correlationId') correlationId: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    return this.replayService.exportEvidence(correlationId, scopedProjectId);
  }
}
