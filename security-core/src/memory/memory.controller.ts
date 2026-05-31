import { Body, Controller, Get, Param, Post, Req } from '@nestjs/common';
import { MemoryService } from './memory.service';
import { RecordMutationDto } from './memory.dto';
import type { AuthenticatedRequest } from '../auth/auth-context';
import { assertProjectScope } from '../common/project-scope';

@Controller('memory')
export class MemoryController {
  constructor(private readonly memoryService: MemoryService) {}

  @Post('mutate')
  async recordMutation(
    @Body() body: RecordMutationDto,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    assertProjectScope(scopedProjectId, body.projectId);
    return this.memoryService.recordMutation(body);
  }

  @Get(':agentId/mutations')
  async getMutations(
    @Param('agentId') agentId: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    return this.memoryService.getMutations(agentId, scopedProjectId);
  }

  @Post('checkpoint')
  async createCheckpoint(
    @Body() body: { agentId: string, state: Record<string, unknown> },
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    return this.memoryService.createCheckpoint({
      ...body,
      projectId: scopedProjectId,
    });
  }

  @Post('rollback/:id')
  async rollback(
    @Param('id') checkpointId: string,
    @Req() req: AuthenticatedRequest,
  ) {
    const scopedProjectId = req.auth?.projectId ?? '';
    return this.memoryService.rollback(checkpointId, scopedProjectId);
  }
}
