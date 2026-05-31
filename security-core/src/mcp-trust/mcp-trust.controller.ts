import {
  Controller,
  Get,
  Post,
  Patch,
  Body,
  Param,
  UseGuards,
  Request,
} from '@nestjs/common';
import { McpTrustService } from './mcp-trust.service';
import { AuthGuard } from '../auth/auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('mcp')
@UseGuards(AuthGuard, RolesGuard)
export class McpTrustController {
  constructor(private mcpTrust: McpTrustService) {}

  @Get('registry')
  @Roles('admin', 'approver', 'viewer')
  async getRegistry(@Request() req: { auth: { projectId: string } }) {
    return this.mcpTrust.getRegistry(req.auth.projectId);
  }

  @Post('registry')
  @Roles('admin')
  async addTool(
    @Body() body: { name: string; publisher: string; schemaHash: string },
    @Request() req: { auth: { projectId: string } },
  ) {
    return this.mcpTrust.addTool(body, req.auth.projectId);
  }

  @Patch('registry/:id/revoke')
  @Roles('admin')
  async revokeTool(@Param('id') id: string, @Request() req: { auth: { projectId: string } }) {
    return this.mcpTrust.revokeTool(id, req.auth.projectId);
  }
}
