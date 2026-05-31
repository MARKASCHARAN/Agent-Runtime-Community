import { Controller, Get, UseGuards, Request } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthGuard } from '../auth/auth.guard';
import { RolesGuard } from '../auth/roles.guard';
import { Roles } from '../auth/roles.decorator';

@Controller('privacy')
@UseGuards(AuthGuard, RolesGuard)
export class PrivacyController {
  constructor(private prisma: PrismaService) {}

  @Get('dlp/violations')
  @Roles('admin', 'approver', 'viewer')
  async getDlpViolations(@Request() req: { auth: { projectId: string } }) {
    return this.prisma.dlpViolation.findMany({
      where: { projectId: req.auth.projectId },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });
  }
}
