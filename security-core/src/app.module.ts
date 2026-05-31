import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

import { PrismaModule } from './prisma/prisma.module';
import { PolicyModule } from './policy/policy.module';
import { ReplayModule } from './replay/replay.module';
import { McpTrustModule } from './mcp-trust/mcp-trust.module';
import { MemoryModule } from './memory/memory.module';

@Module({
  imports: [
    PrismaModule,
    PolicyModule,
    ReplayModule,
    McpTrustModule,
    MemoryModule,
    EventsModule,
    PrivacyModule,
    IntegrationsModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
