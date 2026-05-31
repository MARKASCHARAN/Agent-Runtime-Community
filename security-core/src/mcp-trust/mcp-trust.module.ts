import { Module, Global } from '@nestjs/common';
import { McpTrustService } from './mcp-trust.service';
import { McpTrustController } from './mcp-trust.controller';

@Global()
@Module({
  controllers: [McpTrustController],
  providers: [McpTrustService],
  exports: [McpTrustService],
})
export class McpTrustModule {}
