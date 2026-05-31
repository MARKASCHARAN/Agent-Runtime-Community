import { Module, Global } from '@nestjs/common';
import { PrivacyService } from './privacy.service';
import { PrivacyController } from './privacy.controller';

@Global()
@Module({
  controllers: [PrivacyController],
  providers: [PrivacyService],
  exports: [PrivacyService],
})
export class PrivacyModule {}
