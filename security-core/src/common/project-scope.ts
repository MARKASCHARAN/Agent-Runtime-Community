import { ForbiddenException } from '@nestjs/common';

export function assertProjectScope(
  scopedProjectId: string,
  requestedProjectId: string,
): string {
  if (!requestedProjectId || scopedProjectId !== requestedProjectId) {
    throw new ForbiddenException('Project scope mismatch');
  }

  return requestedProjectId;
}
