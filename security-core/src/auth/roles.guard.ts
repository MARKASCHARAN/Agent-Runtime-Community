import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthenticatedRequest } from './auth-context';
import { ROLES_KEY } from './roles.decorator';

/**
 * RBAC (Role-Based Access Control) Guard.
 * Restricts endpoint access based on the role assigned to the authenticated user's session.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  /**
   * Verifies if the request's context matches the required roles specified via the @Roles decorator.
   * 
   * @param context The execution context provided by NestJS.
   * @returns True if the user possesses the required role, throws ForbiddenException otherwise.
   */
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const currentRole = request.auth?.role;

    if (!currentRole || !requiredRoles.includes(currentRole)) {
      throw new ForbiddenException('Insufficient role to perform this action');
    }

    return true;
  }
}
