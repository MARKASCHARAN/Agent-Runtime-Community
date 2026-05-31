import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthenticatedRequest, UserRole } from './auth-context';
import { AgentAuthService } from '../agent-auth/agent-auth.service';

const ALLOWED_ROLES: UserRole[] = ['admin', 'approver', 'viewer'];

/**
 * Global authentication guard.
 * Validates either an Agent JIT Token or a static API Key.
 * Injects verified credentials and project scope into the request.
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private agentAuth: AgentAuthService) {}

  /**
   * Evaluates the incoming request headers to determine access.
   * Extracts API keys or Bearer tokens and validates against the DB or ENV.
   * 
   * @param context The execution context provided by NestJS.
   * @returns True if authenticated, throws UnauthorizedException/ForbiddenException otherwise.
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();

    const bearer = request.headers.authorization
      ?.replace(/^Bearer\s+/i, '')
      .trim();
    const headerApiKey = request.headers['x-api-key'];
    const apiKey =
      (typeof headerApiKey === 'string' ? headerApiKey : undefined) ?? bearer;

    if (!apiKey) {
      throw new UnauthorizedException('Missing API credentials');
    }

    // Check if the credential is a valid Agent Token
    const agentData = await this.agentAuth.validateToken(apiKey);
    
    const rawProjectId = request.headers['x-project-id'];
    const headerProjectId =
      typeof rawProjectId === 'string' && rawProjectId.trim().length > 0
        ? rawProjectId.trim()
        : undefined;

    if (agentData) {
      if (headerProjectId && headerProjectId !== agentData.projectId) {
        throw new ForbiddenException('Project scope mismatch');
      }

      request.auth = {
        apiKeyId: agentData.clientId,
        role: 'agent' as any, // Add agent role
        projectId: agentData.projectId,
      };
      return true;
    }

    // Fall back to standard API Key authentication
    const configuredKeys = (process.env.API_KEYS ?? 'dev-api-key')
      .split(',')
      .map((key) => key.trim())
      .filter(Boolean);

    if (!configuredKeys.includes(apiKey)) {
      throw new UnauthorizedException('Invalid API credentials');
    }

    if (!headerProjectId) {
      throw new ForbiddenException('x-project-id header is required');
    }

    const rawRole = request.headers['x-user-role'];
    const normalizedRole =
      typeof rawRole === 'string'
        ? (rawRole.trim().toLowerCase() as UserRole)
        : 'viewer';

    request.auth = {
      apiKeyId: apiKey,
      role: ALLOWED_ROLES.includes(normalizedRole) ? normalizedRole : 'viewer',
      projectId: headerProjectId,
    };

    return true;
  }
}
