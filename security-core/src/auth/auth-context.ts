import { Request } from 'express';

/**
 * Defines the allowed RBAC roles for dashboard and administrative operations.
 */
export type UserRole = 'admin' | 'approver' | 'viewer';

/**
 * The standard authentication context attached to requests that pass the AuthGuard.
 */
export interface AuthContext {
  apiKeyId: string;
  role: UserRole;
  projectId: string;
}

/**
 * An Express Request object extended with the verified authentication context.
 */
export interface AuthenticatedRequest extends Request {
  auth?: AuthContext;
}
