import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * Model Context Protocol (MCP) Trust Registry.
 * Cryptographically verifies tool schemas to prevent Supply Chain Attacks in autonomous swarms.
 */
@Injectable()
export class McpTrustService {
  private readonly logger = new Logger(McpTrustService.name);

  constructor(private prisma: PrismaService) {}

  /**
   * Verifies if a tool and its schema hash are approved in the enterprise registry.
   */
  async verifyTool(
    name: string,
    schemaHash: string,
    projectId: string,
  ): Promise<boolean> {
    const registryEntry = await this.prisma.mcpRegistry.findFirst({
      where: {
        name,
        projectId,
        status: 'APPROVED',
      },
    });

    if (!registryEntry) {
      this.logger.warn(
        `MCP Verification Failed: Tool '${name}' is not in the approved registry.`,
      );
      return false;
    }

    if (registryEntry.schemaHash !== schemaHash) {
      this.logger.error(
        `MCP Verification Failed: Tool '${name}' hash mismatch! Expected ${registryEntry.schemaHash}, got ${schemaHash}. Possible supply chain attack.`,
      );
      return false;
    }

    return true;
  }

  /**
   * Retrieves all registered MCP tools for a specific project.
   */
  async getRegistry(projectId: string) {
    return this.prisma.mcpRegistry.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Registers a new tool in the Enterprise Trust Registry.
   * 
   * @param data The tool's name, publisher, and secure cryptographic hash.
   * @param projectId The isolated project context.
   */
  async addTool(
    data: { name: string; publisher: string; schemaHash: string },
    projectId: string,
  ) {
    return this.prisma.mcpRegistry.create({
      data: {
        ...data,
        projectId,
      },
    });
  }

  /**
   * Revokes trust for a compromised or deprecated MCP tool, instantly blocking agent access.
   */
  async revokeTool(id: string, projectId: string) {
    return this.prisma.mcpRegistry.update({
      where: { id },
      data: { status: 'REVOKED' },
    });
  }
}
