#!/usr/bin/env node
import { loadConfig } from "./config/env.js";
import { SshTunnelManager } from "./connection/ssh-tunnel.js";
import { MysqlClientManager } from "./connection/mysql-client.js";
import { ApprovalManager } from "./security/approval-manager.js";
import { createMcpServer } from "./server.js";
import { auditLogger } from "./audit/logger.js";

async function main(): Promise<void> {
  try {
    const config = loadConfig();

    auditLogger.info(
      {
        db: config.DB_NAME,
        host: config.DB_HOST,
        port: config.EFFECTIVE_DB_PORT,
        sshEnabled: config.SSH_ENABLED
      },
      "Initializing Secure MySQL MCP Server..."
    );

    const tunnelManager = new SshTunnelManager({
      enabled: config.SSH_ENABLED,
      sshHost: config.SSH_HOST,
      sshPort: config.SSH_PORT,
      sshUser: config.SSH_USER,
      sshKeyPath: config.SSH_KEY_PATH,
      localPort: config.SSH_LOCAL_PORT,
      remoteHost: config.SSH_REMOTE_HOST,
      remotePort: config.SSH_REMOTE_PORT
    });

    if (config.SSH_ENABLED) {
      await tunnelManager.ensureTunnel();
    }

    const clientManager = new MysqlClientManager(config);
    const approvalManager = new ApprovalManager(config.APPROVAL_EXPIRY_SECONDS, config.APPROVAL_STORE_PATH);

    // Teardown hook
    const shutdown = async (signal: string) => {
      auditLogger.info(`Received ${signal}. Shutting down cleanly...`);
      try {
        await clientManager.close();
        tunnelManager.close();
      } catch (err: unknown) {
        auditLogger.error({ err }, "Error during shutdown");
      }
      process.exit(0);
    };

    process.on("SIGINT", () => shutdown("SIGINT"));
    process.on("SIGTERM", () => shutdown("SIGTERM"));

    const { start } = createMcpServer(config, clientManager, approvalManager);
    await start();
  } catch (err: unknown) {
    const errMsg = err instanceof Error ? err.message : String(err);
    auditLogger.fatal({ err: errMsg }, "Fatal initialization error");
    process.exit(1);
  }
}

main().catch(err => {
  console.error("Unhandled top-level error:", err);
  process.exit(1);
});
