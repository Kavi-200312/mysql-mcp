import { MysqlClientManager } from "../connection/mysql-client.js";
import { EnvConfig } from "../config/env.js";
import { validateReadQuery } from "../security/sql-validator.js";
import { QueryResult } from "../types/database.js";
import { logAuditEvent } from "../audit/logger.js";
import crypto from "crypto";

export class ReadQueryTool {
  private client: MysqlClientManager;
  private config: EnvConfig;

  constructor(client: MysqlClientManager, config: EnvConfig) {
    this.client = client;
    this.config = config;
  }

  public async execute(
    sql: string,
    params: unknown[] = [],
    database?: string,
    limit?: number
  ): Promise<QueryResult> {
    const targetDb = database || this.config.DB_NAME;
    if (targetDb.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Queries against database '${targetDb}' are blocked. Configured DB: '${this.config.DB_NAME}'`);
    }

    // AST-based validation: strictly SELECT/SHOW/DESCRIBE only
    const validated = validateReadQuery(sql, this.config.DB_NAME);

    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    try {
      const result = await this.client.executeReadQuery(validated.statement.rawSql, params, { limit });

      logAuditEvent({
        requestId,
        toolName: "read_query",
        database: targetDb,
        operationType: "SELECT",
        sql: validated.statement.rawSql,
        params,
        durationMs: Date.now() - startTime,
        success: true
      });

      return result;
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "read_query",
        database: targetDb,
        operationType: "SELECT",
        sql: validated.statement.rawSql,
        params,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }
}
