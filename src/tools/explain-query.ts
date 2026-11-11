import { MysqlClientManager } from "../connection/mysql-client.js";
import { EnvConfig } from "../config/env.js";
import { validateReadQuery } from "../security/sql-validator.js";
import { QueryResult } from "../types/database.js";
import { logAuditEvent } from "../audit/logger.js";
import crypto from "crypto";

export class ExplainQueryTool {
  private client: MysqlClientManager;
  private config: EnvConfig;

  constructor(client: MysqlClientManager, config: EnvConfig) {
    this.client = client;
    this.config = config;
  }

  public async execute(sql: string, params: unknown[] = [], database?: string): Promise<QueryResult> {
    const targetDb = database || this.config.DB_NAME;
    if (targetDb.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Queries against database '${targetDb}' are blocked. Configured DB: '${this.config.DB_NAME}'`);
    }

    const cleanSql = sql.trim().replace(/^explain\s+/i, "");
    // Ensure inner query is a valid read query
    validateReadQuery(cleanSql, this.config.DB_NAME);

    const explainSql = `EXPLAIN ${cleanSql}`;
    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    try {
      const result = await this.client.executeReadQuery(explainSql, params);

      logAuditEvent({
        requestId,
        toolName: "explain_query",
        database: targetDb,
        operationType: "EXPLAIN",
        sql: explainSql,
        params,
        durationMs: Date.now() - startTime,
        success: true
      });

      return result;
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "explain_query",
        database: targetDb,
        operationType: "EXPLAIN",
        sql: explainSql,
        params,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }
}
