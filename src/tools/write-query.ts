import nodeSqlParser from "node-sql-parser";
import { MysqlClientManager } from "../connection/mysql-client.js";
import { EnvConfig } from "../config/env.js";
import { validateWriteQuery, SecurityPolicyOptions } from "../security/sql-validator.js";
import { ApprovalManager } from "../security/approval-manager.js";
import { logAuditEvent, auditLogger } from "../audit/logger.js";
import crypto from "crypto";

const { Parser } = nodeSqlParser;
const mysqlParser = new Parser();

export interface WriteQueryResult {
  success: boolean;
  operation: string;
  database: string;
  table: string;
  affectedRows: number;
  durationMs: number;
  message: string;
  requiresApproval?: boolean;
  approvalToken?: string;
  instructions?: string;
}

export class WriteQueryTool {
  private client: MysqlClientManager;
  private approvalManager: ApprovalManager;
  private config: EnvConfig;

  constructor(client: MysqlClientManager, approvalManager: ApprovalManager, config: EnvConfig) {
    this.client = client;
    this.approvalManager = approvalManager;
    this.config = config;
  }

  private getPolicyOptions(): SecurityPolicyOptions {
    return {
      allowDelete: this.config.POLICY_ALLOW_DELETE,
      allowDdl: this.config.POLICY_ALLOW_DDL,
      requireWhere: this.config.POLICY_REQUIRE_WHERE,
      autoApproveInsert: this.config.POLICY_AUTO_APPROVE_INSERT,
      autoApproveUpdate: this.config.POLICY_AUTO_APPROVE_UPDATE,
      autoApproveDelete: this.config.POLICY_AUTO_APPROVE_DELETE,
      autoApproveDdl: this.config.POLICY_AUTO_APPROVE_DDL,
      policyMode: this.config.POLICY_MODE
    };
  }

  public async execute(
    sql: string,
    params: unknown[] = [],
    database?: string,
    userConfirmed = false,
    confirmBulk = false
  ): Promise<WriteQueryResult> {
    const targetDb = database || this.config.DB_NAME;
    if (targetDb.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot execute write on database '${targetDb}'. Configured DB: '${this.config.DB_NAME}'`);
    }

    const policy = this.getPolicyOptions();
    const validated = validateWriteQuery(sql, this.config.DB_NAME, policy);
    const { operation, table, isAutoApproved, statement } = validated;

    // Estimate affected rows for UPDATE/DELETE
    let expectedAffectedRows = 1;
    if ((operation === "UPDATE" || operation === "DELETE") && statement.ast["where"]) {
      try {
        const countAst = {
          type: "select",
          columns: [
            {
              expr: {
                type: "aggr_func",
                name: "COUNT",
                args: { expr: { type: "star", value: "*" } }
              },
              as: "count"
            }
          ],
          from: statement.ast["table"] || [{ db: null, table }],
          where: statement.ast["where"]
        };
        const countSql = mysqlParser.sqlify(countAst as any, { database: "MySQL" });
        const countRes = await this.client.executeReadQuery<{ count: number }>(countSql);
        expectedAffectedRows = countRes.rows[0]?.count ?? 0;
      } catch (err: unknown) {
        auditLogger.warn({ err: err instanceof Error ? err.message : String(err) }, "Failed to estimate count in write_query");
      }
    }

    const isBulk = expectedAffectedRows > this.config.BULK_AFFECTED_ROW_THRESHOLD;
    if (isBulk && !confirmBulk) {
      throw new Error(
        `Bulk modification safety block: Estimated ${expectedAffectedRows} affected rows exceeds threshold of ${this.config.BULK_AFFECTED_ROW_THRESHOLD}. Set confirmBulk: true to authorize bulk execution.`
      );
    }

    // If policy requires approval and user hasn't explicitly confirmed
    if (!isAutoApproved && !userConfirmed) {
      const approval = this.approvalManager.createApproval({
        sql: validated.statement.rawSql,
        params,
        database: targetDb,
        table,
        operation,
        expectedAffectedRows,
        isBulk,
        expirySeconds: this.config.APPROVAL_EXPIRY_SECONDS
      });

      return {
        success: false,
        requiresApproval: true,
        approvalToken: approval.token,
        operation,
        database: targetDb,
        table,
        affectedRows: 0,
        durationMs: 0,
        message: `Approval required: '${operation}' operations require user confirmation under the current security policy.`,
        instructions: `Present the proposed SQL to the user. To execute once authorized, call 'execute_approved_write' with token '${approval.token}' and userConfirmed: true. To bypass prompts in the future, set POLICY_AUTO_APPROVE_${operation}=true or POLICY_MODE=autonomous in .env.`
      };
    }

    // Execute atomic transaction
    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    try {
      const result = await this.client.executeWriteQuery(validated.statement.rawSql, params);
      const durationMs = Date.now() - startTime;

      logAuditEvent({
        requestId,
        toolName: "write_query",
        database: targetDb,
        operationType: operation,
        sql: validated.statement.rawSql,
        params,
        approvalStatus: isAutoApproved ? "AUTO_APPROVED" : "USER_CONFIRMED",
        affectedRows: result.affectedRows,
        durationMs,
        success: true
      });

      return {
        success: true,
        operation,
        database: targetDb,
        table,
        affectedRows: result.affectedRows,
        durationMs,
        message: `Successfully executed ${operation} on '${table}'. Affected rows: ${result.affectedRows}.`
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const durationMs = Date.now() - startTime;

      logAuditEvent({
        requestId,
        toolName: "write_query",
        database: targetDb,
        operationType: operation,
        sql: validated.statement.rawSql,
        params,
        affectedRows: 0,
        durationMs,
        success: false,
        error: errMsg
      });

      throw new Error(`Execution failed: ${errMsg}`);
    }
  }
}
