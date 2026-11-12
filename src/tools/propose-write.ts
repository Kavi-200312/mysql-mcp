import nodeSqlParser from "node-sql-parser";
import { MysqlClientManager } from "../connection/mysql-client.js";
import { EnvConfig } from "../config/env.js";
import { validateWriteQuery, SecurityPolicyOptions } from "../security/sql-validator.js";
import { ApprovalManager } from "../security/approval-manager.js";
import { ApprovalRequest, WriteOperationType } from "../types/approval.js";
import { logAuditEvent, auditLogger } from "../audit/logger.js";
import crypto from "crypto";

const { Parser } = nodeSqlParser;
const mysqlParser = new Parser();

export interface ProposeWriteResult {
  approvalToken: string;
  database: string;
  table: string;
  operation: WriteOperationType;
  expectedAffectedRows: number;
  isBulk: boolean;
  bulkWarning?: string;
  currentValuesPreview?: Record<string, unknown>[];
  expiresAt: string;
  instructions: string;
  isAutoApproved: boolean;
}

export class ProposeWriteTool {
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
    confirmBulk = false
  ): Promise<ProposeWriteResult> {
    const targetDb = database || this.config.DB_NAME;
    if (targetDb.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot propose write on database '${targetDb}'. Configured DB: '${this.config.DB_NAME}'`);
    }

    // 1. AST-based validation with configurable policy
    const validated = validateWriteQuery(sql, this.config.DB_NAME, this.getPolicyOptions());
    const { operation, table, isAutoApproved, statement } = validated;

    let expectedAffectedRows = 1;
    let currentValuesPreview: Record<string, unknown>[] | undefined = undefined;

    // 2. For UPDATE and DELETE, construct count and preview using AST
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

        const previewAst = {
          type: "select",
          columns: [{ expr: { type: "star", value: "*" }, as: null }],
          from: statement.ast["table"] || [{ db: null, table }],
          where: statement.ast["where"],
          limit: {
            seperator: "",
            value: [{ type: "number", value: 5 }]
          }
        };

        const countSql = mysqlParser.sqlify(countAst as any, { database: "MySQL" });
        const countRes = await this.client.executeReadQuery<{ count: number }>(countSql);
        expectedAffectedRows = countRes.rows[0]?.count ?? 0;

        const previewSql = mysqlParser.sqlify(previewAst as any, { database: "MySQL" });
        const previewRes = await this.client.executeReadQuery(previewSql);
        currentValuesPreview = previewRes.rows;
      } catch (err: unknown) {
        auditLogger.warn({ err: err instanceof Error ? err.message : String(err) }, "Failed to generate AST preview for write statement");
      }
    }

    const isBulk = expectedAffectedRows > this.config.BULK_AFFECTED_ROW_THRESHOLD;
    if (isBulk && !confirmBulk) {
      throw new Error(
        `Bulk modification safety block: Estimated ${expectedAffectedRows} affected rows exceeds threshold of ${this.config.BULK_AFFECTED_ROW_THRESHOLD}. Explicit confirmation (confirmBulk: true) is required to issue approval token.`
      );
    }

    // 3. Create cryptographically bound approval token
    const approval: ApprovalRequest = this.approvalManager.createApproval({
      sql: validated.statement.rawSql,
      params,
      database: targetDb,
      table,
      operation,
      expectedAffectedRows,
      currentValuesPreview,
      isBulk,
      expirySeconds: this.config.APPROVAL_EXPIRY_SECONDS
    });

    const requestId = crypto.randomUUID();
    logAuditEvent({
      requestId,
      toolName: "propose_write",
      database: targetDb,
      operationType: operation,
      sql: validated.statement.rawSql,
      params,
      approvalToken: approval.token,
      approvalStatus: isAutoApproved ? "AUTO_APPROVED" : "PENDING",
      affectedRows: expectedAffectedRows,
      durationMs: 0,
      success: true
    });

    return {
      approvalToken: approval.token,
      database: targetDb,
      table,
      operation,
      expectedAffectedRows,
      isBulk,
      currentValuesPreview,
      expiresAt: new Date(approval.expiresAt).toISOString(),
      isAutoApproved,
      instructions: isAutoApproved
        ? "This operation is configured as AUTO-APPROVED by user policy. You can execute it immediately with execute_approved_write."
        : "Review the proposed changes above carefully. To execute this write, call 'execute_approved_write' with this approvalToken and userConfirmed: true. This token is short-lived and strictly bound to this exact SQL statement and parameters."
    };
  }
}
