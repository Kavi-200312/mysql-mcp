import { MysqlClientManager } from "../connection/mysql-client.js";
import { ApprovalManager } from "../security/approval-manager.js";
import { validateWriteQuery, SecurityPolicyOptions } from "../security/sql-validator.js";
import { EnvConfig } from "../config/env.js";
import { logAuditEvent } from "../audit/logger.js";
import crypto from "crypto";

export interface ExecuteApprovedWriteResult {
  success: boolean;
  operation: string;
  database: string;
  table: string;
  affectedRows: number;
  durationMs: number;
  message: string;
}

export class ExecuteApprovedWriteTool {
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

  public async execute(approvalToken: string, userConfirmed: boolean): Promise<ExecuteApprovedWriteResult> {
    if (!userConfirmed) {
      throw new Error("Execution rejected: Explicit confirmation (userConfirmed: true) is required");
    }

    // 1. Validate and consume token (checks expiry, tamper-resistance, single-use)
    const approval = this.approvalManager.validateAndConsume(approvalToken);

    // 2. Security Revalidation: Re-run live policy validation against SQL at execution time
    validateWriteQuery(approval.sql, approval.database, this.getPolicyOptions());

    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    try {
      // 3. Execute within atomic transaction using the dedicated writer pool
      const result = await this.client.executeWriteQuery(approval.sql, approval.params);
      const durationMs = Date.now() - startTime;

      // 4. Record execution result
      this.approvalManager.recordExecution({
        token: approval.token,
        sql: approval.sql,
        database: approval.database,
        operation: approval.operation,
        affectedRows: result.affectedRows,
        durationMs,
        success: true,
        executedAt: Date.now()
      });

      logAuditEvent({
        requestId,
        toolName: "execute_approved_write",
        database: approval.database,
        operationType: approval.operation,
        sql: approval.sql,
        params: approval.params,
        approvalToken: approval.token,
        approvalStatus: "EXECUTED",
        affectedRows: result.affectedRows,
        durationMs,
        success: true
      });

      return {
        success: true,
        operation: approval.operation,
        database: approval.database,
        table: approval.table,
        affectedRows: result.affectedRows,
        durationMs,
        message: `Successfully executed ${approval.operation} on '${approval.table}'. Affected rows: ${result.affectedRows}.`
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const durationMs = Date.now() - startTime;

      // On transient failure, release execution lock so operation can be retried safely
      this.approvalManager.releaseExecutionLock(approvalToken);

      this.approvalManager.recordExecution({
        token: approval.token,
        sql: approval.sql,
        database: approval.database,
        operation: approval.operation,
        affectedRows: 0,
        durationMs,
        success: false,
        executedAt: Date.now(),
        error: errMsg
      });

      logAuditEvent({
        requestId,
        toolName: "execute_approved_write",
        database: approval.database,
        operationType: approval.operation,
        sql: approval.sql,
        params: approval.params,
        approvalToken: approval.token,
        approvalStatus: "FAILED",
        affectedRows: 0,
        durationMs,
        success: false,
        error: errMsg
      });

      throw new Error(`Execution failed: ${errMsg}`);
    }
  }
}
