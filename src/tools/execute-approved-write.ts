import { MysqlClientManager } from "../connection/mysql-client.js";
import { ApprovalManager } from "../security/approval-manager.js";
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

  constructor(client: MysqlClientManager, approvalManager: ApprovalManager) {
    this.client = client;
    this.approvalManager = approvalManager;
  }

  public async execute(approvalToken: string, userConfirmed: boolean): Promise<ExecuteApprovedWriteResult> {
    if (!userConfirmed) {
      throw new Error("Execution rejected: Explicit confirmation (userConfirmed: true) is required");
    }

    // 1. Validate and consume token (checks expiry, tamper-resistance, single-use)
    const approval = this.approvalManager.validateAndConsume(approvalToken);

    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    try {
      // 2. Execute within atomic transaction using the dedicated writer pool
      const result = await this.client.executeWriteQuery(approval.sql, approval.params);

      const durationMs = Date.now() - startTime;

      // 3. Record execution result
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
