import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { ApprovalRequest, ExecutionRecord, WriteOperationType } from "../types/approval.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const APPROVAL_STORE_PATH = path.resolve(__dirname, "../../.approvals.json");

export class ApprovalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalError";
  }
}

export class ApprovalManager {
  private approvals: Map<string, ApprovalRequest> = new Map();
  private executions: ExecutionRecord[] = [];
  private readonly defaultExpirySeconds: number;

  constructor(defaultExpirySeconds = 300) {
    this.defaultExpirySeconds = defaultExpirySeconds;
    this.loadFromDisk();
  }

  private loadFromDisk(): void {
    try {
      if (fs.existsSync(APPROVAL_STORE_PATH)) {
        const raw = fs.readFileSync(APPROVAL_STORE_PATH, "utf-8");
        const list: ApprovalRequest[] = JSON.parse(raw);
        for (const item of list) {
          if (Date.now() <= item.expiresAt + 60000) {
            this.approvals.set(item.token, item);
          }
        }
      }
    } catch {
      // Ignore disk read errors
    }
  }

  private saveToDisk(): void {
    try {
      const active = Array.from(this.approvals.values()).filter(
        a => Date.now() <= a.expiresAt + 60000
      );
      fs.writeFileSync(APPROVAL_STORE_PATH, JSON.stringify(active, null, 2), "utf-8");
    } catch {
      // Ignore disk write errors
    }
  }

  /**
   * Generates a unique, short-lived approval token bound to exact SQL, params, DB, and operation.
   */
  public createApproval(params: {
    sql: string;
    normalizedSql?: string;
    params?: unknown[];
    database: string;
    table: string;
    operation: WriteOperationType;
    expectedAffectedRows: number;
    currentValuesPreview?: Record<string, unknown>[];
    proposedChangesPreview?: Record<string, unknown> | Record<string, unknown>[];
    isBulk: boolean;
    expirySeconds?: number;
  }): ApprovalRequest {
    this.loadFromDisk();
    const token = `appr_${crypto.randomBytes(20).toString("hex")}`;
    const now = Date.now();
    const expiryMs = (params.expirySeconds || this.defaultExpirySeconds) * 1000;

    const request: ApprovalRequest = {
      token,
      sql: params.sql.trim(),
      normalizedSql: params.normalizedSql || params.sql.trim(),
      params: params.params || [],
      database: params.database,
      table: params.table,
      operation: params.operation,
      expectedAffectedRows: params.expectedAffectedRows,
      currentValuesPreview: params.currentValuesPreview,
      proposedChangesPreview: params.proposedChangesPreview,
      isBulk: params.isBulk,
      createdAt: now,
      expiresAt: now + expiryMs,
      status: "PENDING"
    };

    this.approvals.set(token, request);
    this.saveToDisk();
    return request;
  }

  /**
   * Retrieves an approval request by token.
   */
  public getApproval(token: string): ApprovalRequest | null {
    this.loadFromDisk();
    const approval = this.approvals.get(token);
    if (!approval) return null;

    if (Date.now() > approval.expiresAt && approval.status === "PENDING") {
      approval.status = "EXPIRED";
      this.saveToDisk();
    }

    return approval;
  }

  /**
   * Validates and consumes the approval token for execution.
   * Throws an ApprovalError if expired, modified, mismatched, or already consumed.
   */
  public validateAndConsume(
    token: string,
    validation?: {
      sql?: string;
      params?: unknown[];
      database?: string;
    }
  ): ApprovalRequest {
    this.loadFromDisk();
    const approval = this.approvals.get(token);

    if (!approval) {
      throw new ApprovalError(`Approval token '${token}' not found or invalid`);
    }

    if (approval.status === "EXECUTED") {
      throw new ApprovalError("This approval token has already been executed. Re-authorization required.");
    }

    if (Date.now() > approval.expiresAt || approval.status === "EXPIRED") {
      approval.status = "EXPIRED";
      this.saveToDisk();
      throw new ApprovalError(`Approval token expired at ${new Date(approval.expiresAt).toISOString()}`);
    }

    if (approval.status !== "PENDING") {
      throw new ApprovalError(`Approval token is in invalid state: ${approval.status}`);
    }

    // Strict parameter and SQL binding checks
    if (validation?.sql && validation.sql.trim() !== approval.sql.trim()) {
      throw new ApprovalError("SQL statement does not match the statement authorized for this approval token");
    }

    if (validation?.database && validation.database.toLowerCase() !== approval.database.toLowerCase()) {
      throw new ApprovalError(`Database mismatch: Approval is bound to '${approval.database}', not '${validation.database}'`);
    }

    if (validation?.params) {
      const authParamsJson = JSON.stringify(approval.params);
      const reqParamsJson = JSON.stringify(validation.params);
      if (authParamsJson !== reqParamsJson) {
        throw new ApprovalError("Query parameters do not match the parameters authorized for this approval token");
      }
    }

    // Consume token
    approval.status = "EXECUTED";
    this.saveToDisk();
    return approval;
  }

  /**
   * Logs execution record.
   */
  public recordExecution(record: ExecutionRecord): void {
    this.executions.push(record);
  }

  public getExecutionHistory(): ExecutionRecord[] {
    return [...this.executions];
  }
}
