import crypto from "crypto";
import fs from "fs";
import path from "path";
import { ApprovalRequest, ExecutionRecord, WriteOperationType } from "../types/approval.js";
import { redactSensitiveParams } from "../audit/logger.js";

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
  private readonly storePath?: string;

  constructor(defaultExpirySeconds = 300, storePath?: string) {
    this.defaultExpirySeconds = defaultExpirySeconds;
    this.storePath = storePath;
    this.loadFromDisk();
  }

  private hashToken(token: string): string {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  private loadFromDisk(): void {
    if (!this.storePath) return;
    try {
      if (fs.existsSync(this.storePath)) {
        const raw = fs.readFileSync(this.storePath, "utf-8");
        const list: ApprovalRequest[] = JSON.parse(raw);
        for (const item of list) {
          if (Date.now() <= item.expiresAt + 60000) {
            this.approvals.set(item.token, item);
          }
        }
      }
    } catch {
      // Fallback silently to memory
    }
  }

  private saveToDisk(): void {
    if (!this.storePath) return;
    try {
      const dir = path.dirname(this.storePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const active = Array.from(this.approvals.values()).filter(
        a => Date.now() <= a.expiresAt + 60000
      );

      const tempFile = `${this.storePath}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tempFile, JSON.stringify(active, null, 2), "utf-8");
      fs.renameSync(tempFile, this.storePath);
    } catch {
      // Fallback silently to memory if disk write fails
    }
  }

  /**
   * Generates a unique, short-lived approval token bound to exact SQL, params, DB, and operation.
   * Stores hashed token internally to prevent exposure.
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
    isBulk: boolean;
    expirySeconds?: number;
  }): ApprovalRequest {
    this.loadFromDisk();
    const rawToken = `appr_${crypto.randomBytes(24).toString("hex")}`;
    const tokenHash = this.hashToken(rawToken);
    const now = Date.now();
    const expiryMs = (params.expirySeconds || this.defaultExpirySeconds) * 1000;

    // Redact any PII/secrets from stored preview and params
    const safePreview = params.currentValuesPreview
      ? (redactSensitiveParams(params.currentValuesPreview) as Record<string, unknown>[])
      : undefined;
    const safeParams = (redactSensitiveParams(params.params || []) as unknown[]) || [];

    const storedRequest: ApprovalRequest = {
      token: tokenHash, // Store hashed token
      sql: params.sql.trim(),
      normalizedSql: params.normalizedSql || params.sql.trim(),
      params: safeParams,
      database: params.database,
      table: params.table,
      operation: params.operation,
      expectedAffectedRows: params.expectedAffectedRows,
      currentValuesPreview: safePreview,
      isBulk: params.isBulk,
      createdAt: now,
      expiresAt: now + expiryMs,
      status: "PENDING"
    };

    this.approvals.set(tokenHash, storedRequest);
    this.saveToDisk();

    // Return request with the unhashed rawToken to the caller so they can use it as bearer token
    return {
      ...storedRequest,
      token: rawToken
    };
  }

  /**
   * Retrieves an approval request by bearer token.
   */
  public getApproval(rawToken: string): ApprovalRequest | null {
    this.loadFromDisk();
    const tokenHash = this.hashToken(rawToken);
    const approval = this.approvals.get(tokenHash);
    if (!approval) return null;

    if (Date.now() > approval.expiresAt && approval.status === "PENDING") {
      approval.status = "EXPIRED";
      this.saveToDisk();
    }

    return approval;
  }

  /**
   * Validates and marks approval token as consumed.
   * Throws an ApprovalError if expired, modified, mismatched, or already consumed.
   */
  public validateAndConsume(
    rawToken: string,
    validation?: {
      sql?: string;
      params?: unknown[];
      database?: string;
    }
  ): ApprovalRequest {
    this.loadFromDisk();
    const tokenHash = this.hashToken(rawToken);
    const approval = this.approvals.get(tokenHash);

    if (!approval) {
      throw new ApprovalError("Approval token not found or invalid");
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

    // Check parameters against authorized sanitized parameters
    if (validation?.params) {
      const sanitizedReq = redactSensitiveParams(validation.params);
      const authParamsJson = JSON.stringify(approval.params);
      const reqParamsJson = JSON.stringify(sanitizedReq);
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
   * Resets a token from EXECUTED back to PENDING if execution failed due to transient network failure.
   */
  public releaseExecutionLock(rawToken: string): void {
    const tokenHash = this.hashToken(rawToken);
    const approval = this.approvals.get(tokenHash);
    if (approval && approval.status === "EXECUTED") {
      approval.status = "PENDING";
      this.saveToDisk();
    }
  }

  public recordExecution(record: ExecutionRecord): void {
    this.executions.push(record);
  }

  public getExecutionHistory(): ExecutionRecord[] {
    return [...this.executions];
  }
}
