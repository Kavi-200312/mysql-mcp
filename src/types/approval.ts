export type WriteOperationType =
  | "INSERT"
  | "UPDATE"
  | "DELETE"
  | "REPLACE"
  | "CREATE"
  | "ALTER"
  | "DROP"
  | "TRUNCATE"
  | "RENAME";

export type ApprovalStatus = "PENDING" | "EXECUTED" | "EXPIRED" | "CANCELLED";

export interface ApprovalRequest {
  token: string;
  sql: string;
  normalizedSql: string;
  params: unknown[];
  database: string;
  table: string;
  operation: WriteOperationType;
  expectedAffectedRows: number;
  currentValuesPreview?: Record<string, unknown>[];
  proposedChangesPreview?: Record<string, unknown> | Record<string, unknown>[];
  isBulk: boolean;
  createdAt: number;
  expiresAt: number;
  status: ApprovalStatus;
}

export interface ExecutionRecord {
  token: string;
  sql: string;
  database: string;
  operation: WriteOperationType;
  affectedRows: number;
  durationMs: number;
  success: boolean;
  executedAt: number;
  error?: string;
}
