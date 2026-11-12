import pino from "pino";

// CRITICAL for stdio MCP: stdout is exclusively reserved for JSON-RPC messages.
// All application and audit logs MUST be directed to stderr or a dedicated stream.
export const auditLogger = pino(
  {
    level: process.env["LOG_LEVEL"] || "info",
    timestamp: pino.stdTimeFunctions.isoTime,
    formatters: {
      level(label) {
        return { level: label };
      }
    },
    redact: {
      paths: [
        "password",
        "*.password",
        "secret",
        "*.secret",
        "token",
        "*.token",
        "approvalToken",
        "*.approvalToken",
        "key",
        "*.key",
        "privateKey",
        "*.privateKey",
        "credentials",
        "*.credentials"
      ],
      censor: "[REDACTED]"
    }
  },
  process.stderr
);

export interface AuditEvent {
  requestId: string;
  toolName: string;
  database: string;
  operationType: string;
  sql: string;
  params?: unknown[];
  approvalToken?: string;
  approvalStatus?: string;
  affectedRows?: number;
  durationMs: number;
  success: boolean;
  error?: string;
}

/**
 * Deep recursive parameter and PII sanitizer.
 */
export function redactSensitiveParams(param: unknown): unknown {
  if (param === null || param === undefined) return param;

  if (Array.isArray(param)) {
    return param.map(item => redactSensitiveParams(item));
  }

  if (typeof param === "object") {
    const copy: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(param as Record<string, unknown>)) {
      if (/password|secret|token|key|credit|auth|hash|pin|cvv|ssn|authorization/i.test(k)) {
        copy[k] = "[REDACTED]";
      } else {
        copy[k] = redactSensitiveParams(v);
      }
    }
    return copy;
  }

  if (typeof param === "string") {
    if (param.length > 256) {
      return `${param.substring(0, 32)}...[TRUNCATED ${param.length} chars]`;
    }
    // Redact tokens in raw strings
    if (/^appr_[a-f0-9]{40,}$/i.test(param) || /^Bearer\s+/i.test(param)) {
      return "[REDACTED]";
    }
  }

  return param;
}

export function logAuditEvent(event: AuditEvent): void {
  const safeEvent = {
    ...event,
    approvalToken: event.approvalToken ? "[REDACTED]" : undefined,
    params: Array.isArray(event.params)
      ? (redactSensitiveParams(event.params) as unknown[])
      : []
  };

  if (event.success) {
    auditLogger.info(safeEvent, `[AUDIT] Tool executed: ${event.toolName} (${event.operationType})`);
  } else {
    auditLogger.error(safeEvent, `[AUDIT] Tool failed: ${event.toolName} (${event.operationType})`);
  }
}
