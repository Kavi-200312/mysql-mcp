import { parseAndValidateSql, ParsedStatement, SqlSecurityError, SqlParserPolicy } from "./sql-parser.js";
import { WriteOperationType } from "../types/approval.js";

export interface ValidatedReadQuery {
  statement: ParsedStatement;
  isExplain: boolean;
}

export interface SecurityPolicyOptions extends SqlParserPolicy {
  requireWhere?: boolean;
  autoApproveInsert?: boolean;
  autoApproveUpdate?: boolean;
  autoApproveDelete?: boolean;
  autoApproveDdl?: boolean;
  policyMode?: "strict" | "prompt" | "autonomous";
}

export interface ValidatedWriteQuery {
  statement: ParsedStatement;
  operation: WriteOperationType;
  table: string;
  database: string;
  requiresWhereCheck: boolean;
  isAutoApproved: boolean;
}

/**
 * Validates read queries (SELECT, SHOW, DESCRIBE, EXPLAIN).
 * Rejects any writes or queries crossing outside configured database.
 */
export function validateReadQuery(
  sql: string,
  configuredDatabase: string,
  policy?: SqlParserPolicy
): ValidatedReadQuery {
  const trimmed = sql.trim();

  // Fast-track SHOW and DESCRIBE statements that some AST parsers treat as special commands
  if (/^\s*(show\s+|describe\s+|desc\s+)/i.test(trimmed)) {
    // Ensure no multiple statements exist
    if (trimmed.includes(";")) {
      const parts = trimmed.split(";").map(p => p.trim()).filter(Boolean);
      if (parts.length > 1) {
        throw new SqlSecurityError("Multiple statements are prohibited");
      }
    }

    // Verify safe SHOW / DESCRIBE patterns
    if (
      !/^\s*(show\s+(tables|databases|columns|fields|index|keys|create\s+table|table\s+status|variables|status)|describe\s+[a-zA-Z0-9_`]+|desc\s+[a-zA-Z0-9_`]+)/i.test(
        trimmed
      )
    ) {
      throw new SqlSecurityError("Unsupported or prohibited SHOW / DESCRIBE statement");
    }

    return {
      statement: {
        type: "show",
        ast: {},
        table: "",
        hasWhereClause: false,
        rawSql: trimmed
      },
      isExplain: false
    };
  }

  // Handle EXPLAIN queries
  const isExplain = /^\s*explain\s+/i.test(trimmed);
  const sqlToParse = isExplain ? trimmed.replace(/^\s*explain\s+/i, "") : trimmed;

  const statement = parseAndValidateSql(sqlToParse, policy);

  if (statement.type !== "select") {
    throw new SqlSecurityError(
      `Read queries only allow SELECT, SHOW, DESCRIBE, or EXPLAIN. Detected: ${statement.type.toUpperCase()}`
    );
  }

  if (statement.database && statement.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
    throw new SqlSecurityError(
      `Access denied: Query references database '${statement.database}', but server is restricted to '${configuredDatabase}'`
    );
  }

  return {
    statement,
    isExplain
  };
}

/**
 * Validates write queries (INSERT, UPDATE, DELETE, and DDL according to policy).
 */
export function validateWriteQuery(
  sql: string,
  configuredDatabase: string,
  policy?: SecurityPolicyOptions
): ValidatedWriteQuery {
  const statement = parseAndValidateSql(sql, {
    allowDelete: policy?.allowDelete,
    allowDdl: policy?.allowDdl
  });

  const rawType = statement.type.toUpperCase();
  const validOperations: WriteOperationType[] = [
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "ALTER",
    "DROP",
    "TRUNCATE"
  ];

  if (!validOperations.includes(rawType as WriteOperationType)) {
    throw new SqlSecurityError(`Unsupported write operation type: ${rawType}`);
  }

  const operation = rawType as WriteOperationType;

  if (statement.database && statement.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
    throw new SqlSecurityError(
      `Access denied: Statement targets database '${statement.database}', but server is restricted to '${configuredDatabase}'`
    );
  }

  const requireWhere = policy?.requireWhere !== false;
  if ((operation === "UPDATE" || operation === "DELETE") && requireWhere && !statement.hasWhereClause) {
    throw new SqlSecurityError(
      `${operation} without a WHERE clause is strictly prohibited to prevent catastrophic data loss. Set POLICY_REQUIRE_WHERE=false to override.`
    );
  }

  // Check auto-approve status
  let isAutoApproved = false;
  if (policy?.policyMode === "autonomous") {
    isAutoApproved = true;
  } else if (operation === "INSERT" && policy?.autoApproveInsert) {
    isAutoApproved = true;
  } else if (operation === "UPDATE" && policy?.autoApproveUpdate) {
    isAutoApproved = true;
  } else if (operation === "DELETE" && policy?.autoApproveDelete) {
    isAutoApproved = true;
  } else if (
    ["CREATE", "ALTER", "DROP", "TRUNCATE"].includes(operation) &&
    policy?.autoApproveDdl
  ) {
    isAutoApproved = true;
  }

  return {
    statement,
    operation,
    table: statement.table || "schema",
    database: statement.database || configuredDatabase,
    requiresWhereCheck: (operation === "UPDATE" || operation === "DELETE") && requireWhere,
    isAutoApproved
  };
}
