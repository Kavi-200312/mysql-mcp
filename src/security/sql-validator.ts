import { parseAndValidateSql, stripComments, ParsedStatement, SqlSecurityError, SqlParserPolicy } from "./sql-parser.js";
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
 * Validates SHOW and DESCRIBE statements, ensuring target database qualifications
 * strictly match the configured database.
 */
function validateShowOrDescribe(sql: string, configuredDatabase: string): ValidatedReadQuery | null {
  const clean = stripComments(sql).trim();

  // Fast pattern checks
  const isDesc = /^(?:describe|desc)\b/i.test(clean);
  const isShow = /^show\b/i.test(clean);

  if (!isDesc && !isShow) {
    return null;
  }

  // Multiple statements check
  if (clean.includes(";")) {
    const parts = clean.split(";").map(p => p.trim()).filter(Boolean);
    if (parts.length > 1) {
      throw new SqlSecurityError("Multiple statements are prohibited");
    }
  }

  // Handle DESCRIBE / DESC
  if (isDesc) {
    const descMatch = clean.match(/^(?:describe|desc)\s+(?:`?([a-zA-Z0-9_]+)`?\.)?`?([a-zA-Z0-9_]+)`?/i);
    if (!descMatch) {
      throw new SqlSecurityError("Invalid DESCRIBE syntax");
    }

    const db = descMatch[1];
    const table = descMatch[2] || "";

    if (db && db.toLowerCase() !== configuredDatabase.toLowerCase()) {
      throw new SqlSecurityError(
        `Access denied: DESCRIBE targets database '${db}', but server is restricted to '${configuredDatabase}'`
      );
    }

    return {
      statement: {
        type: "show",
        ast: {},
        table,
        ...(db ? { database: db } : {}),
        allTables: [{ action: "describe", database: db, table }],
        hasWhereClause: false,
        hasLockingRead: false,
        hasIntoClause: false,
        rawSql: clean
      },
      isExplain: false
    };
  }

  // Handle SHOW
  const safeShowPatterns = /^\s*show\s+(?:tables|databases|columns|fields|index|keys|create\s+table|table\s+status|variables|status)\b/i;
  if (!safeShowPatterns.test(clean)) {
    throw new SqlSecurityError("Unsupported or prohibited SHOW statement");
  }

  let targetDb: string | undefined = undefined;

  // Extract explicit database qualifiers if present:
  // 1. Any qualified table identifier: <db>.<table> (e.g. SHOW CREATE TABLE other_db.users, SHOW COLUMNS FROM other_db.users)
  const dotDbMatch = clean.match(/\b(?:table|view|from|in)\s+`?([a-zA-Z0-9_]+)`?\.`?([a-zA-Z0-9_]+)`?/i) ||
                     clean.match(/\b`?([a-zA-Z0-9_]+)`?\.`?([a-zA-Z0-9_]+)`?/i);
  if (dotDbMatch) {
    targetDb = dotDbMatch[1];
  }

  // 2. SHOW TABLES FROM <db> / SHOW TABLES IN <db>
  if (!targetDb) {
    const fromDbMatch = clean.match(/\bshow\s+(?:tables|table\s+status)\s+(?:from|in)\s+`?([a-zA-Z0-9_]+)`?/i);
    if (fromDbMatch) {
      targetDb = fromDbMatch[1];
    }
  }

  // 3. SHOW COLUMNS FROM <table> FROM <db>
  if (!targetDb) {
    const secondFromMatch = clean.match(/\b(?:from|in)\s+`?[a-zA-Z0-9_]+`?\s+(?:from|in)\s+`?([a-zA-Z0-9_]+)`?/i);
    if (secondFromMatch) {
      targetDb = secondFromMatch[1];
    }
  }

  if (targetDb && targetDb.toLowerCase() !== configuredDatabase.toLowerCase()) {
    throw new SqlSecurityError(
      `Access denied: SHOW targets database '${targetDb}', but server is restricted to '${configuredDatabase}'`
    );
  }

  return {
    statement: {
      type: "show",
      ast: {},
      table: "",
      ...(targetDb ? { database: targetDb } : {}),
      allTables: targetDb ? [{ action: "show", database: targetDb, table: "" }] : [],
      hasWhereClause: false,
      hasLockingRead: false,
      hasIntoClause: false,
      rawSql: clean
    },
    isExplain: false
  };
}

/**
 * Validates read queries (SELECT, SHOW, DESCRIBE, EXPLAIN).
 * Rejects any writes, locking reads, or queries crossing outside configured database.
 */
export function validateReadQuery(
  sql: string,
  configuredDatabase: string,
  policy?: SqlParserPolicy
): ValidatedReadQuery {
  const clean = stripComments(sql);

  // Check SHOW / DESCRIBE
  const showResult = validateShowOrDescribe(clean, configuredDatabase);
  if (showResult) {
    return showResult;
  }

  // Handle EXPLAIN queries
  const isExplain = /^\s*explain\s+/i.test(clean);
  const sqlToParse = isExplain ? clean.replace(/^\s*explain\s+/i, "") : clean;

  const statement = parseAndValidateSql(sqlToParse, policy);

  if (statement.type !== "select") {
    throw new SqlSecurityError(
      `Read queries only allow SELECT, SHOW, DESCRIBE, or EXPLAIN. Detected: ${statement.type.toUpperCase()}`
    );
  }

  // Prohibit locking reads on the read-only path
  if (statement.hasLockingRead) {
    throw new SqlSecurityError(
      "Locking reads (FOR UPDATE / LOCK IN SHARE MODE) are prohibited on read queries"
    );
  }

  // Cross-database validation: check every referenced table across all subqueries, joins, and unions
  for (const ref of statement.allTables) {
    if (ref.database && ref.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
      throw new SqlSecurityError(
        `Access denied: Query references database '${ref.database}', but server is strictly restricted to '${configuredDatabase}'`
      );
    }
  }

  if (statement.database && statement.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
    throw new SqlSecurityError(
      `Access denied: Query references database '${statement.database}', but server is strictly restricted to '${configuredDatabase}'`
    );
  }

  return {
    statement,
    isExplain
  };
}

/**
 * Validates write queries (INSERT, UPDATE, DELETE, REPLACE, and DDL according to policy).
 * Recursively enforces cross-database boundaries across all referenced tables.
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
    "REPLACE",
    "CREATE",
    "ALTER",
    "DROP",
    "TRUNCATE",
    "RENAME"
  ];

  if (!validOperations.includes(rawType as WriteOperationType)) {
    throw new SqlSecurityError(`Unsupported write operation type: ${rawType}`);
  }

  const operation = rawType as WriteOperationType;

  // Cross-database validation across all referenced tables/subqueries
  for (const ref of statement.allTables) {
    if (ref.database && ref.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
      throw new SqlSecurityError(
        `Access denied: Statement targets database '${ref.database}', but server is strictly restricted to '${configuredDatabase}'`
      );
    }
  }

  if (statement.database && statement.database.toLowerCase() !== configuredDatabase.toLowerCase()) {
    throw new SqlSecurityError(
      `Access denied: Statement targets database '${statement.database}', but server is strictly restricted to '${configuredDatabase}'`
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
  } else if ((operation === "DELETE" || operation === "REPLACE") && policy?.autoApproveDelete) {
    isAutoApproved = true;
  } else if (
    ["CREATE", "ALTER", "DROP", "TRUNCATE", "RENAME"].includes(operation) &&
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
