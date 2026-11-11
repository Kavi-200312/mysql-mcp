import nodeSqlParser from "node-sql-parser";

const { Parser } = nodeSqlParser;
const mysqlParser = new Parser();

export interface ParsedStatement {
  type: string;
  ast: Record<string, unknown>;
  table: string;
  database?: string;
  hasWhereClause: boolean;
  rawSql: string;
}

export class SqlSecurityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SqlSecurityError";
  }
}

export interface SqlParserPolicy {
  allowDelete?: boolean;
  allowDdl?: boolean;
}

/**
 * Validates and parses raw SQL into a structured AST representation.
 * Strictly enforces single-statement execution and blocks malicious syntax patterns.
 */
export function parseAndValidateSql(sql: string, policy?: SqlParserPolicy): ParsedStatement {
  if (!sql || typeof sql !== "string") {
    throw new SqlSecurityError("SQL query must be a non-empty string");
  }

  const trimmed = sql.trim();
  if (trimmed.length === 0) {
    throw new SqlSecurityError("SQL query cannot be empty or whitespace");
  }

  // Strip quoted string literals to avoid false positives on email addresses or text content
  const sqlWithoutStrings = trimmed.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, "");

  // Pre-parse checks on SQL code structure (excluding literal contents)
  if (/into\s+(outfile|dumpfile)/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("INTO OUTFILE / INTO DUMPFILE statements are strictly prohibited");
  }

  if (/load\s+data/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("LOAD DATA INFILE statements are strictly prohibited");
  }

  if (/@{1,2}[a-zA-Z0-9_]+/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("User-defined session variables (@var, @@var) are strictly prohibited");
  }

  if (/^\s*(call|begin|commit|rollback|start\s+transaction|set|grant|revoke)/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("Administrative, transaction-control, and procedure calls are prohibited");
  }

  let astResult: unknown;
  try {
    astResult = mysqlParser.astify(trimmed, { database: "MySQL" });
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    throw new SqlSecurityError(`SQL Syntax error or unparseable query: ${errorMsg}`);
  }

  // Multiple statements check: node-sql-parser returns an Array if multiple queries are detected
  if (Array.isArray(astResult)) {
    if (astResult.length > 1) {
      throw new SqlSecurityError("Multiple SQL statements in a single execution are strictly prohibited");
    }
    astResult = astResult[0];
  }

  if (!astResult || typeof astResult !== "object") {
    throw new SqlSecurityError("Failed to parse valid SQL AST structure");
  }

  const ast = astResult as Record<string, unknown>;
  const rawType = typeof ast["type"] === "string" ? (ast["type"] as string).toLowerCase() : "";

  // Administrative / privilege escalation commands are permanently blocked
  const permanentlyProhibited = ["lock", "unlock", "grant", "revoke", "use"];
  if (permanentlyProhibited.includes(rawType)) {
    throw new SqlSecurityError(`Prohibited SQL operation type: ${rawType.toUpperCase()}`);
  }

  // Configurable DDL protection
  const ddlTypes = ["drop", "truncate", "alter", "create", "rename"];
  if (ddlTypes.includes(rawType) && !policy?.allowDdl) {
    throw new SqlSecurityError(
      `DDL statement (${rawType.toUpperCase()}) is disabled by policy. Set POLICY_ALLOW_DDL=true in .env to allow DDL operations.`
    );
  }

  // Configurable DELETE protection
  if ((rawType === "delete" || rawType === "replace") && !policy?.allowDelete) {
    throw new SqlSecurityError(
      `DELETE / REPLACE statements are disabled by policy. Set POLICY_ALLOW_DELETE=true in .env to allow deletions.`
    );
  }

  // Extract primary table and database from AST
  const { table, database } = extractTargetTable(ast, rawType);

  // Check WHERE clause
  const hasWhere = Boolean(ast["where"]);

  return {
    type: rawType,
    ast,
    table,
    ...(database ? { database } : {}),
    hasWhereClause: hasWhere,
    rawSql: trimmed
  };
}

function extractTargetTable(ast: Record<string, unknown>, type: string): { table: string; database?: string } {
  let tableName = "";
  let dbName: string | undefined = undefined;

  if (type === "select" || type === "delete") {
    const from = ast["from"];
    if (Array.isArray(from) && from.length > 0) {
      const firstFrom = from[0] as Record<string, unknown>;
      tableName = typeof firstFrom["table"] === "string" ? firstFrom["table"] : "";
      if (typeof firstFrom["db"] === "string") {
        dbName = firstFrom["db"];
      }
    }
  } else if (type === "insert") {
    const tableField = ast["table"];
    if (Array.isArray(tableField) && tableField.length > 0) {
      const first = tableField[0] as Record<string, unknown>;
      tableName = typeof first["table"] === "string" ? first["table"] : "";
      if (typeof first["db"] === "string") {
        dbName = first["db"];
      }
    }
  } else if (type === "update") {
    const tableField = ast["table"];
    if (Array.isArray(tableField) && tableField.length > 0) {
      const first = tableField[0] as Record<string, unknown>;
      tableName = typeof first["table"] === "string" ? first["table"] : "";
      if (typeof first["db"] === "string") {
        dbName = first["db"];
      }
    }
  }

  return { table: tableName, database: dbName };
}
