import nodeSqlParser from "node-sql-parser";

const { Parser } = nodeSqlParser;
const mysqlParser = new Parser();

export interface TableReference {
  action: string;
  database?: string;
  table: string;
}

export interface ParsedStatement {
  type: string;
  ast: Record<string, unknown>;
  table: string;
  database?: string;
  allTables: TableReference[];
  hasWhereClause: boolean;
  hasLockingRead: boolean;
  hasIntoClause: boolean;
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
 * Strips block comments, line comments, and normalizes whitespace while preserving strings.
 */
export function stripComments(sql: string): string {
  // Strip block comments /* ... */
  let clean = sql.replace(/\/\*[\s\S]*?\*\//g, " ");
  // Strip line comments (-- ... and # ...)
  clean = clean.replace(/--[^\r\n]*/g, " ").replace(/#[^\r\n]*/g, " ");
  return clean.trim();
}

/**
 * Validates and parses raw SQL into a structured AST representation.
 * Strictly enforces single-statement execution, extracts all table/DB references,
 * and blocks malicious syntax patterns.
 */
export function parseAndValidateSql(sql: string, policy?: SqlParserPolicy): ParsedStatement {
  if (!sql || typeof sql !== "string") {
    throw new SqlSecurityError("SQL query must be a non-empty string");
  }

  const cleanSql = stripComments(sql);
  if (cleanSql.length === 0) {
    throw new SqlSecurityError("SQL query cannot be empty or comment-only");
  }

  // Strip quoted string literals to prevent bypasses or false positives in pre-checks
  const sqlWithoutStrings = cleanSql.replace(/'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"/g, "");

  // Pre-parse checks for dangerous keywords and escape hatches
  if (/\binto\s+(?:outfile|dumpfile)\b/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("INTO OUTFILE / INTO DUMPFILE statements are strictly prohibited");
  }

  if (/\bload\s+data\b/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("LOAD DATA INFILE statements are strictly prohibited");
  }

  if (/@{1,2}[a-zA-Z0-9_]+/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("User-defined session variables (@var, @@var) are strictly prohibited");
  }

  if (/^\s*(call|begin|commit|rollback|start\s+transaction|set|grant|revoke)\b/i.test(sqlWithoutStrings)) {
    throw new SqlSecurityError("Administrative, transaction-control, and procedure calls are prohibited");
  }

  let astResult: unknown;
  try {
    astResult = mysqlParser.astify(cleanSql, { database: "MySQL" });
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

  // Administrative commands are permanently blocked
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

  // Configurable DELETE / REPLACE protection
  if ((rawType === "delete" || rawType === "replace") && !policy?.allowDelete) {
    throw new SqlSecurityError(
      `${rawType.toUpperCase()} statements are disabled by policy. Set POLICY_ALLOW_DELETE=true in .env to allow deletions.`
    );
  }

  // Inspect AST for INTO OUTFILE / DUMPFILE
  let hasIntoClause = false;
  if (ast["into"] && typeof ast["into"] === "object") {
    const intoObj = ast["into"] as Record<string, unknown>;
    const pos = String(intoObj["position"] || "").toLowerCase();
    const kw = String(intoObj["keyword"] || "").toLowerCase();
    if (pos.includes("outfile") || pos.includes("dumpfile") || kw.includes("outfile") || kw.includes("dumpfile")) {
      throw new SqlSecurityError("INTO OUTFILE / INTO DUMPFILE statements are strictly prohibited");
    }
    hasIntoClause = true;
  }

  // Inspect locking read
  const hasLockingRead = Boolean(ast["locking_read"]);

  // Extract ALL referenced tables and databases recursively using parser.tableList
  let tableList: string[] = [];
  try {
    tableList = mysqlParser.tableList(cleanSql, { database: "MySQL" });
  } catch {
    // If tableList fails on non-standard syntax, fallback to AST extraction
    tableList = [];
  }

  const allTables: TableReference[] = tableList.map(entry => {
    const parts = entry.split("::");
    const action = parts[0] || "";
    const db = parts[1] && parts[1] !== "null" ? parts[1] : undefined;
    const tbl = parts[2] || "";
    return { action, database: db, table: tbl };
  });

  // Extract primary table and database
  const primary = extractPrimaryTable(ast, rawType, allTables);

  const hasWhere = Boolean(ast["where"]);

  return {
    type: rawType,
    ast,
    table: primary.table,
    ...(primary.database ? { database: primary.database } : {}),
    allTables,
    hasWhereClause: hasWhere,
    hasLockingRead,
    hasIntoClause,
    rawSql: cleanSql
  };
}

function extractPrimaryTable(
  ast: Record<string, unknown>,
  type: string,
  allTables: TableReference[]
): { table: string; database?: string } {
  // If tableList found entries, the first relevant write/read target is usually the primary
  if (allTables.length > 0) {
    const matching = allTables.find(t => t.table.length > 0);
    if (matching) {
      return { table: matching.table, database: matching.database };
    }
  }

  let tableName = "";
  let dbName: string | undefined = undefined;

  if (type === "select" || type === "delete") {
    const from = ast["from"];
    if (Array.isArray(from) && from.length > 0) {
      const first = from[0] as Record<string, unknown>;
      tableName = typeof first["table"] === "string" ? first["table"] : "";
      if (typeof first["db"] === "string") dbName = first["db"];
    }
  } else if (type === "insert" || type === "update" || type === "replace") {
    const tbl = ast["table"];
    if (Array.isArray(tbl) && tbl.length > 0) {
      const first = tbl[0] as Record<string, unknown>;
      tableName = typeof first["table"] === "string" ? first["table"] : "";
      if (typeof first["db"] === "string") dbName = first["db"];
    }
  }

  return { table: tableName, database: dbName };
}
