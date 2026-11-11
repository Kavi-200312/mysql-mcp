import { MysqlClientManager } from "../connection/mysql-client.js";
import { EnvConfig } from "../config/env.js";
import { TableRelationship, TableOverview, DatabaseOverview } from "../types/database.js";
import { logAuditEvent } from "../audit/logger.js";
import crypto from "crypto";

export class DatabaseInfoTools {
  private client: MysqlClientManager;
  private config: EnvConfig;

  constructor(client: MysqlClientManager, config: EnvConfig) {
    this.client = client;
    this.config = config;
  }

  public async listDatabases(): Promise<{ databases: string[] }> {
    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    try {
      const result = await this.client.executeReadQuery<{ Database: string }>("SHOW DATABASES;");
      const dbs = result.rows.map(r => r.Database);

      logAuditEvent({
        requestId,
        toolName: "list_databases",
        database: this.config.DB_NAME,
        operationType: "METADATA",
        sql: "SHOW DATABASES;",
        durationMs: Date.now() - startTime,
        success: true
      });

      return { databases: dbs };
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "list_databases",
        database: this.config.DB_NAME,
        operationType: "METADATA",
        sql: "SHOW DATABASES;",
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }

  public async listTables(targetDb?: string): Promise<{ database: string; tables: Array<{ name: string; type: string }> }> {
    const db = targetDb || this.config.DB_NAME;
    if (db.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot list tables outside configured database '${this.config.DB_NAME}'`);
    }

    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    const sql = `SHOW FULL TABLES IN \`${db}\`;`;

    try {
      const result = await this.client.executeReadQuery<Record<string, string>>(sql);
      const tables = result.rows.map(r => {
        const keys = Object.keys(r);
        const name = r[keys[0] || ""] || "";
        const type = r[keys[1] || ""] || "BASE TABLE";
        return { name, type };
      });

      logAuditEvent({
        requestId,
        toolName: "list_tables",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: true
      });

      return { database: db, tables };
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "list_tables",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }

  public async describeTable(tableName: string, targetDb?: string): Promise<{ database: string; table: string; columns: Record<string, unknown>[] }> {
    const db = targetDb || this.config.DB_NAME;
    if (db.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot describe table outside configured database '${this.config.DB_NAME}'`);
    }

    // Sanitize identifier
    const sanitizedTable = tableName.replace(/[^a-zA-Z0-9_]/g, "");
    if (!sanitizedTable) {
      throw new Error("Invalid table name identifier");
    }

    const requestId = crypto.randomUUID();
    const startTime = Date.now();
    const sql = `DESCRIBE \`${db}\`.\`${sanitizedTable}\`;`;

    try {
      const result = await this.client.executeReadQuery(sql);

      logAuditEvent({
        requestId,
        toolName: "describe_table",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: true
      });

      return { database: db, table: sanitizedTable, columns: result.rows };
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "describe_table",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }

  public async getTableRelationships(tableName?: string, targetDb?: string): Promise<{ relationships: TableRelationship[] }> {
    const db = targetDb || this.config.DB_NAME;
    if (db.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot inspect relationships outside configured database '${this.config.DB_NAME}'`);
    }

    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    let sql = `
      SELECT 
        CONSTRAINT_NAME as constraintName,
        TABLE_NAME as tableName,
        COLUMN_NAME as columnName,
        REFERENCED_TABLE_NAME as referencedTableName,
        REFERENCED_COLUMN_NAME as referencedColumnName
      FROM information_schema.KEY_COLUMN_USAGE
      WHERE TABLE_SCHEMA = ?
        AND REFERENCED_TABLE_NAME IS NOT NULL
    `;
    const params: unknown[] = [db];

    if (tableName) {
      sql += " AND (TABLE_NAME = ? OR REFERENCED_TABLE_NAME = ?)";
      params.push(tableName, tableName);
    }

    try {
      const result = await this.client.executeReadQuery<TableRelationship>(sql, params);

      logAuditEvent({
        requestId,
        toolName: "get_table_relationships",
        database: db,
        operationType: "METADATA",
        sql,
        params,
        durationMs: Date.now() - startTime,
        success: true
      });

      return { relationships: result.rows };
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "get_table_relationships",
        database: db,
        operationType: "METADATA",
        sql,
        params,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }

  public async getDatabaseOverview(targetDb?: string): Promise<DatabaseOverview> {
    const db = targetDb || this.config.DB_NAME;
    if (db.toLowerCase() !== this.config.DB_NAME.toLowerCase()) {
      throw new Error(`Access restricted: Cannot inspect database outside configured database '${this.config.DB_NAME}'`);
    }

    const requestId = crypto.randomUUID();
    const startTime = Date.now();

    const sql = `
      SELECT 
        TABLE_NAME as name,
        COALESCE(TABLE_ROWS, 0) as rowCount,
        ROUND((DATA_LENGTH) / 1024, 2) as dataSizeKb,
        ROUND((INDEX_LENGTH) / 1024, 2) as indexSizeKb,
        COALESCE(ENGINE, '') as engine,
        COALESCE(TABLE_COLLATION, '') as collation
      FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = ?
      ORDER BY TABLE_NAME ASC;
    `;

    try {
      const result = await this.client.executeReadQuery<TableOverview>(sql, [db]);

      logAuditEvent({
        requestId,
        toolName: "get_database_overview",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: true
      });

      return {
        database: db,
        totalTables: result.rowCount,
        tables: result.rows
      };
    } catch (err: unknown) {
      logAuditEvent({
        requestId,
        toolName: "get_database_overview",
        database: db,
        operationType: "METADATA",
        sql,
        durationMs: Date.now() - startTime,
        success: false,
        error: err instanceof Error ? err.message : String(err)
      });
      throw err;
    }
  }
}
