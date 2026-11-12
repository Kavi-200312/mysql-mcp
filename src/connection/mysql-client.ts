import mysql, { Pool, PoolOptions, FieldPacket, RowDataPacket, ResultSetHeader } from "mysql2/promise";
import fs from "fs";
import { EnvConfig } from "../config/env.js";
import { QueryResult } from "../types/database.js";
import { auditLogger } from "../audit/logger.js";

export class MysqlClientManager {
  private readerPool: Pool | null = null;
  private writerPool: Pool | null = null;
  private config: EnvConfig;

  constructor(config: EnvConfig) {
    this.config = config;
  }

  private createPoolOptions(user: string, password?: string): PoolOptions {
    const isSslRequired =
      this.config.DB_SSL === true ||
      (this.config.DB_SSL === "auto" &&
        (this.config.EFFECTIVE_DB_PORT === 25060 || this.config.DB_HOST.includes("ondigitalocean.com")));

    let sslOptions: mysql.SslOptions | undefined = undefined;

    if (isSslRequired) {
      sslOptions = {
        rejectUnauthorized: this.config.DB_SSL_REJECT_UNAUTHORIZED ?? false
      };

      if (this.config.DB_SSL_CA_PATH && fs.existsSync(this.config.DB_SSL_CA_PATH)) {
        sslOptions.ca = fs.readFileSync(this.config.DB_SSL_CA_PATH);
        if (this.config.DB_SSL_REJECT_UNAUTHORIZED === undefined) {
          sslOptions.rejectUnauthorized = true;
        }
      }
    }

    return {
      host: this.config.DB_HOST,
      port: this.config.EFFECTIVE_DB_PORT,
      database: this.config.DB_NAME,
      user,
      password: password || "",
      waitForConnections: true,
      connectionLimit: 5,
      queueLimit: 0,
      connectTimeout: 10000,
      dateStrings: true,
      timezone: "Z",
      ...(sslOptions ? { ssl: sslOptions } : {})
    };
  }

  public getReaderPool(): Pool {
    if (!this.readerPool) {
      this.readerPool = mysql.createPool(
        this.createPoolOptions(this.config.DB_READER_USER, this.config.DB_READER_PASSWORD)
      );
    }
    return this.readerPool;
  }

  public getWriterPool(): Pool {
    if (!this.writerPool) {
      this.writerPool = mysql.createPool(
        this.createPoolOptions(this.config.DB_WRITER_USER, this.config.DB_WRITER_PASSWORD)
      );
    }
    return this.writerPool;
  }

  /**
   * Applies server-side row limiting and optimizer timeout hint to protect MySQL and Node memory.
   */
  private applyServerSideLimits(sql: string, effectiveLimit: number, timeoutMs: number): string {
    let rewritten = sql.trim();

    // Check if it's a SELECT query
    if (/^\s*select\b/i.test(rewritten)) {
      // 1. Inject MySQL 8+ MAX_EXECUTION_TIME optimizer hint if not already present
      if (!/MAX_EXECUTION_TIME/i.test(rewritten)) {
        rewritten = rewritten.replace(/^\s*select\b/i, `SELECT /*+ MAX_EXECUTION_TIME(${timeoutMs}) */`);
      }

      // 2. Inject or clamp LIMIT at database level so MySQL does not return unbounded result sets
      const hasLimit = /\blimit\s+(\d+)(?:\s*,\s*(\d+)|\s+offset\s+(\d+))?\s*;?$/i.exec(rewritten);
      if (!hasLimit) {
        // Remove trailing semicolon if present and append limit
        rewritten = rewritten.replace(/;\s*$/, "") + ` LIMIT ${effectiveLimit + 1}`;
      } else {
        const currentLimit = parseInt(hasLimit[1] || "0", 10);
        if (currentLimit > effectiveLimit) {
          rewritten = rewritten.replace(/\blimit\s+\d+/i, `LIMIT ${effectiveLimit + 1}`);
        }
      }
    }

    return rewritten;
  }

  /**
   * Executes a read query safely using the reader connection pool.
   * Enforces server-side limits, database query cancellation on timeout, and payload caps.
   */
  public async executeReadQuery<T = Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
    options?: { limit?: number; timeoutMs?: number }
  ): Promise<QueryResult<T>> {
    const pool = this.getReaderPool();
    const effectiveLimit = Math.min(options?.limit || this.config.DB_MAX_ROWS, this.config.DB_MAX_ROWS);
    const timeoutMs = options?.timeoutMs || this.config.DB_QUERY_TIMEOUT_MS;

    const safeSql = this.applyServerSideLimits(sql, effectiveLimit, timeoutMs);
    const startTime = Date.now();

    // Acquire dedicated connection so we can track threadId for server-side KILL QUERY
    const conn = await pool.getConnection();
    const threadId = (conn as unknown as { threadId?: number }).threadId;

    let timer: NodeJS.Timeout | null = null;
    let isTimedOut = false;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(async () => {
        isTimedOut = true;
        // Kill the remote MySQL query server-side so it stops executing immediately
        if (threadId) {
          try {
            await pool.query(`KILL QUERY ${threadId}`);
            auditLogger.warn({ threadId, timeoutMs }, "Sent KILL QUERY to remote MySQL for timed-out query");
          } catch {
            // Thread may have already finished
          }
        }
        reject(new Error(`Query timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });

    try {
      const queryPromise = conn.query<RowDataPacket[]>(safeSql, params);
      const [rows, fields] = await Promise.race([queryPromise, timeoutPromise]);

      const executionDurationMs = Date.now() - startTime;
      const isArrayResult = Array.isArray(rows);
      const rawRows = (isArrayResult ? rows : []) as unknown as T[];

      const truncated = rawRows.length > effectiveLimit;
      const slicedRows = truncated ? rawRows.slice(0, effectiveLimit) : rawRows;

      // Check payload size
      const serialized = JSON.stringify(slicedRows);
      if (Buffer.byteLength(serialized, "utf-8") > this.config.DB_MAX_PAYLOAD_BYTES) {
        throw new Error(
          `Query result payload exceeded limit of ${this.config.DB_MAX_PAYLOAD_BYTES} bytes. Refine query with specific columns or tighter filters.`
        );
      }

      return {
        rows: slicedRows,
        rowCount: slicedRows.length,
        truncated,
        fields: ((fields as FieldPacket[]) || []).map(f => ({
          name: f.name,
          type: f.type
        })),
        executionDurationMs
      };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      auditLogger.error({ sql, durationMs: Date.now() - startTime, err: errMsg }, "Read query failed");
      throw new Error(`Database read execution error: ${errMsg}`);
    } finally {
      if (timer) clearTimeout(timer);
      if (conn) {
        if (isTimedOut) {
          conn.destroy(); // Destroy connection if timed out to avoid dirty socket state
        } else {
          conn.release();
        }
      }
    }
  }

  /**
   * Executes an approved write statement inside an atomic MySQL transaction using the writer pool.
   */
  public async executeWriteQuery(
    sql: string,
    params: unknown[] = []
  ): Promise<{ affectedRows: number; durationMs: number }> {
    const pool = this.getWriterPool();
    const startTime = Date.now();
    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [result] = await conn.execute<ResultSetHeader>(
        sql,
        params as (string | number | boolean | null)[]
      );
      const affectedRows = result?.affectedRows ?? 0;

      await conn.commit();

      const durationMs = Date.now() - startTime;
      return { affectedRows, durationMs };
    } catch (err: unknown) {
      await conn.rollback().catch(() => {});
      const errMsg = err instanceof Error ? err.message : String(err);
      auditLogger.error({ sql, err: errMsg }, "Write transaction failed and rolled back");
      throw new Error(`Write transaction failed: ${errMsg}`);
    } finally {
      conn.release();
    }
  }

  public async close(): Promise<void> {
    if (this.readerPool) {
      await this.readerPool.end().catch(() => {});
      this.readerPool = null;
    }
    if (this.writerPool) {
      await this.writerPool.end().catch(() => {});
      this.writerPool = null;
    }
  }
}
