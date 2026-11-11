import { describe, it, expect, vi } from "vitest";
import { redactSensitiveParams } from "../../src/audit/logger.js";
import { MysqlClientManager } from "../../src/connection/mysql-client.js";
import { EnvConfig } from "../../src/config/env.js";

describe("Row Limits, Timeouts & Audit Redaction Tests", () => {
  const dummyConfig: EnvConfig = {
    SSH_ENABLED: false,
    SSH_HOST: "127.0.0.1",
    SSH_PORT: 22,
    SSH_USER: "test",
    SSH_KEY_PATH: "",
    SSH_LOCAL_PORT: 13306,
    SSH_REMOTE_HOST: "127.0.0.1",
    SSH_REMOTE_PORT: 3306,
    DB_HOST: "127.0.0.1",
    DB_PORT: 13306,
    DB_NAME: "test_db",
    DB_READER_USER: "ai_agent_reader",
    DB_READER_PASSWORD: "secret_password",
    DB_WRITER_USER: "ai_agent_writer",
    DB_WRITER_PASSWORD: "secret_password",
    DB_QUERY_TIMEOUT_MS: 50, // Short timeout for testing
    DB_MAX_ROWS: 5, // Low max rows for testing
    DB_MAX_PAYLOAD_BYTES: 100, // Low payload limit for testing
    APPROVAL_EXPIRY_SECONDS: 300,
    BULK_AFFECTED_ROW_THRESHOLD: 10,
    LOG_LEVEL: "info"
  };

  it("redacts passwords, tokens, secrets, and keys from parameter arrays", () => {
    const rawParams = [
      "user_123",
      {
        password: "super_secret_value",
        token: "bearer_xyz123",
        email: "user@example.com",
        apiKey: "pk_live_987654321"
      },
      "plain text string"
    ];

    const redacted = redactSensitiveParams(rawParams) as [string, Record<string, unknown>, string];

    expect(redacted[0]).toBe("user_123");
    expect(redacted[1].password).toBe("[REDACTED]");
    expect(redacted[1].token).toBe("[REDACTED]");
    expect(redacted[1].apiKey).toBe("[REDACTED]");
    expect(redacted[1].email).toBe("user@example.com");
    expect(redacted[2]).toBe("plain text string");
  });

  it("truncates excessively long string parameters to prevent log bloating", () => {
    const longString = "A".repeat(500);
    const redacted = redactSensitiveParams([longString]);
    expect(typeof redacted[0]).toBe("string");
    expect((redacted[0] as string).includes("[TRUNCATED 500 chars]")).toBe(true);
  });

  it("enforces timeout when query execution exceeds configured duration", async () => {
    const client = new MysqlClientManager(dummyConfig);

    // Mock readerPool query to simulate a hanging/delayed response
    vi.spyOn(client as any, "getReaderPool").mockReturnValue({
      query: vi.fn().mockImplementation(() => {
        return new Promise(resolve => setTimeout(resolve, 200)); // takes 200ms, timeout is 50ms
      })
    });

    await expect(client.executeReadQuery("SELECT * FROM large_table")).rejects.toThrowError(
      /Query timed out after 50ms/
    );
  });

  it("enforces row count truncation when results exceed max rows limit", async () => {
    const customConfig = { ...dummyConfig, DB_MAX_PAYLOAD_BYTES: 10000 };
    const client = new MysqlClientManager(customConfig);

    // Mock readerPool returning 10 rows when limit is 5
    const mockRows = Array.from({ length: 10 }, (_, i) => ({ id: i, name: `item_${i}` }));
    vi.spyOn(client as any, "getReaderPool").mockReturnValue({
      query: vi.fn().mockResolvedValue([mockRows, []])
    });

    const result = await client.executeReadQuery("SELECT * FROM items");
    expect(result.rowCount).toBe(5);
    expect(result.truncated).toBe(true);
    expect(result.rows.length).toBe(5);
  });

  it("enforces maximum payload byte size limit", async () => {
    const client = new MysqlClientManager(dummyConfig); // DB_MAX_PAYLOAD_BYTES is 100

    // Return payload that exceeds 100 bytes
    const mockRows = [{ description: "x".repeat(200) }];
    vi.spyOn(client as any, "getReaderPool").mockReturnValue({
      query: vi.fn().mockResolvedValue([mockRows, []])
    });

    await expect(client.executeReadQuery("SELECT * FROM big_docs")).rejects.toThrowError(
      /Query result payload exceeded limit/
    );
  });
});
