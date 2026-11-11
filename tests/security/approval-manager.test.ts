import { describe, it, expect } from "vitest";
import { ApprovalManager, ApprovalError } from "../../src/security/approval-manager.js";

describe("Approval Manager & Gate Security Tests", () => {
  const TEST_DB = "talc_dev_db";

  it("generates approval token bound to exact SQL, params, DB and operation", () => {
    const manager = new ApprovalManager(300);
    const sql = "UPDATE users SET status = ? WHERE id = ?";
    const params = ["active", 42];

    const approval = manager.createApproval({
      sql,
      params,
      database: TEST_DB,
      table: "users",
      operation: "UPDATE",
      expectedAffectedRows: 1,
      isBulk: false
    });

    expect(approval.token).toMatch(/^appr_[a-f0-9]{40}$/);
    expect(approval.status).toBe("PENDING");
    expect(approval.expectedAffectedRows).toBe(1);

    // Validate and consume successfully
    const consumed = manager.validateAndConsume(approval.token, {
      sql,
      params,
      database: TEST_DB
    });

    expect(consumed.status).toBe("EXECUTED");
  });

  it("rejects approval consumption if SQL is modified after approval", () => {
    const manager = new ApprovalManager(300);
    const originalSql = "UPDATE users SET status = 'active' WHERE id = 1";
    const maliciousSql = "UPDATE users SET status = 'admin' WHERE id = 1";

    const approval = manager.createApproval({
      sql: originalSql,
      database: TEST_DB,
      table: "users",
      operation: "UPDATE",
      expectedAffectedRows: 1,
      isBulk: false
    });

    expect(() => {
      manager.validateAndConsume(approval.token, {
        sql: maliciousSql,
        database: TEST_DB
      });
    }).toThrowError(/SQL statement does not match/);
  });

  it("rejects approval consumption if parameters are modified after approval", () => {
    const manager = new ApprovalManager(300);
    const sql = "UPDATE users SET role = ? WHERE id = ?";

    const approval = manager.createApproval({
      sql,
      params: ["student", 10],
      database: TEST_DB,
      table: "users",
      operation: "UPDATE",
      expectedAffectedRows: 1,
      isBulk: false
    });

    expect(() => {
      manager.validateAndConsume(approval.token, {
        sql,
        params: ["superuser", 10], // Tampered parameter
        database: TEST_DB
      });
    }).toThrowError(/Query parameters do not match/);
  });

  it("rejects approval consumption if target database is changed", () => {
    const manager = new ApprovalManager(300);
    const sql = "INSERT INTO logs (event) VALUES ('login')";

    const approval = manager.createApproval({
      sql,
      database: TEST_DB,
      table: "logs",
      operation: "INSERT",
      expectedAffectedRows: 1,
      isBulk: false
    });

    expect(() => {
      manager.validateAndConsume(approval.token, {
        sql,
        database: "production_db"
      });
    }).toThrowError(/Database mismatch/);
  });

  it("rejects expired approval tokens", () => {
    const manager = new ApprovalManager(-1); // Instantly expired
    const sql = "INSERT INTO audits (action) VALUES ('test')";

    const approval = manager.createApproval({
      sql,
      database: TEST_DB,
      table: "audits",
      operation: "INSERT",
      expectedAffectedRows: 1,
      isBulk: false,
      expirySeconds: -1
    });

    expect(() => {
      manager.validateAndConsume(approval.token, {
        sql,
        database: TEST_DB
      });
    }).toThrowError(/Approval token expired/);
  });

  it("rejects re-use of an already consumed approval token", () => {
    const manager = new ApprovalManager(300);
    const sql = "INSERT INTO users (name) VALUES ('Charlie')";

    const approval = manager.createApproval({
      sql,
      database: TEST_DB,
      table: "users",
      operation: "INSERT",
      expectedAffectedRows: 1,
      isBulk: false
    });

    manager.validateAndConsume(approval.token, { sql, database: TEST_DB });

    // Second consumption attempt must fail
    expect(() => {
      manager.validateAndConsume(approval.token, { sql, database: TEST_DB });
    }).toThrowError(/already been executed/);
  });
});
