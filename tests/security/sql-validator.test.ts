import { describe, it, expect } from "vitest";
import { validateReadQuery, validateWriteQuery } from "../../src/security/sql-validator.js";
import { SqlSecurityError } from "../../src/security/sql-parser.js";

describe("SQL Validator & AST Parser Security Tests", () => {
  const TEST_DB = "talc_dev_db";

  describe("Read Query Operations", () => {
    it("allows standard SELECT statements", () => {
      const res = validateReadQuery("SELECT id, name, email FROM users WHERE status = 1", TEST_DB);
      expect(res.statement.type).toBe("select");
      expect(res.isExplain).toBe(false);
    });

    it("allows SHOW statements", () => {
      const res = validateReadQuery("SHOW TABLES;", TEST_DB);
      expect(res.statement.type).toBe("show");
    });

    it("allows DESCRIBE statements", () => {
      const res = validateReadQuery("DESCRIBE users;", TEST_DB);
      expect(res.statement.type).toBe("show");
    });

    it("allows EXPLAIN statements", () => {
      const res = validateReadQuery("EXPLAIN SELECT * FROM users WHERE id = 10", TEST_DB);
      expect(res.statement.type).toBe("select");
      expect(res.isExplain).toBe(true);
    });

    it("rejects read queries targeting a different database", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM production_db.users", TEST_DB);
      }).toThrowError(SqlSecurityError);
    });

    it("rejects multiple statements in read query", () => {
      expect(() => {
        validateReadQuery("SELECT 1; SELECT 2;", TEST_DB);
      }).toThrowError(/Multiple SQL statements/);
    });
  });

  describe("Default Strict Policy (Destructive Operations Blocked)", () => {
    it("rejects DELETE queries by default", () => {
      expect(() => {
        validateWriteQuery("DELETE FROM users WHERE id = 1", TEST_DB);
      }).toThrowError(/DELETE \/ REPLACE statements are disabled by policy/);
    });

    it("rejects DROP queries by default", () => {
      expect(() => {
        validateWriteQuery("DROP TABLE users", TEST_DB);
      }).toThrowError(/DDL statement \(DROP\) is disabled by policy/);
    });

    it("rejects TRUNCATE queries by default", () => {
      expect(() => {
        validateWriteQuery("TRUNCATE TABLE users", TEST_DB);
      }).toThrowError(/DDL statement \(TRUNCATE\) is disabled by policy/);
    });

    it("rejects ALTER queries by default", () => {
      expect(() => {
        validateWriteQuery("ALTER TABLE users ADD COLUMN phone VARCHAR(20)", TEST_DB);
      }).toThrowError(/DDL statement \(ALTER\) is disabled by policy/);
    });

    it("rejects CREATE queries by default", () => {
      expect(() => {
        validateWriteQuery("CREATE TABLE rogue (id INT)", TEST_DB);
      }).toThrowError(/DDL statement \(CREATE\) is disabled by policy/);
    });
  });

  describe("Custom Configurable Policy (Opt-in Permissions)", () => {
    it("allows DELETE with WHERE when POLICY_ALLOW_DELETE=true", () => {
      const res = validateWriteQuery("DELETE FROM users WHERE id = 10", TEST_DB, {
        allowDelete: true,
        requireWhere: true
      });
      expect(res.operation).toBe("DELETE");
      expect(res.table).toBe("users");
    });

    it("rejects DELETE without WHERE even when DELETE is allowed", () => {
      expect(() => {
        validateWriteQuery("DELETE FROM users", TEST_DB, {
          allowDelete: true,
          requireWhere: true
        });
      }).toThrowError(/DELETE without a WHERE clause is strictly prohibited/);
    });

    it("allows CREATE and ALTER when POLICY_ALLOW_DDL=true", () => {
      const createRes = validateWriteQuery("CREATE TABLE audit_log (id INT, log TEXT)", TEST_DB, {
        allowDdl: true
      });
      expect(createRes.operation).toBe("CREATE");

      const alterRes = validateWriteQuery("ALTER TABLE users ADD COLUMN phone VARCHAR(20)", TEST_DB, {
        allowDdl: true
      });
      expect(alterRes.operation).toBe("ALTER");
    });

    it("correctly identifies auto-approved operations when configured", () => {
      const normal = validateWriteQuery("INSERT INTO users (name) VALUES ('Bob')", TEST_DB, {
        autoApproveInsert: false
      });
      expect(normal.isAutoApproved).toBe(false);

      const auto = validateWriteQuery("INSERT INTO users (name) VALUES ('Bob')", TEST_DB, {
        autoApproveInsert: true
      });
      expect(auto.isAutoApproved).toBe(true);

      const autonomous = validateWriteQuery("UPDATE users SET name = 'Bob' WHERE id = 1", TEST_DB, {
        policyMode: "autonomous"
      });
      expect(autonomous.isAutoApproved).toBe(true);
    });
  });

  describe("Permanent Exploit Blocks (Never Bypassed Even With Permissive Policies)", () => {
    it("permanently rejects INTO OUTFILE and INTO DUMPFILE", () => {
      expect(() => {
        validateWriteQuery("SELECT * FROM users INTO OUTFILE '/tmp/dump.txt'", TEST_DB, {
          allowDdl: true,
          allowDelete: true,
          policyMode: "autonomous"
        });
      }).toThrowError(/INTO OUTFILE/);
    });

    it("permanently rejects user session variables (@var, @@var)", () => {
      expect(() => {
        validateWriteQuery("SELECT @admin_pass FROM users", TEST_DB, {
          allowDdl: true,
          allowDelete: true,
          policyMode: "autonomous"
        });
      }).toThrowError(/session variables/);
    });

    it("permanently rejects multiple statements", () => {
      expect(() => {
        validateWriteQuery("INSERT INTO users (name) VALUES ('A'); DROP TABLE users;", TEST_DB, {
          allowDdl: true,
          allowDelete: true,
          policyMode: "autonomous"
        });
      }).toThrowError(/Multiple SQL statements/);
    });

    it("strictly rejects UPDATE queries WITHOUT a WHERE clause", () => {
      expect(() => {
        validateWriteQuery("UPDATE users SET name = 'Catastrophe'", TEST_DB);
      }).toThrowError(/UPDATE without a WHERE clause is strictly prohibited/);
    });
  });
});
