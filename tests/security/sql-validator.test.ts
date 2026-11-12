import { describe, it, expect } from "vitest";
import { validateReadQuery, validateWriteQuery } from "../../src/security/sql-validator.js";

describe("SQL Validator & AST Parser Security Tests", () => {
  const TEST_DB = "talc_dev_db";

  describe("Read Query Operations & Safe Inspection", () => {
    it("allows standard SELECT statements", () => {
      const res = validateReadQuery("SELECT id, name, email FROM users WHERE status = 1", TEST_DB);
      expect(res.statement.type).toBe("select");
      expect(res.isExplain).toBe(false);
    });

    it("allows SHOW statements targeting current database", () => {
      const res = validateReadQuery("SHOW TABLES;", TEST_DB);
      expect(res.statement.type).toBe("show");

      const res2 = validateReadQuery(`SHOW TABLES FROM ${TEST_DB};`, TEST_DB);
      expect(res2.statement.type).toBe("show");
    });

    it("allows DESCRIBE statements targeting current database", () => {
      const res = validateReadQuery("DESCRIBE users;", TEST_DB);
      expect(res.statement.type).toBe("show");

      const res2 = validateReadQuery(`DESCRIBE ${TEST_DB}.users;`, TEST_DB);
      expect(res2.statement.type).toBe("show");
    });

    it("allows EXPLAIN statements", () => {
      const res = validateReadQuery("EXPLAIN SELECT * FROM users WHERE id = 10", TEST_DB);
      expect(res.statement.type).toBe("select");
      expect(res.isExplain).toBe(true);
    });
  });

  describe("Cross-Database Bypass Prevention (DML, Subqueries, Joins, UNION)", () => {
    it("rejects JOIN referencing external database", () => {
      expect(() => {
        validateReadQuery(`SELECT * FROM ${TEST_DB}.users u JOIN other_db.secrets s ON u.id = s.user_id`, TEST_DB);
      }).toThrowError(/Access denied: Query references database 'other_db'/);
    });

    it("rejects subquery in FROM referencing external database", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM (SELECT * FROM other_db.users) x", TEST_DB);
      }).toThrowError(/Access denied: Query references database 'other_db'/);
    });

    it("rejects UNION referencing external database", () => {
      expect(() => {
        validateReadQuery(`SELECT * FROM users UNION SELECT * FROM other_db.users`, TEST_DB);
      }).toThrowError(/Access denied: Query references database 'other_db'/);
    });

    it("rejects subquery in WHERE clause referencing external database", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM users WHERE id IN (SELECT id FROM other_db.users)", TEST_DB);
      }).toThrowError(/Access denied: Query references database 'other_db'/);
    });

    it("rejects INSERT ... SELECT referencing external database", () => {
      expect(() => {
        validateWriteQuery(`INSERT INTO ${TEST_DB}.logs SELECT * FROM other_db.users`, TEST_DB);
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects multi-table UPDATE referencing external database", () => {
      expect(() => {
        validateWriteQuery(`UPDATE ${TEST_DB}.users u JOIN other_db.secrets s ON u.id = s.id SET u.name = 'x' WHERE u.id = 1`, TEST_DB);
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects multi-table DELETE referencing external database", () => {
      expect(() => {
        validateWriteQuery(`DELETE u FROM ${TEST_DB}.users u JOIN other_db.secrets s ON u.id = s.id WHERE u.id = 1`, TEST_DB, {
          allowDelete: true
        });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });
  });

  describe("Cross-Database Bypass Prevention (SHOW & DESCRIBE)", () => {
    it("rejects SHOW TABLES FROM other_db", () => {
      expect(() => {
        validateReadQuery("SHOW TABLES FROM other_db", TEST_DB);
      }).toThrowError(/Access denied: SHOW targets database 'other_db'/);
    });

    it("rejects SHOW COLUMNS FROM other_db.users", () => {
      expect(() => {
        validateReadQuery("SHOW COLUMNS FROM other_db.users", TEST_DB);
      }).toThrowError(/Access denied: SHOW targets database 'other_db'/);
    });

    it("rejects SHOW CREATE TABLE other_db.users", () => {
      expect(() => {
        validateReadQuery("SHOW CREATE TABLE other_db.users", TEST_DB);
      }).toThrowError(/Access denied: SHOW targets database 'other_db'/);
    });

    it("rejects DESCRIBE other_db.users", () => {
      expect(() => {
        validateReadQuery("DESCRIBE other_db.users", TEST_DB);
      }).toThrowError(/Access denied: DESCRIBE targets database 'other_db'/);
    });

    it("rejects DESC other_db.users", () => {
      expect(() => {
        validateReadQuery("DESC other_db.users", TEST_DB);
      }).toThrowError(/Access denied: DESCRIBE targets database 'other_db'/);
    });
  });

  describe("Cross-Database Bypass Prevention (DDL)", () => {
    it("rejects DROP TABLE other_db.users even when allowDdl is true", () => {
      expect(() => {
        validateWriteQuery("DROP TABLE other_db.users", TEST_DB, { allowDdl: true });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects CREATE TABLE other_db.evil even when allowDdl is true", () => {
      expect(() => {
        validateWriteQuery("CREATE TABLE other_db.evil (id INT)", TEST_DB, { allowDdl: true });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects ALTER TABLE other_db.users even when allowDdl is true", () => {
      expect(() => {
        validateWriteQuery("ALTER TABLE other_db.users ADD COLUMN secret INT", TEST_DB, { allowDdl: true });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects TRUNCATE TABLE other_db.users even when allowDdl is true", () => {
      expect(() => {
        validateWriteQuery("TRUNCATE TABLE other_db.users", TEST_DB, { allowDdl: true });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });

    it("rejects RENAME TABLE to other_db even when allowDdl is true", () => {
      expect(() => {
        validateWriteQuery("RENAME TABLE users TO other_db.users", TEST_DB, { allowDdl: true });
      }).toThrowError(/Access denied: Statement targets database 'other_db'/);
    });
  });

  describe("Locking Reads Protection", () => {
    it("rejects SELECT ... FOR UPDATE on read query", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM users FOR UPDATE", TEST_DB);
      }).toThrowError(/Locking reads \(FOR UPDATE \/ LOCK IN SHARE MODE\) are prohibited/);
    });

    it("rejects SELECT ... LOCK IN SHARE MODE on read query", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM users LOCK IN SHARE MODE", TEST_DB);
      }).toThrowError(/Locking reads \(FOR UPDATE \/ LOCK IN SHARE MODE\) are prohibited/);
    });
  });

  describe("Comment Obfuscation & INTO OUTFILE Prevention", () => {
    it("rejects INTO OUTFILE even with comment obfuscation INTO/**/OUTFILE", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM users INTO/**/OUTFILE '/tmp/x'", TEST_DB);
      }).toThrowError(/INTO OUTFILE/);
    });

    it("rejects INTO DUMPFILE with block comments", () => {
      expect(() => {
        validateReadQuery("SELECT * FROM users INTO/*comment*/DUMPFILE '/tmp/x'", TEST_DB);
      }).toThrowError(/INTO OUTFILE \/ INTO DUMPFILE/);
    });

    it("rejects multi-statements embedded in comments", () => {
      expect(() => {
        validateReadQuery("SELECT 1; /*comment*/ SELECT 2;", TEST_DB);
      }).toThrowError(/Multiple SQL statements/);
    });
  });

  describe("Default Policy Safeguards", () => {
    it("rejects DELETE queries by default", () => {
      expect(() => {
        validateWriteQuery("DELETE FROM users WHERE id = 1", TEST_DB);
      }).toThrowError(/DELETE statements are disabled by policy/);
    });

    it("rejects DROP queries by default", () => {
      expect(() => {
        validateWriteQuery("DROP TABLE users", TEST_DB);
      }).toThrowError(/DDL statement \(DROP\) is disabled by policy/);
    });

    it("rejects UPDATE queries WITHOUT a WHERE clause", () => {
      expect(() => {
        validateWriteQuery("UPDATE users SET name = 'Catastrophe'", TEST_DB);
      }).toThrowError(/UPDATE without a WHERE clause is strictly prohibited/);
    });
  });
});
