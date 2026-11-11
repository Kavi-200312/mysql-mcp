<div align="center">

# 🛡️ Secure MySQL MCP Server

**The enterprise-grade, AST-guarded Model Context Protocol (MCP) server for MySQL.**  
Works seamlessly with **Antigravity**, **Claude Code**, **Cursor**, **Devin**, **Codex**, and any MCP client.

[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP%20Spec-2024--11--05-orange.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-30%20passed-success.svg)]()

</div>

---

## 🌟 Why This MCP Server?

Standard off-the-shelf MySQL MCP servers blindly execute any raw SQL string passed by the AI agent — allowing unintended table drops, mass updates without `WHERE` clauses, or data corruption.

**Secure MySQL MCP** solves this by putting a **protective AST parser, configurable permission gate, and automated SSH tunnel** directly between the AI and your database.

```
AI Coding Agent (Antigravity / Claude / Cursor / Devin)
    │
    ▼ (stdio JSON-RPC)
Secure MySQL MCP Server
    ├── 🔍 AST SQL Parser (node-sql-parser)
    │     ├── Blocks multi-statements, INTO OUTFILE, session variables
    │     └── Enforces WHERE clauses on UPDATE and DELETE
    ├── 🚦 Configurable Policy Engine (Strict / Prompt / Autonomous)
    │     ├── Safe by default (Blocks DROP, TRUNCATE, DELETE, DDL)
    │     └── Granular opt-in auto-approval flags
    ├── 🔐 Dual Pool Isolation
    │     ├── ai_agent_reader (SELECT, SHOW VIEW only)
    │     └── ai_agent_writer (INSERT, UPDATE, DELETE in atomic transactions)
    └── 📜 Pino Structured Audit Logger (Auto-redacts credentials & keys)
    │
    ▼ (127.0.0.1:13306 or Direct SSL)
SSH Tunnel / Cloud Database (DigitalOcean, AWS RDS, GCP Cloud SQL, Self-hosted VPS)
```

---

## 🚀 Key Features

- **🛡️ Safe by Default:** Destructive statements (`DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `CREATE`) are blocked out of the box.
- **⚡ Fully Customizable Autonomy:** Want the AI to write without asking permission? Switch `POLICY_MODE=autonomous` or toggle granular flags (`POLICY_AUTO_APPROVE_INSERT=true`, `POLICY_ALLOW_DELETE=true`).
- **🛑 No Full-Table Accidents:** AST parser rejects `UPDATE` or `DELETE` without a `WHERE` clause.
- **🔒 Anti-Injection Guardrails:** Permanently eliminates `INTO OUTFILE`, `LOAD DATA INFILE`, user session variable tampering (`@var`), and chained multi-statements.
- **🔑 Built-in SSH Tunnel:** Automatically provisions and tears down a local SSH tunnel (`ssh -N -L`) or connects directly via TLS/SSL.
- **👥 Least-Privilege Architecture:** Dual connection pools route reads to a read-only DB user and writes to a write-restricted DB user.
- **📊 10 Powerful Tools:** 7 inspection & query tools, plus 3 write tools (`propose_write`, `write_query`, `execute_approved_write`).

---

## 📦 Quick Installation

### Option 1: Run with `npx` (No installation needed)

```bash
npx mysql-mcp
```

### Option 2: Clone and Build Locally

```bash
git clone https://github.com/your-username/mysql-mcp.git
cd mysql-mcp
npm install
npm run build
npm test
```

---

## 🤖 Client Setup Guides

### 1. Antigravity Setup
Add to `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "mysql": {
      "command": "node",
      "args": ["/path/to/mysql-mcp/dist/index.js"]
    }
  }
}
```

### 2. Claude Desktop / Claude Code Setup
Add to `claude_desktop_config.json` (Mac: `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows: `%APPDATA%\Claude\claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "mysql": {
      "command": "node",
      "args": ["/path/to/mysql-mcp/dist/index.js"],
      "env": {
        "DB_HOST": "127.0.0.1",
        "DB_PORT": "3306",
        "DB_NAME": "my_database",
        "DB_READER_USER": "ai_agent_reader",
        "DB_READER_PASSWORD": "your_password",
        "DB_WRITER_USER": "ai_agent_writer",
        "DB_WRITER_PASSWORD": "your_password"
      }
    }
  }
}
```

### 3. Cursor Setup
In Cursor, go to **Settings > Features > MCP**, click **Add New MCP Server**:
- **Name:** `mysql`
- **Type:** `command`
- **Command:** `node /path/to/mysql-mcp/dist/index.js`

Or add to `.cursor/mcp.json` in your workspace:

```json
{
  "mcpServers": {
    "mysql": {
      "command": "node",
      "args": ["/path/to/mysql-mcp/dist/index.js"]
    }
  }
}
```

### 4. Devin Setup
Add to your Devin machine configuration or `devin.json`:

```json
{
  "mcpServers": {
    "mysql": {
      "command": "node",
      "args": ["/path/to/mysql-mcp/dist/index.js"]
    }
  }
}
```

---

## ⚙️ Configuration Reference (`.env`)

Copy `.env.example` to `.env` in the project root:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| **Database Connection** | | |
| `DB_HOST` | `127.0.0.1` | MySQL server host (or localhost if using SSH tunnel) |
| `DB_PORT` | `3306` | MySQL port (e.g. `25060` for DigitalOcean, `3306` standard) |
| `DB_NAME` | `""` | Target development database name |
| `DB_SSL` | `auto` | `true`, `false`, or `auto` (auto-enables SSL for port 25060 or cloud hosts) |
| `DB_READER_USER` | `ai_agent_reader` | Least-privilege user for read tools |
| `DB_READER_PASSWORD` | `""` | Password for reader user |
| `DB_WRITER_USER` | `ai_agent_writer` | Dedicated user for write tools |
| `DB_WRITER_PASSWORD` | `""` | Password for writer user |
| **SSH Tunneling** | | |
| `SSH_ENABLED` | `false` | Set to `true` to tunnel connections through a remote VPS/Droplet |
| `SSH_HOST` | `""` | Remote SSH IP or hostname |
| `SSH_PORT` | `22` | Remote SSH port |
| `SSH_USER` | `""` | Remote SSH username |
| `SSH_KEY_PATH` | `""` | Path to private key (e.g. `~/.ssh/id_ed25519`) |
| `SSH_LOCAL_PORT` | `13306` | Local forwarding port |
| **Security & Permission Policies** | | |
| `POLICY_MODE` | `strict` | `strict` (Prompt everything), `prompt` (Permissive with prompts), or `autonomous` (AI executes allowed ops with zero prompts) |
| `POLICY_ALLOW_DELETE` | `false` | Enable `DELETE` statements (still requires WHERE) |
| `POLICY_ALLOW_DDL` | `false` | Enable `CREATE`, `ALTER`, `DROP`, `TRUNCATE` |
| `POLICY_REQUIRE_WHERE` | `true` | Enforce mandatory `WHERE` clause on `UPDATE` & `DELETE` |
| `POLICY_AUTO_APPROVE_INSERT` | `false` | Auto-execute `INSERT` without asking user confirmation |
| `POLICY_AUTO_APPROVE_UPDATE` | `false` | Auto-execute `UPDATE` without asking user confirmation |
| `POLICY_AUTO_APPROVE_DELETE` | `false` | Auto-execute `DELETE` without asking user confirmation |
| `POLICY_AUTO_APPROVE_DDL` | `false` | Auto-execute DDL (`CREATE`, `ALTER`) without asking user confirmation |
| **Limits & Auditing** | | |
| `DB_MAX_ROWS` | `500` | Max rows returned per query to prevent memory bloat |
| `DB_QUERY_TIMEOUT_MS` | `15000` | Query execution timeout (15s) |
| `DB_MAX_PAYLOAD_BYTES` | `524288` | Payload size cap (512 KB) |
| `APPROVAL_EXPIRY_SECONDS`| `300` | Lifetime of write approval tokens (5 min) |
| `LOG_LEVEL` | `info` | Structured logging level (`info`, `debug`, `warn`) |

---

## 🛠️ Available MCP Tools

### Read & Inspection Tools
| Tool | Description |
|---|---|
| `list_databases` | Lists all accessible databases on the host. |
| `list_tables` | Lists all tables and views in the configured database. |
| `describe_table` | Inspects table schema, columns, data types, keys, and nullability. |
| `read_query` | Executes AST-validated `SELECT` query (max 500 rows, 15s timeout). |
| `explain_query` | Inspects MySQL execution plan (`EXPLAIN`) for performance tuning. |
| `get_table_relationships`| Inspects foreign key constraints and referenced tables. |
| `get_database_overview` | Generates summary of table sizes, engine, and row estimates. |

### Write & Execution Tools
| Tool | Description |
|---|---|
| `propose_write` | Previews changes, estimates affected rows, and generates an approval token. |
| `write_query` | Smart execution tool: runs immediately if permitted by policy, or returns a prompt token if approval is required. |
| `execute_approved_write` | Atomically executes a previously authorized token with explicit confirmation. |

---

## 🛡️ Database Provisioning Script

Run this on your remote MySQL server to create isolated accounts:

```sql
-- 1. Create read-only user (SELECT and SHOW VIEW only)
CREATE USER IF NOT EXISTS 'ai_agent_reader'@'%' IDENTIFIED BY 'STRONG_READER_PASSWORD';
GRANT SELECT, SHOW VIEW ON `my_dev_db`.* TO 'ai_agent_reader'@'%';

-- 2. Create writer user (Restricted to DML only)
CREATE USER IF NOT EXISTS 'ai_agent_writer'@'%' IDENTIFIED BY 'STRONG_WRITER_PASSWORD';
GRANT SELECT, INSERT, UPDATE, DELETE ON `my_dev_db`.* TO 'ai_agent_writer'@'%';

FLUSH PRIVILEGES;
```

---

## 🧪 Testing

The test suite runs 30 automated security tests using **Vitest**:

```bash
npm test
```

Verifies:
-  `SELECT`, `SHOW`, `DESCRIBE`, `EXPLAIN` allowed
-  `DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `CREATE` blocked by default
-  Configurable policies allow `DELETE` and `DDL` only when explicitly enabled
-  `UPDATE` and `DELETE` without `WHERE` rejected
-  Session variable injections (`@var`) and `INTO OUTFILE` permanently blocked
-  Approval tokens reject tampered queries, altered params, and re-executions
-  Row caps, timeouts, and payload limits enforced
-  Sensitive credentials automatically redacted from audit logs

---

## 📄 License

MIT © [StinSoft & Open Source Contributors](LICENSE)
