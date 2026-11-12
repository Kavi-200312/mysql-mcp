import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from "@modelcontextprotocol/sdk/types.js";
import { EnvConfig } from "./config/env.js";
import { MysqlClientManager } from "./connection/mysql-client.js";
import { ApprovalManager } from "./security/approval-manager.js";
import { DatabaseInfoTools } from "./tools/database-info.js";
import { ReadQueryTool } from "./tools/read-query.js";
import { ExplainQueryTool } from "./tools/explain-query.js";
import { ProposeWriteTool } from "./tools/propose-write.js";
import { WriteQueryTool } from "./tools/write-query.js";
import { ExecuteApprovedWriteTool } from "./tools/execute-approved-write.js";
import {
  ListTablesSchema,
  DescribeTableSchema,
  ReadQuerySchema,
  ExplainQuerySchema,
  GetTableRelationshipsSchema,
  GetDatabaseOverviewSchema,
  ProposeWriteSchema,
  WriteQuerySchema,
  ExecuteApprovedWriteSchema
} from "./types/tools.js";
import { auditLogger } from "./audit/logger.js";

export function createMcpServer(
  config: EnvConfig,
  client: MysqlClientManager,
  approvalManager: ApprovalManager
): { server: Server; start: () => Promise<void> } {
  const server = new Server(
    {
      name: "secure-mysql-mcp",
      version: "1.0.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  const dbInfo = new DatabaseInfoTools(client, config);
  const readQuery = new ReadQueryTool(client, config);
  const explainQuery = new ExplainQueryTool(client, config);
  const proposeWrite = new ProposeWriteTool(client, approvalManager, config);
  const writeQuery = new WriteQueryTool(client, approvalManager, config);
  const executeWrite = new ExecuteApprovedWriteTool(client, approvalManager, config);

  const tools: Tool[] = [
    {
      name: "list_databases",
      description: "List accessible databases on the remote MySQL instance.",
      inputSchema: {
        type: "object",
        properties: {},
        additionalProperties: false
      }
    },
    {
      name: "list_tables",
      description: "List all tables and views in the development database.",
      inputSchema: {
        type: "object",
        properties: {
          database: {
            type: "string",
            description: "Optional database name (must match configured development database)."
          }
        },
        additionalProperties: false
      }
    },
    {
      name: "describe_table",
      description: "Get column details, data types, keys, and nullability for a table.",
      inputSchema: {
        type: "object",
        properties: {
          table: {
            type: "string",
            description: "The name of the table to inspect."
          },
          database: {
            type: "string",
            description: "Optional database name."
          }
        },
        required: ["table"],
        additionalProperties: false
      }
    },
    {
      name: "read_query",
      description: "Execute a read-only SELECT query against the development database. AST-enforced, single statement only. Max 500 rows.",
      inputSchema: {
        type: "object",
        properties: {
          sql: {
            type: "string",
            description: "The SELECT query to execute."
          },
          params: {
            type: "array",
            description: "Optional query parameters for parameterized queries."
          },
          database: {
            type: "string",
            description: "Optional database name."
          },
          limit: {
            type: "number",
            description: "Optional row limit (max 500)."
          }
        },
        required: ["sql"],
        additionalProperties: false
      }
    },
    {
      name: "explain_query",
      description: "Get MySQL query execution plan (EXPLAIN) for a SELECT statement.",
      inputSchema: {
        type: "object",
        properties: {
          sql: {
            type: "string",
            description: "The SQL statement to explain."
          },
          params: {
            type: "array",
            description: "Optional query parameters."
          },
          database: {
            type: "string",
            description: "Optional database name."
          }
        },
        required: ["sql"],
        additionalProperties: false
      }
    },
    {
      name: "get_table_relationships",
      description: "Inspect foreign key relationships and table constraints.",
      inputSchema: {
        type: "object",
        properties: {
          table: {
            type: "string",
            description: "Optional specific table to filter relationships."
          },
          database: {
            type: "string",
            description: "Optional database name."
          }
        },
        additionalProperties: false
      }
    },
    {
      name: "get_database_overview",
      description: "Get high-level summary of tables, estimated row counts, storage size, and collation.",
      inputSchema: {
        type: "object",
        properties: {
          database: {
            type: "string",
            description: "Optional database name."
          }
        },
        additionalProperties: false
      }
    },
    {
      name: "propose_write",
      description: "Propose an INSERT, UPDATE, DELETE, or DDL statement. Validates SQL AST, shows preview diff of affected rows, and generates an approval token. NEVER executes immediately.",
      inputSchema: {
        type: "object",
        properties: {
          sql: {
            type: "string",
            description: "The SQL statement (UPDATE/DELETE require a WHERE clause)."
          },
          params: {
            type: "array",
            description: "Optional parameterized values."
          },
          database: {
            type: "string",
            description: "Optional database name."
          },
          confirmBulk: {
            type: "boolean",
            description: "Set to true if modifying more rows than the bulk threshold."
          }
        },
        required: ["sql"],
        additionalProperties: false
      }
    },
    {
      name: "write_query",
      description: "Execute a write statement (INSERT, UPDATE, DELETE, or DDL). If the operation is configured for auto-approval in policy, it executes immediately in an atomic transaction; otherwise, it returns a pending approval request.",
      inputSchema: {
        type: "object",
        properties: {
          sql: {
            type: "string",
            description: "The SQL statement to execute."
          },
          params: {
            type: "array",
            description: "Optional query parameters."
          },
          database: {
            type: "string",
            description: "Optional database name."
          },
          userConfirmed: {
            type: "boolean",
            description: "Set to true if user has explicitly confirmed execution in chat."
          }
        },
        required: ["sql"],
        additionalProperties: false
      }
    },
    {
      name: "execute_approved_write",
      description: "Execute a previously proposed and user-approved write operation using its short-lived approval token. Strictly requires userConfirmed: true.",
      inputSchema: {
        type: "object",
        properties: {
          approvalToken: {
            type: "string",
            description: "The short-lived approval token returned by propose_write."
          },
          userConfirmed: {
            type: "boolean",
            description: "Explicit confirmation from the user (must be true)."
          }
        },
        required: ["approvalToken", "userConfirmed"],
        additionalProperties: false
      }
    }
  ];

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case "list_databases": {
          const res = await dbInfo.listDatabases();
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "list_tables": {
          const parsed = ListTablesSchema.parse(args || {});
          const res = await dbInfo.listTables(parsed.database);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "describe_table": {
          const parsed = DescribeTableSchema.parse(args || {});
          const res = await dbInfo.describeTable(parsed.table, parsed.database);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "read_query": {
          const parsed = ReadQuerySchema.parse(args || {});
          const res = await readQuery.execute(parsed.sql, parsed.params, parsed.database, parsed.limit);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "explain_query": {
          const parsed = ExplainQuerySchema.parse(args || {});
          const res = await explainQuery.execute(parsed.sql, parsed.params, parsed.database);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "get_table_relationships": {
          const parsed = GetTableRelationshipsSchema.parse(args || {});
          const res = await dbInfo.getTableRelationships(parsed.table, parsed.database);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "get_database_overview": {
          const parsed = GetDatabaseOverviewSchema.parse(args || {});
          const res = await dbInfo.getDatabaseOverview(parsed.database);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "propose_write": {
          const parsed = ProposeWriteSchema.parse(args || {});
          const res = await proposeWrite.execute(
            parsed.sql,
            parsed.params,
            parsed.database,
            parsed.confirmBulk
          );
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "write_query": {
          const parsed = WriteQuerySchema.parse(args || {});
          const res = await writeQuery.execute(
            parsed.sql,
            parsed.params,
            parsed.database,
            parsed.userConfirmed,
            parsed.confirmBulk
          );
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        case "execute_approved_write": {
          const parsed = ExecuteApprovedWriteSchema.parse(args || {});
          const res = await executeWrite.execute(parsed.approvalToken, parsed.userConfirmed);
          return { content: [{ type: "text", text: JSON.stringify(res, null, 2) }] };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      auditLogger.error({ tool: name, error: errorMsg }, "Tool execution error");
      return {
        content: [{ type: "text", text: JSON.stringify({ error: errorMsg }, null, 2) }],
        isError: true
      };
    }
  });

  const start = async () => {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    auditLogger.info("Secure MySQL MCP server running on stdio transport");
  };

  return { server, start };
}
