import { z } from "zod";

export const ListDatabasesSchema = z.object({});

export const ListTablesSchema = z.object({
  database: z.string().optional()
});

export const DescribeTableSchema = z.object({
  table: z.string().min(1, "Table name cannot be empty"),
  database: z.string().optional()
});

export const ReadQuerySchema = z.object({
  sql: z.string().min(1, "SQL query cannot be empty"),
  params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  database: z.string().optional(),
  limit: z.number().int().positive().max(500).optional()
});

export const ExplainQuerySchema = z.object({
  sql: z.string().min(1, "SQL query cannot be empty"),
  params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  database: z.string().optional()
});

export const GetTableRelationshipsSchema = z.object({
  table: z.string().optional(),
  database: z.string().optional()
});

export const GetDatabaseOverviewSchema = z.object({
  database: z.string().optional()
});

export const ProposeWriteSchema = z.object({
  sql: z.string().min(1, "SQL statement cannot be empty"),
  params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  database: z.string().optional(),
  confirmBulk: z.boolean().optional().default(false)
});

export const WriteQuerySchema = z.object({
  sql: z.string().min(1, "SQL statement cannot be empty"),
  params: z.array(z.union([z.string(), z.number(), z.boolean(), z.null()])).optional(),
  database: z.string().optional(),
  userConfirmed: z.boolean().optional().default(false),
  confirmBulk: z.boolean().optional().default(false)
});

export const ExecuteApprovedWriteSchema = z.object({
  approvalToken: z.string().min(10, "Valid approval token required"),
  userConfirmed: z.boolean().refine(val => val === true, {
    message: "Explicit user confirmation (userConfirmed: true) is strictly required to execute write"
  })
});
