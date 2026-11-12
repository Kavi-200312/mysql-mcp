import dotenv from "dotenv";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import { z } from "zod";

// Always load .env from the project directory regardless of cwd
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectEnvPath = path.resolve(__dirname, "../../.env");
dotenv.config({ path: projectEnvPath });
dotenv.config();

const cleanString = (val?: string) => {
  if (!val) return "";
  return val.trim().replace(/^['"](.*)['"]$/, "$1");
};

const portSchema = z
  .string()
  .optional()
  .transform(val => {
    const cleaned = cleanString(val);
    if (!cleaned) return undefined;
    const num = parseInt(cleaned, 10);
    if (isNaN(num) || num < 1 || num > 65535) {
      throw new Error(`Invalid port: ${cleaned}. Must be between 1 and 65535.`);
    }
    return num;
  });

const positiveIntSchema = (defaultVal: number, min = 1, max = 10000000) =>
  z
    .string()
    .optional()
    .default(String(defaultVal))
    .transform(val => {
      const cleaned = cleanString(val);
      const num = parseInt(cleaned || String(defaultVal), 10);
      if (isNaN(num) || num < min || num > max) {
        throw new Error(`Invalid numeric value: ${cleaned}. Must be between ${min} and ${max}.`);
      }
      return num;
    });

const envSchema = z.object({
  // SSH Tunnel configuration
  SSH_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  SSH_HOST: z.string().optional().default("").transform(cleanString),
  SSH_PORT: portSchema.transform(val => val || 22),
  SSH_USER: z.string().optional().default("").transform(cleanString),
  SSH_KEY_PATH: z.string().optional().default("").transform(cleanString),
  SSH_LOCAL_PORT: portSchema.transform(val => val || 13306),
  SSH_REMOTE_HOST: z.string().optional().default("127.0.0.1").transform(cleanString),
  SSH_REMOTE_PORT: portSchema.transform(val => val || 3306),

  // Database Connection
  DB_HOST: z.string().optional().default("127.0.0.1").transform(cleanString),
  DB_PORT: portSchema,
  DB_NAME: z.string().optional().default("").transform(cleanString),
  DB_READER_USER: z.string().optional().default("ai_agent_reader").transform(cleanString),
  DB_READER_PASSWORD: z.string().optional().default("").transform(cleanString),
  DB_WRITER_USER: z.string().optional().default("ai_agent_writer").transform(cleanString),
  DB_WRITER_PASSWORD: z.string().optional().default("").transform(cleanString),
  DB_SSL: z
    .string()
    .optional()
    .default("auto")
    .transform(val => {
      const cleaned = cleanString(val).toLowerCase();
      if (cleaned === "true" || cleaned === "1") return true;
      if (cleaned === "false" || cleaned === "0") return false;
      return "auto";
    }),
  DB_SSL_CA_PATH: z.string().optional().default("").transform(cleanString),
  DB_SSL_REJECT_UNAUTHORIZED: z
    .string()
    .optional()
    .transform(val => {
      if (val === undefined || val === "") return undefined;
      const cleaned = cleanString(val).toLowerCase();
      return cleaned === "true" || cleaned === "1";
    }),

  // Granular Security & Permission Policies
  POLICY_MODE: z
    .enum(["strict", "prompt", "autonomous"])
    .optional()
    .default("strict"),
  POLICY_ALLOW_DELETE: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  POLICY_ALLOW_DDL: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  POLICY_REQUIRE_WHERE: z
    .string()
    .optional()
    .default("true")
    .transform(val => cleanString(val) !== "false" && cleanString(val) !== "0"),
  POLICY_AUTO_APPROVE_INSERT: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  POLICY_AUTO_APPROVE_UPDATE: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  POLICY_AUTO_APPROVE_DELETE: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  POLICY_AUTO_APPROVE_DDL: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),

  // Storage path for approvals
  APPROVAL_STORE_PATH: z
    .string()
    .optional()
    .default("")
    .transform(val => {
      const cleaned = cleanString(val);
      if (cleaned) return path.resolve(cleaned);
      // Default to secure OS temp directory so global npx / read-only installs work
      return path.join(os.tmpdir(), "mysql-mcp", "approvals.json");
    }),

  // Limits & Safeguards
  DB_QUERY_TIMEOUT_MS: positiveIntSchema(15000, 100, 300000),
  DB_MAX_ROWS: positiveIntSchema(500, 1, 50000),
  DB_MAX_PAYLOAD_BYTES: positiveIntSchema(524288, 1024, 52428800),
  APPROVAL_EXPIRY_SECONDS: positiveIntSchema(300, 10, 86400),
  BULK_AFFECTED_ROW_THRESHOLD: positiveIntSchema(10, 1, 10000),

  // Logging
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).optional().default("info")
});

export type EnvConfig = z.infer<typeof envSchema> & {
  EFFECTIVE_DB_PORT: number;
};

export function loadConfig(): EnvConfig {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const errorDetails = parsed.error.issues
      .map(issue => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Configuration validation failed:\n${errorDetails}`);
  }

  const config = parsed.data;

  // Fail-closed validation for SSH tunnel
  if (config.SSH_ENABLED && (!config.SSH_HOST || !config.SSH_USER)) {
    throw new Error(
      "SSH_ENABLED=true but SSH_HOST or SSH_USER is missing. Refusing to connect directly to prevent unencrypted transmission."
    );
  }

  // Auto-align DB port to SSH local forwarding port when tunnel is active
  let effectiveDbPort = config.DB_PORT || 3306;
  if (config.SSH_ENABLED) {
    effectiveDbPort = config.SSH_LOCAL_PORT;
  }

  return {
    ...config,
    EFFECTIVE_DB_PORT: effectiveDbPort
  };
}
