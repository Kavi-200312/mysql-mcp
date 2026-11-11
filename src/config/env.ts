import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { z } from "zod";

// Always load .env from the project directory regardless of cwd
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectEnvPath = path.resolve(__dirname, "../../.env");
dotenv.config({ path: projectEnvPath });
// Also fall back to default cwd .env if not found
dotenv.config();

const cleanString = (val?: string) => {
  if (!val) return "";
  return val.trim().replace(/^['"](.*)['"]$/, "$1");
};

const envSchema = z.object({
  // SSH Tunnel configuration
  SSH_ENABLED: z
    .string()
    .optional()
    .default("false")
    .transform(val => cleanString(val) === "true" || cleanString(val) === "1"),
  SSH_HOST: z.string().optional().default("").transform(cleanString),
  SSH_PORT: z
    .string()
    .optional()
    .default("22")
    .transform(val => parseInt(cleanString(val) || "22", 10)),
  SSH_USER: z.string().optional().default("").transform(cleanString),
  SSH_KEY_PATH: z.string().optional().default("").transform(cleanString),
  SSH_LOCAL_PORT: z
    .string()
    .optional()
    .default("13306")
    .transform(val => parseInt(cleanString(val) || "13306", 10)),
  SSH_REMOTE_HOST: z.string().optional().default("127.0.0.1").transform(cleanString),
  SSH_REMOTE_PORT: z
    .string()
    .optional()
    .default("3306")
    .transform(val => parseInt(cleanString(val) || "3306", 10)),

  // Database Connection
  DB_HOST: z.string().optional().default("127.0.0.1").transform(cleanString),
  DB_PORT: z
    .string()
    .optional()
    .default("3306")
    .transform(val => parseInt(cleanString(val) || "3306", 10)),
  DB_NAME: z.string().optional().default("talc_db").transform(cleanString),
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

  // Limits & Safeguards
  DB_QUERY_TIMEOUT_MS: z
    .string()
    .optional()
    .default("15000")
    .transform(val => parseInt(val, 10)),
  DB_MAX_ROWS: z
    .string()
    .optional()
    .default("500")
    .transform(val => parseInt(val, 10)),
  DB_MAX_PAYLOAD_BYTES: z
    .string()
    .optional()
    .default("524288")
    .transform(val => parseInt(val, 10)),
  APPROVAL_EXPIRY_SECONDS: z
    .string()
    .optional()
    .default("300")
    .transform(val => parseInt(val, 10)),
  BULK_AFFECTED_ROW_THRESHOLD: z
    .string()
    .optional()
    .default("10")
    .transform(val => parseInt(val, 10)),

  // Logging
  LOG_LEVEL: z.enum(["trace", "debug", "info", "warn", "error", "fatal"]).optional().default("info")
});

export type EnvConfig = z.infer<typeof envSchema>;

export function loadConfig(): EnvConfig {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const errorDetails = parsed.error.issues
      .map(issue => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    throw new Error(`Configuration validation failed:\n${errorDetails}`);
  }

  const config = parsed.data;

  // Additional sanity check for SSH if enabled
  if (config.SSH_ENABLED && (!config.SSH_HOST || !config.SSH_USER)) {
    // If not configured yet, we will allow starting in configuration mode or warn
  }

  return config;
}
