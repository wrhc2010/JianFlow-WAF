import type { ProtectionMode, ProtectionStrength } from "@jev-waf/core";

function numberEnv(name: string, fallback: number): number {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : fallback;
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  apiHost: process.env.API_HOST ?? "127.0.0.1",
  apiPort: numberEnv("API_PORT", 4000),
  proxyHost: process.env.PROXY_HOST ?? "0.0.0.0",
  proxyPort: numberEnv("PROXY_PORT", 8080),
  httpsPort: numberEnv("HTTPS_PORT", 8443),
  tlsKeyPath: process.env.TLS_KEY_PATH ?? "",
  tlsCertPath: process.env.TLS_CERT_PATH ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  openRouterKey: process.env.OPENROUTER_API_KEY ?? "",
  openRouterModel: process.env.OPENROUTER_MODEL ?? "typesafe/jev-1.13",
  adminUser: process.env.ADMIN_USER ?? "admin",
  adminPassword: process.env.ADMIN_PASSWORD ?? "change-me-now",
  sessionSecret: process.env.SESSION_SECRET ?? "development-only-secret",
  upstreamUrl: process.env.UPSTREAM_URL ?? "http://127.0.0.1:9000",
  aiTimeoutMs: numberEnv("AI_TIMEOUT_MS", 2000),
  aiBodyLimit: numberEnv("AI_BODY_LIMIT", 32768),
  logRetentionDays: numberEnv("LOG_RETENTION_DAYS", 30),
  defaultMode: (process.env.DEFAULT_MODE as ProtectionMode | undefined) ?? "hybrid",
  defaultStrength: (process.env.DEFAULT_STRENGTH as ProtectionStrength | undefined) ?? "medium"
};

export type AppConfig = typeof config;
