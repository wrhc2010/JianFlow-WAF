import type { ProtectionMode, ProtectionStrength } from "@jev-waf/core";
import { loadEnvFile } from "node:process";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { loadSessionSecret } from "./secrets.js";

try {
  loadEnvFile(fileURLToPath(new URL("../../../.env", import.meta.url)));
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
}

function numberEnv(name: string, fallback: number, min = 1, max = Number.MAX_SAFE_INTEGER): number {
  if (!process.env[name]?.trim()) return fallback;
  const value = Number(process.env[name]);
  return Number.isSafeInteger(value) && value >= min && value <= max ? value : fallback;
}

export type SitePortRange = {
  min: number;
  max: number;
};

function parsePortRange(value: string | undefined, fallback: SitePortRange): SitePortRange {
  const raw = value?.trim() ?? "";
  const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(raw);
  if (!match) return fallback;
  const min = Number(match[1]);
  const max = Number(match[2] ?? match[1]);
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 1 || max > 65535 || min > max) {
    return fallback;
  }
  return { min, max };
}

export type DatabaseUrlOptions = {
  host: string;
  port: string;
  user: string;
  password: string;
  database: string;
};

export function buildDatabaseUrl(options: DatabaseUrlOptions): string {
  const url = new URL("postgresql://localhost");
  url.username = options.user;
  url.password = options.password;
  url.hostname = options.host;
  url.port = options.port;
  url.pathname = `/${options.database}`;
  return url.toString();
}

const dataDir = process.env.DATA_DIR?.trim() || fileURLToPath(new URL("../../../data", import.meta.url));
function databaseUrlFromSecret(): string {
  const passwordFile = process.env.POSTGRES_PASSWORD_FILE?.trim() || "";
  const password = process.env.POSTGRES_PASSWORD?.trim()
    || (passwordFile && existsSync(passwordFile) ? readFileSync(passwordFile, "utf8").trim() : "");
  const host = process.env.POSTGRES_HOST?.trim() || "";
  if (!password || !host) return "";
  return buildDatabaseUrl({
    host,
    port: process.env.POSTGRES_PORT?.trim() || "5432",
    user: process.env.POSTGRES_USER?.trim() || "jevwaf",
    password,
    database: process.env.POSTGRES_DB?.trim() || "jevwaf"
  });
}
const databaseUrl = process.env.DATABASE_URL?.trim() || databaseUrlFromSecret();
const proxyPort = numberEnv("PROXY_PORT", 8080);
const sitePortRange = parsePortRange(process.env.SITE_PORT_RANGE, { min: 8080, max: 8099 });
if (proxyPort < sitePortRange.min || proxyPort > sitePortRange.max) {
  throw new Error(`PROXY_PORT ${proxyPort} must be inside SITE_PORT_RANGE ${sitePortRange.min}-${sitePortRange.max}`);
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  apiHost: process.env.API_HOST ?? "127.0.0.1",
  apiPort: numberEnv("API_PORT", 4000),
  proxyHost: process.env.PROXY_HOST ?? "0.0.0.0",
  proxyPort,
  sitePortRange,
  httpsPort: numberEnv("HTTPS_PORT", 8443),
  tlsKeyPath: process.env.TLS_KEY_PATH ?? "",
  tlsCertPath: process.env.TLS_CERT_PATH ?? "",
  databaseUrl,
  environmentApiKey: process.env.JEV_API_KEY ?? process.env.OPENROUTER_API_KEY ?? "",
  openRouterKey: process.env.JEV_API_KEY ?? process.env.OPENROUTER_API_KEY ?? "",
  openRouterModel: process.env.JEV_MODEL ?? process.env.OPENROUTER_MODEL ?? "typesafe/jev-1.13",
  jevBaseUrl: process.env.JEV_BASE_URL ?? process.env.OPENROUTER_BASE_URL ?? "https://openrouter.ai",
  adminUser: process.env.ADMIN_USER ?? "admin",
  adminPassword: process.env.ADMIN_PASSWORD ?? "",
  sessionSecret: loadSessionSecret(dataDir, process.env.SESSION_SECRET),
  sessionCookieSecure: process.env.SESSION_COOKIE_SECURE === "true",
  upstreamUrl: process.env.UPSTREAM_URL ?? "http://127.0.0.1:9000",
  aiTimeoutMs: numberEnv("AI_TIMEOUT_MS", 2000),
  aiBodyLimit: numberEnv("AI_BODY_LIMIT", 32768),
  maxRequestBodyBytes: numberEnv("MAX_REQUEST_BODY_BYTES", 10 * 1024 * 1024),
  logRetentionDays: numberEnv("LOG_RETENTION_DAYS", 30),
  dataDir,
  geoIpDatabasePath: process.env.GEOIP_DATABASE_PATH ?? "",
  geoIpAsnDatabasePath: process.env.GEOIP_ASN_DATABASE_PATH ?? "",
  trustedProxyCidrs: (process.env.TRUSTED_PROXY_CIDRS ?? "").split(",").map((value) => value.trim()).filter(Boolean),
  defaultMode: (process.env.DEFAULT_MODE as ProtectionMode | undefined) ?? "hybrid",
  defaultStrength: (process.env.DEFAULT_STRENGTH as ProtectionStrength | undefined) ?? "medium"
};

export type AppConfig = typeof config;
