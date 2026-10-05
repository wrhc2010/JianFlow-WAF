import { Pool } from "pg";
import { config } from "../config.js";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY DEFAULT 1,
  mode TEXT NOT NULL DEFAULT 'hybrid',
  strength TEXT NOT NULL DEFAULT 'medium',
  custom_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.5,
  model TEXT NOT NULL DEFAULT 'typesafe/jev-1.13',
  jev_base_url TEXT NOT NULL DEFAULT 'https://openrouter.ai',
  api_key_ciphertext TEXT,
  admin_password_salt TEXT,
  admin_password_hash TEXT,
  initialized BOOLEAN NOT NULL DEFAULT FALSE,
  ai_timeout_ms INTEGER NOT NULL DEFAULT 2000,
  ai_body_limit INTEGER NOT NULL DEFAULT 32768,
  upstream_url TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  listen_port INTEGER,
  upstream_url TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'hybrid',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  target TEXT NOT NULL,
  operator TEXT NOT NULL,
  pattern TEXT NOT NULL,
  action TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  package_id TEXT NOT NULL DEFAULT 'jianflow-core',
  license TEXT NOT NULL DEFAULT 'MIT',
  options JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  request_id TEXT NOT NULL,
  action TEXT NOT NULL,
  mode TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  ip TEXT,
  status_code INTEGER,
  score DOUBLE PRECISION,
  threshold DOUBLE PRECISION,
  reason TEXT NOT NULL,
  matched_rules JSONB NOT NULL DEFAULT '[]'::jsonb,
  ai JSONB,
  partial_inspection BOOLEAN NOT NULL DEFAULT FALSE,
  country TEXT,
  region TEXT,
  city TEXT,
  latitude DOUBLE PRECISION,
  longitude DOUBLE PRECISION,
  asn INTEGER,
  finalized BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE settings ADD COLUMN IF NOT EXISTS jev_base_url TEXT NOT NULL DEFAULT 'https://openrouter.ai';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS listen_port INTEGER;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS policy JSONB;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS operation_mode TEXT NOT NULL DEFAULT 'defense';
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ai_profile_id TEXT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS wait_room JSONB NOT NULL DEFAULT '{"enabled":false,"maxActive":100,"maxQueue":100,"timeoutSeconds":60}'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS maintenance JSONB NOT NULL DEFAULT '{"source":"default","statusCode":503}'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS upstream_error JSONB NOT NULL DEFAULT '{"source":"default","statusCode":502}'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS redirect JSONB;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS upstream_pool JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS audit_mode TEXT;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS captcha_enabled BOOLEAN;
CREATE TABLE IF NOT EXISTS runtime_bans (
  site_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  until_ms BIGINT NOT NULL,
  seconds INTEGER NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY(site_id,ip)
);
CREATE TABLE IF NOT EXISTS nginx_imports (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  digest TEXT NOT NULL,
  ports JSONB NOT NULL
);
ALTER TABLE settings ADD COLUMN IF NOT EXISTS api_key_ciphertext TEXT;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS admin_password_salt TEXT;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS admin_password_hash TEXT;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS initialized BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE rules ADD COLUMN IF NOT EXISTS package_id TEXT NOT NULL DEFAULT 'jianflow-core';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS license TEXT NOT NULL DEFAULT 'MIT';
ALTER TABLE rules ADD COLUMN IF NOT EXISTS options JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE events ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS region TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS city TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;
ALTER TABLE events ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;
ALTER TABLE events ADD COLUMN IF NOT EXISTS asn INTEGER;
ALTER TABLE events ADD COLUMN IF NOT EXISTS finalized BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS default_policy JSONB;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS audit_mode TEXT NOT NULL DEFAULT 'sync';
ALTER TABLE settings ADD COLUMN IF NOT EXISTS async_ban_base_seconds INTEGER NOT NULL DEFAULT 60;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS async_ban_increment_seconds INTEGER NOT NULL DEFAULT 60;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS async_ban_max_seconds INTEGER NOT NULL DEFAULT 86400;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS whitelist_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS malicious_ip_cidrs JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS wait_room_defaults JSONB NOT NULL DEFAULT '{"enabled":false,"maxActive":100,"maxQueue":100,"timeoutSeconds":60}'::jsonb;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS captcha JSONB NOT NULL DEFAULT '{"enabled":false,"provider":"local","siteKey":"","secretConfigured":false}'::jsonb;
ALTER TABLE settings ADD COLUMN IF NOT EXISTS captcha_secret_ciphertext TEXT;
CREATE TABLE IF NOT EXISTS ai_profiles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  base_url TEXT NOT NULL,
  model TEXT NOT NULL,
  api_key_ciphertext TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  priority INTEGER NOT NULL DEFAULT 100,
  timeout_ms INTEGER NOT NULL DEFAULT 2000,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE ai_profiles ADD COLUMN IF NOT EXISTS failure_action TEXT NOT NULL DEFAULT 'inherit';
ALTER TABLE events ADD COLUMN IF NOT EXISTS site_id TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS context JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE TABLE IF NOT EXISTS scoped_rules (id TEXT PRIMARY KEY, site_id TEXT NOT NULL, kind TEXT NOT NULL, value JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS scoped_rules_site_idx ON scoped_rules(site_id,kind);

CREATE TABLE IF NOT EXISTS builtin_rule_catalog (id TEXT PRIMARY KEY);
WITH older AS (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY request_id ORDER BY created_at DESC, id DESC) AS position
  FROM events WHERE finalized
)
UPDATE events SET finalized = FALSE FROM older WHERE events.id = older.id AND older.position > 1;
CREATE UNIQUE INDEX IF NOT EXISTS events_final_request_idx ON events (request_id) WHERE finalized;
CREATE TABLE IF NOT EXISTS event_totals (id INTEGER PRIMARY KEY CHECK(id=1), total BIGINT NOT NULL,
  allowed BIGINT NOT NULL, blocked BIGINT NOT NULL, errors BIGINT NOT NULL, ai BIGINT NOT NULL,
  traditional BIGINT NOT NULL, hybrid BIGINT NOT NULL, ai_unavailable BIGINT NOT NULL);
INSERT INTO event_totals SELECT 1,count(*),count(*) FILTER(WHERE action='allow'),count(*) FILTER(WHERE action='block'),
  count(*) FILTER(WHERE action='error'),count(*) FILTER(WHERE mode='ai'),count(*) FILTER(WHERE mode='traditional'),
  count(*) FILTER(WHERE mode='hybrid'),count(*) FILTER(WHERE (ai->>'available')::boolean=FALSE) FROM events WHERE finalized
  ON CONFLICT(id) DO NOTHING;

CREATE INDEX IF NOT EXISTS events_created_at_idx ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS events_action_idx ON events (action);
CREATE INDEX IF NOT EXISTS events_country_idx ON events (country);
CREATE INDEX IF NOT EXISTS events_ip_idx ON events (ip);
CREATE INDEX IF NOT EXISTS events_site_time_idx ON events (site_id, created_at DESC, id DESC);
`;

export async function migrate(): Promise<void> {
  if (!config.databaseUrl) {
    console.log("DATABASE_URL is empty; using persistent local SQLite storage.");
    return;
  }
  const pool = new Pool({ connectionString: config.databaseUrl });
  try {
    await pool.query(schema);
    console.log("Database schema ready.");
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await migrate();
}
