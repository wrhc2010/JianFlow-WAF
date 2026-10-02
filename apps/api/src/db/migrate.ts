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

CREATE TABLE IF NOT EXISTS builtin_rule_catalog (id TEXT PRIMARY KEY);
WITH older AS (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY request_id ORDER BY created_at DESC, id DESC) AS position
  FROM events WHERE finalized
)
UPDATE events SET finalized = FALSE FROM older WHERE events.id = older.id AND older.position > 1;
CREATE UNIQUE INDEX IF NOT EXISTS events_final_request_idx ON events (request_id) WHERE finalized;

CREATE INDEX IF NOT EXISTS events_created_at_idx ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS events_action_idx ON events (action);
CREATE INDEX IF NOT EXISTS events_country_idx ON events (country);
CREATE INDEX IF NOT EXISTS events_ip_idx ON events (ip);
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
