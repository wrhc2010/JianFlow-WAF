import { Pool } from "pg";
import { config } from "../config.js";

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY DEFAULT 1,
  mode TEXT NOT NULL DEFAULT 'hybrid',
  strength TEXT NOT NULL DEFAULT 'medium',
  custom_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.7,
  model TEXT NOT NULL DEFAULT 'typesafe/jev-1.13',
  ai_timeout_ms INTEGER NOT NULL DEFAULT 2000,
  ai_body_limit INTEGER NOT NULL DEFAULT 32768,
  upstream_url TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
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
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS events_created_at_idx ON events (created_at DESC);
CREATE INDEX IF NOT EXISTS events_action_idx ON events (action);
`;

export async function migrate(): Promise<void> {
  if (!config.databaseUrl) {
    console.log("DATABASE_URL is empty; using in-memory storage.");
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

if (import.meta.url === `file://${process.argv[1]}`) {
  await migrate();
}
