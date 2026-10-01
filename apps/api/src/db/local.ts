import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { AppSettings, EventRecord } from "./store.js";
import type { WafRule } from "@jev-waf/core";
import { SetupConflictError } from "../errors.js";

export type LocalState = {
  settings: AppSettings;
  initialized: boolean;
  credential?: { salt: string; hash: string } | undefined;
  apiKeyCiphertext: string | null;
  rules: WafRule[];
  builtinRuleIds?: string[] | undefined;
  sites: Array<{ id: string; name: string; upstreamUrl: string; mode: "ai" | "traditional" | "hybrid"; enabled: boolean; createdAt: string }>;
};

export class LocalDatabase {
  private readonly db: DatabaseSync;

  constructor(directory: string) {
    mkdirSync(directory, { recursive: true });
    this.db = new DatabaseSync(join(directory, "jianflow.sqlite"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL UNIQUE,
        value TEXT NOT NULL
      );
    `);
  }

  readState(): LocalState | undefined {
    const row = this.db.prepare("SELECT value FROM state WHERE id = 1").get();
    return row ? JSON.parse(String(row.value)) as LocalState : undefined;
  }

  writeState(state: LocalState): void {
    this.db.prepare("INSERT INTO state (id, value) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET value = excluded.value")
      .run(JSON.stringify(state));
  }

  completeSetup(state: LocalState): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (this.readState()?.initialized) throw new SetupConflictError("系统已经完成初始化");
      this.writeState(state);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  saveEvent(record: EventRecord): number | undefined {
    const result = this.db.prepare("INSERT INTO events (request_id, value) VALUES (?, ?) ON CONFLICT(request_id) DO NOTHING")
      .run(record.requestId, JSON.stringify(record));
    return result.changes ? Number(result.lastInsertRowid) : undefined;
  }

  readEvents(): EventRecord[] {
    return this.db.prepare("SELECT id, value FROM events ORDER BY id DESC").all()
      .map((row) => ({ ...JSON.parse(String(row.value)) as EventRecord, id: Number(row.id) }));
  }

  close(): void {
    this.db.close();
  }
}
