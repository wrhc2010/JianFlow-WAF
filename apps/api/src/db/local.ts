import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { AppSettings, EventRecord, EventFilters, TimeSeriesPoint, AttackMap, AiProfile, Site, RuntimeBan, NginxImportRecord } from "./store.js";
import type { WafRule } from "@jev-waf/core";
import { SetupConflictError } from "../errors.js";
import type { RuleException, AccessRule } from "@jev-waf/core";

export type LocalState = {
  settings: AppSettings;
  initialized: boolean;
  credential?: { salt: string; hash: string } | undefined;
  apiKeyCiphertext: string | null;
  aiProfiles?: Array<AiProfile & { apiKeyCiphertext?: string | null }>;
  captchaSecretCiphertext?: string | null;
  runtimeBans?: RuntimeBan[];
  nginxImports?: NginxImportRecord[];
  rules: WafRule[];
  builtinRuleIds?: string[] | undefined;
  scopedRules?: Array<RuleException | AccessRule>;
  sites: Array<Omit<Site, "runtime">>;
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
      CREATE INDEX IF NOT EXISTS events_time_idx ON events(json_extract(value, '$.createdAt') DESC, id DESC);
      CREATE INDEX IF NOT EXISTS events_site_idx ON events(json_extract(value, '$.siteId'), json_extract(value, '$.createdAt') DESC);
      CREATE TABLE IF NOT EXISTS event_totals(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS runtime_bans (
        site_id TEXT NOT NULL, ip TEXT NOT NULL, until_ms INTEGER NOT NULL,
        seconds INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(site_id, ip)
      );
    `);
    if (!this.db.prepare("SELECT id FROM event_totals WHERE id=1").get()) {
      this.db.prepare("INSERT INTO event_totals(id,value) VALUES(1,?)").run(JSON.stringify(this.eventSummary()));
    }
  }

  readState(): LocalState | undefined {
    const row = this.db.prepare("SELECT value FROM state WHERE id = 1").get();
    return row ? JSON.parse(String(row.value)) as LocalState : undefined;
  }

  writeState(state: LocalState): void {
    this.db.prepare("INSERT INTO state (id, value) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET value = excluded.value")
      .run(JSON.stringify(state));
  }

  migrateRuntimeBans(bans: RuntimeBan[]): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const insert = this.db.prepare("INSERT INTO runtime_bans(site_id,ip,until_ms,seconds,count) VALUES(?,?,?,?,?) ON CONFLICT(site_id,ip) DO NOTHING");
      for (const ban of bans) insert.run(ban.siteId, ban.ip, ban.until, ban.seconds, ban.count);
      this.db.exec("COMMIT");
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  readRuntimeBan(siteId: string, ip: string): RuntimeBan | undefined {
    const row = this.db.prepare("SELECT * FROM runtime_bans WHERE site_id=? AND ip=?").get(siteId, ip);
    return row ? { siteId, ip, until: Number(row.until_ms), seconds: Number(row.seconds), count: Number(row.count) } : undefined;
  }

  activeRuntimeBans(now: number): RuntimeBan[] {
    return this.db.prepare("SELECT * FROM runtime_bans WHERE until_ms>?").all(now).map((row) => ({
      siteId: String(row.site_id), ip: String(row.ip), until: Number(row.until_ms), seconds: Number(row.seconds), count: Number(row.count),
    }));
  }

  writeRuntimeBan(ban: RuntimeBan): void {
    this.db.prepare(`INSERT INTO runtime_bans(site_id,ip,until_ms,seconds,count) VALUES(?,?,?,?,?)
      ON CONFLICT(site_id,ip) DO UPDATE SET until_ms=excluded.until_ms,seconds=excluded.seconds,count=excluded.count`)
      .run(ban.siteId, ban.ip, ban.until, ban.seconds, ban.count);
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
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = this.db.prepare("INSERT INTO events (request_id, value) VALUES (?, ?) ON CONFLICT(request_id) DO NOTHING")
        .run(record.requestId, JSON.stringify(record));
      if (result.changes) {
        const totals = this.summary();
        totals.total = (totals.total ?? 0) + 1;
        const action = record.action === "allow" ? "allowed" : record.action === "block" ? "blocked" : "errors";
        totals[action] = (totals[action] ?? 0) + 1;
        totals[record.mode] = (totals[record.mode] ?? 0) + 1;
        if (record.ai && (record.ai as { available?: boolean }).available === false) totals.aiUnavailable = (totals.aiUnavailable ?? 0) + 1;
        this.db.prepare("UPDATE event_totals SET value=? WHERE id=1").run(JSON.stringify(totals));
      }
      this.db.exec("COMMIT");
      return result.changes ? Number(result.lastInsertRowid) : undefined;
    } catch (error) { this.db.exec("ROLLBACK"); throw error; }
  }

  listEvents(filters: EventFilters, cursor?: { time: string; id: string }): EventRecord[] {
    const conditions: string[] = [];
    const params: Array<string | number> = [];
    const add = (sql: string, value: string) => { conditions.push(sql); params.push(value); };
    if (cursor) { conditions.push("(json_extract(value,'$.createdAt'),id) < (?,?)"); params.push(cursor.time, Number(cursor.id)); }
    if (filters.action) add("json_extract(value,'$.action') = ?", filters.action);
    if (filters.ip) add("json_extract(value,'$.ip') = ?", filters.ip);
    if (filters.siteId) add(filters.siteId === "unknown"
      ? "coalesce(json_extract(value,'$.siteId'),'unknown') = ?" : "json_extract(value,'$.siteId') = ?", filters.siteId);
    if (filters.since) add("json_extract(value,'$.createdAt') >= ?", new Date(filters.since).toISOString());
    if (filters.until) add("json_extract(value,'$.createdAt') <= ?", new Date(filters.until).toISOString());
    if (filters.search) add("instr(lower(json_extract(value,'$.path') || ' ' || json_extract(value,'$.requestId') || ' ' || coalesce(json_extract(value,'$.ip'),'')),lower(?)) > 0", filters.search);
    params.push(Math.min(filters.limit ?? 50, 500) + 1);
    return this.db.prepare(`SELECT id,value FROM events ${conditions.length ? `WHERE ${conditions.join(" AND ")}` : ""}
      ORDER BY json_extract(value,'$.createdAt') DESC,id DESC LIMIT ?`).all(...params)
      .map((row) => {
        const event = JSON.parse(String(row.value)) as EventRecord;
        return { ...event, siteId: event.siteId ?? "unknown", id: Number(row.id) };
      });
  }

  summary(): Record<string, number> {
    return JSON.parse(String(this.db.prepare("SELECT value FROM event_totals WHERE id=1").get()!.value)) as Record<string, number>;
  }

  private eventSummary(): Record<string, number> {
    const result = this.db.prepare(`SELECT count(*) as total,
      sum(json_extract(value,'$.action')='allow') as allowed, sum(json_extract(value,'$.action')='block') as blocked,
      sum(json_extract(value,'$.action')='error') as errors,
      sum(json_extract(value,'$.mode')='ai') as ai, sum(json_extract(value,'$.mode')='traditional') as traditional,
      sum(json_extract(value,'$.mode')='hybrid') as hybrid, sum(json_extract(value,'$.ai.available')=0) as aiUnavailable FROM events`).get()!;
    return Object.fromEntries(Object.entries(result).map(([key, value]) => [key, Number(value ?? 0)]));
  }

  timeseries(since: string): TimeSeriesPoint[] {
    return this.db.prepare(`SELECT substr(json_extract(value,'$.createdAt'),1,13) || ':00:00.000Z' as time,
      count(*) as total, sum(json_extract(value,'$.action')='allow') as allowed,
      sum(json_extract(value,'$.action')='block') as blocked, sum(json_extract(value,'$.action')='error') as errors
      FROM events WHERE json_extract(value,'$.createdAt') >= ? GROUP BY time ORDER BY time`).all(since) as TimeSeriesPoint[];
  }

  attackMap(since: string): AttackMap {
    const scope = "json_extract(value,'$.action')='block' AND json_extract(value,'$.createdAt') >= ?";
    const blocked = Number(this.db.prepare(`SELECT count(*) as count FROM events WHERE ${scope}`).get(since)!.count);
    const countries = this.db.prepare(`SELECT coalesce(json_extract(value,'$.country'),'未知地区') as name,count(*) as count
      FROM events WHERE ${scope} GROUP BY name ORDER BY count DESC,name LIMIT 10`).all(since)
      .map((row) => ({ name: String(row.name), count: Number(row.count) }));
    const points = this.db.prepare(`SELECT json_extract(value,'$.latitude') as latitude,json_extract(value,'$.longitude') as longitude,
      json_extract(value,'$.country') as country,json_extract(value,'$.ip') as ip,count(*) as count
      FROM events WHERE ${scope} AND json_extract(value,'$.latitude') IS NOT NULL AND json_extract(value,'$.longitude') IS NOT NULL
      GROUP BY latitude,longitude,country,ip ORDER BY count DESC LIMIT 500`).all(since)
      .map((row) => ({ latitude: Number(row.latitude), longitude: Number(row.longitude), country: String(row.country ?? ""), ip: String(row.ip ?? ""), count: Number(row.count) }));
    const attackers = this.db.prepare(`SELECT json_extract(value,'$.ip') as ip,count(*) as count,
      max(json_extract(value,'$.createdAt')) as last_seen FROM events WHERE ${scope} GROUP BY ip ORDER BY count DESC LIMIT 20`).all(since)
      .map((row) => {
        const latest = this.db.prepare(`SELECT value FROM events WHERE ${scope} AND json_extract(value,'$.ip') IS ?
          ORDER BY json_extract(value,'$.createdAt') DESC,id DESC LIMIT 1`).get(since, row.ip ?? null)!;
        const event = JSON.parse(String(latest.value)) as EventRecord;
        const rules = this.db.prepare(`SELECT DISTINCT json_extract(rule.value,'$.name') as name FROM events,json_each(events.value,'$.matchedRules') as rule
          WHERE ${scope} AND json_extract(events.value,'$.ip') IS ? AND json_extract(rule.value,'$.name') IS NOT NULL LIMIT 50`
          .replaceAll("json_extract(value,", "json_extract(events.value,")).all(since, row.ip ?? null).map((entry) => String(entry.name));
        return { ip: event.ip, count: Number(row.count), path: event.path, rules, lastSeen: String(row.last_seen),
          country: event.country, region: event.region, city: event.city, asn: event.asn };
      });
    return { blocked, countries, points, attackers };
  }

  retention(cutoff: string): number {
    return Number(this.db.prepare(`DELETE FROM events WHERE id IN (SELECT id FROM events
      WHERE json_extract(value,'$.createdAt') < ? LIMIT 1000)`).run(cutoff).changes);
  }

  close(): void {
    this.db.close();
  }
}
