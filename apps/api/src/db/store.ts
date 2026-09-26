import { randomUUID } from "node:crypto";
import { Pool, type QueryResultRow } from "pg";
import {
  BUILTIN_RULES,
  type EvaluationSettings,
  type ProtectionMode,
  type ProtectionStrength,
  type WafRule,
  type WafDecision
} from "@jev-waf/core";
import { config } from "../config.js";
import { migrate } from "./migrate.js";

type Site = {
  id: string;
  name: string;
  upstreamUrl: string;
  mode: ProtectionMode;
  enabled: boolean;
  createdAt: string;
};

type EventRecord = {
  id: string | number;
  requestId: string;
  action: string;
  mode: string;
  method: string;
  path: string;
  ip: string | undefined;
  statusCode: number | undefined;
  score: number | undefined;
  threshold: number | undefined;
  reason: string;
  matchedRules: unknown[];
  ai: unknown | undefined;
  partialInspection: boolean;
  createdAt: string;
};

export type AppSettings = EvaluationSettings & { upstreamUrl: string };

const defaultSettings: AppSettings = {
  mode: config.defaultMode,
  strength: config.defaultStrength,
  customThreshold: 0.7,
  model: config.openRouterModel,
  aiTimeoutMs: config.aiTimeoutMs,
  aiBodyLimit: config.aiBodyLimit,
  upstreamUrl: config.upstreamUrl
};

export class Store {
  private readonly pool: Pool | null;
  private settings: AppSettings = { ...defaultSettings };
  private readonly sites = new Map<string, Site>();
  private rules: WafRule[] = [...BUILTIN_RULES];
  private readonly events: EventRecord[] = [];

  constructor() {
    this.pool = config.databaseUrl ? new Pool({ connectionString: config.databaseUrl }) : null;
    this.sites.set("default", {
      id: "default",
      name: "默认站点",
      upstreamUrl: this.settings.upstreamUrl,
      mode: this.settings.mode,
      enabled: true,
      createdAt: new Date().toISOString()
    });
  }

  async init(): Promise<void> {
    if (!this.pool) {
      return;
    }
    await migrate();
    await this.pool.query(
      `INSERT INTO settings (upstream_url) VALUES ($1)
       ON CONFLICT (id) DO NOTHING`,
      [this.settings.upstreamUrl]
    );
    const settingResult = await this.pool.query(
      `SELECT mode, strength, custom_threshold, model, ai_timeout_ms, ai_body_limit, upstream_url
       FROM settings WHERE id = 1`
    );
    const row = settingResult.rows[0] as Record<string, unknown> | undefined;
    if (row) {
      this.settings = {
        mode: row.mode as ProtectionMode,
        strength: row.strength as ProtectionStrength,
        customThreshold: Number(row.custom_threshold),
        model: String(row.model),
        aiTimeoutMs: Number(row.ai_timeout_ms),
        aiBodyLimit: Number(row.ai_body_limit),
        upstreamUrl: String(row.upstream_url)
      };
    }
    const ruleResult = await this.pool.query(`SELECT * FROM rules ORDER BY created_at ASC`);
    if (ruleResult.rows.length === 0) {
      for (const rule of BUILTIN_RULES) {
        await this.saveRule(rule);
      }
    } else {
      this.rules = ruleResult.rows.map(mapRule);
    }
    const siteResult = await this.pool.query(`SELECT * FROM sites ORDER BY created_at ASC`);
    if (siteResult.rows.length > 0) {
      this.sites.clear();
      for (const row of siteResult.rows) {
        this.sites.set(String(row.id), mapSite(row));
      }
    }
  }

  getSettings(): AppSettings {
    return { ...this.settings };
  }

  async updateSettings(next: Partial<AppSettings>): Promise<AppSettings> {
    this.settings = { ...this.settings, ...next };
    if (this.pool) {
      await this.pool.query(
        `UPDATE settings SET mode = $1, strength = $2, custom_threshold = $3,
         model = $4, ai_timeout_ms = $5, ai_body_limit = $6, upstream_url = $7, updated_at = NOW()
         WHERE id = 1`,
        [
          this.settings.mode,
          this.settings.strength,
          this.settings.customThreshold,
          this.settings.model,
          this.settings.aiTimeoutMs,
          this.settings.aiBodyLimit,
          this.settings.upstreamUrl
        ]
      );
    }
    const defaultSite = this.sites.get("default");
    if (defaultSite) {
      defaultSite.upstreamUrl = this.settings.upstreamUrl;
      defaultSite.mode = this.settings.mode;
    }
    return this.getSettings();
  }

  listSites(): Site[] {
    return [...this.sites.values()];
  }

  async saveSite(input: Omit<Site, "createdAt" | "id"> & { id?: string }): Promise<Site> {
    const site: Site = {
      id: input.id ?? randomUUID(),
      name: input.name,
      upstreamUrl: input.upstreamUrl,
      mode: input.mode,
      enabled: input.enabled,
      createdAt: new Date().toISOString()
    };
    this.sites.set(site.id, site);
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO sites (id, name, upstream_url, mode, enabled)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name,
         upstream_url = EXCLUDED.upstream_url, mode = EXCLUDED.mode, enabled = EXCLUDED.enabled`,
        [site.id, site.name, site.upstreamUrl, site.mode, site.enabled]
      );
    }
    return site;
  }

  async deleteSite(id: string): Promise<void> {
    if (id === "default") {
      return;
    }
    this.sites.delete(id);
    if (this.pool) {
      await this.pool.query(`DELETE FROM sites WHERE id = $1`, [id]);
    }
  }

  listRules(): WafRule[] {
    return this.rules.map((rule) => ({ ...rule }));
  }

  async saveRule(input: WafRule): Promise<WafRule> {
    this.rules = [...this.rules.filter((rule) => rule.id !== input.id), input];
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO rules (id, name, source, category, severity, target, operator, pattern, action, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, source = EXCLUDED.source,
         category = EXCLUDED.category, severity = EXCLUDED.severity, target = EXCLUDED.target,
         operator = EXCLUDED.operator, pattern = EXCLUDED.pattern, action = EXCLUDED.action,
         enabled = EXCLUDED.enabled`,
        [
          input.id,
          input.name,
          input.source,
          input.category,
          input.severity,
          input.target,
          input.operator,
          input.pattern,
          input.action,
          input.enabled
        ]
      );
    }
    return input;
  }

  async deleteRule(id: string): Promise<void> {
    this.rules = this.rules.filter((rule) => rule.id !== id);
    if (this.pool) {
      await this.pool.query(`DELETE FROM rules WHERE id = $1`, [id]);
    }
  }

  async saveEvent(decision: WafDecision, request: { method: string; path: string; ip?: string | undefined }, statusCode?: number): Promise<void> {
    const record: EventRecord = {
      id: this.events.length + 1,
      requestId: decision.requestId,
      action: decision.action,
      mode: decision.mode,
      method: request.method,
      path: request.path,
      ip: request.ip,
      statusCode,
      score: decision.score,
      threshold: decision.threshold,
      reason: decision.reason,
      matchedRules: decision.matchedRules,
      ai: decision.ai,
      partialInspection: decision.partialInspection ?? false,
      createdAt: new Date().toISOString()
    };
    this.events.unshift(record);
    this.events.splice(1000);
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO events
         (request_id, action, mode, method, path, ip, status_code, score, threshold, reason, matched_rules, ai, partial_inspection)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          record.requestId,
          record.action,
          record.mode,
          record.method,
          record.path,
          record.ip ?? null,
          record.statusCode ?? null,
          record.score ?? null,
          record.threshold ?? null,
          record.reason,
          JSON.stringify(record.matchedRules),
          record.ai ? JSON.stringify(record.ai) : null,
          record.partialInspection
        ]
      );
    }
  }

  async listEvents(limit = 50): Promise<EventRecord[]> {
    if (!this.pool) {
      return this.events.slice(0, limit);
    }
    const result = await this.pool.query(
      `SELECT id, request_id, action, mode, method, path, ip, status_code,
       score, threshold, reason, matched_rules, ai, partial_inspection, created_at
       FROM events ORDER BY created_at DESC LIMIT $1`,
      [Math.min(limit, 100)]
    );
    return result.rows.map((row) => ({
      id: row.id as string | number,
      requestId: String(row.request_id),
      action: String(row.action),
      mode: String(row.mode),
      method: String(row.method),
      path: String(row.path),
      ip: row.ip ? String(row.ip) : undefined,
      statusCode: row.status_code ? Number(row.status_code) : undefined,
      score: row.score === null ? undefined : Number(row.score),
      threshold: row.threshold === null ? undefined : Number(row.threshold),
      reason: String(row.reason),
      matchedRules: (row.matched_rules as unknown[]) ?? [],
      ai: row.ai ?? undefined,
      partialInspection: Boolean(row.partial_inspection),
      createdAt: new Date(row.created_at as string).toISOString()
    }));
  }

  async summary(): Promise<Record<string, number>> {
    const events = await this.listEvents(1000);
    return {
      total: events.length,
      blocked: events.filter((event) => event.action === "block" || event.action === "error").length,
      allowed: events.filter((event) => event.action === "allow").length,
      ai: events.filter((event) => event.mode === "ai").length,
      traditional: events.filter((event) => event.mode === "traditional").length,
      hybrid: events.filter((event) => event.mode === "hybrid").length,
      aiUnavailable: events.filter((event) => event.ai && (event.ai as { available?: boolean }).available === false).length
    };
  }
}

function mapRule(row: QueryResultRow): WafRule {
  return {
    id: String(row.id),
    name: String(row.name),
    source: String(row.source),
    category: String(row.category),
    severity: row.severity as WafRule["severity"],
    target: row.target as WafRule["target"],
    operator: row.operator as WafRule["operator"],
    pattern: String(row.pattern),
    action: row.action as WafRule["action"],
    enabled: Boolean(row.enabled)
  };
}

function mapSite(row: QueryResultRow): Site {
  return {
    id: String(row.id),
    name: String(row.name),
    upstreamUrl: String(row.upstream_url),
    mode: row.mode as ProtectionMode,
    enabled: Boolean(row.enabled),
    createdAt: new Date(row.created_at as string).toISOString()
  };
}
