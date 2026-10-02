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
import { configureAdmin, exportAdminCredential, loadAdminCredential, makeAdminCredential } from "../auth.js";
import { GeoIpResolver, type GeoPoint } from "../geo.js";
import { decryptSecret, encryptSecret } from "../secrets.js";
import { migrate } from "./migrate.js";
import { LocalDatabase, type LocalState } from "./local.js";
import { ConflictError, SetupConflictError, ValidationError } from "../errors.js";
import { MAX_TOTAL_RULES, validateRule } from "../rule-import.js";

export type Site = {
  id: string;
  name: string;
  listenPort: number;
  upstreamUrl: string;
  mode: ProtectionMode;
  enabled: boolean;
  createdAt: string;
};

export type EventRecord = {
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
  country?: string | undefined;
  region?: string | undefined;
  city?: string | undefined;
  latitude?: number | undefined;
  longitude?: number | undefined;
  asn?: number | undefined;
  createdAt: string;
};

export type AppSettings = EvaluationSettings & {
  upstreamUrl: string;
  jevBaseUrl: string;
  apiKeyConfigured: boolean;
  apiKeySource: "environment" | "database" | "none";
};

export type EventFilters = {
  limit?: number;
  cursor?: string;
  action?: "allow" | "block" | "error";
  ip?: string;
  since?: string;
  until?: string;
  search?: string;
};

export type TimeSeriesPoint = {
  time: string;
  total: number;
  allowed: number;
  blocked: number;
  errors: number;
};

type SettingsUpdate = Partial<Omit<AppSettings, "apiKeyConfigured" | "apiKeySource">> & {
  apiKey?: string | null;
};

function defaultSettings(): AppSettings {
  return {
  mode: config.defaultMode,
  strength: config.defaultStrength,
  customThreshold: 0.5,
  model: config.openRouterModel,
  aiTimeoutMs: config.aiTimeoutMs,
  aiBodyLimit: config.aiBodyLimit,
  upstreamUrl: config.upstreamUrl,
  jevBaseUrl: config.jevBaseUrl,
  apiKeyConfigured: Boolean(config.openRouterKey),
  apiKeySource: config.openRouterKey ? "environment" : "none"
  };
}

export type AttackerRecord = GeoPoint & {
  ip?: string | undefined;
  count: number;
  path: string;
  rules: string[];
  lastSeen: string;
};

export type AttackMap = {
  points: Array<GeoPoint & { ip?: string | undefined; count: number }>;
  countries: Array<{ name: string; count: number }>;
  attackers: AttackerRecord[];
  blocked: number;
};

export class Store {
  private readonly pool: Pool | null;
  private readonly local: LocalDatabase | null;
  private readonly geoIp = new GeoIpResolver();
  private settings: AppSettings = defaultSettings();
  private initialized = Boolean(config.adminPassword && config.adminPassword !== "change-me-now");
  private readonly sites = new Map<string, Site>();
  private rules: WafRule[] = BUILTIN_RULES.map(withRuleMetadata);
  private readonly events: EventRecord[] = [];
  private credential: { salt: string; hash: string } | undefined;
  private apiKeyCiphertext: string | null = null;
  private setupInProgress = false;
  private mutationQueue: Promise<unknown> = Promise.resolve();
  private builtinRuleIds = new Set<string>();
  private siteChangeListener: (() => void | Promise<void>) | undefined;

  constructor() {
    this.pool = config.databaseUrl ? new Pool({ connectionString: config.databaseUrl }) : null;
    this.local = this.pool ? null : new LocalDatabase(config.dataDir);
    this.sites.set("default", {
      id: "default",
      name: "默认站点",
      listenPort: config.proxyPort,
      upstreamUrl: this.settings.upstreamUrl,
      mode: this.settings.mode,
      enabled: true,
      createdAt: new Date().toISOString()
    });
  }

  async init(): Promise<void> {
    await this.geoIp.init();
    if (!this.pool) {
      const state = this.local!.readState();
      if (state) {
        this.settings = state.settings;
        this.initialized = Boolean(state.initialized && state.credential);
        this.credential = state.credential;
        this.apiKeyCiphertext = state.apiKeyCiphertext;
        this.rules = state.rules;
        this.builtinRuleIds = new Set(state.builtinRuleIds ?? state.rules.map((rule) => rule.id));
        this.sites.clear();
        for (const site of state.sites) this.sites.set(site.id, site);
      } else if (this.initialized) {
        this.credential = makeAdminCredential(config.adminPassword);
      }
      if (this.credential) loadAdminCredential(this.credential.salt, this.credential.hash);
      const known = new Set(this.rules.map((rule) => rule.id));
      for (const rule of BUILTIN_RULES) {
        if (!known.has(rule.id) && !this.builtinRuleIds.has(rule.id)) this.rules.push(withRuleMetadata(rule));
        this.builtinRuleIds.add(rule.id);
      }
      this.syncRuntimeSettings();
      const site = this.sites.get("default");
      if (site) {
        site.listenPort = config.proxyPort;
        site.upstreamUrl = this.settings.upstreamUrl;
        site.mode = this.settings.mode;
      } else {
        this.sites.set("default", {
          id: "default",
          name: "默认站点",
          listenPort: config.proxyPort,
          upstreamUrl: this.settings.upstreamUrl,
          mode: this.settings.mode,
          enabled: true,
          createdAt: new Date().toISOString()
        });
      }
      this.normalizeSitePorts();
      this.normalizeUnavailableSiteModes();
      this.local!.writeState(this.snapshot());
      for (const event of this.local!.readEvents()) this.events.push(event);
      return;
    }

    await migrate();
    await this.pool.query(
      `INSERT INTO settings (upstream_url, jev_base_url, initialized, mode, strength,
       custom_threshold, model, ai_timeout_ms, ai_body_limit)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (id) DO NOTHING`,
      [this.settings.upstreamUrl, this.settings.jevBaseUrl, this.initialized, this.settings.mode, this.settings.strength,
        this.settings.customThreshold, this.settings.model, this.settings.aiTimeoutMs, this.settings.aiBodyLimit]
    );
    const settingResult = await this.pool.query(
      `SELECT mode, strength, custom_threshold, model, jev_base_url,
              api_key_ciphertext, admin_password_salt, admin_password_hash,
              initialized, ai_timeout_ms, ai_body_limit, upstream_url
       FROM settings WHERE id = 1`
    );
    const row = settingResult.rows[0] as Record<string, unknown> | undefined;
    if (row) {
      this.settings = {
        mode: row.mode as ProtectionMode,
        strength: row.strength as ProtectionStrength,
        customThreshold: Number(row.custom_threshold),
        model: String(row.model),
        jevBaseUrl: normalizeBaseUrl(String(row.jev_base_url)),
        aiTimeoutMs: Number(row.ai_timeout_ms),
        aiBodyLimit: Number(row.ai_body_limit),
        upstreamUrl: String(row.upstream_url),
        apiKeyConfigured: Boolean(config.environmentApiKey || row.api_key_ciphertext),
        apiKeySource: row.api_key_ciphertext ? "database" : config.environmentApiKey ? "environment" : "none"
      };
      this.initialized = Boolean(row.initialized);
      if (row.admin_password_salt && row.admin_password_hash) {
        this.credential = { salt: String(row.admin_password_salt), hash: String(row.admin_password_hash) };
        loadAdminCredential(this.credential.salt, this.credential.hash);
        this.initialized = true;
      } else if (this.initialized && config.adminPassword) {
        configureAdmin(config.adminPassword);
      }
      this.apiKeyCiphertext = row.api_key_ciphertext ? String(row.api_key_ciphertext) : null;
    }
    if (this.initialized && !row?.admin_password_hash && config.adminPassword) {
      this.credential = exportAdminCredential();
      await this.persistAdminCredential();
    }
    this.syncRuntimeSettings();

    await this.pool.query(
      `INSERT INTO sites (id, name, listen_port, upstream_url, mode, enabled)
       VALUES ('default', $1, $2, $3, $4, TRUE)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name,
       listen_port = EXCLUDED.listen_port, upstream_url = EXCLUDED.upstream_url,
       mode = EXCLUDED.mode, enabled = TRUE`,
      ["默认站点", config.proxyPort, this.settings.upstreamUrl, this.settings.mode]
    );

    const ruleResult = await this.pool.query(`SELECT * FROM rules ORDER BY created_at ASC`);
    this.rules = ruleResult.rows.map(mapRule);
    const catalog = await this.pool.query("SELECT id FROM builtin_rule_catalog");
    const known = new Set(catalog.rows.map((entry) => String(entry.id)));
    for (const rule of BUILTIN_RULES) {
      if (!known.has(rule.id)) {
        const current = this.rules.find((item) => item.id === rule.id);
        if (!current) await this.saveRule(withRuleMetadata(rule));
        await this.pool.query("INSERT INTO builtin_rule_catalog (id) VALUES ($1) ON CONFLICT DO NOTHING", [rule.id]);
      }
    }
    const siteResult = await this.pool.query(`SELECT * FROM sites ORDER BY created_at ASC`);
    if (siteResult.rows.length > 0) {
      this.sites.clear();
      for (const site of siteResult.rows) this.sites.set(String(site.id), mapSite(site));
    }
    this.normalizeSitePorts();
    this.normalizeUnavailableSiteModes();
    await this.persistSiteCompatibilityFields();
  }

  setupStatus(): {
    initialized: boolean;
    databaseConfigured: boolean;
    aiConfigured: boolean;
    geoIpConfigured: boolean;
  } {
    return {
      initialized: this.initialized,
      databaseConfigured: Boolean(this.pool),
      aiConfigured: Boolean(config.openRouterKey),
      geoIpConfigured: this.geoIp.isReady
    };
  }

  async health(): Promise<boolean> {
    try {
      if (this.pool) await this.pool.query("SELECT 1");
      else this.local!.readState();
      return true;
    } catch {
      return false;
    }
  }

  async completeSetup(password: string): Promise<void> {
    if (this.initialized || this.setupInProgress) throw new SetupConflictError("系统已经完成初始化或正在初始化");
    if (password.trim().length < 8) throw new ValidationError("管理员密码至少需要 8 个字符");
    if (password.length > 1024) throw new ValidationError("管理员密码不能超过 1024 个字符");
    this.setupInProgress = true;
    try {
      const credential = makeAdminCredential(password);
      if (this.pool) {
        const result = await this.pool.query(
          `UPDATE settings SET admin_password_salt = $1, admin_password_hash = $2,
           initialized = TRUE, updated_at = NOW() WHERE id = 1 AND initialized = FALSE`,
          [credential.salt, credential.hash]
        );
        if (result.rowCount !== 1) throw new SetupConflictError("系统已经完成初始化");
      } else {
        this.local!.completeSetup({ ...this.snapshot(), initialized: true, credential });
      }
      this.credential = credential;
      this.initialized = true;
      loadAdminCredential(credential.salt, credential.hash);
    } finally {
      this.setupInProgress = false;
    }
  }

  private async persistAdminCredential(): Promise<void> {
    if (!this.pool) return;
    const credential = exportAdminCredential();
    await this.pool.query(
      `UPDATE settings SET admin_password_salt = $1, admin_password_hash = $2,
       initialized = TRUE, updated_at = NOW() WHERE id = 1`,
      [credential.salt, credential.hash]
    );
  }

  getSettings(): AppSettings {
    return {
      ...this.settings,
      apiKeyConfigured: Boolean(config.openRouterKey),
      apiKeySource: this.settings.apiKeySource
    };
  }

  async updateSettings(next: SettingsUpdate): Promise<AppSettings> {
    return this.serializeMutation(() => this.commitSettings(next));
  }

  private async commitSettings(next: SettingsUpdate): Promise<AppSettings> {
    const { apiKey, ...settings } = next;
    const candidate = {
      ...this.settings,
      ...settings,
      jevBaseUrl: settings.jevBaseUrl ? normalizeBaseUrl(settings.jevBaseUrl) : this.settings.jevBaseUrl
    };
    let apiKeyCiphertext = this.apiKeyCiphertext;
    if (apiKey !== undefined) {
      if (apiKey === null || apiKey.trim() === "") {
        apiKeyCiphertext = null;
      } else {
        if (apiKey.length > 8192) throw new ValidationError("API key 超过长度限制");
        apiKeyCiphertext = encryptSecret(apiKey.trim(), config.sessionSecret);
      }
    }
    const effectiveApiKey = apiKey !== undefined
      ? (apiKeyCiphertext ? decryptSecret(apiKeyCiphertext, config.sessionSecret) : config.environmentApiKey)
      : config.openRouterKey;
    candidate.mode = effectiveApiKey ? candidate.mode : "traditional";
    validateSettings(candidate);
    if (this.pool) {
      await this.pool.query(
        `UPDATE settings SET mode = $1, strength = $2, custom_threshold = $3,
         model = $4, jev_base_url = $5, ai_timeout_ms = $6, ai_body_limit = $7,
         upstream_url = $8,
         api_key_ciphertext = CASE WHEN $9::boolean THEN $10::text ELSE api_key_ciphertext END,
         updated_at = NOW() WHERE id = 1`,
        [
          candidate.mode, candidate.strength, candidate.customThreshold, candidate.model,
          candidate.jevBaseUrl, candidate.aiTimeoutMs, candidate.aiBodyLimit, candidate.upstreamUrl,
          apiKey !== undefined,
          apiKeyCiphertext ?? null
        ]
      );
    }
    this.settings = candidate;
    this.apiKeyCiphertext = apiKeyCiphertext;
    this.syncRuntimeSettings();
    const defaultSite = this.sites.get("default");
    if (defaultSite) {
      defaultSite.upstreamUrl = this.settings.upstreamUrl;
      defaultSite.mode = this.settings.mode;
    }
    if (this.pool) await this.persistDefaultSite();
    else this.local!.writeState(this.snapshot());
    await this.notifySitesChanged();
    return this.getSettings();
  }

  listSites(): Site[] {
    return [...this.sites.values()].map((site) => ({ ...site }));
  }

  getSiteByPort(port: number): Site | undefined {
    const site = [...this.sites.values()].find((entry) => entry.listenPort === port && entry.enabled);
    return site ? { ...site } : undefined;
  }

  setSiteChangeListener(listener: (() => void | Promise<void>) | undefined): void {
    this.siteChangeListener = listener;
  }

  async saveSite(input: Omit<Site, "createdAt" | "id"> & { id?: string; listenPort?: number }): Promise<Site> {
    return this.serializeMutation(async () => {
      const current = input.id ? this.sites.get(input.id) : undefined;
      const listenPort = input.listenPort ?? current?.listenPort ?? this.findAvailableSitePort();
      const candidate = { ...input, listenPort };
      validateSite(candidate);
      if (input.id === "default" && listenPort !== config.proxyPort) {
        throw new ValidationError(`默认站点必须使用入口端口 ${config.proxyPort}`);
      }
      const duplicate = [...this.sites.values()].find((site) => site.id !== input.id && site.listenPort === listenPort);
      if (duplicate) throw new ConflictError(`入口端口 ${listenPort} 已被站点“${duplicate.name}”占用`);
      const site: Site = {
        id: input.id ?? randomUUID(),
        name: input.name,
        listenPort,
        upstreamUrl: input.upstreamUrl,
        mode: effectiveProtectionMode(input.mode, Boolean(config.openRouterKey)),
        enabled: input.enabled,
        createdAt: current?.createdAt ?? new Date().toISOString()
      };
      if (site.id === "default") {
        this.settings.upstreamUrl = site.upstreamUrl;
        this.settings.mode = site.mode;
      }
      if (this.pool) {
        await this.pool.query(
          `INSERT INTO sites (id, name, listen_port, upstream_url, mode, enabled)
           VALUES ($1, $2, $3, $4, $5, $6)
           ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, listen_port = EXCLUDED.listen_port,
           upstream_url = EXCLUDED.upstream_url, mode = EXCLUDED.mode, enabled = EXCLUDED.enabled`,
          [site.id, site.name, site.listenPort, site.upstreamUrl, site.mode, site.enabled]
        );
        if (site.id === "default") {
          await this.pool.query(
            `UPDATE settings SET upstream_url = $1, mode = $2, updated_at = NOW() WHERE id = 1`,
            [site.upstreamUrl, site.mode]
          );
        }
      } else {
        this.local!.writeState({ ...this.snapshot(), sites: [...this.sites.values()].filter((item) => item.id !== site.id).concat(site) });
      }
      this.sites.set(site.id, site);
      await this.notifySitesChanged();
      return { ...site };
    });
  }

  async deleteSite(id: string): Promise<void> {
    return this.serializeMutation(async () => {
      if (id === "default") throw new ConflictError("默认站点不能删除");
      if (this.pool) await this.pool.query(`DELETE FROM sites WHERE id = $1`, [id]);
      else this.local!.writeState({ ...this.snapshot(), sites: [...this.sites.values()].filter((site) => site.id !== id) });
      this.sites.delete(id);
      await this.notifySitesChanged();
    });
  }

  listRules(): WafRule[] {
    return this.rules.map((rule) => structuredClone(withRuleMetadata(rule)));
  }

  async saveRule(input: WafRule): Promise<WafRule> {
    return (await this.importRules([input], "overwrite")).data[0]!;
  }

  async importRules(input: WafRule[], conflict: "reject" | "overwrite" | "skip" = "reject", enabled?: boolean):
    Promise<{ data: WafRule[]; skipped: number }> {
    return this.serializeMutation(async () => {
      const candidates = input.map((rule) => validateRule({ ...rule, ...(enabled === undefined ? {} : { enabled }) }));
      if (new Set(candidates.map((rule) => rule.id)).size !== candidates.length) throw new ValidationError("规则包包含重复 id");
      let current = this.rules;
      const client = this.pool ? await this.pool.connect() : null;
      try {
        if (client) {
          await client.query("BEGIN");
          await client.query("LOCK TABLE rules IN SHARE ROW EXCLUSIVE MODE");
          current = (await client.query("SELECT * FROM rules ORDER BY created_at ASC")).rows.map(mapRule);
        }
        const ids = new Set(current.map((rule) => rule.id));
        const conflicts = candidates.filter((rule) => ids.has(rule.id));
        if (conflict === "reject" && conflicts.length) throw new ValidationError(`规则 id 已存在：${conflicts.map((rule) => rule.id).join("、")}`);
        const saved = conflict === "skip" ? candidates.filter((rule) => !ids.has(rule.id)) : candidates;
        const savedIds = new Set(saved.map((rule) => rule.id));
        const rules = [...current.filter((rule) => !savedIds.has(rule.id)), ...saved];
        if (rules.length > MAX_TOTAL_RULES) throw new ValidationError("规则总数不能超过 5000 条");
        if (client) {
          for (const rule of saved) {
            await client.query(
              `INSERT INTO rules (id, name, source, category, severity, target, operator, pattern, action, enabled, package_id, license, options)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
               ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, source = EXCLUDED.source,
               category = EXCLUDED.category, severity = EXCLUDED.severity, target = EXCLUDED.target,
               operator = EXCLUDED.operator, pattern = EXCLUDED.pattern, action = EXCLUDED.action,
               enabled = EXCLUDED.enabled, package_id = EXCLUDED.package_id, license = EXCLUDED.license, options = EXCLUDED.options`,
              [rule.id, rule.name, rule.source, rule.category, rule.severity, rule.target, rule.operator,
                rule.pattern, rule.action, rule.enabled, rule.packageId, rule.license, JSON.stringify(ruleOptions(rule))]
            );
          }
          await client.query("COMMIT");
        } else {
          this.local!.writeState({ ...this.snapshot(), rules });
        }
        this.rules = rules;
        return { data: saved.map((rule) => structuredClone(rule)), skipped: candidates.length - saved.length };
      } catch (error) {
        if (client) await client.query("ROLLBACK");
        throw error;
      } finally {
        client?.release();
      }
    });
  }

  async deleteRule(id: string): Promise<void> {
    return this.serializeMutation(async () => {
      if (this.pool) await this.pool.query(`DELETE FROM rules WHERE id = $1`, [id]);
      else this.local!.writeState({ ...this.snapshot(), rules: this.rules.filter((rule) => rule.id !== id) });
      this.rules = this.rules.filter((rule) => rule.id !== id);
    });
  }

  async saveEvent(
    decision: WafDecision,
    request: { method: string; path: string; ip?: string | undefined },
    statusCode?: number
  ): Promise<void> {
    const geo = this.geoIp.lookup(request.ip);
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
      ...geo,
      createdAt: new Date().toISOString()
    };
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO events
         (request_id, action, mode, method, path, ip, status_code, score, threshold, reason,
          matched_rules, ai, partial_inspection, country, region, city, latitude, longitude, asn)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
         ON CONFLICT (request_id) WHERE finalized DO NOTHING`,
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
          record.partialInspection,
          record.country ?? null,
          record.region ?? null,
          record.city ?? null,
          record.latitude ?? null,
          record.longitude ?? null,
          record.asn ?? null
        ]
      );
    } else {
      const id = this.local!.saveEvent(record);
      if (id !== undefined) this.events.unshift({ ...record, id });
    }
  }

  async listEvents(filters: EventFilters = {}): Promise<{ data: EventRecord[]; nextCursor?: string }> {
    validateFilters(filters);
    const cursor = filters.cursor ? decodeCursor(filters.cursor) : undefined;
    const safeLimit = Math.min(Math.max(filters.limit ?? 50, 1), 500);
    if (!this.pool) {
      const filtered = this.events.filter((event) =>
        (!cursor || event.createdAt < cursor.time || (event.createdAt === cursor.time && BigInt(event.id) < BigInt(cursor.id)))
        && (!filters.action || event.action === filters.action)
        && (!filters.ip || event.ip === filters.ip)
        && (!filters.since || Date.parse(event.createdAt) >= Date.parse(filters.since))
        && (!filters.until || Date.parse(event.createdAt) <= Date.parse(filters.until))
        && (!filters.search || [event.path, event.requestId, event.ip ?? ""].some((text) => text.toLowerCase().includes(filters.search!.toLowerCase())))
      );
      const page = filtered.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || Number(b.id) - Number(a.id)).slice(0, safeLimit + 1);
      const data = page.slice(0, safeLimit);
      return {
        data,
        ...(page.length > safeLimit && data.length ? { nextCursor: encodeCursor(data[data.length - 1]!) } : {})
      };
    }
    const conditions: string[] = ["finalized"];
    const values: unknown[] = [];
    const add = (sql: string, value: unknown): void => {
      values.push(value);
      conditions.push(sql.replace("?", `$${values.length}`));
    };
    if (cursor) {
      values.push(cursor.time, cursor.id);
      conditions.push(`(created_at, id) < ($${values.length - 1}::timestamptz, $${values.length}::bigint)`);
    }
    if (filters.action) add(`action = ?`, filters.action);
    if (filters.ip) add(`ip = ?`, filters.ip);
    if (filters.since) add(`created_at >= ?::timestamptz`, filters.since);
    if (filters.until) add(`created_at <= ?::timestamptz`, filters.until);
    if (filters.search) add(`strpos(lower(path || ' ' || request_id || ' ' || COALESCE(ip, '')), lower(?)) > 0`, filters.search);
    values.push(safeLimit + 1);
    const limitPlaceholder = `$${values.length}`;
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await this.pool.query(
      `SELECT id, request_id, action, mode, method, path, ip, status_code, score, threshold,
       reason, matched_rules, ai, partial_inspection, country, region, city, latitude, longitude, asn, created_at,
       created_at::text AS cursor_time
       FROM events ${where} ORDER BY created_at DESC, id DESC LIMIT ${limitPlaceholder}`,
      values
    );
    const mapped = result.rows.map(mapEvent);
    const data = mapped.slice(0, safeLimit);
    return {
      data,
      ...(mapped.length > safeLimit && data.length ? { nextCursor: encodeCursor(data[data.length - 1]!, String(result.rows[data.length - 1]!.cursor_time)) } : {})
    };
  }

  async summary(): Promise<Record<string, number>> {
    if (this.pool) {
      const result = await this.pool.query(`
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE action = 'block')::int AS blocked,
          COUNT(*) FILTER (WHERE action = 'allow')::int AS allowed,
          COUNT(*) FILTER (WHERE action = 'error')::int AS errors,
          COUNT(*) FILTER (WHERE mode = 'ai')::int AS ai,
          COUNT(*) FILTER (WHERE mode = 'traditional')::int AS traditional,
          COUNT(*) FILTER (WHERE mode = 'hybrid')::int AS hybrid,
          COUNT(*) FILTER (WHERE (ai->>'available')::boolean = FALSE)::int AS ai_unavailable
        FROM events WHERE finalized
      `);
      const row = result.rows[0] as Record<string, unknown>;
      return {
        total: Number(row.total),
        blocked: Number(row.blocked),
        allowed: Number(row.allowed),
        errors: Number(row.errors),
        ai: Number(row.ai),
        traditional: Number(row.traditional),
        hybrid: Number(row.hybrid),
        aiUnavailable: Number(row.ai_unavailable)
      };
    }
    return summarize(this.events);
  }

  async attackMap(hours = 24): Promise<AttackMap> {
    const safeHours = Math.min(Math.max(Math.floor(hours), 1), 168);
    if (this.pool) {
      const scope = `finalized AND action = 'block' AND created_at >= NOW() - ($1 * INTERVAL '1 hour')`;
      const [total, countries, points, attackers] = await Promise.all([
        this.pool.query(`SELECT COUNT(*) AS count FROM events WHERE ${scope}`, [safeHours]),
        this.pool.query(`SELECT COALESCE(country, '未知地区') AS name, COUNT(*) AS count
          FROM events WHERE ${scope} GROUP BY country ORDER BY count DESC, name LIMIT 10`, [safeHours]),
        this.pool.query(`SELECT latitude, longitude, country, region, city, ip, COUNT(*) AS count
          FROM events WHERE ${scope} AND latitude IS NOT NULL AND longitude IS NOT NULL
          GROUP BY latitude, longitude, country, region, city, ip ORDER BY count DESC LIMIT 500`, [safeHours]),
        this.pool.query(`
          WITH ranked AS (
            SELECT ip, COUNT(*) AS count, MAX(created_at) AS last_seen FROM events WHERE ${scope}
            GROUP BY ip ORDER BY count DESC LIMIT 20
          )
          SELECT ranked.*, latest.path, latest.country, latest.region, latest.city, latest.asn,
                 ARRAY(SELECT DISTINCT rule->>'name' FROM events, jsonb_array_elements(matched_rules) AS rule
                   WHERE ${scope} AND events.ip IS NOT DISTINCT FROM ranked.ip
                   AND rule->>'name' IS NOT NULL LIMIT 50) AS rules
          FROM ranked JOIN LATERAL (
            SELECT path, country, region, city, asn FROM events WHERE ${scope}
            AND events.ip IS NOT DISTINCT FROM ranked.ip ORDER BY created_at DESC, id DESC LIMIT 1
          ) latest ON TRUE ORDER BY ranked.count DESC, ranked.ip`, [safeHours])
      ]);
      return {
        blocked: Number(total.rows[0]!.count),
        countries: countries.rows.map((row) => ({ name: String(row.name), count: Number(row.count) })),
        points: points.rows.map((row) => ({
          latitude: Number(row.latitude), longitude: Number(row.longitude), country: row.country ?? undefined,
          region: row.region ?? undefined, city: row.city ?? undefined, ip: row.ip ?? undefined, count: Number(row.count)
        })),
        attackers: attackers.rows.map((row) => ({
          ip: row.ip ?? undefined, count: Number(row.count), path: String(row.path), rules: row.rules as string[],
          country: row.country ?? undefined, region: row.region ?? undefined, city: row.city ?? undefined,
          asn: row.asn === null ? undefined : Number(row.asn), lastSeen: new Date(row.last_seen as string).toISOString()
        }))
      };
    }
    const events = this.events.filter((event) => Date.now() - Date.parse(event.createdAt) <= safeHours * 60 * 60 * 1000 && event.action === "block");
    const countryCounts = new Map<string, number>();
    const pointCounts = new Map<string, GeoPoint & { ip?: string | undefined; count: number }>();
    const attackerCounts = new Map<string, AttackerRecord>();
    for (const event of events) {
      const country = event.country ?? "未知地区";
      countryCounts.set(country, (countryCounts.get(country) ?? 0) + 1);
      const attacker = attackerCounts.get(event.ip ?? "");
      const ruleNames = event.matchedRules.flatMap((rule) =>
        rule && typeof rule === "object" && "name" in rule ? [String(rule.name)] : []);
      const latest = !attacker || event.createdAt >= attacker.lastSeen;
      attackerCounts.set(event.ip ?? "", {
        ip: event.ip, count: (attacker?.count ?? 0) + 1, path: latest ? event.path : attacker.path,
        rules: [...new Set([...(attacker?.rules ?? []), ...ruleNames])].slice(0, 50),
        lastSeen: latest ? event.createdAt : attacker.lastSeen, country: event.country,
        region: event.region, city: event.city, asn: event.asn
      });
      if (event.latitude === undefined || event.longitude === undefined) continue;
      const key = `${event.latitude.toFixed(2)}:${event.longitude.toFixed(2)}`;
      const previous = pointCounts.get(key);
      pointCounts.set(key, {
        latitude: event.latitude,
        longitude: event.longitude,
        country: event.country,
        region: event.region,
        city: event.city,
        ip: event.ip,
        count: (previous?.count ?? 0) + 1
      });
    }
    return {
      points: [...pointCounts.values()],
      countries: [...countryCounts.entries()]
        .map(([name, count]) => ({ name, count }))
        .sort((left, right) => right.count - left.count)
        .slice(0, 10),
      blocked: events.length,
      attackers: [...attackerCounts.values()].sort((a, b) => b.count - a.count).slice(0, 20)
    };
  }

  async timeseries(hours = 24): Promise<TimeSeriesPoint[]> {
    const safeHours = Math.min(Math.max(Math.floor(hours), 1), 168);
    const currentHour = new Date();
    currentHour.setMinutes(0, 0, 0);
    const start = new Date(currentHour.getTime() - (safeHours - 1) * 60 * 60 * 1000);
    const buckets = new Map<string, TimeSeriesPoint>();
    for (let index = 0; index < safeHours; index += 1) {
      const time = new Date(start.getTime() + index * 60 * 60 * 1000);
      const key = time.toISOString();
      buckets.set(key, { time: key, total: 0, allowed: 0, blocked: 0, errors: 0 });
    }
    if (this.pool) {
      const result = await this.pool.query(
        `SELECT date_trunc('hour', created_at) AS bucket,
                COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE action = 'allow')::int AS allowed,
                COUNT(*) FILTER (WHERE action = 'block')::int AS blocked,
                COUNT(*) FILTER (WHERE action = 'error')::int AS errors
         FROM events
         WHERE finalized AND created_at >= NOW() - ($1 * INTERVAL '1 hour')
         GROUP BY 1 ORDER BY 1`,
        [safeHours]
      );
      for (const row of result.rows) {
        const key = new Date(row.bucket as string).toISOString();
        const bucket = buckets.get(key);
        if (bucket) {
          bucket.total = Number(row.total);
          bucket.allowed = Number(row.allowed);
          bucket.blocked = Number(row.blocked);
          bucket.errors = Number(row.errors);
        }
      }
    } else {
      for (const event of this.events) {
        const date = new Date(event.createdAt);
        if (date < start) continue;
        date.setMinutes(0, 0, 0);
        const bucket = buckets.get(date.toISOString());
        if (!bucket) continue;
        bucket.total += 1;
        if (event.action === "allow") bucket.allowed += 1;
        if (event.action === "block") bucket.blocked += 1;
        if (event.action === "error") bucket.errors += 1;
      }
    }
    return [...buckets.values()];
  }

  private snapshot(): LocalState {
    return {
      settings: this.settings, initialized: this.initialized, credential: this.credential,
      apiKeyCiphertext: this.apiKeyCiphertext, rules: this.rules, sites: [...this.sites.values()],
      builtinRuleIds: [...this.builtinRuleIds]
    };
  }

  private syncRuntimeSettings(): void {
    config.jevBaseUrl = this.settings.jevBaseUrl;
    config.openRouterModel = this.settings.model;
    config.openRouterKey = this.apiKeyCiphertext
      ? decryptSecret(this.apiKeyCiphertext, config.sessionSecret) : config.environmentApiKey;
    this.settings.apiKeyConfigured = Boolean(config.openRouterKey);
    this.settings.apiKeySource = this.apiKeyCiphertext ? "database" : config.environmentApiKey ? "environment" : "none";
  }

  private normalizeSitePorts(): void {
    const used = new Set<number>();
    const ordered = [...this.sites.values()].sort((left, right) => {
      if (left.id === "default") return -1;
      if (right.id === "default") return 1;
      return left.createdAt.localeCompare(right.createdAt);
    });
    for (const site of ordered) {
      if (!isSitePort(site.listenPort) || used.has(site.listenPort)) {
        site.listenPort = this.findAvailableSitePort(used);
      }
      used.add(site.listenPort);
    }
  }

  private normalizeUnavailableSiteModes(): void {
    if (config.openRouterKey) return;
    for (const site of this.sites.values()) {
      if (site.mode !== "traditional") site.mode = "traditional";
    }
    if (this.settings.mode !== "traditional") this.settings.mode = "traditional";
  }

  private findAvailableSitePort(used = new Set([...this.sites.values()].map((site) => site.listenPort))): number {
    for (let port = config.sitePortRange.min; port <= config.sitePortRange.max; port += 1) {
      if (!used.has(port)) return port;
    }
    throw new ValidationError(`没有可用的站点入口端口（${formatPortRange()}）`);
  }

  private async persistSiteCompatibilityFields(): Promise<void> {
    if (!this.pool) return;
    for (const site of this.sites.values()) {
      await this.pool.query(
        `UPDATE sites SET listen_port = $1, mode = $2 WHERE id = $3`,
        [site.listenPort, site.mode, site.id]
      );
    }
    await this.pool.query(`UPDATE settings SET mode = $1 WHERE id = 1`, [this.settings.mode]);
  }

  private async persistDefaultSite(): Promise<void> {
    const site = this.sites.get("default");
    if (!site) return;
    if (!this.pool) {
      this.local!.writeState(this.snapshot());
      return;
    }
    await this.pool.query(
      `INSERT INTO sites (id, name, listen_port, upstream_url, mode, enabled)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name,
       listen_port = EXCLUDED.listen_port, upstream_url = EXCLUDED.upstream_url,
       mode = EXCLUDED.mode, enabled = EXCLUDED.enabled`,
      [site.id, site.name, site.listenPort, site.upstreamUrl, site.mode, site.enabled]
    );
  }

  private async notifySitesChanged(): Promise<void> {
    await this.siteChangeListener?.();
  }

  private serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(operation);
    this.mutationQueue = result.catch(() => {});
    return result;
  }

  async close(): Promise<void> {
    await this.mutationQueue;
    this.local?.close();
    await this.pool?.end();
  }
}

function validateSettings(settings: AppSettings): void {
  if (!["ai", "traditional", "hybrid"].includes(settings.mode)) throw new ValidationError("防护模式无效");
  if (!["veryLow", "low", "medium", "high", "extreme", "custom"].includes(settings.strength)) throw new ValidationError("防护强度无效");
  if (!Number.isFinite(settings.customThreshold) || settings.customThreshold < 0 || settings.customThreshold > 1) throw new ValidationError("阈值必须在 0 到 1 之间");
  if (!Number.isInteger(settings.aiTimeoutMs) || settings.aiTimeoutMs < 100 || settings.aiTimeoutMs > 60000) throw new ValidationError("AI 超时必须在 100 到 60000 毫秒之间");
  if (!Number.isInteger(settings.aiBodyLimit) || settings.aiBodyLimit < 1024 || settings.aiBodyLimit > config.maxRequestBodyBytes) throw new ValidationError("AI 正文限制超出有效范围");
  if (!settings.model.trim() || settings.model.length > 256) throw new ValidationError("模型名称无效");
  for (const value of [settings.upstreamUrl, settings.jevBaseUrl]) {
    let url: URL;
    try { url = new URL(value); } catch { throw new ValidationError("服务地址必须是完整 HTTP(S) URL"); }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || url.search) {
      throw new ValidationError("服务地址仅支持不含凭据、查询串和片段的 HTTP(S) URL");
    }
  }
}

function validateSite(site: Omit<Site, "createdAt" | "id"> & { id?: string }): void {
  if (!site.name.trim() || site.name.length > 256) throw new ValidationError("站点名称必须是 1 到 256 字符");
  if (!isSitePort(site.listenPort)) throw new ValidationError(`入口端口必须在 ${formatPortRange()} 范围内`);
  if (!["ai", "traditional", "hybrid"].includes(site.mode)) throw new ValidationError("站点防护模式无效");
  if (typeof site.enabled !== "boolean") throw new ValidationError("站点启用状态无效");
  validateHttpEndpoint(site.upstreamUrl, "上游地址");
}

function validateHttpEndpoint(value: string, label: string): void {
  let url: URL;
  try { url = new URL(value); } catch { throw new ValidationError(`${label}必须是完整 HTTP(S) URL`); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || url.search) {
    throw new ValidationError(`${label}仅支持不含凭据、查询串和片段的 HTTP(S) URL`);
  }
}

function validateFilters(filters: EventFilters): void {
  if (filters.limit !== undefined && (!Number.isInteger(filters.limit) || filters.limit < 1 || filters.limit > 500)) throw new ValidationError("分页大小必须在 1 到 500 之间");
  for (const time of [filters.since, filters.until]) {
    if (time && !Number.isFinite(Date.parse(time))) throw new ValidationError("时间过滤格式无效");
  }
  if (filters.since && filters.until && Date.parse(filters.since) > Date.parse(filters.until)) throw new ValidationError("开始时间不能晚于结束时间");
  if (filters.search && filters.search.length > 256) throw new ValidationError("搜索不能超过 256 字符");
}

function encodeCursor(event: EventRecord, time = event.createdAt): string {
  return Buffer.from(JSON.stringify({ time, id: String(event.id) })).toString("base64url");
}

function decodeCursor(value: string): { time: string; id: string } {
  try {
    if (value.length > 256 || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error();
    const cursor = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as { time: string; id: string };
    if (typeof cursor.time !== "string" || !Number.isFinite(Date.parse(cursor.time))
      || typeof cursor.id !== "string" || !/^\d{1,19}$/.test(cursor.id) || BigInt(cursor.id) > 9223372036854775807n) throw new Error();
    return cursor;
  } catch {
    throw new ValidationError("分页游标无效");
  }
}

function normalizeBaseUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  return trimmed.replace(/\/api\/(?:alpha|v1)\/decisions$/, "");
}

function withRuleMetadata(rule: WafRule): WafRule {
  return {
    ...rule,
    packageId: rule.packageId ?? "jianflow-core",
    license: rule.license ?? "MIT"
  };
}

function summarize(events: EventRecord[]): Record<string, number> {
  return {
    total: events.length,
    blocked: events.filter((event) => event.action === "block").length,
    allowed: events.filter((event) => event.action === "allow").length,
    errors: events.filter((event) => event.action === "error").length,
    ai: events.filter((event) => event.mode === "ai").length,
    traditional: events.filter((event) => event.mode === "traditional").length,
    hybrid: events.filter((event) => event.mode === "hybrid").length,
    aiUnavailable: events.filter((event) => Boolean(event.ai && (event.ai as { available?: boolean }).available === false)).length
  };
}

function mapRule(row: QueryResultRow): WafRule {
  return {
    ...((row.options as Partial<WafRule>) ?? {}),
    id: String(row.id),
    name: String(row.name),
    source: String(row.source),
    category: String(row.category),
    severity: row.severity as WafRule["severity"],
    target: row.target as WafRule["target"],
    operator: row.operator as WafRule["operator"],
    pattern: String(row.pattern),
    action: row.action as WafRule["action"],
    enabled: Boolean(row.enabled),
    packageId: String(row.package_id ?? "jianflow-core"),
    license: String(row.license ?? "MIT")
  };
}

function ruleOptions(rule: WafRule): Partial<WafRule> {
  const { id, name, source, category, severity, target, operator, pattern, action, enabled, packageId, license, ...options } = rule;
  return options;
}

function mapSite(row: QueryResultRow): Site {
  return {
    id: String(row.id),
    name: String(row.name),
    listenPort: row.listen_port === null || row.listen_port === undefined ? 0 : Number(row.listen_port),
    upstreamUrl: String(row.upstream_url),
    mode: row.mode as ProtectionMode,
    enabled: Boolean(row.enabled),
    createdAt: new Date(row.created_at as string).toISOString()
  };
}

function isSitePort(value: unknown): value is number {
  return typeof value === "number"
    && Number.isInteger(value)
    && value >= config.sitePortRange.min
    && value <= config.sitePortRange.max;
}

function formatPortRange(): string {
  return config.sitePortRange.min === config.sitePortRange.max
    ? String(config.sitePortRange.min)
    : `${config.sitePortRange.min}-${config.sitePortRange.max}`;
}

function effectiveProtectionMode(mode: ProtectionMode, aiConfigured: boolean): ProtectionMode {
  return aiConfigured || mode === "traditional" ? mode : "traditional";
}

function mapEvent(row: QueryResultRow): EventRecord {
  return {
    id: row.id as string | number,
    requestId: String(row.request_id ?? ""),
    action: String(row.action),
    mode: String(row.mode),
    method: String(row.method ?? ""),
    path: String(row.path ?? ""),
    ip: row.ip ? String(row.ip) : undefined,
    statusCode: row.status_code === null ? undefined : Number(row.status_code),
    score: row.score === null ? undefined : Number(row.score),
    threshold: row.threshold === null ? undefined : Number(row.threshold),
    reason: String(row.reason ?? ""),
    matchedRules: (row.matched_rules as unknown[]) ?? [],
    ai: row.ai ?? undefined,
    partialInspection: Boolean(row.partial_inspection),
    country: row.country ? String(row.country) : undefined,
    region: row.region ? String(row.region) : undefined,
    city: row.city ? String(row.city) : undefined,
    latitude: row.latitude === null || row.latitude === undefined ? undefined : Number(row.latitude),
    longitude: row.longitude === null || row.longitude === undefined ? undefined : Number(row.longitude),
    asn: row.asn === null || row.asn === undefined ? undefined : Number(row.asn),
    createdAt: new Date(row.created_at as string).toISOString()
  };
}
