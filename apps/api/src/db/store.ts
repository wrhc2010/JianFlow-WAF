import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve, relative, sep } from "node:path";
import { Pool, type QueryResultRow } from "pg";
import {
  BUILTIN_RULES,
  defaultPolicy, safeRequestPath,
  type SitePolicy, type RuleException, type AccessRule,
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
import { parsePolicy, parseScopedRule } from "../policy-validation.js";

export type RuntimeStatus = {
  state: "pending" | "active" | "disabled" | "error";
  desiredRevision: number; appliedRevision: number; lastError?: string;
};

export type Site = {
  id: string;
  name: string;
  listenPort: number;
  upstreamUrl: string;
  redirect?: { statusCode: 301 | 302; location: string } | null;
  mode: ProtectionMode;
  enabled: boolean;
  createdAt: string;
  policy?: SitePolicy | null;
  revision?: number;
  operationMode?: "defense" | "record" | "maintenance";
  aiProfileId?: string | null;
  waitRoom?: WaitRoomConfig;
  maintenance?: PageConfig;
  upstreamError?: PageConfig;
  runtime?: RuntimeStatus;
};

export type WaitRoomConfig = {
  enabled: boolean;
  maxActive: number;
  maxQueue: number;
  timeoutSeconds: number;
};

export type PageConfig = {
  source: "default" | "file" | "inline";
  filePath?: string;
  html?: string;
  statusCode: number;
};

export type RuntimeBan = { siteId: string; ip: string; until: number; seconds: number; count: number };

export type AiProfile = {
  id: string;
  name: string;
  baseUrl: string;
  model: string;
  enabled: boolean;
  priority: number;
  timeoutMs: number;
  apiKeyConfigured: boolean;
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
  siteId?: string;
  listenPort?: number;
  policyRevision?: number;
  module?: string;
  localInspectionComplete?: boolean;
  aiInspectionComplete?: boolean;
  aiOmittedReason?: string;
  wouldBlock?: boolean;
  exceptionIds?: string[];
};

export type AppSettings = EvaluationSettings & {
  upstreamUrl: string;
  jevBaseUrl: string;
  apiKeyConfigured: boolean;
  apiKeySource: "environment" | "database" | "none";
  defaultPolicy: SitePolicy;
  auditMode: "sync" | "async";
  asyncBanBaseSeconds: number;
  asyncBanIncrementSeconds: number;
  asyncBanMaxSeconds: number;
  whitelistCidrs: string[];
  maliciousIpCidrs: string[];
  waitRoomDefaults: WaitRoomConfig;
  captcha: { enabled: boolean; provider: "local" | "turnstile" | "hcaptcha" | "recaptcha"; siteKey: string; secretConfigured: boolean };
};

export type EventFilters = {
  limit?: number;
  cursor?: string;
  action?: "allow" | "block" | "error";
  ip?: string;
  since?: string;
  until?: string;
  search?: string;
  siteId?: string;
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

export type AiProfileInput = {
  id?: string;
  name: string;
  baseUrl: string;
  model: string;
  apiKey?: string | null;
  enabled?: boolean;
  priority?: number;
  timeoutMs?: number;
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
  ,defaultPolicy: { ...defaultPolicy(), strength: config.defaultStrength },
  auditMode: "sync",
  asyncBanBaseSeconds: 60,
  asyncBanIncrementSeconds: 60,
  asyncBanMaxSeconds: 86400,
  whitelistCidrs: [],
  maliciousIpCidrs: [],
  waitRoomDefaults: { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 },
  captcha: { enabled: false, provider: "local", siteKey: "", secretConfigured: false }
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
  private scopedRules: Array<RuleException | AccessRule> = [];
  private readonly runtime = new Map<string, RuntimeStatus>();
  private readonly eventWrites = new Set<Promise<void>>();
  private droppedEvents = 0;
  private eventWriteErrors = 0;
  private retentionTimer: ReturnType<typeof setInterval> | undefined;
  private retentionWork: Promise<number> | undefined;
  private credential: { salt: string; hash: string } | undefined;
  private apiKeyCiphertext: string | null = null;
  private aiProfiles = new Map<string, AiProfile & { apiKeyCiphertext?: string | null }>();
  private setupInProgress = false;
  private mutationQueue: Promise<unknown> = Promise.resolve();
  private builtinRuleIds = new Set<string>();
  private siteChangeListener: (() => void | Promise<void>) | undefined;
  private readonly runtimeBans = new Map<string, RuntimeBan>();

  constructor() {
    this.pool = config.databaseUrl ? new Pool({ connectionString: config.databaseUrl }) : null;
    this.local = this.pool ? null : new LocalDatabase(config.dataDir);
    this.sites.set("default", {
      id: "default",
      name: "默认站点",
      listenPort: config.proxyPort,
      upstreamUrl: this.settings.upstreamUrl,
      redirect: null,
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
        this.normalizeSettingsDefaults();
        this.settings.defaultPolicy ??= { ...defaultPolicy(), strength: this.settings.strength, customThreshold: this.settings.customThreshold };
        this.scopedRules = state.scopedRules ?? [];
        this.initialized = Boolean(state.initialized && state.credential);
        this.credential = state.credential;
        this.apiKeyCiphertext = state.apiKeyCiphertext;
        this.aiProfiles.clear();
        for (const profile of state.aiProfiles ?? []) this.aiProfiles.set(profile.id, profile);
        this.rules = state.rules;
        this.builtinRuleIds = new Set(state.builtinRuleIds ?? state.rules.map((rule) => rule.id));
        this.sites.clear();
        for (const site of state.sites) this.sites.set(site.id, this.normalizeSite(site));
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
      if (!this.aiProfiles.size && (this.settings.apiKeyConfigured || config.environmentApiKey)) {
        this.aiProfiles.set("default", { id: "default", name: "默认 Jev", baseUrl: this.settings.jevBaseUrl, model: this.settings.model, enabled: true, priority: 100, timeoutMs: this.settings.aiTimeoutMs, apiKeyConfigured: Boolean(this.apiKeyCiphertext || config.environmentApiKey), apiKeyCiphertext: this.apiKeyCiphertext });
      }
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
      this.startRetention();
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
              initialized, ai_timeout_ms, ai_body_limit, upstream_url, default_policy,
              audit_mode, async_ban_base_seconds, async_ban_increment_seconds, async_ban_max_seconds,
              whitelist_cidrs, malicious_ip_cidrs, wait_room_defaults, captcha
       FROM settings WHERE id = 1`
    );
    const row = settingResult.rows[0] as Record<string, unknown> | undefined;
    if (row) {
      this.settings = {
        ...defaultSettings(),
        mode: row.mode as ProtectionMode,
        strength: row.strength as ProtectionStrength,
        customThreshold: Number(row.custom_threshold),
        model: String(row.model),
        jevBaseUrl: normalizeBaseUrl(String(row.jev_base_url)),
        aiTimeoutMs: Number(row.ai_timeout_ms),
        aiBodyLimit: Number(row.ai_body_limit),
        upstreamUrl: String(row.upstream_url),
        apiKeyConfigured: Boolean(config.environmentApiKey || row.api_key_ciphertext),
        apiKeySource: row.api_key_ciphertext ? "database" : config.environmentApiKey ? "environment" : "none",
        defaultPolicy: row.default_policy ? parsePolicy(row.default_policy) : { ...defaultPolicy(), strength: row.strength as ProtectionStrength, customThreshold: Number(row.custom_threshold) }
      };
      this.settings.auditMode = row.audit_mode === "async" ? "async" : "sync";
      this.settings.asyncBanBaseSeconds = Number(row.async_ban_base_seconds ?? 60);
      this.settings.asyncBanIncrementSeconds = Number(row.async_ban_increment_seconds ?? 60);
      this.settings.asyncBanMaxSeconds = Number(row.async_ban_max_seconds ?? 86400);
      this.settings.whitelistCidrs = readStringArray(row.whitelist_cidrs);
      this.settings.maliciousIpCidrs = readStringArray(row.malicious_ip_cidrs);
      this.settings.waitRoomDefaults = parseWaitRoom(row.wait_room_defaults);
      this.settings.captcha = parseCaptcha(row.captcha);
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
    await this.ensureDefaultAiProfile();
    if (this.initialized && !row?.admin_password_hash && config.adminPassword) {
      this.credential = exportAdminCredential();
      await this.persistAdminCredential();
    }
    this.syncRuntimeSettings();

    await this.pool.query(
      `INSERT INTO sites (id, name, listen_port, upstream_url, mode, enabled)
       VALUES ('default', $1, $2, $3, $4, TRUE)
       ON CONFLICT (id) DO UPDATE SET
       upstream_url = EXCLUDED.upstream_url,
       mode = EXCLUDED.mode`,
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
    await this.pool.query("CREATE UNIQUE INDEX IF NOT EXISTS sites_port_unique ON sites(listen_port)");
    const scoped = await this.pool.query("SELECT value FROM scoped_rules ORDER BY id");
    this.scopedRules = scoped.rows.map((entry) => entry.value as RuleException | AccessRule);
    this.startRetention();
  }

  async listAiProfiles(): Promise<AiProfile[]> {
    if (!this.pool) return [...this.aiProfiles.values()].map(({ apiKeyCiphertext: _secret, ...profile }) => structuredClone(profile));
    const result = await this.pool.query("SELECT id,name,base_url,model,enabled,priority,timeout_ms,api_key_ciphertext FROM ai_profiles ORDER BY priority ASC, name ASC");
    return result.rows.map((row) => ({ id: String(row.id), name: String(row.name), baseUrl: String(row.base_url), model: String(row.model), enabled: Boolean(row.enabled), priority: Number(row.priority), timeoutMs: Number(row.timeout_ms), apiKeyConfigured: Boolean(row.api_key_ciphertext) }));
  }

  async getAiProvider(id?: string | null): Promise<{ profile: AiProfile; provider: { baseUrl: string; apiKey: string } } | undefined> {
    const profiles = await this.listAiProfiles();
    const selected = profiles.find((profile) => profile.id === (id ?? "default"))
      ?? profiles.find((profile) => profile.enabled && profile.apiKeyConfigured)
      ?? profiles.find((profile) => profile.enabled);
    if (!selected || !selected.enabled) return undefined;
    let apiKey = "";
    if (selected.id === "default") {
      apiKey = this.apiKeyCiphertext ? decryptSecret(this.apiKeyCiphertext, config.sessionSecret) : config.environmentApiKey;
    } else if (this.pool) {
      const result = await this.pool.query("SELECT api_key_ciphertext FROM ai_profiles WHERE id=$1", [selected.id]);
      const ciphertext = result.rows[0]?.api_key_ciphertext ? String(result.rows[0].api_key_ciphertext) : "";
      apiKey = ciphertext ? decryptSecret(ciphertext, config.sessionSecret) : "";
    } else {
      const profile = this.aiProfiles.get(selected.id);
      apiKey = profile?.apiKeyCiphertext ? decryptSecret(profile.apiKeyCiphertext, config.sessionSecret) : "";
      if (!apiKey && selected.id === "default") apiKey = config.environmentApiKey;
    }
    if (!apiKey) return undefined;
    return { profile: selected, provider: { baseUrl: selected.baseUrl, apiKey } };
  }

  async saveAiProfile(input: AiProfileInput): Promise<AiProfile> {
    const id = input.id?.trim() || randomUUID();
    if (!input.name.trim() || input.name.length > 128) throw new ValidationError("Profile 名称无效");
    const baseUrl = normalizeBaseUrl(input.baseUrl);
    validateHttpEndpoint(baseUrl, "Jev Base URL");
    if (!input.model.trim() || input.model.length > 256) throw new ValidationError("Profile 模型无效");
    if (!Number.isInteger(input.priority ?? 100) || (input.priority ?? 100) < 0 || (input.priority ?? 100) > 100000) throw new ValidationError("Profile 优先级无效");
    if (!Number.isInteger(input.timeoutMs ?? 2000) || (input.timeoutMs ?? 2000) < 100 || (input.timeoutMs ?? 2000) > 60000) throw new ValidationError("Profile 超时无效");
    const ciphertext = input.apiKey?.trim() ? encryptSecret(input.apiKey.trim(), config.sessionSecret) : null;
    if (!this.pool) {
      const current = this.aiProfiles.get(id);
      const ciphertext = input.apiKey === undefined ? current?.apiKeyCiphertext ?? null : input.apiKey?.trim() ? encryptSecret(input.apiKey.trim(), config.sessionSecret) : null;
      const profile = { id, name: input.name.trim(), baseUrl, model: input.model.trim(), enabled: input.enabled ?? current?.enabled ?? true, priority: input.priority ?? current?.priority ?? 100, timeoutMs: input.timeoutMs ?? current?.timeoutMs ?? 2000, apiKeyConfigured: Boolean(ciphertext || (id === "default" && config.environmentApiKey)), apiKeyCiphertext: ciphertext };
      this.aiProfiles.set(id, profile);
      if (id === "default") await this.updateSettings({ jevBaseUrl: baseUrl, model: profile.model, aiTimeoutMs: profile.timeoutMs, ...(input.apiKey === undefined ? {} : { apiKey: input.apiKey }) });
      this.local!.writeState(this.snapshot());
      const { apiKeyCiphertext: _secret, ...publicProfile } = profile;
      return structuredClone(publicProfile);
    }
    await this.pool.query(`INSERT INTO ai_profiles(id,name,base_url,model,api_key_ciphertext,enabled,priority,timeout_ms,updated_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,NOW()) ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,base_url=EXCLUDED.base_url,model=EXCLUDED.model,
      api_key_ciphertext=COALESCE(EXCLUDED.api_key_ciphertext,ai_profiles.api_key_ciphertext),enabled=EXCLUDED.enabled,priority=EXCLUDED.priority,timeout_ms=EXCLUDED.timeout_ms,updated_at=NOW()`,
      [id, input.name.trim(), baseUrl, input.model.trim(), ciphertext, input.enabled ?? true, input.priority ?? 100, input.timeoutMs ?? 2000]);
    return (await this.listAiProfiles()).find((profile) => profile.id === id)!;
  }

  async deleteAiProfile(id: string): Promise<void> {
    if (id === "default") throw new ConflictError("默认 Profile 不能删除");
    if (!this.pool) {
      if (id === "default") throw new ConflictError("默认 Profile 不能删除");
      this.aiProfiles.delete(id);
      this.local!.writeState(this.snapshot());
      return;
    }
    await this.pool.query("DELETE FROM ai_profiles WHERE id=$1", [id]);
  }

  private async ensureDefaultAiProfile(): Promise<void> {
    if (!this.pool) return;
    const exists = await this.pool.query("SELECT 1 FROM ai_profiles LIMIT 1");
    if (!exists.rowCount) {
      await this.pool.query("INSERT INTO ai_profiles(id,name,base_url,model,api_key_ciphertext,enabled,priority,timeout_ms) VALUES('default',$1,$2,$3,$4,TRUE,100,$5)", ["默认 Jev", this.settings.jevBaseUrl, this.settings.model, this.apiKeyCiphertext, this.settings.aiTimeoutMs]);
    }
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
    return structuredClone({
      ...this.settings,
      apiKeyConfigured: Boolean(config.openRouterKey),
      apiKeySource: this.settings.apiKeySource
    });
  }

  readPage(page: PageConfig | undefined): string | undefined {
    if (!page || page.source !== "file" || !page.filePath) return page?.html;
    try {
      const root = resolve(config.dataDir, "pages");
      const target = resolve(root, page.filePath);
      const relation = relative(root, target);
      if (relation.startsWith(`..${sep}`) || relation === ".." || !existsSync(target)) return undefined;
      if (!target.toLowerCase().endsWith(".html")) return undefined;
      const body = readFileSync(target);
      if (body.length > 512 * 1024) return undefined;
      return body.toString("utf8");
    } catch { return undefined; }
  }

  getRuntimeBan(siteId: string, ip: string): RuntimeBan | undefined {
    const ban = this.runtimeBans.get(`${siteId}\0${ip}`);
    if (!ban || ban.until <= Date.now()) {
      if (ban) this.runtimeBans.delete(`${siteId}\0${ip}`);
      return undefined;
    }
    return { ...ban };
  }

  recordRuntimeBan(siteId: string, ip: string, baseSeconds: number, incrementSeconds: number, maxSeconds: number): RuntimeBan {
    const key = `${siteId}\0${ip}`;
    const previous = this.runtimeBans.get(key);
    const count = (previous?.count ?? 0) + 1;
    const seconds = Math.min(maxSeconds, baseSeconds + Math.max(0, count - 1) * incrementSeconds);
    const ban = { siteId, ip, until: Date.now() + seconds * 1000, seconds, count };
    this.runtimeBans.set(key, ban);
    return { ...ban };
  }

  async updateSettings(next: SettingsUpdate): Promise<AppSettings> {
    return this.serializeMutation(() => this.commitSettings(next));
  }

  private async commitSettings(next: SettingsUpdate): Promise<AppSettings> {
    const { apiKey, ...settings } = next;
    const candidate: AppSettings = {
      ...this.settings,
      ...settings,
      jevBaseUrl: settings.jevBaseUrl ? normalizeBaseUrl(settings.jevBaseUrl) : this.settings.jevBaseUrl
    };
    if (settings.defaultPolicy !== undefined) candidate.defaultPolicy = parsePolicy(settings.defaultPolicy);
    else if (settings.strength !== undefined || settings.customThreshold !== undefined) candidate.defaultPolicy = {
      ...candidate.defaultPolicy, strength: candidate.strength, customThreshold: candidate.customThreshold
    };
    if (settings.defaultPolicy !== undefined) {
      candidate.strength = candidate.defaultPolicy.strength;
      candidate.customThreshold = candidate.defaultPolicy.customThreshold;
    }
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
    candidate.auditMode = candidate.auditMode === "async" ? "async" : "sync";
    candidate.whitelistCidrs = readStringArray(candidate.whitelistCidrs);
    candidate.maliciousIpCidrs = readStringArray(candidate.maliciousIpCidrs);
    candidate.waitRoomDefaults = parseWaitRoom(candidate.waitRoomDefaults);
    candidate.captcha = parseCaptcha(candidate.captcha);
    validateSettings(candidate);
    const sites = this.listSites().map((site) => ({
      ...site,
      upstreamUrl: site.id === "default" ? candidate.upstreamUrl : site.upstreamUrl,
      mode: effectiveProtectionMode(site.id === "default" ? candidate.mode : site.mode, Boolean(effectiveApiKey))
      ,revision: (site.revision ?? 1) + 1,
      operationMode: site.operationMode ?? "defense",
      aiProfileId: site.aiProfileId ?? null,
      waitRoom: parseWaitRoom(site.waitRoom ?? candidate.waitRoomDefaults),
      maintenance: parsePageConfig(site.maintenance, 503),
      upstreamError: parsePageConfig(site.upstreamError, 502)
    }));
    const client = this.pool ? await this.pool.connect() : null;
    try {
      if (client) {
        await client.query("BEGIN");
        await client.query(
          `UPDATE settings SET mode = $1, strength = $2, custom_threshold = $3,
           model = $4, jev_base_url = $5, ai_timeout_ms = $6, ai_body_limit = $7,
           upstream_url = $8,
           api_key_ciphertext = CASE WHEN $9::boolean THEN $10::text ELSE api_key_ciphertext END,
           default_policy = $11::jsonb, audit_mode = $12, async_ban_base_seconds = $13,
           async_ban_increment_seconds = $14, async_ban_max_seconds = $15,
           whitelist_cidrs = $16::jsonb, malicious_ip_cidrs = $17::jsonb,
           wait_room_defaults = $18::jsonb, captcha = $19::jsonb, updated_at = NOW() WHERE id = 1`,
          [
            candidate.mode, candidate.strength, candidate.customThreshold, candidate.model,
            candidate.jevBaseUrl, candidate.aiTimeoutMs, candidate.aiBodyLimit, candidate.upstreamUrl,
            apiKey !== undefined,
            apiKeyCiphertext ?? null, JSON.stringify(candidate.defaultPolicy), candidate.auditMode,
            candidate.asyncBanBaseSeconds, candidate.asyncBanIncrementSeconds, candidate.asyncBanMaxSeconds,
            JSON.stringify(candidate.whitelistCidrs), JSON.stringify(candidate.maliciousIpCidrs),
            JSON.stringify(candidate.waitRoomDefaults), JSON.stringify(candidate.captcha)
          ]
        );
        for (const site of sites) {
          await client.query(
            `UPDATE sites SET upstream_url = $1, mode = $2, revision = $4, operation_mode = $5,
             ai_profile_id = $6, wait_room = $7::jsonb, maintenance = $8::jsonb, upstream_error = $9::jsonb, redirect = $10::jsonb WHERE id = $3`,
            [site.upstreamUrl, site.mode, site.id, site.revision, site.operationMode, site.aiProfileId,
              JSON.stringify(site.waitRoom), JSON.stringify(site.maintenance), JSON.stringify(site.upstreamError), site.redirect ? JSON.stringify(site.redirect) : null]
          );
        }
        await client.query("COMMIT");
      } else {
        this.local!.writeState({ ...this.snapshot(), settings: candidate, apiKeyCiphertext, sites });
      }
    } catch (error) {
      if (client) await client.query("ROLLBACK");
      throw error;
    } finally {
      client?.release();
    }
    this.settings = candidate;
    this.apiKeyCiphertext = apiKeyCiphertext;
    this.syncRuntimeSettings();
    for (const site of sites) this.sites.set(site.id, site);
    await this.notifySitesChanged();
    return this.getSettings();
  }

  listSites(): Site[] {
    return [...this.sites.values()].map((site) => structuredClone({ ...site,
      runtime: this.runtime.get(site.id) ?? { state: site.enabled ? "pending" : "disabled", desiredRevision: site.revision ?? 1, appliedRevision: 0 }
    }));
  }

  effectivePolicy(site: Site): SitePolicy { return structuredClone(site.policy ?? this.settings.defaultPolicy); }

  reportRuntime(id: string, status: RuntimeStatus): void { this.runtime.set(id, status); }

  readiness(): boolean {
    return this.listSites().every((site) => !site.enabled || site.runtime?.state === "active"
      && site.runtime.appliedRevision === (site.revision ?? 1));
  }

  async retryListeners(): Promise<void> { await this.notifySitesChanged(); }

  listScopedRules(siteId: string, kind: "exceptions" | "access-rules"): Array<RuleException | AccessRule> {
    return structuredClone(this.scopedRules.filter((rule) => rule.siteId === siteId
      && (kind === "exceptions" ? "ruleIds" in rule : "cidr" in rule)));
  }

  async saveScopedRule(siteId: string, kind: "exceptions" | "access-rules", input: unknown, id: string = randomUUID()): Promise<RuleException | AccessRule> {
    return this.serializeMutation(async () => {
      if (!this.sites.has(siteId)) throw new ValidationError("站点不存在");
      const rule = parseScopedRule(input, siteId, id, kind);
      if ("ruleIds" in rule && rule.ruleIds.some((ruleId) => !this.rules.some((entry) => entry.id === ruleId))) throw new ValidationError("例外引用了不存在的规则");
      const next = this.scopedRules.filter((entry) => entry.id !== id).concat(rule);
      if (next.filter((entry) => entry.siteId === siteId).length > 500) throw new ConflictError("每个站点最多保存 500 条例外及访问控制");
      const site = { ...this.sites.get(siteId)!, revision: (this.sites.get(siteId)!.revision ?? 1) + 1 };
      const client = this.pool ? await this.pool.connect() : null;
      try {
        if (client) {
          await client.query("BEGIN");
          await client.query("INSERT INTO scoped_rules(id,site_id,kind,value) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET value=EXCLUDED.value", [id, siteId, kind, JSON.stringify(rule)]);
          await client.query("UPDATE sites SET revision=$2 WHERE id=$1", [siteId, site.revision]);
          await client.query("COMMIT");
        } else this.local!.writeState({ ...this.snapshot(), scopedRules: next, sites: [...this.sites.values()].map((entry) => entry.id === siteId ? site : entry) });
      } catch (error) { if (client) await client.query("ROLLBACK"); throw error; } finally { client?.release(); }
      this.scopedRules = next;
      this.sites.set(siteId, site);
      await this.notifySitesChanged();
      return structuredClone(rule);
    });
  }

  async deleteScopedRule(siteId: string, id: string): Promise<void> {
    return this.serializeMutation(async () => {
      const next = this.scopedRules.filter((entry) => !(entry.id === id && entry.siteId === siteId));
      const site = { ...this.sites.get(siteId)!, revision: (this.sites.get(siteId)!.revision ?? 1) + 1 };
      const client = this.pool ? await this.pool.connect() : null;
      try {
        if (client) {
          await client.query("BEGIN");
          await client.query("DELETE FROM scoped_rules WHERE id=$1 AND site_id=$2", [id, siteId]);
          await client.query("UPDATE sites SET revision=$2 WHERE id=$1", [siteId, site.revision]);
          await client.query("COMMIT");
        } else this.local!.writeState({ ...this.snapshot(), scopedRules: next, sites: [...this.sites.values()].map((entry) => entry.id === siteId ? site : entry) });
      } catch (error) { if (client) await client.query("ROLLBACK"); throw error; } finally { client?.release(); }
      this.scopedRules = next;
      this.sites.set(siteId, site);
      await this.notifySitesChanged();
    });
  }

  getSiteByPort(port: number): Site | undefined {
    const site = [...this.sites.values()].find((entry) => entry.listenPort === port && entry.enabled);
    return site ? { ...site } : undefined;
  }

  setSiteChangeListener(listener: (() => void | Promise<void>) | undefined): void {
    this.siteChangeListener = listener;
  }

  async saveSite(input: Omit<Site, "createdAt" | "id" | "runtime" | "revision"> & { id?: string; listenPort?: number }): Promise<Site> {
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
      const site: Site = this.normalizeSite({
        id: input.id ?? randomUUID(),
        name: input.name,
        listenPort,
        upstreamUrl: input.upstreamUrl,
        redirect: input.redirect ?? current?.redirect ?? null,
        mode: effectiveProtectionMode(input.mode, Boolean(config.openRouterKey)),
        enabled: input.enabled,
        createdAt: current?.createdAt ?? new Date().toISOString(),
        policy: input.policy === undefined ? current?.policy ?? null : input.policy === null ? null : parsePolicy(input.policy),
        revision: (current?.revision ?? 0) + 1,
        operationMode: input.operationMode ?? current?.operationMode ?? "defense",
        aiProfileId: input.aiProfileId ?? current?.aiProfileId ?? null,
        waitRoom: input.waitRoom ?? current?.waitRoom ?? this.settings.waitRoomDefaults,
        maintenance: input.maintenance ?? current?.maintenance ?? { source: "default", statusCode: 503 },
        upstreamError: input.upstreamError ?? current?.upstreamError ?? { source: "default", statusCode: 502 }
      });
      const settings = site.id === "default"
        ? { ...this.settings, upstreamUrl: site.upstreamUrl, mode: site.mode }
        : this.settings;
      const client = this.pool ? await this.pool.connect() : null;
      try {
        if (client) {
          await client.query("BEGIN");
          await client.query(
            `INSERT INTO sites (id, name, listen_port, upstream_url, mode, enabled, policy, revision, created_at,
             operation_mode, ai_profile_id, wait_room, maintenance, upstream_error, redirect)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13::jsonb, $14::jsonb, $15::jsonb)
             ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, listen_port = EXCLUDED.listen_port,
             upstream_url = EXCLUDED.upstream_url, mode = EXCLUDED.mode, enabled = EXCLUDED.enabled,
             policy = EXCLUDED.policy, revision = EXCLUDED.revision, operation_mode = EXCLUDED.operation_mode,
             ai_profile_id = EXCLUDED.ai_profile_id, wait_room = EXCLUDED.wait_room,
             maintenance = EXCLUDED.maintenance, upstream_error = EXCLUDED.upstream_error, redirect = EXCLUDED.redirect`,
            [site.id, site.name, site.listenPort, site.upstreamUrl, site.mode, site.enabled, site.policy ? JSON.stringify(site.policy) : null, site.revision, site.createdAt,
              site.operationMode, site.aiProfileId, JSON.stringify(site.waitRoom), JSON.stringify(site.maintenance), JSON.stringify(site.upstreamError), site.redirect ? JSON.stringify(site.redirect) : null]
          );
          if (site.id === "default") {
            await client.query(
              `UPDATE settings SET upstream_url = $1, mode = $2, updated_at = NOW() WHERE id = 1`,
              [site.upstreamUrl, site.mode]
            );
          }
          await client.query("COMMIT");
        } else {
          this.local!.writeState({
            ...this.snapshot(), settings,
            sites: [...this.sites.values()].filter((item) => item.id !== site.id).concat(site)
          });
        }
      } catch (error) {
        if (client) await client.query("ROLLBACK");
        throw error;
      } finally {
        client?.release();
      }
      this.settings = settings;
      this.sites.set(site.id, site);
      await this.notifySitesChanged();
      return this.listSites().find((entry) => entry.id === site.id)!;
    });
  }

  async deleteSite(id: string): Promise<void> {
    return this.serializeMutation(async () => {
      if (id === "default") throw new ConflictError("默认站点不能删除");
      if (this.pool) {
        const client = await this.pool.connect();
        try {
          await client.query("BEGIN");
          await client.query("DELETE FROM scoped_rules WHERE site_id=$1", [id]);
          await client.query("DELETE FROM sites WHERE id=$1", [id]);
          await client.query("COMMIT");
        } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
      } else this.local!.writeState({ ...this.snapshot(), sites: [...this.sites.values()].filter((site) => site.id !== id), scopedRules: this.scopedRules.filter((rule) => rule.siteId !== id) });
      this.scopedRules = this.scopedRules.filter((rule) => rule.siteId !== id);
      this.sites.delete(id);
      this.runtime.delete(id);
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
    request: { method: string; path: string; ip?: string | undefined; siteId?: string; listenPort?: number; policyRevision?: number },
    statusCode?: number,
    analysis?: Promise<Partial<WafDecision>>
  ): Promise<void> {
    if (this.eventWrites.size >= config.eventQueueLimit) { this.droppedEvents += 1; return; }
    // Include shadow completion in the bounded write set drained during shutdown.
    const write = (async () => this.persistEvent({ ...decision, ...await analysis }, request, statusCode))();
    this.eventWrites.add(write);
    try { await write; } catch (error) { this.eventWriteErrors += 1; throw error; }
    finally { this.eventWrites.delete(write); }
  }

  private async persistEvent(decision: WafDecision, request: { method: string; path: string; ip?: string | undefined; siteId?: string; listenPort?: number; policyRevision?: number }, statusCode?: number): Promise<void> {
    const geo = this.geoIp.lookup(request.ip);
    const record: EventRecord = {
      id: 0,
      requestId: decision.requestId,
      action: decision.action,
      mode: decision.mode,
      method: request.method,
      path: safeRequestPath(request.path),
      ip: request.ip,
      statusCode,
      score: decision.score,
      threshold: decision.threshold,
      reason: decision.reason,
      matchedRules: decision.matchedRules,
      ai: decision.ai,
      partialInspection: decision.partialInspection ?? false,
      ...geo,
      createdAt: new Date().toISOString(), siteId: request.siteId ?? "unknown",
      ...(request.listenPort === undefined ? {} : { listenPort: request.listenPort }),
      ...(request.policyRevision === undefined ? {} : { policyRevision: request.policyRevision }),
      module: decision.module ?? "protocol", localInspectionComplete: decision.localInspectionComplete ?? false,
      ...(decision.aiInspectionComplete === undefined ? {} : { aiInspectionComplete: decision.aiInspectionComplete }),
      ...(decision.aiOmittedReason ? { aiOmittedReason: decision.aiOmittedReason } : {}),
      wouldBlock: decision.wouldBlock ?? false, exceptionIds: decision.exceptionIds ?? []
    };
    if (this.pool) {
      await this.pool.query(
        `WITH inserted AS (INSERT INTO events
         (request_id, action, mode, method, path, ip, status_code, score, threshold, reason,
          matched_rules, ai, partial_inspection, country, region, city, latitude, longitude, asn, site_id, context)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
         ON CONFLICT (request_id) WHERE finalized DO NOTHING RETURNING action,mode,ai)
         UPDATE event_totals SET total=total+1, allowed=allowed+(inserted.action='allow')::int,
           blocked=blocked+(inserted.action='block')::int, errors=errors+(inserted.action='error')::int,
           ai=event_totals.ai+(inserted.mode='ai')::int, traditional=traditional+(inserted.mode='traditional')::int,
           hybrid=hybrid+(inserted.mode='hybrid')::int, ai_unavailable=ai_unavailable+COALESCE((inserted.ai->>'available'='false')::int,0)
         FROM inserted WHERE event_totals.id=1`,
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
          record.asn ?? null, record.siteId, JSON.stringify({ listenPort: record.listenPort, policyRevision: record.policyRevision,
            module: record.module, localInspectionComplete: record.localInspectionComplete, aiInspectionComplete: record.aiInspectionComplete,
            aiOmittedReason: record.aiOmittedReason, wouldBlock: record.wouldBlock, exceptionIds: record.exceptionIds })
        ]
      );
    } else {
      this.local!.saveEvent(record);
    }
  }

  async listEvents(filters: EventFilters = {}): Promise<{ data: EventRecord[]; nextCursor?: string }> {
    validateFilters(filters);
    const cursor = filters.cursor ? decodeCursor(filters.cursor) : undefined;
    const safeLimit = Math.min(Math.max(filters.limit ?? 50, 1), 500);
    if (!this.pool) {
      const page = this.local!.listEvents(filters, cursor);
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
    if (filters.siteId) add(`COALESCE(site_id,'unknown') = ?`, filters.siteId);
    if (filters.since) add(`created_at >= ?::timestamptz`, filters.since);
    if (filters.until) add(`created_at <= ?::timestamptz`, filters.until);
    if (filters.search) add(`strpos(lower(path || ' ' || request_id || ' ' || COALESCE(ip, '')), lower(?)) > 0`, filters.search);
    values.push(safeLimit + 1);
    const limitPlaceholder = `$${values.length}`;
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const result = await this.pool.query(
      `SELECT id, request_id, action, mode, method, path, ip, status_code, score, threshold,
       reason, matched_rules, ai, partial_inspection, country, region, city, latitude, longitude, asn, created_at,
       created_at::text AS cursor_time, site_id, context
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
        SELECT total,blocked,allowed,errors,ai,traditional,hybrid,ai_unavailable
        FROM event_totals WHERE id=1
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
    return this.local!.summary();
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
    return this.local!.attackMap(new Date(Date.now() - safeHours * 3600000).toISOString());
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
      for (const point of this.local!.timeseries(start.toISOString())) if (buckets.has(point.time)) buckets.set(point.time, point);
    }
    return [...buckets.values()];
  }

  private snapshot(): LocalState {
    return {
      settings: this.settings, initialized: this.initialized, credential: this.credential,
      apiKeyCiphertext: this.apiKeyCiphertext, rules: this.rules, sites: [...this.sites.values()],
      aiProfiles: [...this.aiProfiles.values()],
      builtinRuleIds: [...this.builtinRuleIds], scopedRules: this.scopedRules
    };
  }

  private normalizeSettingsDefaults(): void {
    const defaults = defaultSettings();
    this.settings = {
      ...defaults,
      ...this.settings,
      defaultPolicy: this.settings.defaultPolicy ?? defaults.defaultPolicy,
      auditMode: this.settings.auditMode === "async" ? "async" : "sync",
      asyncBanBaseSeconds: Number.isFinite(this.settings.asyncBanBaseSeconds) ? this.settings.asyncBanBaseSeconds : defaults.asyncBanBaseSeconds,
      asyncBanIncrementSeconds: Number.isFinite(this.settings.asyncBanIncrementSeconds) ? this.settings.asyncBanIncrementSeconds : defaults.asyncBanIncrementSeconds,
      asyncBanMaxSeconds: Number.isFinite(this.settings.asyncBanMaxSeconds) ? this.settings.asyncBanMaxSeconds : defaults.asyncBanMaxSeconds,
      whitelistCidrs: Array.isArray(this.settings.whitelistCidrs) ? this.settings.whitelistCidrs : [],
      maliciousIpCidrs: Array.isArray(this.settings.maliciousIpCidrs) ? this.settings.maliciousIpCidrs : [],
      waitRoomDefaults: parseWaitRoom(this.settings.waitRoomDefaults),
      captcha: parseCaptcha(this.settings.captcha)
    };
  }

  private normalizeSite(site: Site): Site {
    return {
      ...site,
      operationMode: site.operationMode === "record" || site.operationMode === "maintenance" ? site.operationMode : "defense",
      aiProfileId: site.aiProfileId ?? null,
      waitRoom: parseWaitRoom(site.waitRoom ?? this.settings.waitRoomDefaults),
      maintenance: parsePageConfig(site.maintenance, 503),
      upstreamError: parsePageConfig(site.upstreamError, 502)
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
      if (site.id === "default") site.listenPort = config.proxyPort;
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
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("UPDATE sites SET listen_port=NULL");
      for (const site of this.sites.values()) await client.query(
        `UPDATE sites SET listen_port = $1, mode = $2 WHERE id = $3`,
        [site.listenPort, site.mode, site.id]
      );
      await client.query(`UPDATE settings SET mode = $1 WHERE id = 1`, [this.settings.mode]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); }
  }

  private async notifySitesChanged(): Promise<void> {
    await this.siteChangeListener?.();
  }

  eventRuntime() { return { queueDepth: this.eventWrites.size, queueLimit: config.eventQueueLimit,
    droppedEvents: this.droppedEvents, writeErrors: this.eventWriteErrors, retentionDays: config.logRetentionDays }; }

  pruneEvents(cutoff = new Date(Date.now() - config.logRetentionDays * 86400000).toISOString()): Promise<number> {
    if (this.retentionWork) return this.retentionWork;
    const work = (async () => {
      if (this.local) return this.local.retention(cutoff);
      const result = await this.pool!.query("DELETE FROM events WHERE id IN (SELECT id FROM events WHERE created_at < $1::timestamptz ORDER BY id LIMIT 1000)", [cutoff]);
      return result.rowCount ?? 0;
    })();
    this.retentionWork = work;
    void work.finally(() => { this.retentionWork = undefined; }).catch(() => {});
    return work;
  }

  private startRetention(): void {
    this.retentionTimer = setInterval(() => { void this.pruneEvents().catch(() => { this.eventWriteErrors += 1; }); }, 60000);
    this.retentionTimer.unref();
  }

  private serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.mutationQueue.then(operation);
    this.mutationQueue = result.catch(() => {});
    return result;
  }

  async close(): Promise<void> {
    clearInterval(this.retentionTimer);
    await this.mutationQueue;
    await Promise.allSettled([...this.eventWrites]);
    await this.retentionWork?.catch(() => {});
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
  if (!Number.isInteger(settings.asyncBanBaseSeconds) || settings.asyncBanBaseSeconds < 1 || settings.asyncBanBaseSeconds > 86400) throw new ValidationError("异步封禁基础时长无效");
  if (!Number.isInteger(settings.asyncBanIncrementSeconds) || settings.asyncBanIncrementSeconds < 1 || settings.asyncBanIncrementSeconds > 86400) throw new ValidationError("异步封禁递增时长无效");
  if (!Number.isInteger(settings.asyncBanMaxSeconds) || settings.asyncBanMaxSeconds < settings.asyncBanBaseSeconds || settings.asyncBanMaxSeconds > 604800) throw new ValidationError("异步封禁最大时长无效");
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
  if (!["defense", "record", "maintenance"].includes(site.operationMode ?? "defense")) throw new ValidationError("站点运行模式无效");
  validateHttpEndpoint(site.upstreamUrl, "上游地址");
  if (site.redirect !== undefined && site.redirect !== null) {
    if (site.redirect.statusCode !== 301 && site.redirect.statusCode !== 302) throw new ValidationError("跳转状态码必须是 301 或 302");
    validateHttpEndpoint(site.redirect.location, "跳转地址");
  }
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

function readStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === "string").map((item) => item.trim()).filter(Boolean);
  if (typeof value === "string") {
    try { return readStringArray(JSON.parse(value)); } catch { return []; }
  }
  return [];
}

function parseWaitRoom(value: unknown): WaitRoomConfig {
  const source = typeof value === "object" && value !== null ? value as Partial<WaitRoomConfig> : {};
  return {
    enabled: Boolean(source.enabled),
    maxActive: clampInteger(source.maxActive, 100, 1, 100000),
    maxQueue: clampInteger(source.maxQueue, 100, 0, 100000),
    timeoutSeconds: clampInteger(source.timeoutSeconds, 60, 1, 86400)
  };
}

function parsePageConfig(value: unknown, statusCode: number): PageConfig {
  const source = typeof value === "object" && value !== null ? value as Partial<PageConfig> : {};
  const sourceType = source.source === "file" || source.source === "inline" ? source.source : "default";
  return {
    source: sourceType,
    ...(typeof source.filePath === "string" && source.filePath ? { filePath: source.filePath } : {}),
    ...(typeof source.html === "string" && source.html ? { html: source.html } : {}),
    statusCode: clampInteger(source.statusCode, statusCode, 400, 599)
  };
}

function parseCaptcha(value: unknown): AppSettings["captcha"] {
  const source = typeof value === "object" && value !== null ? value as Partial<AppSettings["captcha"]> : {};
  const provider = source.provider === "turnstile" || source.provider === "hcaptcha" || source.provider === "recaptcha" ? source.provider : "local";
  return { enabled: Boolean(source.enabled), provider, siteKey: typeof source.siteKey === "string" ? source.siteKey : "", secretConfigured: Boolean(source.secretConfigured) };
}

function clampInteger(value: unknown, fallback: number, min: number, max: number): number {
  return typeof value === "number" && Number.isInteger(value) ? Math.min(max, Math.max(min, value)) : fallback;
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
    createdAt: new Date(row.created_at as string).toISOString(), policy: row.policy ? parsePolicy(row.policy) : null,
    revision: Number(row.revision ?? 1),
    operationMode: row.operation_mode === "record" || row.operation_mode === "maintenance" ? row.operation_mode : "defense",
    aiProfileId: row.ai_profile_id ? String(row.ai_profile_id) : null,
    waitRoom: parseWaitRoom(row.wait_room),
    maintenance: parsePageConfig(row.maintenance, 503),
    upstreamError: parsePageConfig(row.upstream_error, 502),
    redirect: parseRedirect(row.redirect) ?? null
  };
}

function parseRedirect(value: unknown): Site["redirect"] {
  if (!value || typeof value !== "object") return null;
  const source = value as { statusCode?: unknown; location?: unknown };
  if ((source.statusCode !== 301 && source.statusCode !== 302) || typeof source.location !== "string" || !source.location.trim()) return null;
  try {
    const target = new URL(source.location);
    if (target.protocol !== "http:" && target.protocol !== "https:") return null;
  } catch { return null; }
  return { statusCode: source.statusCode, location: source.location.trim() };
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
    ...(row.context as Partial<EventRecord> ?? {}), siteId: String(row.site_id ?? "unknown"),
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
