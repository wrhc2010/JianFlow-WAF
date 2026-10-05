import { createHash, randomUUID } from "node:crypto";
import Fastify, { type FastifyReply } from "fastify";
import cookie from "@fastify/cookie";
import websocket from "@fastify/websocket";
import rateLimit from "@fastify/rate-limit";
import {
  evaluateRules,
  type WafRule,
  type ProtectionMode,
  type ProtectionStrength,
} from "@jev-waf/core";
import {
  checkPassword,
  createSession,
  destroySession,
  getSession,
} from "./auth.js";
import { config } from "./config.js";
import { parseRuleImport, RuleImportError, validateRule } from "./rule-import.js";
import { Store, type EventFilters } from "./db/store.js";
import { previewNginxConfig } from "./nginx-import.js";
import { classifyWithJev } from "./jev.js";
import { ConflictError, SetupConflictError, ValidationError } from "./errors.js";
import { policySchema, parsePolicy } from "./policy-validation.js";
import { aiRuntime } from "./jev.js";
import { trafficRuntime } from "./proxy.js";
import { clientIp } from "./proxy.js";
import { createChallenge, verifyChallenge } from "./captcha.js";
import type { SitePolicy, RuleException, AccessRule } from "@jev-waf/core";
import type { Site, AiProfileInput } from "./db/store.js";
import { parseThreatFeed } from "./threat-feed.js";
import { captureConfigurationSchemas } from "./configuration-file.js";

const pageSchema = { type: "object", additionalProperties: false, required: ["source", "statusCode"], properties: {
  source: { type: "string", enum: ["default", "file", "inline"] }, filePath: { type: "string", minLength: 1, maxLength: 256 },
  html: { type: "string", maxLength: 512 * 1024 }, statusCode: { type: "integer", minimum: 400, maximum: 599 },
} };
const waitRoomSchema = { type: "object", additionalProperties: false, required: ["enabled", "maxActive", "maxQueue", "timeoutSeconds"], properties: {
  enabled: { type: "boolean" }, maxActive: { type: "integer", minimum: 1, maximum: 100000 },
  maxQueue: { type: "integer", minimum: 0, maximum: 100000 }, timeoutSeconds: { type: "integer", minimum: 1, maximum: 86400 },
  page: pageSchema, fullAction: { type: "string", enum: ["reject", "unavailable"] },
} };

function notFound(reply: FastifyReply, detail: string, instance: string) {
  return reply.code(404).type("application/problem+json").send({ type: "about:blank", title: "Not Found", status: 404, detail, instance });
}

export async function createApp(store: Store, logger = true) {
  const app = Fastify({
    logger,
    trustProxy: config.trustedProxyCidrs.length
      ? config.trustedProxyCidrs
      : false,
    ajv: { customOptions: { removeAdditional: false } },
  });
  captureConfigurationSchemas(app);

  await app.register(cookie, { secret: config.sessionSecret });
  await app.register(websocket);
  await app.register(rateLimit, { global: false });
  app.addContentTypeParser("application/octet-stream", { parseAs: "buffer", bodyLimit: 128 * 1024 * 1024 }, (_request, body, done) => done(null, body));
  app.setErrorHandler((error, request, reply) => {
    const failure = (
      error instanceof Error ? error : new Error("请求处理失败")
    ) as Error & {
      validation?: unknown;
      statusCode?: number;
    };
    const status =
      error instanceof SetupConflictError
        || error instanceof ConflictError
        ? 409
        : error instanceof ValidationError || failure.validation
          ? 422
          : failure.statusCode && failure.statusCode < 500
            ? failure.statusCode
            : 500;
    if (status >= 500)
      request.log.error({ err: failure }, "Management request failed");
    return reply.code(status).type("application/problem+json").send({
      type: "about:blank",
      title: status >= 500 ? "Storage error" : "Validation error",
      status,
      detail: status >= 500 ? "操作未完成，请稍后重试" : failure.message,
    });
  });

  app.get("/api/v1/health", async (_request, reply) => {
    const ok = await store.health();
    return reply.code(ok ? 200 : 503).send({
      ok,
      service: "jianflow-waf-api",
      database: Boolean(config.databaseUrl),
      aiConfigured: store.getSettings().apiKeyConfigured,
      setup: store.setupStatus(),
      timestamp: new Date().toISOString(),
    });
  });
  app.get("/api/v1/health/live", async () => ({ ok: true }));
  app.get("/api/v1/health/ready", async (_request, reply) => {
    const ok = await store.health() && store.readiness();
    return reply.code(ok ? 200 : 503).send({ ok });
  });

  app.get("/api/v1/setup/status", async () => store.setupStatus());

  app.get<{ Params: { siteId: string } }>("/api/v1/captcha/challenge/:siteId", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    schema: { params: { type: "object", required: ["siteId"], additionalProperties: false, properties: { siteId: { type: "string", minLength: 1, maxLength: 128 } } } },
  }, async (request, reply) => {
    const settings = store.getSettings();
    if (!settings.captcha.enabled || settings.captcha.provider !== "local") return reply.code(404).send({ detail: "本地挑战未启用" });
    if (!store.listSites().some((site) => site.id === request.params.siteId && site.enabled)) return notFound(reply, "站点不存在", request.url);
    const ip = clientIp(request.raw);
    if (!ip) return reply.code(400).send({ detail: "无法识别客户端地址" });
    return createChallenge(request.params.siteId, ip);
  });
  app.post<{ Params: { siteId: string }; Body: { challenge: string; answer: string } }>("/api/v1/captcha/verify/:siteId", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
    schema: {
      params: { type: "object", required: ["siteId"], additionalProperties: false, properties: { siteId: { type: "string", minLength: 1, maxLength: 128 } } },
      body: { type: "object", required: ["challenge", "answer"], additionalProperties: false, properties: { challenge: { type: "string", minLength: 1, maxLength: 2048 }, answer: { type: "string", minLength: 1, maxLength: 32 } } },
    },
  }, async (request, reply) => {
    const settings = store.getSettings();
    if (!settings.captcha.enabled || settings.captcha.provider !== "local") return reply.code(404).send({ detail: "本地挑战未启用" });
    if (!store.listSites().some((site) => site.id === request.params.siteId && site.enabled)) return notFound(reply, "站点不存在", request.url);
    const ip = clientIp(request.raw);
    if (!ip) return reply.code(400).send({ detail: "无法识别客户端地址" });
    const token = verifyChallenge(request.params.siteId, ip, request.body?.challenge ?? "", request.body?.answer ?? "");
    if (!token) return reply.code(403).send({ detail: "挑战答案无效或已过期" });
    return { token, expiresInSeconds: 600 };
  });

  app.post<{ Body: { password?: string; confirmPassword?: string } }>(
    "/api/v1/setup",
    {
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      schema: {
        body: {
          type: "object",
          required: ["password", "confirmPassword"],
          additionalProperties: false,
          properties: {
            password: { type: "string", minLength: 8, maxLength: 1024 },
            confirmPassword: { type: "string", minLength: 8, maxLength: 1024 },
          },
        },
      },
    },
    async (request, reply) => {
      const { password = "", confirmPassword = "" } = request.body ?? {};
      if (store.setupStatus().initialized) {
        return reply.code(409).send({
          type: "about:blank",
          title: "Already initialized",
          status: 409,
          detail: "系统已经完成初始化",
        });
      }
      if (password !== confirmPassword) {
        return reply.code(422).send({
          type: "about:blank",
          title: "Validation error",
          status: 422,
          detail: "两次输入的管理员密码不一致",
        });
      }
      await store.completeSetup(password);
      return { initialized: true };
    },
  );

  app.post<{ Body: { username?: string; password?: string } }>(
    "/api/v1/auth/login",
    {
      config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
      schema: {
        body: {
          type: "object",
          required: ["username", "password"],
          additionalProperties: false,
          properties: {
            username: { type: "string", maxLength: 256 },
            password: { type: "string", maxLength: 1024 },
          },
        },
      },
    },
    async (request, reply) => {
      if (!store.setupStatus().initialized) {
        return reply.code(428).send({
          type: "about:blank",
          title: "Precondition required",
          status: 428,
          detail: "请先完成首次初始化",
        });
      }
      const username = request.body?.username ?? "";
      const password = request.body?.password ?? "";
      if (username !== config.adminUser || !checkPassword(password)) {
        return reply.code(401).send({
          type: "about:blank",
          title: "Unauthorized",
          status: 401,
          detail: "用户名或密码错误",
        });
      }
      const token = createSession(username);
      reply.setCookie("jev_session", token, {
        httpOnly: true,
        sameSite: "lax",
        secure: config.sessionCookieSecure || request.protocol === "https",
        path: "/",
        maxAge: 8 * 60 * 60,
      });
      return { username };
    },
  );

  app.post("/api/v1/auth/logout", async (request, reply) => {
    destroySession(request.cookies.jev_session);
    reply.clearCookie("jev_session", { path: "/" });
    return { ok: true };
  });

  app.addHook("onRequest", async (request, reply) => {
    if (
      request.url.startsWith("/api/v1/health") ||
      request.url.startsWith("/api/v1/setup") ||
      request.url.startsWith("/api/v1/auth/") ||
      request.url.startsWith("/api/v1/captcha/")
    )
      return;
    if (!store.setupStatus().initialized) {
      return reply.code(428).send({
        type: "about:blank",
        title: "Precondition required",
        status: 428,
        detail: "请先完成首次初始化",
      });
    }
    if (!getSession(request.cookies.jev_session)) {
      return reply.code(401).send({
        type: "about:blank",
        title: "Unauthorized",
        status: 401,
        detail: "请先登录管理后台",
      });
    }
  });

  app.get("/api/v1/auth/me", async (request, reply) => {
    if (!store.setupStatus().initialized) {
      return reply.code(428).send({
        type: "about:blank",
        title: "Precondition required",
        status: 428,
        detail: "请先完成首次初始化",
      });
    }
    const session = getSession(request.cookies.jev_session);
    if (!session)
      return reply
        .code(401)
        .send({ type: "about:blank", title: "Unauthorized", status: 401 });
    return { username: session.username };
  });

  app.get("/api/v1/dashboard/summary", async () => store.summary());
  app.get("/api/v1/system", async () => ({
    proxyPort: config.proxyPort, apiPort: config.apiPort, httpsPort: config.httpsPort,
    sitePortRange: config.sitePortRange,
    maxRequestBodyBytes: config.maxRequestBodyBytes,
    httpsConfigured: Boolean(config.tlsKeyPath && config.tlsCertPath),
    httpsEnabled: Boolean(config.tlsKeyPath && config.tlsCertPath) && store.listSites().some((site) => site.id === "default" && site.enabled && site.runtime?.state === "active"),
    geoIpAsnConfigured: Boolean(config.geoIpAsnDatabasePath),
    ready: store.readiness(), aiRuntime: aiRuntime(), events: store.eventRuntime(), traffic: trafficRuntime(store),
    ...store.setupStatus()
  }));
  app.get("/api/v1/dashboard/attack-map", async (request) => {
    const hours = Number((request.query as { hours?: string }).hours ?? 24);
    return store.attackMap(
      Number.isFinite(hours) ? Math.min(Math.max(hours, 1), 168) : 24,
    );
  });
  app.get("/api/v1/dashboard/timeseries", async (request) => {
    const hours = Number((request.query as { hours?: string }).hours ?? 24);
    return store.timeseries(
      Number.isFinite(hours) ? Math.min(Math.max(hours, 1), 168) : 24,
    );
  });
  app.get(
    "/api/v1/events",
    {
      schema: {
        querystring: {
          type: "object",
          additionalProperties: false,
          properties: {
            limit: { type: "integer", minimum: 1, maximum: 500 },
            cursor: { type: "string", maxLength: 256 },
            action: { type: "string", enum: ["allow", "block", "error"] },
            ip: { type: "string", maxLength: 64 },
            since: { type: "string", format: "date-time" },
            until: { type: "string", format: "date-time" },
            search: { type: "string", maxLength: 256 },
            siteId: { type: "string", minLength: 1, maxLength: 256 },
          },
        },
      },
    },
    async (request) => {
      const query = request.query as Partial<
        Record<keyof EventFilters, string>
      >;
      const limit = Number(query.limit ?? 50);
      const action =
        query.action === "allow" ||
        query.action === "block" ||
        query.action === "error"
          ? query.action
          : undefined;
      return store.listEvents({
        limit: Number.isFinite(limit) ? limit : 50,
        ...(query.cursor ? { cursor: query.cursor } : {}),
        ...(action ? { action } : {}),
        ...(query.ip ? { ip: query.ip } : {}),
        ...(query.since ? { since: query.since } : {}),
        ...(query.until ? { until: query.until } : {}),
        ...(query.search ? { search: query.search } : {}),
        ...(query.siteId ? { siteId: query.siteId } : {}),
      });
    },
  );

  app.get("/api/v1/settings", async () => store.getSettings());
  app.get("/api/v1/geoip", async () => store.geoIpStatus());
  app.put<{ Params: { kind: "city" | "asn" }; Body: Buffer }>("/api/v1/geoip/:kind", {
    bodyLimit: 128 * 1024 * 1024,
    schema: { params: { type: "object", required: ["kind"], properties: { kind: { enum: ["city", "asn"] } } } },
  }, async (request) => {
    if (!Buffer.isBuffer(request.body)) throw new ValidationError("GeoIP 上传需要 application/octet-stream");
    const filename = String(request.headers["x-filename"] ?? "");
    return store.uploadGeoIp(request.params.kind, filename, request.body);
  });
  app.post<{ Body: { content: string; format: "text" | "json" | "csv" | "stix" | "taxii" } }>("/api/v1/ip-feed-previews", {
    bodyLimit: 2 * 1024 * 1024,
    schema: { body: { type: "object", required: ["content", "format"], additionalProperties: false, properties: { content: { type: "string", minLength: 1, maxLength: 1024 * 1024 }, format: { type: "string", enum: ["text", "json", "csv", "stix", "taxii"] } } } },
  }, async (request) => {
    try { return { data: parseThreatFeed(request.body.content, request.body.format) }; }
    catch (error) { throw new ValidationError(error instanceof Error ? error.message : "IP 库格式无效"); }
  });
  const profileProperties = {
    name: { type: "string", minLength: 1, maxLength: 128 }, baseUrl: { type: "string", minLength: 1, maxLength: 2048 },
    model: { type: "string", minLength: 1, maxLength: 256 }, apiKey: { type: ["string", "null"], maxLength: 8192 },
    enabled: { type: "boolean" }, priority: { type: "integer", minimum: 0, maximum: 100000 },
    timeoutMs: { type: "integer", minimum: 100, maximum: 60000 }, failureAction: { type: "string", enum: ["inherit", "allow", "block"] },
  };
  app.get("/api/v1/ai-profiles", async () => ({ data: await store.listAiProfiles() }));
  app.post<{ Body: AiProfileInput }>("/api/v1/ai-profiles", {
    schema: { body: { type: "object", required: ["name", "baseUrl", "model"], additionalProperties: false, properties: profileProperties } },
  }, async (request, reply) => reply.code(201).send(await store.saveAiProfile(request.body)));
  app.patch<{ Params: { id: string }; Body: Partial<Omit<AiProfileInput, "id">> }>("/api/v1/ai-profiles/:id", {
    schema: { body: { type: "object", minProperties: 1, additionalProperties: false, properties: profileProperties } },
  }, async (request, reply) => {
    const current = (await store.listAiProfiles()).find((profile) => profile.id === request.params.id);
    if (!current) return notFound(reply, "Profile 不存在", request.url);
    const { apiKeyConfigured: _configured, ...profile } = current;
    return store.saveAiProfile({ ...profile, ...request.body, id: current.id });
  });
  app.delete<{ Params: { id: string } }>("/api/v1/ai-profiles/:id", async (request) => { await store.deleteAiProfile(request.params.id); return { ok: true }; });
  app.patch<{ Body: Record<string, unknown> }>(
    "/api/v1/settings",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          properties: {
            mode: { type: "string", enum: ["ai", "traditional", "hybrid"] },
            defaultPolicy: policySchema,
            strength: {
              type: "string",
              enum: ["veryLow", "low", "medium", "high", "extreme", "custom"],
            },
            customThreshold: { type: "number", minimum: 0, maximum: 1 },
            model: { type: "string", minLength: 1, maxLength: 256 },
            apiKey: { type: ["string", "null"], maxLength: 8192 },
            jevBaseUrl: { type: "string", minLength: 1, maxLength: 2048 },
            upstreamUrl: { type: "string", minLength: 1, maxLength: 2048 },
            aiTimeoutMs: { type: "integer", minimum: 100, maximum: 60000 },
            aiBodyLimit: {
              type: "integer",
              minimum: 1024,
              maximum: config.maxRequestBodyBytes,
            },
            auditMode: { type: "string", enum: ["sync", "async"] },
            asyncBanBaseSeconds: { type: "integer", minimum: 1, maximum: 86400 },
            asyncBanIncrementSeconds: { type: "integer", minimum: 1, maximum: 86400 },
            asyncBanMaxSeconds: { type: "integer", minimum: 1, maximum: 604800 },
            whitelistCidrs: { type: "array", maxItems: 5000, items: { type: "string", maxLength: 64 } },
            maliciousIpCidrs: { type: "array", maxItems: 5000, items: { type: "string", maxLength: 64 } },
            waitRoomDefaults: waitRoomSchema,
            captcha: { type: "object", additionalProperties: false, properties: { enabled: { type: "boolean" }, provider: { type: "string", enum: ["local", "turnstile", "hcaptcha", "recaptcha"] }, siteKey: { type: "string", maxLength: 512 }, secret: { type: ["string", "null"], maxLength: 8192 }, secretConfigured: { type: "boolean" }, timeoutMs: { type: "integer", minimum: 100, maximum: 30000 }, failureAction: { type: "string", enum: ["allow", "block"] }, trigger: { type: "string", enum: ["always", "cc"] } } },
          },
        },
      },
    },
    async (request, reply) => {
      const body = request.body ?? {};
      const nextSettings: Parameters<Store["updateSettings"]>[0] = {};
      if (body.defaultPolicy !== undefined) nextSettings.defaultPolicy = parsePolicy(body.defaultPolicy);
      if (body.mode !== undefined)
        nextSettings.mode = body.mode as ProtectionMode;
      if (body.strength !== undefined)
        nextSettings.strength = body.strength as ProtectionStrength;
      if (body.customThreshold !== undefined)
        nextSettings.customThreshold = Number(body.customThreshold);
      if (body.model !== undefined) nextSettings.model = String(body.model);
      if (body.jevBaseUrl !== undefined)
        nextSettings.jevBaseUrl = String(body.jevBaseUrl);
      if (body.apiKey !== undefined)
        nextSettings.apiKey = body.apiKey === null ? null : String(body.apiKey);
      if (body.aiTimeoutMs !== undefined)
        nextSettings.aiTimeoutMs = Number(body.aiTimeoutMs);
      if (body.aiBodyLimit !== undefined)
        nextSettings.aiBodyLimit = Number(body.aiBodyLimit);
      if (body.upstreamUrl !== undefined)
        nextSettings.upstreamUrl = String(body.upstreamUrl);
      if (body.auditMode !== undefined) nextSettings.auditMode = body.auditMode === "async" ? "async" : "sync";
      for (const key of ["asyncBanBaseSeconds", "asyncBanIncrementSeconds", "asyncBanMaxSeconds"] as const) {
        if (body[key] !== undefined) nextSettings[key] = Number(body[key]);
      }
      if (body.whitelistCidrs !== undefined) nextSettings.whitelistCidrs = body.whitelistCidrs as string[];
      if (body.maliciousIpCidrs !== undefined) nextSettings.maliciousIpCidrs = body.maliciousIpCidrs as string[];
      if (body.waitRoomDefaults !== undefined) nextSettings.waitRoomDefaults = body.waitRoomDefaults as NonNullable<Parameters<Store["updateSettings"]>[0]["waitRoomDefaults"]>;
      if (body.captcha !== undefined) {
        const captcha = body.captcha as Record<string, unknown>;
        const { secretConfigured: _configured, ...editable } = captcha;
        nextSettings.captcha = { ...store.getSettings().captcha, ...editable } as NonNullable<Parameters<Store["updateSettings"]>[0]["captcha"]>;
      }
      if (
        nextSettings.customThreshold !== undefined &&
        (!Number.isFinite(nextSettings.customThreshold) ||
          nextSettings.customThreshold < 0 ||
          nextSettings.customThreshold > 1)
      ) {
        return reply.code(422).send({
          type: "about:blank",
          title: "Validation error",
          status: 422,
          detail: "自定义阈值必须在 0 到 1 之间",
        });
      }
      if (
        nextSettings.aiTimeoutMs !== undefined &&
        (!Number.isFinite(nextSettings.aiTimeoutMs) ||
          nextSettings.aiTimeoutMs < 100)
      ) {
        return reply.code(422).send({
          type: "about:blank",
          title: "Validation error",
          status: 422,
          detail: "AI 超时必须至少为 100 毫秒",
        });
      }
      if (
        nextSettings.aiBodyLimit !== undefined &&
        (!Number.isFinite(nextSettings.aiBodyLimit) ||
          nextSettings.aiBodyLimit < 1024)
      ) {
        return reply.code(422).send({
          type: "about:blank",
          title: "Validation error",
          status: 422,
          detail: "AI 请求体上限必须至少为 1 KB",
        });
      }
      return store.updateSettings(nextSettings);
    },
  );

  app.post("/api/v1/settings/test-jev", async () => {
    const settings = store.getSettings();
    const selected = await store.getAiProvider();
    return classifyWithJev(
      JSON.stringify({ test: true, message: "JianFlow WAF connectivity test" }),
      selected?.profile.model ?? settings.model,
      selected?.profile.timeoutMs ?? settings.aiTimeoutMs, "management", selected?.provider,
    );
  });

  app.get("/api/v1/sites", async () => ({ data: store.listSites() }));
  app.get("/api/v1/nginx/imports", async () => ({ data: store.listNginxImports() }));
  app.post<{ Body: { content: string } }>("/api/v1/nginx/import/preview", async (request, reply) => {
    if (typeof request.body?.content !== "string" || request.body.content.length > 1024 * 1024) {
      return reply.code(422).send({ type: "about:blank", title: "Validation error", status: 422, detail: "Nginx 配置必须是 1 MB 以内的文本" });
    }
    return previewNginxConfig(request.body.content);
  });
  app.post<{ Body: { content: string; confirm?: boolean } }>("/api/v1/nginx/import", async (request, reply) => {
    if (request.body?.confirm !== true) return reply.code(409).send({ type: "about:blank", title: "Confirmation required", status: 409, detail: "请先预览并确认导入" });
    const preview = previewNginxConfig(request.body.content);
    if (!preview.valid) return reply.code(422).send(preview);
    const created = await store.importSites(preview.sites.map((imported) => ({ name: imported.name, listenPort: imported.listenPort, upstreamUrl: imported.upstreamUrl ?? imported.redirect!.location, upstreamPool: imported.upstreamPool ?? [], redirect: imported.redirect ?? null, mode: "traditional", enabled: true, operationMode: "defense", aiProfileId: null, policy: null, waitRoom: store.getSettings().waitRoomDefaults, maintenance: { source: "default", statusCode: 503 }, upstreamError: { source: "default", statusCode: 502 } })), createHash("sha256").update(request.body.content).digest("hex"));
    return { imported: created.length, data: created, skipped: 0 };
  });
  app.post<{
    Body: {
      name?: string;
      listenPort?: number;
      upstreamUrl?: string;
      upstreamPool?: Array<{ url: string; weight?: number }>;
      redirect?: { statusCode: 301 | 302; location: string } | null;
      mode?: ProtectionMode;
      operationMode?: "defense" | "record" | "maintenance";
      aiProfileId?: string | null;
      auditMode?: "sync" | "async" | null;
      captchaEnabled?: boolean | null;
      enabled?: boolean;
      policy?: SitePolicy | null;
      waitRoom?: { enabled: boolean; maxActive: number; maxQueue: number; timeoutSeconds: number };
      maintenance?: { source: "default" | "file" | "inline"; filePath?: string; html?: string; statusCode: number };
      upstreamError?: { source: "default" | "file" | "inline"; filePath?: string; html?: string; statusCode: number };
    };
  }>("/api/v1/sites", {
    schema: {
      body: {
        type: "object",
        required: ["name", "listenPort", "upstreamUrl"],
        additionalProperties: false,
        properties: {
          name: { type: "string", minLength: 1, maxLength: 256 },
          listenPort: { type: "integer", minimum: config.sitePortRange.min, maximum: config.sitePortRange.max },
          upstreamUrl: { type: "string", minLength: 1, maxLength: 2048 },
          upstreamPool: { type: "array", maxItems: 32, items: { type: "object", required: ["url"], additionalProperties: false, properties: { url: { type: "string", minLength: 1, maxLength: 2048 }, weight: { type: "integer", minimum: 1, maximum: 1000 } } } },
          redirect: { anyOf: [{ type: "null" }, { type: "object", required: ["statusCode", "location"], additionalProperties: false, properties: { statusCode: { type: "integer", enum: [301, 302] }, location: { type: "string", minLength: 1, maxLength: 2048 } } }] },
          mode: { type: "string", enum: ["ai", "traditional", "hybrid"] },
          operationMode: { type: "string", enum: ["defense", "record", "maintenance"] },
          aiProfileId: { type: ["string", "null"], maxLength: 128 },
          auditMode: { type: ["string", "null"], enum: ["sync", "async", null] },
          captchaEnabled: { type: ["boolean", "null"] },
          enabled: { type: "boolean" },
          policy: { anyOf: [policySchema, { type: "null" }] },
          waitRoom: waitRoomSchema,
          maintenance: pageSchema,
          upstreamError: pageSchema
        }
      }
    }
  }, async (request, reply) => {
    const body = request.body ?? {};
    if (!body.name || body.listenPort === undefined || !body.upstreamUrl) {
      return reply.code(422).send({
        type: "about:blank",
        title: "Validation error",
        status: 422, detail: "name、listenPort 和 upstreamUrl 必填",
      });
    }
    const site = await store.saveSite({
      name: body.name,
      listenPort: body.listenPort,
      upstreamUrl: body.upstreamUrl,
      upstreamPool: body.upstreamPool ?? [],
      redirect: body.redirect ?? null,
      mode: body.mode ?? "hybrid",
      operationMode: body.operationMode ?? "defense",
      aiProfileId: body.aiProfileId ?? null,
      auditMode: body.auditMode ?? null,
      captchaEnabled: body.captchaEnabled ?? null,
      enabled: body.enabled ?? true,
      ...(body.policy === undefined ? {} : { policy: body.policy }),
      ...(body.waitRoom === undefined ? {} : { waitRoom: body.waitRoom }),
      ...(body.maintenance === undefined ? {} : { maintenance: body.maintenance }),
      ...(body.upstreamError === undefined ? {} : { upstreamError: body.upstreamError }),
    });
    return reply.code(201).send(site);
  });
  app.patch<{
    Params: { id: string };
    Body: {
      name?: string;
      listenPort?: number;
      upstreamUrl?: string;
      upstreamPool?: Array<{ url: string; weight?: number }>;
      redirect?: { statusCode: 301 | 302; location: string } | null;
      mode?: ProtectionMode;
      operationMode?: "defense" | "record" | "maintenance";
      aiProfileId?: string | null;
      auditMode?: "sync" | "async" | null;
      captchaEnabled?: boolean | null;
      enabled?: boolean;
      policy?: SitePolicy | null;
      waitRoom?: { enabled: boolean; maxActive: number; maxQueue: number; timeoutSeconds: number };
      maintenance?: { source: "default" | "file" | "inline"; filePath?: string; html?: string; statusCode: number };
      upstreamError?: { source: "default" | "file" | "inline"; filePath?: string; html?: string; statusCode: number };
    };
  }>("/api/v1/sites/:id", {
    schema: {
      body: {
        type: "object",
        minProperties: 1,
        additionalProperties: false,
        properties: {
          name: { type: "string", minLength: 1, maxLength: 256 },
          listenPort: { type: "integer", minimum: config.sitePortRange.min, maximum: config.sitePortRange.max },
          upstreamUrl: { type: "string", minLength: 1, maxLength: 2048 },
          upstreamPool: { type: "array", maxItems: 32, items: { type: "object", required: ["url"], additionalProperties: false, properties: { url: { type: "string", minLength: 1, maxLength: 2048 }, weight: { type: "integer", minimum: 1, maximum: 1000 } } } },
          redirect: { anyOf: [{ type: "null" }, { type: "object", required: ["statusCode", "location"], additionalProperties: false, properties: { statusCode: { type: "integer", enum: [301, 302] }, location: { type: "string", minLength: 1, maxLength: 2048 } } }] },
          mode: { type: "string", enum: ["ai", "traditional", "hybrid"] },
          operationMode: { type: "string", enum: ["defense", "record", "maintenance"] },
          aiProfileId: { type: ["string", "null"], maxLength: 128 },
          auditMode: { type: ["string", "null"], enum: ["sync", "async", null] },
          captchaEnabled: { type: ["boolean", "null"] },
          enabled: { type: "boolean" },
          policy: { anyOf: [policySchema, { type: "null" }] },
          waitRoom: waitRoomSchema,
          maintenance: pageSchema,
          upstreamError: pageSchema
        }
      }
    }
  }, async (request, reply) => {
    const current = store.listSites().find((site) => site.id === request.params.id);
    if (!current) {
      return notFound(reply, "站点不存在", request.url);
    }
    const site = await store.saveSite({ ...current, ...request.body, id: current.id });
    return site;
  });
  app.delete<{ Params: { id: string } }>(
    "/api/v1/sites/:id",
    async (request, reply) => {
      if (!store.listSites().some((site) => site.id === request.params.id)) {
        return notFound(reply, "站点不存在", request.url);
      }
      await store.deleteSite(request.params.id);
      return { ok: true };
    },
  );

  app.post("/api/v1/listener-reloads", async (_request, reply) => {
    await store.retryListeners();
    return reply.code(201).send({ data: store.listSites(), ready: store.readiness() });
  });

  for (const kind of ["exceptions", "access-rules"] as const) {
    const path = `/api/v1/sites/:siteId/${kind}`;
    app.get<{ Params: { siteId: string }; Querystring: { limit?: number; offset?: number } }>(path, {
      schema: { querystring: { type: "object", additionalProperties: false, properties: {
        limit: { type: "integer", minimum: 1, maximum: 100 }, offset: { type: "integer", minimum: 0, maximum: 500 }
      } } }
    }, async (request, reply) => {
      if (!store.listSites().some((site) => site.id === request.params.siteId)) return notFound(reply, "站点不存在", request.url);
      const entries = store.listScopedRules(request.params.siteId, kind);
      const offset = request.query.offset ?? 0, limit = request.query.limit ?? 100;
      return { data: entries.slice(offset, offset + limit), pagination: { total: entries.length, offset, limit } };
    });
    app.post<{ Params: { siteId: string }; Body: unknown }>(path, async (request, reply) => {
      if (!store.listSites().some((site) => site.id === request.params.siteId)) return notFound(reply, "站点不存在", request.url);
      const rule = await store.saveScopedRule(request.params.siteId, kind, request.body);
      return reply.code(201).header("location", `/api/v1/sites/${request.params.siteId}/${kind}/${rule.id}`).send(rule);
    });
    app.patch<{ Params: { siteId: string; id: string }; Body: Record<string, unknown> }>(`${path}/:id`, async (request, reply) => {
      const current = store.listScopedRules(request.params.siteId, kind).find((rule) => rule.id === request.params.id);
      if (!current) return notFound(reply, "配置不存在", request.url);
      const { siteId: _siteId, id: _id, ...editable } = current;
      return store.saveScopedRule(request.params.siteId, kind, { ...editable, ...request.body }, current.id);
    });
    app.delete<{ Params: { siteId: string; id: string } }>(`${path}/:id`, async (request, reply) => {
      if (!store.listScopedRules(request.params.siteId, kind).some((rule) => rule.id === request.params.id)) return notFound(reply, "配置不存在", request.url);
      await store.deleteScopedRule(request.params.siteId, request.params.id);
      return { ok: true };
    });
  }

  app.post<{ Params: { siteId: string }; Body: { method: string; path: string; query?: string; headers?: Record<string, string>; body?: string; exception?: Omit<RuleException, "id" | "siteId"> } }>(
    "/api/v1/sites/:siteId/exception-previews", {
      schema: { body: { type: "object", required: ["method", "path"], additionalProperties: false, properties: {
        method: { type: "string", minLength: 1, maxLength: 32 }, path: { type: "string", minLength: 1, maxLength: 1024 },
        query: { type: "string", maxLength: 65536 }, body: { type: "string", maxLength: 524288 },
        headers: { type: "object", maxProperties: 100, additionalProperties: { type: "string", maxLength: 65536 } }, exception: { type: "object" }
      } } }
    }, async (request, reply) => {
      if (!store.listSites().some((site) => site.id === request.params.siteId)) return notFound(reply, "站点不存在", request.url);
      const { exception, ...sample } = request.body;
      const wafRequest = { ...sample, query: sample.query ?? "", headers: sample.headers ?? {}, siteId: request.params.siteId };
      const { parseScopedRule } = await import("./policy-validation.js");
      const exceptions = store.listScopedRules(request.params.siteId, "exceptions") as RuleException[];
      if (exception) exceptions.push(parseScopedRule(exception, request.params.siteId, "preview", "exceptions") as RuleException);
      return { before: evaluateRules(wafRequest, store.listRules()), after: evaluateRules(wafRequest, store.listRules(), exceptions) };
    }
  );

  app.get("/api/v1/rules", async () => ({ data: store.listRules() }));
  app.post<{ Body: WafRule }>("/api/v1/rules", async (request, reply) => {
    const rule = validateRule(request.body);
    const result = await store.importRules([rule]);
    return reply.code(201).send(result.data[0]);
  });
  type ImportBody = { format: "json" | "modsecurity"; content: string; conflict?: "reject" | "overwrite" | "skip"; enabled?: boolean };
  const importSchema = {
    body: {
      type: "object", required: ["format", "content"], additionalProperties: false,
      properties: {
        format: { type: "string", enum: ["json", "modsecurity"] },
        content: { type: "string", minLength: 1, maxLength: 524288 },
        conflict: { type: "string", enum: ["reject", "overwrite", "skip"] },
        enabled: { type: "boolean" }
      }
    }
  };
  app.post<{ Body: ImportBody }>("/api/v1/rules/import/preview", { schema: importSchema }, async (request) => {
    try {
      const parsed = parseRuleImport(request.body.content, request.body.format);
      const ids = new Set(store.listRules().map((rule) => rule.id));
      return {
        valid: true, data: parsed.rules, warnings: parsed.warnings, errors: [],
        conflicts: parsed.rules.filter((rule) => ids.has(rule.id)).map((rule) => rule.id)
      };
    } catch (error) {
      return { valid: false, data: [], warnings: [], conflicts: [],
        errors: [error instanceof RuleImportError ? error.issue : { message: (error as Error).message, line: 1, column: 1 }] };
    }
  });
  app.post<{ Body: ImportBody }>(
    "/api/v1/rules/import",
    { schema: importSchema },
    async (request) => {
      const parsed = parseRuleImport(request.body.content, request.body.format);
      const saved = await store.importRules(parsed.rules, request.body.conflict ?? "reject", request.body.enabled);
      return { imported: saved.data.length, skipped: saved.skipped, warnings: parsed.warnings, data: saved.data };
    },
  );
  app.patch<{ Params: { id: string }; Body: Partial<WafRule> }>(
    "/api/v1/rules/:id",
    async (request, reply) => {
      const current = store
        .listRules()
        .find((rule) => rule.id === request.params.id);
      if (!current)
        return reply.code(404).send({
          type: "about:blank",
          title: "Not found",
          status: 404,
          detail: "规则不存在",
        });
      if (request.body.id !== undefined && request.body.id !== current.id) throw new ValidationError("不能修改规则 id");
      return store.saveRule({ ...current, ...request.body, id: current.id });
    },
  );
  app.delete<{ Params: { id: string } }>(
    "/api/v1/rules/:id",
    async (request) => {
      await store.deleteRule(request.params.id);
      return { ok: true };
    },
  );
  app.post<{
    Body: {
      method: string;
      path: string;
      query?: string;
      headers?: Record<string, string>;
      body?: string;
      ip?: string;
    };
  }>("/api/v1/rules/test", {
    schema: { body: {
      type: "object", required: ["method", "path"], additionalProperties: false,
      properties: {
        method: { type: "string", minLength: 1, maxLength: 32 },
        path: { type: "string", minLength: 1, maxLength: 65536 },
        query: { type: "string", maxLength: 65536 },
        body: { type: "string", maxLength: 524288 }, ip: { type: "string", maxLength: 64 },
        headers: { type: "object", maxProperties: 100, additionalProperties: { type: "string", maxLength: 65536 } }
      }
    } }
  }, async (request) => {
    const body = request.body;
    const wafRequest = {
      method: body.method,
      path: body.path,
      query: body.query ?? "",
      headers: Object.fromEntries(Object.entries(body.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value])),
      ...(body.body !== undefined ? { body: body.body } : {}),
      ...(body.ip !== undefined ? { ip: body.ip } : {}),
    } as Parameters<typeof evaluateRules>[0];
    return { matches: evaluateRules(wafRequest, store.listRules()) };
  });

  app.get("/api/v1/live", { websocket: true }, (socket) => {
    socket.send(JSON.stringify({ type: "ready", id: randomUUID() }));
  });

  return app;
}
