import { randomUUID } from "node:crypto";
import Fastify from "fastify";
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
import { classifyWithJev } from "./jev.js";
import { SetupConflictError, ValidationError } from "./errors.js";

export async function createApp(store: Store, logger = true) {
  const app = Fastify({
    logger,
    trustProxy: config.trustedProxyCidrs.length
      ? config.trustedProxyCidrs
      : false,
    ajv: { customOptions: { removeAdditional: false } },
  });

  await app.register(cookie, { secret: config.sessionSecret });
  await app.register(websocket);
  await app.register(rateLimit, { global: false });
  app.setErrorHandler((error, request, reply) => {
    const failure = (
      error instanceof Error ? error : new Error("请求处理失败")
    ) as Error & {
      validation?: unknown;
      statusCode?: number;
    };
    const status =
      error instanceof SetupConflictError
        ? 409
        : error instanceof ValidationError || failure.validation
          ? 422
          : failure.statusCode && failure.statusCode < 500
            ? failure.statusCode
            : 500;
    if (status >= 500)
      request.log.error({ err: failure }, "Management request failed");
    return reply.code(status).send({
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
      aiConfigured: Boolean(config.openRouterKey),
      setup: store.setupStatus(),
      timestamp: new Date().toISOString(),
    });
  });

  app.get("/api/v1/setup/status", async () => store.setupStatus());

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

  app.addHook("preHandler", async (request, reply) => {
    if (
      request.url.startsWith("/api/v1/health") ||
      request.url.startsWith("/api/v1/setup") ||
      request.url.startsWith("/api/v1/auth/")
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
    proxyPort: config.proxyPort, apiPort: config.apiPort,
    maxRequestBodyBytes: config.maxRequestBodyBytes,
    httpsEnabled: Boolean(config.tlsKeyPath && config.tlsCertPath),
    geoIpAsnConfigured: Boolean(config.geoIpAsnDatabasePath),
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
      });
    },
  );

  app.get("/api/v1/settings", async () => store.getSettings());
  app.patch<{ Body: Record<string, unknown> }>(
    "/api/v1/settings",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          properties: {
            mode: { type: "string", enum: ["ai", "traditional", "hybrid"] },
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
          },
        },
      },
    },
    async (request, reply) => {
      const body = request.body ?? {};
      const nextSettings: Parameters<Store["updateSettings"]>[0] = {};
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
    return classifyWithJev(
      JSON.stringify({ test: true, message: "JianFlow WAF connectivity test" }),
      settings.model,
      settings.aiTimeoutMs,
    );
  });

  app.get("/api/v1/sites", async () => ({ data: store.listSites() }));
  app.post<{
    Body: {
      name?: string;
      upstreamUrl?: string;
      mode?: ProtectionMode;
      enabled?: boolean;
    };
  }>("/api/v1/sites", async (request, reply) => {
    const body = request.body ?? {};
    if (!body.name || !body.upstreamUrl) {
      return reply.code(422).send({
        type: "about:blank",
        title: "Validation error",
        status: 422,
        detail: "name 和 upstreamUrl 必填",
      });
    }
    const site = await store.saveSite({
      name: body.name,
      upstreamUrl: body.upstreamUrl,
      mode: body.mode ?? "hybrid",
      enabled: body.enabled ?? true,
    });
    return reply.code(201).send(site);
  });
  app.delete<{ Params: { id: string } }>(
    "/api/v1/sites/:id",
    async (request) => {
      await store.deleteSite(request.params.id);
      return { ok: true };
    },
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
