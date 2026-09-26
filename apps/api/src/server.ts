import { randomUUID } from "node:crypto";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import websocket from "@fastify/websocket";
import { evaluateRules, type WafRule, type ProtectionMode, type ProtectionStrength } from "@jev-waf/core";
import { config } from "./config.js";
import { configureAdmin, checkPassword, createSession, destroySession, getSession } from "./auth.js";
import { Store } from "./db/store.js";
import { classifyWithJev } from "./jev.js";
import { createHttpsProxyServer, createProxyServer } from "./proxy.js";

const store = new Store();
const app = Fastify({ logger: true });

await store.init();
configureAdmin(config.adminPassword);
await app.register(cookie, { secret: config.sessionSecret });
await app.register(websocket);

app.get("/api/v1/health", async () => ({
  ok: true,
  service: "jianflow-waf-api",
  database: Boolean(config.databaseUrl),
  aiConfigured: Boolean(config.openRouterKey),
  timestamp: new Date().toISOString()
}));

app.post<{ Body: { username?: string; password?: string } }>("/api/v1/auth/login", async (request, reply) => {
  const username = request.body.username ?? "";
  const password = request.body.password ?? "";
  if (username !== config.adminUser || !checkPassword(password)) {
    return reply.code(401).send({ type: "about:blank", title: "Unauthorized", status: 401, detail: "用户名或密码错误" });
  }
  const token = createSession(username);
  reply.setCookie("jev_session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: request.headers["x-forwarded-proto"] === "https",
    path: "/",
    maxAge: 8 * 60 * 60
  });
  return { username };
});

app.post("/api/v1/auth/logout", async (request, reply) => {
  destroySession(request.cookies.jev_session);
  reply.clearCookie("jev_session", { path: "/" });
  return { ok: true };
});

app.addHook("preHandler", async (request, reply) => {
  if (request.url.startsWith("/api/v1/health") || request.url.startsWith("/api/v1/auth/")) {
    return;
  }
  if (!getSession(request.cookies.jev_session)) {
    return reply.code(401).send({ type: "about:blank", title: "Unauthorized", status: 401, detail: "请先登录管理后台" });
  }
});

app.get("/api/v1/auth/me", async (request, reply) => {
  const session = getSession(request.cookies.jev_session);
  if (!session) {
    return reply.code(401).send({ type: "about:blank", title: "Unauthorized", status: 401 });
  }
  return { username: session.username };
});

app.get("/api/v1/dashboard/summary", async () => store.summary());
app.get("/api/v1/events", async (request) => {
  const limit = Number((request.query as { limit?: string }).limit ?? 50);
  return { data: await store.listEvents(Number.isFinite(limit) ? limit : 50) };
});
app.get("/api/v1/settings", async () => ({
  ...store.getSettings(),
  apiKeyConfigured: Boolean(config.openRouterKey)
}));

app.patch<{ Body: Partial<ReturnType<Store["getSettings"]>> }>("/api/v1/settings", async (request) => {
  const body = request.body as Partial<ReturnType<Store["getSettings"]>>;
  const nextSettings: Partial<ReturnType<Store["getSettings"]>> = {};
  if (body.mode !== undefined) nextSettings.mode = body.mode;
  if (body.strength !== undefined) nextSettings.strength = body.strength;
  if (body.customThreshold !== undefined) nextSettings.customThreshold = body.customThreshold;
  if (body.model !== undefined) nextSettings.model = body.model;
  if (body.aiTimeoutMs !== undefined) nextSettings.aiTimeoutMs = body.aiTimeoutMs;
  if (body.aiBodyLimit !== undefined) nextSettings.aiBodyLimit = body.aiBodyLimit;
  if (body.upstreamUrl !== undefined) nextSettings.upstreamUrl = body.upstreamUrl;
  const next = await store.updateSettings(nextSettings);
  return next;
});

app.post("/api/v1/settings/test-jev", async () => {
  const settings = store.getSettings();
  return classifyWithJev(
    JSON.stringify({ test: true, message: "JianFlow WAF connectivity test" }),
    settings.model,
    settings.aiTimeoutMs
  );
});

app.get("/api/v1/sites", async () => ({ data: store.listSites() }));
app.post<{ Body: { name?: string; upstreamUrl?: string; mode?: ProtectionMode; enabled?: boolean } }>("/api/v1/sites", async (request, reply) => {
  const body = request.body as { name?: string; upstreamUrl?: string; mode?: ProtectionMode; enabled?: boolean };
  if (!body.name || !body.upstreamUrl) {
    return reply.code(422).send({ type: "about:blank", title: "Validation error", status: 422, detail: "name 和 upstreamUrl 必填" });
  }
  const site = await store.saveSite({
    name: body.name,
    upstreamUrl: body.upstreamUrl,
    mode: body.mode ?? "hybrid",
    enabled: body.enabled ?? true
  });
  return reply.code(201).send(site);
});
app.delete<{ Params: { id: string } }>("/api/v1/sites/:id", async (request) => {
  await store.deleteSite(request.params.id);
  return { ok: true };
});

app.get("/api/v1/rules", async () => ({ data: store.listRules() }));
app.post<{ Body: WafRule }>("/api/v1/rules", async (request, reply) => {
  const body = request.body as WafRule;
  if (!body.id || !body.pattern || !body.name) {
    return reply.code(422).send({ type: "about:blank", title: "Validation error", status: 422, detail: "规则 id、name 和 pattern 必填" });
  }
  return reply.code(201).send(await store.saveRule(body));
});
app.patch<{ Params: { id: string }; Body: Partial<WafRule> }>("/api/v1/rules/:id", async (request, reply) => {
  const body = request.body as Partial<WafRule>;
  const current = store.listRules().find((rule) => rule.id === request.params.id);
  if (!current) {
    return reply.code(404).send({ type: "about:blank", title: "Not found", status: 404, detail: "规则不存在" });
  }
  return store.saveRule({ ...current, ...body, id: current.id });
});
app.delete<{ Params: { id: string } }>("/api/v1/rules/:id", async (request) => {
  await store.deleteRule(request.params.id);
  return { ok: true };
});
app.post<{ Body: { method: string; path: string; query?: string; headers?: Record<string, string>; body?: string; ip?: string } }>("/api/v1/rules/test", async (request) => {
  const body = request.body as { method: string; path: string; query?: string; headers?: Record<string, string>; body?: string; ip?: string };
  const wafRequest = {
    method: body.method,
    path: body.path,
    query: body.query ?? "",
    headers: body.headers ?? {}
  } as Parameters<typeof evaluateRules>[0];
  if (body.body !== undefined) wafRequest.body = body.body;
  if (body.ip !== undefined) wafRequest.ip = body.ip;
  return {
    matches: evaluateRules(wafRequest, store.listRules())
  };
});

app.get("/api/v1/live", { websocket: true }, (socket) => {
  socket.send(JSON.stringify({ type: "ready", id: randomUUID() }));
});

const proxyServer = createProxyServer(store);
await app.listen({ host: config.apiHost, port: config.apiPort });
proxyServer.listen(config.proxyPort, config.proxyHost);
const httpsProxyServer = config.tlsKeyPath && config.tlsCertPath
  ? createHttpsProxyServer(store, config.tlsKeyPath, config.tlsCertPath)
  : null;
if (httpsProxyServer) {
  httpsProxyServer.listen(config.httpsPort, config.proxyHost);
}
console.log(`JianFlow WAF API listening on http://${config.apiHost}:${config.apiPort}`);
console.log(`JianFlow WAF proxy listening on http://${config.proxyHost}:${config.proxyPort}`);
if (httpsProxyServer) {
  console.log(`JianFlow WAF TLS proxy listening on https://${config.proxyHost}:${config.httpsPort}`);
}
