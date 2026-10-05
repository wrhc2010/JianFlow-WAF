import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { PassThrough, type Duplex } from "node:stream";
import { randomUUID } from "node:crypto";
import { brotliDecompress, gunzip, inflate } from "node:zlib";
import { promisify } from "node:util";
import httpProxy from "http-proxy";
import { BUILTIN_RULES, evaluateRequest, evaluateRules, defaultPolicy, buildAiInspection, thresholdFor, isIpInCidr,
  type WafDecision, type WafRequest, type SitePolicy, type AccessRule, type RuleException } from "@jev-waf/core";
import { config } from "./config.js";
import { classifyWithJev, aiRuntime } from "./jev.js";
import { Store, type Site } from "./db/store.js";
import { inspectBody } from "./body-inspection.js";
import { TrafficControl } from "./traffic-control.js";
import { WaitRoom } from "./wait-room.js";
export { isIpInCidr } from "@jev-waf/core";

const proxy = httpProxy.createProxyServer({ changeOrigin: true, xfwd: false, proxyTimeout: 30000 });
const decompressGzip = promisify(gunzip);
const decompressDeflate = promisify(inflate);
const decompressBrotli = promisify(brotliDecompress);
const maxRequestBodyBytes = config.maxRequestBodyBytes;
const clientControlledRoutingHeaders = [
  "forwarded",
  "x-client-ip",
  "client-ip",
  "http_x_forwarded_for",
  "http-x-forwarded-for",
  "x-forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-port",
  "x-forwarded-prefix",
  "x-forwarded-proto",
  "x-forwarded-scheme",
  "x-forwarded-user",
  "x-real-ip",
  "x-remote-ip",
  "x-remote-addr",
  "x-on-behalf-of",
  "x-proxy-user",
  "front-end-http-x-forwarded-for",
  "wl-proxy-client-ip",
  "x-original-url",
  "x-rewrite-url",
  "x-http-method-override"
];
const controls = new WeakMap<Store, TrafficControl>();
const waitRooms = new WeakMap<Store, Map<string, WaitRoom>>();
const builtinIds = new Set(BUILTIN_RULES.map((rule) => rule.id));
function control(store: Store): TrafficControl {
  let value = controls.get(store);
  if (!value) { value = new TrafficControl(); controls.set(store, value); }
  return value;
}
function waitRoom(store: Store, site: Site): WaitRoom {
  let rooms = waitRooms.get(store);
  if (!rooms) { rooms = new Map(); waitRooms.set(store, rooms); }
  const key = `${site.id}:${JSON.stringify(site.waitRoom)}`;
  let room = rooms.get(key);
  if (!room) {
    room = new WaitRoom(site.waitRoom ?? { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 });
    rooms.set(key, room);
    for (const old of rooms.keys()) if (old.startsWith(`${site.id}:`) && old !== key) rooms.delete(old);
  }
  return room;
}
export function trafficRuntime(store: Store) { return control(store).snapshot(); }

function headersOf(request: http.IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(
    Object.entries(request)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key, Array.isArray(value) ? value.join("\n") : String(value)])
  );
}

type BodyReadResult = {
  body: string;
  forwardBody: Buffer;
  partial: boolean;
  error?: string;
  fields?: Array<[string, string]>;
};

export async function readBody(request: http.IncomingMessage): Promise<BodyReadResult> {
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of request.iterator({ destroyOnReturn: false })) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > maxRequestBodyBytes) {
        request.resume();
        return { body: "", forwardBody: Buffer.alloc(0), partial: true, error: `请求体超过 ${maxRequestBodyBytes} 字节限制` };
      }
      chunks.push(buffer);
    }
  } catch {
    return { body: "", forwardBody: Buffer.alloc(0), partial: true, error: "请求体传输不完整" };
  }
  const forwardBody = Buffer.concat(chunks);
  const rawEncoding = request.headers["content-encoding"];
  const encodings = (Array.isArray(rawEncoding) ? rawEncoding.join(",") : rawEncoding ?? "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean)
    .reverse();
  let inspectionBody = forwardBody;
  try {
    if (encodings.length > 3) throw new Error("压缩层数超过检测限制");
    const options = { maxOutputLength: maxRequestBodyBytes };
    for (const encoding of encodings) {
      if (encoding === "identity") continue;
      if (encoding === "gzip" || encoding === "x-gzip") inspectionBody = await decompressGzip(inspectionBody, options);
      else if (encoding === "deflate") inspectionBody = await decompressDeflate(inspectionBody, options);
      else if (encoding === "br") inspectionBody = await decompressBrotli(inspectionBody, options);
      else throw new Error(`不支持的 Content-Encoding: ${encoding}`);
    }
    for (const name of ["content-type", "content-encoding"]) {
      if ((request.headersDistinct?.[name]?.length ?? 0) > 1) {
        throw new Error(`重复的 ${name} 头无法被安全检查`);
      }
    }
    const contentType = String(request.headers["content-type"] ?? "");
    const fields: Array<[string, string]> = [];
    const body = await inspectBody(inspectionBody, contentType, maxRequestBodyBytes, fields);
    return { body, forwardBody, partial: false, ...(/^multipart\/form-data\b/i.test(contentType) ? { fields } : {}) };
  } catch (error) {
    const overLimit = (error as NodeJS.ErrnoException).code === "ERR_BUFFER_TOO_LARGE";
    return { body: "", forwardBody, partial: true,
      error: overLimit ? "解压后的请求体超过检测限制" : `请求体无法完整检查: ${error instanceof Error ? error.message : "格式无效"}` };
  }
}

export function clientIp(request: http.IncomingMessage, trustedCidrs = config.trustedProxyCidrs): string | undefined {
  const remote = request.socket.remoteAddress;
  if (!remote) return undefined;
  const normalizedRemote = remote.replace(/^::ffff:/i, "");
  const trusted = (ip: string): boolean => trustedCidrs.some((value) => isIpInCidr(ip, value));
  if (!trusted(normalizedRemote)) return normalizedRemote;
  const forwarded = request.headers["x-forwarded-for"];
  if (typeof forwarded !== "string") return normalizedRemote;
  const chain = forwarded.split(",").map((ip) => ip.trim().replace(/^::ffff:/i, ""));
  if (chain.length > 32 || chain.some((ip) => !isIP(ip))) return normalizedRemote;
  let current = normalizedRemote;
  for (let index = chain.length - 1; index >= 0 && trusted(current); index -= 1) current = chain[index]!;
  return current;
}

function validateRequestFraming(request: http.IncomingMessage): void {
  if (request.httpVersionMajor < 1) throw new Error("不支持 HTTP/0.9 请求");
  const contentLengths = request.headersDistinct?.["content-length"]
    ?? (request.headers["content-length"] ? [String(request.headers["content-length"])] : []);
  if (new Set(contentLengths.map((value) => value.trim())).size > 1) {
    throw new Error("重复的 Content-Length 值不一致");
  }
  const transferEncoding = request.headers["transfer-encoding"];
  if (transferEncoding && contentLengths.length) {
    throw new Error("请求不能同时包含 Content-Length 和 Transfer-Encoding");
  }
  if (transferEncoding && transferEncoding.split(",").some((value) => value.trim().toLowerCase() !== "chunked")) {
    throw new Error("仅支持 chunked Transfer-Encoding");
  }
}

function blockResponse(response: http.ServerResponse, status: number, decisionReason: string, requestId: string): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "x-jev-request-id": requestId
  });
  response.end(JSON.stringify({
    error: status === 503 ? "ai_unavailable" : status === 403 ? "request_blocked" : "request_rejected",
    message: status === 503 ? "AI 防护服务暂时不可用" : status === 403 ? "请求已被 WAF 拦截" : "请求无法被安全检查",
    reason: decisionReason,
    requestId
  }));
}

function isWhitelisted(store: Store, ip: string | undefined): boolean {
  if (!ip) return false;
  return (store.getSettings().whitelistCidrs ?? []).some((cidr) => isIpInCidr(ip, cidr));
}

function isMaliciousIp(store: Store, ip: string | undefined): boolean {
  if (!ip || isWhitelisted(store, ip)) return false;
  return (store.getSettings().maliciousIpCidrs ?? []).some((cidr) => isIpInCidr(ip, cidr));
}

function runtimeBan(store: Store, siteId: string, ip: string | undefined): number {
  if (!ip || isWhitelisted(store, ip)) return 0;
  const stored = typeof store.getRuntimeBan === "function" ? store.getRuntimeBan(siteId, ip) : undefined;
  if (stored) return Math.max(1, Math.ceil((stored.until - Date.now()) / 1000));
  return control(store).isBanned(siteId, ip);
}

function pageResponse(store: Store, response: http.ServerResponse, page: Site["maintenance"] | Site["upstreamError"], status: number, title: string, requestId: string): void {
  const configured = typeof store.readPage === "function" ? store.readPage(page) : page?.source === "inline" ? page.html : undefined;
  const body = configured || `<!doctype html><meta charset="utf-8"><title>${title}</title><style>body{font-family:system-ui,sans-serif;background:#f2f8f4;color:#18352a;padding:10vh 8vw}main{max-width:640px;margin:auto;background:#fff;border:1px solid #cce5d6;border-radius:18px;padding:32px}h1{margin-top:0;color:#147d57}</style><main><h1>${title}</h1><p>请稍后再试。</p><small>Request ID: ${requestId}</small></main>`;
  response.writeHead(page?.statusCode ?? status, { "content-type": "text/html; charset=utf-8", "content-length": Buffer.byteLength(body), "x-jev-request-id": requestId });
  response.end(body);
}

function inspectionFailure(
  mode: WafDecision["mode"],
  requestId: string,
  reason: string
): WafDecision {
  return {
    action: "error",
    mode,
    matchedRules: [],
    reason,
    requestId,
    partialInspection: true
  };
}

function upgradeBlock(socket: Duplex, status: number, requestId: string, retryAfter?: number): void {
  const retry = retryAfter === undefined ? "" : `Retry-After: ${Math.max(1, Math.ceil(retryAfter))}\r\n`;
  socket.end(`HTTP/1.1 ${status} WAF Rejected\r\nConnection: close\r\nContent-Length: 0\r\nX-Jev-Request-Id: ${requestId}\r\n${retry}\r\n`);
}

function requestOf(request: http.IncomingMessage): WafRequest {
  return {
    method: request.method ?? "GET", path: request.url ?? "/", query: "",
    headers: headersOf(request.headersDistinct ?? request.headers),
    ip: clientIp(request), isWebSocketUpgrade: request.headers.upgrade?.toLowerCase() === "websocket"
  };
}

function splitRequestTarget(request: WafRequest): void {
  const raw = request.path;
  if ((!raw.startsWith("/") && raw !== "*") || raw.includes("#")) throw new Error("请求目标格式无效");
  const queryAt = raw.indexOf("?");
  if (queryAt >= 0) {
    request.path = raw.slice(0, queryAt);
    request.query = raw.slice(queryAt);
  }
}

function forwardHeaders(request: http.IncomingMessage, wafRequest: WafRequest): void {
  for (const header of clientControlledRoutingHeaders) delete request.headers[header];
  request.headers["x-forwarded-for"] = wafRequest.ip ?? "";
  request.headers["x-real-ip"] = wafRequest.ip ?? "";
  request.headers["x-forwarded-proto"] = "encrypted" in request.socket && Boolean(request.socket.encrypted) ? "https" : "http";
}

function eventSaver(store: Store, request: WafRequest, site?: Site, shadow?: () => Promise<Partial<WafDecision>> | undefined): (decision: WafDecision, status: number) => Promise<void> {
  let saved = false;
  return async (decision, status) => {
    if (saved) return;
    saved = true;
    try {
      await store.saveEvent(decision, { method: request.method, path: `${request.path}${request.query}`, ip: request.ip,
        ...(site ? { siteId: site.id, listenPort: site.listenPort, policyRevision: site.revision ?? 1 } : {}) }, status, shadow?.());
    } catch {
      console.error(`Failed to persist WAF event ${decision.requestId}`);
    }
  };
}

const responseFailures = new WeakMap<http.IncomingMessage, (reason: string) => void>();
proxy.on("proxyRes", (upstream, request) => {
  upstream.once("aborted", () => responseFailures.get(request)?.("上游响应传输中断"));
  upstream.once("error", () => responseFailures.get(request)?.("上游响应传输失败"));
});

function settingsForPort(store: Store, listenPort?: number) {
  const settings = store.getSettings();
  if (typeof store.getSiteByPort !== "function") return { settings, policy: defaultPolicy(), site: undefined };
  const site = store.getSiteByPort(listenPort ?? config.proxyPort);
  if (!site || !site.enabled) return undefined;
  const policy = store.effectivePolicy?.(site) ?? { ...defaultPolicy(), strength: settings.strength, customThreshold: settings.customThreshold };
  return { settings: { ...settings, mode: site.mode, upstreamUrl: site.upstreamUrl, strength: policy.strength, customThreshold: policy.customThreshold }, policy, site };
}

function accessDecision(store: Store, request: WafRequest, mode: WafDecision["mode"], requestId: string): { decision?: WafDecision; skip: boolean } {
  if (isWhitelisted(store, request.ip)) return { skip: false };
  if (isMaliciousIp(store, request.ip)) return { skip: false, decision: {
    action: "block", mode, requestId, matchedRules: [], reason: "来源 IP 命中恶意 IP 库", module: "threat-feed", localInspectionComplete: true
  } };
  const access = (store.listScopedRules?.(request.siteId ?? "", "access-rules") ?? []) as AccessRule[];
  const matches = access.filter((entry) => entry.enabled && Date.parse(entry.expiresAt) > Date.now()
    && (entry.method === "*" || entry.method === request.method) && (entry.path === "*" || entry.path === request.path)
    && isIpInCidr(request.ip ?? "", entry.cidr));
  const critical = evaluateRules(request, store.listRules().filter((rule) => rule.enabled && rule.action === "block"
    && (rule.target === "ip" || !builtinIds.has(rule.id) && ["path", "method"].includes(rule.target))));
  if (matches.some((entry) => entry.action === "block") || critical.length) return { skip: false, decision: {
    action: "block", mode, requestId, matchedRules: critical, reason: "访问控制拒绝", module: "acl", localInspectionComplete: false
  } };
  return { skip: matches.some((entry) => entry.action === "skip-detection") };
}

async function inspectRequest(store: Store, request: WafRequest, resolved: NonNullable<ReturnType<typeof settingsForPort>>, requestId: string, skip: boolean) {
  const { settings, policy, site } = resolved;
  if (skip) return { decision: { action: "allow", mode: settings.mode, requestId, matchedRules: [], reason: "访问控制：跳过检测", module: "acl", localInspectionComplete: false } as WafDecision };
  const exceptions = (store.listScopedRules?.(site?.id ?? "", "exceptions") ?? []) as RuleException[];
  const profile = typeof store.getAiProvider === "function" ? await store.getAiProvider(site?.aiProfileId) : undefined;
  const effectiveSettings = profile ? { ...settings, model: profile.profile.model, aiTimeoutMs: profile.profile.timeoutMs } : settings;
  const classify = (state: string, model: string, timeout: number) => classifyWithJev(
    state,
    profile?.profile.model ?? model,
    profile?.profile.timeoutMs ?? timeout,
    site?.id,
    profile?.provider
  );
  if (policy.aiBehavior !== "shadow" || effectiveSettings.mode === "traditional") return {
    decision: await evaluateRequest(request, store.listRules(), effectiveSettings, requestId, classify, { policy, exceptions })
  };
  const decision = await evaluateRequest(request, store.listRules(), { ...effectiveSettings, mode: "traditional" }, requestId, classify, { policy, exceptions });
  decision.mode = effectiveSettings.mode;
  if (decision.action !== "allow" || policy.aiScope === "suspicious" && !decision.matchedRules.length) return { decision };
  const inspection = buildAiInspection(request, effectiveSettings.aiBodyLimit, policy.aiBodyFields);
  // Shadow work has no waiting queue; admission and provider timeout bound its lifetime.
  const shadow = aiRuntime().active >= config.aiMaxConcurrent
    ? Promise.resolve({ aiInspectionComplete: false, aiOmittedReason: "concurrency_limit" } as Partial<WafDecision>)
    : profile ? classify(inspection.state, profile.profile.model, profile.profile.timeoutMs).then((ai): Partial<WafDecision> => ({ ai,
      ...(ai.available ? { score: ai.noul } : {}), threshold: thresholdFor(effectiveSettings),
      aiInspectionComplete: inspection.complete, ...(inspection.omittedReason ? { aiOmittedReason: inspection.omittedReason } : {}),
      partialInspection: !inspection.complete, module: "rules+ai-shadow"
    })) : Promise.resolve({ aiInspectionComplete: false, aiOmittedReason: "missing_profile" } as Partial<WafDecision>);
  return { decision, shadow };
}

function scheduleAsyncAudit(
  store: Store,
  request: WafRequest,
  resolved: NonNullable<ReturnType<typeof settingsForPort>>,
  decision: WafDecision,
  requestId: string
): void {
  if (store.getSettings().auditMode !== "async" || !request.ip || isWhitelisted(store, request.ip)) return;
  const { settings, policy, site } = resolved;
  if (!site || !policy.aiScope || policy.aiBehavior === "shadow" || settings.mode === "traditional") return;
  const profilePromise = typeof store.getAiProvider === "function" ? store.getAiProvider(site.aiProfileId) : Promise.resolve(undefined);
  void profilePromise.then(async (profile) => {
    const inspection = buildAiInspection(request, settings.aiBodyLimit, policy.aiBodyFields);
    const provider = profile?.provider;
    const ai = await classifyWithJev(inspection.state, profile?.profile.model ?? settings.model, profile?.profile.timeoutMs ?? settings.aiTimeoutMs, site.id, provider);
    if (!ai.available || ai.noul < thresholdFor(settings)) return;
    const current = store.getSettings();
    const base = current.asyncBanBaseSeconds;
    const increment = current.asyncBanIncrementSeconds;
    const max = current.asyncBanMaxSeconds;
    const stored = typeof store.recordRuntimeBan === "function"
      ? store.recordRuntimeBan(site.id, request.ip!, base, increment, max)
      : undefined;
    const seconds = stored?.seconds ?? Math.min(max, base + (control(store).isBanned(site.id, request.ip!) > 0 ? increment : 0));
    if (!stored) control(store).ban(site.id, request.ip!, seconds);
    const followup: WafDecision = {
      action: "block", mode: settings.mode, requestId: `${requestId}:async`, matchedRules: [],
      reason: `异步审核判定恶意，已封禁 ${seconds} 秒`, module: "async-ai", ai, score: ai.noul,
      threshold: thresholdFor(settings), aiInspectionComplete: inspection.complete, partialInspection: !inspection.complete
    };
    await store.saveEvent(followup, { method: request.method, path: `${request.path}${request.query}`, ip: request.ip, siteId: site.id, listenPort: site.listenPort, policyRevision: site.revision ?? 1 }, 403);
  }).catch(() => undefined);
}

async function handleProxyRequest(store: Store, request: http.IncomingMessage, response: http.ServerResponse, listenPort?: number): Promise<void> {
  const requestId = randomUUID();
  const resolved = settingsForPort(store, listenPort);
  if (!resolved) { request.resume(); blockResponse(response, 503, "入口不存在或已停用", requestId); return; }
  const { settings, policy, site } = resolved;
  const wafRequest = requestOf(request);
  if (site) wafRequest.siteId = site.id;
  let shadow: Promise<Partial<WafDecision>> | undefined;
  const saveOnce = eventSaver(store, wafRequest, site, () => shadow);
  let release = () => {};
  let decision = inspectionFailure(settings.mode, requestId, "请求尚未完成检查");
  response.once("finish", () => {
    release();
    const status = response.statusCode || 502;
    if (status >= 500 && decision.action === "allow") decision = { ...decision, action: "error", reason: `上游返回 HTTP ${status}` };
    void saveOnce(decision, status);
  });
  response.once("close", () => {
    release();
    if (!response.writableFinished) void saveOnce({ ...decision, action: "error", reason: "响应传输中断" }, 499);
  });
  request.setTimeout(15000, () => {
    decision = inspectionFailure(settings.mode, requestId, "请求体读取超时");
    if (!response.headersSent) blockResponse(response, 408, decision.reason, requestId);
    void saveOnce(decision, 408);
    request.destroy();
  });
  try {
    validateRequestFraming(request);
    splitRequestTarget(wafRequest);
    const access = accessDecision(store, wafRequest, settings.mode, requestId);
    if (access.decision) { decision = access.decision; request.resume(); blockResponse(response, 403, decision.reason, requestId); return; }
    const activeBan = runtimeBan(store, site?.id ?? "default", wafRequest.ip);
    if (activeBan && !isWhitelisted(store, wafRequest.ip)) {
      decision = { action: "block", mode: settings.mode, requestId, matchedRules: [], reason: "来源 IP 暂时封禁", module: "async-ai", localInspectionComplete: true };
      request.resume(); response.setHeader("retry-after", activeBan); blockResponse(response, 403, decision.reason, requestId); return;
    }
    const admission = control(store).enter(site?.id ?? "default", wafRequest.ip ?? "unknown", wafRequest.path, policy);
    release = admission.release;
    if (!admission.allowed) {
      decision = { action: "block", mode: settings.mode, requestId, matchedRules: [], reason: admission.reason ?? "限速", module: "cc", localInspectionComplete: false };
      request.resume(); response.setHeader("retry-after", admission.retryAfter ?? 1);
      blockResponse(response, 429, decision.reason, requestId); return;
    }
    if (site?.operationMode === "maintenance") {
      decision = { action: "allow", mode: settings.mode, requestId, matchedRules: [], reason: "维护模式", module: "maintenance", localInspectionComplete: true };
      request.resume();
      pageResponse(store, response, site.maintenance, 503, "站点维护中", requestId);
      await saveOnce(decision, site.maintenance?.statusCode ?? 503);
      return;
    }
    const roomAdmission = site ? await waitRoom(store, site).enter() : { allowed: true, queued: false, release: () => {} };
    if (!roomAdmission.allowed) {
      decision = { action: "block", mode: settings.mode, requestId, matchedRules: [], reason: roomAdmission.reason ?? "等候室拒绝", module: "wait-room", localInspectionComplete: false };
      request.resume(); response.setHeader("retry-after", roomAdmission.retryAfter ?? 1);
      blockResponse(response, 429, decision.reason, requestId); return;
    }
    const roomRelease = roomAdmission.release;
    const previousRelease = release;
    release = () => { previousRelease(); roomRelease(); };
    const body = await readBody(request);
    request.setTimeout(0);
    if (response.destroyed) return;
    wafRequest.body = body.body;
    if (body.fields) wafRequest.bodyFields = body.fields;
    if (body.error) decision = inspectionFailure(settings.mode, requestId, body.error);
    else {
      const result = await inspectRequest(store, wafRequest, resolved, requestId, access.skip);
      decision = result.decision;
      shadow = result.shadow;
    }
    decision.partialInspection = body.partial || Boolean(decision.partialInspection);
    if (response.destroyed) return;
    if (decision.action !== "allow" && site?.operationMode !== "record") {
      const status = decision.action === "block" ? 403 : body.error ? body.error.includes("超过") ? 413 : 400 : decision.partialInspection ? 413 : 503;
      blockResponse(response, status, decision.reason, requestId);
      await saveOnce(decision, status);
      return;
    }
    if (decision.action !== "allow" && site?.operationMode === "record") decision = { ...decision, action: "allow", wouldBlock: true, reason: `记录模式：${decision.reason}` };
    scheduleAsyncAudit(store, wafRequest, resolved, decision, requestId);
    forwardHeaders(request, wafRequest);
    response.setHeader("x-jev-request-id", requestId);
    responseFailures.set(request, (reason) => {
      decision = { ...decision, action: "error", reason };
      void saveOnce(decision, 502);
      response.destroy();
    });
    const stream = new PassThrough();
    stream.end(body.forwardBody);
    proxy.web(request, response, { target: settings.upstreamUrl, buffer: stream }, () => {
      decision = { ...decision, action: "error", reason: "上游连接失败" };
      if (!response.headersSent) pageResponse(store, response, site?.upstreamError, 502, "上游暂不可用", requestId);
      else response.destroy();
      void saveOnce(decision, 502);
    });
  } catch (error) {
    decision = inspectionFailure(settings.mode, requestId, error instanceof Error ? error.message : "检测异常");
    if (!response.headersSent && !response.destroyed) blockResponse(response, 400, decision.reason, requestId);
    else response.destroy();
    await saveOnce(decision, 400);
  }
}

async function handleUpgrade(store: Store, request: http.IncomingMessage, socket: Duplex, head: Buffer, listenPort?: number): Promise<void> {
  const requestId = randomUUID();
  const resolved = settingsForPort(store, listenPort);
  if (!resolved) { upgradeBlock(socket, 503, requestId); return; }
  const { settings, policy, site } = resolved;
  const wafRequest = requestOf(request);
  if (site) wafRequest.siteId = site.id;
  let shadow: Promise<Partial<WafDecision>> | undefined;
  const saveOnce = eventSaver(store, wafRequest, site, () => shadow);
  let release = () => {};
  let decision = inspectionFailure(settings.mode, requestId, "WebSocket 握手尚未完成");
  let upgraded = false;
  socket.once("close", () => {
    release();
    if (!upgraded) void saveOnce({ ...decision, action: "error", reason: "WebSocket 握手中断" }, 499);
  });
  try {
    splitRequestTarget(wafRequest);
    if (wafRequest.method !== "GET" || request.headers.upgrade?.toLowerCase() !== "websocket"
      || request.headers["transfer-encoding"] || Number(request.headers["content-length"] ?? 0) !== 0) {
      throw new Error("WebSocket 握手格式无效");
    }
    validateRequestFraming(request);
    const access = accessDecision(store, wafRequest, settings.mode, requestId);
    if (access.decision) { decision = access.decision; await saveOnce(decision, 403); upgradeBlock(socket, 403, requestId); return; }
    const activeBan = runtimeBan(store, site?.id ?? "default", wafRequest.ip);
    if (activeBan && !isWhitelisted(store, wafRequest.ip)) { decision = { action: "block", mode: settings.mode, requestId, matchedRules: [], reason: "来源 IP 暂时封禁", module: "async-ai" }; await saveOnce(decision, 403); upgradeBlock(socket, 403, requestId, activeBan); return; }
    const admission = control(store).enter(site?.id ?? "default", wafRequest.ip ?? "unknown", wafRequest.path, policy);
    release = admission.release;
    if (!admission.allowed) {
      decision = { action: "block", mode: settings.mode, requestId, matchedRules: [], reason: admission.reason ?? "限速", module: "cc" };
      await saveOnce(decision, 429); upgradeBlock(socket, 429, requestId, admission.retryAfter ?? 1); return;
    }
    const result = await inspectRequest(store, wafRequest, resolved, requestId, access.skip);
    decision = result.decision;
    shadow = result.shadow;
    if (socket.destroyed) return;
    if (decision.action !== "allow") {
      const status = decision.action === "block" ? 403 : 503;
      await saveOnce(decision, status);
      upgradeBlock(socket, status, requestId);
      return;
    }
    scheduleAsyncAudit(store, wafRequest, resolved, decision, requestId);
    forwardHeaders(request, wafRequest);
    const target = new URL(settings.upstreamUrl);
    const transport = target.protocol === "https:" ? https : http;
    const path = `${target.pathname.replace(/\/$/, "")}${request.url}`;
    const outgoing = transport.request(target, { method: "GET", path, headers: { ...request.headers, host: target.host } });
    const fail = (): void => {
      decision = { ...decision, action: "error", reason: "WebSocket 上游连接失败" };
      void saveOnce(decision, 502);
      if (!socket.destroyed) upgradeBlock(socket, 502, requestId);
    };
    outgoing.on("error", fail);
    outgoing.setTimeout(30000, () => outgoing.destroy(new Error("upstream timeout")));
    socket.once("close", () => { if (!upgraded) outgoing.destroy(); });
    outgoing.on("response", (upstream) => {
      decision = { ...decision, action: "error", reason: `上游拒绝 WebSocket 握手: HTTP ${upstream.statusCode}` };
      void saveOnce(decision, upstream.statusCode ?? 502);
      // The incoming stream is already de-chunked, so delimit a rejected response by connection close.
      const headers = { ...upstream.headers, connection: "close", "x-jev-request-id": requestId };
      delete headers["transfer-encoding"];
      socket.write(`HTTP/1.1 ${upstream.statusCode ?? 502} ${upstream.statusMessage ?? "Rejected"}\r\n`
        + Object.entries(headers).flatMap(([key, value]) => (Array.isArray(value) ? value : [value])
          .filter((item) => item !== undefined).map((item) => `${key}: ${item}`)).join("\r\n") + "\r\n\r\n");
      upstream.on("error", () => socket.destroy());
      upstream.pipe(socket);
    });
    outgoing.on("upgrade", (upstream, upstreamSocket, upstreamHead) => {
      upgraded = true;
      outgoing.setTimeout(0);
      void saveOnce(decision, 101);
      socket.write("HTTP/1.1 101 Switching Protocols\r\n"
        + Object.entries({ ...upstream.headers, "x-jev-request-id": requestId })
          .flatMap(([key, value]) => (Array.isArray(value) ? value : [value])
            .filter((item) => item !== undefined).map((item) => `${key}: ${item}`)).join("\r\n") + "\r\n\r\n");
      if (upstreamHead.length) socket.write(upstreamHead);
      if (head.length) upstreamSocket.write(head);
      upstreamSocket.on("error", () => socket.destroy());
      socket.on("error", () => upstreamSocket.destroy());
      socket.once("close", () => upstreamSocket.destroy());
      upstreamSocket.pipe(socket).pipe(upstreamSocket);
    });
    outgoing.end();
  } catch (error) {
    decision = inspectionFailure(settings.mode, requestId, error instanceof Error ? error.message : "WebSocket 检测异常");
    await saveOnce(decision, 400);
    upgradeBlock(socket, 400, requestId);
  }
}

function attachUpgradeHandler(server: http.Server | https.Server, store: Store, listenPort?: number): void {
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  server.on("upgrade", (request, socket, head) => {
    void handleUpgrade(store, request, socket, head, listenPort).catch(() => socket.destroy());
  });
}

export function createProxyServer(store: Store, listenPort?: number): http.Server {
  const server = http.createServer((request, response) => {
    void handleProxyRequest(store, request, response, listenPort).catch(() => response.destroy());
  });
  attachUpgradeHandler(server, store, listenPort);
  return server;
}

export function createHttpsProxyServer(store: Store, keyPath: string, certPath: string, listenPort?: number): https.Server | null {
  try {
    const server = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (request, response) => {
      void handleProxyRequest(store, request, response, listenPort).catch(() => response.destroy());
    });
    attachUpgradeHandler(server, store, listenPort);
    return server;
  } catch {
    return null;
  }
}
