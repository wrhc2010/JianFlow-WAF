import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { PassThrough, type Duplex } from "node:stream";
import { randomUUID } from "node:crypto";
import { brotliDecompress, gunzip, inflate } from "node:zlib";
import { promisify } from "node:util";
import httpProxy from "http-proxy";
import { evaluateRequest, isIpInCidr, type WafDecision, type WafRequest } from "@jev-waf/core";
import { config } from "./config.js";
import { classifyWithJev } from "./jev.js";
import { Store } from "./db/store.js";
import { inspectBody } from "./body-inspection.js";
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

function upgradeBlock(socket: Duplex, status: number, requestId: string): void {
  socket.end(`HTTP/1.1 ${status} WAF Rejected\r\nConnection: close\r\nContent-Length: 0\r\nX-Jev-Request-Id: ${requestId}\r\n\r\n`);
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

function eventSaver(store: Store, request: WafRequest): (decision: WafDecision, status: number) => Promise<void> {
  let saved = false;
  return async (decision, status) => {
    if (saved) return;
    saved = true;
    try {
      await store.saveEvent(decision, { method: request.method, path: `${request.path}${request.query}`, ip: request.ip }, status);
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

async function handleProxyRequest(store: Store, request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
  const requestId = randomUUID();
  const settings = store.getSettings();
  const wafRequest = requestOf(request);
  const saveOnce = eventSaver(store, wafRequest);
  let decision = inspectionFailure(settings.mode, requestId, "请求尚未完成检查");
  response.once("finish", () => {
    const status = response.statusCode || 502;
    if (status >= 500 && decision.action === "allow") decision = { ...decision, action: "error", reason: `上游返回 HTTP ${status}` };
    void saveOnce(decision, status);
  });
  response.once("close", () => {
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
    const body = await readBody(request);
    request.setTimeout(0);
    if (response.destroyed) return;
    wafRequest.body = body.body;
    if (body.fields) wafRequest.bodyFields = body.fields;
    decision = body.error
      ? inspectionFailure(settings.mode, requestId, body.error)
      : await evaluateRequest(wafRequest, store.listRules(), settings, requestId, classifyWithJev);
    decision.partialInspection = body.partial || Boolean(decision.partialInspection);
    if (response.destroyed) return;
    if (decision.action !== "allow") {
      const status = decision.action === "block" ? 403 : body.error ? body.error.includes("超过") ? 413 : 400 : decision.partialInspection ? 413 : 503;
      blockResponse(response, status, decision.reason, requestId);
      await saveOnce(decision, status);
      return;
    }
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
      if (!response.headersSent) blockResponse(response, 502, decision.reason, requestId);
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

async function handleUpgrade(store: Store, request: http.IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
  const settings = store.getSettings();
  const requestId = randomUUID();
  const wafRequest = requestOf(request);
  const saveOnce = eventSaver(store, wafRequest);
  let decision = inspectionFailure(settings.mode, requestId, "WebSocket 握手尚未完成");
  let upgraded = false;
  socket.once("close", () => {
    if (!upgraded) void saveOnce({ ...decision, action: "error", reason: "WebSocket 握手中断" }, 499);
  });
  try {
    splitRequestTarget(wafRequest);
    if (wafRequest.method !== "GET" || request.headers.upgrade?.toLowerCase() !== "websocket"
      || request.headers["transfer-encoding"] || Number(request.headers["content-length"] ?? 0) !== 0) {
      throw new Error("WebSocket 握手格式无效");
    }
    decision = await evaluateRequest(wafRequest, store.listRules(), settings, requestId, classifyWithJev);
    if (socket.destroyed) return;
    if (decision.action !== "allow") {
      const status = decision.action === "block" ? 403 : 503;
      await saveOnce(decision, status);
      upgradeBlock(socket, status, requestId);
      return;
    }
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

function attachUpgradeHandler(server: http.Server | https.Server, store: Store): void {
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  server.on("upgrade", (request, socket, head) => {
    void handleUpgrade(store, request, socket, head).catch(() => socket.destroy());
  });
}

export function createProxyServer(store: Store): http.Server {
  const server = http.createServer((request, response) => {
    void handleProxyRequest(store, request, response).catch(() => response.destroy());
  });
  attachUpgradeHandler(server, store);
  return server;
}

export function createHttpsProxyServer(store: Store, keyPath: string, certPath: string): https.Server | null {
  try {
    const server = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (request, response) => {
      void handleProxyRequest(store, request, response).catch(() => response.destroy());
    });
    attachUpgradeHandler(server, store);
    return server;
  } catch {
    return null;
  }
}
