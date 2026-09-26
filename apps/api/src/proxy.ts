import http from "node:http";
import https from "node:https";
import { readFileSync } from "node:fs";
import { PassThrough, type Duplex } from "node:stream";
import { randomUUID } from "node:crypto";
import httpProxy from "http-proxy";
import { evaluateRequest, type WafRequest } from "@jev-waf/core";
import { config } from "./config.js";
import { classifyWithJev } from "./jev.js";
import { Store } from "./db/store.js";

const proxy = httpProxy.createProxyServer({ changeOrigin: true, ws: true, xfwd: true });
const bodyLimit = 256 * 1024;

function headersOf(request: http.IncomingHttpHeaders): Record<string, string> {
  return Object.fromEntries(
    Object.entries(request)
      .filter(([, value]) => typeof value === "string")
      .map(([key, value]) => [key, value as string])
  );
}

async function readBody(request: http.IncomingMessage): Promise<{ body: string; partial: boolean }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size <= bodyLimit) {
      chunks.push(buffer);
    }
  }
  return { body: Buffer.concat(chunks).toString("utf8"), partial: size > bodyLimit };
}

function blockResponse(response: http.ServerResponse, status: number, decisionReason: string, requestId: string): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "x-jev-request-id": requestId
  });
  response.end(JSON.stringify({
    error: status === 503 ? "ai_unavailable" : "request_blocked",
    message: status === 503 ? "AI 防护服务暂时不可用" : "请求已被 WAF 拦截",
    reason: decisionReason,
    requestId
  }));
}

function upgradeBlock(socket: Duplex, status: number, requestId: string): void {
  socket.write(`HTTP/1.1 ${status} WAF Blocked\r\nConnection: close\r\nX-Jev-Request-Id: ${requestId}\r\n\r\n`);
  socket.destroy();
}

function attachUpgradeHandler(server: http.Server | https.Server, store: Store): void {
  server.on("upgrade", (request, socket, head) => {
    void (async () => {
      const requestId = randomUUID();
      const settings = store.getSettings();
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
      const wafRequest: WafRequest = {
        method: request.method ?? "GET",
        path: url.pathname,
        query: url.search,
        headers: headersOf(request.headers),
        body: "",
        isWebSocketUpgrade: true
      };
      if (request.socket.remoteAddress) {
        wafRequest.ip = request.socket.remoteAddress;
      }
      const decision = await evaluateRequest(wafRequest, store.listRules(), settings, requestId, classifyWithJev);
      if (decision.action === "block" || decision.action === "error") {
        const status = decision.action === "error" ? 503 : 403;
        upgradeBlock(socket, status, requestId);
        await store.saveEvent(decision, { method: wafRequest.method, path: `${wafRequest.path}${wafRequest.query}`, ip: wafRequest.ip }, status);
        return;
      }
      await store.saveEvent(decision, { method: wafRequest.method, path: `${wafRequest.path}${wafRequest.query}`, ip: wafRequest.ip }, 101);
      proxy.ws(request, socket, head, { target: settings.upstreamUrl });
    })().catch(() => socket.destroy());
  });
}

async function handleProxyRequest(store: Store, request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const requestId = randomUUID();
    const settings = store.getSettings();
    const { body, partial } = await readBody(request);
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    const wafRequest: WafRequest = {
      method: request.method ?? "GET",
      path: url.pathname,
      query: url.search,
      headers: headersOf(request.headers),
      body,
      isWebSocketUpgrade: request.headers.upgrade?.toLowerCase() === "websocket"
    };
    if (request.socket.remoteAddress) {
      wafRequest.ip = request.socket.remoteAddress;
    }
    const decision = await evaluateRequest(
      wafRequest,
      store.listRules(),
      settings,
      requestId,
      classifyWithJev
    );
    decision.partialInspection = partial;
    if (decision.action === "block" || decision.action === "error") {
      const status = decision.action === "error" ? 503 : 403;
      blockResponse(response, status, decision.reason, requestId);
      await store.saveEvent(decision, { method: wafRequest.method, path: `${wafRequest.path}${wafRequest.query}`, ip: wafRequest.ip }, status);
      return;
    }
    await store.saveEvent(decision, { method: wafRequest.method, path: `${wafRequest.path}${wafRequest.query}`, ip: wafRequest.ip }, 0);
    const target = settings.upstreamUrl;
    const stream = new PassThrough();
    if (body.length > 0) {
      stream.end(Buffer.from(body));
    } else {
      stream.end();
    }
    proxy.web(request, response, { target, buffer: stream }, (error) => {
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json; charset=utf-8" });
        response.end(JSON.stringify({ error: "upstream_unavailable", message: "上游服务不可用", requestId }));
      }
      void store.saveEvent({
        ...decision,
        action: "error",
        reason: error.message
      }, { method: wafRequest.method, path: `${wafRequest.path}${wafRequest.query}`, ip: wafRequest.ip }, 502);
    });
}

export function createProxyServer(store: Store): http.Server {
  const server = http.createServer((request, response) => {
    void handleProxyRequest(store, request, response);
  });
  attachUpgradeHandler(server, store);
  return server;
}

export function createHttpsProxyServer(store: Store, keyPath: string, certPath: string): https.Server | null {
  try {
    const server = https.createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, (request, response) => {
      void handleProxyRequest(store, request, response);
    });
    attachUpgradeHandler(server, store);
    return server;
  } catch {
    return null;
  }
}
