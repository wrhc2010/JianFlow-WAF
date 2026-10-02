import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { BUILTIN_RULES, type WafDecision } from "@jev-waf/core";
import { createProxyServer } from "../src/proxy.js";
import { ProxyListenerManager } from "../src/proxy-manager.js";
import type { Store } from "../src/db/store.js";

async function listen(server: http.Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return (server.address() as import("node:net").AddressInfo).port;
}

async function exchange(port: number, path: string, body?: Buffer, headers: Record<string, string> = {}): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path, method: body ? "POST" : "GET", headers }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode!));
    });
    request.on("error", reject);
    if (body) {
      const middle = Math.floor(body.length / 2);
      request.write(body.subarray(0, middle));
      request.end(body.subarray(middle));
    } else request.end();
  });
}

async function rawExchange(port: number, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    let response = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => { response += chunk; });
    socket.on("error", reject);
    socket.on("close", () => resolve(response));
    socket.on("connect", () => socket.end(payload));
  });
}

test("real proxy blocks encoded, chunked and full-body attacks with one final event", { timeout: 15000 }, async (t) => {
  const received: Buffer[] = [];
  const upstream = http.createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    received.push(Buffer.concat(chunks));
    response.writeHead(request.url === "/fail" ? 500 : 200);
    response.end("upstream");
  });
  const upstreamPort = await listen(upstream);
  const events: Array<{ decision: WafDecision; status: number }> = [];
  const settings = {
    mode: "traditional" as const, strength: "medium" as const, customThreshold: 0.5, model: "test",
    aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`
  };
  const store = {
    getSettings: () => settings,
    listRules: () => BUILTIN_RULES,
    saveEvent: async (decision: WafDecision, _request: unknown, status: number) => { events.push({ decision, status }); }
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });

  assert.equal(await exchange(proxyPort, "/safe/../secret"), 403);
  assert.equal(await exchange(proxyPort, "/ok", undefined, { "x-test": "%253Cscript%253Ealert(1)" }), 403);
  assert.equal(await exchange(proxyPort, "/ok", Buffer.from('{"input":"\\u0066ile:\\/\\/\\/etc\\/passwd"}'),
    { "content-type": "application/json" }), 403);
  assert.equal(await exchange(proxyPort, "/ok", Buffer.from("url=union+select+password+from+users"),
    { "content-type": "application/x-www-form-urlencoded" }), 403);
  assert.equal(await exchange(proxyPort, "/ok", Buffer.from(`${"a".repeat(300 * 1024)}file:///etc/passwd`)), 403);
  assert.equal(await exchange(proxyPort, "/ok", Buffer.from("{broken"), { "content-type": "application/json" }), 400);
  assert.equal(await exchange(proxyPort, "/ok", gzipSync(Buffer.alloc(10 * 1024 * 1024 + 1, "a")),
    { "content-encoding": "gzip" }), 413);
  const benign = gzipSync(Buffer.from("normal request"));
  assert.equal(await exchange(proxyPort, "/ok", benign, { "content-encoding": "gzip" }), 200);
  assert.deepEqual(received[0], benign);
  assert.equal(await exchange(proxyPort, "/fail"), 500);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(events.length, 9);
  assert.equal(new Set(events.map((event) => event.decision.requestId)).size, 9);
  assert.equal(events.filter((event) => event.decision.action === "block").length, 5);
  assert.equal(events.filter((event) => event.decision.action === "allow").length, 1);
  assert.equal(events.filter((event) => event.decision.action === "error").length, 3);
});

test("records rejected WebSocket handshakes as errors rather than a premature allow", { timeout: 5000 }, async (t) => {
  const upstream = http.createServer((_request, response) => { response.writeHead(401); response.end("denied"); });
  const upstreamPort = await listen(upstream);
  const events: WafDecision[] = [];
  const store = {
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`
    }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async (decision: WafDecision) => { events.push(decision); }
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });
  assert.equal(await exchange(proxyPort, "/socket", undefined, { connection: "Upgrade", upgrade: "websocket" }), 401);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(events.length, 1);
  assert.equal(events[0]?.action, "error");
});

test("strips client-controlled forwarding and routing headers before proxying", { timeout: 5000 }, async (t) => {
  let upstreamHeaders: http.IncomingHttpHeaders | undefined;
  const upstream = http.createServer((request, response) => {
    upstreamHeaders = request.headers;
    response.end("ok");
  });
  const upstreamPort = await listen(upstream);
  const store = {
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`
    }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });

  assert.equal(await exchange(proxyPort, "/safe", undefined, {
    "x-forwarded-for": "198.51.100.10",
    "x-real-ip": "198.51.100.10",
    forwarded: "for=198.51.100.10;proto=https",
    "x-original-url": "/admin",
    "x-rewrite-url": "/admin",
    "x-http-method-override": "DELETE",
    "x-forwarded-proto": "https"
  }), 200);
  assert.equal(upstreamHeaders?.["x-forwarded-for"], "127.0.0.1");
  assert.equal(upstreamHeaders?.["x-real-ip"], "127.0.0.1");
  assert.equal(upstreamHeaders?.["x-forwarded-proto"], "http");
  for (const header of [
    "forwarded", "x-original-url", "x-rewrite-url", "x-http-method-override",
    "x-forwarded-host", "x-forwarded-port", "x-forwarded-prefix"
  ]) assert.equal(upstreamHeaders?.[header], undefined, header);
});

test("rejects HTTP/0.9 and ambiguous request framing", { timeout: 5000 }, async (t) => {
  const upstream = http.createServer((_request, response) => { response.end("ok"); });
  const upstreamPort = await listen(upstream);
  const store = {
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`
    }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });

  const http09 = await rawExchange(proxyPort, "GET /legacy HTTP/0.9\r\n\r\n");
  assert.match(http09, /^HTTP\/1\.1 400\b/);
  assert.equal(await exchange(proxyPort, "/v1/health#q=union%20select"), 400);
  const conflictingFraming = await rawExchange(proxyPort,
    "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n");
  assert.match(conflictingFraming, /^HTTP\/1\.1 400\b/);
});

test("routes enabled listener ports to their own site upstreams", { timeout: 5000 }, async (t) => {
  const upstreams = [9101, 9102].map((port) => http.createServer((_request, response) => {
    response.writeHead(200, { "x-upstream-port": String(port) });
    response.end(String(port));
  }));
  const upstreamPorts = await Promise.all(upstreams.map((upstream) => listen(upstream)));
  const store = {
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPorts[0]}`
    }),
    getSiteByPort: (port: number) => port === 28081
      ? { id: "one", name: "One", listenPort: 28081, upstreamUrl: `http://127.0.0.1:${upstreamPorts[0]}`, mode: "traditional", enabled: true, createdAt: "" }
      : { id: "two", name: "Two", listenPort: 28082, upstreamUrl: `http://127.0.0.1:${upstreamPorts[1]}`, mode: "traditional", enabled: true, createdAt: "" },
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const first = createProxyServer(store, 28081);
  const second = createProxyServer(store, 28082);
  const [firstPort, secondPort] = await Promise.all([listen(first), listen(second)]);
  t.after(() => {
    first.closeAllConnections();
    second.closeAllConnections();
    first.close();
    second.close();
    for (const upstream of upstreams) upstream.closeAllConnections();
    for (const upstream of upstreams) upstream.close();
  });
  const responseFor = (port: number) => new Promise<string>((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, path: "/" }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve(body));
    });
    request.on("error", reject);
  });
  assert.equal(await responseFor(firstPort!), "9101");
  assert.equal(await responseFor(secondPort!), "9102");
});

test("disabling a listener closes upgraded WebSocket connections without hanging", { timeout: 5000 }, async (t) => {
  const upstreamSockets = new Set<import("node:stream").Duplex>();
  const upstream = http.createServer();
  upstream.on("upgrade", (_request, socket) => {
    upstreamSockets.add(socket);
    socket.on("close", () => upstreamSockets.delete(socket));
    socket.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  });
  const upstreamPort = await listen(upstream);
  const reservation = http.createServer();
  const port = await listen(reservation);
  await new Promise<void>((resolve) => reservation.close(() => resolve()));
  let enabled = true;
  const store = {
    listSites: () => [{ listenPort: port, enabled }],
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`
    }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const manager = new ProxyListenerManager(store);
  let socket: net.Socket | undefined;
  t.after(async () => {
    socket?.destroy();
    for (const connection of upstreamSockets) connection.destroy();
    await manager.close();
    upstream.close();
  });
  await manager.sync();
  socket = net.connect(port, "127.0.0.1");
  socket.on("error", () => {});
  await once(socket, "connect");
  socket.write("GET /socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  assert.match(String((await once(socket, "data"))[0]), /^HTTP\/1\.1 101\b/);
  enabled = false;
  const result = await Promise.race([
    manager.sync().then(() => true),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 500))
  ]);
  assert.equal(result, true, "listener shutdown must not wait for a WebSocket client to disconnect");
});
