import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { BUILTIN_RULES, defaultPolicy, type WafDecision } from "@jev-waf/core";
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

test("enforces malicious IP feeds while whitelist has priority", { timeout: 5000 }, async (t) => {
  const upstream = http.createServer((_request, response) => response.end("ok"));
  const upstreamPort = await listen(upstream);
  const settings = {
    mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
    aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`,
    whitelistCidrs: ["127.0.0.1/32"], maliciousIpCidrs: ["127.0.0.0/8"]
  };
  const events: WafDecision[] = [];
  const store = {
    getSettings: () => settings,
    listRules: () => BUILTIN_RULES,
    saveEvent: async (decision: WafDecision) => { events.push(decision); }
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });
  assert.equal(await exchange(proxyPort, "/allowed"), 200);
  settings.whitelistCidrs = [];
  assert.equal(await exchange(proxyPort, "/blocked"), 403);
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(events.at(-1)?.module, "threat-feed");
});

test("dynamic traffic bans reject later requests", { timeout: 5000 }, async (t) => {
  const upstream = http.createServer((_request, response) => response.end("ok"));
  const upstreamPort = await listen(upstream);
  const store = {
    getSettings: () => ({
      mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test",
      aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`,
      whitelistCidrs: [], maliciousIpCidrs: []
    }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const proxyPort = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });
  assert.equal(await exchange(proxyPort, "/before"), 200);
  // The runtime ban API is deliberately exercised through the same Store-compatible control path.
  const { trafficRuntime } = await import("../src/proxy.js");
  assert.equal(trafficRuntime(store).concurrent, 0);
});

test("async malicious verdict interrupts an active proxied response", { timeout: 10000 }, async (t) => {
  let releaseVerdict!: (response: Response) => void;
  const verdict = new Promise<Response>((resolve) => { releaseVerdict = resolve; });
  let reached = 0;
  let closedUpstream!: () => void;
  const upstreamClosed = new Promise<void>((resolve) => { closedUpstream = resolve; });
  const upstream = http.createServer((_request, response) => {
    reached++;
    response.writeHead(200);
    response.write("started");
    response.once("close", closedUpstream);
  });
  const upstreamPort = await listen(upstream);
  const events: WafDecision[] = [];
  const store = {
    getSettings: () => ({ mode: "hybrid", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, auditMode: "async", asyncBanBaseSeconds: 60, asyncBanIncrementSeconds: 60, asyncBanMaxSeconds: 3600, whitelistCidrs: [], maliciousIpCidrs: [], captcha: { enabled: false, provider: "local" } }),
    listRules: () => BUILTIN_RULES,
    listScopedRules: () => [],
    getSiteByPort: () => ({ id: "async-site", name: "Async", listenPort: 28083, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, mode: "hybrid", enabled: true, createdAt: "", aiProfileId: "profile" }),
    effectivePolicy: () => ({ ...defaultPolicy(), aiScope: "all", aiBehavior: "enforce" }),
    getAiProvider: async () => ({ profile: { model: "test", timeoutMs: 2000 }, provider: { baseUrl: "http://jev.test", apiKey: "secret" } }),
    recordRuntimeBan: () => ({ siteId: "async-site", ip: "127.0.0.1", until: Date.now() + 60000, seconds: 60, count: 1 }),
    saveEvent: async (decision: WafDecision) => { events.push(decision); },
  } as unknown as Store;
  const proxy = createProxyServer(store, 28083);
  const proxyPort = await listen(proxy);
  t.mock.method(globalThis, "fetch", () => verdict);
  t.after(() => { releaseVerdict(new Response()); proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });
  const result = await new Promise<{ status: number; ended: boolean }>((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port: proxyPort, path: "/slow" }, (response) => {
      let ended = false;
      response.once("data", () => {
        assert.equal(reached, 1);
        assert.equal(events.some((event) => event.module === "async-ai"), false);
        releaseVerdict(new Response(JSON.stringify({ answers: { malicious: { noul: 0.99 } } })));
      });
      response.on("end", () => { ended = true; resolve({ status: response.statusCode!, ended }); });
      response.on("close", () => { if (!ended) resolve({ status: response.statusCode!, ended }); });
    });
    request.on("error", reject);
  });
  assert.equal(result.status, 200);
  assert.equal(result.ended, false);
  await upstreamClosed;
  assert.ok(events.some((event) => event.module === "async-ai"));
});

test("upstream pools honor weights above 100 without capping the ratio", { timeout: 10000 }, async (t) => {
  const counts = [0, 0];
  const upstreams = counts.map((_, index) => http.createServer((_request, response) => { counts[index]++; response.end("ok"); }));
  const ports = await Promise.all(upstreams.map(listen));
  const store = {
    getSettings: () => ({ mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${ports[0]}` }),
    getSiteByPort: () => ({ id: "pool", name: "Pool", enabled: true, mode: "traditional", listenPort: 8080, upstreamUrl: `http://127.0.0.1:${ports[0]}`, upstreamPool: ports.map((port, index) => ({ url: `http://127.0.0.1:${port}`, weight: index === 0 ? 1000 : 10 })) }),
    listRules: () => [], saveEvent: async () => {},
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const port = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); for (const upstream of upstreams) { upstream.closeAllConnections(); upstream.close(); } });
  for (let index = 0; index < 101; index++) assert.equal(await exchange(port, "/"), 200);
  assert.deepEqual(counts, [100, 1]);
});

test("async audit closes an established WebSocket on both sides", { timeout: 10000 }, async (t) => {
  let releaseVerdict!: (response: Response) => void;
  const verdict = new Promise<Response>((resolve) => { releaseVerdict = resolve; });
  let upstreamSocket: import("node:stream").Duplex | undefined;
  let upstreamEnded = false;
  let upstreamClosed!: () => void;
  const closed = new Promise<void>((resolve) => { upstreamClosed = resolve; });
  const upstream = http.createServer();
  upstream.on("upgrade", (_request, socket) => {
    upstreamSocket = socket;
    socket.once("close", upstreamClosed);
    socket.once("end", () => { upstreamEnded = true; socket.end(); });
    socket.on("error", () => {});
    socket.resume();
    socket.write("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
  });
  const upstreamPort = await listen(upstream);
  let bans = 0;
  const store = {
    getSettings: () => ({ mode: "hybrid", strength: "medium", customThreshold: 0.5, model: "test", aiBodyLimit: 32768, auditMode: "sync", asyncBanBaseSeconds: 60, asyncBanIncrementSeconds: 60, asyncBanMaxSeconds: 3600 }),
    getSiteByPort: () => ({ id: "socket", enabled: true, listenPort: 8080, mode: "hybrid", auditMode: "async", upstreamUrl: `http://127.0.0.1:${upstreamPort}` }),
    effectivePolicy: () => ({ ...defaultPolicy(), aiScope: "all" }),
    listRules: () => [],
    getAiProvider: async () => ({ profile: { model: "test", timeoutMs: 2000 }, provider: { baseUrl: "http://jev.test", apiKey: "secret" } }),
    recordRuntimeBan: async () => { bans++; return { seconds: 60 }; },
    saveEvent: async () => {},
  } as unknown as Store;
  const proxy = createProxyServer(store);
  const port = await listen(proxy);
  let clientSocket: import("node:stream").Duplex | undefined;
  t.after(() => { releaseVerdict(new Response()); clientSocket?.destroy(); upstreamSocket?.destroy(); proxy.closeAllConnections(); proxy.close(); upstream.close(); });
  t.mock.method(globalThis, "fetch", () => verdict);
  await new Promise<void>((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, path: "/socket", headers: { connection: "Upgrade", upgrade: "websocket" } });
    request.on("error", reject);
    request.on("upgrade", (response, socket) => {
      assert.equal(response.statusCode, 101);
      clientSocket = socket;
      socket.on("error", () => {});
      socket.once("close", resolve);
      socket.resume();
      releaseVerdict(new Response('{"answers":{"malicious":{"noul":0.99}}}'));
    });
  });
  await closed;
  assert.equal(upstreamEnded, true);
  assert.equal(bans, 1);
});

for (const scenario of ["record", "late-whitelist"] as const) {
  test(`async ${scenario} records a malicious verdict without interrupting traffic`, { timeout: 10000 }, async (t) => {
    let releaseVerdict!: (response: Response) => void;
    const verdict = new Promise<Response>((resolve) => { releaseVerdict = resolve; });
    let upstreamResponse: http.ServerResponse | undefined;
    const upstream = http.createServer((_request, response) => { upstreamResponse = response; response.write("started"); });
    const upstreamPort = await listen(upstream);
    const settings = { mode: "hybrid", strength: "medium", customThreshold: 0.5, model: "test", aiBodyLimit: 32768, auditMode: "async", whitelistCidrs: [] as string[] };
    let auditSaved!: (decision: WafDecision) => void;
    const audited = new Promise<WafDecision>((resolve) => { auditSaved = resolve; });
    let bans = 0;
    const store = {
      getSettings: () => settings,
      getSiteByPort: () => ({ id: "safe", enabled: true, listenPort: 8080, mode: "hybrid", operationMode: scenario === "record" ? "record" : "defense", upstreamUrl: `http://127.0.0.1:${upstreamPort}` }),
      effectivePolicy: () => ({ ...defaultPolicy(), aiScope: "all" }), listRules: () => [],
      getAiProvider: async () => ({ profile: { model: "test", timeoutMs: 2000 }, provider: { baseUrl: "http://jev.test", apiKey: "secret" } }),
      recordRuntimeBan: async () => { bans++; return { seconds: 60 }; },
      saveEvent: async (decision: WafDecision) => { if (decision.module === "async-ai") auditSaved(decision); },
    } as unknown as Store;
    const proxy = createProxyServer(store); const port = await listen(proxy);
    t.after(() => { releaseVerdict(new Response()); proxy.closeAllConnections(); proxy.close(); upstream.closeAllConnections(); upstream.close(); });
    t.mock.method(globalThis, "fetch", () => verdict);
    const completed = new Promise<number>((resolve, reject) => {
      const request = http.get({ host: "127.0.0.1", port, path: "/" }, (response) => {
        response.once("data", () => {
          if (scenario === "late-whitelist") settings.whitelistCidrs = ["127.0.0.1/32"];
          releaseVerdict(new Response('{"answers":{"malicious":{"noul":0.99}}}'));
        });
        response.on("end", () => resolve(response.statusCode!));
        response.on("error", reject);
      });
      request.on("error", reject);
    });
    const decision = await audited;
    assert.equal(decision.action, "allow"); assert.equal(decision.wouldBlock, true); assert.equal(bans, 0);
    assert.equal(upstreamResponse!.destroyed, false);
    upstreamResponse!.end("done");
    assert.equal(await completed, 200);
  });
}

test("pool failover visits each node once and does not replay POST", { timeout: 10000 }, async (t) => {
  const counts = [0, 0, 0];
  const upstreams = counts.map((_, index) => http.createServer((request, response) => {
    counts[index]++;
    if (index < 2) request.socket.destroy();
    else response.end("ok");
  }));
  const ports = await Promise.all(upstreams.map(listen));
  const createStore = () => ({
    getSettings: () => ({ mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: `http://127.0.0.1:${ports[0]}` }),
    getSiteByPort: () => ({ id: "pool", name: "Pool", enabled: true, mode: "traditional", listenPort: 8080, upstreamUrl: `http://127.0.0.1:${ports[0]}`, upstreamPool: ports.map((port) => ({ url: `http://127.0.0.1:${port}`, weight: 1 })) }),
    listRules: () => [], saveEvent: async () => {},
  } as unknown as Store);
  const proxies = [createProxyServer(createStore()), createProxyServer(createStore())];
  const proxyPorts = await Promise.all(proxies.map(listen));
  t.after(() => { for (const server of [...proxies, ...upstreams]) { server.closeAllConnections(); server.close(); } });
  assert.equal(await exchange(proxyPorts[0]!, "/"), 200);
  assert.deepEqual(counts, [1, 1, 1]);
  assert.equal(await exchange(proxyPorts[1]!, "/", Buffer.from("operation=charge")), 502);
  assert.deepEqual(counts, [2, 1, 1]);
});

test("site redirect returns the configured status and location", { timeout: 5000 }, async (t) => {
  const store = {
    getSettings: () => ({ mode: "traditional", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 32768, upstreamUrl: "http://127.0.0.1:9", whitelistCidrs: [], maliciousIpCidrs: [] }),
    getSiteByPort: () => ({ id: "redirect", name: "Redirect", listenPort: 8081, upstreamUrl: "http://127.0.0.1:9", redirect: { statusCode: 302, location: "https://example.com/login" }, mode: "traditional", enabled: true, createdAt: "" }),
    listRules: () => BUILTIN_RULES,
    saveEvent: async () => {}
  } as unknown as Store;
  const proxy = createProxyServer(store, 8081);
  const port = await listen(proxy);
  t.after(() => { proxy.closeAllConnections(); proxy.close(); });
  const result = await new Promise<{ status: number; location?: string }>((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, path: "/" }, (response) => { response.resume(); response.on("end", () => resolve({ status: response.statusCode!, location: response.headers.location })); });
    request.on("error", reject);
  });
  assert.equal(result.status, 302);
  assert.equal(result.location, "https://example.com/login");
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
