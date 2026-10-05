import assert from "node:assert/strict";
import http from "node:http";
import { once } from "node:events";
import { createHash, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import test, { type TestContext } from "node:test";
import { defaultPolicy } from "@jev-waf/core";
import { config } from "../src/config.js";
import { Store, type Site } from "../src/db/store.js";
import { createProxyServer } from "../src/proxy.js";

async function fixture(t: TestContext) {
  const previous = { ...config };
  config.databaseUrl = "";
  config.dataDir = resolve("../../../verification", `visitor-${randomUUID()}`);
  config.environmentApiKey = ""; config.openRouterKey = ""; config.adminPassword = "";
  const store = new Store(); await store.init();
  const sockets = new Set<import("node:net").Socket>();
  const servers: http.Server[] = [];
  async function listen(server: http.Server) {
    servers.push(server);
    server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    return (server.address() as import("node:net").AddressInfo).port;
  }
  t.after(async () => {
    const closed = [...sockets].filter((socket) => !socket.closed).map((socket) => new Promise<void>((done) => socket.once("close", done)));
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map((server) => new Promise<void>((done) => server.close(() => done()))));
    await Promise.all(closed);
    await new Promise<void>((done) => setImmediate(done));
    await store.close(); Object.assign(config, previous);
  });
  const upstream = http.createServer((request, response) => {
    if (request.url === "/hold") { response.writeHead(200); response.write("active"); }
    else if (request.url === "/failure") { response.writeHead(500); response.end("raw upstream error"); }
    else response.end("upstream");
  });
  upstream.on("upgrade", (_request, socket) => { socket.end("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); });
  const upstreamPort = await listen(upstream);
  let site: Site = await store.saveSite({ name: "Visitor", listenPort: 8081, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, mode: "traditional", enabled: true });
  const port = await listen(createProxyServer(store, 8081));
  return { store, port, async change(patch: Partial<Site>) { site = await store.saveSite({ ...site, ...patch }); return site; } };
}

async function get(port: number, path = "/", headers: Record<string, string> = {}, body?: object) {
  return new Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>((done, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path, method: body ? "POST" : "GET", headers: { ...(body ? { "content-type": "application/json" } : {}), ...headers } }, (response) => {
      let text = ""; response.setEncoding("utf8"); response.on("data", (chunk) => text += chunk);
      response.on("end", () => done({ status: response.statusCode!, body: text, headers: response.headers }));
    });
    request.on("error", reject); request.end(body ? JSON.stringify(body) : undefined);
  });
}

async function upgrade(port: number, path = "/socket") {
  return new Promise<number>((done, reject) => {
    const request = http.get({ host: "127.0.0.1", port, path, headers: { connection: "Upgrade", upgrade: "websocket" } });
    request.on("response", (response) => { response.resume(); response.once("end", () => done(response.statusCode!)); });
    request.on("upgrade", (response, socket) => { socket.destroy(); done(response.statusCode!); });
    request.on("error", reject);
  });
}

test("maintenance and record modes apply to HTTP and WebSocket handshakes", { timeout: 10000 }, async (t) => {
  const { store, port, change } = await fixture(t);
  await change({ operationMode: "maintenance", maintenance: { source: "inline", html: "<h1>Planned maintenance</h1>", statusCode: 503 } });
  const maintenance = await get(port);
  assert.equal(maintenance.status, 503); assert.match(maintenance.body, /Planned maintenance/);
  assert.match(maintenance.headers["content-security-policy"]!, /sandbox/);
  assert.doesNotMatch(maintenance.headers["content-security-policy"]!, /allow-scripts/);
  assert.match(maintenance.headers["content-security-policy"]!, /script-src 'none'/);
  assert.equal(await upgrade(port), 503);
  await change({ operationMode: "record" });
  assert.equal((await get(port, "/?q=union%20select%20password")).status, 200);
  assert.equal(await upgrade(port, "/socket?q=union%20select%20password"), 101);
  await new Promise<void>((done) => setImmediate(done));
  assert.ok((await store.listEvents()).data.filter((event) => event.wouldBlock).length >= 2);
  await change({ operationMode: "defense" });
  assert.equal(await upgrade(port, "/socket?q=union%20select%20password"), 403);
});

test("browser waiting tickets preserve FIFO, isolate custom HTML and honor queue-full status", { timeout: 10000 }, async (t) => {
  const { port, change } = await fixture(t);
  await change({ waitRoom: { enabled: true, maxActive: 1, maxQueue: 1, timeoutSeconds: 3, fullAction: "unavailable", page: { source: "inline", html: "<h1>Custom queue</h1><script>fetch('/api/v1/settings')</script>", statusCode: 429 } } });
  const activeRequest = http.get({ host: "127.0.0.1", port, path: "/hold" });
  const [activeResponse] = await once(activeRequest, "response") as [http.IncomingMessage];
  const queued = await get(port, "/", { accept: "text/html" });
  assert.equal(queued.status, 202);
  assert.match(queued.body, /Custom queue/);
  assert.match(queued.body, /<iframe[^>]+sandbox/);
  assert.match(queued.headers["content-security-policy"]!, /script-src 'nonce-/);
  assert.equal(queued.headers["referrer-policy"], "no-referrer");
  const cookie = queued.headers["set-cookie"]![0]!.split(";")[0]!;
  assert.equal(JSON.parse((await get(port, "/.jianflow/wait/status", { cookie })).body).state, "waiting");
  assert.equal((await get(port, "/", { accept: "text/html", cookie })).status, 202);
  assert.equal((await get(port, "/", { accept: "text/html" })).status, 503);
  activeResponse.destroy(); activeRequest.destroy();
  for (let attempt = 0; attempt < 50; attempt++) {
    if (JSON.parse((await get(port, "/.jianflow/wait/status", { cookie })).body).state === "ready") break;
    await new Promise((done) => setTimeout(done, 10));
  }
  assert.equal((await get(port, "/", { accept: "text/html", cookie })).body, "upstream");
  assert.equal((await get(port, "/.jianflow/wait/status", { cookie })).status, 410);
});

for (const scenario of [
  { name: "trusted HTTPS", trusted: true, proto: "https", secure: true },
  { name: "trusted HTTP", trusted: true, proto: "http", secure: false },
  { name: "forged HTTPS", trusted: false, proto: "https", secure: false },
  { name: "ambiguous protocol", trusted: true, proto: "https,http", secure: false },
]) {
  test(`waiting tickets use Secure only for ${scenario.name}`, { timeout: 10000 }, async (t) => {
    const { port, change } = await fixture(t);
    config.trustedProxyCidrs = scenario.trusted ? ["127.0.0.1/32"] : [];
    await change({ waitRoom: { enabled: true, maxActive: 1, maxQueue: 1, timeoutSeconds: 5 } });
    const active = http.get({ host: "127.0.0.1", port, path: "/hold" });
    active.on("error", () => {});
    const [response] = await once(active, "response") as [http.IncomingMessage];
    try {
      const headers = { accept: "text/html", "x-forwarded-proto": scenario.proto };
      const queued = await get(port, "/", headers);
      assert.equal(queued.status, 202);
      const signedCookie = queued.headers["set-cookie"]![0]!;
      assert.equal(/; Secure(?:;|$)/.test(signedCookie), scenario.secure);
      assert.match(signedCookie, /; HttpOnly;/);
      assert.match(signedCookie, /; SameSite=Lax;/);
      const repeated = await get(port, "/", { ...headers, cookie: signedCookie.split(";")[0]! });
      assert.equal(repeated.status, 202);
      assert.equal(/; Secure(?:;|$)/.test(repeated.headers["set-cookie"]![0]!), scenario.secure);
    } finally { response.destroy(); active.destroy(); }
  });
}

test("visitor PoW verifies once, clears CC bans and strips clearance before forwarding", { timeout: 10000 }, async (t) => {
  const { store, port, change } = await fixture(t);
  await store.updateSettings({ captcha: { enabled: true, provider: "local", siteKey: "", secretConfigured: false, trigger: "cc" } });
  const policy = defaultPolicy(); policy.rateLimit = { ...policy.rateLimit, enabled: true, requestsPerSecond: 1, burst: 1, maxConcurrent: 1, blockSeconds: 60 };
  await change({ policy });
  assert.equal((await get(port)).status, 200);
  const rejected = await get(port);
  assert.equal(rejected.status, 403); assert.match(rejected.body, /访问验证/);
  assert.equal(rejected.headers["referrer-policy"], "no-referrer");
  const challenge = JSON.parse((await get(port, "/.jianflow/captcha/challenge")).body);
  let n = 0;
  while (!createHash("sha256").update(`${challenge.challenge}:${n}`).digest("hex").startsWith("0".repeat(challenge.difficulty))) n++;
  const verified = await get(port, "/.jianflow/captcha/verify", {}, { challenge: challenge.challenge, answer: String(n) });
  assert.equal(verified.status, 200);
  const cookie = verified.headers["set-cookie"]![0]!.split(";")[0]!;
  assert.equal((await get(port, "/", { cookie })).status, 200);
  assert.equal((await get(port, "/.jianflow/captcha/verify", {}, { challenge: challenge.challenge, answer: String(n) })).status, 403);
});

test("WebSocket activity occupies the same waiting-room capacity as HTTP", { timeout: 10000 }, async (t) => {
  const { port, change } = await fixture(t);
  await change({ waitRoom: { enabled: true, maxActive: 1, maxQueue: 0, timeoutSeconds: 1 } });
  const active = http.get({ host: "127.0.0.1", port, path: "/hold" });
  const [response] = await once(active, "response") as [http.IncomingMessage];
  assert.equal(await upgrade(port), 429);
  response.destroy(); active.destroy();
});

test("site captcha switches override the global setting", { timeout: 10000 }, async (t) => {
  const { store, port, change } = await fixture(t);
  await store.updateSettings({ captcha: { enabled: false, provider: "local", siteKey: "", secretConfigured: false } });
  await change({ captchaEnabled: true });
  assert.equal((await get(port)).status, 403);
  assert.equal((await get(port, "/.jianflow/captcha/challenge")).status, 200);
  await change({ captchaEnabled: false });
  await store.updateSettings({ captcha: { ...store.getSettings().captcha, enabled: true } });
  assert.equal((await get(port)).status, 200);
});

test("upstream HTTP failures return the configured static error page", { timeout: 10000 }, async (t) => {
  const { port, change } = await fixture(t);
  await change({ upstreamError: { source: "inline", html: "<h1>Service temporarily unavailable</h1>", statusCode: 502 } });
  const response = await get(port, "/failure");
  assert.equal(response.status, 502);
  assert.match(response.body, /Service temporarily unavailable/);
  assert.doesNotMatch(response.body, /raw upstream error/);
});

for (const protocol of ["http", "websocket"] as const) {
  test(`${protocol}: rule observation does not silently disable CC enforcement`, { timeout: 10000 }, async (t) => {
    const { store, port, change } = await fixture(t);
    const policy = defaultPolicy();
    policy.enforcement = "observe";
    policy.rateLimit = { enabled: true, requestsPerSecond: 0.1, burst: 1, maxConcurrent: 1, blockSeconds: 60, paths: [] };
    await change({ policy });
    const request = () => protocol === "http" ? get(port).then((response) => response.status) : upgrade(port);
    assert.equal(await request(), protocol === "http" ? 200 : 101);
    assert.equal(await request(), 429);
    await new Promise<void>((done) => setImmediate(done));
    assert.ok((await store.listEvents()).data.some((event) => event.module === "cc" && event.action === "block"));
  });
}

test("CC observation records both protocols without disabling content rules or persistent bans", { timeout: 10000 }, async (t) => {
  const { store, port, change } = await fixture(t);
  const policy = defaultPolicy();
  Object.assign(policy.rateLimit, { enabled: true, action: "observe", requestsPerSecond: 0.1, burst: 1, maxConcurrent: 1, blockSeconds: 60 });
  const site = await change({ policy });
  for (let index = 0; index < 3; index++) assert.equal((await get(port)).status, 200);
  assert.equal(await upgrade(port), 101);
  await new Promise<void>((done) => setImmediate(done));
  const events = (await store.listEvents()).data.filter((event) => event.module === "cc" && event.wouldBlock);
  assert.ok(events.some((event) => event.statusCode === 200));
  assert.ok(events.some((event) => event.statusCode === 101));
  assert.equal((await get(port, "/?q=union%20select%20password")).status, 403);
  assert.equal(await upgrade(port, "/socket?q=union%20select%20password"), 403);
  await store.recordRuntimeBan(site.id, "127.0.0.1", 60, 60, 3600);
  assert.equal((await get(port)).status, 403);
  assert.equal(await upgrade(port), 403);
  await store.updateSettings({ whitelistCidrs: ["127.0.0.1"] });
  assert.equal((await get(port)).status, 200);
});
