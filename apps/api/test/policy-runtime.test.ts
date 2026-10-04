import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import http from "node:http";
import https from "node:https";
import { mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";
import { defaultPolicy } from "@jev-waf/core";
import { config } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { createApp } from "../src/app.js";
import { ProxyListenerManager } from "../src/proxy-manager.js";
import { classifyWithJev, aiRuntime } from "../src/jev.js";
import { TrafficControl } from "../src/traffic-control.js";

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return (server.address() as { port: number }).port;
}
function configureLocal() {
  config.databaseUrl = ""; config.adminPassword = ""; config.environmentApiKey = ""; config.openRouterKey = "";
  config.dataDir = resolve("../../../verification", `policy-${randomUUID()}`);
  mkdirSync(config.dataDir, { recursive: true });
}

test("policy inheritance, scoped CRUD, sample replay, privacy and retention persist in SQLite", async (t) => {
  configureLocal();
  const store = new Store(); await store.init();
  const app = await createApp(store, false);
  t.after(async () => { await app.close(); await store.close(); });
  await store.completeSetup("Policy-review-2026!");
  const login = await app.inject({ method: "POST", url: "/api/v1/auth/login", payload: { username: "admin", password: "Policy-review-2026!" } });
  const headers = { cookie: String(login.headers["set-cookie"]).split(";", 1)[0]! };
  const policy = { ...defaultPolicy(), enforcement: "observe" as const, customThreshold: 0.37, strength: "custom" as const };
  await store.updateSettings({ defaultPolicy: policy });
  const site = await store.saveSite({ name: "Editor", listenPort: 8081, upstreamUrl: "http://127.0.0.1:9101", mode: "traditional", enabled: true });
  assert.equal(store.effectivePolicy(site).customThreshold, 0.37);
  const exception = { name: "Templates", method: "POST", path: "/editor", target: "body", selector: "template",
    ruleIds: ["JIANFLOW-ENC-001", "JIANFLOW-SSTI-BODY"], reason: "Template editor", expiresAt: "2099-01-01T00:00:00Z", enabled: true };
  const base = `/api/v1/sites/${site.id}`;
  for (const invalid of [{ ...exception, method: "bad*" }, { ...exception, path: "*" }, { ...exception, selector: "__proto__.x" }, { ...exception, ruleIds: ["missing"] }]) {
    assert.equal((await app.inject({ method: "POST", url: `${base}/exceptions`, headers, payload: invalid })).statusCode, 422);
  }
  const created = await app.inject({ method: "POST", url: `${base}/exceptions`, headers, payload: exception });
  assert.equal(created.statusCode, 201);
  const preview = await app.inject({ method: "POST", url: `${base}/exception-previews`, headers, payload: {
    method: "POST", path: "/editor", headers: { "content-type": "application/json" }, body: JSON.stringify({ template: "{{ name }}" })
  } });
  assert.ok(preview.json().before.length > 0); assert.equal(preview.json().after.length, 0);
  const access = await app.inject({ method: "POST", url: `${base}/access-rules`, headers, payload: { name: "Local", method: "*", path: "*", cidr: "127.0.0.0/8", action: "skip-detection", expiresAt: "2099-01-01T00:00:00Z", enabled: true } });
  assert.equal(access.statusCode, 201);
  assert.equal((await app.inject({ method: "PATCH", url: `${base}/exceptions/${created.json().id}`, headers, payload: { enabled: false } })).statusCode, 200);
  assert.equal((await app.inject({ method: "PATCH", url: `${base}/exceptions/${created.json().id}`, headers, payload: { enabled: true } })).statusCode, 200);
  assert.equal((await app.inject({ url: `${base}/exceptions?limit=101`, headers })).statusCode, 422);
  await store.saveEvent({ requestId: "secret-url", action: "allow", mode: "traditional", matchedRules: [], reason: "test", localInspectionComplete: true },
    { method: "GET", path: "/session/SENTINEL?%2574oken=SENTINEL", siteId: site.id, listenPort: 8081, policyRevision: 7 }, 200);
  const page = await store.listEvents({ siteId: site.id });
  assert.equal(page.data.length, 1); assert.doesNotMatch(JSON.stringify(page), /SENTINEL/);
  assert.equal(page.data[0]!.policyRevision, 7);
  const restarted = new Store(); await restarted.init();
  assert.equal(restarted.effectivePolicy(restarted.listSites().find((entry) => entry.id === site.id)!).customThreshold, 0.37);
  assert.equal(restarted.listScopedRules(site.id, "exceptions").length, 1);
  assert.equal(await restarted.pruneEvents("2099-01-01T00:00:00Z"), 1);
  assert.equal((await restarted.listEvents()).data.length, 0);
  assert.equal((await restarted.summary()).total, 1);
  await restarted.close();
  assert.equal((await app.inject({ method: "DELETE", url: `${base}/exceptions/${created.json().id}`, headers })).statusCode, 200);
  await store.deleteSite(site.id);
  assert.equal(store.listScopedRules(site.id, "access-rules").length, 0);
});

test("token buckets enforce burst, critical paths, concurrency, temporary bans and bounded keys", () => {
  const original = config.maxTrackedClients;
  config.maxTrackedClients = 3;
  const control = new TrafficControl();
  const policy = defaultPolicy();
  policy.rateLimit = { enabled: true, requestsPerSecond: 1, burst: 2, maxConcurrent: 1, blockSeconds: 2,
    paths: [{ path: "/login", requestsPerSecond: 0.1, burst: 1 }] };
  const first = control.enter("a", "one", "/", policy, 10000);
  assert.ok(first.allowed);
  assert.equal(control.enter("a", "one", "/", policy, 10000).reason, "client_concurrency");
  first.release(); first.release(); assert.equal(control.snapshot().concurrent, 0);
  assert.equal(control.enter("a", "one", "/", policy, 11000).reason, "temporary_ban");
  const recovered = control.enter("a", "one", "/login", policy, 13000); assert.ok(recovered.allowed); recovered.release();
  assert.equal(control.enter("a", "one", "/login", policy, 13000).reason, "request_rate");
  const second = control.enter("b", "one", "/", policy, 13000); assert.ok(second.allowed); second.release();
  assert.equal(control.enter("a", "other", "/", policy, 13000).reason, "tracked_client_limit");
  assert.ok(control.snapshot().trackedClients <= 3);
  const clean = control.enter("a", "other", "/", policy, 300000); assert.ok(clean.allowed); clean.release();
  config.maxTrackedClients = original;
});

test("shutdown drains bounded shadow event writes and retention keeps historical totals", async () => {
  configureLocal();
  const store = new Store(); await store.init();
  const previous = config.eventQueueLimit; config.eventQueueLimit = 2;
  let complete!: (value: Partial<import("@jev-waf/core").WafDecision>) => void;
  const shadow = new Promise<Partial<import("@jev-waf/core").WafDecision>>((resolve) => { complete = resolve; });
  const decision = { requestId: "shadow-one", action: "allow" as const, mode: "hybrid" as const, matchedRules: [], reason: "local" };
  const request = { method: "GET", path: "/", siteId: "default" };
  const writes = [store.saveEvent(decision, request, 200, shadow), store.saveEvent({ ...decision, requestId: "shadow-two" }, request, 200, shadow)];
  await store.saveEvent({ ...decision, requestId: "dropped" }, request, 200, shadow);
  assert.equal(store.eventRuntime().queueDepth, 2); assert.equal(store.eventRuntime().droppedEvents, 1);
  let closed = false; const closing = store.close().then(() => { closed = true; });
  await new Promise((resolve) => setTimeout(resolve, 10)); assert.equal(closed, false);
  complete({ aiInspectionComplete: true, ai: { model: "test", available: true, noul: 0.9, latencyMs: 10 } });
  await Promise.all(writes); await closing;
  const restarted = new Store(); await restarted.init();
  try {
    assert.equal((await restarted.summary()).total, 2);
    const events = await restarted.listEvents(); assert.equal(events.data[0]!.score, undefined);
    assert.equal(events.data[0]!.ai!.noul, 0.9); assert.equal(events.data[0]!.action, "allow");
  } finally { await restarted.close(); config.eventQueueLimit = previous; }
});

test("HTTP and HTTPS stop together; occupied ports report errors and recover on retry", { timeout: 15000 }, async (t) => {
  configureLocal();
  const previous = { proxyHost: config.proxyHost, proxyPort: config.proxyPort, sitePortRange: config.sitePortRange, tlsKeyPath: config.tlsKeyPath, tlsCertPath: config.tlsCertPath, httpsPort: config.httpsPort };
  config.proxyHost = "127.0.0.1";
  const reservation = http.createServer(); config.proxyPort = await listen(reservation); await new Promise<void>((resolve) => reservation.close(() => resolve()));
  config.sitePortRange = { min: 1024, max: 65535 };
  const tlsReservation = http.createServer(); config.httpsPort = await listen(tlsReservation); await new Promise<void>((resolve) => tlsReservation.close(() => resolve()));
  const openssl = existsSync("C:/Program Files/Git/usr/bin/openssl.exe") ? "C:/Program Files/Git/usr/bin/openssl.exe" : "openssl";
  config.tlsKeyPath = resolve(config.dataDir, "test.key"); config.tlsCertPath = resolve(config.dataDir, "test.crt");
  if (process.env.TEST_TLS_KEY_PATH && process.env.TEST_TLS_CERT_PATH) {
    config.tlsKeyPath = process.env.TEST_TLS_KEY_PATH; config.tlsCertPath = process.env.TEST_TLS_CERT_PATH;
  } else execFileSync(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", config.tlsKeyPath, "-out", config.tlsCertPath, "-subj", "/CN=localhost", "-days", "1"], { stdio: "ignore" });
  let reached = 0;
  const upstream = http.createServer((_request, response) => { reached++; response.end("upstream"); });
  const upstreamPort = await listen(upstream);
  const store = new Store(); await store.init();
  const manager = new ProxyListenerManager(store); store.setSiteChangeListener(() => manager.sync());
  t.after(async () => { await manager.close(); await store.close(); upstream.closeAllConnections(); upstream.close(); Object.assign(config, previous); });
  let site = await store.saveSite({ ...store.listSites()[0]!, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, enabled: true });
  assert.equal(site.runtime!.state, "active"); assert.ok(store.readiness());
  const tlsRequest = () => new Promise<number>((resolve, reject) => {
    const request = https.get({ host: "127.0.0.1", port: config.httpsPort, rejectUnauthorized: false }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode!)); }); request.on("error", reject);
  });
  assert.equal(await tlsRequest(), 200);
  site = await store.saveSite({ ...site, enabled: false });
  await assert.rejects(tlsRequest()); assert.equal(reached, 1);
  const occupied = http.createServer(); const port = await listen(occupied);
  t.after(() => { occupied.closeAllConnections(); occupied.close(); });
  const failed = await store.saveSite({ name: "Occupied", listenPort: port, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, mode: "traditional", enabled: true });
  assert.equal(failed.runtime!.state, "error"); assert.match(failed.runtime!.lastError!, /EADDRINUSE/); assert.equal(store.readiness(), false);
  await new Promise<void>((resolve) => occupied.close(() => resolve())); await manager.sync();
  assert.equal(store.listSites().find((entry) => entry.id === failed.id)!.runtime!.state, "active"); assert.ok(store.readiness());
  await store.saveSite({ ...failed, policy: { ...defaultPolicy(), rateLimit: { ...defaultPolicy().rateLimit, enabled: true, requestsPerSecond: 0.1, burst: 1 } } });
  assert.equal((await fetch(`http://127.0.0.1:${port}/`)).status, 200);
  const rejectedUpgrade = await new Promise<{ status: number; retryAfter: string | undefined }>((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, headers: { connection: "Upgrade", upgrade: "websocket", "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==", "sec-websocket-version": "13" } }, (response) => {
      response.resume(); response.on("end", () => resolve({ status: response.statusCode!, retryAfter: response.headers["retry-after"] }));
    }); request.on("error", reject);
  });
  assert.equal(rejectedUpgrade.status, 429); assert.equal(rejectedUpgrade.retryAfter, "10");
  await store.saveSite({ ...failed, policy: null });
  const reachedBeforeAcl = reached;
  await store.saveScopedRule(failed.id, "access-rules", { name: "Mandatory block", method: "*", path: "*", cidr: "127.0.0.0/8", action: "block", expiresAt: "2099-01-01T00:00:00Z", enabled: true });
  await store.updateSettings({ apiKey: "synthetic", defaultPolicy: { ...defaultPolicy(), enforcement: "observe" } });
  await store.saveSite({ ...failed, mode: "ai", policy: { ...defaultPolicy(), enforcement: "observe" } });
  assert.equal((await fetch(`http://127.0.0.1:${port}/`)).status, 403); assert.equal(reached, reachedBeforeAcl);
  config.tlsKeyPath = "not-a-key";
  await store.saveSite({ ...site, enabled: true });
  assert.equal(store.listSites().find((entry) => entry.id === "default")!.runtime!.state, "error");
  assert.equal((await fetch(`http://127.0.0.1:${port}/`)).status, 403);
});

test("Jev strictly validates responses, bounds admission and opens a circuit only after failures", async (t) => {
  config.openRouterKey = "synthetic-key"; config.jevBaseUrl = "http://provider.local"; config.aiRequestsPerMinute = 10000;
  let response: unknown = 0;
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ answers: { malicious: { noul: response } } })));
  for (const value of [null, "", false, "0.4", -1, 2, {}, undefined]) {
    response = value; const invalid = await classifyWithJev("{}", "test", 100);
    assert.equal(invalid.available, false); assert.equal(invalid.errorCode, "invalid_response");
    response = 0; assert.ok((await classifyWithJev("{}", "test", 100)).available);
  }
  for (const value of [0, 1, 0.3]) { response = value; assert.equal((await classifyWithJev("{}", "test", 100)).noul, value); }
  let complete!: (response: Response) => void;
  t.mock.method(globalThis, "fetch", () => new Promise<Response>((resolve) => { complete = resolve; }));
  const maxConcurrent = config.aiMaxConcurrent; config.aiMaxConcurrent = 1;
  const pending = classifyWithJev("{}", "test", 1000);
  assert.equal((await classifyWithJev("{}", "test", 1000)).errorCode, "concurrency_limit");
  complete(new Response('{"answers":{"malicious":{"noul":0}}}')); await pending;
  config.aiMaxConcurrent = maxConcurrent;
  for (const [mode, expected] of [["429", "provider_429"], ["size", "invalid_response"], ["timeout", "timeout"]]) {
    t.mock.method(globalThis, "fetch", async (_url: unknown, options: RequestInit) => {
      if (mode === "429") return new Response("", { status: 429 });
      if (mode === "size") return new Response("x".repeat(65537));
      return new Promise<Response>((_resolve, reject) => options.signal!.addEventListener("abort", () => reject(new Error("aborted"))));
    });
    assert.equal((await classifyWithJev("{}", "test", 10)).errorCode, expected);
    t.mock.method(globalThis, "fetch", async () => new Response('{"answers":{"malicious":{"noul":0}}}'));
    assert.ok((await classifyWithJev("{}", "test", 100)).available);
  }
  const budget = config.aiRequestsPerMinute; config.aiRequestsPerMinute = 1;
  assert.equal((await classifyWithJev("{}", "test", 100)).errorCode, "budget_exhausted");
  config.aiRequestsPerMinute = budget;
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ answers: { malicious: { noul: response } } })));
  assert.equal(aiRuntime().circuitOpen, false);
  for (let i = 0; i < 5; i++) { response = null; await classifyWithJev("{}", "test", 100); }
  assert.equal(aiRuntime().circuitOpen, true);
  assert.equal((await classifyWithJev("{}", "test", 100)).errorCode, "circuit_open");
});
