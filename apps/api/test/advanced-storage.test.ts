import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import http from "node:http";
import { once } from "node:events";
import { DatabaseSync } from "node:sqlite";
import { Pool } from "pg";
import { defaultPolicy } from "@jev-waf/core";
import { config } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { createProxyServer } from "../src/proxy.js";

async function fixture(t: TestContext, database: "sqlite" | "postgres") {
  const previous = { ...config };
  const stores: Store[] = [];
  let admin: Pool | undefined;
  let schema: string | undefined;
  let db: Pool | undefined;
  t.after(async () => {
    for (const store of stores) await store.close();
    await db?.end();
    if (admin && schema) { await admin.query(`DROP SCHEMA ${schema} CASCADE`); await admin.end(); }
    Object.assign(config, previous);
  });
  config.databaseUrl = "";
  config.dataDir = resolve("../../../verification", `advanced-${randomUUID()}`);
  config.environmentApiKey = ""; config.openRouterKey = ""; config.adminPassword = "";
  if (database === "postgres") {
    const url = new URL(process.env.TEST_DATABASE_URL!);
    admin = new Pool({ connectionString: url.toString() });
    schema = `advanced_${randomUUID().replaceAll("-", "")}`;
    await admin.query(`CREATE SCHEMA ${schema}`);
    url.searchParams.set("options", `-c search_path=${schema}`);
    config.databaseUrl = url.toString();
    db = new Pool({ connectionString: config.databaseUrl });
  }
  const open = async () => { const store = new Store(); stores.push(store); await store.init(); return store; };
  const storedKeys = async () => {
    if (db) return (await db.query("SELECT id,api_key_ciphertext FROM ai_profiles")).rows;
    const sqlite = new DatabaseSync(resolve(config.dataDir, "jianflow.sqlite"), { readOnly: true });
    try { return JSON.parse(String(sqlite.prepare("SELECT value FROM state WHERE id=1").get()!.value)).aiProfiles; }
    finally { sqlite.close(); }
  };
  return { store: await open(), open, storedKeys };
}

async function listen(server: http.Server): Promise<number> {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  return (server.address() as import("node:net").AddressInfo).port;
}

async function request(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: "/" }, (response) => { response.resume(); response.on("end", () => resolve(response.statusCode!)); }).on("error", reject);
  });
}

for (const database of ["sqlite", "postgres"] as const) {
  test(`${database} persists upstream pools, site audit modes and escalating ban history`, {
    skip: database === "postgres" && !process.env.TEST_DATABASE_URL,
  }, async (t) => {
    const { store, open } = await fixture(t, database);
    const upstreamPool = [{ url: "http://app-a:9000", weight: 1000 }, { url: "https://app-b:9443/api", weight: 10 }];
    const site = await store.saveSite({ name: "Balanced", listenPort: 8081, upstreamUrl: "http://app-a:9000", upstreamPool, auditMode: "async", captchaEnabled: true, mode: "traditional", enabled: true });
    for (const pool of [
      [{ url: "file:///etc/passwd", weight: 1 }], [{ url: "http://user:pass@example.com", weight: 1 }],
      [{ url: "http://app-a:9000", weight: 0 }], [{ url: "http://app-a:9000", weight: 0.5 }],
      [{ url: "http://app-a:9000", weight: 1001 }], Array(33).fill({ url: "http://app-a:9000", weight: 1 }),
      [{ url: "http://app-a:9000" }, { url: "http://app-a:9000" }],
    ]) await assert.rejects(store.saveSite({ ...site, upstreamPool: pool }));
    assert.deepEqual(store.getSiteByPort(8081)?.upstreamPool, upstreamPool);
    let now = Date.now();
    t.mock.method(Date, "now", () => now);
    assert.equal((await store.recordRuntimeBan(site.id, "203.0.113.10", 2, 3, 6)).seconds, 2);
    now += 3000;
    assert.equal(store.getRuntimeBan(site.id, "203.0.113.10"), undefined);
    assert.equal((await store.recordRuntimeBan(site.id, "203.0.113.10", 2, 3, 6)).seconds, 5);
    const restart = await open();
    assert.deepEqual(restart.getSiteByPort(8081)?.upstreamPool, upstreamPool);
    assert.equal(restart.getSiteByPort(8081)?.auditMode, "async");
    assert.equal(restart.getSiteByPort(8081)?.captchaEnabled, true);
    assert.equal(restart.getRuntimeBan(site.id, "203.0.113.10")?.count, 2);
    assert.equal((await restart.recordRuntimeBan(site.id, "203.0.113.10", 2, 3, 6)).seconds, 6);
    await restart.saveSite({ ...site, upstreamPool: [], auditMode: null });
    const again = await open();
    assert.deepEqual(again.getSiteByPort(8081)?.upstreamPool, []);
    assert.equal(again.getSiteByPort(8081)?.auditMode, null);
    assert.equal(again.getRuntimeBan(site.id, "203.0.113.10")?.count, 3);
    now += 10000;
    const expired = await open();
    assert.equal(expired.getRuntimeBan(site.id, "203.0.113.10"), undefined);
    assert.equal((await expired.recordRuntimeBan(site.id, "203.0.113.10", 2, 3, 6)).count, 4);
  });

  test(`${database} routes each profile to its own model, base URL and encrypted key`, {
    skip: database === "postgres" && !process.env.TEST_DATABASE_URL, timeout: 15000,
  }, async (t) => {
    const { store, open, storedKeys } = await fixture(t, database);
    const calls: Array<{ node: number; model: string; authorization: string | undefined }> = [];
    let failFirst = false;
    const providers = [0, 1].map((node) => http.createServer(async (request, response) => {
      const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      calls.push({ node, model: body.model, authorization: request.headers.authorization });
      response.writeHead(node === 0 && failFirst ? 503 : 200, { "content-type": "application/json" });
      response.end('{"answers":{"malicious":{"noul":0.1}}}');
    }));
    const upstream = http.createServer((_request, response) => response.end("ok"));
    const proxies: http.Server[] = [];
    t.after(() => { for (const server of [...proxies, ...providers, upstream]) { server.closeAllConnections(); server.close(); } });
    const providerPorts = await Promise.all(providers.map(listen)); const upstreamPort = await listen(upstream);
    const first = await store.saveAiProfile({ name: "First", baseUrl: `http://127.0.0.1:${providerPorts[0]}`, model: "first/model", apiKey: "first-secret-not-public", priority: 2, failureAction: "block" });
    const second = await store.saveAiProfile({ name: "Second", baseUrl: `http://127.0.0.1:${providerPorts[1]}`, model: "second/model", apiKey: "second-secret-not-public", priority: 1, failureAction: "allow" });
    assert.equal(store.getSettings().apiKeyConfigured, true);
    assert.equal((await store.getAiProvider())?.profile.id, second.id);
    assert.equal(await store.getAiProvider("missing-profile"), undefined);
    const firstSite = await store.saveSite({ name: "First", listenPort: 8081, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, mode: "ai", aiProfileId: first.id, enabled: true, policy: { ...defaultPolicy(), aiScope: "all" } });
    const secondSite = await store.saveSite({ name: "Second", listenPort: 8082, upstreamUrl: `http://127.0.0.1:${upstreamPort}`, mode: "ai", aiProfileId: second.id, enabled: true });
    assert.equal(firstSite.mode, "ai"); assert.equal(secondSite.mode, "ai");
    proxies.push(createProxyServer(store, 8081), createProxyServer(store, 8082));
    const ports = await Promise.all(proxies.map(listen));
    assert.equal(await request(ports[0]!), 200); assert.equal(await request(ports[1]!), 200);
    assert.deepEqual(calls, [
      { node: 0, model: "first/model", authorization: "Bearer first-secret-not-public" },
      { node: 1, model: "second/model", authorization: "Bearer second-secret-not-public" },
    ]);
    assert.doesNotMatch(JSON.stringify(await store.listAiProfiles()), /first-secret|second-secret|ciphertext/);
    assert.doesNotMatch(JSON.stringify(await storedKeys()), /first-secret-not-public|second-secret-not-public/);
    failFirst = true;
    assert.equal(await request(ports[0]!), 503);
    assert.equal(await request(ports[1]!), 200);
    await store.saveAiProfile({ ...first, enabled: false });
    assert.equal(await store.getAiProvider(first.id), undefined);
    assert.equal(store.getSiteByPort(8081)?.mode, "traditional");
    await assert.rejects(store.deleteAiProfile(second.id), /请先修改/);
    await store.saveAiProfile({ ...second, apiKey: null });
    assert.equal(store.getSettings().apiKeyConfigured, false);
    assert.equal(store.getSiteByPort(8082)?.mode, "traditional");
    const restart = await open();
    assert.equal(await restart.getAiProvider(second.id), undefined);
    assert.equal((await restart.listAiProfiles()).find((entry) => entry.id === second.id)?.apiKeyConfigured, false);
    await restart.saveAiProfile({ ...first, enabled: true });
    assert.equal((await restart.getAiProvider(first.id))?.provider.apiKey, "first-secret-not-public");
    assert.equal(restart.getSettings().apiKeyConfigured, true);
    await restart.saveSite({ ...firstSite, aiProfileId: null });
    assert.equal(restart.getSiteByPort(8081)?.aiProfileId, null);
  });

  test(`${database} encrypts captcha secrets and imports sites atomically`, {
    skip: database === "postgres" && !process.env.TEST_DATABASE_URL,
  }, async (t) => {
    const { store, open } = await fixture(t, database);
    await store.updateSettings({ captcha: { enabled: true, provider: "turnstile", siteKey: "public-site-key", secretConfigured: false, secret: "private-captcha-secret" } });
    assert.doesNotMatch(JSON.stringify(store.getSettings()), /private-captcha-secret|ciphertext/);
    const restart = await open();
    assert.equal(restart.getCaptchaSecret(), "private-captcha-secret");
    assert.equal(restart.getSettings().captcha.secretConfigured, true);
    const before = restart.listSites().length;
    const entry = { name: "Imported", listenPort: 8081, upstreamUrl: "http://app:9000", mode: "traditional" as const, enabled: true };
    await assert.rejects(restart.importSites([entry, { ...entry, name: "Conflict", listenPort: 8080 }]));
    assert.equal(restart.listSites().length, before);
    const imported = await restart.importSites([entry, { ...entry, name: "Second", listenPort: 8082 }]);
    assert.equal(imported.length, 2);
    await restart.importSites([{ ...entry, listenPort: 8083 }], "a".repeat(64));
    const record = restart.listNginxImports()[0]!;
    assert.equal(record.digest, "a".repeat(64));
    assert.deepEqual(record.ports, [8083]);
    await restart.updateSettings({ captcha: { ...restart.getSettings().captcha, enabled: false, secret: null } });
    const again = await open();
    assert.equal(again.getCaptchaSecret(), "");
    assert.equal(again.getSettings().captcha.secretConfigured, false);
    assert.equal(again.listSites().length, before + 3);
    assert.deepEqual(again.listNginxImports(), [record]);
    await again.importSites([{ ...entry, listenPort: 8084 }], "b".repeat(64));
    const expectedHistory = again.listNginxImports();
    const final = await open();
    assert.deepEqual(final.listNginxImports(), expectedHistory);
  });
}
