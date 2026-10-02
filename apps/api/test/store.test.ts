import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { checkPassword } from "../src/auth.js";
import { config } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { parseRuleImport } from "../src/rule-import.js";
import { evaluateRules } from "@jev-waf/core";

function fixtureDir(): string {
  const directory = resolve("../../../verification", `local-${randomUUID()}`);
  mkdirSync(directory, { recursive: true });
  return directory;
}

test("persists setup, encrypted provider settings and all events without PostgreSQL", async () => {
  config.databaseUrl = "";
  config.dataDir = fixtureDir();
  config.adminPassword = "";
  config.environmentApiKey = "environment-fallback-test";
  const store = new Store();
  await store.init();
  await store.completeSetup("Strong-test-password-2026");
  await store.updateSettings({
    model: "test/provider-model", jevBaseUrl: "http://127.0.0.1:9988/api/v1/decisions",
    apiKey: "database-provider-key-test", mode: "traditional"
  });
  for (let index = 0; index < 320; index += 1) {
    await store.saveEvent({
      action: index % 3 === 0 ? "allow" : index % 3 === 1 ? "block" : "error",
      mode: "traditional", matchedRules: [], reason: "test", requestId: randomUUID()
    }, { method: "GET", path: `/event/${index}`, ip: "8.8.8.8" }, 200);
  }
  const restarted = new Store();
  await restarted.init();
  assert.equal(restarted.setupStatus().initialized, true);
  assert.equal(checkPassword("Strong-test-password-2026"), true);
  assert.equal(restarted.getSettings().model, "test/provider-model");
  assert.equal(config.jevBaseUrl, "http://127.0.0.1:9988");
  assert.equal(config.openRouterKey, "database-provider-key-test");
  assert.equal(restarted.getSettings().apiKeySource, "database");
  const summary = await restarted.summary();
  assert.equal(summary.total, 320);
  assert.equal(summary.total, summary.allowed! + summary.blocked! + summary.errors!);
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const page = await restarted.listEvents({ limit: 37, ...(cursor ? { cursor } : {}) });
    for (const event of page.data) {
      assert.equal(seen.has(String(event.id)), false);
      seen.add(String(event.id));
    }
    cursor = page.nextCursor;
  } while (cursor);
  assert.equal(seen.size, 320);
  await restarted.updateSettings({ apiKey: null });
  assert.equal(config.openRouterKey, "environment-fallback-test");
  assert.equal(restarted.getSettings().apiKeySource, "environment");
});

test("allows only one concurrent first-run setup", async () => {
  config.dataDir = fixtureDir();
  config.adminPassword = "";
  const store = new Store();
  await store.init();
  const result = await Promise.allSettled([
    store.completeSetup("First-admin-password-2026"),
    store.completeSetup("Second-admin-password-2026")
  ]);
  assert.equal(result.filter((item) => item.status === "fulfilled").length, 1);
  await assert.rejects(store.completeSetup("Third-admin-password-2026"));
});

test("rejects invalid settings and event filters without mutating runtime state", async () => {
  config.dataDir = fixtureDir();
  const store = new Store();
  await store.init();
  const before = store.getSettings();
  await assert.rejects(store.updateSettings({ mode: "invalid" as "ai" }));
  await assert.rejects(store.updateSettings({ upstreamUrl: "file:///etc/passwd" }));
  await assert.rejects(store.updateSettings({ jevBaseUrl: "javascript:alert(1)" }));
  await assert.rejects(store.updateSettings({ aiTimeoutMs: -1 }));
  await assert.rejects(store.updateSettings({ customThreshold: Number.NaN }));
  await assert.rejects(store.listEvents({ cursor: "invalid" }));
  await assert.rejects(store.listEvents({ since: "not-a-date" }));
  assert.deepEqual(store.getSettings(), before);
});

test("accepts ordinary HTTP(S) site endpoints and rejects unsafe URL forms", async () => {
  config.databaseUrl = "";
  config.dataDir = fixtureDir();
  config.adminPassword = "";
  const store = new Store();
  await store.init();
  try {
    const saved = await store.saveSite({
      name: "Primary upstream",
      upstreamUrl: "https://example.com/api",
      mode: "traditional",
      enabled: true
    });
    assert.equal(saved.upstreamUrl, "https://example.com/api");
    await store.updateSettings({ upstreamUrl: "https://upstream.example.com" });
    const restarted = new Store();
    await restarted.init();
    assert.equal(restarted.listSites().find((site) => site.id === "default")?.upstreamUrl, "https://upstream.example.com");
    await restarted.close();
    for (const upstreamUrl of [
      "file:///etc/passwd",
      "http://user:password@example.com",
      "http://example.com/api?next=http://127.0.0.1",
      "http://example.com/api#fragment"
    ]) {
      await assert.rejects(store.saveSite({
        name: "Unsafe upstream",
        upstreamUrl,
        mode: "traditional",
        enabled: true
      }));
    }
  } finally {
    await store.close();
  }
});

test("persists per-site ports, rejects collisions, protects the default site and falls back without Jev", async () => {
  const previous = {
    databaseUrl: config.databaseUrl,
    dataDir: config.dataDir,
    adminPassword: config.adminPassword,
    environmentApiKey: config.environmentApiKey,
    openRouterKey: config.openRouterKey,
    sitePortRange: config.sitePortRange,
    proxyPort: config.proxyPort
  };
  config.databaseUrl = "";
  config.dataDir = fixtureDir();
  config.adminPassword = "";
  config.environmentApiKey = "";
  config.openRouterKey = "";
  const store = new Store();
  await store.init();
  try {
    const created = await store.saveSite({
      name: "Orders",
      listenPort: 8081,
      upstreamUrl: "http://127.0.0.1:9101",
      mode: "hybrid",
      enabled: true
    });
    assert.equal(created.listenPort, 8081);
    assert.equal(created.mode, "traditional");
    await assert.rejects(
      store.saveSite({
        name: "Collision",
        listenPort: 8081,
        upstreamUrl: "http://127.0.0.1:9102",
        mode: "traditional",
        enabled: true
      }),
      /已被站点/
    );
    await store.saveSite({
      ...created,
      name: "Orders edited",
      upstreamUrl: "http://127.0.0.1:9103"
    });
    assert.equal(store.getSiteByPort(8081)?.upstreamUrl, "http://127.0.0.1:9103");
    await assert.rejects(store.deleteSite("default"), /默认站点不能删除/);

    const restarted = new Store();
    await restarted.init();
    try {
      assert.equal(restarted.listSites().find((site) => site.id === created.id)?.listenPort, 8081);
      assert.equal(restarted.getSiteByPort(8081)?.name, "Orders edited");
    } finally {
      await restarted.close();
    }
  } finally {
    await store.close();
    config.databaseUrl = previous.databaseUrl;
    config.dataDir = previous.dataDir;
    config.adminPassword = previous.adminPassword;
    config.environmentApiKey = previous.environmentApiKey;
    config.openRouterKey = previous.openRouterKey;
    config.sitePortRange = previous.sitePortRange;
    config.proxyPort = previous.proxyPort;
  }
});

test("imports whole packs atomically, honors conflicts and preserves options across local restart", async (t) => {
  config.dataDir = fixtureDir();
  const store = new Store();
  await store.init();
  const rules = parseRuleImport('SecRule REQUEST_HEADERS:X-Token "@streq danger" "id:8801,deny,t:none,t:lowercase"', "modsecurity").rules;
  const original = store.listRules();
  await assert.rejects(store.importRules([rules[0]!, { ...rules[0]!, id: "NEW", target: "invalid" as "path" }]));
  assert.deepEqual(store.listRules(), original);
  await store.importRules(rules, "reject", false);
  await assert.rejects(store.importRules(rules));
  const skipped = await store.importRules(rules, "skip");
  assert.equal(skipped.skipped, 1);
  await store.importRules(rules, "overwrite", true);
  const restarted = new Store();
  await restarted.init();
  t.after(async () => { await restarted.close(); await store.close(); });
  const rule = restarted.listRules().find((entry) => entry.id === rules[0]!.id)!;
  assert.deepEqual(rule.variables, rules[0]!.variables);
  assert.deepEqual(rule.transforms, ["lowercase"]);
  assert.equal(evaluateRules({ method: "GET", path: "/", query: "", headers: { "x-token": "DANGER" } }, [rule]).length, 1);
});
