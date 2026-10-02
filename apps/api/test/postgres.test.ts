import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { Pool } from "pg";
import { BUILTIN_RULES } from "@jev-waf/core";
import { config } from "../src/config.js";
import { checkPassword } from "../src/auth.js";
import { Store } from "../src/db/store.js";
import { parseRuleImport } from "../src/rule-import.js";

test("real PostgreSQL migration, restart, all-history metrics and failure atomicity", {
  skip: !process.env.TEST_DATABASE_URL, timeout: 30000
}, async (t) => {
  const url = new URL(process.env.TEST_DATABASE_URL!);
  const schema = `verify_${randomUUID().replace(/-/g, "")}`;
  const admin = new Pool({ connectionString: url.toString() });
  await admin.query(`CREATE SCHEMA ${schema}`);
  url.searchParams.set("options", `-c search_path=${schema}`);
  config.databaseUrl = url.toString();
  config.adminPassword = "";
  config.environmentApiKey = "environment-test-fallback";
  config.openRouterKey = config.environmentApiKey;
  config.openRouterModel = "environment/test-model";
  config.jevBaseUrl = "http://127.0.0.1:9988";
  const db = new Pool({ connectionString: config.databaseUrl });
  const stores: Store[] = [];
  t.after(async () => {
    for (const store of stores) await store.close();
    await db.end();
    await admin.end();
  });
  const store = new Store();
  stores.push(store);
  await store.init();
  assert.equal(store.getSettings().model, "environment/test-model");
  assert.equal(store.setupStatus().initialized, false);
  await db.query("ALTER TABLE settings RENAME TO settings_unavailable");
  await assert.rejects(store.completeSetup("Unpersisted-password-2026"));
  assert.equal(store.setupStatus().initialized, false);
  assert.equal(checkPassword("Unpersisted-password-2026"), false);
  await db.query("ALTER TABLE settings_unavailable RENAME TO settings");
  const rival = new Store();
  stores.push(rival);
  await rival.init();
  const setup = await Promise.allSettled([
    store.completeSetup("Database-password-2026"),
    rival.completeSetup("Rival-password-2026")
  ]);
  assert.equal(setup.filter((item) => item.status === "fulfilled").length, 1);
  const winningPassword = setup[0]?.status === "fulfilled" ? "Database-password-2026" : "Rival-password-2026";
  await store.updateSettings({
    apiKey: "saved-database-key", model: "saved/test-model",
    jevBaseUrl: "http://127.0.0.1:9977/api/alpha/decisions", mode: "traditional"
  });
  const saved = await db.query("SELECT api_key_ciphertext FROM settings");
  assert.notEqual(saved.rows[0].api_key_ciphertext, "saved-database-key");
  assert.doesNotMatch(JSON.stringify(store.getSettings()), /saved-database-key|ciphertext/);
  const before = store.getSettings();
  await db.query("ALTER TABLE settings RENAME TO settings_unavailable");
  await assert.rejects(store.updateSettings({ model: "must-not-apply", apiKey: "must-not-apply" }));
  assert.deepEqual(store.getSettings(), before);
  assert.equal(config.openRouterKey, "saved-database-key");
  await db.query("ALTER TABLE settings_unavailable RENAME TO settings");

  await db.query(`DELETE FROM rules WHERE id <> ALL($1::text[])`, [BUILTIN_RULES.slice(0, 5).map((rule) => rule.id)]);
  await db.query("DELETE FROM builtin_rule_catalog");
  await db.query("UPDATE rules SET enabled = FALSE WHERE id = $1", [BUILTIN_RULES[0]!.id]);
  const restarted = new Store();
  stores.push(restarted);
  await restarted.init();
  assert.equal(restarted.setupStatus().initialized, true);
  assert.equal(checkPassword(winningPassword), true);
  assert.equal(config.jevBaseUrl, "http://127.0.0.1:9977");
  assert.equal(config.openRouterModel, "saved/test-model");
  assert.equal(config.openRouterKey, "saved-database-key");
  assert.equal(restarted.listRules().length, BUILTIN_RULES.length);
  assert.equal(restarted.listRules().find((rule) => rule.id === BUILTIN_RULES[0]!.id)?.enabled, false);
  const pack = parseRuleImport('SecRule REQUEST_HEADERS:X-Token "@streq danger" "id:8802,deny,t:none,t:lowercase"', "modsecurity").rules;
  await restarted.importRules(pack);
  await db.query(`ALTER TABLE rules ADD CONSTRAINT reject_second_test_rule CHECK (id <> 'FAIL-SECOND')`);
  await assert.rejects(restarted.importRules([{ ...pack[0]!, id: "ATOMIC-FIRST" }, { ...pack[0]!, id: "FAIL-SECOND" }]));
  assert.equal((await db.query("SELECT id FROM rules WHERE id = 'ATOMIC-FIRST'")).rowCount, 0);
  assert.equal(restarted.listRules().some((rule) => rule.id === "ATOMIC-FIRST"), false);
  const options = await db.query("SELECT options FROM rules WHERE id = $1", [pack[0]!.id]);
  assert.deepEqual(options.rows[0].options.transforms, ["lowercase"]);
  const third = new Store();
  stores.push(third);
  await third.init();
  assert.deepEqual(third.listRules().find((rule) => rule.id === pack[0]!.id)?.variables, pack[0]!.variables);

  await db.query(`
    INSERT INTO events (request_id, action, mode, method, path, ip, status_code, reason,
                        country, region, latitude, longitude, matched_rules, created_at)
    SELECT 'bulk-' || n, CASE WHEN n <= 2200 THEN 'block' WHEN n <= 2250 THEN 'allow' ELSE 'error' END,
           'traditional', 'GET', '/probe/' || n, '203.0.113.7', 403, 'test',
           'US', 'New York', 40.7, -74.0, '[{"name":"SQL injection"}]'::jsonb,
           NOW() - (n % 5) * INTERVAL '1 minute' + (n % 100) * INTERVAL '1 microsecond'
    FROM generate_series(1, 2300) n
  `);
  const summary = await restarted.summary();
  assert.equal(summary.total, 2300);
  assert.equal(summary.blocked, 2200);
  assert.equal(summary.total, summary.blocked! + summary.allowed! + summary.errors!);
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const page = await restarted.listEvents({ limit: 137, ...(cursor ? { cursor } : {}) });
    for (const event of page.data) {
      assert.equal(seen.has(String(event.id)), false);
      seen.add(String(event.id));
    }
    cursor = page.nextCursor;
  } while (cursor);
  assert.equal(seen.size, 2300);
  const map = await restarted.attackMap(24);
  assert.equal(map.blocked, 2200);
  assert.equal(map.countries[0]?.count, 2200);
  assert.equal(map.points[0]?.count, 2200);
  assert.equal((await restarted.timeseries()).reduce((sum, point) => sum + point.total, 0), 2300);
  const requestId = randomUUID();
  const decision = { requestId, action: "allow" as const, mode: "traditional" as const, matchedRules: [], reason: "test" };
  await restarted.saveEvent(decision, { method: "GET", path: "/dedup" }, 200);
  await restarted.saveEvent(decision, { method: "GET", path: "/dedup" }, 200);
  assert.equal((await restarted.summary()).total, 2301);
  await restarted.updateSettings({ apiKey: null });
  assert.equal(config.openRouterKey, "environment-test-fallback");
  console.log(`Verified PostgreSQL schema: ${schema}`);
});

test("PostgreSQL preserves default edits and legacy site ports across restart and key removal", {
  skip: !process.env.TEST_DATABASE_URL, timeout: 30000
}, async (t) => {
  const url = new URL(process.env.TEST_DATABASE_URL!);
  const schema = `sites_${randomUUID().replace(/-/g, "")}`;
  const admin = new Pool({ connectionString: url.toString() });
  await admin.query(`CREATE SCHEMA ${schema}`);
  url.searchParams.set("options", `-c search_path=${schema}`);
  config.databaseUrl = url.toString();
  config.adminPassword = "";
  config.environmentApiKey = "";
  config.openRouterKey = "";
  const db = new Pool({ connectionString: config.databaseUrl });
  const stores: Store[] = [];
  t.after(async () => {
    for (const store of stores) await store.close();
    await db.end();
    await admin.end();
  });
  await db.query(`
    CREATE TABLE sites (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, upstream_url TEXT NOT NULL,
      mode TEXT NOT NULL DEFAULT 'hybrid', enabled BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO sites (id, name, upstream_url, mode, enabled) VALUES
      ('default', 'Existing default', 'http://127.0.0.1:9100', 'traditional', FALSE),
      ('legacy-one', 'Legacy one', 'http://127.0.0.1:9101', 'ai', TRUE),
      ('legacy-two', 'Legacy two', 'http://127.0.0.1:9102', 'hybrid', FALSE);
  `);
  const store = new Store();
  stores.push(store);
  await store.init();
  const migrated = store.listSites();
  assert.equal(migrated.length, 3);
  assert.equal(new Set(migrated.map((site) => site.listenPort)).size, 3);
  assert.equal(migrated.find((site) => site.id === "default")?.listenPort, 8080);
  assert.equal(migrated.find((site) => site.id === "default")?.name, "Existing default");
  assert.equal(migrated.find((site) => site.id === "default")?.enabled, false);
  assert.ok(migrated.every((site) => site.mode === "traditional"));
  await store.saveSite({
    ...migrated.find((site) => site.id === "default")!, name: "Edited default"
  });
  const defaultBefore = store.listSites().find((site) => site.id === "default")!;
  const settingsBefore = store.getSettings();
  await db.query(`
    ALTER TABLE settings ADD CONSTRAINT reject_default_edit_test
    CHECK (upstream_url <> 'http://127.0.0.1:9199')
  `);
  await assert.rejects(store.saveSite({ ...defaultBefore, upstreamUrl: "http://127.0.0.1:9199" }));
  assert.deepEqual(store.getSettings(), settingsBefore);
  assert.deepEqual(store.listSites().find((site) => site.id === "default"), defaultBefore);
  assert.equal((await db.query("SELECT upstream_url FROM sites WHERE id = 'default'")).rows[0].upstream_url, defaultBefore.upstreamUrl);
  await db.query("ALTER TABLE settings DROP CONSTRAINT reject_default_edit_test");
  await store.updateSettings({ apiKey: "temporary-test-key", mode: "hybrid" });
  await store.saveSite({ ...migrated.find((site) => site.id === "legacy-one")!, mode: "ai" });
  const before = store.getSettings();
  await db.query(`
    ALTER TABLE sites ADD CONSTRAINT reject_fallback_test
    CHECK (id <> 'legacy-one' OR mode <> 'traditional')
  `);
  await assert.rejects(store.updateSettings({ apiKey: null }));
  assert.deepEqual(store.getSettings(), before);
  assert.equal(store.getSiteByPort(migrated.find((site) => site.id === "legacy-one")!.listenPort)?.mode, "ai");
  assert.equal((await db.query("SELECT mode FROM settings")).rows[0].mode, "hybrid");
  await db.query("ALTER TABLE sites DROP CONSTRAINT reject_fallback_test");
  await store.updateSettings({ apiKey: null });
  assert.ok(store.listSites().every((site) => site.mode === "traditional"));
  assert.ok((await db.query("SELECT mode FROM sites")).rows.every((row) => row.mode === "traditional"));
  const restarted = new Store();
  stores.push(restarted);
  await restarted.init();
  assert.deepEqual(restarted.listSites(), store.listSites());
  assert.equal(restarted.listSites().find((site) => site.id === "default")?.name, "Edited default");
  assert.equal(restarted.listSites().find((site) => site.id === "default")?.enabled, false);
});
