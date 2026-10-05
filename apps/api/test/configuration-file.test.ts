import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import test from "node:test";
import { config } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { createApp } from "../src/app.js";
import { applyConfigurationFile } from "../src/configuration-file.js";

test("configuration JSON uses API validation, encrypted profiles and stable site IDs", async (t) => {
  const previous = { ...config };
  config.databaseUrl = ""; config.environmentApiKey = ""; config.openRouterKey = ""; config.adminPassword = "";
  config.dataDir = resolve("../../../verification", `configuration-${randomUUID()}`);
  const store = new Store(); await store.init();
  const app = await createApp(store, false);
  t.after(async () => { await app.close(); await store.close(); Object.assign(config, previous); });
  await mkdir(config.dataDir, { recursive: true });
  const path = resolve(config.dataDir, "configuration.json");
  const save = (document: object) => writeFile(path, JSON.stringify(document));
  await save({ settings: { auditMode: "async" }, profiles: [{ id: "local-jev", name: "Local", baseUrl: "https://jev.example", model: "model-a", apiKey: "file-private-key" }], sites: [{ id: "configured", name: "Configured", listenPort: 8081, upstreamUrl: "http://app:9000", mode: "hybrid", aiProfileId: "local-jev", captchaEnabled: false, maintenance: { source: "file", filePath: "maintenance.html", statusCode: 503 } }] });
  await applyConfigurationFile(app, store, path);
  assert.equal(store.getSettings().auditMode, "async");
  assert.equal(store.getSiteByPort(8081)?.id, "configured");
  assert.equal(store.getSiteByPort(8081)?.mode, "hybrid");
  assert.equal((await store.getAiProvider("local-jev"))?.provider.apiKey, "file-private-key");
  assert.doesNotMatch(JSON.stringify(await store.listAiProfiles()), /file-private-key/);
  await applyConfigurationFile(app, store, path);
  assert.equal(store.listSites().length, 2);
  for (const invalid of [{ dangerous: true }, { settings: { auditMode: "bad" } }, { sites: [{ id: "new", listenPort: 8082 }] }, { settings: { apiKeySource: "database" } }]) {
    await save(invalid); await assert.rejects(applyConfigurationFile(app, store, path));
    assert.equal(store.getSettings().auditMode, "async");
    assert.equal(store.listSites().length, 2);
  }
});
