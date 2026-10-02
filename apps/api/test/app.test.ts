import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import test from "node:test";
import { createApp } from "../src/app.js";
import { config } from "../src/config.js";
import { Store } from "../src/db/store.js";

test("management setup, production HTTP login, validation and private key responses", async (t) => {
  config.databaseUrl = "";
  config.adminPassword = "";
  config.nodeEnv = "production";
  config.sessionCookieSecure = false;
  config.dataDir = resolve("../../../verification", `app-${randomUUID()}`);
  const store = new Store();
  await store.init();
  const app = await createApp(store, false);
  t.after(async () => { await app.close(); await store.close(); });
  const status = await app.inject("/api/v1/setup/status");
  assert.equal(status.statusCode, 200);
  assert.equal(status.json().initialized, false);
  assert.equal((await app.inject("/api/v1/settings")).statusCode, 428);
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/setup",
    payload: { password: "Test-password-2026", confirmPassword: "Mismatch-password-2026" } })).statusCode, 422);
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/setup",
    payload: { password: "Test-password-2026", confirmPassword: "Test-password-2026" } })).statusCode, 200);
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/setup",
    payload: { password: "Test-password-2026", confirmPassword: "Test-password-2026" } })).statusCode, 409);
  assert.equal((await app.inject("/api/v1/settings")).statusCode, 401);
  const login = await app.inject({ method: "POST", url: "/api/v1/auth/login",
    payload: { username: "admin", password: "Test-password-2026" } });
  assert.equal(login.statusCode, 200);
  const cookie = String(login.headers["set-cookie"]).split(";")[0]!;
  assert.match(String(login.headers["set-cookie"]), /HttpOnly/);
  assert.doesNotMatch(String(login.headers["set-cookie"]), /; Secure/);
  assert.equal((await app.inject({ url: "/api/v1/auth/me", headers: { cookie } })).statusCode, 200);
  for (const payload of [{ mode: "invalid" }, { aiTimeoutMs: -1 }, { jevBaseUrl: "file:///tmp/key" }, { apiKeyConfigured: true }]) {
    assert.equal((await app.inject({ method: "PATCH", url: "/api/v1/settings", headers: { cookie }, payload })).statusCode, 422);
  }
  const saved = await app.inject({ method: "PATCH", url: "/api/v1/settings", headers: { cookie },
    payload: { apiKey: "must-not-be-returned", mode: "traditional" } });
  assert.equal(saved.statusCode, 200);
  assert.doesNotMatch(saved.body, /must-not-be-returned|ciphertext/);
  assert.equal(saved.json().apiKeyConfigured, true);
  assert.equal(saved.json().apiKeySource, "database");
  const site = await app.inject({ method: "POST", url: "/api/v1/sites", headers: { cookie },
    payload: { name: "Orders", listenPort: 8081, upstreamUrl: "http://127.0.0.1:9101", mode: "hybrid", enabled: true } });
  assert.equal(site.statusCode, 201);
  assert.equal(site.json().listenPort, 8081);
  const editedSite = await app.inject({ method: "PATCH", url: `/api/v1/sites/${site.json().id}`, headers: { cookie },
    payload: { upstreamUrl: "http://127.0.0.1:9102" } });
  assert.equal(editedSite.statusCode, 200);
  assert.equal(editedSite.json().upstreamUrl, "http://127.0.0.1:9102");
  const duplicateSite = await app.inject({ method: "POST", url: "/api/v1/sites", headers: { cookie },
    payload: { name: "Collision", listenPort: 8081, upstreamUrl: "http://127.0.0.1:9103" } });
  assert.equal(duplicateSite.statusCode, 409);
  const defaultDelete = await app.inject({ method: "DELETE", url: "/api/v1/sites/default", headers: { cookie } });
  assert.equal(defaultDelete.statusCode, 409);
  for (const query of ["cursor=invalid", "since=not-a-date", "limit=501", "action=invalid"]) {
    assert.equal((await app.inject({ url: `/api/v1/events?${query}`, headers: { cookie } })).statusCode, 422);
  }
  const content = JSON.stringify([{ id: "UI-IMPORT", name: "UI import", target: "query", operator: "contains", pattern: "needle" }]);
  const preview = await app.inject({ method: "POST", url: "/api/v1/rules/import/preview", headers: { cookie },
    payload: { format: "json", content } });
  assert.equal(preview.json().valid, true);
  assert.equal(store.listRules().some((rule) => rule.id === "UI-IMPORT"), false);
  const imported = await app.inject({ method: "POST", url: "/api/v1/rules/import", headers: { cookie },
    payload: { format: "json", content, enabled: false } });
  assert.equal(imported.statusCode, 200);
  assert.equal(imported.json().data[0].enabled, false);
  const conflict = await app.inject({ method: "POST", url: "/api/v1/rules/import", headers: { cookie },
    payload: { format: "json", content } });
  assert.equal(conflict.statusCode, 422);
  const skipped = await app.inject({ method: "POST", url: "/api/v1/rules/import", headers: { cookie },
    payload: { format: "json", content, conflict: "skip" } });
  assert.equal(skipped.json().skipped, 1);
  const invalid = await app.inject({ method: "POST", url: "/api/v1/rules/import/preview", headers: { cookie },
    payload: { format: "modsecurity", content: '# comment\nSecAction "deny"' } });
  assert.equal(invalid.json().valid, false);
  assert.equal(invalid.json().errors[0].line, 2);
  assert.equal((await app.inject({ method: "PATCH", url: "/api/v1/rules/UI-IMPORT", headers: { cookie },
    payload: { operator: "executeScript" } })).statusCode, 422);
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/rules/test", headers: { cookie },
    payload: { path: "/", headers: {} } })).statusCode, 422);
  assert.equal((await app.inject({ method: "POST", url: "/api/v1/auth/logout", headers: { cookie } })).statusCode, 200);
  assert.equal((await app.inject({ url: "/api/v1/auth/me", headers: { cookie } })).statusCode, 401);
});

test("enables Secure cookies explicitly behind HTTPS termination", async (t) => {
  config.sessionCookieSecure = true;
  config.dataDir = resolve("../../../verification", `secure-${randomUUID()}`);
  const store = new Store();
  await store.init();
  await store.completeSetup("Secure-cookie-password-2026");
  const app = await createApp(store, false);
  t.after(async () => { await app.close(); await store.close(); config.sessionCookieSecure = false; });
  const login = await app.inject({ method: "POST", url: "/api/v1/auth/login",
    payload: { username: "admin", password: "Secure-cookie-password-2026" } });
  assert.equal(login.statusCode, 200);
  assert.match(String(login.headers["set-cookie"]), /; Secure/);
});
