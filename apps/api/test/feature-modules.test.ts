import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { config } from "../src/config.js";
import { parseThreatFeed } from "../src/threat-feed.js";
import { previewNginxConfig } from "../src/nginx-import.js";
import { WaitRoom } from "../src/wait-room.js";

test("parses supported threat feed formats without accepting invalid addresses", () => {
  assert.deepEqual(parseThreatFeed("203.0.113.10\n2001:db8::/32\nnot-an-ip", "text"), ["203.0.113.10", "2001:db8::/32"]);
  assert.deepEqual(parseThreatFeed('{"ips":["203.0.113.10","203.0.113.10","10.0.0.999"]}', "json"), ["203.0.113.10"]);
  assert.deepEqual(parseThreatFeed("203.0.113.10,high\n# ignored", "csv"), ["203.0.113.10"]);
  assert.deepEqual(parseThreatFeed(JSON.stringify({ objects: [{ type: "indicator", pattern: "[ipv4-addr:value = '198.51.100.7']" }] }), "stix"), ["198.51.100.7"]);
});

test("previews the safe nginx subset and rejects unknown directives", () => {
  const preview = previewNginxConfig(`server { listen 8081; server_name app.example; location / { proxy_pass http://127.0.0.1:9001; proxy_read_timeout 30s; } }`);
  assert.equal(preview.valid, true);
  assert.equal(preview.sites[0]?.listenPort, 8081);
  assert.equal(preview.sites[0]?.upstreamUrl, "http://127.0.0.1:9001");
  const rejected = previewNginxConfig("server { listen 8080; location / { proxy_pass http://127.0.0.1:9000; lua_code_cache off; } }");
  assert.equal(rejected.valid, false);
  assert.match(rejected.errors.join("\n"), /lua_code_cache/);
});

test("nginx preview keeps imports behind explicit confirmation", async () => {
  const { createApp } = await import("../src/app.js");
  const store = {
    setupStatus: () => ({ initialized: false }),
    listSites: () => [],
    getSettings: () => ({ waitRoomDefaults: { enabled: false, maxActive: 100, maxQueue: 100, timeoutSeconds: 60 } })
  } as never;
  const app = await createApp(store, false);
  const preview = await app.inject({ method: "POST", url: "/api/v1/nginx/import/preview", payload: { content: "server { listen 8081; location / { proxy_pass http://127.0.0.1:9001; } }" } });
  assert.equal(preview.statusCode, 428);
  await app.close();
});

test("wait room grants active requests FIFO and rejects a full queue", async () => {
  const room = new WaitRoom({ enabled: true, maxActive: 1, maxQueue: 1, timeoutSeconds: 1 });
  const first = await room.enter();
  assert.equal(first.allowed, true);
  const second = room.enter();
  const third = await room.enter();
  assert.equal(third.allowed, false);
  assert.match(third.reason ?? "", /已满/);
  first.release();
  const admitted = await second;
  assert.equal(admitted.allowed, true);
  admitted.release();
  assert.deepEqual(room.snapshot(), { active: 0, queued: 0 });
});

test("custom page files are restricted to the data pages directory", async () => {
  const { Store } = await import("../src/db/store.js");
  const store = new Store();
  const root = join(config.dataDir, "pages");
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "maintenance.html"), "<h1>maintenance</h1>", "utf8");
  assert.equal(store.readPage({ source: "file", filePath: "maintenance.html", statusCode: 503 }), "<h1>maintenance</h1>");
  assert.equal(store.readPage({ source: "file", filePath: "../jianflow.sqlite", statusCode: 503 }), undefined);
  assert.equal(store.readPage({ source: "file", filePath: "maintenance.txt", statusCode: 503 }), undefined);
  await store.close();
  rmSync(join(config.dataDir, "pages"), { recursive: true, force: true });
});

test("local captcha issues a short-lived token bound to site and IP", async () => {
  const { createChallenge, verifyChallenge, verifyToken, clearChallenges } = await import("../src/captcha.js");
  const challenge = createChallenge("site-a", "203.0.113.10");
  const answer = challenge.question.split("=")[0]!.split("+").map((value) => Number(value.trim())).reduce((sum, value) => sum + value, 0);
  const token = verifyChallenge("site-a", "203.0.113.10", challenge.challenge, String(answer));
  assert.ok(token);
  assert.equal(verifyToken("site-a", "203.0.113.10", token!), true);
  assert.equal(verifyToken("site-b", "203.0.113.10", token!), false);
  clearChallenges();
});
