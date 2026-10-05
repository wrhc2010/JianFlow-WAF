import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { config } from "../src/config.js";
import { parseThreatFeed } from "../src/threat-feed.js";
import { previewNginxConfig } from "../src/nginx-import.js";
import { WaitRoom } from "../src/wait-room.js";
import { createHash, randomUUID } from "node:crypto";

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

test("custom page files are restricted to the data pages directory", async (t) => {
  const previous = config.dataDir;
  config.dataDir = resolve("../../../verification", `page-files-${randomUUID()}`);
  t.after(() => { config.dataDir = previous; });
  const { Store } = await import("../src/db/store.js");
  const store = new Store();
  const root = join(config.dataDir, "pages");
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, "maintenance.html"), "<h1>maintenance</h1>", "utf8");
  assert.equal(store.readPage({ source: "file", filePath: "maintenance.html", statusCode: 503 }), "<h1>maintenance</h1>");
  assert.equal(store.readPage({ source: "file", filePath: "../jianflow.sqlite", statusCode: 503 }), undefined);
  assert.equal(store.readPage({ source: "file", filePath: "maintenance.txt", statusCode: 503 }), undefined);
  await store.close();
});

test("local captcha issues a short-lived token bound to site and IP", async () => {
  const { createChallenge, verifyChallenge, verifyToken, clearChallenges } = await import("../src/captcha.js");
  const challenge = createChallenge("site-a", "203.0.113.10");
  let answer = 0;
  while (!createHash("sha256").update(`${challenge.challenge}:${answer}`).digest("hex").startsWith("0".repeat(challenge.difficulty))) answer++;
  const token = verifyChallenge("site-a", "203.0.113.10", challenge.challenge, String(answer));
  assert.ok(token);
  assert.equal(verifyToken("site-a", "203.0.113.10", token!), true);
  assert.equal(verifyToken("site-b", "203.0.113.10", token!), false);
  clearChallenges();
});

test("wait room removes cancelled entries and marks FIFO admissions as queued", async () => {
  const room = new WaitRoom({ enabled: true, maxActive: 1, maxQueue: 2, timeoutSeconds: 1 });
  const first = await room.enter();
  const abort = new AbortController();
  const cancelled = room.enter(abort.signal);
  const next = room.enter();
  abort.abort();
  assert.equal((await cancelled).allowed, false);
  assert.deepEqual(room.snapshot(), { active: 1, queued: 1 });
  first.release();
  const admitted = await next;
  assert.equal(admitted.queued, true);
  admitted.release();
  assert.deepEqual(room.snapshot(), { active: 0, queued: 0 });
});

test("nginx tree parsing imports weighted upstreams and redirect-only servers safely", () => {
  const preview = previewNginxConfig(`
    # ignore comment containing include
    upstream app { server app-a:9000 weight=1000; server app-b:9000 weight=10; }
    server { listen 8081; server_name shop.example; location / { proxy_pass http://app; } }
    server { listen 8082; return 302 "https://example.com/new"; }
  `);
  assert.equal(preview.valid, true, preview.errors.join("\n"));
  assert.deepEqual(preview.sites[0]?.upstreamPool, [{ url: "http://app-a:9000", weight: 1000 }, { url: "http://app-b:9000", weight: 10 }]);
  assert.deepEqual(preview.sites[1]?.redirect, { statusCode: 302, location: "https://example.com/new" });
  for (const content of [
    'server { listen 8081; include "/tmp/backdoor.conf"; }',
    "server { listen 8081; location / { proxy_pass http://app; }",
    "server { listen 8081; location /admin { proxy_pass http://app; } }",
    "upstream app { server app:9000; keepalive 32; }",
  ]) assert.equal(previewNginxConfig(content).valid, false);
});

test("IP feeds handle quoted CSV, multiple STIX indicators and TAXII envelopes", () => {
  assert.deepEqual(parseThreatFeed('"203.0.113.10","comma, description"\n"2001:db8::/32",ipv6', "csv"), ["203.0.113.10", "2001:db8::/32"]);
  assert.deepEqual(parseThreatFeed(JSON.stringify({ objects: [
    { type: "indicator", pattern: "[ipv4-addr:value = '203.0.113.1' OR ipv6-addr:value = '2001:db8::/32']" },
    { type: "indicator", pattern: "[ipv4-addr:value != '203.0.113.2']" },
    { type: "identity", pattern: "[ipv4-addr:value = '203.0.113.3']" },
  ] }), "taxii"), ["203.0.113.1", "2001:db8::/32"]);
  assert.deepEqual(parseThreatFeed("203.0.113.1/24/1\n203.0.113.2/33", "text"), []);
});

test("all CAPTCHA providers bind verification to hostname and honor failure policy", async () => {
  const { verifyProvider } = await import("../src/captcha.js");
  const urls = { turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify", hcaptcha: "https://api.hcaptcha.com/siteverify", recaptcha: "https://www.google.com/recaptcha/api/siteverify" };
  for (const provider of ["turnstile", "hcaptcha", "recaptcha"] as const) {
    const options = { enabled: true, provider, siteKey: "test", secretConfigured: true, timeoutMs: 100, failureAction: "block" as const };
    const mock = (hostname: string, success = true) => (async (url: string | URL | Request, init?: RequestInit) => {
      assert.equal(String(url), urls[provider]);
      assert.equal(init?.method, "POST");
      const body = init?.body as URLSearchParams;
      assert.equal(body.get("secret"), "private-secret");
      assert.equal(body.get("response"), "token");
      assert.equal(body.get("remoteip"), "203.0.113.1");
      assert.ok(init?.signal);
      return new Response(JSON.stringify({ success, hostname }));
    }) as typeof fetch;
    const verify = (fetcher: typeof fetch) => verifyProvider(options, "private-secret", "token", "203.0.113.1", "app.example", fetcher);
    assert.equal((await verify(mock("APP.example"))).allowed, true);
    assert.equal((await verify(mock("evil.example"))).allowed, false);
    assert.equal((await verify(mock("app.example", false))).allowed, false);
    assert.equal((await verify(async () => new Response("x".repeat(16385)))).unavailable, true);
    assert.equal((await verify(async () => new Response("", { status: 503 }))).allowed, false);
    const unavailable = (async () => { throw new Error("offline"); }) as typeof fetch;
    assert.equal((await verify(unavailable)).allowed, false);
    assert.equal((await verifyProvider({ ...options, failureAction: "allow" }, "private-secret", "token", "203.0.113.1", "app.example", unavailable)).allowed, true);
  }
});
