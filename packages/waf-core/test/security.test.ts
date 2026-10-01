import assert from "node:assert/strict";
import test from "node:test";
import { BUILTIN_RULES, evaluateRequest, evaluateRules, type RuleTarget, type WafRequest, type WafRule } from "../src/index.js";

function requestAt(target: RuleTarget, payload: string): WafRequest {
  const request: WafRequest = { method: "POST", path: "/submit", query: "", headers: {} };
  if (target === "path") request.path = `/${payload}`;
  if (target === "query") request.query = `?input=${payload}`;
  if (target === "header") request.headers["x-inspection-test"] = payload;
  if (target === "cookie") request.headers.cookie = `input=${payload}`;
  if (target === "body") {
    request.body = JSON.stringify({ input: payload });
    request.headers["content-type"] = "application/json";
  }
  return request;
}

const attacks = [
  "union select password from users",
  "UNION/**/SELECT password FROM users",
  "' or 1=1--",
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "{{7*7}}",
  '{"$gt":""}',
  ";cat /etc/passwd",
  "$(whoami)",
  "../../etc/passwd",
  "file:///etc/passwd",
  "gopher://127.0.0.1:6379/_INFO",
  "data:text/html,<h1>test</h1>",
  "http://10.2.3.4/admin",
  "http://172.16.0.10/admin",
  "http://192.168.2.8/admin",
  "http://169.254.169.254/latest/meta-data",
  "http://2130706433/",
  "http://0x7f000001/",
  "http://127.1/",
  "http://[::ffff:127.0.0.1]/",
  "http://[fc00::1]/",
  "http://localhost./"
];

for (const target of ["path", "query", "header", "cookie", "body"] as const) {
  for (const payload of attacks) {
    test(`blocks ${target} attack ${payload}`, () => {
      assert.ok(evaluateRules(requestAt(target, payload), BUILTIN_RULES).some((match) => match.action === "block"));
    });
  }
  test(`decodes percent-encoded ${target} attacks with unrelated malformed escapes`, () => {
    const request = requestAt(target, `bad%ZZ${encodeURIComponent(encodeURIComponent("<script>alert(1)</script>"))}`);
    assert.ok(evaluateRules(request, BUILTIN_RULES).some((match) => match.action === "block"));
  });
  for (const encoded of ["%FF%3Cscript%3Ealert(1)", "%u003Cscript%u003Ealert(1)", "%EF%BC%853Cscript%EF%BC%853E"]) {
    test(`decodes ${target} byte and Unicode escapes ${encoded}`, () => {
      assert.ok(evaluateRules(requestAt(target, encoded), BUILTIN_RULES).some((match) => match.action === "block"));
    });
  }
}

test("inspects parsed JSON strings, keys, arrays and Unicode escapes", () => {
  const request: WafRequest = {
    method: "POST", path: "/", query: "", headers: { "content-type": "application/json" },
    body: '{"nested":[{"input":"\\u0066ile:\\/\\/\\/etc\\/passwd","\\u0024gt":""}]}'
  };
  assert.ok(evaluateRules(request, BUILTIN_RULES).some((match) => match.category === "SSRF"));
  assert.ok(evaluateRules(request, BUILTIN_RULES).some((match) => match.category === "NoSQL 注入"));
});

test("AI-only mode does not allow requests whose bodies exceed the AI inspection limit", async () => {
  let called = false;
  const decision = await evaluateRequest(
    requestAt("body", `${"a".repeat(2048)}file:///etc/passwd`), [],
    { mode: "ai", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 1024 },
    "ai-limit-test", async () => {
      called = true;
      return { model: "test", available: true, noul: 0, latencyMs: 0 };
    }
  );
  assert.equal(decision.action, "error");
  assert.equal(called, false);
  assert.equal(decision.partialInspection, true);
});

test("inspects bounded base64-encoded payloads", () => {
  const request = requestAt("body", Buffer.from("file:///etc/passwd").toString("base64"));
  assert.ok(evaluateRules(request, BUILTIN_RULES).some((match) => match.action === "block"));
});

test("matches IPv4, IPv6 and mapped IPv4 CIDR rule operators", () => {
  const rule: WafRule = {
    id: "cidr", name: "cidr", source: "test", category: "IP", severity: "high",
    target: "ip", operator: "cidr", pattern: "192.168.0.0/16", action: "block", enabled: true
  };
  const request: WafRequest = { method: "GET", path: "/", query: "", headers: {}, ip: "192.168.2.42" };
  assert.equal(evaluateRules(request, [rule]).length, 1);
  request.ip = "::ffff:192.168.2.42";
  assert.equal(evaluateRules(request, [rule]).length, 1);
  request.ip = "2001:db8:abcd::1";
  rule.pattern = "2001:db8::/32";
  assert.equal(evaluateRules(request, [rule]).length, 1);
  request.ip = "2001:db9::1";
  assert.equal(evaluateRules(request, [rule]).length, 0);
});

test("blocks repeated slash paths before routing normalization can diverge", () => {
  const request: WafRequest = { method: "GET", path: "/v1//health", query: "", headers: {} };
  assert.ok(evaluateRules(request, BUILTIN_RULES).some((match) => match.ruleId === "JIANFLOW-PATH-002"));
});

test("inspects the attachment report's header injection families", () => {
  const headers = [
    "x-client-ip", "http_x_forwarded_for", "x-forwarded", "x-remote-ip", "x-remote-addr",
    "x-forwarded-user", "x-on-behalf-of", "x-proxy-user", "origin", "referer", "x-requested-with",
    "x-csrf-token", "x-forwarded-proto", "x-forwarded-port", "x-forwarded-scheme", "x-app-url",
    "forwarded", "x-forwarded-by", "x-auth-token", "authorization"
  ];
  const payloads = ["1.1.1.1%27 OR %271%27=%271", "1.1.1.1<script>alert(1)</script>", "../../etc/passwd", ";cat /etc/passwd"];
  for (const header of headers) for (const payload of payloads) {
    const matches = evaluateRules({ method: "GET", path: "/", query: "", headers: { [header]: payload } }, BUILTIN_RULES);
    assert.ok(matches.some((match) => match.action === "block"), `${header} ${payload}`);
  }
});

for (const payload of ["hello world", "https://example.com/product?id=2", "http://172.32.0.1/", "127.0.0.1", "2026-09-30", "colour=red; shape=square"]) {
  test(`allows ordinary data ${payload}`, () => {
    for (const target of ["query", "header", "cookie", "body"] as const) {
      assert.equal(evaluateRules(requestAt(target, payload), BUILTIN_RULES).filter((match) => match.action === "block").length, 0);
    }
  });
}
