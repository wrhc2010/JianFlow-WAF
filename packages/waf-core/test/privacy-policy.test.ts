import assert from "node:assert/strict";
import test from "node:test";
import { buildAiInspection, safeRequestPath, evaluateRequest, BUILTIN_RULES, defaultPolicy } from "../src/index.js";

test("redacts +json and JSON Patch secrets and omits unstructured bodies", () => {
  for (const [type, body] of [
    ["application/problem+json", JSON.stringify({ password: "SENTINEL" })],
    ["application/json-patch+json", JSON.stringify([{ op: "replace", path: "/password", value: "SENTINEL" }])],
    ["text/plain", "SENTINEL"], ["text/xml", "<password>SENTINEL</password>"],
    ["multipart/form-data", "SENTINEL"]
  ]) {
    const state = buildAiInspection({ method: "POST", path: "/", query: "", headers: { "content-type": type! }, body: body! }, 1024);
    assert.doesNotMatch(state.state, /SENTINEL/);
  }
  assert.doesNotMatch(safeRequestPath("/login?access_token=SENTINEL"), /SENTINEL/);
});

test("marks hybrid AI coverage incomplete without truncating JSON into invalid data", async () => {
  const decision = await evaluateRequest({ method: "POST", path: "/", query: "", headers: { "content-type": "application/json" },
    body: JSON.stringify({ note: "A".repeat(40000) }) }, [],
  { mode: "hybrid", strength: "medium", customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 1024 }, "coverage",
  async (state) => {
    assert.doesNotThrow(() => JSON.parse(JSON.parse(state).body));
    return { model: "test", noul: 0, available: true, latencyMs: 0 };
  });
  assert.equal(decision.partialInspection, true);
  assert.equal(decision.aiInspectionComplete, false);
  assert.equal(decision.localInspectionComplete, true);
});

test("precise exceptions preserve other fields, paths, sites and rules; observation preserves evidence", async () => {
  const policy = { ...defaultPolicy(), aiScope: "all" as const };
  const settings = { mode: "traditional" as const, strength: "medium" as const, customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 1024 };
  const request = { siteId: "one", method: "POST", path: "/editor", query: "", headers: { "content-type": "application/json" }, body: JSON.stringify({ template: "{{ name }}" }) };
  const exception = { id: "e", siteId: "one", name: "Editor", method: "POST", path: "/editor", target: "body" as const,
    selector: "template", ruleIds: ["JIANFLOW-ENC-001", "JIANFLOW-SSTI-BODY"], expiresAt: "2099-01-01T00:00:00Z", reason: "Template editor", enabled: true };
  const classify = async () => ({ model: "test", noul: 0, available: true, latencyMs: 0 });
  const run = (req = request) => evaluateRequest(req, BUILTIN_RULES, settings, "exception", classify, { policy, exceptions: [exception] });
  assert.equal((await run()).action, "allow");
  assert.deepEqual((await run()).exceptionIds, ["e"]);
  assert.equal((await run({ ...request, path: "/login" })).action, "block");
  assert.equal((await run({ ...request, siteId: "two" })).action, "block");
  const other = await run({ ...request, body: JSON.stringify({ template: "{{ name }}", other: "{{ 7*7 }}" }) });
  assert.equal(other.action, "block");
  assert.equal(other.matchedRules.find((match) => match.ruleId === "JIANFLOW-SSTI-BODY")?.field, "other");
  assert.equal((await run({ ...request, body: JSON.stringify({ template: "{{ name }}", other: "file:///etc/passwd" }) })).action, "block");
  const expired = await evaluateRequest(request, BUILTIN_RULES, settings, "expired", classify, { policy, exceptions: [{ ...exception, expiresAt: "2020-01-01T00:00:00Z" }] });
  assert.equal(expired.action, "block");
  assert.equal((await run({ ...request, method: "PUT" })).action, "block");
  assert.equal((await run({ ...request, body: JSON.stringify({ other: "%7B%7B%20name%20%7D%7D" }) })).action, "block");
  const observed = await evaluateRequest(request, BUILTIN_RULES, settings, "observe", classify, { policy: { ...policy, enforcement: "observe" } });
  assert.equal(observed.action, "allow");
  assert.equal(observed.wouldBlock, true);
  assert.ok(observed.matchedRules.length);
  assert.doesNotMatch(JSON.stringify(observed.matchedRules), /name\s*\}\}/);
  assert.ok(observed.matchedRules.some((rule) => rule.snippet?.includes("OMITTED")));
});

test("AI incomplete local policy actually evaluates local rules and reports the fallback", async () => {
  const settings = { mode: "ai" as const, strength: "medium" as const, customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 1024 };
  let called = false;
  const classify = async () => { called = true; return { model: "test", noul: 0, available: true, latencyMs: 0 }; };
  const request = { method: "POST", path: "/editor", query: "", headers: { "content-type": "text/plain" }, body: "hello" };
  const allowed = await evaluateRequest(request, BUILTIN_RULES, settings, "local", classify, { policy: defaultPolicy() });
  assert.equal(allowed.action, "allow"); assert.equal(allowed.localInspectionComplete, true); assert.equal(allowed.aiInspectionComplete, false);
  const blocked = await evaluateRequest({ ...request, body: "{{ 7*7 }}" }, BUILTIN_RULES, settings, "block", classify, { policy: defaultPolicy() });
  assert.equal(blocked.action, "block"); assert.equal(called, false); assert.equal(blocked.module, "rules");
});

test("records exceptions only when local inspection actually suppresses a rule", async () => {
  const settings = { mode: "ai" as const, strength: "medium" as const, customThreshold: 0.5, model: "test", aiTimeoutMs: 100, aiBodyLimit: 1024 };
  const request = { siteId: "one", method: "POST", path: "/editor", query: "", headers: { "content-type": "application/json" }, body: JSON.stringify({ template: "{{ name }}" }) };
  const exception = { id: "editor", siteId: "one", name: "Editor", method: "POST", path: "/editor", target: "body" as const,
    selector: "template", ruleIds: ["JIANFLOW-ENC-001", "JIANFLOW-SSTI-BODY"], expiresAt: "2099-01-01T00:00:00Z", reason: "Template editor", enabled: true };
  let calls = 0;
  const classify = async () => { calls += 1; return { model: "test", noul: 0, available: true, latencyMs: 0 }; };
  const policy = { ...defaultPolicy(), aiBodyFields: ["template"] };
  const complete = await evaluateRequest(request, BUILTIN_RULES, settings, "complete", classify, { policy, exceptions: [exception] });
  assert.equal(complete.aiInspectionComplete, true);
  assert.equal(complete.localInspectionComplete, false);
  assert.deepEqual(complete.exceptionIds, []);
  assert.equal(calls, 1);
  const fallback = await evaluateRequest(request, BUILTIN_RULES, { ...settings, aiBodyLimit: 1 }, "fallback", classify, { policy, exceptions: [exception] });
  assert.equal(fallback.localInspectionComplete, true);
  assert.equal(fallback.aiInspectionComplete, false);
  assert.equal(fallback.action, "allow");
  assert.deepEqual(fallback.exceptionIds, ["editor"]);
  assert.equal(calls, 1);
});
