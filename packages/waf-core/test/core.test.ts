import assert from "node:assert/strict";
import test from "node:test";
import { BUILTIN_RULES, STRENGTH_THRESHOLDS, buildAiState, evaluateRules, thresholdFor } from "../src/index.js";

test("maps protection strengths to monotonic thresholds", () => {
  assert.equal(STRENGTH_THRESHOLDS.veryLow, 0.1);
  assert.equal(STRENGTH_THRESHOLDS.low, 0.3);
  assert.equal(STRENGTH_THRESHOLDS.medium, 0.5);
  assert.equal(STRENGTH_THRESHOLDS.high, 0.7);
  assert.equal(STRENGTH_THRESHOLDS.extreme, 0.9);
  assert.ok(STRENGTH_THRESHOLDS.low < STRENGTH_THRESHOLDS.medium);
});

test("clamps custom thresholds", () => {
  assert.equal(thresholdFor({ strength: "custom", customThreshold: 2 }), 1);
  assert.equal(thresholdFor({ strength: "custom", customThreshold: -1 }), 0);
});

test("redacts credential headers from AI state", () => {
  const state = buildAiState({
    method: "GET",
    path: "/admin",
    query: "",
    headers: { authorization: "secret", host: "example.test" }
  }, 1000);
  assert.match(state, /REDACTED/);
  assert.doesNotMatch(state, /secret/);
});

test("redacts sensitive query and nested JSON fields before contacting Jev", () => {
  const state = buildAiState({
    method: "POST",
    path: "/login",
    query: "?q=select&access_token=private-query",
    headers: { "content-type": "application/json", "x-api-key": "private-header" },
    body: JSON.stringify({ username: "admin", nested: { password: "private-body" } })
  }, 1000);
  assert.doesNotMatch(state, /private-query|private-header|private-body/);
  assert.match(state, /select/);
  assert.match(state, /admin/);
});

test("omits unstructured body formats from AI state", () => {
  const state = buildAiState({
    method: "POST",
    path: "/upload",
    query: "",
    headers: { "content-type": "text/plain" },
    body: "sensitive plain text"
  }, 1000);
  assert.doesNotMatch(state, /sensitive plain text/);
});

test("normalizes Unicode and repeated URL encoding for traditional rules", () => {
  const matches = evaluateRules({
    method: "GET",
    path: "/search",
    query: "q=%25%25%EF%BC%9Cscript%EF%BC%9E",
    headers: {}
  }, [{
    id: "unicode-xss",
    name: "unicode xss",
    source: "test",
    category: "XSS",
    severity: "high",
    target: "query",
    operator: "regex",
    pattern: "(<script>)",
    action: "block",
    enabled: true
  }]);
  assert.equal(matches[0]?.ruleId, "unicode-xss");
});

test("evaluates traditional rules", () => {
  const matches = evaluateRules({
    method: "GET",
    path: "/search",
    query: "q=union+select+password+from+users",
    headers: {}
  }, [{
    id: "test",
    name: "test",
    source: "test",
    category: "SQL",
    severity: "high",
    target: "query",
    operator: "regex",
    pattern: "union\\s+select",
    action: "block",
    enabled: true
  }]);
  assert.equal(matches[0]?.ruleId, "test");
});

test("inspects Host without treating ordinary local addressing as an attack", () => {
  const matches = evaluateRules({
    method: "GET",
    path: "/health",
    query: "",
    headers: { host: "127.0.0.1:8088" }
  }, BUILTIN_RULES);
  assert.equal(matches.length, 0);
});
