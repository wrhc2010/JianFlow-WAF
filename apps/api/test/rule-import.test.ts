import assert from "node:assert/strict";
import test from "node:test";
import { parseRuleImport } from "../src/rule-import.js";
import { evaluateRules } from "@jev-waf/core";

test("imports JSON rules with defaults and metadata", () => {
  const result = parseRuleImport(JSON.stringify({
    rules: [{
      id: "CUSTOM-001",
      name: "custom query rule",
      target: "query",
      operator: "regex",
      pattern: "union\\s+select"
    }]
  }), "json");
  assert.equal(result.rules.length, 1);
  assert.equal(result.rules[0]?.action, "block");
  assert.equal(result.rules[0]?.packageId, "user-import");
  assert.equal(result.rules[0]?.license, "User supplied");
});

test("rejects unknown operators, directives, chains and transformations with source locations", () => {
  for (const input of [
    'SecRule ARGS "@unknown payload" "id:1001,deny"',
    'SecAction "id:1001,deny"',
    'SecRule ARGS "@rx payload" "id:1001,deny,chain"',
    'SecRule ARGS "@rx payload" "id:1001,deny,t:unknownTransform"',
    'SecRule ARGS "@rx payload" "id:1001,deny,setvar:tx.score=1"',
    'SecRule RESPONSE_BODY "@rx payload" "id:1001,phase:4,deny"'
  ]) {
    assert.throws(() => parseRuleImport(`# first line\n${input}`, "modsecurity"), /行 2.*列/);
  }
});

test("supports multiline SecRule, single quotes, metadata, selectors and transformations", () => {
  const result = parseRuleImport(String.raw`SecRule REQUEST_HEADERS:X-Token \
    '@rx ^danger$' \
    "id:2001,phase:1,deny,t:none,t:lowercase,msg:'Custom, token check',severity:'CRITICAL',tag:'test'"
SecRule ARGS '@contains needle' 'id:2002,phase:2,deny'`, "modsecurity");
  assert.equal(result.rules.length, 2);
  assert.equal(result.rules[0]?.name, "Custom, token check");
  assert.equal(result.rules[0]?.severity, "critical");
  assert.equal(evaluateRules({
    method: "POST", path: "/", query: "", headers: { "x-token": "DANGER", "content-type": "application/json" },
    body: '{"value":"needle"}'
  }, result.rules).length, 2);
  assert.equal(evaluateRules({
    method: "GET", path: "/", query: "?other=normal", headers: { "x-other": "DANGER" }
  }, result.rules).length, 0);
});

test("supports negation, URI query inspection, phrase matching and CIDR lists", () => {
  const result = parseRuleImport(String.raw`SecRule REQUEST_METHOD "!@streq POST" "id:3001,deny"
SecRule REQUEST_URI "@contains danger" "id:3002,deny"
SecRule ARGS:input "@pm one two" "id:3003,deny"
SecRule REMOTE_ADDR "@ipMatch 192.168.0.0/16,2001:db8::/32" "id:3004,deny"`, "modsecurity");
  assert.equal(evaluateRules({
    method: "GET", path: "/normal", query: "?input=two&target=danger", headers: {}, ip: "2001:db8::5"
  }, result.rules).length, 4);
});

test("rejects duplicate IDs, type coercion, unknown JSON properties and oversized packs", () => {
  const rule = { id: "DUP", name: "test", target: "query", operator: "contains", pattern: "test" };
  assert.throws(() => parseRuleImport(JSON.stringify([rule, rule]), "json"), /重复/);
  for (const field of [{ enabled: "yes" }, { action: "deny" }, { severity: 1 }, { id: 12 }, { typo: true }]) {
    assert.throws(() => parseRuleImport(JSON.stringify([{ ...rule, ...field }]), "json"));
  }
  assert.throws(() => parseRuleImport(JSON.stringify(Array.from({ length: 1001 }, (_, index) => ({ ...rule, id: `RULE-${index}` }))), "json"), /1000/);
});

test("JSON errors identify the rule index and exact line and column", () => {
  assert.throws(() => parseRuleImport('[\n{"id":"bad","name":"bad","target":"not-a-target","operator":"contains","pattern":"x"}\n]', "json"),
    /第 1 条规则.*行 2.*列/);
  assert.throws(() => parseRuleImport('[\n{"id":}\n]', "json"), /行 2.*列/);
});

test("rejects invalid JSON rule fields before persistence", () => {
  assert.throws(
    () => parseRuleImport(JSON.stringify([{
      id: "CUSTOM-002",
      name: "invalid",
      target: "query",
      operator: "regex",
      pattern: "["
    }]), "json"),
    /正则表达式无效/
  );
});

test("maps common ModSecurity SecRule targets and actions", () => {
  const result = parseRuleImport(
    'SecRule REQUEST_HEADERS "@rx <script>" "id:1001,deny,log"\nSecRule REQUEST_COOKIES "@streq admin" "id:1002,log"',
    "modsecurity"
  );
  assert.equal(result.rules[0]?.target, "header");
  assert.equal(result.rules[0]?.action, "block");
  assert.equal(result.rules[1]?.target, "cookie");
  assert.equal(result.rules[1]?.operator, "equals");
  assert.equal(result.rules[1]?.action, "log");
});

test("keeps ModSecurity comparisons per variable and honors explicit transformations", () => {
  const result = parseRuleImport(String.raw`SecRule ARGS|!ARGS:safe "@streq DANGER" "id:4001,deny,t:none"
SecRule REQUEST_BODY "@contains <script>" "id:4002,deny,t:none,t:urlDecode"
SecRule ARGS_POST:message "@streq multipart-needle" "id:4003,deny"`, "modsecurity");
  assert.equal(evaluateRules({ method: "POST", path: "/", query: "?safe=DANGER&value=danger", headers: {},
    body: "%253Cscript%253E" }, result.rules).length, 0);
  assert.equal(evaluateRules({ method: "POST", path: "/", query: "?other=DANGER", headers: {},
    body: "%3Cscript%3E", bodyFields: [["message", "multipart-needle"]] }, result.rules).length, 3);
});
