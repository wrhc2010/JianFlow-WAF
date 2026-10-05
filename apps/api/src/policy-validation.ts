import { Ajv } from "ajv";
import { defaultPolicy, isIpInCidr, type SitePolicy, type RuleException, type AccessRule } from "@jev-waf/core";
import { ValidationError } from "./errors.js";

const ajv = new Ajv({ allErrors: false, strict: false });
const boundedText = { type: "string", maxLength: 256 };
const ids = { type: "array", maxItems: 500, uniqueItems: true, items: { ...boundedText, minLength: 1 } };
const number = (min: number, max: number) => ({ type: "number", minimum: min, maximum: max });
const integer = (min: number, max: number) => ({ ...number(min, max), type: "integer" });
export const policySchema = {
  type: "object", additionalProperties: false, required: Object.keys(defaultPolicy()),
  properties: {
    enforcement: { enum: ["enforce", "observe"] }, strength: { enum: ["veryLow", "low", "medium", "high", "extreme", "custom"] },
    customThreshold: number(0, 1), disabledRuleIds: ids, aiBehavior: { enum: ["enforce", "shadow"] },
    aiScope: { enum: ["all", "suspicious"] }, aiFailureAction: { enum: ["inherit", "allow", "block"] },
    aiIncompleteAction: { enum: ["local", "block"] }, aiBodyFields: ids,
    rateLimit: { type: "object", additionalProperties: false,
      required: ["enabled", "requestsPerSecond", "burst", "maxConcurrent", "blockSeconds", "paths"],
      properties: { enabled: { type: "boolean" }, action: { enum: ["block", "observe"] }, requestsPerSecond: number(0.1, 10000), burst: integer(1, 10000),
        maxConcurrent: integer(1, 10000), blockSeconds: integer(1, 3600),
        paths: { type: "array", maxItems: 100, items: { type: "object", additionalProperties: false,
          required: ["path", "requestsPerSecond", "burst"], properties: { path: { type: "string", minLength: 1, maxLength: 1024 },
            requestsPerSecond: number(0.1, 10000), burst: integer(1, 10000) } } }
      }
    }
  }
};
const validatePolicy = ajv.compile(policySchema);
export function parsePolicy(value: unknown): SitePolicy {
  if (!validatePolicy(value)) throw new ValidationError(`站点策略无效：${ajv.errorsText(validatePolicy.errors)}`);
  const policy = structuredClone(value as SitePolicy);
  policy.rateLimit.action ??= "block";
  for (const path of policy.rateLimit.paths) validatePath(path.path);
  for (const field of policy.aiBodyFields) validateSelector(field);
  if (new Set(policy.rateLimit.paths.map((entry) => entry.path)).size !== policy.rateLimit.paths.length) throw new ValidationError("限速路径不能重复");
  return policy;
}
function text(value: unknown, label: string, limit = 256): asserts value is string {
  if (typeof value !== "string" || !value.trim() || value.length > limit) throw new ValidationError(`${label}无效`);
}
function validatePath(path: string): void {
  if (!path.startsWith("/") || /[?#\r\n]/.test(path)) throw new ValidationError("路径必须为不含查询串的完整路径");
}
function validateSelector(selector: string): void {
  if (selector.split(/[./]/).some((part) => ["__proto__", "prototype", "constructor"].includes(part))) throw new ValidationError("字段选择器无效");
}
export function parseScopedRule(value: unknown, siteId: string, id: string, kind: "exceptions" | "access-rules"): RuleException | AccessRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ValidationError("配置必须为对象");
  const input = value as Record<string, unknown>;
  const allowed = kind === "exceptions" ? ["name", "method", "path", "target", "selector", "ruleIds", "expiresAt", "reason", "enabled"]
    : ["name", "method", "path", "cidr", "action", "expiresAt", "enabled"];
  if (Object.keys(input).some((key) => !allowed.includes(key))) throw new ValidationError("配置包含未知字段");
  text(input.name, "名称"); text(input.method, "方法", 32); text(input.path, "路径", 1024);
  text(input.expiresAt, "有效期", 64);
  if (!/^(?:\*|[A-Z]+)$/.test(input.method)) throw new ValidationError("HTTP 方法无效");
  if (input.path !== "*") validatePath(input.path);
  if (!Number.isFinite(Date.parse(input.expiresAt))) throw new ValidationError("有效期必须为有效时间");
  if (typeof input.enabled !== "boolean") throw new ValidationError("启用状态无效");
  if (kind === "access-rules") {
    text(input.cidr, "IP/CIDR");
    const [address] = input.cidr.split("/");
    if (!isIpInCidr(address!, input.cidr)) throw new ValidationError("IP/CIDR 无效");
    if (!["block", "skip-detection"].includes(String(input.action))) throw new ValidationError("访问控制动作无效");
  } else {
    if (input.path === "*") throw new ValidationError("例外必须指定完整路径");
    if (!["body", "query", "header", "cookie"].includes(String(input.target))) throw new ValidationError("例外仅支持结构化字段");
    text(input.selector, "字段"); validateSelector(input.selector);
    text(input.reason, "原因", 1024);
    if (!Array.isArray(input.ruleIds) || !input.ruleIds.length || input.ruleIds.length > 100
      || input.ruleIds.some((entry) => typeof entry !== "string" || !entry || entry.length > 256)) throw new ValidationError("规则 ID 无效");
  }
  return { ...input, siteId, id } as RuleException | AccessRule;
}
