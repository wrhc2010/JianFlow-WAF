import { createScanner, findNodeAtLocation, getNodeValue, parseTree, type Node, type ParseError } from "jsonc-parser";
import { compileSafeRegex, isIpInCidr, RULE_TRANSFORMS, type WafRule, type RuleVariable, type RuleTransform } from "@jev-waf/core";
import { ValidationError } from "./errors.js";

export const MAX_IMPORT_RULES = 1000;
export const MAX_TOTAL_RULES = 5000;
export const MAX_IMPORT_BYTES = 512 * 1024;
export type RuleImportResult = { rules: WafRule[]; warnings: string[] };
export type RuleImportIssue = { message: string; line: number; column: number; ruleIndex?: number };

export class RuleImportError extends ValidationError {
  readonly issue: RuleImportIssue;
  constructor(message: string, raw: string, offset = 0, ruleIndex?: number) {
    const prefix = raw.slice(0, offset);
    const line = prefix.split("\n").length;
    const column = offset - prefix.lastIndexOf("\n");
    super(`${ruleIndex === undefined ? "" : `第 ${ruleIndex + 1} 条规则：`}${message}（行 ${line}，列 ${column}）`);
    this.issue = { message: this.message, line, column, ...(ruleIndex === undefined ? {} : { ruleIndex: ruleIndex + 1 }) };
  }
}

const targets = ["path", "query", "header", "cookie", "body", "ip", "args", "argNames", "headerNames", "cookieNames", "uri", "method"];
const operators = ["contains", "equals", "regex", "startsWith", "endsWith", "phrase", "cidr", "unsafeUrl"];
const fields = ["id", "name", "source", "category", "severity", "target", "operator", "pattern", "action", "enabled",
  "packageId", "license", "selector", "argumentSource", "variables", "transforms", "normalization", "caseSensitive", "negate"];

export function validateRule(value: unknown): WafRule {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ValidationError("规则必须是对象");
  const item = value as Record<string, unknown>;
  for (const field of Object.keys(item)) {
    if (!fields.includes(field)) throw new ValidationError(`不支持的规则字段：${field}`);
  }
  for (const field of ["id", "name", "target", "operator", "pattern"]) {
    if (typeof item[field] !== "string" || !(item[field] as string).length) throw new ValidationError(`${field} 必须是非空字符串`);
  }
  for (const field of ["name", "source", "category", "packageId", "license", "selector"]) {
    if (item[field] !== undefined && (typeof item[field] !== "string" || !(item[field] as string).trim() || (item[field] as string).length > 512)) {
      throw new ValidationError(`${field} 必须是 1 到 512 字符的字符串`);
    }
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(item.id as string)) throw new ValidationError("id 仅支持 1 到 128 字符的字母、数字、点、冒号、下划线和连字符");
  if (!targets.includes(item.target as string)) throw new ValidationError("target 无效");
  if (!operators.includes(item.operator as string)) throw new ValidationError("operator 无效");
  if ((item.pattern as string).length > 8192) throw new ValidationError("pattern 不能超过 8192 字符");
  for (const [field, allowed] of [
    ["severity", ["low", "medium", "high", "critical"]], ["action", ["block", "log"]],
    ["argumentSource", ["query", "body"]], ["normalization", ["security", "modsecurity"]]
  ] as const) {
    if (item[field] !== undefined && !allowed.includes(item[field] as never)) throw new ValidationError(`${field} 无效`);
  }
  for (const field of ["enabled", "caseSensitive", "negate"]) {
    if (item[field] !== undefined && typeof item[field] !== "boolean") throw new ValidationError(`${field} 必须是布尔值`);
  }
  if (item.transforms !== undefined && (!Array.isArray(item.transforms) || item.transforms.length > 16
    || !item.transforms.every((entry) => RULE_TRANSFORMS.includes(entry)))) throw new ValidationError("transforms 含不支持的转换或超过 16 项");
  if (item.variables !== undefined) {
    if (!Array.isArray(item.variables) || !item.variables.length || item.variables.length > 32) throw new ValidationError("variables 必须包含 1 到 32 项");
    for (const variable of item.variables) {
      if (!variable || typeof variable !== "object" || Array.isArray(variable)
        || Object.keys(variable).some((key) => !["target", "selector", "argumentSource", "exclude"].includes(key))
        || !targets.includes(variable.target)
        || (variable.selector !== undefined && (typeof variable.selector !== "string" || !variable.selector.length || variable.selector.length > 512))
        || (variable.exclude !== undefined && typeof variable.exclude !== "boolean")
        || (variable.argumentSource !== undefined && !["query", "body"].includes(variable.argumentSource))) throw new ValidationError("variables 字段无效");
    }
    if (!item.variables.some((variable) => !variable.exclude)) throw new ValidationError("variables 至少需要一个包含变量");
  }
  if (item.operator === "regex") {
    try { compileSafeRegex(item.pattern as string, item.caseSensitive as boolean | undefined); }
    catch { throw new ValidationError("正则表达式无效或包含 RE2 不支持的回溯、前后查找"); }
  }
  if (item.operator === "cidr" && !(item.pattern as string).split(/[,\s]+/).every((cidr) =>
    Boolean(cidr) && isIpInCidr(cidr.split("/")[0]!, cidr))) throw new ValidationError("CIDR 列表无效");
  return {
    source: "user-import", category: "自定义", severity: "medium", action: "block", enabled: true,
    packageId: "user-import", license: "User supplied", ...item
  } as WafRule;
}

export function parseRuleImport(raw: string, format: "json" | "modsecurity"): RuleImportResult {
  if (!raw.trim()) throw new RuleImportError("规则内容不能为空", raw);
  if (Buffer.byteLength(raw) > MAX_IMPORT_BYTES) throw new RuleImportError("规则文件不能超过 512 KB", raw);
  return format === "json" ? parseJsonRules(raw) : parseModSecurityRules(raw);
}

function uniqueRules(rules: WafRule[], raw: string, offsets: number[]): RuleImportResult {
  if (rules.length > MAX_IMPORT_RULES) throw new RuleImportError("每次最多导入 1000 条规则", raw);
  if (!rules.length) throw new RuleImportError("文件中没有可导入的规则", raw);
  const seen = new Set<string>();
  for (const [index, rule] of rules.entries()) {
    if (seen.has(rule.id)) throw new RuleImportError(`规则 id 重复：${rule.id}`, raw, offsets[index], index);
    seen.add(rule.id);
  }
  return { rules, warnings: [] };
}

function parseJsonRules(raw: string): RuleImportResult {
  const scanner = createScanner(raw, true);
  let depth = 0;
  for (let token = scanner.scan(); token !== 17; token = scanner.scan()) {
    if (token === 1 || token === 3) depth += 1;
    if (token === 2 || token === 4) depth -= 1;
    if (depth > 32) throw new RuleImportError("JSON 嵌套超过 32 层", raw, scanner.getTokenOffset());
  }
  const errors: ParseError[] = [];
  const root = parseTree(raw, errors, { disallowComments: true, allowTrailingComma: false });
  if (errors.length || !root) throw new RuleImportError("JSON 语法无效", raw, errors[0]?.offset);
  const nodes = [root];
  for (let index = 0; index < nodes.length; index += 1) {
    const node = nodes[index]!;
    if (node.type === "object") {
      const seen = new Set<string>();
      for (const property of node.children ?? []) {
        const key = property.children?.[0]?.value as string;
        if (seen.has(key)) throw new RuleImportError(`JSON 字段重复：${key}`, raw, property.offset);
        seen.add(key);
      }
    }
    nodes.push(...(node.children ?? []));
  }
  if (root.type === "object" && root.children?.some((property) => property.children?.[0]?.value !== "rules")) {
    throw new RuleImportError("JSON 包对象仅支持 rules 字段", raw, root.offset);
  }
  const rulesNode = root.type === "array" ? root : findNodeAtLocation(root, ["rules"]);
  if (rulesNode?.type !== "array") throw new RuleImportError("JSON 必须是规则数组或包含 rules 数组的对象", raw);
  if ((rulesNode.children?.length ?? 0) > MAX_IMPORT_RULES) throw new RuleImportError("每次最多导入 1000 条规则", raw);
  const entries = rulesNode.children ?? [];
  const rules = entries.map((node, index) => {
    try { return validateRule(getNodeValue(node)); }
    catch (error) {
      throw new RuleImportError(error instanceof Error ? error.message : "规则无效", raw, fieldOffset(node, error), index);
    }
  });
  return uniqueRules(rules, raw, entries.map((node) => node.offset));
}

function fieldOffset(node: Node, error: unknown): number {
  const field = error instanceof Error ? fields.find((key) => error.message.startsWith(key)) : undefined;
  return (field && findNodeAtLocation(node, [field])?.offset) || node.offset;
}

type LogicalLine = { text: string; offsets: number[] };
function logicalLines(raw: string): LogicalLine[] {
  const lines: LogicalLine[] = [];
  let current: LogicalLine = { text: "", offsets: [] };
  let offset = 0;
  for (const physical of raw.split("\n")) {
    const trimmed = physical.replace(/\r$/, "");
    const continuation = /\\\s*$/.test(trimmed);
    const content = continuation ? trimmed.replace(/\\\s*$/, " ") : trimmed;
    current.text += content;
    for (let index = 0; index < content.length; index += 1) current.offsets.push(offset + index);
    if (!continuation) {
      lines.push(current);
      current = { text: "", offsets: [] };
    }
    offset += physical.length + 1;
  }
  if (current.text.trim()) throw new RuleImportError("未完成的多行续接", raw, current.offsets[0]);
  return lines;
}

function tokens(line: LogicalLine, raw: string): Array<{ value: string; offset: number }> {
  const result: Array<{ value: string; offset: number }> = [];
  let index = 0;
  while (index < line.text.length) {
    while (/\s/.test(line.text[index] ?? "") && index < line.text.length) index += 1;
    if (index >= line.text.length || line.text[index] === "#") break;
    const start = index;
    const quote = line.text[index] === '"' || line.text[index] === "'" ? line.text[index++] : undefined;
    let value = "";
    let closed = !quote;
    while (index < line.text.length) {
      const char = line.text[index++]!;
      if (quote && char === quote) { closed = true; break; }
      if (!quote && /\s/.test(char)) break;
      if (quote && char === "\\" && line.text[index] === quote) value += line.text[index++]!;
      else if (quote && char === "\\" && line.text[index] === "\\") { value += "\\\\"; index += 1; }
      else value += char;
    }
    if (!closed) throw new RuleImportError("引号未闭合", raw, line.offsets[start]);
    result.push({ value, offset: line.offsets[start] ?? 0 });
  }
  return result;
}

function actionParts(input: string): string[] {
  const parts: string[] = [];
  let current = "";
  let quote = "";
  for (let index = 0; index < input.length; index += 1) {
    const char = input[index]!;
    if (char === "\\" && index + 1 < input.length) { current += char + input[++index]; continue; }
    if ((char === "'" || char === '"') && (!quote || quote === char)) quote = quote ? "" : char;
    if (char === "," && !quote) { parts.push(current.trim()); current = ""; }
    else current += char;
  }
  if (quote) throw new ValidationError("action 引号未闭合");
  parts.push(current.trim());
  return parts.filter(Boolean);
}

function actionValue(value: string): string {
  const trimmed = value.trim();
  return /^(['"]).*\1$/s.test(trimmed) ? trimmed.slice(1, -1).replace(/\\(['"])/g, "$1") : trimmed;
}

function modVariable(value: string): RuleVariable {
  const exclude = value.startsWith("!");
  const input = exclude ? value.slice(1) : value;
  const separator = input.indexOf(":");
  const name = (separator < 0 ? input : input.slice(0, separator)).toUpperCase();
  const selector = separator < 0 ? undefined : input.slice(separator + 1);
  const mapped: Record<string, RuleVariable> = {
    ARGS: { target: "args" }, ARGS_NAMES: { target: "argNames" },
    ARGS_GET: { target: "args", argumentSource: "query" }, ARGS_POST: { target: "args", argumentSource: "body" },
    ARGS_GET_NAMES: { target: "argNames", argumentSource: "query" }, ARGS_POST_NAMES: { target: "argNames", argumentSource: "body" },
    REQUEST_HEADERS: { target: "header" }, REQUEST_HEADERS_NAMES: { target: "headerNames" },
    REQUEST_COOKIES: { target: "cookie" }, REQUEST_COOKIES_NAMES: { target: "cookieNames" },
    REQUEST_URI: { target: "uri" }, REQUEST_URI_RAW: { target: "uri" }, REQUEST_FILENAME: { target: "path" },
    REQUEST_BODY: { target: "body" }, REQUEST_METHOD: { target: "method" }, REMOTE_ADDR: { target: "ip" },
    QUERY_STRING: { target: "query" }
  };
  const variable = mapped[name];
  if (!variable || (selector !== undefined && (!selector.length || selector.startsWith("/") ||
    !["args", "argNames", "header", "headerNames", "cookie", "cookieNames"].includes(variable.target)))) {
    throw new ValidationError(`不支持的变量或选择器：${value}`);
  }
  return { ...variable, ...(selector ? { selector } : {}), ...(exclude ? { exclude: true } : {}) };
}

function parseModSecurityRules(raw: string): RuleImportResult {
  const rules: WafRule[] = [];
  const offsets: number[] = [];
  for (const line of logicalLines(raw)) {
    const parsed = tokens(line, raw);
    if (!parsed.length) continue;
    const fail = (message: string, offset = parsed[0]!.offset): never => { throw new RuleImportError(message, raw, offset, rules.length); };
    if (parsed[0]?.value.toLowerCase() !== "secrule" || parsed.length !== 4) fail("仅支持包含变量、operator 和 actions 的 SecRule");
    const subject = parsed[1]!;
    const operation = parsed[2]!;
    const actions = parsed[3]!;
    if (operation.value.includes("%{") || actions.value.includes("%{")) fail("不支持动态宏展开");
    let variables: RuleVariable[];
    try { variables = subject.value.split("|").map(modVariable); } catch (error) { fail((error as Error).message, subject.offset); }
    if (!variables!.some((variable) => !variable.exclude)) fail("至少需要一个包含变量", subject.offset);
    const match = /^(!)?@(\w+)(?:\s+([\s\S]*))?$/.exec(operation.value);
    const operatorName = match?.[2]?.toLowerCase() ?? "rx";
    const operatorMap: Record<string, WafRule["operator"]> = {
      rx: "regex", contains: "contains", streq: "equals", beginswith: "startsWith", endswith: "endsWith",
      pm: "phrase", ipmatch: "cidr"
    };
    const operator = operatorMap[operatorName];
    if (!operator || (!match && /^[!]?@/.test(operation.value))) fail(`不支持的 operator：${operatorName}`, operation.offset);
    const pattern = match ? match[3] ?? "" : operation.value;
    let parts: string[];
    try { parts = actionParts(actions.value); } catch (error) { fail((error as Error).message, actions.offset); }
    const settings = new Map<string, string>();
    let transforms: RuleTransform[] = [];
    const allowed = ["id", "phase", "deny", "block", "pass", "log", "nolog", "auditlog", "noauditlog", "msg", "tag",
      "severity", "rev", "ver", "accuracy", "maturity", "t", "status"];
    for (const part of parts!) {
      const separator = part.indexOf(":");
      const key = (separator < 0 ? part : part.slice(0, separator)).toLowerCase();
      const value = separator < 0 ? "" : actionValue(part.slice(separator + 1));
      if (!allowed.includes(key)) fail(`不支持的 action：${key}`, actions.offset);
      if (key === "t") {
        if (!RULE_TRANSFORMS.includes(value as RuleTransform)) fail(`不支持的转换：${value}`, actions.offset);
        if (value === "none") transforms = [];
        else transforms.push(value as RuleTransform);
      } else {
        if (settings.has(key) && key !== "tag") fail(`action 重复：${key}`, actions.offset);
        settings.set(key, value);
      }
    }
    const id = settings.get("id");
    if (!id || !/^\d+$/.test(id)) fail("id 必须是数字", actions.offset);
    const phase = settings.get("phase") ?? "2";
    if (!["1", "2"].includes(phase)) fail("仅支持请求阶段 phase:1 和 phase:2", actions.offset);
    if (phase === "1" && variables!.some((variable) => variable.target === "body" || variable.argumentSource === "body")) {
      fail("phase:1 不能检查请求体变量", actions.offset);
    }
    if (settings.has("status") && settings.get("status") !== "403") fail("当前仅支持 status:403", actions.offset);
    const blocking = settings.has("deny") || settings.has("block");
    if (blocking && settings.has("pass")) fail("不能同时使用阻断和 pass", actions.offset);
    if (!blocking && !settings.has("pass") && !settings.has("log")) fail("必须显式指定 deny、block、pass 或 log", actions.offset);
    const severity = (settings.get("severity") ?? "WARNING").toUpperCase();
    const severities: Record<string, WafRule["severity"]> = {
      "0": "critical", "1": "critical", "2": "critical", "3": "high", "4": "medium", "5": "low", "6": "low", "7": "low",
      EMERGENCY: "critical", ALERT: "critical", CRITICAL: "critical", ERROR: "high", WARNING: "medium",
      NOTICE: "low", INFO: "low", DEBUG: "low", HIGH: "high", MEDIUM: "medium", LOW: "low"
    };
    if (!severities[severity]) fail("severity 无效", actions.offset);
    try {
      rules.push(validateRule({
        id: `MODSEC-${id}`, name: settings.get("msg") || `ModSecurity ${id}`, source: "ModSecurity import",
        category: settings.get("tag") || "导入规则", severity: severities[severity], target: variables![0]!.target,
        variables: variables!, normalization: "modsecurity", caseSensitive: true, transforms,
        negate: Boolean(match?.[1]), operator, pattern, action: blocking ? "block" : "log",
        enabled: true, packageId: "modsecurity-import", license: "User supplied"
      }));
    } catch (error) { fail((error as Error).message, operation.offset); }
    offsets.push(parsed[0]!.offset);
    if (rules.length > MAX_IMPORT_RULES) fail("每次最多导入 1000 条规则");
  }
  return uniqueRules(rules, raw, offsets);
}
