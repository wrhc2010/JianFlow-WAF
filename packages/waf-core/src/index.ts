import { isIpInCidr, isUnsafeUrl } from "./ip.js";
import { compileSafeRegex } from "./regex.js";
import { transformValue, variableValues } from "./rule-values.js";
export { isIpInCidr } from "./ip.js";
export { compileSafeRegex, MAX_PATTERN_LENGTH } from "./regex.js";
export { RULE_TRANSFORMS } from "./rule-values.js";

export type ProtectionMode = "ai" | "traditional" | "hybrid";
export type ProtectionStrength = "veryLow" | "low" | "medium" | "high" | "extreme" | "custom";
export type DecisionAction = "allow" | "block" | "error";
export type RuleAction = "block" | "log";
export type RuleTarget = "path" | "query" | "header" | "cookie" | "body" | "ip" | "args" | "argNames" | "headerNames" | "cookieNames" | "uri" | "method";
export type RuleOperator = "contains" | "equals" | "regex" | "startsWith" | "endsWith" | "phrase" | "cidr" | "unsafeUrl";
export type RuleTransform = "none" | "lowercase" | "urlDecode" | "urlDecodeUni" | "htmlEntityDecode" | "compressWhitespace"
  | "removeNulls" | "replaceNulls" | "trim" | "trimLeft" | "trimRight" | "removeWhitespace" | "normalizePath" | "normalizePathWin" | "base64Decode" | "length";
export type RuleVariable = { target: RuleTarget; selector?: string; argumentSource?: "query" | "body"; exclude?: boolean };

export const STRENGTH_THRESHOLDS: Record<Exclude<ProtectionStrength, "custom">, number> = {
  veryLow: 0.1,
  low: 0.3,
  medium: 0.5,
  high: 0.7,
  extreme: 0.9
};

export type WafRequest = {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body?: string | undefined;
  bodyFields?: Array<[string, string]>;
  ip?: string | undefined;
  isWebSocketUpgrade?: boolean;
};

export type WafRule = {
  id: string;
  name: string;
  source: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  target: RuleTarget;
  operator: RuleOperator;
  pattern: string;
  action: RuleAction;
  enabled: boolean;
  packageId?: string;
  license?: string;
  selector?: string;
  argumentSource?: "query" | "body";
  variables?: RuleVariable[];
  transforms?: RuleTransform[];
  normalization?: "security" | "modsecurity";
  caseSensitive?: boolean;
  negate?: boolean;
};

export type RuleMatch = {
  ruleId: string;
  name: string;
  category: string;
  severity: WafRule["severity"];
  action: RuleAction;
  target: RuleTarget;
};

export type AiDecision = {
  model: string;
  noul: number;
  latencyMs: number;
  available: boolean;
  error?: string;
};

export type WafDecision = {
  action: DecisionAction;
  mode: ProtectionMode;
  score?: number;
  threshold?: number;
  matchedRules: RuleMatch[];
  reason: string;
  requestId: string;
  ai?: AiDecision;
  partialInspection?: boolean;
};

export type EvaluationSettings = {
  mode: ProtectionMode;
  strength: ProtectionStrength;
  customThreshold: number;
  model: string;
  aiTimeoutMs: number;
  aiBodyLimit: number;
};

export function thresholdFor(settings: Pick<EvaluationSettings, "strength" | "customThreshold">): number {
  if (settings.strength === "custom") {
    return Math.min(1, Math.max(0, settings.customThreshold));
  }
  return STRENGTH_THRESHOLDS[settings.strength];
}

function targetValue(request: WafRequest, target: RuleTarget): string {
  switch (target) {
    case "path":
      return normalizeSecurityText(decodeRepeated(request.path));
    case "query":
      return normalizeSecurityText(decodeRepeated(request.query.replace(/\+/g, " ")));
    case "header":
      return normalizeSecurityText(decodeRepeated(Object.entries(request.headers)
        .map(([key, value]) => `${key}: ${value}`)
        .join("\n")));
    case "cookie":
      return normalizeSecurityText(decodeRepeated(request.headers.cookie ?? ""));
    case "body":
      return normalizeSecurityText(decodeRepeated(bodyInspectionText(request)));
    case "ip":
      return normalizeSecurityText(request.ip ?? "");
    default:
      return variableValues(request, [{ target }]).map((value) => normalizeSecurityText(decodeRepeated(value))).join("\n");
  }
}

export function decodeRepeated(value: string, rounds = 5): string {
  let current = value.normalize("NFKC");
  for (let index = 0; index < rounds; index += 1) {
    const decoded = current
      .replace(/%u([0-9a-f]{4})/gi, (_, code: string) => String.fromCharCode(Number.parseInt(code, 16)))
      .replace(/(?:%[0-9a-f]{2})+/gi, (run) => Buffer.from(run.replace(/%/g, ""), "hex").toString("utf8"))
      .normalize("NFKC");
    if (decoded === current) break;
    current = decoded;
  }
  return current;
}

function bodyInspectionText(request: WafRequest): string {
  const body = request.body ?? "";
  if (/^application\/x-www-form-urlencoded\b/i.test(request.headers["content-type"] ?? "")) {
    return `${body}\n${[...new URLSearchParams(body)].flatMap(([key, value]) => [key, value]).join("\n")}`;
  }
  if (!/\b(?:application\/(?:[\w.-]+\+)?json)\b/i.test(request.headers["content-type"] ?? "")) return body;
  try {
    const queue: unknown[] = [JSON.parse(body)];
    const text = [body];
    for (let index = 0; index < queue.length; index += 1) {
      const value = queue[index];
      if (typeof value === "string") text.push(value);
      else if (Array.isArray(value)) {
        for (const item of value) queue.push(item);
      }
      else if (value && typeof value === "object") {
        for (const [key, item] of Object.entries(value)) {
          text.push(key);
          queue.push(item);
        }
      }
    }
    return text.join("\n");
  } catch {
    return body;
  }
}

export function normalizeSecurityText(value: string): string {
  return value
    .normalize("NFKC")
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060\ufeff]/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/&#(?:x([0-9a-f]{1,6})|(\d{1,7}));?/gi, (raw, hex: string | undefined, decimal: string | undefined) => {
      const code = Number.parseInt(hex ?? decimal ?? "", hex ? 16 : 10);
      return code <= 0x10ffff ? String.fromCodePoint(code) : raw;
    })
    .replace(/&(lt|gt|quot|apos|amp);/gi, (_, entity: string) => ({ lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" })[entity.toLowerCase()] ?? _)
    .replace(/\s+/g, " ");
}

function inspectionValues(request: WafRequest, target: RuleTarget): string[] {
  const value = targetValue(request, target);
  const values = [value];
  if (target === "ip") return values;
  let current = value;
  for (let round = 0; round < 2; round += 1) {
    const decoded: string[] = [];
    for (const match of current.matchAll(/(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/_-])/g)) {
      if (match[0].length > 65536) continue;
      const bytes = Buffer.from(match[0], "base64url");
      if (bytes.length > 0 && bytes.every((byte) => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126))) {
        decoded.push(normalizeSecurityText(decodeRepeated(bytes.toString("utf8"))));
      }
    }
    if (!decoded.length) break;
    current = decoded.join("\n");
    values.push(current);
  }
  return values;
}

function matchesRule(value: string, rule: WafRule): boolean {
  const text = rule.caseSensitive ? value : value.toLowerCase();
  const pattern = rule.caseSensitive ? rule.pattern : rule.pattern.toLowerCase();
  switch (rule.operator) {
    case "contains":
      return text.includes(pattern);
    case "equals":
      return text === pattern;
    case "startsWith":
      return text.startsWith(pattern);
    case "endsWith":
      return text.endsWith(pattern);
    case "phrase":
      return pattern.split(/\s+/).filter(Boolean).some((phrase) => text.includes(phrase));
    case "regex":
      try {
        return compileSafeRegex(rule.pattern, rule.caseSensitive).test(value);
      } catch {
        return false;
      }
    case "cidr":
      return rule.pattern.split(/[,\s]+/).filter(Boolean).some((cidr) => isIpInCidr(value, cidr));
    case "unsafeUrl":
      return isUnsafeUrl(value);
  }
}

export function evaluateRules(request: WafRequest, rules: WafRule[]): RuleMatch[] {
  const values = new Map<RuleTarget, string[]>();
  return rules
    .filter((rule) => {
      if (!rule.enabled) return false;
      if (rule.normalization === "modsecurity" || rule.selector || rule.variables
        || rule.target === "args" || rule.target.endsWith("Names") || rule.target === "method") {
        const variables = rule.variables ?? [{
          target: rule.target, ...(rule.selector ? { selector: rule.selector } : {}),
          ...(rule.argumentSource ? { argumentSource: rule.argumentSource } : {})
        }];
        const inputs = variableValues(request, variables);
        return inputs.some((input) => {
          const value = rule.normalization === "modsecurity" ? input : normalizeSecurityText(decodeRepeated(input));
          const match = matchesRule(transformValue(value, rule.transforms ?? []), rule);
          return rule.negate ? !match : match;
        });
      }
      let target = values.get(rule.target);
      if (!target) {
        target = inspectionValues(request, rule.target);
        values.set(rule.target, target);
      }
      return target.some((value) => {
        const match = matchesRule(transformValue(value, rule.transforms ?? []), rule);
        return rule.negate ? !match : match;
      });
    })
    .map((rule) => ({
      ruleId: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      action: rule.action,
      target: rule.target
    }));
}

function hasBlockingMatch(matches: RuleMatch[]): boolean {
  return matches.some((match) => match.action === "block");
}

const sensitiveField = /auth|api.?key|pass(word|wd)?|pwd|secret|token|session|credential|cookie/i;
function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .map(([key, value]) => [key, sensitiveField.test(key) ? "[REDACTED]" : value])
  );
}

function sanitizeParams(raw: string): string {
  const params = new URLSearchParams(decodeRepeated(raw.startsWith("?") ? raw.slice(1) : raw));
  for (const key of params.keys()) {
    if (sensitiveField.test(key)) params.set(key, "[REDACTED]");
  }
  return params.toString();
}

function sanitizeJson(value: unknown, depth = 0): unknown {
  if (depth > 8) return "[OMITTED: nesting limit]";
  if (Array.isArray(value)) return value.map((item) => sanitizeJson(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, sensitiveField.test(key) ? "[REDACTED]" : sanitizeJson(item, depth + 1)])
    );
  }
  return value;
}

function sanitizeBody(body: string, contentType: string): string {
  if (!body) return "";
  if (/^application\/json\b/i.test(contentType)) {
    try {
      return JSON.stringify(sanitizeJson(JSON.parse(body)));
    } catch {
      return "[OMITTED: invalid JSON]";
    }
  }
  if (/^application\/x-www-form-urlencoded\b/i.test(contentType)) return sanitizeParams(body);
  if (/^(application\/xml|text\/xml|text\/plain|multipart\/form-data)\b/i.test(contentType)) {
    return normalizeSecurityText(body).slice(0, 32768);
  }
  return normalizeSecurityText(body).slice(0, 32768);
}

export function buildAiState(request: WafRequest, bodyLimit: number): string {
  const safeHeaders = sanitizeHeaders(request.headers);
  const body = sanitizeBody((request.body ?? "").slice(0, bodyLimit), request.headers["content-type"] ?? "");
  return JSON.stringify({
    method: request.method,
    path: request.path,
    query: sanitizeParams(request.query),
    headers: safeHeaders,
    body,
    ip: request.ip,
    websocketUpgrade: request.isWebSocketUpgrade ?? false
  });
}

export async function evaluateRequest(
  request: WafRequest,
  rules: WafRule[],
  settings: EvaluationSettings,
  requestId: string,
  classify: (state: string, model: string, timeoutMs: number) => Promise<AiDecision>
): Promise<WafDecision> {
  const matches = settings.mode === "ai" ? [] : evaluateRules(request, rules);
  if (hasBlockingMatch(matches)) {
    return {
      action: "block",
      mode: settings.mode,
      matchedRules: matches,
      reason: "传统规则命中",
      requestId
    };
  }

  if (settings.mode === "traditional") {
    return {
      action: "allow",
      mode: settings.mode,
      matchedRules: matches,
      reason: matches.length > 0 ? "规则仅记录" : "未命中传统规则",
      requestId
    };
  }

  if (settings.mode === "ai" && Buffer.byteLength(request.body ?? "", "utf8") > settings.aiBodyLimit) {
    return {
      action: "error", mode: settings.mode, matchedRules: matches, requestId,
      reason: "请求体超过 AI 完整检测上限", partialInspection: true
    };
  }

  const ai = await classify(buildAiState(request, settings.aiBodyLimit), settings.model, settings.aiTimeoutMs);
  if (!ai.available) {
    if (settings.mode === "ai") {
      return {
        action: "error",
        mode: settings.mode,
        matchedRules: matches,
        reason: "Jev 不可用，AI 模式已阻断",
        requestId,
        ai
      };
    }
    return {
      action: "allow",
      mode: settings.mode,
      matchedRules: matches,
      reason: "Jev 不可用，混合模式按传统规则降级放行",
      requestId,
      ai
    };
  }

  const threshold = thresholdFor(settings);
  const action = ai.noul >= threshold ? "block" : "allow";
  return {
    action,
    mode: settings.mode,
    score: ai.noul,
    threshold,
    matchedRules: matches,
    reason: action === "block" ? "Jev 概率达到拦截阈值" : "Jev 概率低于拦截阈值",
    requestId,
    ai
  };
}

const legacyRules: WafRule[] = [
  {
    id: "CRS-SQL-001",
    name: "SQL 注入关键字",
    source: "OWASP-CRS-subset",
    category: "SQL 注入",
    severity: "high",
    target: "query",
    operator: "regex",
    pattern: "(union\\s+select|sleep\\s*\\(|benchmark\\s*\\(|or\\s+1\\s*=\\s*1|select\\s+.+\\s+from)",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "CRS-XSS-001",
    name: "脚本注入标签",
    source: "OWASP-CRS-subset",
    category: "XSS",
    severity: "high",
    target: "query",
    operator: "regex",
    pattern: "(<script|javascript:|onerror\\s*=|onload\\s*=)",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "CRS-PATH-001",
    name: "路径穿越",
    source: "OWASP-CRS-subset",
    category: "路径穿越",
    severity: "high",
    target: "path",
    operator: "regex",
    pattern: "(\\.\\./|%2e%2e|%252e)",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "JIANFLOW-PATH-002",
    name: "重复斜杠路径规范化绕过",
    source: "JianFlow-Core",
    category: "路径规范化",
    severity: "medium",
    target: "path",
    operator: "regex",
    pattern: "/{2,}",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  },
  {
    id: "CRS-CMD-001",
    name: "命令注入分隔符",
    source: "OWASP-CRS-subset",
    category: "命令注入",
    severity: "critical",
    target: "query",
    operator: "regex",
    pattern: "(;\\s*(cat|curl|wget|bash|sh)\\b|\\|\\s*(cat|curl|wget|bash|sh)\\b)",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "CRS-SCAN-001",
    name: "敏感扫描路径",
    source: "OWASP-CRS-subset",
    category: "扫描器",
    severity: "medium",
    target: "path",
    operator: "regex",
    pattern: "(\\.env|wp-admin|phpmyadmin|actuator/env|\\.git/config)",
    action: "log",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "JIANFLOW-ENC-001",
    name: "多重编码与 Unicode 归一化",
    source: "JianFlow-Core",
    category: "绕过防护",
    severity: "high",
    target: "body",
    operator: "regex",
    pattern: "(union\\s+select|select\\s+.+\\s+from|<script|javascript:|\\.\\./|\\$\\s*(gt|ne|where)|\\{\\{\\s*[^}]+\\}\\})",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  },
  {
    id: "JIANFLOW-HEADER-001",
    name: "请求头注入",
    source: "JianFlow-Core",
    category: "请求头攻击",
    severity: "high",
    target: "header",
    operator: "regex",
    pattern: "(<script|javascript:|union\\s+select|\\b(or|and)\\s+['\"]?\\d+['\"]?\\s*=|\\.\\./)",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  },
  {
    id: "JIANFLOW-URL-001",
    name: "危险 URL 协议与内网目标",
    source: "JianFlow-Core",
    category: "SSRF",
    severity: "critical",
    target: "body",
    operator: "regex",
    pattern: "(file:\\/\\/|gopher:\\/\\/|data:text\\/html|\\bhttps?:\\/\\/(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|169\\.254\\.169\\.254|\\[::1\\]))",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  },
  {
    id: "CRS-XML-001",
    name: "XML 外部实体与脚本",
    source: "OWASP-CRS-subset",
    category: "XML 注入",
    severity: "high",
    target: "body",
    operator: "regex",
    pattern: "(<!DOCTYPE|<!ENTITY|SYSTEM\\s+[\"']|<script|xinclude)",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "CRS-CMD-002",
    name: "命令注入编码变体",
    source: "OWASP-CRS-subset",
    category: "命令注入",
    severity: "critical",
    target: "body",
    operator: "regex",
    pattern: "(;\\s*(?:cat|curl|wget|bash|sh|id|whoami)\\b|\\|\\s*(?:cat|curl|wget|bash|sh|id|whoami)\\b|\\$\\([^)]*(?:cat|curl|wget|bash|sh|id|whoami))",
    action: "block",
    enabled: true,
    packageId: "jianflow-crs-subset",
    license: "Apache-2.0"
  },
  {
    id: "JIANFLOW-COOKIE-001",
    name: "Cookie 注入",
    source: "JianFlow-Core",
    category: "请求头攻击",
    severity: "high",
    target: "cookie",
    operator: "regex",
    pattern: "(<script|javascript:|union\\s+select|\\.\\./|\\{\\{\\s*[^}]+\\}\\})",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  },
  {
    id: "JIANFLOW-URL-002",
    name: "请求参数中的危险 URL",
    source: "JianFlow-Core",
    category: "SSRF",
    severity: "critical",
    target: "query",
    operator: "regex",
    pattern: "(file:\\/\\/|gopher:\\/\\/|data:text\\/html|\\bhttps?:\\/\\/(?:localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|169\\.254\\.169\\.254|\\[::1\\]))",
    action: "block",
    enabled: true,
    packageId: "jianflow-core",
    license: "MIT"
  }
];

const attackPatterns = [
  { id: "SQL", name: "SQL 注入", category: "SQL 注入", pattern: "\\b(?:union\\s+(?:all\\s+)?select|(?:or|and)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|(?:sleep|benchmark|pg_sleep)\\s*\\(|select\\s+.{1,256}?\\s+from)\\b" },
  { id: "XSS", name: "脚本与事件处理器", category: "XSS", pattern: "<\\s*(?:script|iframe|object|embed)\\b|\\b(?:javascript|vbscript)\\s*:|\\bon(?:error|load|click|focus|mouseover)\\s*=" },
  { id: "SSTI", name: "模板表达式注入", category: "SSTI", pattern: "\\{\\{.{1,512}?\\}\\}|\\$\\{.{1,512}?\\}|<%[=]?.{1,512}?%>" },
  { id: "NOSQL", name: "NoSQL 操作符注入", category: "NoSQL 注入", pattern: "\\$(?:gt|gte|lt|lte|ne|where|regex|nin|function|accumulator)\\b" },
  { id: "CMD", name: "命令拼接与替换", category: "命令注入", pattern: "(?:[;|&]|\\$\\(|`)\\s*(?:cat|curl|wget|bash|sh|id|whoami|nc|powershell|cmd(?:\\.exe)?)\\b" },
  { id: "PATH", name: "路径穿越", category: "路径穿越", pattern: "\\.\\.[/\\\\]|%2e%2e|%252e" },
  { id: "XML", name: "XML 外部实体", category: "XML 注入", pattern: "<!\\s*(?:DOCTYPE|ENTITY)\\b|\\bSYSTEM\\s+[\"']|<\\s*(?:xi:)?include\\b" }
];

export const BUILTIN_RULES: WafRule[] = [
  ...legacyRules.map((rule) => ({
    ...rule, source: "JianFlow original · CRS-compatible", packageId: "jianflow-crs-compatible-original", license: "MIT"
  })),
  ...(["path", "query", "header", "cookie", "body"] as const).flatMap((target) => [
    ...attackPatterns.map((attack): WafRule => ({
      id: `JIANFLOW-${attack.id}-${target.toUpperCase()}`,
      name: `${attack.name} · ${target}`, source: "JianFlow original", category: attack.category,
      severity: "high", target, operator: "regex", pattern: attack.pattern, action: "block",
      enabled: true, packageId: "jianflow-original", license: "MIT"
    })),
    {
      id: `JIANFLOW-SSRF-${target.toUpperCase()}`, name: `危险协议与内网 URL · ${target}`,
      source: "JianFlow original", category: "SSRF", severity: "critical", target,
      operator: "unsafeUrl", pattern: "non-public-destinations", action: "block", enabled: true,
      packageId: "jianflow-original", license: "MIT"
    } satisfies WafRule
  ])
];
