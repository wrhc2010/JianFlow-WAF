export type ProtectionMode = "ai" | "traditional" | "hybrid";
export type ProtectionStrength = "low" | "medium" | "high" | "extreme" | "custom";
export type DecisionAction = "allow" | "block" | "error";
export type RuleAction = "block" | "log";
export type RuleTarget = "path" | "query" | "header" | "cookie" | "body" | "ip";
export type RuleOperator = "contains" | "equals" | "regex" | "startsWith" | "cidr";

export const STRENGTH_THRESHOLDS: Record<Exclude<ProtectionStrength, "custom">, number> = {
  low: 0.5,
  medium: 0.7,
  high: 0.85,
  extreme: 0.95
};

export type WafRequest = {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body?: string | undefined;
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
      return request.path;
    case "query":
      try {
        return decodeURIComponent(request.query.replace(/\+/g, " "));
      } catch {
        return request.query;
      }
    case "header":
      return Object.entries(request.headers).map(([key, value]) => `${key}: ${value}`).join("\n");
    case "cookie":
      return request.headers.cookie ?? "";
    case "body":
      return request.body ?? "";
    case "ip":
      return request.ip ?? "";
  }
}

function matchesRule(request: WafRequest, rule: WafRule): boolean {
  const value = targetValue(request, rule.target);
  switch (rule.operator) {
    case "contains":
      return value.toLowerCase().includes(rule.pattern.toLowerCase());
    case "equals":
      return value.toLowerCase() === rule.pattern.toLowerCase();
    case "startsWith":
      return value.toLowerCase().startsWith(rule.pattern.toLowerCase());
    case "regex":
      try {
        return new RegExp(rule.pattern, "i").test(value);
      } catch {
        return false;
      }
    case "cidr":
      return value === rule.pattern;
  }
}

export function evaluateRules(request: WafRequest, rules: WafRule[]): RuleMatch[] {
  return rules
    .filter((rule) => rule.enabled && matchesRule(request, rule))
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
const allowedHeader = /^(host|user-agent|content-type|accept|accept-language)$/i;

function sanitizeHeaders(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([key]) => allowedHeader.test(key) || sensitiveField.test(key))
      .map(([key, value]) => [key, sensitiveField.test(key) ? "[REDACTED]" : value])
  );
}

function sanitizeParams(raw: string): string {
  const params = new URLSearchParams(raw.startsWith("?") ? raw.slice(1) : raw);
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
  return "[OMITTED: unsupported body format]";
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

export const BUILTIN_RULES: WafRule[] = [
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
    enabled: true
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
    enabled: true
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
    enabled: true
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
    enabled: true
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
    enabled: true
  }
];
