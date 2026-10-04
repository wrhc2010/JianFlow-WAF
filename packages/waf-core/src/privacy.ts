import type { WafRequest } from "./index.js";

export const sensitiveField = /auth|api.?key|pass(word|wd)?|pwd|secret|token|session|credential|cookie|credit.?card|ssn/i;
export function mediaType(value: string): string {
  return value.split(";", 1)[0]!.trim().toLowerCase();
}
export function isJsonType(value: string): boolean {
  return /^application\/(?:[\w.-]+\+)?json$/.test(mediaType(value));
}
function fieldSensitive(path: string): boolean {
  let decoded = path;
  for (let round = 0; round < 5; round += 1) {
    try { const next = decodeURIComponent(decoded); if (next === decoded) break; decoded = next; } catch { break; }
  }
  return decoded.normalize("NFKC").split(/[./\[\]]/).some((part) => sensitiveField.test(part));
}
function safeValue(value: string): string {
  return value.replace(/\b(Bearer|Basic)\s+[^\s]+/gi, "$1 [REDACTED]")
    .replace(/([?&](?:[^=&]*(?:token|secret|password|api.?key|session)[^=&]*)=)[^&#\s]*/gi, "$1[REDACTED]")
    .replace(/(https?:\/\/)[^/\s@]+@/gi, "$1[REDACTED]@");
}
export function safeParams(raw: string): string {
  const params = new URLSearchParams(raw.replace(/^\?/, ""));
  return [...params].map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(
    fieldSensitive(key) ? "[REDACTED]" : safeValue(value)
  )}`).join("&");
}
export function safeRequestPath(raw: string): string {
  const index = raw.indexOf("?");
  const path = (index < 0 ? raw : raw.slice(0, index)).split("/").map((part, position, parts) =>
    position > 0 && fieldSensitive(parts[position - 1] ?? "") ? "[REDACTED]" : safeValue(part)
  ).join("/");
  return `${path}${index < 0 ? "" : `?${safeParams(raw.slice(index + 1))}`}`.slice(0, 8192);
}
function cleanJson(value: unknown, allowFields: string[] | undefined, coverage: { omitted: boolean }, path = "", depth = 0): unknown {
  if (depth > 32) { coverage.omitted = true; return "[OMITTED: nesting limit]"; }
  if (fieldSensitive(path)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item, index) => cleanJson(item, allowFields, coverage, `${path}${path ? "." : ""}${index}`, depth + 1));
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const patchSensitive = typeof record.path === "string" && fieldSensitive(record.path)
      || typeof record.from === "string" && fieldSensitive(record.from);
    return Object.fromEntries(Object.entries(record).map(([key, item]) => [key,
      patchSensitive && key === "value" ? "[REDACTED]" : cleanJson(item, allowFields, coverage, path ? `${path}.${key}` : key, depth + 1)
    ]));
  }
  if (allowFields && !allowFields.includes("*") && !allowFields.some((field) => path === field || path.startsWith(`${field}.`))) {
    coverage.omitted = true;
    return "[OMITTED]";
  }
  return typeof value === "string" ? safeValue(value) : value;
}

export type AiInspectionState = { state: string; complete: boolean; omittedReason?: string };
export function buildAiInspection(request: WafRequest, bodyLimit: number, allowFields?: string[]): AiInspectionState {
  let body = "";
  let omittedReason: string | undefined;
  const raw = request.body ?? "";
  const type = mediaType(request.headers["content-type"] ?? "");
  if (raw) {
    if (isJsonType(type)) {
      try {
        const coverage = { omitted: false };
        body = JSON.stringify(cleanJson(JSON.parse(raw), allowFields, coverage));
        if (coverage.omitted) omittedReason = "field_policy";
      } catch { omittedReason = "invalid_json"; }
    } else if (type === "application/x-www-form-urlencoded") {
      const params = new URLSearchParams(raw);
      if (allowFields && !allowFields.includes("*")) {
        for (const key of [...params.keys()]) if (!allowFields.includes(key)) { params.delete(key); omittedReason = "field_policy"; }
      }
      body = safeParams(params.toString());
    } else {
      omittedReason = "unsupported_body_type";
    }
    if (Buffer.byteLength(body) > bodyLimit || Buffer.byteLength(raw) > bodyLimit) {
      body = isJsonType(type) ? JSON.stringify({ omitted: "body_limit" }) : "";
      omittedReason = "body_limit";
    }
  }
  const headers = Object.fromEntries(Object.entries(request.headers).map(([key, value]) => [key,
    fieldSensitive(key) ? "[REDACTED]" : /^(host|content-type|content-length|accept|user-agent)$/i.test(key)
      ? safeValue(value).slice(0, 1024) : "[OMITTED]"
  ]));
  return {
    state: JSON.stringify({ method: request.method, path: safeRequestPath(request.path), query: safeParams(request.query),
      headers, body, ip: request.ip, websocketUpgrade: request.isWebSocketUpgrade ?? false }),
    complete: !omittedReason, ...(omittedReason ? { omittedReason } : {})
  };
}

export function safeSnippet(value: string, field: string): string {
  if (fieldSensitive(field)) return "[REDACTED]";
  // Retain only recognized attack syntax, never surrounding business values.
  if (/union\s+(?:all\s+)?select/i.test(value)) return "UNION SELECT [OMITTED]";
  if (/\{\{[\s\S]*?\}\}/.test(value)) return "{{ [OMITTED] }}";
  if (/<script\b/i.test(value)) return "<script>[OMITTED]</script>";
  if (/(?:\.\.\/|\.\.\\)/.test(value)) return "../[OMITTED]";
  const scheme = /\b(file|gopher|dict):\/\//i.exec(value);
  if (scheme) return `${scheme[1]!.toLowerCase()}://[OMITTED]`;
  return value ? "[MATCHED: content omitted]" : "[EMPTY]";
}
