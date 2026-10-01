import type { RuleTransform, RuleVariable, WafRequest } from "./index.js";

type NamedValue = { name: string; value: string };

function bodyArguments(request: WafRequest): NamedValue[] {
  if (request.bodyFields) return request.bodyFields.map(([name, value]) => ({ name, value }));
  const body = request.body ?? "";
  const contentType = request.headers["content-type"] ?? "";
  if (/^application\/x-www-form-urlencoded\b/i.test(contentType)) {
    return [...new URLSearchParams(body)].map(([name, value]) => ({ name, value }));
  }
  if (!/^application\/(?:[\w.-]+\+)?json\b/i.test(contentType)) return [];
  try {
    const pending = [{ name: "", value: JSON.parse(body) as unknown }];
    const values: NamedValue[] = [];
    for (let index = 0; index < pending.length && index < 100000; index += 1) {
      const item = pending[index]!;
      if (item.value && typeof item.value === "object") {
        for (const [key, value] of Object.entries(item.value)) {
          pending.push({ name: item.name ? `${item.name}.${key}` : key, value });
        }
      } else {
        values.push({ name: item.name, value: item.value === null ? "" : String(item.value) });
      }
    }
    return values;
  } catch {
    return [];
  }
}

function namedValues(request: WafRequest, variable: RuleVariable): NamedValue[] {
  switch (variable.target) {
    case "args":
    case "argNames": {
      const query = [...new URLSearchParams(request.query.replace(/^\?/, ""))]
        .map(([name, value]) => ({ name, value }));
      return variable.argumentSource === "query" ? query
        : variable.argumentSource === "body" ? bodyArguments(request) : query.concat(bodyArguments(request));
    }
    case "header":
    case "headerNames":
      return Object.entries(request.headers).map(([name, value]) => ({ name, value }));
    case "cookie":
    case "cookieNames":
      return (request.headers.cookie ?? "").split(";").flatMap((cookie) => {
        const separator = cookie.indexOf("=");
        return separator < 0 ? [] : [{ name: cookie.slice(0, separator).trim(), value: cookie.slice(separator + 1).trim() }];
      });
    case "method": return [{ name: "", value: request.method }];
    case "uri": return [{ name: "", value: request.path + (request.query && !request.query.startsWith("?") ? "?" : "") + request.query }];
    case "path": return [{ name: "", value: request.path }];
    case "query": return [{ name: "", value: request.query.replace(/^\?/, "") }];
    case "body": return [{ name: "", value: request.body ?? "" }];
    case "ip": return request.ip ? [{ name: "", value: request.ip }] : [];
  }
}

function selected(name: string, variable: RuleVariable): boolean {
  if (!variable.selector) return true;
  return variable.target === "header" || variable.target === "headerNames"
    ? name.toLowerCase() === variable.selector.toLowerCase() : name === variable.selector;
}

export function variableValues(request: WafRequest, variables: RuleVariable[]): string[] {
  return variables.filter((variable) => !variable.exclude).flatMap((variable) => {
    const values = namedValues(request, variable).filter((item) => selected(item.name, variable)
      && !variables.some((excluded) => excluded.exclude && excluded.target === variable.target
        && (!excluded.argumentSource || excluded.argumentSource === variable.argumentSource)
        && selected(item.name, excluded)));
    return values.map((item) =>
      ["argNames", "headerNames", "cookieNames"].includes(variable.target) ? item.name : item.value);
  });
}

export const RULE_TRANSFORMS: readonly RuleTransform[] = [
  "none", "lowercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode", "compressWhitespace",
  "removeNulls", "replaceNulls", "trim", "trimLeft", "trimRight", "removeWhitespace",
  "normalizePath", "normalizePathWin", "base64Decode", "length"
];

function urlDecode(value: string, unicode: boolean): string {
  const decoded = unicode ? value.replace(/%u([a-f0-9]{4})/gi, (_, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16))) : value;
  return decoded.replace(/\+/g, " ").replace(/(?:%[a-f0-9]{2})+/gi, (run) =>
    Buffer.from(run.replace(/%/g, ""), "hex").toString("utf8"));
}

function htmlDecode(value: string): string {
  return value.replace(/&#(?:x([0-9a-f]{1,6})|(\d{1,7}));?/gi, (raw, hex: string | undefined, decimal: string | undefined) => {
    const code = Number.parseInt(hex ?? decimal ?? "", hex ? 16 : 10);
    return code <= 0x10ffff ? String.fromCodePoint(code) : raw;
  }).replace(/&(lt|gt|quot|apos|amp);/gi, (raw, entity: string) =>
    ({ lt: "<", gt: ">", quot: '"', apos: "'", amp: "&" })[entity.toLowerCase()] ?? raw);
}

function normalizePath(value: string): string {
  const parts: string[] = [];
  for (const part of value.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === ".." && parts.length && parts[parts.length - 1] !== "..") parts.pop();
    else if (part !== ".." || !value.startsWith("/")) parts.push(part);
  }
  return `${value.startsWith("/") ? "/" : ""}${parts.join("/")}${value.endsWith("/") && parts.length ? "/" : ""}`;
}

export function transformValue(input: string, transforms: readonly RuleTransform[]): string {
  let value = input;
  for (const transform of transforms) {
    switch (transform) {
      case "none": break;
      case "lowercase": value = value.toLowerCase(); break;
      case "urlDecode": value = urlDecode(value, false); break;
      case "urlDecodeUni": value = urlDecode(value, true); break;
      case "htmlEntityDecode": value = htmlDecode(value); break;
      case "compressWhitespace": value = value.replace(/\s+/g, " "); break;
      case "removeNulls": value = value.replace(/\0/g, ""); break;
      case "replaceNulls": value = value.replace(/\0/g, " "); break;
      case "trim": value = value.trim(); break;
      case "trimLeft": value = value.trimStart(); break;
      case "trimRight": value = value.trimEnd(); break;
      case "removeWhitespace": value = value.replace(/\s/g, ""); break;
      case "normalizePath": value = normalizePath(value); break;
      case "normalizePathWin": value = normalizePath(value.replace(/\\/g, "/")); break;
      case "base64Decode": value = Buffer.from(value, "base64").toString("utf8"); break;
      case "length": value = String(Buffer.byteLength(value)); break;
    }
  }
  return value;
}
