import { isIP } from "node:net";

export function parseThreatFeed(content: string, format: "text" | "json" | "csv" | "stix" = "text"): string[] {
  if (format === "json") {
    const value = JSON.parse(content) as unknown;
    const entries = Array.isArray(value) ? value : value && typeof value === "object" && Array.isArray((value as { ips?: unknown }).ips) ? (value as { ips: unknown[] }).ips : [];
    return normalize(entries.filter((entry): entry is string => typeof entry === "string"));
  }
  if (format === "csv") return normalize(content.split(/\r?\n/).map((line) => line.split(",")[0] ?? ""));
  if (format === "stix") {
    const value = JSON.parse(content) as { objects?: unknown[] };
    const result: string[] = [];
    for (const item of value.objects ?? []) {
      if (!item || typeof item !== "object") continue;
      const pattern = String((item as { pattern?: unknown }).pattern ?? "");
      const match = /(?:ipv4-addr|ipv6-addr)(?::value)?\s*[=]?\s*['"]([^'"]+)['"]/i.exec(pattern);
      if (match) result.push(match[1]!);
    }
    return normalize(result);
  }
  return normalize(content.split(/\r?\n/));
}

function normalize(values: string[]): string[] {
  const result = new Set<string>();
  for (const value of values) {
    const item = value.trim().replace(/^['"]|['"]$/g, "");
    if (!item || item.startsWith("#")) continue;
    const [address, prefix] = item.split("/");
    if (!address || !isIP(address)) continue;
    const max = isIP(address) === 4 ? 32 : 128;
    if (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > max)) continue;
    result.add(prefix === undefined ? item : `${address}/${Number(prefix)}`);
  }
  return [...result];
}
