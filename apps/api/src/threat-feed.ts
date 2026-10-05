import { isIP } from "node:net";
import { parse } from "csv-parse/sync";

export function validIpEntry(value: string): boolean {
  const parts = value.split("/");
  const version = isIP(parts[0] ?? "");
  return Boolean(version) && parts.length <= 2 && (parts[1] === undefined || /^\d+$/.test(parts[1]) && Number(parts[1]) <= (version === 4 ? 32 : 128));
}

export function parseThreatFeed(content: string, format: "text" | "json" | "csv" | "stix" | "taxii" = "text"): string[] {
  if (Buffer.byteLength(content) > 1024 * 1024) throw new Error("IP 库最多为 1 MB");
  if (format === "json") {
    const value = JSON.parse(content) as unknown;
    const entries = Array.isArray(value) ? value : value && typeof value === "object" && Array.isArray((value as { ips?: unknown }).ips) ? (value as { ips: unknown[] }).ips : [];
    return normalize(entries.filter((entry): entry is string => typeof entry === "string"));
  }
  if (format === "csv") return normalize((parse(content, { bom: true, skip_empty_lines: true, relax_column_count: true, comment: "#" }) as string[][]).map((row) => row[0] ?? ""));
  if (format === "stix" || format === "taxii") {
    const value = JSON.parse(content) as { objects?: unknown[] };
    const result: string[] = [];
    for (const item of value.objects ?? []) {
      if (!item || typeof item !== "object") continue;
      if ((item as { type?: unknown }).type !== "indicator") continue;
      const pattern = String((item as { pattern?: unknown }).pattern ?? "");
      if (/\b(?:NOT|LIKE|MATCHES|FOLLOWEDBY|WITHIN|REPEATS)\b|!=|>=|<=/.test(pattern)) continue;
      for (const match of pattern.matchAll(/(?:ipv4-addr|ipv6-addr):value\s*=\s*['"]([^'"]+)['"]/gi)) result.push(match[1]!);
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
    if (!validIpEntry(item)) continue;
    result.add(prefix === undefined ? item : `${address}/${Number(prefix)}`);
  }
  if (result.size > 5000) throw new Error("IP 库最多包含 5000 个地址或网段");
  return [...result];
}
