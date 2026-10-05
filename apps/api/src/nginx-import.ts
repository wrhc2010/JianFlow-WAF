export type ImportedNginxSite = {
  name: string;
  listenPort: number;
  serverNames: string[];
  upstreamUrl?: string;
  redirect?: { statusCode: 301 | 302; location: string };
};

const allowed = new Set(["server", "listen", "server_name", "location", "proxy_pass", "return", "upstream", "proxy_set_header", "proxy_read_timeout", "proxy_connect_timeout"]);

export function previewNginxConfig(content: string): { valid: boolean; sites: ImportedNginxSite[]; warnings: string[]; errors: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  for (const match of content.matchAll(/(^|\s)([a-zA-Z_][\w]*)\s+/gm)) {
    const directive = match[2]!;
    if (!allowed.has(directive)) errors.push(`不支持的 Nginx 指令: ${directive}`);
  }
  const sites: ImportedNginxSite[] = [];
  for (const server of content.split(/\bserver\s*\{/i).slice(1)) {
    const block = server.split("}")[0] ?? "";
    const listen = /\blisten\s+(\d{1,5})\b/.exec(block);
    if (!listen) { warnings.push("server 缺少 listen，已跳过"); continue; }
    const port = Number(listen[1]);
    if (port < 1 || port > 65535) { errors.push(`端口无效: ${port}`); continue; }
    const names = /\bserver_name\s+([^;]+)/.exec(block)?.[1]?.trim().split(/\s+/).filter(Boolean) ?? [];
    const proxy = /\bproxy_pass\s+(https?:\/\/[^;\s]+)/.exec(block)?.[1];
    const redirectMatch = /\breturn\s+(301|302)\s+([^;\s]+)/.exec(block);
    sites.push({ name: names[0] ?? `imported-${port}`, listenPort: port, serverNames: names, ...(proxy ? { upstreamUrl: proxy } : {}), ...(redirectMatch ? { redirect: { statusCode: Number(redirectMatch[1]) as 301 | 302, location: redirectMatch[2]! } } : {}) });
  }
  if (!sites.length && !errors.length) errors.push("没有发现可导入的 server");
  return { valid: errors.length === 0, sites, warnings, errors };
}
