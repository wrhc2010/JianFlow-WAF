import { NginxParser } from "nginx-conf";

type Node = { name: string; value: string; isBlock: boolean; children: Node[] | null };
export type ImportedNginxSite = {
  name: string;
  listenPort: number;
  serverNames: string[];
  upstreamUrl?: string;
  upstreamPool?: Array<{ url: string; weight: number }>;
  redirect?: { statusCode: 301 | 302; location: string };
};

function endpoint(value: string): string {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || url.search || value.includes("$")) throw new Error(`不支持的上游或跳转地址: ${value}`);
  return value;
}

function words(value: string): string[] {
  return (value.match(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s]+/g) ?? []).map((word) => word.replace(/^(["'])(.*)\1$/, "$2"));
}

// nginx-conf handles the tree; this guard rejects unfinished input it otherwise tolerates.
function validateStructure(content: string): void {
  let quote = "", comment = false, pending = false, depth = 0, directives = 0;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i]!;
    if (comment) { if (ch === "\n") comment = false; continue; }
    if (ch === "\\") { i++; pending = true; continue; }
    if (quote) { if (ch === quote) quote = ""; continue; }
    if (ch === "\"" || ch === "'") { quote = ch; pending = true; continue; }
    if (ch === "#") { comment = true; continue; }
    if (ch === "{") { if (!pending || ++depth > 16) throw new Error("配置嵌套无效或过深"); pending = false; directives++; }
    else if (ch === "}") { if (pending || --depth < 0) throw new Error("配置缺少分号或括号不匹配"); }
    else if (ch === ";") { if (!pending) throw new Error("空指令"); pending = false; directives++; }
    else if (!/\s/.test(ch)) pending = true;
    if (directives > 4096) throw new Error("配置最多包含 4096 条指令");
  }
  if (quote || depth || pending) throw new Error("配置包含未结束的字符串、指令或区块");
}

export function previewNginxConfig(content: string): { valid: boolean; sites: ImportedNginxSite[]; warnings: string[]; errors: string[] } {
  const errors: string[] = [], warnings: string[] = [], sites: ImportedNginxSite[] = [];
  try {
    if (typeof content !== "string" || Buffer.byteLength(content) > 1024 * 1024 || content.includes("\0")) throw new Error("配置必须是 1 MB 以内的文本");
    validateStructure(content);
    let tree: Node | undefined;
    new NginxParser().parse(content, (error, result) => { if (error) throw new Error(error.message); tree = result; });
    const root = tree?.children ?? [];
    const blocks = root.flatMap((node) => node.name === "http" && node.isBlock && !node.value ? node.children ?? [] : [node]);
    const pools = new Map<string, Array<{ address: string; weight: number }>>();
    for (const node of blocks) {
      if (node.name !== "server" && node.name !== "upstream" || !node.isBlock) throw new Error(`不支持的 Nginx 指令: ${node.name}`);
      if (node.name !== "upstream") continue;
      if (!/^[A-Za-z_][\w-]*$/.test(node.value) || pools.has(node.value)) throw new Error("upstream 名称无效或重复");
      const nodes = (node.children ?? []).map((entry) => {
        if (entry.name !== "server" || entry.isBlock) throw new Error(`upstream 不支持指令: ${entry.name}`);
        const [address, ...options] = words(entry.value);
        if (!address || options.length > 1 || options.some((option) => !/^weight=\d{1,4}$/.test(option))) throw new Error("upstream server 仅支持地址与 weight");
        endpoint(`http://${address}`);
        const weight = Number(options[0]?.slice(7) ?? 1);
        if (weight < 1 || weight > 1000) throw new Error("上游权重必须为 1 到 1000");
        return { address, weight };
      });
      if (!nodes.length || nodes.length > 32) throw new Error("upstream 必须包含 1 到 32 个节点");
      pools.set(node.value, nodes);
    }
    const ports = new Set<number>();
    for (const server of blocks.filter((node) => node.name === "server")) {
      if (server.value) throw new Error("server 区块不能带参数");
      const children = server.children ?? [];
      const listens = children.filter((node) => node.name === "listen");
      if (listens.length !== 1 || listens[0]!.isBlock || !/^\d{1,5}$/.test(listens[0]!.value)) throw new Error("每个 server 需要一个纯数字 listen 端口");
      const listenPort = Number(listens[0]!.value);
      if (listenPort < 1 || listenPort > 65535 || ports.has(listenPort)) throw new Error("入口端口无效或重复；不支持 Host 路由");
      ports.add(listenPort);
      const names = children.filter((node) => node.name === "server_name");
      if (names.length > 1) throw new Error("server_name 重复");
      const serverNames = words(names[0]?.value ?? "");
      let route: Node | undefined;
      function checkRoute(node: Node): void {
        if (node.isBlock) throw new Error(`不支持的区块: ${node.name} ${node.value}`);
        if (node.name === "proxy_pass" || node.name === "return") {
          if (route) throw new Error("一个入口只能包含一个 proxy_pass 或 return");
          route = node;
        } else if (["proxy_set_header", "proxy_read_timeout", "proxy_connect_timeout"].includes(node.name)) {
          warnings.push(`${node.name} 使用 JianFlow 的安全代理默认值，不直接执行导入值`);
        } else throw new Error(`不支持的 Nginx 指令: ${node.name}`);
      }
      for (const node of children) {
        if (["listen", "server_name"].includes(node.name) && !node.isBlock) continue;
        if (node.name === "location" && node.isBlock && node.value === "/") {
          for (const child of node.children ?? []) checkRoute(child);
        } else checkRoute(node);
      }
      const site: ImportedNginxSite = { name: serverNames[0] ?? `imported-${listenPort}`, listenPort, serverNames };
      if (!route) throw new Error(`端口 ${listenPort} 缺少代理或跳转指令`);
      const selected: Node = route;
      if (selected.name === "return") {
        const [code, location, ...extra] = words(selected.value);
        if (!location || extra.length || !["301", "302"].includes(code ?? "")) throw new Error("return 只支持 301/302 与固定 HTTP(S) URL");
        site.redirect = { statusCode: Number(code) as 301 | 302, location: endpoint(location) };
      } else {
        const [target, ...extra] = words(selected.value);
        if (!target || extra.length) throw new Error("proxy_pass 地址无效");
        const url = new URL(endpoint(target));
        const pool = pools.get(url.hostname);
        if (pool) {
          if (url.port) throw new Error("引用 upstream 时不能指定端口");
          site.upstreamPool = pool.map((node) => ({ url: endpoint(`${url.protocol}//${node.address}${url.pathname === "/" ? "" : url.pathname}`), weight: node.weight }));
          site.upstreamUrl = site.upstreamPool[0]!.url;
        } else site.upstreamUrl = target;
      }
      sites.push(site);
    }
    if (!sites.length) throw new Error("没有发现可导入的 server");
  } catch (error) { errors.push(error instanceof Error ? error.message : "Nginx 配置无效"); }
  return { valid: errors.length === 0, sites: errors.length ? [] : sites, warnings, errors };
}
