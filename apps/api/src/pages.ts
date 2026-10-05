import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { config } from "./config.js";
import { ValidationError } from "./errors.js";
import type { PageConfig } from "./db/store.js";

export const MAX_PAGE_BYTES = 512 * 1024;

export function validateHtml(body: Uint8Array): string {
  if (!body.length || body.length > MAX_PAGE_BYTES) throw new ValidationError("HTML 文件必须在 1 字节到 512 KB 之间");
  try {
    const html = new TextDecoder("utf-8", { fatal: true }).decode(body);
    if (html.includes("\0")) throw new Error("NUL");
    return html;
  } catch { throw new ValidationError("HTML 文件必须使用 UTF-8 编码且不能包含 NUL"); }
}

export function readStaticPage(page: PageConfig | undefined): string | undefined {
  if (!page || page.source === "default") return undefined;
  if (page.source === "inline") {
    try { return validateHtml(Buffer.from(page.html ?? "", "utf8")); } catch { return undefined; }
  }
  let descriptor: number | undefined;
  try {
    if (!page.filePath || isAbsolute(page.filePath) || !page.filePath.toLowerCase().endsWith(".html")) return undefined;
    const root = realpathSync(config.pagesDir || resolve(config.dataDir, "pages"));
    const target = realpathSync(resolve(root, page.filePath));
    const relation = relative(root, target);
    if (isAbsolute(relation) || relation === ".." || relation.startsWith(`..${sep}`)) return undefined;
    descriptor = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > MAX_PAGE_BYTES) return undefined;
    return validateHtml(readFileSync(descriptor));
  } catch { return undefined; }
  finally { if (descriptor !== undefined) closeSync(descriptor); }
}

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]!);
}

export function defaultPage(title: string, message: string, content = ""): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{margin:0;background:#f3f6f5;color:#19352e;font:16px/1.6 system-ui,sans-serif}main{max-width:620px;margin:12vh auto;padding:32px}h1{font-size:28px}p{color:#536b62}button{background:#168a63;color:white;border:0;border-radius:8px;padding:12px 20px;cursor:pointer}small{color:#65786e}@media(prefers-color-scheme:dark){body{background:#161d1b;color:#e5eee9}p,small{color:#a0b5a9}}</style></head><body><main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>${content}</main></body></html>`;
}
