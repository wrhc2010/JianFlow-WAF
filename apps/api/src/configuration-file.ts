import { readFile, stat } from "node:fs/promises";
import { Ajv } from "ajv";
import addFormats from "ajv-formats";
import type { FastifyInstance } from "fastify";
import type { Store, AiProfileInput } from "./db/store.js";
import { ValidationError } from "./errors.js";

type Schema = { type: string; required?: string[]; additionalProperties?: boolean; properties: Record<string, object> };
const schemas = new WeakMap<FastifyInstance, Map<string, Schema>>();

export function captureConfigurationSchemas(app: FastifyInstance): void {
  const bodies = new Map<string, Schema>(); schemas.set(app, bodies);
  app.addHook("onRoute", (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    if ((route.url === "/api/v1/settings" && methods.includes("PATCH") || ["/api/v1/sites", "/api/v1/ai-profiles"].includes(route.url) && methods.includes("POST")) && route.schema?.body) bodies.set(route.url, route.schema.body as Schema);
  });
}

export async function applyConfigurationFile(app: FastifyInstance, store: Store, path: string): Promise<void> {
  if (!path) return;
  if ((await stat(path)).size > 4 * 1024 * 1024) throw new ValidationError("配置 JSON 不能超过 4 MB");
  let input: unknown;
  try { input = JSON.parse(await readFile(path, "utf8")); }
  catch { throw new ValidationError("配置文件必须是 UTF-8 JSON"); }
  const bodies = schemas.get(app)!;
  const ajv = new Ajv({ allErrors: true, strict: false }); addFormats.default(ajv);
  const settings = bodies.get("/api/v1/settings")!;
  const profile = bodies.get("/api/v1/ai-profiles")!;
  const site = bodies.get("/api/v1/sites")!;
  const id = { type: "string", minLength: 1, maxLength: 128, pattern: "^[A-Za-z0-9_-]+$" };
  const validate = ajv.compile({ type: "object", additionalProperties: false, properties: {
    settings,
    profiles: { type: "array", maxItems: 100, items: { ...profile, required: [...profile.required!, "id"], properties: { ...profile.properties, id } } },
    sites: { type: "array", maxItems: 1000, items: { ...site, required: [...site.required!, "id"], properties: { ...site.properties, id } } },
  } });
  if (!validate(input)) throw new ValidationError(`配置字段无效：${validate.errors?.map((error) => `${error.instancePath || "/"} ${error.keyword}`).join("；")}`);
  const document = input as { settings?: Parameters<Store["updateSettings"]>[0]; profiles?: AiProfileInput[]; sites?: Array<Parameters<Store["saveSite"]>[0]> };
  for (const list of [document.profiles, document.sites]) {
    if (new Set(list?.map((entry) => entry.id)).size !== (list?.length ?? 0)) throw new ValidationError("配置文件中存在重复 ID");
  }
  if (new Set(document.sites?.map((entry) => entry.listenPort)).size !== (document.sites?.length ?? 0)) throw new ValidationError("配置文件中存在重复入口端口");
  for (const entry of document.sites ?? []) {
    if (entry.id === "default" && entry.listenPort !== store.listSites().find((current) => current.id === "default")?.listenPort) throw new ValidationError("配置文件不能修改默认站点入口端口");
    if (store.listSites().some((current) => current.id !== entry.id && current.listenPort === entry.listenPort)) throw new ValidationError(`配置端口 ${entry.listenPort} 已被现有站点占用`);
  }
  // Startup configuration uses the same encrypted, persistent mutation paths as the console.
  for (const entry of document.profiles ?? []) await store.saveAiProfile(entry);
  if (document.settings) await store.updateSettings(document.settings);
  for (const entry of document.sites ?? []) {
    const current = store.listSites().find((site) => site.id === entry.id);
    await store.saveSite({ ...entry, enabled: entry.enabled ?? current?.enabled ?? true, mode: entry.mode ?? current?.mode ?? "hybrid" });
  }
}
