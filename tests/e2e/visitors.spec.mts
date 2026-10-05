import { test as base, expect } from "@playwright/test";
import http from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { defaultPolicy } from "@jev-waf/core";
import { config } from "../../apps/api/src/config.js";
import { Store, type Site } from "../../apps/api/src/db/store.js";
import { createProxyServer } from "../../apps/api/src/proxy.js";

const screenshots = resolve("../verification/v030-browser/screenshots");
type VisitorFixture = {
  url: string;
  store: Store;
  received: Array<{ path: string; cookie: string }>;
  held: Map<string, http.ServerResponse>;
  change: (patch: Partial<Site>) => Promise<void>;
};

const test = base.extend<{ visitor: VisitorFixture }>({
  visitor: async ({}, use) => {
    const previous = { ...config };
    config.databaseUrl = "";
    config.dataDir = resolve("../verification/v030-browser", `visitors-${randomUUID()}`);
    config.environmentApiKey = "";
    config.openRouterKey = "";
    config.adminPassword = "";
    const store = new Store();
    const servers: http.Server[] = [];
    const sockets = new Set<import("node:net").Socket>();
    const received: VisitorFixture["received"] = [];
    const held = new Map<string, http.ServerResponse>();
    async function listen(server: http.Server) {
      servers.push(server);
      server.on("connection", (socket) => {
        sockets.add(socket);
        socket.once("close", () => sockets.delete(socket));
      });
      server.listen(0, "127.0.0.1");
      await once(server, "listening");
      return (server.address() as import("node:net").AddressInfo).port;
    }
    try {
      await store.init();
      const upstream = await listen(http.createServer((request, response) => {
        const path = request.url ?? "/";
        received.push({ path, cookie: request.headers.cookie ?? "" });
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.write(`<!doctype html><html><head><meta charset="utf-8"><link rel="icon" href="data:,"></head><body><h1>Admitted ${path}</h1>`);
        if (path === "/hold" || path === "/first") held.set(path, response);
        else response.end("</body></html>");
      }));
      let site = await store.saveSite({
        name: "Browser visitors", listenPort: 8081, upstreamUrl: `http://127.0.0.1:${upstream}`,
        mode: "traditional", enabled: true,
      });
      const port = await listen(createProxyServer(store, site.listenPort));
      await use({
        url: `http://127.0.0.1:${port}`, store, received, held,
        change: async (patch) => { site = await store.saveSite({ ...site, ...patch }); },
      });
    } finally {
      const closed = [...sockets].filter((socket) => !socket.closed)
        .map((socket) => new Promise<void>((done) => socket.once("close", done)));
      for (const socket of sockets) socket.destroy();
      await Promise.all(servers.map((server) => new Promise<void>((done) => server.close(() => done()))));
      await Promise.all(closed);
      await new Promise<void>((done) => setImmediate(done));
      await store.close();
      Object.assign(config, previous);
    }
  },
});

for (const viewport of [{ width: 1864, height: 828 }, { width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  test(`waiting browsers enter automatically in FIFO order ${viewport.width}`, async ({ browser, visitor }) => {
    await visitor.change({ waitRoom: {
      enabled: true, maxActive: 1, maxQueue: 2, timeoutSeconds: 20,
      page: { source: "inline", statusCode: 429, html: '<h1>Custom waiting room</h1><script>parent.customQueueExecuted=true;fetch("/custom-probe")</script>' },
    } });
    const firstContext = await browser.newContext({ viewport });
    const secondContext = await browser.newContext({ viewport });
    const active = http.get(`${visitor.url}/hold`);
    active.on("error", () => {});
    try {
      await once(active, "response");
      const first = await firstContext.newPage();
      const second = await secondContext.newPage();
      expect((await first.goto(`${visitor.url}/first`))!.status()).toBe(202);
      await expect(first.getByRole("status")).toHaveText("正在排队…");
      await expect(first.frameLocator('iframe[title="等候室"]').getByRole("heading", { name: "Custom waiting room" })).toBeVisible();
      await expect(first.locator('iframe[title="等候室"]')).toHaveAttribute("sandbox", "");
      expect(await first.evaluate(() => Object.hasOwn(window, "customQueueExecuted"))).toBe(false);
      for (const colorScheme of ["light", "dark"] as const) {
        await first.emulateMedia({ colorScheme });
        await first.screenshot({ path: resolve(screenshots, `visitor-queue-${colorScheme}-${viewport.width}.png`) });
      }
      expect(await first.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
      expect((await second.goto(`${visitor.url}/second`))!.status()).toBe(202);
      await expect(second.getByRole("status")).toHaveText("正在排队…");
      expect((await secondContext.request.get(`${visitor.url}/third`, { headers: { accept: "text/html", cookie: "" } })).status()).toBe(429);

      visitor.held.get("/hold")!.end("</body></html>");
      await expect.poll(() => visitor.received.some((request) => request.path === "/first")).toBe(true);
      expect(visitor.received.some((request) => request.path === "/second")).toBe(false);
      await expect(second.getByRole("status")).toHaveText("正在排队…");
      visitor.held.get("/first")!.end("</body></html>");
      await expect(first.getByRole("heading", { name: "Admitted /first" })).toBeVisible();
      await expect(second.getByRole("heading", { name: "Admitted /second" })).toBeVisible();
      expect(visitor.received.map((request) => request.path)).toEqual(["/hold", "/first", "/second"]);
      expect(visitor.received.every((request) => !request.cookie.includes("jf_wait="))).toBe(true);
      expect((await firstContext.request.get(`${visitor.url}/.jianflow/wait/status`)).status()).toBe(410);
    } finally {
      active.destroy();
      await firstContext.close();
      await secondContext.close();
    }
  });

  test(`local challenge click clears a CC ban ${viewport.width}`, async ({ page, visitor }) => {
    await page.setViewportSize(viewport);
    await visitor.store.updateSettings({ captcha: { enabled: true, provider: "local", siteKey: "", secretConfigured: false, trigger: "cc" } });
    const policy = defaultPolicy();
    Object.assign(policy.rateLimit, { enabled: true, requestsPerSecond: 0.1, burst: 1, maxConcurrent: 3, blockSeconds: 60 });
    await visitor.change({ policy });
    await page.context().addCookies([{ name: "ordinary", value: "preserved", url: visitor.url }]);
    expect((await page.goto(`${visitor.url}/`))!.status()).toBe(200);
    expect((await page.goto(`${visitor.url}/after-verification`))!.status()).toBe(403);
    await expect(page.getByRole("button", { name: "验证并继续", exact: true })).toBeVisible();
    for (const colorScheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme });
      await page.screenshot({ path: resolve(screenshots, `visitor-captcha-${colorScheme}-${viewport.width}.png`) });
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const verified = page.waitForResponse((response) => response.url().endsWith("/.jianflow/captcha/verify") && response.request().method() === "POST");
    await page.getByRole("button", { name: "验证并继续", exact: true }).click();
    expect((await verified).status()).toBe(200);
    await expect(page.getByRole("heading", { name: "Admitted /after-verification" })).toBeVisible({ timeout: 30000 });
    const clearance = (await page.context().cookies(visitor.url)).find((cookie) => cookie.name === "jf_clearance");
    expect(clearance).toMatchObject({ httpOnly: true, sameSite: "Lax" });
    expect(await page.evaluate(() => document.cookie)).not.toContain("jf_clearance=");
    const forwarded = visitor.received.find((request) => request.path === "/after-verification")!;
    expect(forwarded.cookie).toContain("ordinary=preserved");
    expect(forwarded.cookie).not.toContain("jf_clearance=");
  });
}

test("waiting browser sees timeout without reaching the upstream", async ({ page, visitor }) => {
  await visitor.change({ waitRoom: { enabled: true, maxActive: 1, maxQueue: 1, timeoutSeconds: 1 } });
  const active = http.get(`${visitor.url}/hold`);
  active.on("error", () => {});
  try {
    await once(active, "response");
    expect((await page.goto(`${visitor.url}/expired`))!.status()).toBe(202);
    await expect(page.getByRole("status")).toHaveText("等待已结束，请刷新重试。");
    expect(visitor.received.map((request) => request.path)).toEqual(["/hold"]);
    expect((await (await page.request.get(`${visitor.url}/.jianflow/wait/status`)).json()).state).toBe("rejected");
  } finally { active.destroy(); }
});
