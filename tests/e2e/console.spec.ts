import { test, expect, type Page } from "@playwright/test";
import { resolve } from "node:path";

const screenshots = resolve("../verification/v030-browser/screenshots");
async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("管理员账号").fill("admin");
  await page.getByLabel("管理员密码", { exact: true }).fill("Browser-test-password-2026");
  await page.getByRole("button", { name: "进入控制台" }).click();
  await expect(page.locator(".app-shell")).toBeVisible();
}

for (const viewport of [{ width: 1864, height: 828 }, { width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  test(`themes and fixed navigation ${viewport.width}x${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await login(page);
    await page.getByRole("button", { name: "防护策略", exact: true }).click();
    await expect(page.getByRole("button", { name: "保存策略" })).toBeVisible();
    await expect(page.locator(".threshold-reference")).toHaveCount(0);
    await expect(page.locator(".mode-option").filter({ hasText: "混合模式" })).toBeDisabled();
    await expect(page.locator(".mode-option").filter({ hasText: "AI 判断" })).toBeDisabled();
    const sidebar = await page.locator(".sidebar").boundingBox();
    expect(Math.round(sidebar!.height)).toBe(viewport.height);
    await page.locator(".main-area").evaluate((element) => { element.scrollTop = element.scrollHeight; });
    expect(await page.evaluate(() => window.scrollY)).toBe(0);
    expect(await page.locator(".sidebar").evaluate((element) => element.scrollTop)).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.locator(".main-area").evaluate((element) => { element.scrollTop = 0; });
    await page.screenshot({ path: resolve(screenshots, `settings-light-${viewport.width}.png`) });
    await page.getByRole("button", { name: "折叠导航", exact: true }).click();
    await expect(page.locator(".sidebar .nav-list .nav-item span")).toHaveCount(0);
    await page.getByRole("button", { name: "切换深色模式", exact: true }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.screenshot({ path: resolve(screenshots, `settings-dark-collapsed-${viewport.width}.png`) });
    await page.reload();
    await expect(page.locator(".sidebar")).toHaveClass(/collapsed/);
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.getByRole("button", { name: "站点与上游", exact: true }).click();
    await expect(page.locator(".site-card").first()).toBeVisible();
    await page.screenshot({ path: resolve(screenshots, `sites-dark-${viewport.width}.png`) });
    await page.getByRole("button", { name: "新建站点", exact: true }).click();
    const editor = page.getByRole("dialog", { name: "新建站点", exact: true });
    await expect(editor).toBeVisible();
    await page.screenshot({ path: resolve(screenshots, `site-editor-${viewport.width}.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await editor.getByRole("button", { name: "取消", exact: true }).click();
  });
}

test("settings cancel is local, save persists and captcha secrets stay private", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "防护策略", exact: true }).click();
  const before = await page.getByLabel("Jev 模型", { exact: true }).inputValue();
  const writes: string[] = [];
  page.on("request", (request) => { if (request.method() === "PATCH") writes.push(request.url()); });
  const cc = page.getByRole("combobox", { name: "CC 超限处理", exact: true });
  await expect(cc).toHaveValue("block");
  await cc.selectOption("observe");
  await page.getByLabel("Jev 模型", { exact: true }).fill("draft-only");
  await page.getByRole("button", { name: "取消更改", exact: true }).click();
  await expect(page.getByLabel("Jev 模型", { exact: true })).toHaveValue(before);
  await expect(cc).toHaveValue("block");
  expect(writes).toHaveLength(0);
  await cc.selectOption("observe");
  await page.getByLabel("Jev 模型", { exact: true }).fill("saved-model");
  await page.getByRole("button", { name: "保存策略", exact: true }).click();
  await expect(page.getByText("策略已保存", { exact: true })).toBeVisible();
  expect(writes.filter((url) => url.endsWith("/settings"))).toHaveLength(1);
  expect((await (await page.request.get("/api/v1/settings")).json()).defaultPolicy.rateLimit.action).toBe("observe");
  await page.getByRole("button", { name: "新增 Profile", exact: true }).click();
  const profile = page.getByRole("dialog", { name: "编辑 API Profile" });
  await profile.getByLabel("名称", { exact: true }).fill("Browser Profile");
  await profile.getByLabel("Base URL", { exact: true }).fill("http://127.0.0.1:19999");
  await profile.getByLabel("模型", { exact: true }).fill("independent-model");
  await profile.getByLabel("API Key", { exact: true }).fill("browser-private-key");
  await page.screenshot({ path: resolve(screenshots, "profile-editor.png") });
  await profile.getByRole("button", { name: "保存 Profile", exact: true }).click();
  await expect(profile).toBeHidden();
  const response = await page.request.get("/api/v1/ai-profiles");
  expect(await response.text()).not.toContain("browser-private-key");
  await expect(page.locator(".mode-option").filter({ hasText: "混合模式" })).toBeEnabled();
  const row = page.locator(".profile-row").filter({ hasText: "Browser Profile" });
  await row.getByRole("button", { name: "编辑 Profile" }).click();
  await profile.getByLabel("保存时移除 Key").check();
  await profile.getByRole("button", { name: "保存 Profile", exact: true }).click();
  await expect(profile).toBeHidden();
  await expect(page.locator(".mode-option").filter({ hasText: "混合模式" })).toBeDisabled();
});

test("Profile drafts cancel without writes and keyboard focus stays in the dialog", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "防护策略", exact: true }).click();
  const writes: string[] = [];
  page.on("request", (request) => {
    if (["POST", "PATCH", "DELETE"].includes(request.method()) && request.url().includes("/ai-profiles")) writes.push(request.url());
  });
  const add = page.getByRole("button", { name: "新增 Profile", exact: true });
  await add.click();
  const dialog = page.getByRole("dialog", { name: "编辑 API Profile" });
  await dialog.getByLabel("名称", { exact: true }).fill("Cancelled Profile");
  await dialog.getByLabel("API Key", { exact: true }).fill("never-submitted-secret");
  await dialog.getByRole("button", { name: "保存 Profile", exact: true }).focus();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: "关闭", exact: true })).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(dialog.getByRole("button", { name: "保存 Profile", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(add).toBeFocused();
  expect(writes).toHaveLength(0);
  const row = page.locator(".profile-row").first();
  const edit = row.getByRole("button", { name: "编辑 Profile" });
  await edit.click();
  await dialog.getByLabel("模型", { exact: true }).fill("cancelled-model");
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  await expect(edit).toBeFocused();
  expect(writes).toHaveLength(0);
  expect(await (await page.request.get("/api/v1/ai-profiles")).text()).not.toContain("cancelled-model");
});

test("GeoIP files stay local until saved and nginx import requires preview", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "防护策略", exact: true }).click();
  const geo = page.locator(".geoip-fields");
  const uploads: string[] = [];
  page.on("request", (request) => { if (request.method() === "PUT") uploads.push(request.url()); });
  const fixture = resolve("apps/api/test/fixtures/GeoIP2-City-Test.mmdb");
  await geo.locator("input[type=file]").setInputFiles(fixture);
  await geo.getByRole("button", { name: "取消", exact: true }).click();
  expect(uploads).toHaveLength(0);
  await geo.locator("input[type=file]").setInputFiles(fixture);
  await geo.getByRole("button", { name: "保存 GeoIP", exact: true }).click();
  await expect(geo.getByRole("status")).toHaveText("GeoIP 已更新");
  expect(uploads).toHaveLength(1);
  await page.screenshot({ path: resolve(screenshots, "geoip-saved.png") });
  await page.getByRole("button", { name: "站点与上游", exact: true }).click();
  const section = page.locator(".nginx-import-section");
  await section.locator("summary").click();
  await section.getByLabel("Nginx 配置内容").fill('server { listen 18109; server_name browser-import.example; return 302 https://example.com/new; }');
  await expect(section.getByRole("button", { name: "确认导入" })).toBeDisabled();
  await section.getByRole("button", { name: "预览站点" }).click();
  await expect(section.getByRole("button", { name: "确认导入" })).toBeEnabled();
  const before = (await (await page.request.get("/api/v1/sites")).json()).data;
  expect(before.some((site: { listenPort: number }) => site.listenPort === 18109)).toBe(false);
  await section.getByRole("button", { name: "确认导入" }).click();
  await expect(page.locator(".site-card").filter({ hasText: "browser-import.example" })).toBeVisible();
  await expect(section.getByLabel("导入历史")).toBeVisible();
  const imported = (await (await page.request.get("/api/v1/sites")).json()).data.find((site: { listenPort: number }) => site.listenPort === 18109);
  expect((await page.request.get("http://127.0.0.1:18109/", { maxRedirects: 0 })).status()).toBe(302);
  await page.request.delete(`/api/v1/sites/${imported.id}`);
});

for (const viewport of [{ width: 1864, height: 828 }, { width: 1440, height: 1000 }, { width: 390, height: 844 }]) {
  test(`3D scene renders, moves and responds to drag ${viewport.width}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await login(page);
    await page.getByRole("button", { name: "攻击大屏", exact: true }).click();
    await page.getByRole("button", { name: /3D/ }).click();
    const canvas = page.locator(".globe-stage canvas");
    await expect(canvas).toBeVisible();
    const pixels = () => canvas.evaluate((element: HTMLCanvasElement) => {
      const gl = element.getContext("webgl2")!;
      const data = new Uint8Array(gl.drawingBufferWidth * gl.drawingBufferHeight * 4);
      gl.readPixels(0, 0, gl.drawingBufferWidth, gl.drawingBufferHeight, gl.RGBA, gl.UNSIGNED_BYTE, data);
      let visible = 0, hash = 0;
      for (let index = 0; index < data.length; index += 4) {
        if (data[index + 3]! > 0 && data[index]! + data[index + 1]! + data[index + 2]! > 15) visible++;
        hash = (hash * 31 + data[index]! + data[index + 1]! * 2) >>> 0;
      }
      return { visible, hash, width: gl.drawingBufferWidth, height: gl.drawingBufferHeight };
    });
    await expect.poll(async () => (await pixels()).visible).toBeGreaterThan(1000);
    const first = await pixels();
    await expect.poll(async () => (await pixels()).hash).not.toBe(first.hash);
    const box = await canvas.boundingBox();
    expect(box!.width).toBeGreaterThan(200);
    await canvas.scrollIntoViewIfNeeded();
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
    await page.mouse.down();
    await page.mouse.move(box!.x + box!.width / 2 + 60, box!.y + box!.height / 2 - 30, { steps: 6 });
    await page.mouse.up();
    await expect.poll(async () => (await pixels()).hash).not.toBe(first.hash);
    await page.screenshot({ path: resolve(screenshots, `attack-globe-${viewport.width}.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test("site create, custom HTML draft, edit, toggle and delete", async ({ page }) => {
  await login(page);
  await page.getByRole("button", { name: "站点与上游", exact: true }).click();
  await page.getByRole("button", { name: "新建站点", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "新建站点", exact: true });
  await dialog.getByLabel("站点名称", { exact: true }).fill("Browser Site");
  await dialog.getByLabel("默认上游地址", { exact: true }).fill("http://127.0.0.1:19999");
  await dialog.getByRole("combobox", { name: "运行模式", exact: true }).selectOption("maintenance");
  await dialog.getByLabel("启用等候室", { exact: true }).check();
  await dialog.getByLabel("活动上限", { exact: true }).fill("2");
  await dialog.getByLabel("队列上限", { exact: true }).fill("3");
  await dialog.getByLabel("等待超时", { exact: true }).fill("10");
  await dialog.getByRole("tab", { name: "限速", exact: true }).click();
  await dialog.getByLabel("继承全局默认", { exact: false }).uncheck();
  await dialog.getByRole("combobox", { name: "CC 超限处理", exact: true }).selectOption("block");
  await page.screenshot({ path: resolve(screenshots, "site-cc-editor.png") });
  await dialog.getByRole("tab", { name: "页面", exact: true }).click();
  const maintenance = dialog.locator("fieldset").filter({ has: page.locator("legend", { hasText: "维护页面" }) });
  await maintenance.getByRole("combobox", { name: "页面来源", exact: true }).selectOption("inline");
  await maintenance.locator("input[type=file]").setInputFiles({ name: "maintenance.html", mimeType: "text/html", buffer: Buffer.from('<!doctype html><h1>Browser maintenance</h1>') });
  await expect(maintenance.locator("iframe")).toBeVisible();
  await dialog.getByRole("button", { name: "保存站点", exact: true }).click();
  await expect(dialog).toBeHidden();
  const card = page.locator(".site-card").filter({ hasText: "Browser Site" });
  await expect(card).toBeVisible();
  await expect(card.getByText("维护模式", { exact: true })).toBeVisible();
  const sites = (await (await page.request.get("/api/v1/sites")).json()).data;
  const site = sites.find((entry: { name: string }) => entry.name === "Browser Site");
  expect(site.waitRoom).toMatchObject({ enabled: true, maxActive: 2, maxQueue: 3, timeoutSeconds: 10 });
  expect(site.policy.rateLimit.action).toBe("block");
  const maintenanceResponse = await page.request.get(`http://127.0.0.1:${site.listenPort}/`);
  expect(maintenanceResponse.status()).toBe(503);
  expect(await maintenanceResponse.text()).toContain("Browser maintenance");
  await card.getByRole("button", { name: "编辑站点", exact: true }).click();
  const edit = page.getByRole("dialog", { name: "编辑站点", exact: true });
  await edit.getByLabel("站点名称", { exact: true }).fill("Cancelled Site");
  page.once("dialog", (confirm) => confirm.accept());
  await edit.getByRole("button", { name: "取消", exact: true }).click();
  await expect(card).toBeVisible();
  await expect(card.getByRole("button", { name: "编辑站点", exact: true })).toBeFocused();
  await card.getByRole("button", { name: "停用站点" }).click();
  await expect(card.getByText("已停用", { exact: true })).toBeVisible();
  await card.getByRole("button", { name: "启用站点" }).click();
  await expect(card.getByText("运行中", { exact: true })).toBeVisible();
  page.once("dialog", (confirm) => confirm.accept());
  await card.getByRole("button", { name: "删除站点" }).click();
  await expect(card).toBeHidden();
});
