import { defineConfig } from "@playwright/test";
import { resolve } from "node:path";

const verification = resolve("../verification/v030-browser");
export default defineConfig({
  testDir: "./tests/e2e",
  workers: 1,
  timeout: 45000,
  expect: { timeout: 8000 },
  reporter: "list",
  outputDir: resolve(verification, "results"),
  use: { channel: process.env.CI ? "chromium" : "chrome", baseURL: "http://127.0.0.1:13100", trace: "retain-on-failure" },
  webServer: [
    {
      command: "node --import tsx apps/api/src/server.ts",
      url: "http://127.0.0.1:14100/api/v1/health",
      reuseExistingServer: false,
      env: {
        NODE_ENV: "test", API_HOST: "127.0.0.1", API_PORT: "14100", PROXY_HOST: "127.0.0.1", PROXY_PORT: "18100", SITE_PORT_RANGE: "18100-18109",
        DATA_DIR: resolve(verification, `data-${Date.now()}`), DATABASE_URL: "", POSTGRES_HOST: "", POSTGRES_PASSWORD: "", POSTGRES_PASSWORD_FILE: "",
        JEV_API_KEY: "", OPENROUTER_API_KEY: "", CAPTCHA_ENABLED: "false", CAPTCHA_SECRET_KEY: "", ADMIN_PASSWORD: "Browser-test-password-2026", SESSION_COOKIE_SECURE: "false", UPSTREAM_URL: "http://127.0.0.1:19999",
      },
    },
    { command: "npm run dev -w apps/web -- --host 127.0.0.1 --port 13100 --strictPort", url: "http://127.0.0.1:13100", reuseExistingServer: false, env: { VITE_API_PROXY: "http://127.0.0.1:14100" } },
  ],
});
