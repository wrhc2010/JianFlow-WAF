import type { AiDecision } from "@jev-waf/core";
import { config } from "./config.js";

type DecisionsResponse = {
  answers?: Record<string, { noul?: unknown }>;
};

let active = 0;
let windowStarted = Date.now();
let calls = 0;
let failures = 0;
let openUntil = 0;
const siteCalls = new Map<string, number>();
export function aiRuntime() { return { active, calls, limit: config.aiRequestsPerMinute, circuitOpen: openUntil > Date.now() }; }

export async function classifyWithJev(state: string, model: string, timeoutMs: number, siteId = "management"): Promise<AiDecision> {
  const started = performance.now();
  const unavailable = (errorCode: string): AiDecision => ({ model, noul: 0, available: false,
    latencyMs: Math.round(performance.now() - started), error: errorCode, errorCode });
  if (Date.now() - windowStarted >= 60000) { calls = 0; siteCalls.clear(); windowStarted = Date.now(); }
  if (openUntil > Date.now()) return unavailable("circuit_open");
  if (active >= config.aiMaxConcurrent) return unavailable("concurrency_limit");
  if (calls >= config.aiRequestsPerMinute || (siteCalls.get(siteId) ?? 0) >= Math.max(1, Math.ceil(config.aiRequestsPerMinute / 2))) return unavailable("budget_exhausted");
  if (!config.openRouterKey) {
    return {
      model,
      noul: 0,
      latencyMs: Math.round(performance.now() - started),
      available: false,
      error: "JEV_API_KEY/OPENROUTER_API_KEY 未配置", errorCode: "missing_key"
    };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  active += 1;
  let succeeded = false;
  calls += 1;
  siteCalls.set(siteId, (siteCalls.get(siteId) ?? 0) + 1);
  try {
    const baseUrl = config.jevBaseUrl.replace(/\/+$/, "").replace(/\/api\/(?:alpha|v1)\/decisions$/, "");
    const response = await fetch(`${baseUrl}/api/alpha/decisions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.openRouterKey}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:3000",
        "X-Title": "JianFlow WAF"
      },
      body: JSON.stringify({
        model,
        state,
        questions: {
          malicious: {
            type: "noul",
            instructions: "Is this HTTP request malicious or exploitative?"
          }
        }
      }),
      signal: controller.signal
    });
    if (!response.ok) {
      return {
        model,
        noul: 0,
        latencyMs: Math.round(performance.now() - started),
        available: false,
        error: `Provider HTTP ${response.status}`,
        errorCode: response.status === 429 ? "provider_429" : "provider_http"
      };
    }
    const reader = response.body?.getReader();
    if (!reader) return unavailable("invalid_response");
    const chunks: Uint8Array[] = [];
    let bytes = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > 65536) { await reader.cancel(); return unavailable("invalid_response"); }
      chunks.push(part.value);
    }
    let payload: DecisionsResponse;
    try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")) as DecisionsResponse; }
    catch { return unavailable("invalid_response"); }
    const value = payload?.answers?.malicious?.noul;
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
      return {
        model,
        noul: 0,
        latencyMs: Math.round(performance.now() - started),
        available: false,
        error: "Jev 响应缺少合法风险分数",
        errorCode: "invalid_response"
      };
    }
    failures = 0;
    succeeded = true;
    return {
      model,
      noul: value,
      latencyMs: Math.round(performance.now() - started),
      available: true
    };
  } catch (error) {
    return {
      model,
      noul: 0,
      latencyMs: Math.round(performance.now() - started),
      available: false,
      error: controller.signal.aborted ? "AI timeout" : "AI network error",
      errorCode: controller.signal.aborted ? "timeout" : "network"
    };
  } finally {
    clearTimeout(timer);
    active -= 1;
    // A success resets the streak; sustained errors open a short recovery window.
    if (!succeeded && ++failures >= 5) { openUntil = Date.now() + 30000; failures = 0; }
  }
}
