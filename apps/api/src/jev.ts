import type { AiDecision } from "@jev-waf/core";
import { config } from "./config.js";

type DecisionsResponse = {
  answers?: Record<string, { noul?: unknown }>;
};

export async function classifyWithJev(state: string, model: string, timeoutMs: number): Promise<AiDecision> {
  const started = performance.now();
  if (!config.openRouterKey) {
    return {
      model,
      noul: 0,
      latencyMs: Math.round(performance.now() - started),
      available: false,
      error: "OPENROUTER_API_KEY 未配置"
    };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch("https://openrouter.ai/api/alpha/decisions", {
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
        error: `OpenRouter HTTP ${response.status}`
      };
    }
    const payload = await response.json() as DecisionsResponse;
    const value = Number(payload.answers?.malicious?.noul);
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      return {
        model,
        noul: 0,
        latencyMs: Math.round(performance.now() - started),
        available: false,
        error: "Jev 响应缺少合法 noul 概率"
      };
    }
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
      error: error instanceof Error ? error.message : "Jev 请求失败"
    };
  } finally {
    clearTimeout(timer);
  }
}
