import type { SitePolicy } from "@jev-waf/core";
import { config } from "./config.js";

type Bucket = { tokens: number; updated: number; lastSeen: number; banUntil: number; active: number };
export class TrafficControl {
  private readonly buckets = new Map<string, Bucket>();
  private concurrent = 0;
  private lastSweep = 0;

  snapshot() { return { concurrent: this.concurrent, trackedClients: this.buckets.size, maxTrackedClients: config.maxTrackedClients }; }

  ban(siteId: string, ip: string, seconds: number, now = Date.now()): void {
    if (!ip) return;
    const key = `${siteId}\0${ip}`;
    const current = this.buckets.get(key);
    const bucket = current ?? { tokens: 0, updated: now, lastSeen: now, banUntil: 0, active: 0 };
    bucket.lastSeen = now;
    bucket.banUntil = Math.max(bucket.banUntil, now + Math.max(1, Math.ceil(seconds)) * 1000);
    this.buckets.set(key, bucket);
  }

  isBanned(siteId: string, ip: string, now = Date.now()): number {
    const until = this.buckets.get(`${siteId}\0${ip}`)?.banUntil ?? 0;
    return until > now ? Math.max(1, Math.ceil((until - now) / 1000)) : 0;
  }

  enter(siteId: string, ip: string, path: string, policy: SitePolicy, now = Date.now()): { allowed: boolean; reason?: string; retryAfter?: number; release: () => void } {
    const denied = (reason: string, seconds = 1) => ({ allowed: false, reason, retryAfter: seconds, release: () => {} });
    if (this.concurrent >= config.maxProxyConcurrent) return denied("global_concurrency");
    if (now - this.lastSweep > 10000) {
      for (const [key, bucket] of this.buckets) if (!bucket.active && bucket.banUntil <= now && now - bucket.lastSeen > 120000) this.buckets.delete(key);
      this.lastSweep = now;
    }
    const limits = policy.rateLimit;
    let client: Bucket | undefined;
    if (limits.enabled) {
      const scopes = [{ key: `${siteId}\0${ip}`, rate: limits.requestsPerSecond, burst: limits.burst },
        ...limits.paths.filter((entry) => entry.path === path).map((entry) => ({ key: `${siteId}\0${ip}\0${path}`, rate: entry.requestsPerSecond, burst: entry.burst }))];
      for (const scope of scopes) {
        let bucket = this.buckets.get(scope.key);
        if (!bucket) {
          if (this.buckets.size >= config.maxTrackedClients) return denied("tracked_client_limit");
          bucket = { tokens: scope.burst, updated: now, lastSeen: now, banUntil: 0, active: 0 };
          this.buckets.set(scope.key, bucket);
        }
        bucket.lastSeen = now;
        if (!client) client = bucket;
        if (bucket.banUntil > now) return denied("temporary_ban", Math.max(1, Math.ceil((bucket.banUntil - now) / 1000)));
        bucket.tokens = Math.min(scope.burst, bucket.tokens + Math.max(0, now - bucket.updated) * scope.rate / 1000);
        bucket.updated = now;
        if (bucket.tokens < 1 || client.active >= limits.maxConcurrent) {
          bucket.banUntil = now + limits.blockSeconds * 1000;
          return denied(bucket.tokens < 1 ? "request_rate" : "client_concurrency", limits.blockSeconds);
        }
        bucket.tokens -= 1;
      }
    }
    this.concurrent += 1;
    if (client) client.active += 1;
    let released = false;
    return { allowed: true, release: () => {
      if (released) return;
      released = true;
      this.concurrent -= 1;
      if (client) client.active -= 1;
    } };
  }
}
