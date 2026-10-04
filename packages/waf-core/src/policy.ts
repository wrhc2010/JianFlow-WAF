import type { ProtectionStrength, RuleTarget } from "./index.js";

export type SitePolicy = {
  enforcement: "enforce" | "observe";
  strength: ProtectionStrength;
  customThreshold: number;
  disabledRuleIds: string[];
  aiBehavior: "enforce" | "shadow";
  aiScope: "all" | "suspicious";
  aiFailureAction: "inherit" | "allow" | "block";
  aiIncompleteAction: "local" | "block";
  aiBodyFields: string[];
  rateLimit: {
    enabled: boolean;
    requestsPerSecond: number;
    burst: number;
    maxConcurrent: number;
    blockSeconds: number;
    paths: Array<{ path: string; requestsPerSecond: number; burst: number }>;
  };
};

export type RuleException = {
  id: string;
  siteId: string;
  name: string;
  method: string;
  path: string;
  target: RuleTarget;
  selector: string;
  ruleIds: string[];
  expiresAt: string;
  reason: string;
  enabled: boolean;
};

export type AccessRule = {
  id: string;
  siteId: string;
  name: string;
  cidr: string;
  method: string;
  path: string;
  action: "block" | "skip-detection";
  expiresAt: string;
  enabled: boolean;
};

export function defaultPolicy(): SitePolicy {
  return {
    enforcement: "enforce", strength: "medium", customThreshold: 0.5, disabledRuleIds: [],
    aiBehavior: "enforce", aiScope: "suspicious", aiFailureAction: "inherit",
    aiIncompleteAction: "local", aiBodyFields: [],
    rateLimit: { enabled: false, requestsPerSecond: 20, burst: 40, maxConcurrent: 50, blockSeconds: 10, paths: [] }
  };
}
