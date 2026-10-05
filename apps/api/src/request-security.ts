import type { IncomingMessage } from "node:http";
import { isIpInCidr } from "@jev-waf/core";
import { config } from "./config.js";

export function secureRequest(request: IncomingMessage): boolean {
  if ("encrypted" in request.socket && request.socket.encrypted) return true;
  const remote = request.socket.remoteAddress?.replace(/^::ffff:/i, "");
  return Boolean(remote && config.trustedProxyCidrs.some((cidr) => isIpInCidr(remote, cidr)) && request.headers["x-forwarded-proto"] === "https");
}
