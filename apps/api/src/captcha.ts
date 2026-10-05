import { createHmac, randomInt, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

type Challenge = { answer: string; expiresAt: number; siteId: string; ip: string };
const challenges = new Map<string, Challenge>();

function sign(value: string): string {
  return createHmac("sha256", config.sessionSecret).update(value).digest("base64url");
}

function encode(value: object): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }

export function createChallenge(siteId: string, ip: string): { challenge: string; question: string; expiresAt: number } {
  const left = randomInt(2, 20);
  const right = randomInt(2, 20);
  const id = `${Date.now().toString(36)}-${randomInt(1_000_000).toString(36)}`;
  const expiresAt = Date.now() + 2 * 60 * 1000;
  challenges.set(id, { answer: String(left + right), expiresAt, siteId, ip });
  return { challenge: id, question: `${left} + ${right} = ?`, expiresAt };
}

export function verifyChallenge(siteId: string, ip: string, challenge: string, answer: string): string | undefined {
  const record = challenges.get(challenge);
  challenges.delete(challenge);
  if (!record || record.expiresAt <= Date.now() || record.siteId !== siteId || record.ip !== ip || record.answer !== answer.trim()) return undefined;
  const payload = { siteId, ip, exp: Date.now() + 10 * 60 * 1000, nonce: challenge };
  const body = encode(payload);
  return `${body}.${sign(body)}`;
}

export function verifyToken(siteId: string, ip: string, token: string): boolean {
  const [body, signature] = token.split(".");
  if (!body || !signature) return false;
  const expected = sign(body);
  if (signature.length !== expected.length || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as { siteId?: string; ip?: string; exp?: number };
    return payload.siteId === siteId && payload.ip === ip && typeof payload.exp === "number" && payload.exp > Date.now();
  } catch { return false; }
}

export function clearChallenges(): void { challenges.clear(); }
