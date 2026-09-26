import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

type Session = { username: string; expiresAt: number };
const sessions = new Map<string, Session>();

function digest(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

const adminSalt = randomBytes(16);
let adminHash: Buffer;

export function configureAdmin(password: string): void {
  adminHash = digest(password, adminSalt);
}

export function checkPassword(password: string): boolean {
  const candidate = digest(password, adminSalt);
  return timingSafeEqual(candidate, adminHash);
}

export function createSession(username: string): string {
  const token = randomBytes(32).toString("hex");
  sessions.set(token, { username, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
  return token;
}

export function getSession(token: string | undefined): Session | undefined {
  if (!token) {
    return undefined;
  }
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(token);
    return undefined;
  }
  return session;
}

export function destroySession(token: string | undefined): void {
  if (token) {
    sessions.delete(token);
  }
}
