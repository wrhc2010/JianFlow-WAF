import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

type Session = { username: string; expiresAt: number };
const sessions = new Map<string, Session>();

function digest(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32);
}

let adminSalt = randomBytes(16);
let adminHash: Buffer | undefined;

export function makeAdminCredential(password: string): { salt: string; hash: string } {
  const salt = randomBytes(16);
  return { salt: salt.toString("base64"), hash: digest(password, salt).toString("base64") };
}

export function configureAdmin(password: string): void {
  const credential = makeAdminCredential(password);
  loadAdminCredential(credential.salt, credential.hash);
}

export function loadAdminCredential(salt: string, hash: string): void {
  const parsedSalt = Buffer.from(salt, "base64");
  const parsedHash = Buffer.from(hash, "base64");
  if (parsedSalt.length < 16 || parsedHash.length !== 32) {
    throw new Error("管理员凭据格式无效");
  }
  adminSalt = parsedSalt;
  adminHash = parsedHash;
}

export function exportAdminCredential(): { salt: string; hash: string } {
  if (!adminHash) {
    throw new Error("管理员密码尚未配置");
  }
  return {
    salt: adminSalt.toString("base64"),
    hash: adminHash.toString("base64")
  };
}

export function hasAdminCredential(): boolean {
  return Boolean(adminHash);
}

export function checkPassword(password: string): boolean {
  if (!adminHash) return false;
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
