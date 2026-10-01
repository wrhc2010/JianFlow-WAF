import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export function loadSessionSecret(directory: string, supplied = ""): string {
  const value = supplied.trim();
  if (value && !["development-only-secret", "change-me-session-secret"].includes(value)) {
    if (value.length < 32) throw new Error("SESSION_SECRET 至少需要 32 个字符，或留空自动生成");
    return value;
  }
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "session-secret");
  try {
    writeFileSync(path, randomBytes(48).toString("base64url"), { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const secret = readFileSync(path, "utf8").trim();
  if (secret.length < 32) throw new Error("持久化会话密钥文件无效，请恢复数据目录备份");
  return secret;
}

function keyFromSecret(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

export function encryptSecret(value: string, secret: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", keyFromSecret(secret), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, encrypted].map((part) => part.toString("base64url")).join(".");
}

export function decryptSecret(value: string, secret: string): string {
  const [ivValue, tagValue, encryptedValue] = value.split(".");
  if (!ivValue || !tagValue || !encryptedValue) throw new Error("密钥密文格式无效");
  const decipher = createDecipheriv("aes-256-gcm", keyFromSecret(secret), Buffer.from(ivValue, "base64url"));
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedValue, "base64url")),
    decipher.final()
  ]).toString("utf8");
}
