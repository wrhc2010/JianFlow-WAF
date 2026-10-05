import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { config } from "./config.js";
import { defaultPage } from "./pages.js";
import type { CaptchaConfig } from "./db/store.js";

const spent = new Map<string, number>();
const difficulty = 3;

function sign(value: string): string {
  return createHmac("sha256", config.sessionSecret).update(value).digest("base64url");
}

function encode(value: object): string { return Buffer.from(JSON.stringify(value)).toString("base64url"); }

export function createChallenge(siteId: string, ip: string): { challenge: string; difficulty: number; expiresAt: number } {
  const expiresAt = Date.now() + 120000;
  const body = encode({ siteId, ip, exp: expiresAt, nonce: randomBytes(16).toString("hex"), kind: "pow" });
  return { challenge: `${body}.${sign(body)}`, difficulty, expiresAt };
}

export function verifyChallenge(siteId: string, ip: string, challenge: string, answer: string): string | undefined {
  for (const [key, expiry] of spent) if (expiry <= Date.now()) spent.delete(key);
  if (spent.size >= 10000 || spent.has(challenge) || !/^\d{1,9}$/.test(answer) || !verifySigned(siteId, ip, challenge, "pow")) return undefined;
  if (!createHash("sha256").update(`${challenge}:${answer}`).digest("hex").startsWith("0".repeat(difficulty))) return undefined;
  spent.set(challenge, Date.now() + 120000);
  return issueToken(siteId, ip);
}

export function issueToken(siteId: string, ip: string): string {
  const payload = { siteId, ip, exp: Date.now() + 600000, nonce: randomBytes(16).toString("hex"), kind: "clearance" };
  const body = encode(payload);
  return `${body}.${sign(body)}`;
}

export function verifyToken(siteId: string, ip: string, token: string): boolean {
  return verifySigned(siteId, ip, token, "clearance");
}

function verifySigned(siteId: string, ip: string, token: string, kind: string): boolean {
  if (token.length > 2048) return false;
  const [body, signature] = token.split(".");
  if (!body || !signature) return false;
  const expected = sign(body);
  if (!/^[A-Za-z0-9_-]+$/.test(signature) || Buffer.byteLength(signature) !== Buffer.byteLength(expected) || !timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as { siteId?: string; ip?: string; exp?: number; kind?: string };
    return payload.kind === kind && payload.siteId === siteId && payload.ip === ip && typeof payload.exp === "number" && payload.exp > Date.now();
  } catch { return false; }
}

export function clearChallenges(): void { spent.clear(); }

const verifyUrls = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
  hcaptcha: "https://api.hcaptcha.com/siteverify",
  recaptcha: "https://www.google.com/recaptcha/api/siteverify",
};

export async function verifyProvider(options: CaptchaConfig, secret: string, response: string, ip: string, hostname: string, fetcher: typeof fetch = fetch): Promise<{ allowed: boolean; unavailable?: boolean }> {
  if (options.provider === "local" || !secret || !response || response.length > 8192) return { allowed: false };
  try {
    const result = await fetcher(verifyUrls[options.provider], { method: "POST", body: new URLSearchParams({ secret, response, remoteip: ip }), signal: AbortSignal.timeout(options.timeoutMs ?? 5000) });
    if (!result.ok) throw new Error("verification unavailable");
    const reader = result.body?.getReader();
    if (!reader) throw new Error("empty verification response");
    let size = 0;
    const chunks: Uint8Array[] = [];
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > 16384) throw new Error("verification response too large");
        chunks.push(value);
      }
    } finally { await reader.cancel().catch(() => {}); }
    const data = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { success?: boolean; hostname?: string };
    return { allowed: data.success === true && data.hostname?.toLowerCase() === hostname.toLowerCase() };
  } catch { return { allowed: options.failureAction === "allow", unavailable: true }; }
}

export function captchaPage(options: CaptchaConfig): string {
  const common = `<p id="status" role="status">请完成验证后继续访问。</p><script>
    async function complete(payload){const r=await fetch('/.jianflow/captcha/verify',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});if(r.ok){location.reload()}else{document.getElementById('status').textContent='验证失败或已过期，请刷新重试。'}}
    function onVerified(token){complete({response:token})}
  </script>`;
  const siteKey = options.siteKey.replace(/[&<>"']/g, "");
  const widget = options.provider === "turnstile" ? `<div class="cf-turnstile" data-sitekey="${siteKey}" data-callback="onVerified"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
    : options.provider === "hcaptcha" ? `<div class="h-captcha" data-sitekey="${siteKey}" data-callback="onVerified"></div><script src="https://js.hcaptcha.com/1/api.js" async defer></script>`
    : options.provider === "recaptcha" ? `<div class="g-recaptcha" data-sitekey="${siteKey}" data-callback="onVerified"></div><script src="https://www.google.com/recaptcha/api.js" async defer></script>`
    : `<button id="verify">验证并继续</button><script>
      document.getElementById('verify').onclick=async function(){this.disabled=true;document.getElementById('status').textContent='正在验证…';try{const c=await fetch('/.jianflow/captcha/challenge').then(r=>r.json());const prefix='0'.repeat(c.difficulty);const encoder=new TextEncoder();for(let n=0;n<1000000000;n++){const bytes=await crypto.subtle.digest('SHA-256',encoder.encode(c.challenge+':'+n));const hash=Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('');if(hash.startsWith(prefix)){await complete({challenge:c.challenge,answer:String(n)});return;}if(n%64===0)await new Promise(r=>setTimeout(r,0));}throw new Error();}catch{document.getElementById('status').textContent='验证无法完成，请刷新重试。';this.disabled=false;}}
    </script>`;
  return defaultPage("访问验证", "确认后即可继续访问站点。", common + widget);
}
