import { randomBytes, randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Store, Site } from "./db/store.js";
import type { Admission } from "./wait-room.js";
import { defaultPage } from "./pages.js";
import { secureRequest } from "./request-security.js";

type Ticket = { id: string; siteId: string; ip: string; controller: AbortController; admission?: Admission; rejected: boolean; timer: ReturnType<typeof setTimeout>; cleanup: () => void };
const tickets = new WeakMap<Store, Map<string, Ticket>>();

function entries(store: Store) {
  let map = tickets.get(store);
  if (!map) { map = new Map(); tickets.set(store, map); }
  return map;
}
function ticketFor(store: Store, request: IncomingMessage, siteId: string, ip: string): Ticket | undefined {
  const id = request.headers.cookie?.split(";").map((part) => part.trim()).find((part) => part.startsWith("jf_wait="))?.slice(8);
  const ticket = id ? entries(store).get(id) : undefined;
  return ticket?.siteId === siteId && ticket.ip === ip ? ticket : undefined;
}
function remove(store: Store, ticket: Ticket): void {
  clearTimeout(ticket.timer);
  ticket.controller.abort();
  ticket.admission?.release();
  ticket.cleanup();
  entries(store).delete(ticket.id);
}

export function waitStatus(store: Store, request: IncomingMessage, response: ServerResponse, siteId: string, ip: string): void {
  const ticket = ticketFor(store, request, siteId, ip);
  response.writeHead(ticket ? 200 : 410, { "content-type": "application/json", "cache-control": "no-store" });
  response.end(JSON.stringify({ state: !ticket ? "expired" : ticket.rejected ? "rejected" : ticket.admission ? "ready" : "waiting" }));
}

export function takeWaitingAdmission(store: Store, request: IncomingMessage, siteId: string, ip: string): Admission | undefined {
  const ticket = ticketFor(store, request, siteId, ip);
  if (!ticket?.admission) return undefined;
  const admission = ticket.admission;
  delete ticket.admission;
  remove(store, ticket);
  return admission;
}

function sendWaitingPage(store: Store, request: IncomingMessage, response: ServerResponse, site: Site, ticket: Ticket): void {
  const nonce = randomBytes(16).toString("base64");
  const runtime = `<p id="queue-state" role="status">正在排队…</p><script nonce="${nonce}">const timer=setInterval(async()=>{try{const r=await fetch('/.jianflow/wait/status',{cache:'no-store'});const s=await r.json();if(s.state==='ready'){clearInterval(timer);location.reload()}else if(s.state!=='waiting'){clearInterval(timer);document.getElementById('queue-state').textContent='等待已结束，请刷新重试。'}}catch{}},1000);</script>`;
  const custom = store.readPage(site.waitRoom?.page);
  // Custom HTML never shares the control page's origin or script privileges.
  const preview = custom ? `<iframe title="等候室" sandbox srcdoc="${custom.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!)}" style="width:100%;height:65vh;border:0"></iframe>` : "";
  const body = defaultPage("请稍候", "当前访问较多，正在按顺序安排请求。", preview + runtime);
  response.writeHead(202, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer", "set-cookie": `jf_wait=${ticket.id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${(site.waitRoom?.timeoutSeconds ?? 60) + 10}${secureRequest(request) ? "; Secure" : ""}`, "content-security-policy": `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; connect-src 'self'; frame-src 'self'; img-src data: https:; base-uri 'none'; form-action 'none'` });
  request.resume(); response.end(body);
}

export function repeatWaitingResponse(store: Store, request: IncomingMessage, response: ServerResponse, site: Site, ip: string): boolean {
  const ticket = ticketFor(store, request, site.id, ip);
  if (!ticket || ticket.admission || ticket.rejected) return false;
  sendWaitingPage(store, request, response, site, ticket);
  return true;
}

export function browserWaitResponse(store: Store, request: IncomingMessage, response: ServerResponse, site: Site, ip: string, pending: Promise<Admission>, controller: AbortController, track: (destroy: () => void) => () => void): void {
  const id = randomUUID();
  const ticket: Ticket = { id, siteId: site.id, ip, controller, rejected: false, timer: setTimeout(() => remove(store, ticket), (site.waitRoom?.timeoutSeconds ?? 60) * 1000 + 10000), cleanup: () => {} };
  ticket.timer.unref();
  ticket.cleanup = track(() => remove(store, ticket));
  entries(store).set(id, ticket);
  void pending.then((admission) => {
    if (!entries(store).has(id)) { admission.release(); return; }
    if (admission.allowed) ticket.admission = admission;
    else ticket.rejected = true;
    clearTimeout(ticket.timer);
    ticket.timer = setTimeout(() => remove(store, ticket), 10000); ticket.timer.unref();
  });
  sendWaitingPage(store, request, response, site, ticket);
}
