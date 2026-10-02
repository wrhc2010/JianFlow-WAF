import http from "node:http";
import type { Socket } from "node:net";
import { once } from "node:events";
import { config } from "./config.js";
import { createProxyServer } from "./proxy.js";
import { Store } from "./db/store.js";

export class ProxyListenerManager {
  private readonly listeners = new Map<number, http.Server>();
  private readonly connections = new WeakMap<http.Server, Set<Socket>>();
  private queue: Promise<void> = Promise.resolve();

  constructor(private readonly store: Store) {}

  sync(): Promise<void> {
    const next = this.queue.then(() => this.apply());
    this.queue = next.catch(() => {});
    return next;
  }

  async close(): Promise<void> {
    await this.queue;
    await Promise.all([...this.listeners.entries()].map(async ([port, server]) => {
      await this.closeListener(server);
      this.listeners.delete(port);
    }));
  }

  private async apply(): Promise<void> {
    const desired = new Set(
      this.store.listSites()
        .filter((site) => site.enabled)
        .map((site) => site.listenPort)
    );
    for (const [port, server] of this.listeners) {
      if (desired.has(port)) continue;
      await this.closeListener(server);
      this.listeners.delete(port);
    }
    for (const port of desired) {
      if (this.listeners.has(port)) continue;
      const server = createProxyServer(this.store, port);
      const connections = new Set<Socket>();
      this.connections.set(server, connections);
      server.on("connection", (socket) => {
        connections.add(socket);
        socket.once("close", () => connections.delete(socket));
      });
      server.listen(port, config.proxyHost);
      await once(server, "listening");
      this.listeners.set(port, server);
    }
  }

  private async closeListener(server: http.Server): Promise<void> {
    const closing = closeServer(server);
    for (const socket of this.connections.get(server) ?? []) socket.destroy();
    await closing;
  }
}

async function closeServer(server: http.Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
