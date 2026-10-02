import http from "node:http";
import { once } from "node:events";
import { config } from "./config.js";
import { createProxyServer } from "./proxy.js";
import { Store } from "./db/store.js";

export class ProxyListenerManager {
  private readonly listeners = new Map<number, http.Server>();
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
      server.closeAllConnections();
      await closeServer(server);
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
      server.closeAllConnections();
      await closeServer(server);
      this.listeners.delete(port);
    }
    for (const port of desired) {
      if (this.listeners.has(port)) continue;
      const server = createProxyServer(this.store, port);
      server.listen(port, config.proxyHost);
      await once(server, "listening");
      this.listeners.set(port, server);
    }
  }
}

async function closeServer(server: http.Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
