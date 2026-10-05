import http from "node:http";
import type { Socket } from "node:net";
import { once } from "node:events";
import { config } from "./config.js";
import { createProxyServer, createHttpsProxyServer } from "./proxy.js";
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
    const desired = new Set<number>();
    for (const site of this.store.listSites()) {
      const revision = site.revision ?? 1;
      if (!site.enabled) {
        this.store.reportRuntime?.(site.id, { state: "disabled", desiredRevision: revision, appliedRevision: revision });
        continue;
      }
      const ports = [{ port: site.listenPort, tls: false }];
      if (site.id === "default" && (config.tlsKeyPath || config.tlsCertPath)) ports.push({ port: config.httpsPort, tls: true });
      let lastError = "";
      for (const binding of ports) {
        desired.add(binding.port);
        if (this.listeners.has(binding.port)) continue;
        const server = binding.tls
          ? createHttpsProxyServer(this.store, config.tlsKeyPath, config.tlsCertPath, site.listenPort)
          : createProxyServer(this.store, site.listenPort);
        if (!server) { lastError = "TLS certificate could not be loaded"; continue; }
        const connections = new Set<Socket>();
        this.connections.set(server, connections);
        server.on("connection", (socket) => {
          connections.add(socket);
          socket.once("close", () => connections.delete(socket));
        });
        try {
          const listening = once(server, "listening");
          server.listen(binding.port, config.proxyHost);
          await listening;
          this.listeners.set(binding.port, server);
        } catch (error) {
          lastError = `${binding.tls ? "HTTPS" : "HTTP"} :${binding.port} ${(error as NodeJS.ErrnoException).code ?? "listen_failed"}`;
          await this.closeListener(server);
        }
      }
      this.store.reportRuntime?.(site.id, { state: lastError ? "error" : "active", desiredRevision: revision,
        appliedRevision: lastError ? site.runtime?.appliedRevision ?? 0 : revision, ...(lastError ? { lastError } : {}) });
    }
    // Prepare additions first, so an occupied new port does not disturb other entries.
    for (const [port, server] of this.listeners) {
      if (desired.has(port)) continue;
      await this.closeListener(server);
      this.listeners.delete(port);
    }
  }

  private async closeListener(server: http.Server): Promise<void> {
    const closing = closeServer(server);
    const connections = [...this.connections.get(server) ?? []];
    const closed = connections.filter((socket) => !socket.closed).map((socket) => new Promise<void>((resolve) => socket.once("close", resolve)));
    for (const socket of connections) socket.destroy();
    await closing;
    await Promise.all(closed);
  }
}

async function closeServer(server: http.Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
