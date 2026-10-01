import { once } from "node:events";
import { createApp } from "./app.js";
import { config } from "./config.js";
import { Store } from "./db/store.js";
import { createHttpsProxyServer, createProxyServer } from "./proxy.js";

const store = new Store();
await store.init();
const app = await createApp(store);
const proxy = createProxyServer(store);
const httpsProxy = config.tlsKeyPath && config.tlsCertPath
  ? createHttpsProxyServer(store, config.tlsKeyPath, config.tlsCertPath) : null;
if (config.tlsKeyPath && config.tlsCertPath && !httpsProxy) throw new Error("TLS 证书无法加载");

await app.listen({ host: config.apiHost, port: config.apiPort });
proxy.listen(config.proxyPort, config.proxyHost);
await once(proxy, "listening");
if (httpsProxy) {
  httpsProxy.listen(config.httpsPort, config.proxyHost);
  await once(httpsProxy, "listening");
}
console.log(`JianFlow WAF proxy listening on http://${config.proxyHost}:${config.proxyPort}`);

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  proxy.closeAllConnections();
  proxy.close();
  httpsProxy?.closeAllConnections();
  httpsProxy?.close();
  await app.close();
  await store.close();
}
process.once("SIGTERM", () => { void shutdown(); });
process.once("SIGINT", () => { void shutdown(); });
