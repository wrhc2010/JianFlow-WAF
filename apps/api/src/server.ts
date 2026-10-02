import { once } from "node:events";
import { createApp } from "./app.js";
import { config } from "./config.js";
import { Store } from "./db/store.js";
import { createHttpsProxyServer } from "./proxy.js";
import { ProxyListenerManager } from "./proxy-manager.js";

const store = new Store();
await store.init();
const app = await createApp(store);
const proxy = new ProxyListenerManager(store);
store.setSiteChangeListener(() => proxy.sync());
const httpsProxy = config.tlsKeyPath && config.tlsCertPath
  ? createHttpsProxyServer(store, config.tlsKeyPath, config.tlsCertPath, config.proxyPort) : null;
if (config.tlsKeyPath && config.tlsCertPath && !httpsProxy) throw new Error("TLS 证书无法加载");

await app.listen({ host: config.apiHost, port: config.apiPort });
await proxy.sync();
if (httpsProxy) {
  httpsProxy.listen(config.httpsPort, config.proxyHost);
  await once(httpsProxy, "listening");
}
console.log(`JianFlow WAF proxy listening on ${config.proxyHost}:${config.sitePortRange.min}-${config.sitePortRange.max}`);

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  await proxy.close();
  httpsProxy?.closeAllConnections();
  httpsProxy?.close();
  await app.close();
  await store.close();
}
process.once("SIGTERM", () => { void shutdown(); });
process.once("SIGINT", () => { void shutdown(); });
