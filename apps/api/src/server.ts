import { createApp } from "./app.js";
import { config } from "./config.js";
import { Store } from "./db/store.js";
import { ProxyListenerManager } from "./proxy-manager.js";
import { applyConfigurationFile } from "./configuration-file.js";

const store = new Store();
await store.init();
const app = await createApp(store);
await applyConfigurationFile(app, store, config.configurationFile);
const proxy = new ProxyListenerManager(store);
store.setSiteChangeListener(() => proxy.sync());

await app.listen({ host: config.apiHost, port: config.apiPort });
await proxy.sync();
console.log(`JianFlow WAF proxy listening on ${config.proxyHost}:${config.sitePortRange.min}-${config.sitePortRange.max}`);

let stopping = false;
async function shutdown(): Promise<void> {
  if (stopping) return;
  stopping = true;
  await proxy.close();
  await app.close();
  await store.close();
}
process.once("SIGTERM", () => { void shutdown(); });
process.once("SIGINT", () => { void shutdown(); });
