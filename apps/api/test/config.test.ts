import assert from "node:assert/strict";
import test from "node:test";
import { buildDatabaseUrl } from "../src/config.js";

test("builds a PostgreSQL URL with credentials from secret configuration", () => {
  const url = new URL(
    buildDatabaseUrl({
      host: "postgres",
      port: "5432",
      user: "jevwaf",
      password: "p@ss word",
      database: "jevwaf"
    })
  );

  assert.equal(url.username, "jevwaf");
  assert.equal(url.password, "p%40ss%20word");
  assert.equal(url.hostname, "postgres");
  assert.equal(url.port, "5432");
  assert.equal(url.pathname, "/jevwaf");
});
