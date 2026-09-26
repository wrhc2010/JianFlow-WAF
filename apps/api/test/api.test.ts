import assert from "node:assert/strict";
import test from "node:test";
import { classifyWithJev } from "../src/jev.js";

test("Jev client reports missing configuration instead of exposing a key", async () => {
  const decision = await classifyWithJev("{}", "typesafe/jev-1.13", 10);
  if (!process.env.OPENROUTER_API_KEY) {
    assert.equal(decision.available, false);
    assert.match(decision.error ?? "", /未配置/);
  } else {
    assert.equal(typeof decision.available, "boolean");
  }
});
