import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { decryptSecret, encryptSecret, loadSessionSecret } from "../src/secrets.js";

test("encrypts and decrypts API keys without exposing plaintext", () => {
  const value = "jev-test-secret";
  const ciphertext = encryptSecret(value, "session-secret");
  assert.notEqual(ciphertext, value);
  assert.equal(decryptSecret(ciphertext, "session-secret"), value);
  assert.throws(() => decryptSecret(ciphertext, "wrong-secret"));
});

test("generates a stable private session secret when optional configuration is empty", () => {
  const directory = resolve("../../../verification", `secrets-${randomUUID()}`);
  const first = loadSessionSecret(directory, "");
  assert.ok(first.length >= 32);
  assert.equal(loadSessionSecret(directory), first);
  const encrypted = encryptSecret("provider-key-test", first);
  assert.equal(decryptSecret(encrypted, loadSessionSecret(directory)), "provider-key-test");
  assert.throws(() => loadSessionSecret(directory, "short-secret"));
});
