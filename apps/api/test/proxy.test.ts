import assert from "node:assert/strict";
import { brotliCompressSync, deflateSync, gzipSync } from "node:zlib";
import { Readable } from "node:stream";
import test from "node:test";
import { clientIp, isIpInCidr, readBody } from "../src/proxy.js";

function bodyRequest(body: Buffer, headers: Record<string, string> = {}): import("node:http").IncomingMessage {
  return Object.assign(Readable.from([body]), { headers }) as unknown as import("node:http").IncomingMessage;
}

test("walks forwarded chains from the nearest trusted hop and discards spoofed prefixes", () => {
  const request = {
    socket: { remoteAddress: "::ffff:127.0.0.1" },
    headers: { "x-forwarded-for": "8.8.8.8, 203.0.113.42" }
  } as unknown as import("node:http").IncomingMessage;
  assert.equal(clientIp(request, ["127.0.0.1"]), "203.0.113.42");
  request.headers["x-forwarded-for"] = "8.8.8.8, 10.0.0.2";
  assert.equal(clientIp(request, ["127.0.0.1", "10.0.0.0/8"]), "8.8.8.8");
  request.headers["x-forwarded-for"] = "forged, 10.0.0.2";
  assert.equal(clientIp(request, ["127.0.0.1", "10.0.0.0/8"]), "127.0.0.1");
  request.socket.remoteAddress = "192.0.2.10";
  request.headers["x-forwarded-for"] = "8.8.8.8";
  assert.equal(clientIp(request, ["127.0.0.1"]), "192.0.2.10");
  assert.equal(clientIp(request, []), "192.0.2.10");
});
test("matches IPv4 and IPv6 trusted proxy CIDRs", () => {
  assert.equal(isIpInCidr("192.168.1.42", "192.168.1.0/24"), true);
  assert.equal(isIpInCidr("192.168.2.42", "192.168.1.0/24"), false);
  assert.equal(isIpInCidr("2001:db8:abcd::1", "2001:db8::/32"), true);
  assert.equal(isIpInCidr("2001:db9::1", "2001:db8::/32"), false);
});

test("decompresses bodies for inspection while preserving raw bytes for forwarding", async () => {
  const raw = gzipSync(Buffer.from("file:///etc/passwd"));
  const request = Object.assign(Readable.from([raw]), {
    headers: { "content-encoding": "gzip" }
  }) as unknown as import("node:http").IncomingMessage;
  const result = await readBody(request);
  assert.equal(result.error, undefined);
  assert.equal(result.body, "file:///etc/passwd");
  assert.deepEqual(result.forwardBody, raw);
});

test("inspects the complete body beyond the former 256 KB cutoff", async () => {
  const raw = Buffer.from(`${"a".repeat(300 * 1024)}file:///etc/passwd`);
  const result = await readBody(bodyRequest(raw));
  assert.equal(result.error, undefined);
  assert.equal(result.partial, false);
  assert.equal(result.body, raw.toString());
});

test("rejects malformed JSON instead of allowing uninspectable data", async () => {
  const result = await readBody(bodyRequest(Buffer.from('{"url":'), { "content-type": "application/json" }));
  assert.ok(result.error);
  assert.equal(result.partial, true);
});

test("rejects invalid UTF-8 rather than silently replacing attack bytes", async () => {
  const result = await readBody(bodyRequest(Buffer.from([0xff, 0xfe, 0x7b])));
  assert.ok(result.error);
});

test("rejects malformed XML and incomplete multipart bodies", async () => {
  const xml = await readBody(bodyRequest(Buffer.from("<root><x></root>"), { "content-type": "application/xml" }));
  assert.ok(xml.error);
  const multipart = await readBody(bodyRequest(Buffer.from("--missing\r\nbroken"), {
    "content-type": "multipart/form-data; boundary=missing"
  }));
  assert.ok(multipart.error);
});

test("validates complete multipart including text fields and binary files", async () => {
  const raw = Buffer.concat([
    Buffer.from('--waf\r\nContent-Disposition: form-data; name="url"\r\n\r\nfile:///etc/passwd\r\n'
      + '--waf\r\nContent-Disposition: form-data; name="upload"; filename="hello.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'),
    Buffer.from([0xff, 0xfe, 0x00]),
    Buffer.from("\r\n--waf--\r\n")
  ]);
  const result = await readBody(bodyRequest(raw, { "content-type": "multipart/form-data; boundary=waf" }));
  assert.equal(result.error, undefined);
  assert.match(result.body, /file:\/\/\/etc\/passwd/);
  assert.deepEqual(result.forwardBody, raw);
});

for (const [encoding, compress] of Object.entries({ gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync })) {
  test(`bounds expanded ${encoding} bodies and rejects decompression bombs`, async () => {
    const raw = compress(Buffer.alloc(10 * 1024 * 1024 + 1, "a"));
    const result = await readBody(bodyRequest(raw, { "content-encoding": encoding }));
    assert.ok(result.error);
    assert.equal(result.partial, true);
    assert.equal(result.body, "");
  });
}
