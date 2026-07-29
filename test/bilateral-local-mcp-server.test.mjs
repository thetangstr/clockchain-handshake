import assert from "node:assert/strict";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createPayerMcpServer } from "../src/bilateral/local-mcp/server.mjs";
import { buildPaymentIntakeToolResult, PAYMENT_INTAKE_TOOL_DESCRIPTOR } from "../src/bilateral/local-mcp/payment-intake.mjs";
import { createPayerMcpIntakeStore } from "../src/bilateral/local-mcp/intake-store.mjs";

const PROTOCOL_VERSION = "2025-11-25";
const REPOSITORY_SHA = "a".repeat(40);
const CAPABILITY = "ab".repeat(32);
const CAPABILITY_DIGEST = createHash("sha256").update(Buffer.from(CAPABILITY, "hex")).digest("hex");
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const GENERIC_UNAUTHORIZED = { error: "PAYER_MCP_PROTOCOL_FAILED", paymentMoved: false };

function paymentInput(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
    ...overrides,
  };
}

async function makeFixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "payer-mcp-server-"));
  const certificatePath = join(root, "cert.pem");
  const privateKeyPath = join(root, "key.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
  ], { stdio: "ignore" });
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tlsPrivateKeyPem = await readFile(privateKeyPath, "utf8");
  const intakeStore = await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root });
  const observed = [];
  const server = createPayerMcpServer({
    capabilityDigest: CAPABILITY_DIGEST,
    host: options.host ?? "127.0.0.1",
    intakeStore,
    nowMs: options.nowMs,
    port: 0,
    randomBytes: options.randomBytes ?? (() => Buffer.alloc(16, 1)),
    repositorySha: REPOSITORY_SHA,
    sideEffects: {
      appendRelayEvent: () => observed.push("relay"),
      createVerdict: () => observed.push("verdict"),
      movePayment: () => observed.push("payment"),
      writeClockchain: () => observed.push("clockchain"),
    },
    tlsCertificatePem,
    tlsPrivateKeyPem,
  });
  const listening = await server.start();
  t.after(async () => {
    await server.stop();
    await rm(root, { force: true, recursive: true });
  });
  return { ...listening, certificate: tlsCertificatePem, fingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"), observed, root, server };
}

async function request({ body, fixture, headers = {}, method = "POST", path = "/mcp" }) {
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const requestHeaders = Object.fromEntries(Object.entries({
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${CAPABILITY}`,
      "Content-Type": "application/json",
      Host: `${fixture.host}:${fixture.port}`,
      ...(payload ? { "Content-Length": String(payload.length) } : {}),
      ...headers,
    }).filter(([, value]) => value !== undefined));
    const req = https.request({
      ca: fixture.certificate,
      headers: requestHeaders,
      host: fixture.host,
      method,
      path,
      port: fixture.port,
      rejectUnauthorized: true,
      servername: "",
      timeout: 5_000,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({
          body: text === "" ? null : JSON.parse(text),
          headers: res.headers,
          statusCode: res.statusCode,
          text,
        });
      });
    });
    req.once("error", reject);
    req.end(payload);
  });
}

const rpc = (id, method, params = {}) => ({ id, jsonrpc: "2.0", method, params });

async function initializedSession(t, fixture) {
  fixture ??= await makeFixture(t);
  const initialized = await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION } });
  assert.equal(initialized.statusCode, 200);
  const sessionId = initialized.headers["mcp-session-id"];
  assert.match(sessionId, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(initialized.headers["mcp-protocol-version"], PROTOCOL_VERSION);
  const notification = await request({
    body: { jsonrpc: "2.0", method: "notifications/initialized" },
    fixture,
    headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId },
  });
  assert.equal(notification.statusCode, 202);
  return { fixture, sessionId };
}

test("serves the exact JSON-only MCP lifecycle and persists one request_payment intake", async (t) => {
  const { fixture, sessionId } = await initializedSession(t);
  const tools = await request({ body: rpc(2, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } });
  assert.equal(tools.statusCode, 200);
  assert.deepEqual(tools.body, { id: 2, jsonrpc: "2.0", result: { tools: [PAYMENT_INTAKE_TOOL_DESCRIPTOR] } });
  assert.equal(tools.headers["content-type"], "application/json");
  assert.equal(String(tools.text).includes("text/event-stream"), false);

  const call = await request({
    body: rpc(3, "tools/call", { arguments: paymentInput(), name: "request_payment" }),
    fixture,
    headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId },
  });
  assert.equal(call.statusCode, 200);
  assert.deepEqual(call.body, {
    id: 3,
    jsonrpc: "2.0",
    result: buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: paymentInput() }),
  });
  assert.equal(call.text.includes("AUTHORIZED"), false);
  assert.deepEqual(fixture.observed, []);

  const deleted = await request({ body: undefined, fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId }, method: "DELETE" });
  assert.equal(deleted.statusCode, 200);
  const afterDelete = await request({ body: rpc(4, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } });
  assert.equal(afterDelete.statusCode, 400);
  await fixture.server.stop();
});

test("rejects unsafe transport boundary, host, path, headers, session, method, and tool shapes", async (t) => {
  const fixture = await makeFixture(t);
  assert.throws(() => createPayerMcpServer({ ...fixture, capabilityDigest: CAPABILITY_DIGEST, host: "0.0.0.0", intakeStore: {}, repositorySha: REPOSITORY_SHA, tlsCertificatePem: fixture.certificate, tlsPrivateKeyPem: "x" }));
  assert.throws(() => createPayerMcpServer({ ...fixture, capabilityDigest: CAPABILITY_DIGEST, host: "localhost", intakeStore: {}, repositorySha: REPOSITORY_SHA, tlsCertificatePem: fixture.certificate, tlsPrivateKeyPem: "x" }));

  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, method: "GET" })).statusCode, 405);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, path: "/mcp?x=1" })).statusCode, 404);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Host: "127.0.0.1" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Origin: "https://example.invalid" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Accept: "application/json" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { "Content-Type": "text/plain" } })).statusCode, 415);

  const { sessionId } = await initializedSession(t, fixture);
  for (const body of [
    rpc(9, "initialize", { protocolVersion: PROTOCOL_VERSION }),
    rpc(10, "tools/call", { arguments: paymentInput(), name: "other" }),
    rpc(11, "unknown"),
    { id: 12, jsonrpc: "2.0", method: "tools/list", extra: true },
  ]) {
    const response = await request({ body, fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } });
    assert.equal(response.statusCode, 400);
  }
  assert.equal((await request({ body: rpc(13, "tools/list"), fixture, headers: { "MCP-Protocol-Version": "2024-01-01", "MCP-Session-Id": sessionId } })).statusCode, 400);
  assert.equal((await request({ body: rpc(14, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": "wrong" } })).statusCode, 400);
  await fixture.server.stop();
});

test("uses generic capability failures, rate limits failed auth, caps session requests, body and header count", async (t) => {
  let now = 1_000;
  const fixture = await makeFixture(t, { nowMs: () => now });
  for (const auth of [undefined, "Bearer bad", "Basic abc"]) {
    const response = await request({
      body: rpc(randomBytes(1)[0], "initialize", { protocolVersion: PROTOCOL_VERSION }),
      fixture,
      headers: auth === undefined ? { Authorization: undefined } : { Authorization: auth },
    });
    assert.equal(response.statusCode, 401);
    assert.deepEqual(response.body, GENERIC_UNAUTHORIZED);
  }
  for (let index = 0; index < 13; index += 1) {
    await request({ body: rpc(index, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Authorization: "Bearer bad" } });
  }
  const limited = await request({ body: rpc(99, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Authorization: "Bearer bad" } });
  assert.equal(limited.statusCode, 429);
  assert.deepEqual(limited.body, GENERIC_UNAUTHORIZED);
  now += 61_000;
  assert.equal((await request({ body: rpc(100, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture })).statusCode, 200);

  const tooManyHeaders = Object.fromEntries(Array.from({ length: 33 }, (_, index) => [`X-Test-${index}`, "1"]));
  assert.equal((await request({ body: rpc(101, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: tooManyHeaders })).statusCode, 431);
  assert.equal((await request({ body: rpc(102, "initialize", { protocolVersion: PROTOCOL_VERSION, padding: "x".repeat(65_536) }), fixture })).statusCode, 413);

  const { sessionId } = await initializedSession(t, fixture);
  for (let id = 2; id <= 7; id += 1) {
    assert.equal((await request({ body: rpc(id, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 200);
  }
  assert.equal((await request({ body: rpc(8, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 400);
  await fixture.server.stop();
});
