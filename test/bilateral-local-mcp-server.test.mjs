import assert from "node:assert/strict";
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile, mkdtemp, rm } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { createPayerMcpServer } from "../src/bilateral/local-mcp/server.mjs";
import { buildPaymentIntakeToolResult, PAYMENT_INTAKE_TOOL_DESCRIPTOR } from "../src/bilateral/local-mcp/payment-intake.mjs";
import { createPayerMcpIntakeStore } from "../src/bilateral/local-mcp/intake-store.mjs";
import { requestPaymentThroughPayerMcp } from "../src/bilateral/local-mcp/client.mjs";

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
    createHttpsServer: options.createHttpsServer,
    host: options.host ?? "127.0.0.1",
    intakeStore,
    nowMs: options.nowMs,
    port: 0,
    publicUrl: options.publicUrl,
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

async function request({ body, fixture, headers = {}, method = "POST", path = "/mcp", rawBody }) {
  const payload = rawBody === undefined
    ? (body === undefined ? undefined : Buffer.from(JSON.stringify(body)))
    : Buffer.from(rawBody);
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

async function rawRequest({ fixture, rawHeaders, rawBody }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: fixture.host, port: fixture.port }, () => {
      const secure = tls.connect({
        ca: fixture.certificate,
        checkServerIdentity: () => undefined,
        rejectUnauthorized: true,
        servername: "",
        socket,
      });
      secure.once("error", reject);
      secure.once("secureConnect", () => {
        secure.end([
          "POST /mcp HTTP/1.1",
          ...rawHeaders,
          `Content-Length: ${Buffer.byteLength(rawBody)}`,
          "",
          rawBody,
        ].join("\r\n"));
      });
      const chunks = [];
      secure.on("data", (chunk) => chunks.push(chunk));
      secure.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const statusCode = Number(text.match(/^HTTP\/1\.1 ([0-9]{3})/)?.[1]);
        resolve({ statusCode, text });
      });
    });
    socket.once("error", reject);
  });
}

const rpc = (id, method, params = {}) => ({ id, jsonrpc: "2.0", method, params });
const initializeJson = (id = 1) => JSON.stringify(rpc(id, "initialize", { protocolVersion: PROTOCOL_VERSION }));

function rawHeadersFor(fixture, overrides = []) {
  return [
    `Host: ${fixture.host}:${fixture.port}`,
    "Accept: application/json, text/event-stream",
    `Authorization: Bearer ${CAPABILITY}`,
    "Content-Type: application/json",
    ...overrides,
  ];
}

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

test("completes pinned request_payment through a raw TCP relay while the MCP remains loopback-bound", async (t) => {
  let targetPort;
  let forwardedBytes = 0;
  const relaySockets = new Set();
  const relay = net.createServer((downstream) => {
    const upstream = net.connect({
      host: "127.0.0.1",
      port: targetPort,
    });
    relaySockets.add(downstream);
    relaySockets.add(upstream);
    downstream.once("close", () => relaySockets.delete(downstream));
    upstream.once("close", () => relaySockets.delete(upstream));
    downstream.once("error", () => upstream.destroy());
    upstream.once("error", () => downstream.destroy());
    downstream.on("data", (chunk) => {
      forwardedBytes += chunk.length;
    });
    upstream.on("data", (chunk) => {
      forwardedBytes += chunk.length;
    });
    downstream.pipe(upstream);
    upstream.pipe(downstream);
  });
  await new Promise((resolve, reject) => {
    relay.once("error", reject);
    relay.listen(0, "127.0.0.1", () => {
      relay.off("error", reject);
      resolve();
    });
  });
  const relayAddress = relay.address();
  assert.equal(typeof relayAddress, "object");
  const publicUrl = `https://127.0.0.1:${relayAddress.port}/mcp`;
  t.after(() => {
    for (const socket of relaySockets) socket.destroy();
    return new Promise((resolve, reject) => relay.close((error) => error ? reject(error) : resolve()));
  });

  const fixture = await makeFixture(t, { publicUrl });
  targetPort = fixture.port;
  const requestorState = await mkdtemp(join(tmpdir(), "payer-mcp-relay-requestor-"));
  t.after(() => rm(requestorState, { force: true, recursive: true }));

  assert.equal(fixture.host, "127.0.0.1");
  assert.notEqual(fixture.port, relayAddress.port);
  assert.equal(fixture.url, publicUrl);
  const result = await requestPaymentThroughPayerMcp({
    capability: CAPABILITY,
    intakeRequestId: INTAKE_REQUEST_ID,
    mcpUrl: publicUrl,
    repositorySha: REPOSITORY_SHA,
    stateRoot: requestorState,
    tlsCertificatePem: fixture.certificate,
    tlsFingerprint: fixture.fingerprint,
  });
  assert.equal(result.status, "HANDSHAKE_REQUIRED");
  assert.equal(result.paymentMoved, false);
  assert.equal(forwardedBytes > 0, true);
});

test("rejects unsafe transport boundary, host, path, headers, session, method, and tool shapes", async (t) => {
  const fixture = await makeFixture(t);
  const tlsPrivateKeyPem = await readFile(join(fixture.root, "key.pem"), "utf8");
  for (const host of [
    "0.0.0.0",
    "0:0:0:0:0:0:0:0",
    "0000:0000:0000:0000:0000:0000:0000:0000",
    "0:0:0:0:0:0:0:0000",
    "0000:0:0:0:0:0:0:0",
    "::",
    "::0",
    "::ffff:0.0.0.0",
    "::ffff:0:0",
    "0:0:0:0:0:ffff:0:0",
    "localhost",
  ]) {
    assert.throws(() => createPayerMcpServer({
      capabilityDigest: CAPABILITY_DIGEST,
      host,
      intakeStore: { writeIntake: async () => undefined },
      port: 0,
      repositorySha: REPOSITORY_SHA,
      tlsCertificatePem: fixture.certificate,
      tlsPrivateKeyPem,
    }), /Payer MCP server failed safely\./);
  }
  assert.equal(typeof createPayerMcpServer({
    capabilityDigest: CAPABILITY_DIGEST,
    host: "::1",
    intakeStore: { writeIntake: async () => undefined },
    port: 0,
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem: fixture.certificate,
    tlsPrivateKeyPem,
  }).start, "function");
  for (const publicUrl of [
    "http://127.0.0.1:19443/mcp",
    "https://127.0.0.1/mcp",
    "https://127.0.0.1:19443/other",
    "https://127.0.0.1:19443/mcp?proxy=true",
    "https://user@127.0.0.1:19443/mcp",
    "https://0.0.0.0:19443/mcp",
    "https://localhost:19443/mcp",
    "https://203.0.113.10:19443/mcp",
  ]) {
    assert.throws(() => createPayerMcpServer({
      capabilityDigest: CAPABILITY_DIGEST,
      host: "127.0.0.1",
      intakeStore: { writeIntake: async () => undefined },
      port: 0,
      publicUrl,
      repositorySha: REPOSITORY_SHA,
      tlsCertificatePem: fixture.certificate,
      tlsPrivateKeyPem,
    }), /Payer MCP server failed safely\./);
  }
  const publicCertificatePath = join(fixture.root, "public-cert.pem");
  const publicPrivateKeyPath = join(fixture.root, "public-key.pem");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    publicPrivateKeyPath,
    "-out",
    publicCertificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=203.0.113.10",
    "-addext",
    "subjectAltName=IP:203.0.113.10",
  ], { stdio: "ignore" });
  assert.equal(typeof createPayerMcpServer({
    capabilityDigest: CAPABILITY_DIGEST,
    host: "127.0.0.1",
    intakeStore: { writeIntake: async () => undefined },
    port: 0,
    publicUrl: "https://203.0.113.10:19443/mcp",
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem: await readFile(publicCertificatePath, "utf8"),
    tlsPrivateKeyPem: await readFile(publicPrivateKeyPath, "utf8"),
  }).start, "function");
  for (const host of ["2001:0db8::1", "2001:db8:0:0:0:0:0:1", "::0001"]) {
    assert.throws(() => createPayerMcpServer({
      capabilityDigest: CAPABILITY_DIGEST,
      host,
      intakeStore: { writeIntake: async () => undefined },
      port: 0,
      repositorySha: REPOSITORY_SHA,
      tlsCertificatePem: fixture.certificate,
      tlsPrivateKeyPem,
    }), /Payer MCP server failed safely\./);
  }

  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, method: "GET" })).statusCode, 405);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, path: "/mcp?x=1" })).statusCode, 404);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Host: "127.0.0.1" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Origin: "https://example.invalid" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Accept: "application/json" } })).statusCode, 400);
  assert.equal((await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { "Content-Type": "text/plain" } })).statusCode, 415);
  for (const duplicate of [
    [`Host: ${fixture.host}:${fixture.port}`],
    [`Authorization: Bearer ${CAPABILITY}`],
    ["Accept: application/json, text/event-stream"],
    ["Content-Type: application/json"],
    [`Content-Length: ${Buffer.byteLength(initializeJson())}`],
    [`MCP-Protocol-Version: ${PROTOCOL_VERSION}`, `MCP-Protocol-Version: ${PROTOCOL_VERSION}`],
  ]) {
    assert.equal((await rawRequest({
      fixture,
      rawBody: initializeJson(),
      rawHeaders: rawHeadersFor(fixture, duplicate),
    })).statusCode, 400);
  }

  const { sessionId } = await initializedSession(t, fixture);
  assert.equal((await rawRequest({
    fixture,
    rawBody: JSON.stringify(rpc(99, "tools/list")),
    rawHeaders: rawHeadersFor(fixture, [
      `MCP-Protocol-Version: ${PROTOCOL_VERSION}`,
      `MCP-Session-Id: ${sessionId}`,
      `MCP-Session-Id: ${sessionId}`,
    ]),
  })).statusCode, 400);
  assert.equal((await request({ fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId }, rawBody: "{" })).statusCode, 400);
  for (const body of [
    rpc(9, "initialize", { protocolVersion: PROTOCOL_VERSION }),
    rpc(10, "tools/call", { arguments: paymentInput(), name: "other" }),
    rpc(11, "unknown"),
    { id: 12, jsonrpc: "2.0", method: "tools/list", extra: true },
  ]) {
    const response = await request({ body, fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } });
    assert.equal(response.statusCode, 400);
  }
  assert.equal((await request({ body: rpc(13, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 200);
  assert.equal((await request({ body: rpc(13, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 400);
  assert.equal((await request({ body: rpc(13, "tools/list"), fixture, headers: { "MCP-Protocol-Version": "2024-01-01", "MCP-Session-Id": sessionId } })).statusCode, 400);
  assert.equal((await request({ body: rpc(14, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": "wrong" } })).statusCode, 400);
  await fixture.server.stop();
});

test("rejects duplicate JSON keys before parsing can collapse request structure", async (t) => {
  const fixture = await makeFixture(t);
  for (const rawBody of [
    `{"id":1,"id":2,"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"${PROTOCOL_VERSION}"}}`,
    `{"id":1,"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"${PROTOCOL_VERSION}","protocolVersion":"${PROTOCOL_VERSION}"}}`,
  ]) {
    assert.equal((await request({ fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION }, rawBody })).statusCode, 400);
  }

  const { sessionId } = await initializedSession(t, fixture);
  const headers = { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId };
  assert.equal((await request({ fixture, headers, rawBody: '{"id":2,"jsonrpc":"2.0","method":"tools/list","params":{},"params":{}}' })).statusCode, 400);
  assert.equal((await request({ body: rpc(3, "tools/list"), fixture, headers })).statusCode, 200);
  assert.equal((await request({
    fixture,
    headers,
    rawBody: `{"id":4,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"amount":{"currency":"USD","currency":"USD","value":"100"},"intakeRequestId":"${INTAKE_REQUEST_ID}","invoiceReference":"invoice-001","paymentMoved":false,"purpose":"Handshake demo","schema":"clockchain.payer-mcp-payment-intake/v1"},"name":"request_payment"}}`,
  })).statusCode, 400);
  assert.equal((await request({
    fixture,
    headers,
    rawBody: `{"id":5,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"amount":{"currency":"USD","value":"100"},"intakeRequestId":"${INTAKE_REQUEST_ID}","invoiceReference":"invoice-001","paymentMoved":false,"purpose":"Handshake demo","schema":"clockchain.payer-mcp-payment-intake/v1","schema":"clockchain.payer-mcp-payment-intake/v1"},"name":"request_payment"}}`,
  })).statusCode, 400);
});

test("enforces the exact monotonic MCP session state machine", async (t) => {
  const fixture = await makeFixture(t);
  const initialized = await request({ body: rpc(1, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION } });
  const sessionId = initialized.headers["mcp-session-id"];
  const sessionHeaders = { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId };
  assert.equal((await request({ body: rpc(2, "tools/list"), fixture, headers: sessionHeaders })).statusCode, 400);
  assert.equal((await request({ body: rpc(3, "tools/call", { arguments: paymentInput(), name: "request_payment" }), fixture, headers: sessionHeaders })).statusCode, 400);

  const { fixture: secondFixture, sessionId: secondSessionId } = await initializedSession(t);
  const headers = { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": secondSessionId };
  assert.equal((await request({ body: { jsonrpc: "2.0", method: "notifications/initialized" }, fixture: secondFixture, headers })).statusCode, 400);

  const { fixture: thirdFixture, sessionId: thirdSessionId } = await initializedSession(t);
  const thirdHeaders = { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": thirdSessionId };
  assert.equal((await request({ body: rpc(4, "tools/call", { arguments: paymentInput(), name: "request_payment" }), fixture: thirdFixture, headers: thirdHeaders })).statusCode, 400);
  assert.equal((await request({ body: rpc(5, "tools/list"), fixture: thirdFixture, headers: thirdHeaders })).statusCode, 200);
  assert.equal((await request({ body: rpc(6, "tools/call", { arguments: paymentInput(), name: "request_payment" }), fixture: thirdFixture, headers: thirdHeaders })).statusCode, 200);
  assert.equal((await request({ body: rpc(7, "tools/call", { arguments: paymentInput(), name: "request_payment" }), fixture: thirdFixture, headers: thirdHeaders })).statusCode, 400);
});

test("configures the exact MCP server header and request timeouts", async (t) => {
  let created;
  await makeFixture(t, {
    createHttpsServer(options, handler) {
      assert.equal(typeof handler, "function");
      const listeners = new Map();
      created = {
        address: () => ({ address: "127.0.0.1", family: "IPv4", port: 9443 }),
        close: (callback) => callback(),
        headersTimeout: 0,
        listen(port, host, callback) {
          assert.equal(port, 0);
          assert.equal(host, "127.0.0.1");
          callback();
        },
        off(event) {
          listeners.delete(event);
        },
        once(event, listener) {
          listeners.set(event, listener);
        },
        requestTimeout: 0,
      };
      assert.equal(options.cert.includes("BEGIN CERTIFICATE"), true);
      assert.equal(options.key.includes("BEGIN PRIVATE KEY"), true);
      return created;
    },
  });
  assert.equal(created.headersTimeout, 5_000);
  assert.equal(created.requestTimeout, 10_000);
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
  assert.equal((await request({ body: rpc(2, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 200);
  for (let id = 3; id <= 7; id += 1) {
    assert.equal((await request({ body: rpc(id, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 400);
  }
  assert.equal((await request({ body: rpc(8, "tools/list"), fixture, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 400);
  await fixture.server.stop();
});

test("stop clears session and failed-auth state, and failed listen can be retried", async (t) => {
  let now = 1_000;
  const fixture = await makeFixture(t, { nowMs: () => now });
  const { sessionId } = await initializedSession(t, fixture);
  for (let index = 0; index < 16; index += 1) {
    await request({ body: rpc(index + 100, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Authorization: "Bearer bad" } });
  }
  assert.equal((await request({ body: rpc(200, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture, headers: { Authorization: "Bearer bad" } })).statusCode, 429);
  await fixture.server.stop();
  const restarted = { ...fixture, ...(await fixture.server.start()) };
  assert.equal((await request({ body: rpc(201, "tools/list"), fixture: restarted, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION, "MCP-Session-Id": sessionId } })).statusCode, 400);
  assert.equal((await request({ body: rpc(202, "initialize", { protocolVersion: PROTOCOL_VERSION }), fixture: restarted, headers: { "MCP-Protocol-Version": PROTOCOL_VERSION } })).statusCode, 200);

  let attempts = 0;
  const retryServer = createPayerMcpServer({
    capabilityDigest: CAPABILITY_DIGEST,
    createHttpsServer() {
      attempts += 1;
      return {
        address: () => ({ address: "127.0.0.1", family: "IPv4", port: 9443 }),
        close: (callback) => callback(),
        headersTimeout: 0,
        listen(_port, _host, callback) {
          if (attempts === 1) {
            this._error(new Error("listen failed"));
            return;
          }
          callback();
        },
        off() {},
        once(event, listener) {
          if (event === "error") this._error = listener;
        },
        requestTimeout: 0,
      };
    },
    host: "127.0.0.1",
    intakeStore: { writeIntake: async () => undefined },
    port: 0,
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem: fixture.certificate,
    tlsPrivateKeyPem: await readFile(join(fixture.root, "key.pem"), "utf8"),
  });
  await assert.rejects(retryServer.start());
  assert.deepEqual(await retryServer.start(), { host: "127.0.0.1", port: 9443, url: "https://127.0.0.1:9443/mcp" });
  await retryServer.stop();
});
