import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  REQUESTOR_MCP_INTAKE_FILE_NAME,
  requestPaymentThroughPayerMcp,
} from "../src/bilateral/local-mcp/client.mjs";
import { createPayerMcpIntakeStore } from "../src/bilateral/local-mcp/intake-store.mjs";
import {
  PAYMENT_INTAKE_TOOL_DESCRIPTOR,
  buildPaymentIntakeToolResult,
} from "../src/bilateral/local-mcp/payment-intake.mjs";
import { createPayerMcpServer } from "../src/bilateral/local-mcp/server.mjs";

const PROTOCOL_VERSION = "2025-11-25";
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const CAPABILITY = "ab".repeat(32);
const CAPABILITY_DIGEST = createHash("sha256")
  .update(Buffer.from(CAPABILITY, "hex"))
  .digest("hex");
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";

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

async function makeServer(t) {
  const root = await mkdtemp(join(tmpdir(), "requestor-mcp-client-server-"));
  await chmod(root, 0o700);
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
  const server = createPayerMcpServer({
    capabilityDigest: CAPABILITY_DIGEST,
    host: "127.0.0.1",
    intakeStore: await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root }),
    port: 0,
    randomBytes: () => Buffer.alloc(16, 7),
    repositorySha: REPOSITORY_SHA,
    tlsCertificatePem,
    tlsPrivateKeyPem,
  });
  const listening = await server.start();
  t.after(async () => {
    await server.stop();
    await rm(root, { force: true, recursive: true });
  });
  return {
    ...listening,
    fingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
    tlsCertificatePem,
  };
}

test("pinned Requestor client completes exact MCP lifecycle, persists public intake, and keeps capability out of outputs", async (t) => {
  const server = await makeServer(t);
  const stateRoot = await mkdtemp(join(tmpdir(), "requestor-mcp-client-state-"));
  await chmod(stateRoot, 0o700);
  t.after(() => rm(stateRoot, { force: true, recursive: true }));

  process.env.HTTPS_PROXY = "http://proxy.example.invalid:9";
  process.env.HTTP_PROXY = "http://proxy.example.invalid:9";
  process.env.ALL_PROXY = "http://proxy.example.invalid:9";
  t.after(() => {
    delete process.env.HTTPS_PROXY;
    delete process.env.HTTP_PROXY;
    delete process.env.ALL_PROXY;
  });

  const result = await requestPaymentThroughPayerMcp({
    capability: CAPABILITY,
    intakeRequestId: INTAKE_REQUEST_ID,
    mcpUrl: server.url,
    repositorySha: REPOSITORY_SHA,
    stateRoot,
    tlsCertificatePem: server.tlsCertificatePem,
    tlsFingerprint: server.fingerprint,
  });

  const expectedToolResult = buildPaymentIntakeToolResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: paymentInput(),
  });
  assert.deepEqual(result, expectedToolResult.structuredContent);
  assert.equal(result.status, "HANDSHAKE_REQUIRED");
  assert.equal(result.paymentMoved, false);
  assert.equal(JSON.stringify(result).includes(CAPABILITY), false);

  const persisted = await readFile(join(stateRoot, REQUESTOR_MCP_INTAKE_FILE_NAME), "utf8");
  assert.equal(persisted.includes(CAPABILITY), false);
  assert.deepEqual(JSON.parse(persisted), result);
});

test("client rejects transport, lifecycle, schema, result, duplicate-key, and cleanup failures before persisting", async (t) => {
  const stateRoot = await mkdtemp(join(tmpdir(), "requestor-mcp-client-fail-"));
  await chmod(stateRoot, 0o700);
  t.after(() => rm(stateRoot, { force: true, recursive: true }));
  const good = {
    capability: CAPABILITY,
    intakeRequestId: INTAKE_REQUEST_ID,
    mcpUrl: "https://127.0.0.1:4443/mcp",
    repositorySha: REPOSITORY_SHA,
    stateRoot,
    tlsCertificatePem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
    tlsFingerprint: "a".repeat(64),
  };
  const cases = [
    { mcpUrl: "http://127.0.0.1:443/mcp" },
    { mcpUrl: "https://localhost:443/mcp" },
    { mcpUrl: "https://127.0.0.1:443/mcp?x=1" },
    { capability: "AA".repeat(32) },
    { tlsFingerprint: "A".repeat(64) },
    { repositorySha: "b".repeat(40) },
  ];
  for (const overrides of cases) {
    await assert.rejects(
      requestPaymentThroughPayerMcp({
        ...good,
        ...overrides,
        requestJsonRpc: async () => {
          throw new Error("request should not be reached");
        },
      }),
      /Requestor MCP client failed safely/,
    );
  }

  const pinned = await makeServer(t);
  let deleted = false;
  const methods = [];
  const badToolResult = structuredClone(buildPaymentIntakeToolResult({
    repositorySha: REPOSITORY_SHA,
    toolInput: paymentInput(),
  }));
  badToolResult.structuredContent.paymentMoved = true;
  const responseBodies = [
    { id: 1, jsonrpc: "2.0", result: { capabilities: { tools: {} }, protocolVersion: PROTOCOL_VERSION, serverInfo: { name: "clockchain-payer-local-mcp", version: "1.0.0" } } },
    null,
    { id: 2, jsonrpc: "2.0", result: { tools: [PAYMENT_INTAKE_TOOL_DESCRIPTOR] } },
    { id: 3, jsonrpc: "2.0", result: badToolResult },
  ];
  await assert.rejects(
    requestPaymentThroughPayerMcp({
      ...good,
      tlsCertificatePem: pinned.tlsCertificatePem,
      tlsFingerprint: pinned.fingerprint,
      requestJsonRpc: async ({ body, headers, method, url }) => {
        methods.push(method);
        assert.equal(url.href, good.mcpUrl);
        assert.equal(headers.Authorization, `Bearer ${CAPABILITY}`);
        if (method === "DELETE") {
          deleted = true;
          return { body: { paymentMoved: false, status: "deleted" }, headers: { "content-type": "application/json" }, statusCode: 200, text: "{\"paymentMoved\":false,\"status\":\"deleted\"}" };
        }
        assert.equal(JSON.stringify(body).includes(CAPABILITY), false);
        const bodyValue = responseBodies.shift();
        return {
          body: bodyValue,
          headers: body?.method === "initialize"
            ? { "content-type": "application/json", "mcp-protocol-version": PROTOCOL_VERSION, "mcp-session-id": "BwcHBwcHBwcHBwcHBwcHBw" }
            : { "content-type": "application/json" },
          statusCode: body?.method === "notifications/initialized" ? 202 : 200,
          text: JSON.stringify(bodyValue),
        };
      },
    }),
    /Requestor MCP client failed safely/,
  );
  assert.deepEqual(methods, ["POST", "POST", "POST", "POST", "DELETE"]);
  assert.equal(deleted, true);
  await assert.rejects(readFile(join(stateRoot, REQUESTOR_MCP_INTAKE_FILE_NAME)), { code: "ENOENT" });
});
