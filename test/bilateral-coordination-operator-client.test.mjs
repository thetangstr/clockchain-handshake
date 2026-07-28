import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
  X509Certificate,
} from "node:crypto";
import { execFile as execFileCallback } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { privateKeyToAccount } from "viem/accounts";
import { toHex } from "viem";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import {
  createCapabilityRegistration,
} from "../src/bilateral/coordination/capability-registration.mjs";
import {
  PAYER_MANDATE_SCHEMA,
  signPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
import {
  PAYMENT_REQUEST_SCHEMA,
  signPaymentRequest,
} from "../src/bilateral/payment-request.mjs";
import {
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  createOperatorRelayClient,
  createPinnedOperatorHttpsTransport,
  createPinnedOperatorHttpsTransportForTesting,
  OPERATOR_CLIENT_MAX_RESPONSE_BYTES,
} from "../src/bilateral/coordination/operator-client.mjs";
import { CoordinationClientError } from "../src/bilateral/coordination/client.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const RELEASE_ID = "release-operator-client";
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const execFile = promisify(execFileCallback);
const INVITATION_KEYS = Object.freeze({ rehearsal: `0x${"1".repeat(64)}`, stakeholder: `0x${"2".repeat(64)}` });
const INTENT_REQUEST_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const INTENT_PAYER_ACCOUNT = privateKeyToAccount(`0x${"5".repeat(64)}`);
const INTENT_PAYEE_ACCOUNT = privateKeyToAccount(`0x${"6".repeat(64)}`);
const INTENT_OTHER_ACCOUNT = privateKeyToAccount(`0x${"7".repeat(64)}`);
const INTENT_PAYER = Object.freeze({ address: INTENT_PAYER_ACCOUNT.address.toLowerCase(), agentId: "101" });
const INTENT_PAYEE = Object.freeze({ address: INTENT_PAYEE_ACCOUNT.address.toLowerCase(), agentId: "202" });

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function operatorIdentity() {
  const pair = generateKeyPairSync("ed25519");
  return {
    keyId: "clockchain-demo-2026",
    privateKeyPem: pair.privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64"),
  };
}

function rawPublicKey(pair) {
  return pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

async function enrollment(role, coordination) {
  const capabilityDigest = role === "payer" ? "b".repeat(64) : "c".repeat(64);
  const invitationKeys = role === "payer"
    ? INVITATION_KEYS
    : { rehearsal: `0x${"3".repeat(64)}`, stakeholder: `0x${"4".repeat(64)}` };
  const invitations = {};
  for (const run of ["rehearsal", "stakeholder"]) {
    const account = privateKeyToAccount(invitationKeys[run]);
    const address = account.address.toLowerCase();
    invitations[run] = {
      address,
      algorithm: "eip191",
      signature: await account.signMessage({ message: { raw: toHex(invitationProofPreimage({ address, capabilityDigest, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, run, sessionId: SESSION_ID })) } }),
    };
  }
  const body = {
    capabilityDigest,
    coordinationKey: { algorithm: "ed25519", keyId: `${role}-coordination`, publicKey: rawPublicKey(coordination) },
    invitations,
    paymentMoved: false,
    preflightKey: { algorithm: "ed25519", keyId: `${role}-preflight`, publicKey: rawPublicKey(generateKeyPairSync("ed25519")) },
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    schema: "clockchain.bilateral-coordination-enrollment/v1",
    sessionId: SESSION_ID,
  };
  return { ...body, signature: sign(null, coordinationEnrollmentSignaturePreimage(body), coordination.privateKey).toString("base64") };
}

async function enrollmentSet(payer, payee) {
  const entries = {};
  for (const [role, item] of Object.entries({ payer, payee })) {
    const bytes = canonicalBytes(item);
    entries[role] = { enrollmentBase64: bytes.toString("base64"), enrollmentDigest: sha256(bytes), receiptBase64: Buffer.from("receipt", "utf8").toString("base64") };
  }
  return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue({ enrollments: entries, paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, schema: "clockchain.bilateral-coordination-enrollment-set/v1", sessionId: SESSION_ID })), "utf8");
}

function response(body, contentType = "application/json") {
  return {
    body: Buffer.from(body),
    contentType,
    statusCode: 200,
  };
}

function fixture(request) {
  const identity = operatorIdentity();
  return {
    client: createOperatorRelayClient({
      operatorIdentity: identity,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      transport: { request },
    }),
    identity,
  };
}

function canonicalResponse(value) {
  return response(canonicalBytes(value));
}

async function signedLogFixture() {
  const payer = generateKeyPairSync("ed25519");
  const payee = generateKeyPairSync("ed25519");
  const set = await enrollmentSet(await enrollment("payer", payer), await enrollment("payee", payee));
  return Object.freeze({ set });
}

function verifierPublication(subjectRun, publicationDigest = "d".repeat(64)) {
  return {
    paymentMoved: false,
    publicationDigest,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun,
  };
}

function intentMandate(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1785297600000",
    invoiceReferencePrefix: "TREL-",
    issuedAtMs: "1785294000000",
    payee: INTENT_PAYEE,
    payer: INTENT_PAYER,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "freight-services",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    requestEndpoint: `/v1/sessions/${SESSION_ID}/payment-requests`,
    schema: PAYER_MANDATE_SCHEMA,
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
    ...overrides,
  };
}

async function signedIntentMandate(overrides = {}, signer = INTENT_PAYER_ACCOUNT) {
  return signPayerMandate({
    mandate: intentMandate(overrides),
    signMessage: (bytes) => signer.signMessage({ message: { raw: bytes } }),
  });
}

function intentRequest(mandateEnvelope, overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    createdAtMs: "1785294300000",
    expiresAtMs: "1785297000000",
    invoiceReference: "TREL-2026-0001",
    mandateDigest: sha256(canonicalBytes(mandateEnvelope.mandate)),
    payee: INTENT_PAYEE,
    payer: INTENT_PAYER,
    paymentMoved: false,
    protocol: "clockchain.bilateral-authorization/v1",
    purpose: "freight-services",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    requestId: INTENT_REQUEST_ID,
    schema: PAYMENT_REQUEST_SCHEMA,
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
    ...overrides,
  };
}

async function signedIntentRequest(
  mandateEnvelope,
  overrides = {},
  signer = INTENT_PAYEE_ACCOUNT,
) {
  return signPaymentRequest({
    request: intentRequest(mandateEnvelope, overrides),
    signMessage: (bytes) => signer.signMessage({ message: { raw: bytes } }),
  });
}

async function listen(server, t) {
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (error) => error ? reject(error) : resolve()));
  t.after(() => new Promise((resolve) => {
    for (const socket of sockets) socket.destroy();
    server.close(resolve);
  }));
  return server.address().port;
}

function testTransport(tls, port, requestTiming) {
  return createPinnedOperatorHttpsTransportForTesting({
    expectedFingerprint: tls.fingerprint,
    relayUrl: `https://127.0.0.1:${port}`,
    requestTiming,
    tlsCertificatePem: tls.pem,
  });
}

async function certificate(t) {
  const root = await mkdtemp(join(tmpdir(), "operator-client-tls-"));
  const cert = join(root, "cert.pem");
  const key = join(root, "key.pem");
  t.after(() => rm(root, { force: true, recursive: true }));
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", key, "-out", cert, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  await chmod(key, 0o600);
  const pem = await readFile(cert, "utf8");
  return { fingerprint: sha256(new X509Certificate(pem).raw), key: await readFile(key, "utf8"), pem };
}

test("operator client submits one canonical signed capability set and returns its exact receipt", async () => {
  const calls = [];
  let identity;
  const { client, identity: fixtureIdentity } = fixture(async (request) => {
    calls.push(request);
    const registration = JSON.parse(request.body.toString("utf8"));
    const expected = createCapabilityRegistration({
      capabilities: registration.capabilities,
      operatorKeyId: registration.operatorKeyId,
      paymentMoved: false,
      privateKeyPem: identity.privateKeyPem,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
    });
    assert.deepEqual(canonicalBytes(registration), canonicalBytes(expected));
    return response(canonicalBytes({
      capabilities: registration.capabilities,
      paymentMoved: false,
      registrationDigest: sha256(canonicalBytes({ registered: true })),
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      requestDigest: sha256(request.body),
      schema: "clockchain.bilateral-capability-registration-receipt/v1",
      sessionId: SESSION_ID,
    }));
  });
  identity = fixtureIdentity;
  const result = await client.registerCapabilitySet({
    registration: client.prepareCapabilityRegistration({ capabilities: {
      payee: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" },
      payer: { capabilityDigest: "c".repeat(64), expiresAtMs: "1785120060000" },
    } }),
  });
  assert.equal(result.paymentMoved, false);
  assert.deepEqual(calls.map(({ body, method, path }) => ({ body: Buffer.from(body), method, path })), [{
    body: calls[0].body,
    method: "POST",
    path: "/v1/capabilities",
  }]);
});

test("operator client preserves a prepared capability request and rejects its key substitution", async () => {
  const sent = [];
  const { client } = fixture(async (request) => {
    sent.push(Buffer.from(request.body));
    const registration = JSON.parse(request.body.toString("utf8"));
    return response(canonicalBytes({
      capabilities: registration.capabilities,
      paymentMoved: false,
      registrationDigest: "a".repeat(64),
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      requestDigest: sha256(request.body),
      schema: "clockchain.bilateral-capability-registration-receipt/v1",
      sessionId: SESSION_ID,
    }));
  });
  const registration = client.prepareCapabilityRegistration({ capabilities: {
    payee: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" },
    payer: { capabilityDigest: "c".repeat(64), expiresAtMs: "1785120060000" },
  } });
  await client.registerCapabilitySet({ registration });
  assert.deepEqual(sent, [canonicalBytes(registration)]);
  await assert.rejects(
    client.registerCapabilitySet({ registration: { ...registration, operatorKeyId: "other-key" } }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
});

test("operator client fails closed on capability receipt substitution and malformed bytes", async () => {
  for (const body of [
    Buffer.from("{}", "utf8"),
    canonicalBytes({ capabilities: {}, paymentMoved: false, registrationDigest: "a".repeat(64), releaseId: "other", repositorySha: REPOSITORY_SHA, requestDigest: "b".repeat(64), schema: "clockchain.bilateral-capability-registration-receipt/v1", sessionId: SESSION_ID }),
  ]) {
    const { client } = fixture(async () => response(body));
    await assert.rejects(
      client.registerCapabilitySet({ registration: client.prepareCapabilityRegistration({ capabilities: {
        payee: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" },
        payer: { capabilityDigest: "c".repeat(64), expiresAtMs: "1785120060000" },
      } }) }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
    );
  }
});

test("operator client rejects partial, duplicate, and context-substituted capability registrations before transport", async () => {
  let requests = 0;
  const { client } = fixture(async () => { requests += 1; return response(Buffer.from("{}", "utf8")); });
  for (const capabilities of [
    { payer: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" } },
    {
      payee: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" },
      payer: { capabilityDigest: "b".repeat(64), expiresAtMs: "1785120060000" },
    },
  ]) {
    assert.throws(
      () => client.prepareCapabilityRegistration({ capabilities }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
    );
  }
  await assert.rejects(
    client.createVerifiedEvent({
      artifactDigest: "d".repeat(64),
      releaseId: RELEASE_ID,
      repositorySha: "f".repeat(40),
      sessionId: SESSION_ID,
      subjectRun: "rehearsal",
    }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
  assert.equal(requests, 0);
});

test("operator transport rejects plaintext and a certificate/fingerprint mismatch before requests", async (t) => {
  const tls = await certificate(t);
  assert.throws(
    () => createPinnedOperatorHttpsTransport({
      expectedFingerprint: tls.fingerprint,
      relayUrl: "http://127.0.0.1:8443",
      tlsCertificatePem: tls.pem,
    }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
  assert.throws(
    () => createPinnedOperatorHttpsTransport({
      expectedFingerprint: "0".repeat(64),
      relayUrl: "https://127.0.0.1:8443",
      tlsCertificatePem: tls.pem,
    }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
});

test("operator transport marks lost mutation responses ambiguous", async (t) => {
  const tls = await certificate(t);
  const https = await import("node:https");
  const server = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    request.once("end", () => response.socket.destroy());
  });
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", (error) => error ? reject(error) : resolve()));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const transport = createPinnedOperatorHttpsTransport({ expectedFingerprint: tls.fingerprint, relayUrl: `https://127.0.0.1:${port}`, tlsCertificatePem: tls.pem });
  for (const path of ["/v1/capabilities", "/v1/events", "/v1/verified-events"]) {
    await assert.rejects(
      transport.request({ body: Buffer.from("{}", "utf8"), method: "POST", path }),
      { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
      path,
    );
  }
});

test("operator transport closes every route outside the operator allowlist before dialing", async (t) => {
  const tls = await certificate(t);
  const transport = testTransport(tls, 1, { bodyMs: 25, connectMs: 25, headerMs: 25, totalMs: 50 });
  for (const request of [
    { body: null, method: "GET", path: "/v1/capabilities" },
    { body: Buffer.from("{}"), method: "POST", path: "/v1/sessions/anything/events" },
    { body: null, method: "DELETE", path: "/v1/events" },
    { body: null, method: "GET", path: "/v1/artifacts/not-a-digest", artifactType: "token-commitment" },
  ]) {
    await assert.rejects(transport.request(request), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
  }
});

test("operator transport makes connect, header, body-progress, and total deadlines unambiguous", async (t) => {
  const tls = await certificate(t);
  const timings = { bodyMs: 30, connectMs: 30, headerMs: 30, totalMs: 75 };

  const raw = net.createServer((socket) => socket.on("error", () => {}));
  const rawPort = await listen(raw, t);
  await assert.rejects(
    testTransport(tls, rawPort, timings).request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
    "connect timeout",
  );

  const headers = https.createServer({ cert: tls.pem, key: tls.key }, (request) => request.resume());
  const headerPort = await listen(headers, t);
  await assert.rejects(
    testTransport(tls, headerPort, timings).request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
    "header timeout",
  );

  const stalled = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    response.writeHead(200, { "content-length": "2", "content-type": "application/json" });
    response.write("{");
  });
  const stalledPort = await listen(stalled, t);
  await assert.rejects(
    testTransport(tls, stalledPort, timings).request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
    "body-progress timeout",
  );

  const streaming = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    response.writeHead(200, { "content-length": "100", "content-type": "application/json" });
    const interval = setInterval(() => response.write(" "), 10);
    response.once("close", () => clearInterval(interval));
  });
  const streamPort = await listen(streaming, t);
  await assert.rejects(
    testTransport(tls, streamPort, timings).request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
    { code: "COORDINATION_TRANSPORT_AMBIGUOUS" },
    "total timeout",
  );
});

test("operator transport rejects malformed response headers and noncanonical response bodies", async (t) => {
  const tls = await certificate(t);
  let requestCount = 0;
  const server = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    requestCount += 1;
    if (requestCount === 1) {
      response.writeHead(200, { "content-length": "2", "content-type": "text/plain" });
      response.end("{}");
      return;
    }
    if (requestCount === 2) {
      response.writeHead(200, { "content-encoding": "identity", "content-length": "2", "content-type": "application/json" });
      response.end("{}");
      return;
    }
    response.writeHead(200, { "content-length": "3", "content-type": "application/json" });
    response.end(" {}" );
  });
  const port = await listen(server, t);
  const transport = testTransport(tls, port, { bodyMs: 50, connectMs: 50, headerMs: 50, totalMs: 200 });
  for (const label of ["content type", "forbidden header", "noncanonical body"]) {
    await assert.rejects(
      transport.request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
      label,
    );
  }
});

test("operator transport treats only exact commercial-intent reads as bounded octet streams", async (t) => {
  const tls = await certificate(t);
  const body = Buffer.from("{}", "utf8");
  const server = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    response.writeHead(200, { "content-length": String(body.length), "content-type": "application/octet-stream" });
    response.end(body);
  });
  const port = await listen(server, t);
  const transport = testTransport(tls, port, { bodyMs: 50, connectMs: 50, headerMs: 50, totalMs: 200 });
  for (const path of [
    `/v1/sessions/${SESSION_ID}/mandate?subjectRun=rehearsal`,
    `/v1/sessions/${SESSION_ID}/payment-requests/${SESSION_ID}`,
  ]) {
    const result = await transport.request({ body: null, method: "GET", path });
    assert.equal(result.contentType, "application/octet-stream");
    assert.deepEqual(result.body, body);
  }
  await assert.rejects(transport.request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/mandate?subjectRun=release` }), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
});

test("operator transport types only exact safe missing-session view responses", async (t) => {
  const tls = await certificate(t);
  const missing = canonicalBytes({
    code: "COORDINATION_SESSION_NOT_FOUND",
    paymentMoved: false,
  });
  const cases = [
    {
      body: missing,
      headers: { "content-length": String(missing.length), "content-type": "text/plain" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "content-type",
    },
    {
      body: missing,
      headers: { "content-type": "application/json" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "missing content-length",
    },
    {
      body: missing,
      headers: [
        ["content-length", String(missing.length)],
        ["content-length", String(missing.length)],
        ["content-type", "application/json"],
      ],
      statusCode: 404,
      expected: "COORDINATION_TRANSPORT_AMBIGUOUS",
      label: "duplicate content-length",
    },
    {
      body: missing,
      headers: { "content-length": String(OPERATOR_CLIENT_MAX_RESPONSE_BYTES + 1), "content-type": "application/json" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "oversized content-length",
    },
    {
      body: missing,
      headers: { "content-length": String(missing.length), "content-type": "application/json", "transfer-encoding": "chunked" },
      statusCode: 404,
      expected: "COORDINATION_TRANSPORT_AMBIGUOUS",
      label: "transfer-encoding",
    },
    {
      body: missing,
      headers: { "content-encoding": "identity", "content-length": String(missing.length), "content-type": "application/json" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "content-encoding",
    },
    {
      body: missing,
      headers: { "content-length": String(missing.length), "content-type": "application/json", location: "/v1/sessions" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "location",
    },
    {
      body: missing,
      headers: { "content-length": String(missing.length), "content-type": "application/json", upgrade: "h2c" },
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "upgrade",
    },
    {
      body: Buffer.from(`${missing.toString("utf8")}\n`, "utf8"),
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "noncanonical JSON",
    },
    {
      body: canonicalBytes({ code: "COORDINATION_SESSION_NOT_FOUND", extra: false, paymentMoved: false }),
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "extra field",
    },
    {
      body: canonicalBytes({ code: "COORDINATION_SESSION_NOT_FOUND" }),
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "missing field",
    },
    {
      body: canonicalBytes({ code: "COORDINATION_RELAY_REQUEST_INVALID", paymentMoved: false }),
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "wrong code",
    },
    {
      body: canonicalBytes({ code: "COORDINATION_SESSION_NOT_FOUND", paymentMoved: true }),
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_OPERATOR_CLIENT_INVALID",
      label: "payment moved",
    },
    {
      body: missing,
      headers: null,
      statusCode: 404,
      expected: "COORDINATION_SESSION_NOT_FOUND",
      label: "exact missing session",
    },
    {
      abort: true,
      body: missing.subarray(0, missing.length - 1),
      headers: { "content-length": String(missing.length), "content-type": "application/json" },
      statusCode: 404,
      expected: "COORDINATION_TRANSPORT_AMBIGUOUS",
      label: "truncated body",
    },
  ];
  let requestCount = 0;
  const server = https.createServer({ cert: tls.pem, key: tls.key }, (request, response) => {
    request.resume();
    const item = cases[requestCount++];
    const body = item.body;
    const headers = item.headers ?? {
      "content-length": String(body.length),
      "content-type": "application/json",
    };
    response.writeHead(item.statusCode, headers);
    response.write(body);
    if (item.abort) response.destroy();
    else response.end();
  });
  const port = await listen(server, t);
  const transport = testTransport(tls, port, { bodyMs: 50, connectMs: 50, headerMs: 50, totalMs: 200 });

  for (const item of cases) {
    await assert.rejects(
      transport.request({ body: null, method: "GET", path: `/v1/sessions/${SESSION_ID}/view` }),
      { code: item.expected },
      item.label,
    );
  }
});

test("operator client rejects a verifier publication substituted across release context", async () => {
  const { client } = fixture(async () => response(canonicalBytes({
    paymentMoved: false,
    publicationDigest: "d".repeat(64),
    releaseId: "other-release",
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  })));
  await assert.rejects(
    client.readVerifierPublication({
      payer: INTENT_PAYER,
      payee: INTENT_PAYEE,
      subjectRun: "rehearsal",
    }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
});

test("operator client exposes only the coordinator relay boundary", () => {
  const { client } = fixture(async () => response(Buffer.from("null", "utf8")));
  assert.deepEqual(Object.keys(client).sort(), [
    "appendOperatorEvent", "appendVerifiedEvent", "createVerifiedEvent",
    "getArtifact", "prepareCapabilityRegistration", "putArtifact", "readEnrollmentSet", "readEvents",
    "readPayerMandate", "readPaymentRequest", "readSessionView", "readVerifierPublication", "registerCapabilitySet",
  ]);
});

test("readEvents accepts a signed global log and rejects signer, authority, chain, and duplicate-digest attacks", async () => {
  const payer = generateKeyPairSync("ed25519");
  const payee = generateKeyPairSync("ed25519");
  const payerEnrollment = await enrollment("payer", payer);
  const payeeEnrollment = await enrollment("payee", payee);
  const set = await enrollmentSet(payerEnrollment, payeeEnrollment);
  let identity;
  const makeEvent = ({ role, pair, keyId, kind, sequence = "0", previousEventDigest = null }) => createCoordinationEnvelope({ artifactDigest: null, kind, paymentMoved: false, previousEventDigest, privateKeyPem: pair.privateKey.export({ format: "pem", type: "pkcs8" }), publicKey: rawPublicKey(pair), publicKeyId: keyId, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-coordination-event/v1", sequence, sessionId: SESSION_ID, subjectRun: "release" });
  const requests = [];
  let events;
  const built = fixture(async (request) => {
    requests.push(request.path);
    if (request.path.endsWith("/enrollments")) return response(set);
    return response(Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(events)), "utf8"));
  });
  identity = built.identity;
  const operatorPair = { privateKey: { export: () => identity.privateKeyPem }, publicKey: { export: () => Buffer.concat([Buffer.alloc(12), Buffer.from(identity.publicKey, "base64")]) } };
  // The client accepts all canonical lifecycle event kinds, including enrollment and recovery kinds.
  events = [
    makeEvent({ role: "payer", pair: payer, keyId: "payer-coordination", kind: "ENROLLMENT_CONFIRMED" }),
    makeEvent({ role: "payee", pair: payee, keyId: "payee-coordination", kind: "TOKEN_READY" }),
    createCoordinationEnvelope({ artifactDigest: null, kind: "WAIT_FOR_FUNDING", paymentMoved: false, previousEventDigest: null, privateKeyPem: identity.privateKeyPem, publicKey: identity.publicKey, publicKeyId: identity.keyId, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role: "operator", schema: "clockchain.bilateral-coordination-event/v1", sequence: "0", sessionId: SESSION_ID, subjectRun: "release" }),
  ];
  assert.equal((await built.client.readEvents({ after: null, waitMs: 0 })).length, 3);
  for (const hostile of [
    [{ ...events[0], role: "operator" }, events[1], events[2]],
    [{ ...events[0], sequence: "1" }, events[1], events[2]],
    [events[0], events[0], events[2]],
  ]) {
    events = hostile;
    await assert.rejects(built.client.readEvents({ after: null, waitMs: 0 }), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
  }
  assert.ok(requests.every((path) => path.includes("/enrollments") || path.includes("/events?waitMs=0")));
});

test("artifact and advisory-view methods fail closed on hostile route responses", async () => {
  const digest = "a".repeat(64);
  const { client } = fixture(async (request) => {
    if (request.path.startsWith("/v1/artifacts/")) return response(Buffer.from("{}", "utf8"));
    return response(canonicalBytes({ facts: {}, paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, sessionId: SESSION_ID, state: "COMPLETE" }));
  });
  await assert.rejects(client.getArtifact({ artifactType: "token-commitment", digest }), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
  await assert.rejects(client.putArtifact({ artifactType: "unknown", bytes: Buffer.from("x"), expectedDigest: digest }), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
  await assert.rejects(client.readSessionView(), { code: "COORDINATION_OPERATOR_CLIENT_INVALID" });
});

test("appendOperatorEvent appends a signed event only after verifying an enrollment-backed log", async () => {
  const { set } = await signedLogFixture();
  const paths = [];
  const { client } = fixture(async (request) => {
    paths.push(request.path);
    if (request.path.endsWith("/enrollments")) return response(set);
    if (request.path.includes("/events?")) return response(Buffer.from("[]", "utf8"));
    if (request.path === "/v1/events") return response(Buffer.from(request.body));
    throw new Error("unexpected route");
  });
  const accepted = await client.appendOperatorEvent({ artifactDigest: null, kind: "WAIT_FOR_FUNDING", subjectRun: "release" });
  assert.equal(accepted.kind, "WAIT_FOR_FUNDING");
  assert.equal(accepted.role, "operator");
  assert.equal(accepted.sequence, "0");
  assert.deepEqual(paths, [
    `/v1/sessions/${SESSION_ID}/enrollments`,
    `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    "/v1/events",
  ]);
});

test("appendOperatorEvent rejects forged and stale signed server echoes", async () => {
  const { set } = await signedLogFixture();
  for (const mode of ["forged", "stale"]) {
    const built = fixture(async (request) => {
      if (request.path.endsWith("/enrollments")) return response(set);
      if (request.path.includes("/events?")) return response(Buffer.from("[]", "utf8"));
      const event = JSON.parse(request.body.toString("utf8"));
      if (mode === "forged") return canonicalResponse({ ...event, artifactDigest: "e".repeat(64) });
      return canonicalResponse(createCoordinationEnvelope({
        artifactDigest: null,
        kind: "ENROLLMENT_RECEIPT",
        paymentMoved: false,
        previousEventDigest: null,
        privateKeyPem: built.identity.privateKeyPem,
        publicKey: built.identity.publicKey,
        publicKeyId: built.identity.keyId,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        role: "operator",
        sequence: "0",
        sessionId: SESSION_ID,
        subjectRun: "release",
      }));
    });
    await assert.rejects(
      built.client.appendOperatorEvent({ artifactDigest: null, kind: "WAIT_FOR_FUNDING", subjectRun: "release" }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
      mode,
    );
  }
});

test("appendVerifiedEvent binds the publication to its fresh signed verifier event", async () => {
  const { set } = await signedLogFixture();
  const calls = [];
  const { client } = fixture(async (request) => {
    calls.push(request.path);
    if (request.path.endsWith("/enrollments")) return response(set);
    if (request.path.includes("/events?")) return response(Buffer.from("[]", "utf8"));
    const posted = JSON.parse(request.body.toString("utf8"));
    assert.equal(posted.schema, "clockchain.bilateral-verified-event/v1");
    assert.deepEqual(posted.publication, verifierPublication("rehearsal"));
    return canonicalResponse(posted.event);
  });
  const event = await client.createVerifiedEvent({ artifactDigest: "d".repeat(64), releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, sessionId: SESSION_ID, subjectRun: "rehearsal" });
  const accepted = await client.appendVerifiedEvent({ event, publication: verifierPublication("rehearsal") });
  assert.deepEqual(accepted, event);
  assert.equal(calls.filter((path) => path === "/v1/verified-events").length, 1);
});

test("appendVerifiedEvent rejects a publication mismatch before it can be posted", async () => {
  const { set } = await signedLogFixture();
  let postCount = 0;
  const { client } = fixture(async (request) => {
    if (request.path.endsWith("/enrollments")) return response(set);
    if (request.path.includes("/events?")) return response(Buffer.from("[]", "utf8"));
    postCount += 1;
    return canonicalResponse({});
  });
  const event = await client.createVerifiedEvent({ artifactDigest: "d".repeat(64), releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, sessionId: SESSION_ID, subjectRun: "rehearsal" });
  await assert.rejects(
    client.appendVerifiedEvent({ event, publication: verifierPublication("stakeholder") }),
    { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
  );
  assert.equal(postCount, 0);
});

test("appendVerifiedEvent fails closed on a competing chain head, duplicate publication, and lost response", async () => {
  const { set } = await signedLogFixture();
  for (const mode of ["race", "duplicate", "lost-response"]) {
    let verifiedPosts = 0;
    const built = fixture(async (request) => {
      if (request.path.endsWith("/enrollments")) return response(set);
      if (request.path.includes("/events?")) return response(Buffer.from("[]", "utf8"));
      verifiedPosts += 1;
      if (mode === "lost-response") throw new CoordinationClientError("COORDINATION_TRANSPORT_AMBIGUOUS");
      if (mode === "duplicate") return { body: canonicalBytes({ error: "duplicate publication" }), contentType: "application/json", statusCode: 409 };
      const posted = JSON.parse(request.body.toString("utf8"));
      return canonicalResponse(createCoordinationEnvelope({
        artifactDigest: posted.event.artifactDigest,
        kind: "VERIFICATION_PASSED",
        paymentMoved: false,
        previousEventDigest: null,
        privateKeyPem: built.identity.privateKeyPem,
        publicKey: built.identity.publicKey,
        publicKeyId: built.identity.keyId,
        releaseId: RELEASE_ID,
        repositorySha: REPOSITORY_SHA,
        role: "operator",
        sequence: "0",
        sessionId: SESSION_ID,
        subjectRun: "stakeholder",
      }));
    });
    const event = await built.client.createVerifiedEvent({ artifactDigest: "d".repeat(64), releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, sessionId: SESSION_ID, subjectRun: "rehearsal" });
    await assert.rejects(
      built.client.appendVerifiedEvent({ event, publication: verifierPublication("rehearsal") }),
      mode === "lost-response" ? { code: "COORDINATION_TRANSPORT_AMBIGUOUS" } : { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
      mode,
    );
    assert.equal(verifiedPosts, 1, mode);
  }
});

test("operator client exposes only contextual commercial-intent reads", async () => {
  const { client } = fixture(async () => response(Buffer.from("null", "utf8")));
  assert.equal(typeof client.readPayerMandate, "function");
  assert.equal(typeof client.readPaymentRequest, "function");
  assert.equal("publishPayerMandate" in client, false);
  assert.equal("submitPaymentRequest" in client, false);
  for (const helper of [
    "appendPayerMandate",
    "appendPaymentRequest",
    "authorizePaymentRequest",
    "authorizePayment",
    "createAuthorization",
    "markAuthorized",
  ]) {
    assert.equal(helper in client, false, helper);
  }
});

test("operator client rejects hostile payer-mandate reads across envelope and party bindings", async () => {
  const valid = await signedIntentMandate();
  const otherParty = { address: INTENT_OTHER_ACCOUNT.address.toLowerCase(), agentId: "303" };
  const cases = [
    ["wrong outer schema", { ...valid, schema: "clockchain.bilateral-payer-mandate-envelope/v2" }],
    ["forged signature", { ...valid, signature: { ...valid.signature, value: `0x${"0".repeat(130)}` } }],
    ["wrong releaseId", await signedIntentMandate({ releaseId: "release-other" })],
    ["wrong repositorySha", await signedIntentMandate({ repositorySha: "e".repeat(40) })],
    ["wrong sessionId", await signedIntentMandate({ requestEndpoint: "/v1/sessions/9f953393-86d0-4f99-9d6a-102f525fbecd/payment-requests", sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" })],
    ["wrong subjectRun", await signedIntentMandate({ subjectRun: "stakeholder" })],
    ["wrong payer address", await signedIntentMandate({ payer: { ...INTENT_PAYER, address: otherParty.address } }, INTENT_OTHER_ACCOUNT)],
    ["wrong payer agentId", await signedIntentMandate({ payer: { ...INTENT_PAYER, agentId: "303" } })],
    ["wrong payee address", await signedIntentMandate({ payee: { ...INTENT_PAYEE, address: otherParty.address } })],
    ["wrong payee agentId", await signedIntentMandate({ payee: { ...INTENT_PAYEE, agentId: "303" } })],
  ];
  for (const [label, envelope] of cases) {
    const { client } = fixture(async () =>
      response(canonicalBytes(envelope), "application/octet-stream"),
    );
    await assert.rejects(
      client.readPayerMandate({
        payer: INTENT_PAYER,
        payee: INTENT_PAYEE,
        subjectRun: "rehearsal",
      }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
      label,
    );
  }
});

test("operator client rejects hostile payment-request reads across envelope and party bindings", async () => {
  const mandate = await signedIntentMandate();
  const valid = await signedIntentRequest(mandate);
  const otherParty = { address: INTENT_OTHER_ACCOUNT.address.toLowerCase(), agentId: "303" };
  const cases = [
    ["wrong outer schema", { ...valid, schema: "clockchain.bilateral-payment-request-envelope/v2" }],
    ["forged signature", { ...valid, signature: { ...valid.signature, value: `0x${"0".repeat(130)}` } }],
    ["wrong releaseId", await signedIntentRequest(mandate, { releaseId: "release-other" })],
    ["wrong repositorySha", await signedIntentRequest(mandate, { repositorySha: "e".repeat(40) })],
    ["wrong sessionId", await signedIntentRequest(mandate, { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" })],
    ["wrong subjectRun", await signedIntentRequest(mandate, { subjectRun: "stakeholder" })],
    ["wrong payer address", await signedIntentRequest(mandate, { payer: { ...INTENT_PAYER, address: otherParty.address } })],
    ["wrong payer agentId", await signedIntentRequest(mandate, { payer: { ...INTENT_PAYER, agentId: "303" } })],
    ["wrong payee address", await signedIntentRequest(mandate, { payee: { ...INTENT_PAYEE, address: otherParty.address } }, INTENT_OTHER_ACCOUNT)],
    ["wrong payee agentId", await signedIntentRequest(mandate, { payee: { ...INTENT_PAYEE, agentId: "303" } })],
    ["wrong requestId", await signedIntentRequest(mandate, { requestId: "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff" })],
  ];
  for (const [label, envelope] of cases) {
    const { client } = fixture(async () =>
      response(canonicalBytes(envelope), "application/octet-stream"),
    );
    await assert.rejects(
      client.readPaymentRequest({
        payer: INTENT_PAYER,
        payee: INTENT_PAYEE,
        requestId: INTENT_REQUEST_ID,
        subjectRun: "rehearsal",
      }),
      { code: "COORDINATION_OPERATOR_CLIENT_INVALID" },
      label,
    );
  }
});

test("operator client snapshots expected commercial parties before intent read transport awaits", async () => {
  const mandate = await signedIntentMandate();
  const requestEnvelope = await signedIntentRequest(mandate);
  for (const [method, input, body] of [
    [
      "readPayerMandate",
      { payer: { ...INTENT_PAYER }, payee: { ...INTENT_PAYEE }, subjectRun: "rehearsal" },
      canonicalBytes(mandate),
    ],
    [
      "readPaymentRequest",
      { payer: { ...INTENT_PAYER }, payee: { ...INTENT_PAYEE }, requestId: INTENT_REQUEST_ID, subjectRun: "rehearsal" },
      canonicalBytes(requestEnvelope),
    ],
  ]) {
    let release = () => {};
    const { client } = fixture(async () => {
      await new Promise((resolve) => { release = resolve; });
      return response(body, "application/octet-stream");
    });
    const result = client[method](input);
    queueMicrotask(() => {
      input.payer.address = INTENT_OTHER_ACCOUNT.address.toLowerCase();
      input.payer.agentId = "303";
      input.payee.address = INTENT_OTHER_ACCOUNT.address.toLowerCase();
      input.payee.agentId = "303";
      release();
    });
    assert.deepEqual(await result, body, method);
  }
});
