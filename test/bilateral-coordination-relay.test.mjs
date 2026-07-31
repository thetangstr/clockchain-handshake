import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  execFile as execFileCallback,
  spawn,
} from "node:child_process";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";
import {
  fileURLToPath,
} from "node:url";
import { promisify } from "node:util";
import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";

import {
  privateKeyToAccount,
} from "viem/accounts";
import { toHex } from "viem";

import {
  canonicalBytes,
} from "../src/bilateral/canonical.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../src/canonical.mjs";
import {
  createSignedEnvelope,
  dSession,
} from "../src/bilateral/descriptor.mjs";
import {
  PARTY_RESULT_SCHEMA,
  partySignatureBytes,
  writePartyResult,
} from "../src/bilateral/evidence.mjs";
import {
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  createCapabilityRegistration,
} from "../src/bilateral/coordination/capability-registration.mjs";
import {
  TOKEN_COMMITMENT_SIGNATURE_DOMAIN,
} from "../src/bilateral/coordination/preflight.mjs";
import {
  probeKey,
} from "../src/bilateral/refid.mjs";
import {
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
  parseCoordinationEnrollmentSet,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  openCoordinationStore,
} from "../src/bilateral/coordination/storage.mjs";
import {
  MAX_RELAY_WAIT_MS,
  createDescriptorArtifactTransitionValidator,
  createRelayArtifactTransitionValidator,
  createRelayService,
} from "../src/bilateral/coordination/relay.mjs";
import {
  validateRelayArtifactWithFacts,
} from "../src/bilateral/coordination/artifact.mjs";
import {
  signPayerMandate,
} from "../src/bilateral/payer-mandate.mjs";
import {
  signPaymentRequest,
} from "../src/bilateral/payment-request.mjs";
import {
  RELAY_BODY_TIMEOUT_MS,
  RELAY_HEADER_TIMEOUT_MS,
  RELAY_REPOSITORY_ROOT,
  RELAY_TOTAL_TIMEOUT_MS,
  createRelayRequestHandler,
  main as relayMainProduction,
  relayReadinessLine,
} from "../bin/handshake-relay.mjs";

const REPOSITORY_SHA = "e".repeat(40);
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const RELEASE_ID = "release-a";
const NOW_MS = 1_785_120_000_000;
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";
const RECEIPT_SCHEMA =
  "clockchain.bilateral-coordination-receipt/v1";
const OPERATOR_KEY_ID = "relay-test-operator";
const PAYER_CAPABILITY = Buffer.alloc(32, 0x41);
const PAYEE_CAPABILITY = Buffer.alloc(32, 0x42);

function relayMain(arguments_, dependencies = {}) {
  return relayMainProduction(arguments_, {
    ...dependencies,
    allowTestAddresses: true,
  });
}
const execFile = promisify(execFileCallback);

async function invokeRelayHandler(handler, { body = Buffer.alloc(0), contentType = "application/json", hostHeader = "127.0.0.1:8443", method = "POST", url }) {
  const request = new PassThrough();
  request.headers = method === "GET"
    ? { host: hostHeader }
    : { host: hostHeader, "content-type": contentType };
  request.rawHeaders = method === "GET"
    ? ["host", hostHeader]
    : ["host", hostHeader, "content-type", contentType];
  request.method = method;
  request.url = url;
  const response = new EventEmitter();
  const chunks = [];
  response.writeHead = (status, headers) => { response.status = status; response.headers = headers; };
  response.end = (chunk) => { if (chunk !== undefined) chunks.push(Buffer.from(chunk)); response.emit("close"); };
  request.end(body);
  await handler(request, response);
  return { body: Buffer.concat(chunks), status: response.status };
}

const payerCoordination = generateKeyPairSync("ed25519");
const payerPreflight = generateKeyPairSync("ed25519");
const payeeCoordination = generateKeyPairSync("ed25519");
const payeePreflight = generateKeyPairSync("ed25519");

test("routes only exact verified-event posts to the verified service seam", async () => {
  const calls = [];
  const event = { eventDigest: "a".repeat(64) };
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({ eventDigest: "b".repeat(64) }),
    appendVerifiedEvent: async ({ body }) => { calls.push(Buffer.from(body)); return event; },
    bootstrap: async () => ({}), getArtifact: async () => Buffer.alloc(0), putArtifact: async () => ({}), readEnrollmentSet: async () => Buffer.alloc(0), readEvents: async () => [], readSessionView: async () => ({}),
  }, "127.0.0.1", 8443);
  const body = Buffer.from('{"paymentMoved":false}', "utf8");
  const result = await invokeRelayHandler(handler, { body, url: "/v1/verified-events" });
  assert.equal(result.status, 200);
  assert.deepEqual(calls, [body]);
  assert.deepEqual(JSON.parse(result.body), event);
  const rejected = await invokeRelayHandler(handler, { body, url: "/v1/verified-events?x=1" });
  assert.equal(rejected.status, 400);
});

test("routes only exact enrollment-readiness reads to the advisory service seam", async () => {
  const calls = [];
  const ready = {
    paymentMoved: false,
    ready: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  };
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({}),
    appendVerifiedEvent: async () => ({}),
    bootstrap: async () => ({}),
    getArtifact: async () => Buffer.alloc(0),
    putArtifact: async () => ({}),
    readEnrollmentReadiness: async (input) => {
      calls.push(input);
      assert.equal(input.signal?.aborted, false);
      return ready;
    },
    readEnrollmentSet: async () => Buffer.alloc(0),
    readEvents: async () => [],
    readSessionView: async () => ({}),
  }, "127.0.0.1", 8443);
  const url = `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=250`;
  const result = await invokeRelayHandler(handler, { method: "GET", url });
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), ready);
  assert.deepEqual(calls.map(({ sessionId, waitMs }) => ({ sessionId, waitMs })), [
    { sessionId: SESSION_ID, waitMs: 250 },
  ]);
  for (const rejected of [
    `/v1/sessions/${SESSION_ID}/enrollment-readiness`,
    `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=-1`,
    `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=1&after=${"a".repeat(64)}`,
    `/v1/sessions/${SESSION_ID}/enrollment-readiness/`,
  ]) {
    assert.equal((await invokeRelayHandler(handler, { method: "GET", url: rejected })).status, 400);
  }
});

test("routes real service enrollment readiness through the handler validator", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    enrollment: await enrollmentFixture({
      capability: PAYER_CAPABILITY,
      coordination: payerCoordination,
      invitationPrivateKeys: invitationKeys.payer,
      preflight: payerPreflight,
      role: "payer",
    }),
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const handler = createRelayRequestHandler(relay, "127.0.0.1", 8443, REPOSITORY_SHA);
  const result = await invokeRelayHandler(handler, {
    method: "GET",
    url: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
  });
  assert.equal(result.status, 200);
  assert.deepEqual(JSON.parse(result.body), {
    paymentMoved: false,
    ready: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  });
});

test("validates client Host against advertised relay address instead of local bind address", async () => {
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({}),
    appendVerifiedEvent: async () => ({}),
    bootstrap: async () => ({}),
    getArtifact: async () => Buffer.alloc(0),
    putArtifact: async () => ({}),
    readEnrollmentReadiness: async () => ({
      paymentMoved: false,
      ready: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.bilateral-enrollment-readiness/v1",
      sessionId: SESSION_ID,
    }),
    readEnrollmentSet: async () => Buffer.alloc(0),
    readEvents: async () => [],
    readSessionView: async () => ({}),
  }, "32.186.198.119", 8443, REPOSITORY_SHA);
  const accepted = await invokeRelayHandler(handler, {
    hostHeader: "32.186.198.119:8443",
    method: "GET",
    url: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
  });
  assert.equal(accepted.status, 200);
  const rejected = await invokeRelayHandler(handler, {
    hostHeader: "127.0.0.1:8443",
    method: "GET",
    url: `/v1/sessions/${SESSION_ID}/enrollment-readiness?waitMs=0`,
  });
  assert.equal(rejected.status, 400);
});

test("routes the exact payer-owned inbox endpoints with canonical bytes", async () => {
  const calls = [];
  const mandate = Buffer.from('{"mandate":true}', "utf8");
  const request = Buffer.from('{"request":true}', "utf8");
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({}), appendVerifiedEvent: async () => ({}), bootstrap: async () => ({}), getArtifact: async () => Buffer.alloc(0), putArtifact: async () => ({}), readEnrollmentSet: async () => ({}), readEvents: async () => [], readSessionView: async () => ({}),
    readPayerMandate: async (input) => { calls.push(["mandate", input]); return mandate; },
    readPaymentRequest: async (input) => { calls.push(["request", input]); return request; },
    submitPaymentRequest: async (input) => { calls.push(["submit", input]); return { paymentMoved: false, rawEnvelopeDigest: "a".repeat(64) }; },
  }, "127.0.0.1", 8443);
  const mandateUrl = `/v1/sessions/${SESSION_ID}/mandate?subjectRun=rehearsal`;
  const requestUrl = `/v1/sessions/${SESSION_ID}/payment-requests/${SESSION_ID}`;
  const mandateResult = await invokeRelayHandler(handler, { method: "GET", url: mandateUrl });
  assert.equal(mandateResult.status, 200);
  assert.deepEqual(mandateResult.body, mandate);
  const submitted = await invokeRelayHandler(handler, { body: request, contentType: "application/octet-stream", url: `/v1/sessions/${SESSION_ID}/payment-requests` });
  assert.equal(submitted.status, 200);
  const requestResult = await invokeRelayHandler(handler, { method: "GET", url: requestUrl });
  assert.equal(requestResult.status, 200);
  assert.deepEqual(requestResult.body, request);
  assert.deepEqual(calls, [
    ["mandate", { sessionId: SESSION_ID, subjectRun: "rehearsal" }],
    ["submit", { body: request, sessionId: SESSION_ID }],
    ["request", { requestId: SESSION_ID, sessionId: SESSION_ID }],
  ]);
});

test("routes only an exact verifier-publication read to the durable service seam", async () => {
  const calls = [];
  let publication = {
    paymentMoved: false,
    publicationDigest: "a".repeat(64),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({}), appendVerifiedEvent: async () => ({}), bootstrap: async () => ({}), getArtifact: async () => Buffer.alloc(0), putArtifact: async () => ({}), readEnrollmentSet: async () => ({}), readEvents: async () => [], readSessionView: async () => ({}),
    readVerifierPublication: async (input) => { calls.push(input); return publication; },
    registerCapabilities: async () => ({}),
  }, "127.0.0.1", 8443);
  const url = `/v1/sessions/${SESSION_ID}/verifier-publications/rehearsal`;
  const result = await invokeRelayHandler(handler, { method: "GET", url });
  assert.equal(result.status, 200);
  assert.deepEqual(calls, [{ sessionId: SESSION_ID, subjectRun: "rehearsal" }]);
  assert.deepEqual(JSON.parse(result.body), publication);
  publication = null;
  assert.equal(
    JSON.parse((await invokeRelayHandler(handler, { method: "GET", url })).body),
    null,
  );
  for (const rejected of [
    `${url}?x=1`,
    `/v1/sessions/${SESSION_ID}/verifier-publications/release`,
    `/v1/sessions/${SESSION_ID}/verifier-publications/rehearsal/`,
  ]) {
    assert.equal((await invokeRelayHandler(handler, { method: "GET", url: rejected })).status, 400);
  }
  assert.equal((await invokeRelayHandler(handler, { body: Buffer.from("{}"), url })).status, 400);
});

test("routes only exact capability-registration posts to the registration seam", async () => {
  const calls = [];
  const handler = createRelayRequestHandler({
    appendEvent: async () => ({}),
    appendVerifiedEvent: async () => ({}),
    bootstrap: async () => ({}),
    getArtifact: async () => Buffer.alloc(0),
    putArtifact: async () => ({}),
    readEnrollmentSet: async () => ({}),
    readEvents: async () => [],
    readSessionView: async () => ({}),
    registerCapabilities: async ({ body }) => {
      calls.push(Buffer.from(body));
      return { paymentMoved: false };
    },
  }, "127.0.0.1", 8443);
  const body = Buffer.from('{"paymentMoved":false}', "utf8");
  const result = await invokeRelayHandler(handler, {
    body,
    url: "/v1/capabilities",
  });
  assert.equal(result.status, 200);
  assert.deepEqual(calls, [body]);
  assert.equal(
    (await invokeRelayHandler(handler, {
      body,
      url: "/v1/capabilities?retry=1",
    })).status,
    400,
  );
});
const operator = generateKeyPairSync("ed25519");

const invitationKeys = Object.freeze({
  payee: Object.freeze({
    rehearsal: `0x${"3".repeat(64)}`,
    stakeholder: `0x${"4".repeat(64)}`,
  }),
  payer: Object.freeze({
    rehearsal: `0x${"1".repeat(64)}`,
    stakeholder: `0x${"2".repeat(64)}`,
  }),
});

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stableBytes(value) {
  return Buffer.from(
    JSON.stringify(canonicalizeReceiptEventValue(value)),
    "utf8",
  );
}

function rawPublicKey(pair) {
  return pair.publicKey
    .export({ format: "der", type: "spki" })
    .subarray(-32)
    .toString("base64");
}

function privateKeyPem(pair) {
  return pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  });
}

function capabilityRegistration(overrides = {}) {
  return createCapabilityRegistration({
    capabilities: {
      payee: {
        capabilityDigest: sha256(PAYEE_CAPABILITY),
        expiresAtMs: String(NOW_MS + 60_000),
      },
      payer: {
        capabilityDigest: sha256(PAYER_CAPABILITY),
        expiresAtMs: String(NOW_MS + 120_000),
      },
    },
    operatorKeyId: OPERATOR_KEY_ID,
    paymentMoved: false,
    privateKeyPem: privateKeyPem(operator),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    ...overrides,
  });
}

async function privateRoot(t) {
  const root = await mkdtemp(
    join(tmpdir(), "handshake-relay-"),
  );
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function storeFixture(t) {
  const root = await privateRoot(t);
  const store = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => store.close().catch(() => {}));
  return { root, store };
}

async function tlsFixture(
  t,
  algorithm = "ed25519",
  commonName = "127.0.0.1",
) {
  const root = await privateRoot(t);
  const certificatePath = join(root, "tls-cert.pem");
  const privateKeyPath = join(root, "tls-key.pem");
  const keyArguments = {
    "ecdsa-sha256": [
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
    ],
    ed25519: ["ed25519"],
    "rsa-pss-sha256": ["rsa:2048"],
  }[algorithm];
  await execFile("openssl", [
    "req",
    "-x509",
    "-newkey",
    ...keyArguments,
    "-keyout",
    privateKeyPath,
    "-out",
    certificatePath,
    "-nodes",
    "-days",
    "1",
    "-subj",
    `/CN=${commonName}`,
    "-addext",
    `subjectAltName=${net.isIP(commonName) === 0 ? "DNS" : "IP"}:${commonName}`,
  ]);
  await chmod(privateKeyPath, 0o600);
  await chmod(certificatePath, 0o644);
  return {
    certificate: await readFile(certificatePath),
    certificatePath,
    privateKeyPath,
    root,
  };
}

async function availablePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  await new Promise((resolve, reject) => {
    server.close((error) =>
      error === undefined ? resolve() : reject(error),
    );
  });
  return port;
}

function waitForTcpListener(host, port) {
  let deadlineTimer;
  let retryTimer;
  let settled = false;
  let resolveListener;
  let socket;
  const finish = (outcome) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadlineTimer);
    clearTimeout(retryTimer);
    socket?.destroy();
    resolveListener(outcome);
  };
  const listener = new Promise((resolve) => {
    resolveListener = resolve;
    deadlineTimer = setTimeout(
      () => finish({ kind: "deadline" }),
      RELAY_TOTAL_TIMEOUT_MS,
    );
    const attempt = () => {
      if (settled) return;
      socket = net.createConnection({ host, port });
      socket.once("connect", () => {
        socket.destroy();
        finish({ kind: "listening" });
      });
      socket.once("error", () => {
        socket.destroy();
        retryTimer = setTimeout(attempt, 20);
      });
    };
    attempt();
  });
  return { cancel: () => finish({ kind: "cancelled" }), listener };
}

async function observeRelayChild(child, host, port) {
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const closed = new Promise((resolveClose) => {
    child.once("close", (code, signal) => {
      resolveClose({
        code,
        kind: "exit",
        signal,
        stderr,
      });
    });
  });
  const listener = waitForTcpListener(host, port);
  const outcome = await Promise.race([
    closed,
    listener.listener,
  ]);
  listener.cancel();
  if (outcome.kind !== "exit") {
    child.kill("SIGTERM");
    await closed;
  }
  return outcome;
}

function relayArguments({
  advertisedHost = "127.0.0.1",
  certificatePath,
  host = "127.0.0.1",
  port,
  privateKeyPath,
  repositorySha = REPOSITORY_SHA,
  state,
}) {
  return [
    "--advertised-host",
    advertisedHost,
    "--host",
    host,
    "--port",
    String(port),
    "--repository-sha",
    repositorySha,
    "--state",
    state,
    "--tls-certificate",
    certificatePath,
    "--tls-private-key",
    privateKeyPath,
  ];
}

function cleanCheckoutProbe() {
  return Promise.resolve({
    clean: true,
    repositorySha: REPOSITORY_SHA,
  });
}

async function httpsRequest({
  body,
  ca,
  headers = {},
  method,
  path,
  port,
  servername,
}) {
  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        ca,
        headers,
        host: "127.0.0.1",
        method,
        path,
        port,
        rejectUnauthorized: true,
        ...(servername === undefined ? {} : { servername }),
      },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => {
          resolve({
            body: Buffer.concat(chunks),
            headers: response.headers,
            statusCode: response.statusCode,
          });
        });
      },
    );
    request.on("error", reject);
    if (body !== undefined) {
      request.end(body);
    } else {
      request.end();
    }
  });
}

async function rawTlsRequest({
  ca,
  port,
  request,
}) {
  return new Promise((resolveResponse, rejectResponse) => {
    const socket = tls.connect({
      ca,
      host: "127.0.0.1",
      port,
      rejectUnauthorized: true,
    });
    const chunks = [];
    socket.once("secureConnect", () => {
      socket.end(request);
    });
    socket.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk));
    });
    socket.once("end", () => {
      resolveResponse(
        Buffer.concat(chunks).toString("utf8"),
      );
    });
    socket.once("error", rejectResponse);
  });
}

async function registerRole(
  store,
  {
    capability,
    expiresAtMs = String(NOW_MS + 60_000),
    releaseId = RELEASE_ID,
    role,
  },
) {
  return store.registerCapability({
    capabilityDigest: sha256(capability),
    expiresAtMs,
    releaseId,
    role,
    sessionId: SESSION_ID,
  });
}

function signedEnrollment(unsigned, coordination) {
  return {
    ...unsigned,
    signature: sign(
      null,
      coordinationEnrollmentSignaturePreimage(unsigned),
      privateKeyPem(coordination),
    ).toString("base64"),
  };
}

async function enrollmentFixture({
  capability,
  coordination,
  invitationPrivateKeys,
  invitationSigners = invitationPrivateKeys,
  preflight,
  preflightKeyId,
  preflightPublicKey = rawPublicKey(preflight),
  releaseId = RELEASE_ID,
  role,
}) {
  const accounts = {
    rehearsal: privateKeyToAccount(
      invitationPrivateKeys.rehearsal,
    ),
    stakeholder: privateKeyToAccount(
      invitationPrivateKeys.stakeholder,
    ),
  };
  const signers = {
    rehearsal: privateKeyToAccount(
      invitationSigners.rehearsal,
    ),
    stakeholder: privateKeyToAccount(
      invitationSigners.stakeholder,
    ),
  };
  const capabilityDigest = sha256(capability);
  const invitations = {};
  for (const run of ["rehearsal", "stakeholder"]) {
    const address = accounts[run].address.toLowerCase();
    invitations[run] = {
      address,
      algorithm: "eip191",
      signature: await signers[run].signMessage({
        message: {
          raw: toHex(
            invitationProofPreimage({
              address,
              capabilityDigest,
              releaseId,
              repositorySha: REPOSITORY_SHA,
              role,
              run,
              sessionId: SESSION_ID,
            }),
          ),
        },
      }),
    };
  }
  return signedEnrollment(
    {
      capabilityDigest,
      coordinationKey: {
        algorithm: "ed25519",
        keyId: `${role}-coordination`,
        publicKey: rawPublicKey(coordination),
      },
      invitations,
      paymentMoved: false,
      preflightKey: {
        algorithm: "ed25519",
        keyId:
          preflightKeyId ?? `${role}-preflight`,
        publicKey: preflightPublicKey,
      },
      releaseId,
      repositorySha: REPOSITORY_SHA,
      role,
      schema:
        "clockchain.bilateral-coordination-enrollment/v1",
      sessionId: SESSION_ID,
    },
    coordination,
  );
}

function bootstrapBody(capability, enrollment) {
  return canonicalBytes({
    capability: capability.toString("hex"),
    enrollment,
  });
}

function makeReceiptSigner({
  verifyResult = true,
} = {}) {
  const pair = generateKeyPairSync("ed25519");
  let signCalls = 0;
  const signer = Object.freeze({
    certificateSha256: "c".repeat(64),
    signatureAlgorithm: "ed25519",
    sign(preimage) {
      signCalls += 1;
      return sign(null, preimage, pair.privateKey);
    },
    verify(preimage, signature) {
      return (
        verifyResult &&
        verify(null, preimage, pair.publicKey, signature)
      );
    },
  });
  return {
    get signCalls() {
      return signCalls;
    },
    signer,
  };
}

function repositoryResolver(calls = []) {
  return async (context) => {
    calls.push(context);
    return `${rawPublicKey(operator)}\n`;
  };
}

function relayFixture(
  store,
  {
    receipt = makeReceiptSigner(),
    resolver = repositoryResolver(),
  } = {},
) {
  return {
    receipt,
    relay: createRelayService({
      frozenRepositorySha: REPOSITORY_SHA,
      now: () => NOW_MS,
      receiptSigner: receipt.signer,
      repositoryPublicKeyResolver: resolver,
      store,
    }),
  };
}

function storeFacade(store, overrides = {}) {
  return Object.freeze({
    appendEvent: store.appendEvent,
    appendVerifiedEvent: store.appendVerifiedEvent,
    consumeCapability: store.consumeCapability,
    getArtifact: store.getArtifact,
    putPayerMandate: store.putPayerMandate,
    putPaymentRequest: store.putPaymentRequest,
    putArtifact: store.putArtifact,
    readEnrollment: store.readEnrollment,
    readPayerMandate: store.readPayerMandate,
    readPaymentRequest: store.readPaymentRequest,
    readCapabilitySet: store.readCapabilitySet,
    readEvents: store.readEvents,
    readReleaseView: store.readReleaseView,
    readVerifierPublication: store.readVerifierPublication,
    registerCapabilitySet: store.registerCapabilitySet,
    ...overrides,
  });
}

test("registers only an exact operator-signed capability pair and returns a secret-free receipt", async (t) => {
  const { store } = await storeFixture(t);
  const { relay } = relayFixture(store);
  const request = capabilityRegistration();
  const body = canonicalBytes(request);
  const receipt = await relay.registerCapabilities({ body });
  assert.deepEqual(receipt, {
    capabilities: request.capabilities,
    paymentMoved: false,
    registrationDigest: sha256(canonicalBytes({
      payee: {
        ...request.capabilities.payee,
        releaseId: RELEASE_ID,
        role: "payee",
        sessionId: SESSION_ID,
      },
      payer: {
        ...request.capabilities.payer,
        releaseId: RELEASE_ID,
        role: "payer",
        sessionId: SESSION_ID,
      },
    })),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-capability-registration-receipt/v1",
    sessionId: SESSION_ID,
    requestDigest: sha256(canonicalBytes(request)),
  });
  assert.equal(receipt.registrationDigest.includes(PAYER_CAPABILITY.toString("hex")), false);
  assert.deepEqual(
    await relay.registerCapabilities({ body }),
    receipt,
  );
  const wrongKey = capabilityRegistration({
    privateKeyPem: privateKeyPem(generateKeyPairSync("ed25519")),
  });
  const cases = [
    canonicalBytes({ ...request, unexpected: false }),
    canonicalBytes({ ...request, repositorySha: "d".repeat(40) }),
    canonicalBytes(wrongKey),
    Buffer.concat([body, Buffer.from(" ", "utf8")]),
    Buffer.alloc(65_537, 0x61),
  ];
  for (const candidate of cases) {
    await assert.rejects(
      relay.registerCapabilities({ body: candidate }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
  await assert.rejects(
    relay.registerCapabilities({
      body: canonicalBytes(capabilityRegistration({
        capabilities: {
          payee: {
            capabilityDigest: sha256(PAYEE_CAPABILITY),
            expiresAtMs: String(NOW_MS),
          },
          payer: {
            capabilityDigest: sha256(PAYER_CAPABILITY),
            expiresAtMs: String(NOW_MS + 120_000),
          },
        },
      })),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("returns a durable identical capability-registration retry after expiry but rejects a changed expired retry", async (t) => {
  const { root, store } = await storeFixture(t);
  let nowMs = NOW_MS;
  const receipt = makeReceiptSigner();
  const request = capabilityRegistration();
  const createRelay = (activeStore) => createRelayService({
    frozenRepositorySha: REPOSITORY_SHA,
    now: () => nowMs,
    receiptSigner: receipt.signer,
    repositoryPublicKeyResolver: repositoryResolver(),
    store: activeStore,
  });
  const first = await createRelay(store).registerCapabilities({
    body: canonicalBytes(request),
  });
  nowMs += 60_001;
  await store.close();
  const restartedStore = await openCoordinationStore({
    now: () => nowMs,
    repositorySha: REPOSITORY_SHA,
    root,
  });
  t.after(() => restartedStore.close().catch(() => {}));
  assert.deepEqual(
    await createRelay(restartedStore).registerCapabilities({
      body: canonicalBytes(request),
    }),
    first,
  );
  await assert.rejects(
    createRelay(restartedStore).registerCapabilities({
      body: canonicalBytes(capabilityRegistration({
        capabilities: {
          payee: {
            ...request.capabilities.payee,
            expiresAtMs: String(NOW_MS + 90_000),
          },
          payer: request.capabilities.payer,
        },
      })),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

function eventFixture({
  artifactDigest = null,
  coordination,
  keyId,
  kind,
  previousEventDigest = null,
  role,
  sequence = "0",
  subjectRun = "release",
}) {
  return createCoordinationEnvelope({
    artifactDigest,
    kind,
    paymentMoved: false,
    previousEventDigest,
    privateKeyPem: privateKeyPem(coordination),
    publicKey: rawPublicKey(coordination),
    publicKeyId: keyId,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role,
    schema:
      "clockchain.bilateral-coordination-event/v1",
    sequence,
    sessionId: SESSION_ID,
    subjectRun,
  });
}

function descriptorFixture({
  keyId = OPERATOR_KEY_ID,
  repositorySha = REPOSITORY_SHA,
  sessionId = "00112233445566778899aabbccddeeff",
} = {}) {
  return createSignedEnvelope(
    {
      amountOptions: [
        { currency: "USD", value: "100" },
      ],
      chainId: "11155111",
      expirySeconds: "600",
      mandateDigest: "b".repeat(64),
      namespace: "cbv1",
      payee: {
        address:
          "0xffeeddccbbaa99887766554433221100ffeeddcc",
        agentId: "8678",
        displayName: "Iris",
        role: "payee",
      },
      payer: {
        address:
          "0x00112233445566778899aabbccddeeff00112233",
        agentId: "8677",
        displayName: "Billy",
        role: "payer",
      },
      paymentMoved: false,
      promptSha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      protocol: "clockchain.bilateral-authorization/v1",
      protocolVersion: "1",
      registry:
        "0x8004a818bfb912233c491871b3d84c89a494bd9e",
      repositorySha,
      requestDigest: "c".repeat(64),
      schema:
        "clockchain.bilateral-session-descriptor/v2",
      sessionId,
      settlement: "not-executed",
    },
    {
      keyId,
      privateKeyPem: privateKeyPem(operator),
    },
  );
}

function descriptorArtifactMap(...descriptors) {
  const artifacts = new Map();
  for (const descriptor of descriptors) {
    const bytes = canonicalBytes(descriptor);
    artifacts.set(sha256(bytes), bytes);
  }
  return artifacts;
}

function descriptorValidator(artifacts) {
  return createDescriptorArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact(digest) {
      const bytes = artifacts.get(digest);
      if (bytes === undefined) {
        throw new Error("missing test artifact");
      }
      return bytes;
    },
    async resolveOperatorPublicKey() {
      return rawPublicKey(operator);
    },
  });
}

function relayPackage(files) {
  return stableBytes({
    files: files.map(([name, bytes]) => ({
      byteLength: String(bytes.length),
      contentBase64: bytes.toString("base64"),
      name,
      sha256: sha256(bytes),
    })),
    paymentMoved: false,
    schema: "clockchain.bilateral-relay-package/v1",
  });
}

function tokenCommitment(role, coordination, token = `${role}-token`) {
  const unsigned = {
    algorithm: "ed25519",
    coordinationPublicKey: rawPublicKey(coordination),
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    role,
    schema: "clockchain.bilateral-token-commitment/v1",
    tokenSha256: sha256(Buffer.from(token)),
  };
  return {
    ...unsigned,
    signature: sign(null, Buffer.concat([
      Buffer.from(TOKEN_COMMITMENT_SIGNATURE_DOMAIN, "ascii"),
      Buffer.from(sha256(canonicalBytes(unsigned)), "ascii"),
    ]), coordination.privateKey).toString("base64"),
  };
}

function repackPreflight(bytes, name, markerSchema, mutate, signer) {
  const wrapper = JSON.parse(bytes.toString("utf8"));
  const file = wrapper.files.find((entry) => entry.name === `${name}.json`);
  const envelope = JSON.parse(Buffer.from(file.contentBase64, "base64").toString("utf8"));
  mutate(envelope);
  envelope.signature.value = sign(null, canonicalBytes(envelope.report), signer.privateKey).toString("base64");
  return preflightPackage(name, envelope, markerSchema);
}

function preflightPackage(name, envelope, markerSchema) {
  const content = stableBytes(envelope);
  return relayPackage([
    [`.${name}.complete.json`, stableBytes({ fileSha256: sha256(content), schema: markerSchema })],
    [`${name}.json`, content],
  ]);
}

function identityPackage(identity) {
  const content = stableBytes({
    address: identity.address,
    agentId: identity.agentId,
    chainId: "11155111",
    displayName: identity.displayName,
    identityReference: `eip155:11155111:0x8004A818BFB912233c491871b3d84c89A494BD9e:${identity.agentId}`,
    metadata: { blockHeight: "2", transactionHash: `0x${"2".repeat(64)}` },
    paymentMoved: false,
    register: { blockHeight: "1", transactionHash: `0x${"3".repeat(64)}` },
    registryAddress: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-identity-registration/v1",
  });
  return relayPackage([
    [".identity.complete.json", stableBytes({ fileSha256: sha256(content), schema: "clockchain.bilateral-identity-registration-completion/v1" })],
    ["identity.json", content],
  ]);
}

function recoveryManifest({ command = "bin/handshake-propose.mjs", outputPath = "/state/output", role = "payer", subjectRun = "rehearsal", ...scope } = {}) {
  return stableBytes({ arguments: ["--clockchain-token-file", "/state/plan", "--descriptor", "/state/descriptor", "--invitation", "/state/invitation", "--output", outputPath, "--i-understand-this-writes-to-clockchain"], command, paymentMoved: false, reasonCode: "AMBIGUOUS_WRITE", releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-recovery-command-manifest/v1", sessionId: SESSION_ID, subjectRun, ...scope });
}

function failureSummary({ role = "payer", subjectRun = "rehearsal", ...scope } = {}) {
  return stableBytes({ eventKind: "TERMINAL_FAILURE", paymentMoved: false, releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-failure-summary/v1", sessionId: SESSION_ID, subjectRun, terminalCode: "FAILED", ...scope });
}

function enrolledDescriptor(identities) {
  return createSignedEnvelope({
    amountOptions: [{ currency: "USD", value: "100" }], chainId: "11155111", expirySeconds: "600", mandateDigest: "b".repeat(64), namespace: "cbv1",
    payee: { ...identities.payee, role: "payee" }, payer: { ...identities.payer, role: "payer" },
    paymentMoved: false, promptSha256: "ef".repeat(32), protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e", repositorySha: REPOSITORY_SHA,
    requestDigest: "c".repeat(64), schema: "clockchain.bilateral-session-descriptor/v2", sessionId: "00112233445566778899aabbccddeeff", settlement: "not-executed",
  }, { keyId: OPERATOR_KEY_ID, privateKeyPem: privateKeyPem(operator) });
}

function contextualPreflightArtifacts() {
  const tokens = {
    payer: tokenCommitment("payer", payerCoordination),
    payee: tokenCommitment("payee", payeeCoordination),
  };
  const nonce = "0123456789abcdef0123456789abcdef";
  const plan = {
    digests: { payer: "a".repeat(64), payee: "b".repeat(64) },
    keys: { payer: probeKey(nonce, "payer"), payee: probeKey(nonce, "payee") },
    nonce,
    participants: {
      payer: { coordinationPublicKey: rawPublicKey(payerCoordination), publicKey: rawPublicKey(payerPreflight), tokenCommitment: tokens.payer },
      payee: { coordinationPublicKey: rawPublicKey(payeeCoordination), publicKey: rawPublicKey(payeePreflight), tokenCommitment: tokens.payee },
    },
    paymentMoved: false, protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1",
    repositorySha: REPOSITORY_SHA, schema: "clockchain.bilateral-preflight-plan/v1", writeBudget: "2",
  };
  const planEnvelope = { operator: { algorithm: "ed25519", keyId: OPERATOR_KEY_ID, publicKey: rawPublicKey(operator), signature: sign(null, canonicalBytes(plan), operator.privateKey).toString("base64") }, plan };
  const planDigest = sha256(canonicalBytes(plan));
  const write = (role) => ({ anchoredHash: plan.digests[role], assetReferenceId: plan.keys[role], blockHeight: role === "payer" ? "7" : "8", digest: plan.digests[role], key: plan.keys[role], ledgerId: role === "payer" ? "8f953393-86d0-4f99-9d6a-102f525fbecd" : "9f953393-86d0-4f99-9d6a-102f525fbecd", role });
  const anchor = (role) => {
    const { digest, key, role: ignored, ...value } = write(role);
    return value;
  };
  const observation = (peer) => ({ conflict: false, digestAnchor: anchor(peer), digestResolved: true, finalAnchor: anchor(peer), finalVerified: true, peer, referenceAnchor: anchor(peer), referenceResolved: true });
  const participant = (role, key) => {
    const peer = role === "payer" ? "payee" : "payer";
    const report = { channel: "derived-reference-id", completedAtMs: "120000", deadlineAtMs: "120000", observations: [{ channel: "ledger-height", code: "PREFLIGHT_READ_FAILED", observer: role }], paymentMoved: false, peerObservation: observation(peer), planDigest, rateLimits: [{ channel: "digest-hash", code: "MCP_RATE_LIMIT", observer: role, retryAfterMs: "0", wireShape: "http-429" }], repositorySha: REPOSITORY_SHA, role, schema: "clockchain.bilateral-preflight-participant/v1", serializedCadenceMs: "20000", sleeps: ["20000"], startedAtMs: "100000", tokenCommitment: tokens[role], write: write(role) };
    return { report, signature: { algorithm: "ed25519", role, value: sign(null, canonicalBytes(report), key.privateKey).toString("base64") } };
  };
  const participants = { payer: participant("payer", payerPreflight), payee: participant("payee", payeePreflight) };
  const aggregateReport = { channel: "derived-reference-id", completedAtMs: "120001", directions: [{ observer: "payer", ...observation("payee") }, { observer: "payee", ...observation("payer") }], outcome: "RENDEZVOUS_OK", paymentMoved: false, planDigest, protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1", repositorySha: REPOSITORY_SHA, schema: "clockchain.bilateral-preflight/v2", scope: { separateCredentialsAttested: true, separateMachinesAttested: true }, tenancy: "cross-client", writes: [write("payer"), write("payee")] };
  const aggregate = { report: aggregateReport, signature: { algorithm: "ed25519", keyId: OPERATOR_KEY_ID, value: sign(null, canonicalBytes(aggregateReport), operator.privateKey).toString("base64") } };
  return { aggregate: preflightPackage("preflight-report", aggregate, "clockchain.bilateral-preflight-completion/v1"), participants: { payer: preflightPackage("participant-report", participants.payer, "clockchain.bilateral-preflight-participant-completion/v1"), payee: preflightPackage("participant-report", participants.payee, "clockchain.bilateral-preflight-participant-completion/v1") }, plan: stableBytes(planEnvelope), tokens };
}

test("binds the complete signed preflight artifact chain", async () => {
  const artifacts = contextualPreflightArtifacts();
  const enrollment = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const bytes = new Map([
    [sha256(stableBytes(artifacts.tokens.payer)), stableBytes(artifacts.tokens.payer)],
    [sha256(stableBytes(artifacts.tokens.payee)), stableBytes(artifacts.tokens.payee)],
    [sha256(artifacts.plan), artifacts.plan],
    [sha256(artifacts.participants.payer), artifacts.participants.payer],
    [sha256(artifacts.participants.payee), artifacts.participants.payee],
    [sha256(artifacts.aggregate), artifacts.aggregate],
  ]);
  const validator = createRelayArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact(digest) { return bytes.get(digest); },
    async readEnrollment({ role }) { return { bytes: canonicalBytes(enrollment[role]) }; },
    async resolveOperatorPublicKey() { return rawPublicKey(operator); },
  });
  const event = (role, kind, artifactDigest) => eventFixture({ artifactDigest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun: kind === "REGISTER_REHEARSAL" ? "rehearsal" : "release" });
  await assert.doesNotReject(validator.validate(event("payer", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payer)))));
  await assert.doesNotReject(validator.validate(event("payee", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payee)))));
  await assert.doesNotReject(validator.validate(event("operator", "PREFLIGHT_PLAN_READY", sha256(artifacts.plan))));
  await assert.doesNotReject(validator.validate(event("payer", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payer))));
  await assert.doesNotReject(validator.validate(event("payee", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payee))));
  await assert.doesNotReject(validator.validate(event("operator", "REGISTER_REHEARSAL", sha256(artifacts.aggregate))));
});

test("rebinds operator plan enrollment scope instead of trusting store indexing", async () => {
  const artifacts = contextualPreflightArtifacts();
  const correct = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const wrongPayer = await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, releaseId: "release-b", role: "payer" });
  const values = new Map([[sha256(stableBytes(artifacts.tokens.payer)), stableBytes(artifacts.tokens.payer)], [sha256(stableBytes(artifacts.tokens.payee)), stableBytes(artifacts.tokens.payee)], [sha256(artifacts.plan), artifacts.plan]]);
  let payerReads = 0;
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment({ role }) { if (role === "payer" && payerReads++ === 1) return { bytes: canonicalBytes(wrongPayer) }; return { bytes: canonicalBytes(correct[role]) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  const event = (role, kind, artifactDigest) => eventFixture({ artifactDigest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun: "release" });
  await validator.validate(event("payer", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payer))));
  await validator.validate(event("payee", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payee))));
  await assert.rejects(validator.validate(event("operator", "PREFLIGHT_PLAN_READY", sha256(artifacts.plan))), { code: "COORDINATION_RELAY_INVALID" });
});

test("replays contextual artifacts across relay restart fail-closed", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, { capability: PAYER_CAPABILITY, role: "payer" });
  await registerRole(store, { capability: PAYEE_CAPABILITY, role: "payee" });
  const receipt = makeReceiptSigner();
  const { relay } = relayFixture(store, { receipt });
  await bootstrapRole(relay, { capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" });
  await bootstrapRole(relay, { capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" });
  const artifacts = contextualPreflightArtifacts();
  const identity = identityPackage({ address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" });
  const uploads = [["token-commitment", stableBytes(artifacts.tokens.payer)], ["token-commitment", stableBytes(artifacts.tokens.payee)], ["preflight-plan", artifacts.plan], ["preflight-participant-report", artifacts.participants.payer], ["preflight-participant-report", artifacts.participants.payee], ["preflight-aggregate-report", artifacts.aggregate], ["identity-package", identity]];
  for (const [artifactType, body] of uploads) await relay.putArtifact({ artifactType, body, expectedDigest: sha256(body) });
  const build = eventBuilder();
  for (const input of [["payer", "ENROLLMENT_CONFIRMED"], ["payee", "ENROLLMENT_CONFIRMED"], ["operator", "ENROLLMENT_RECEIPT"], ["operator", "WAIT_FOR_FUNDING"], ["payer", "FUNDING_INPUTS_READY"], ["payee", "FUNDING_INPUTS_READY"], ["payer", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payer))], ["payee", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payee))], ["operator", "PREFLIGHT_PLAN_READY", sha256(artifacts.plan)], ["payer", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payer)], ["payee", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payee)]]) await relay.appendEvent({ body: canonicalBytes(build({ role: input[0], kind: input[1], artifactDigest: input[2] })) });
  const { relay: restarted } = relayFixture(store, { receipt });
  await restarted.appendEvent({ body: canonicalBytes(build({ role: "operator", kind: "REGISTER_REHEARSAL", artifactDigest: sha256(artifacts.aggregate), subjectRun: "rehearsal" })) });
  assert.equal((await store.readEvents({ after: null, sessionId: SESSION_ID })).length, 12);
  const broken = relayFixture(storeFacade(store, { getArtifact: async (digest) => { if (digest === sha256(artifacts.plan)) throw new Error("missing plan"); return store.getArtifact(digest); } }), { receipt }).relay;
  const identityEvent = build({ role: "payer", kind: "IDENTITY_PACKAGE_READY", artifactDigest: sha256(identity), subjectRun: "rehearsal" });
  await assert.rejects(broken.appendEvent({ body: canonicalBytes(identityEvent) }), { code: "COORDINATION_RELAY_INVALID" });
  assert.equal((await store.readEvents({ after: null, sessionId: SESSION_ID })).length, 12);
  const { relay: normal } = relayFixture(store, { receipt });
  await normal.appendEvent({ body: canonicalBytes(identityEvent) });
  assert.equal((await store.readEvents({ after: null, sessionId: SESSION_ID })).length, 13);
});

test("rejects contextually substituted preflight artifacts", async () => {
  const fixture = contextualPreflightArtifacts();
  const enrollment = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const alternate = generateKeyPairSync("ed25519");
  const participant = (bytes, mutate, signer = payerPreflight) => repackPreflight(bytes, "participant-report", "clockchain.bilateral-preflight-participant-completion/v1", mutate, signer);
  const aggregate = (mutate, signer = operator) => repackPreflight(fixture.aggregate, "preflight-report", "clockchain.bilateral-preflight-completion/v1", mutate, signer);
  const cases = [
    ["participant signer", "participant", participant(fixture.participants.payer, () => {}, alternate)],
    ["participant plan digest", "participant", participant(fixture.participants.payer, ({ report }) => { report.planDigest = "c".repeat(64); })],
    ["participant token", "participant", participant(fixture.participants.payer, ({ report }) => { report.tokenCommitment = tokenCommitment("payer", payerCoordination, "substituted-token"); })],
    ["participant write digest", "participant", participant(fixture.participants.payer, ({ report }) => { report.write.digest = "c".repeat(64); report.write.anchoredHash = report.write.digest; })],
    ["participant write key", "participant", participant(fixture.participants.payer, ({ report }) => { const key = probeKey("fedcba9876543210fedcba9876543210", "payer"); report.write.key = key; report.write.assetReferenceId = key; })],
    ["aggregate signer", "aggregate", aggregate(() => {}, alternate)],
    ["aggregate plan digest", "aggregate", aggregate(({ report }) => { report.planDigest = "c".repeat(64); })],
    ["aggregate writes reordered", "aggregate", aggregate(({ report }) => { report.writes.reverse(); })],
    ["aggregate directions reordered", "aggregate", aggregate(({ report }) => { report.directions.reverse(); })],
  ];
  for (const [name, phase, hostile] of cases) {
    const bytes = new Map([
      [sha256(stableBytes(fixture.tokens.payer)), stableBytes(fixture.tokens.payer)],
      [sha256(stableBytes(fixture.tokens.payee)), stableBytes(fixture.tokens.payee)],
      [sha256(fixture.plan), fixture.plan],
      [sha256(fixture.participants.payer), fixture.participants.payer],
      [sha256(fixture.participants.payee), fixture.participants.payee],
      [sha256(fixture.aggregate), fixture.aggregate],
      [sha256(hostile), hostile],
    ]);
    const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return bytes.get(digest); }, async readEnrollment({ role }) { return { bytes: canonicalBytes(enrollment[role]) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
    const event = (role, kind, artifactDigest, subjectRun = "release") => eventFixture({ artifactDigest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun });
    await validator.validate(event("payer", "TOKEN_READY", sha256(stableBytes(fixture.tokens.payer))));
    await validator.validate(event("payee", "TOKEN_READY", sha256(stableBytes(fixture.tokens.payee))));
    await validator.validate(event("operator", "PREFLIGHT_PLAN_READY", sha256(fixture.plan)));
    if (phase === "participant") {
      await assert.rejects(validator.validate(event("payer", "PREFLIGHT_PARTICIPANT_READY", sha256(hostile))), { code: "COORDINATION_RELAY_INVALID" }, name);
      continue;
    }
    await validator.validate(event("payer", "PREFLIGHT_PARTICIPANT_READY", sha256(fixture.participants.payer)));
    await validator.validate(event("payee", "PREFLIGHT_PARTICIPANT_READY", sha256(fixture.participants.payee)));
    await assert.rejects(validator.validate(event("operator", "REGISTER_REHEARSAL", sha256(hostile), "rehearsal")), { code: "COORDINATION_RELAY_INVALID" }, name);
  }
});

test("binds enrolled identities through descriptor acceptance", async (t) => {
  const identities = {
    payer: { address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" },
    payee: { address: privateKeyToAccount(invitationKeys.payee.rehearsal).address.toLowerCase(), agentId: "8678", displayName: "Iris" },
  };
  const descriptor = enrolledDescriptor(identities);
  const values = new Map([
    [sha256(identityPackage(identities.payer)), identityPackage(identities.payer)], [sha256(identityPackage(identities.payee)), identityPackage(identities.payee)],
    [sha256(canonicalBytes(descriptor)), canonicalBytes(descriptor)],
  ]);
  const enrollment = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment({ role }) { return { bytes: canonicalBytes(enrollment[role]) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  const event = (role, kind, digest) => eventFixture({ artifactDigest: digest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun: "rehearsal" });
  const digest = sha256(canonicalBytes(descriptor));
  await validator.validate(event("payer", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payer))));
  await validator.validate(event("payee", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payee))));
  await validator.validate(event("operator", "REHEARSAL_DESCRIPTOR_READY", digest));
  await validator.validate(event("payer", "DESCRIPTOR_ACCEPTED", digest));
  await assert.doesNotReject(validator.validate(event("payee", "DESCRIPTOR_ACCEPTED", digest)));
  const payerPackage = await partyResultPackage(t, { descriptor, role: "payer" });
  values.set(sha256(payerPackage), payerPackage);
  await assert.doesNotReject(validator.validate(event("payer", "ROLE_PACKAGE_READY", sha256(payerPackage))));
  const payeePackage = await partyResultPackage(t, { descriptor, role: "payee" });
  values.set(sha256(payeePackage), payeePackage);
  await assert.doesNotReject(validator.validate(event("payee", "ROLE_PACKAGE_READY", sha256(payeePackage))));
});

test("rejects an identity package outside its enrolled invitation", async () => {
  const enrolled = await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" });
  const hostile = identityPackage({ address: `0x${"f".repeat(40)}`, agentId: "8677", displayName: "Billy" });
  const digest = sha256(hostile);
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact() { return hostile; }, async readEnrollment() { return { bytes: canonicalBytes(enrolled) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  await assert.rejects(validator.validate(eventFixture({ artifactDigest: digest, coordination: payerCoordination, keyId: "payer-coordination", kind: "IDENTITY_PACKAGE_READY", role: "payer", subjectRun: "rehearsal" })), { code: "COORDINATION_RELAY_INVALID" });
});

test("normalizes unsupported contextual runs to relay errors", async () => {
  const identity = identityPackage({ address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" });
  const enrolled = await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" });
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact() { return identity; }, async readEnrollment() { return { bytes: canonicalBytes(enrolled) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  await assert.rejects(validator.validate(eventFixture({ artifactDigest: sha256(identity), coordination: payerCoordination, keyId: "payer-coordination", kind: "IDENTITY_PACKAGE_READY", role: "payer" })), { code: "COORDINATION_RELAY_INVALID" });
});

test("keeps exported descriptor validator descriptor-only", async () => {
  const token = stableBytes(tokenCommitment("payer", payerCoordination));
  const validator = createDescriptorArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact() { return token; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  await assert.rejects(validator.validate(eventFixture({ artifactDigest: sha256(token), coordination: payerCoordination, keyId: "payer-coordination", kind: "TOKEN_READY", role: "payer" })), { code: "COORDINATION_RELAY_INVALID" });
});

test("rejects substituted and replayed descriptor acceptances", async () => {
  const identities = {
    payer: { address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" },
    payee: { address: privateKeyToAccount(invitationKeys.payee.rehearsal).address.toLowerCase(), agentId: "8678", displayName: "Iris" },
  };
  const enrollment = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const original = enrolledDescriptor(identities);
  const alteredAgent = enrolledDescriptor({ ...identities, payer: { ...identities.payer, agentId: "9999" } });
  const alteredName = enrolledDescriptor({ ...identities, payee: { ...identities.payee, displayName: "Eve" } });
  const alteredPrompt = createSignedEnvelope({ ...original.descriptor, promptSha256: "ab".repeat(32) }, { keyId: OPERATOR_KEY_ID, privateKeyPem: privateKeyPem(operator) });
  const prepare = async () => {
    const values = new Map([[sha256(identityPackage(identities.payer)), identityPackage(identities.payer)], [sha256(identityPackage(identities.payee)), identityPackage(identities.payee)], [sha256(canonicalBytes(original)), canonicalBytes(original)], [sha256(canonicalBytes(alteredAgent)), canonicalBytes(alteredAgent)], [sha256(canonicalBytes(alteredName)), canonicalBytes(alteredName)], [sha256(canonicalBytes(alteredPrompt)), canonicalBytes(alteredPrompt)]]);
    const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment({ role }) { return { bytes: canonicalBytes(enrollment[role]) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
    const event = (role, kind, digest) => eventFixture({ artifactDigest: digest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun: "rehearsal" });
    await validator.validate(event("payer", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payer))));
    await validator.validate(event("payee", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payee))));
    return { event, validator };
  };
  for (const [name, descriptor] of [["payer agent", alteredAgent], ["payee display name", alteredName]]) {
    const { event, validator } = await prepare();
    await assert.rejects(validator.validate(event("operator", "REHEARSAL_DESCRIPTOR_READY", sha256(canonicalBytes(descriptor)))), { code: "COORDINATION_RELAY_INVALID" }, name);
  }
  { const { event, validator } = await prepare(); await validator.validate(event("operator", "REHEARSAL_DESCRIPTOR_READY", sha256(canonicalBytes(original)))); await assert.rejects(validator.validate(event("payer", "DESCRIPTOR_ACCEPTED", sha256(canonicalBytes(alteredPrompt)))), { code: "COORDINATION_RELAY_INVALID" }); }
  { const { event, validator } = await prepare(); const digest = sha256(canonicalBytes(original)); await validator.validate(event("operator", "REHEARSAL_DESCRIPTOR_READY", digest)); await validator.validate(event("payer", "DESCRIPTOR_ACCEPTED", digest)); await assert.rejects(validator.validate(event("payer", "DESCRIPTOR_ACCEPTED", digest)), { code: "COORDINATION_RELAY_INVALID" }); }
});

test("rejects storage-valid party packages outside accepted descriptor context", async (t) => {
  const identities = {
    payer: { address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" },
    payee: { address: privateKeyToAccount(invitationKeys.payee.rehearsal).address.toLowerCase(), agentId: "8678", displayName: "Iris" },
  };
  const descriptor = enrolledDescriptor(identities);
  const enrollment = {
    payer: await enrollmentFixture({ capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" }),
    payee: await enrollmentFixture({ capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" }),
  };
  const prefix = async (partyBytes, eventRole) => {
    const descriptorDigest = sha256(canonicalBytes(descriptor));
    const values = new Map([[sha256(identityPackage(identities.payer)), identityPackage(identities.payer)], [sha256(identityPackage(identities.payee)), identityPackage(identities.payee)], [descriptorDigest, canonicalBytes(descriptor)], [sha256(partyBytes), partyBytes]]);
    const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment({ role }) { return { bytes: canonicalBytes(enrollment[role]) }; }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
    const event = (role, kind, digest) => eventFixture({ artifactDigest: digest, coordination: role === "payer" ? payerCoordination : role === "payee" ? payeeCoordination : operator, keyId: role === "operator" ? OPERATOR_KEY_ID : `${role}-coordination`, kind, role, subjectRun: "rehearsal" });
    await validator.validate(event("payer", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payer))));
    await validator.validate(event("payee", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payee))));
    await validator.validate(event("operator", "REHEARSAL_DESCRIPTOR_READY", descriptorDigest));
    await validator.validate(event("payer", "DESCRIPTOR_ACCEPTED", descriptorDigest));
    await validator.validate(event("payee", "DESCRIPTOR_ACCEPTED", descriptorDigest));
    return validator.validate(event(eventRole, "ROLE_PACKAGE_READY", sha256(partyBytes)));
  };
  const alternateKey = `0x${"55".repeat(32)}`;
  const alternateAddress = privateKeyToAccount(alternateKey).address.toLowerCase();
  const cases = [
    ["session digest", await partyResultPackage(t, { descriptor, sessionDigest: "ab".repeat(32) }), "payer"],
    ["prompt hash", await partyResultPackage(t, { descriptor, promptSha256: "ab".repeat(32) }), "payer"],
    ["party address", await partyResultPackage(t, { accountKey: alternateKey, descriptor, parties: { ...identities, payer: { address: alternateAddress, agentId: identities.payer.agentId } } }), "payer"],
    ["party agent", await partyResultPackage(t, { descriptor, parties: { ...identities, payer: { address: identities.payer.address, agentId: "9999" } } }), "payer"],
    ["wrong event role", await partyResultPackage(t, { descriptor, role: "payer" }), "payee"],
  ];
  for (const [name, bytes, role] of cases) {
    await assert.doesNotReject(validateRelayArtifactWithFacts({ artifactType: "party-result-package", bytes, expectedDigest: sha256(bytes), secretCanaries: [] }), name);
    await assert.rejects(prefix(bytes, role), { code: "COORDINATION_RELAY_INVALID" }, name);
  }
});

test("binds exact recovery manifests and terminal failure summaries", async () => {
  const manifest = recoveryManifest();
  const summary = failureSummary();
  const values = new Map([[sha256(manifest), manifest], [sha256(summary), summary]]);
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment() { throw new Error("unexpected"); }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  const event = (role, kind, digest) => eventFixture({ artifactDigest: digest, coordination: role === "operator" ? operator : payerCoordination, keyId: role === "operator" ? OPERATOR_KEY_ID : "payer-coordination", kind, role, subjectRun: "rehearsal" });
  await validator.validate(event("payer", "RECOVERY_REQUIRED", sha256(manifest)));
  await assert.doesNotReject(validator.validate(event("operator", "EXACT_RECOVERY_AUTHORIZATION", sha256(manifest))));
  await assert.doesNotReject(validator.validate(event("payer", "TERMINAL_FAILURE", sha256(summary))));
});

test("rejects recovery replay and failure-summary scope substitutions", async () => {
  const manifest = recoveryManifest();
  const summaries = [failureSummary({ role: "payee" }), failureSummary({ releaseId: "release-b" }), failureSummary({ sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" }), failureSummary({ subjectRun: "stakeholder" })];
  for (const summary of summaries) {
    const values = new Map([[sha256(summary), summary]]);
    const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment() { throw new Error("unexpected"); }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
    await assert.rejects(validator.validate(eventFixture({ artifactDigest: sha256(summary), coordination: payerCoordination, keyId: "payer-coordination", kind: "TERMINAL_FAILURE", role: "payer", subjectRun: "rehearsal" })), { code: "COORDINATION_RELAY_INVALID" });
  }
  const values = new Map([[sha256(manifest), manifest]]);
  const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment() { throw new Error("unexpected"); }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
  const required = eventFixture({ artifactDigest: sha256(manifest), coordination: payerCoordination, keyId: "payer-coordination", kind: "RECOVERY_REQUIRED", role: "payer", subjectRun: "rehearsal" });
  await validator.validate(required);
  await assert.rejects(validator.validate(required), { code: "COORDINATION_RELAY_INVALID" });
  await validator.validate(eventFixture({ artifactDigest: sha256(manifest), coordination: operator, keyId: OPERATOR_KEY_ID, kind: "EXACT_RECOVERY_AUTHORIZATION", role: "operator", subjectRun: "rehearsal" }));
  await assert.rejects(validator.validate(eventFixture({ artifactDigest: sha256(manifest), coordination: operator, keyId: OPERATOR_KEY_ID, kind: "EXACT_RECOVERY_AUTHORIZATION", role: "operator", subjectRun: "rehearsal" })), { code: "COORDINATION_RELAY_INVALID" });
});

test("rejects distinct and cross-role recovery authorizations", async () => {
  const payer = recoveryManifest();
  const alternate = recoveryManifest({ outputPath: "/state/other-output" });
  const payee = recoveryManifest({ command: "bin/handshake-accept.mjs", role: "payee" });
  for (const candidate of [alternate, payee]) {
    await assert.doesNotReject(validateRelayArtifactWithFacts({ artifactType: "recovery-command-manifest", bytes: candidate, expectedDigest: sha256(candidate), secretCanaries: [] }));
    const values = new Map([[sha256(payer), payer], [sha256(candidate), candidate]]);
    const validator = createRelayArtifactTransitionValidator({ frozenRepositorySha: REPOSITORY_SHA, async readArtifact(digest) { return values.get(digest); }, async readEnrollment() { throw new Error("unexpected"); }, async resolveOperatorPublicKey() { return rawPublicKey(operator); } });
    await validator.validate(eventFixture({ artifactDigest: sha256(payer), coordination: payerCoordination, keyId: "payer-coordination", kind: "RECOVERY_REQUIRED", role: "payer", subjectRun: "rehearsal" }));
    await assert.rejects(validator.validate(eventFixture({ artifactDigest: sha256(candidate), coordination: operator, keyId: OPERATOR_KEY_ID, kind: "EXACT_RECOVERY_AUTHORIZATION", role: "operator", subjectRun: "rehearsal" })), { code: "COORDINATION_RELAY_INVALID" });
  }
});

async function partyResultPackage(t, { accountKey, descriptor, parties, promptSha256, role = "payer", sessionDigest: suppliedSessionDigest } = {}) {
  const account = privateKeyToAccount(accountKey ?? invitationKeys[role].rehearsal);
  const descriptorData = descriptor?.descriptor;
  const sessionDigest = suppliedSessionDigest ?? (descriptorData === undefined ? "cd".repeat(32) : dSession(descriptorData));
  const party = (partyRole) => {
    const supplied = parties?.[partyRole];
    if (supplied !== undefined) return { address: supplied.address, agentId: supplied.agentId };
    return descriptorData === undefined ? (partyRole === "payer"
    ? { address: account.address.toLowerCase(), agentId: "8677" }
    : { address: `0x${"22".repeat(20)}`, agentId: "9001" }) : {
    address: descriptorData[partyRole].address,
    agentId: descriptorData[partyRole].agentId,
    };
  };
  const head = {
    amount: { currency: "USD", moved: false, value: "100" },
    expirySeconds: "600",
    payee: party("payee"),
    payer: { ...party("payer"), reference: `eip155:11155111:0x8004a818bfb912233c491871b3d84c89a494bd9e:${party("payer").agentId}` },
    protocol: "clockchain.bilateral-authorization/v1",
    schema: "clockchain.bilateral-transition/v1",
    sessionDigest,
  };
  const proposal = { ...head, kind: "proposal", predecessor: null, sequence: "1" };
  const proposalAnchor = { anchoredHash: sha256(canonicalBytes(proposal)), blockHeight: "1869000", kind: "proposal", ledgerId: "3f8a1c2e-9d4b-4a6c-8f2e-0123456789ab" };
  const acceptance = { ...head, decision: "ACCEPT", kind: "acceptance", predecessor: proposalAnchor, sequence: "2" };
  const acceptanceAnchor = { anchoredHash: sha256(canonicalBytes(acceptance)), blockHeight: "1869030", kind: "acceptance", ledgerId: "4a9b2d3f-0e5c-4b7d-9a3f-123456789abc" };
  const acknowledgment = { ...head, kind: "acknowledgment", outcome: "ACKNOWLEDGED", paymentMoved: false, predecessor: acceptanceAnchor, proposal: proposalAnchor, sequence: "3" };
  const transitions = [proposal, acceptance, acknowledgment].map((message, index) => ({
    blockTimeMs: String([1784923200100, 1784923231204, 1784923262309][index]),
    blockTimeRaw: ["2026-07-24T20:00:00.100000001Z", "2026-07-24T20:00:31.204500000Z", "2026-07-24T20:01:02.309999999Z"][index],
    digest: sha256(canonicalBytes(message)),
    onChain: { anchoredHash: sha256(canonicalBytes(message)), blockHeight: ["1869000", "1869030", "1869060"][index], ledgerId: [proposalAnchor.ledgerId, acceptanceAnchor.ledgerId, "5b0c3e40-1f6d-4c8e-ab40-23456789abcd"][index] },
    message,
    upperBoundMs: index === 0 ? null : String([1784923200100, 1784923231204, 1784923262309][index] + 1100),
  }));
  const result = {
    ackObserved: true,
    deadlineMs: "1784923800100",
    localVerdict: "LOCAL_OK",
    paymentMoved: false,
    poolHealth: { degradedAtSubmission: true, nodeParticipationPct: "0.0", totalNodes: "1.0" },
    promptSha256: promptSha256 ?? descriptorData?.promptSha256 ?? "ef".repeat(32),
    protocolVersion: "1",
    rendezvous: { channel: "derived-reference-id", degradedAtSubmission: true, tenancy: "cross-client" },
    repositorySha: REPOSITORY_SHA,
    role,
    schema: PARTY_RESULT_SCHEMA,
    sessionDigest,
    signature: { address: account.address.toLowerCase(), algorithm: "eip191", signature: "" },
    transitions,
  };
  result.signature.signature = await account.signMessage({
    message: { raw: partySignatureBytes({ role, sessionDigest, transitions: result.transitions }) },
  });
  const directory = await mkdtemp(join(tmpdir(), "relay-role-package-"));
  t.after(() => rm(directory, { force: true, recursive: true }));
  await writePartyResult({ directory, result });
  return relayPackage([
    [".party-result.complete.json", await readFile(join(directory, ".party-result.complete.json"))],
    ["PARTY-RESULT.md", await readFile(join(directory, "PARTY-RESULT.md"))],
    ["party-result.json", await readFile(join(directory, "party-result.json"))],
  ]);
}

test("rejects a role package without its accepted descriptor context", async (t) => {
  const bytes = await partyResultPackage(t);
  const digest = sha256(bytes);
  const validator = createRelayArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact(candidate) {
      if (candidate !== digest) throw new Error("missing artifact");
      return bytes;
    },
    async readEnrollment() {
      throw new Error("role package must not reach enrollment without a descriptor");
    },
    async resolveOperatorPublicKey() {
      return rawPublicKey(operator);
    },
  });

  await assert.rejects(
    validator.validate(eventFixture({
      artifactDigest: digest,
      coordination: payerCoordination,
      keyId: "payer-coordination",
      kind: "ROLE_PACKAGE_READY",
      role: "payer",
      subjectRun: "rehearsal",
    })),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("rejects verification passed directly without a trusted verifier seam", async () => {
  const validator = createRelayArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact() { throw new Error("unexpected artifact read"); },
    async readEnrollment() { throw new Error("unexpected enrollment read"); },
    async resolveOperatorPublicKey() { return rawPublicKey(operator); },
  });
  await assert.rejects(
    validator.validate(eventFixture({
      coordination: operator,
      keyId: OPERATOR_KEY_ID,
      kind: "VERIFICATION_PASSED",
      role: "operator",
      subjectRun: "rehearsal",
    })),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("keeps only the declared non-artifact terminal and stakeholder gates", async () => {
  let reads = 0;
  const validator = createRelayArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact() { reads += 1; throw new Error("missing artifact"); },
    async readEnrollment() { throw new Error("unexpected enrollment read"); },
    async resolveOperatorPublicKey() { return rawPublicKey(operator); },
  });
  const operatorEvent = (kind, artifactDigest = null) => eventFixture({
    artifactDigest,
    coordination: operator,
    keyId: OPERATOR_KEY_ID,
    kind,
    role: "operator",
    subjectRun: kind === "REGISTER_STAKEHOLDER" ? "stakeholder" : "rehearsal",
  });
  await assert.doesNotReject(validator.validate(operatorEvent("REGISTER_STAKEHOLDER")));
  await assert.doesNotReject(validator.validate(operatorEvent("TERMINAL_FAILURE")));
  for (const kind of ["REGISTER_STAKEHOLDER", "VERIFICATION_FAILED"]) {
    await assert.rejects(
      validator.validate(operatorEvent(kind, "a".repeat(64))),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
  assert.equal(reads, 0);
});

test("uses one immutable artifact read for a contextual artifact validation", async (t) => {
  const bytes = await partyResultPackage(t);
  const digest = sha256(bytes);
  let reads = 0;
  const validator = createRelayArtifactTransitionValidator({
    frozenRepositorySha: REPOSITORY_SHA,
    async readArtifact(candidate) {
      assert.equal(candidate, digest);
      reads += 1;
      return bytes;
    },
    async readEnrollment() { throw new Error("unexpected enrollment read"); },
    async resolveOperatorPublicKey() { return rawPublicKey(operator); },
  });
  await assert.rejects(validator.validate(eventFixture({
    artifactDigest: digest, coordination: payerCoordination,
    keyId: "payer-coordination", kind: "ROLE_PACKAGE_READY", role: "payer",
    subjectRun: "rehearsal",
  })), { code: "COORDINATION_RELAY_INVALID" });
  assert.equal(reads, 1);
});

function eventBuilder() {
  const state = Object.fromEntries(
    ["operator", "payee", "payer"].map((role) => [
      role,
      { previousEventDigest: null, sequence: 0 },
    ]),
  );
  return ({
    artifactDigest = null,
    kind,
    role,
    subjectRun = "release",
  }) => {
    const authority = {
      operator: {
        coordination: operator,
        keyId: OPERATOR_KEY_ID,
      },
      payee: {
        coordination: payeeCoordination,
        keyId: "payee-coordination",
      },
      payer: {
        coordination: payerCoordination,
        keyId: "payer-coordination",
      },
    }[role];
    const sender = state[role];
    const event = eventFixture({
      artifactDigest,
      ...authority,
      kind,
      previousEventDigest:
        sender.previousEventDigest,
      role,
      sequence: String(sender.sequence),
      subjectRun,
    });
    sender.previousEventDigest = event.eventDigest;
    sender.sequence += 1;
    return event;
  };
}

async function bootstrapRole(
  relay,
  {
    capability,
    coordination,
    enrollment,
    invitationPrivateKeys,
    preflight,
    role,
  },
) {
  const value =
    enrollment ??
    (await enrollmentFixture({
      capability,
      coordination,
      invitationPrivateKeys,
      preflight,
      role,
    }));
  return relay.bootstrap({
    body: bootstrapBody(capability, value),
  });
}

function verifiedEventBody(event, publication = {}) {
  return canonicalBytes({
    event,
    paymentMoved: false,
    publication: {
      paymentMoved: false,
      publicationDigest: event.artifactDigest,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema: "clockchain.bilateral-verifier-publication/v1",
      sessionId: SESSION_ID,
      status: "VERIFICATION_PASSED",
      subjectRun: "rehearsal",
      ...publication,
    },
    schema: "clockchain.bilateral-verified-event/v1",
  });
}

async function rehearsalReadyForVerification(t) {
  const { root, store } = await storeFixture(t);
  await registerRole(store, { capability: PAYER_CAPABILITY, role: "payer" });
  await registerRole(store, { capability: PAYEE_CAPABILITY, role: "payee" });
  const receipt = makeReceiptSigner();
  const { relay } = relayFixture(store, { receipt });
  await bootstrapRole(relay, { capability: PAYER_CAPABILITY, coordination: payerCoordination, invitationPrivateKeys: invitationKeys.payer, preflight: payerPreflight, role: "payer" });
  await bootstrapRole(relay, { capability: PAYEE_CAPABILITY, coordination: payeeCoordination, invitationPrivateKeys: invitationKeys.payee, preflight: payeePreflight, role: "payee" });
  const artifacts = contextualPreflightArtifacts();
  const identities = {
    payer: { address: privateKeyToAccount(invitationKeys.payer.rehearsal).address.toLowerCase(), agentId: "8677", displayName: "Billy" },
    payee: { address: privateKeyToAccount(invitationKeys.payee.rehearsal).address.toLowerCase(), agentId: "8678", displayName: "Iris" },
  };
  const descriptor = enrolledDescriptor(identities);
  const payerAccount = privateKeyToAccount(invitationKeys.payer.rehearsal);
  const payeeAccount = privateKeyToAccount(invitationKeys.payee.rehearsal);
  const mandate = await signPayerMandate({
    mandate: { amount: { currency: "USD", value: "100" }, expiresAtMs: String(NOW_MS + 60_000), intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID, invoiceReferencePrefix: "invoice-", issuedAtMs: String(NOW_MS - 1), payer: { address: payerAccount.address.toLowerCase(), agentId: identities.payer.agentId }, payee: { address: payeeAccount.address.toLowerCase(), agentId: identities.payee.agentId }, paymentMoved: false, protocol: "clockchain.bilateral-authorization/v1", purpose: "Handshake demo", releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, requestEndpoint: `/v1/sessions/${SESSION_ID}/payment-requests`, schema: "clockchain.bilateral-payer-mandate/v1", sessionId: SESSION_ID, subjectRun: "rehearsal" },
    signMessage: (bytes) => payerAccount.signMessage({ message: { raw: toHex(bytes) } }),
  });
  const mandateBytes = canonicalBytes(mandate);
  const request = await signPaymentRequest({
    request: { amount: { currency: "USD", value: "100" }, createdAtMs: String(NOW_MS), expiresAtMs: String(NOW_MS + 30_000), intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID, invoiceReference: "invoice-001", mandateDigest: sha256(canonicalBytes(mandate.mandate)), payer: { address: payerAccount.address.toLowerCase(), agentId: identities.payer.agentId }, payee: { address: payeeAccount.address.toLowerCase(), agentId: identities.payee.agentId }, paymentMoved: false, protocol: "clockchain.bilateral-authorization/v1", purpose: "Handshake demo", releaseId: RELEASE_ID, repositorySha: REPOSITORY_SHA, requestId: "9f953393-86d0-4f99-9d6a-102f525fbecd", schema: "clockchain.bilateral-payment-request/v1", sessionId: SESSION_ID, subjectRun: "rehearsal" },
    signMessage: (bytes) => payeeAccount.signMessage({ message: { raw: toHex(bytes) } }),
  });
  const requestBytes = canonicalBytes(request);
  const payerPackage = await partyResultPackage(t, { descriptor, role: "payer" });
  const payeePackage = await partyResultPackage(t, { descriptor, role: "payee" });
  const uploads = [
    ["token-commitment", stableBytes(artifacts.tokens.payer)], ["token-commitment", stableBytes(artifacts.tokens.payee)],
    ["preflight-plan", artifacts.plan], ["preflight-participant-report", artifacts.participants.payer], ["preflight-participant-report", artifacts.participants.payee], ["preflight-aggregate-report", artifacts.aggregate],
    ["identity-package", identityPackage(identities.payer)], ["identity-package", identityPackage(identities.payee)],
    ["signed-descriptor", canonicalBytes(descriptor)], ["party-result-package", payerPackage], ["party-result-package", payeePackage],
    ["payer-mandate", mandateBytes], ["payment-request", requestBytes],
  ];
  for (const [artifactType, body] of uploads) await relay.putArtifact({ artifactType, body, expectedDigest: sha256(body) });
  const build = eventBuilder();
  let requestReceipt;
  const append = async (role, kind, artifactDigest = null, subjectRun = "release") => relay.appendEvent({ body: canonicalBytes(build({ role, kind, artifactDigest, subjectRun })) });
  for (const [role, kind, artifactDigest, subjectRun] of [
    ["payer", "ENROLLMENT_CONFIRMED"], ["payee", "ENROLLMENT_CONFIRMED"], ["operator", "ENROLLMENT_RECEIPT"], ["operator", "WAIT_FOR_FUNDING"], ["payer", "FUNDING_INPUTS_READY"], ["payee", "FUNDING_INPUTS_READY"],
    ["payer", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payer))], ["payee", "TOKEN_READY", sha256(stableBytes(artifacts.tokens.payee))], ["operator", "PREFLIGHT_PLAN_READY", sha256(artifacts.plan)], ["payer", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payer)], ["payee", "PREFLIGHT_PARTICIPANT_READY", sha256(artifacts.participants.payee)], ["operator", "REGISTER_REHEARSAL", sha256(artifacts.aggregate), "rehearsal"],
    ["payer", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payer)), "rehearsal"], ["payee", "IDENTITY_PACKAGE_READY", sha256(identityPackage(identities.payee)), "rehearsal"], ["payer", "PAYER_MANDATE_READY", sha256(mandateBytes), "rehearsal"], ["payee", "PAYMENT_REQUEST_READY", sha256(requestBytes), "rehearsal"], ["payer", "PAYMENT_REQUEST_MATCHED", null, "rehearsal"], ["operator", "REHEARSAL_DESCRIPTOR_READY", sha256(canonicalBytes(descriptor)), "rehearsal"], ["payer", "DESCRIPTOR_ACCEPTED", sha256(canonicalBytes(descriptor)), "rehearsal"], ["payee", "DESCRIPTOR_ACCEPTED", sha256(canonicalBytes(descriptor)), "rehearsal"], ["operator", "START_REHEARSAL", null, "rehearsal"], ["payee", "ROLE_STARTED", null, "rehearsal"], ["payer", "ROLE_STARTED", null, "rehearsal"], ["payer", "ROLE_PACKAGE_READY", sha256(payerPackage), "rehearsal"], ["payee", "ROLE_PACKAGE_READY", sha256(payeePackage), "rehearsal"],
  ]) {
    try {
      await append(role, kind, artifactDigest, subjectRun);
      if (kind === "PAYER_MANDATE_READY") {
        requestReceipt = await relay.submitPaymentRequest({ body: requestBytes, sessionId: SESSION_ID });
      }
    } catch (error) {
      throw new Error(`rehearsal setup rejected ${kind} for ${role}: ${error}`, { cause: error });
    }
  }
  return { build, mandateBytes, receipt, relay, request, requestBytes, requestReceipt, root, store };
}

test("persists fully verified signed inbox artifacts and returns exact bytes", async (t) => {
  const { mandateBytes, receipt, relay, request, requestBytes, requestReceipt, store } = await rehearsalReadyForVerification(t);
  assert.deepEqual(await relay.readPayerMandate({ sessionId: SESSION_ID, subjectRun: "rehearsal" }), mandateBytes);
  assert.deepEqual(await relay.readPaymentRequest({ requestId: request.request.requestId, sessionId: SESSION_ID }), requestBytes);
  assert.equal(requestReceipt.rawEnvelopeDigest, sha256(requestBytes));
  assert.notEqual(requestReceipt.rawEnvelopeDigest, requestReceipt.paymentRequestDigest);
  const forged = canonicalBytes({ ...request, signature: { ...request.signature, value: `0x${"0".repeat(130)}` } });
  await assert.rejects(relay.submitPaymentRequest({ body: forged, sessionId: SESSION_ID }), { code: "COORDINATION_RELAY_INVALID" });
  const payeeAccount = privateKeyToAccount(invitationKeys.payee.rehearsal);
  const expired = await signPaymentRequest({ request: { ...request.request, createdAtMs: String(NOW_MS - 2), expiresAtMs: String(NOW_MS - 1) }, signMessage: (bytes) => payeeAccount.signMessage({ message: { raw: toHex(bytes) } }) });
  await assert.rejects(relay.submitPaymentRequest({ body: canonicalBytes(expired), sessionId: SESSION_ID }), { code: "COORDINATION_RELAY_INVALID" });
  const wrongMandate = await signPaymentRequest({ request: { ...request.request, mandateDigest: "f".repeat(64) }, signMessage: (bytes) => payeeAccount.signMessage({ message: { raw: toHex(bytes) } }) });
  await assert.rejects(relay.submitPaymentRequest({ body: canonicalBytes(wrongMandate), sessionId: SESSION_ID }), { code: "COORDINATION_RELAY_INVALID" });
  const wrongIntake = await signPaymentRequest({ request: { ...request.request, intakeDigest: "c".repeat(64) }, signMessage: (bytes) => payeeAccount.signMessage({ message: { raw: toHex(bytes) } }) });
  await assert.rejects(relay.submitPaymentRequest({ body: canonicalBytes(wrongIntake), sessionId: SESSION_ID }), { code: "COORDINATION_RELAY_INVALID" });
  const wrongRun = await signPaymentRequest({ request: { ...request.request, subjectRun: "stakeholder" }, signMessage: (bytes) => payeeAccount.signMessage({ message: { raw: toHex(bytes) } }) });
  await assert.rejects(relay.submitPaymentRequest({ body: canonicalBytes(wrongRun), sessionId: SESSION_ID }), { code: "COORDINATION_RELAY_INVALID" });
  await assert.rejects(relay.submitPaymentRequest({ body: requestBytes, sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" }), { code: "COORDINATION_SESSION_NOT_FOUND" });
  const noReadyStore = storeFacade(store, {
    readReleaseView: async (input) => {
      const view = await store.readReleaseView(input);
      return { ...view, events: view.events.filter((event) => event.kind !== "PAYER_MANDATE_READY") };
    },
  });
  const noReadyRelay = createRelayService({ frozenRepositorySha: REPOSITORY_SHA, now: () => NOW_MS, receiptSigner: receipt.signer, repositoryPublicKeyResolver: repositoryResolver(), store: noReadyStore });
  await assert.rejects(noReadyRelay.readPayerMandate({ sessionId: SESSION_ID, subjectRun: "rehearsal" }), { code: "COORDINATION_RELAY_INVALID" });
});

test("creates the exact transport-independent service and requires every authority dependency", async (t) => {
  const { store } = await storeFixture(t);
  const receipt = makeReceiptSigner();
  assert.throws(
    () =>
      createRelayService({
        frozenRepositorySha: REPOSITORY_SHA,
        now: () => NOW_MS,
        receiptSigner: receipt.signer,
        store,
      }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  const { relay } = relayFixture(store, { receipt });
  assert.deepEqual(Object.keys(relay), [
    "appendEvent",
    "appendVerifiedEvent",
    "bootstrap",
    "getArtifact",
    "putArtifact",
    "readPayerMandate",
    "readPaymentRequest",
    "readEnrollmentReadiness",
    "registerCapabilities",
    "readEnrollmentSet",
    "readEvents",
    "readSessionView",
    "readVerifierPublication",
    "submitPaymentRequest",
  ]);
  assert.equal(Object.isFrozen(relay), true);
});

test("reads only the exact frozen durable verifier-publication claim", async (t) => {
  const { store } = await storeFixture(t);
  const calls = [];
  const claim = {
    paymentMoved: false,
    publicationDigest: "d".repeat(64),
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.bilateral-verifier-publication/v1",
    sessionId: SESSION_ID,
    status: "VERIFICATION_PASSED",
    subjectRun: "rehearsal",
  };
  const { relay } = relayFixture(storeFacade(store, {
    async readVerifierPublication(input) {
      calls.push(input);
      return claim;
    },
  }));
  const result = await relay.readVerifierPublication({
    sessionId: SESSION_ID,
    subjectRun: "rehearsal",
  });
  assert.deepEqual({ ...result }, claim);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(calls, [{ sessionId: SESSION_ID, subjectRun: "rehearsal" }]);
  const { relay: absent } = relayFixture(storeFacade(store, {
    async readVerifierPublication() {
      return null;
    },
  }));
  assert.equal(
    await absent.readVerifierPublication({
      sessionId: SESSION_ID,
      subjectRun: "rehearsal",
    }),
    null,
  );
  for (const mutation of [
    { paymentMoved: true },
    { publicationDigest: "invalid" },
    { repositorySha: "f".repeat(40) },
    { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" },
    { subjectRun: "stakeholder" },
    { status: "AUTHORIZED" },
    { extra: true },
  ]) {
    const { relay: hostile } = relayFixture(storeFacade(store, {
      async readVerifierPublication() {
        return { ...claim, ...mutation };
      },
    }));
    await assert.rejects(
      hostile.readVerifierPublication({ sessionId: SESSION_ID, subjectRun: "rehearsal" }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
});

test("trusted verifier seam completes the exact rehearsal lifecycle and is idempotent", async (t) => {
  const { build, relay, root, store } = await rehearsalReadyForVerification(t);
  const event = build({ artifactDigest: "d".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" });
  const body = verifiedEventBody(event);

  await assert.rejects(
    relay.appendEvent({ body: canonicalBytes(event) }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.deepEqual(await relay.appendVerifiedEvent({ body }), event);
  assert.equal((await relay.readSessionView({ sessionId: SESSION_ID })).state, "REHEARSAL_VERIFIED");
  assert.deepEqual(await relay.appendVerifiedEvent({ body }), event);
  assert.equal((await store.readEvents({ after: null, sessionId: SESSION_ID })).length, 26);
  const journal = await readFile(join(root, "journal.log"), "utf8");
  assert.equal(journal.includes("VERIFIED_EVENT_APPENDED"), true);
});

test("trusted verifier seam fails closed when its durable claim disagrees with the event", async (t) => {
  const { build, relay, store } = await rehearsalReadyForVerification(t);
  const event = build({ artifactDigest: "d".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" });
  const cases = [
    ["digest", { publicationDigest: "e".repeat(64) }],
    ["run", { subjectRun: "stakeholder" }],
    ["session", { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" }],
    ["repository", { repositorySha: "f".repeat(40) }],
    ["payment moved", { paymentMoved: true }],
  ];
  for (const [label, publication] of cases) {
    await assert.rejects(relay.appendVerifiedEvent({ body: verifiedEventBody(event, publication) }), { code: "COORDINATION_RELAY_INVALID" }, label);
  }
  await assert.equal((await store.readEvents({ after: null, sessionId: SESSION_ID })).length, 25);
  assert.equal(await store.readVerifierPublication({ sessionId: SESSION_ID, subjectRun: "rehearsal" }), null);
});

test("trusted verifier claim survives restart and replay", async (t) => {
  const { build, receipt, relay, root, store } = await rehearsalReadyForVerification(t);
  const event = build({ artifactDigest: "d".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" });
  const body = verifiedEventBody(event);
  await relay.appendVerifiedEvent({ body });
  await store.close();
  const restartedStore = await openCoordinationStore({ now: () => NOW_MS, repositorySha: REPOSITORY_SHA, root });
  t.after(() => restartedStore.close().catch(() => {}));
  const { relay: restarted } = relayFixture(restartedStore, { receipt });
  assert.equal((await restarted.readSessionView({ sessionId: SESSION_ID })).state, "REHEARSAL_VERIFIED");
  assert.deepEqual(await restarted.appendVerifiedEvent({ body }), event);
});

test("replay rejects every hostile persisted verifier claim substitution", async (t) => {
  const { build, relay, store } = await rehearsalReadyForVerification(t);
  const event = build({ artifactDigest: "d".repeat(64), kind: "VERIFICATION_PASSED", role: "operator", subjectRun: "rehearsal" });
  await relay.appendVerifiedEvent({ body: verifiedEventBody(event) });
  const claim = await store.readVerifierPublication({ sessionId: SESSION_ID, subjectRun: "rehearsal" });
  const mutations = [
    { schema: "clockchain.bilateral-verifier-publication/v2" },
    { paymentMoved: true },
    { publicationDigest: "e".repeat(64) },
    { releaseId: "release-other" },
    { repositorySha: "f".repeat(40) },
    { sessionId: "9f953393-86d0-4f99-9d6a-102f525fbecd" },
    { subjectRun: "stakeholder" },
    { status: "AUTHORIZED" },
  ];
  for (const mutation of mutations) {
    const { relay: hostile } = relayFixture(storeFacade(store, {
      async readVerifierPublication() {
        return { ...claim, ...mutation };
      },
    }));
    await assert.rejects(
      hostile.readSessionView({ sessionId: SESSION_ID }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
});

test("returns an authenticated enrollment set only after both durable role records exist", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await assert.rejects(
    () => relay.readEnrollmentSet({ sessionId: SESSION_ID }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  const payerEnrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    enrollment: payerEnrollment,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await assert.rejects(
    () => relay.readEnrollmentSet({ sessionId: SESSION_ID }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  const payeeEnrollment = await enrollmentFixture({
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    enrollment: payeeEnrollment,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });

  const set = await relay.readEnrollmentSet({
    sessionId: SESSION_ID,
  });
  const storedPayer = await store.readEnrollment({
    role: "payer",
    sessionId: SESSION_ID,
  });
  const storedPayee = await store.readEnrollment({
    role: "payee",
    sessionId: SESSION_ID,
  });
  assert.deepEqual(set, {
    enrollments: {
      payee: {
        enrollmentBase64:
          storedPayee.bytes.toString("base64"),
        enrollmentDigest: storedPayee.digest,
        receiptBase64:
          storedPayee.receiptBytes.toString("base64"),
      },
      payer: {
        enrollmentBase64:
          storedPayer.bytes.toString("base64"),
        enrollmentDigest: storedPayer.digest,
        receiptBase64:
          storedPayer.receiptBytes.toString("base64"),
      },
    },
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-coordination-enrollment-set/v1",
    sessionId: SESSION_ID,
  });
  assert.equal(Object.isFrozen(set), true);
  assert.equal(Object.isFrozen(set.enrollments), true);
  assert.equal(
    Object.isFrozen(set.enrollments.payer),
    true,
  );
});

test("revalidates both persisted enrollment receipts and exact storage records before publishing authority", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const receipt = makeReceiptSigner();
  const { relay } = relayFixture(store, { receipt });
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const exactPayer = await store.readEnrollment({
    role: "payer",
    sessionId: SESSION_ID,
  });

  const mutations = [
    {
      label: "missing receipt",
      mutate(record) {
        const { receiptBytes: _receiptBytes, ...rest } =
          record;
        return rest;
      },
    },
    {
      label: "extra storage field",
      mutate(record) {
        return { ...record, advisoryStatus: "ready" };
      },
    },
    {
      label: "enrollment digest mismatch",
      mutate(record) {
        return { ...record, digest: "0".repeat(64) };
      },
    },
    {
      label: "receipt signature",
      mutate(record) {
        const parsed = JSON.parse(
          record.receiptBytes.toString("utf8"),
        );
        return {
          ...record,
          receiptBytes: stableBytes({
            ...parsed,
            signature:
              Buffer.alloc(64).toString("base64"),
          }),
        };
      },
    },
    {
      label: "receipt certificate",
      mutate(record) {
        const parsed = JSON.parse(
          record.receiptBytes.toString("utf8"),
        );
        return {
          ...record,
          receiptBytes: stableBytes({
            ...parsed,
            certificateSha256: "0".repeat(64),
          }),
        };
      },
    },
  ];
  for (const { label, mutate } of mutations) {
    const hostileStore = storeFacade(store, {
      async readEnrollment(input) {
        const record = await store.readEnrollment(input);
        return input.role === "payer"
          ? mutate(record)
          : record;
      },
    });
    const hostileRelay = relayFixture(hostileStore, {
      receipt,
    }).relay;
    await assert.rejects(
      () =>
        hostileRelay.readEnrollmentSet({
          sessionId: SESSION_ID,
        }),
      { code: "COORDINATION_RELAY_INVALID" },
      label,
    );
    assert.deepEqual(
      await store.readEnrollment({
        role: "payer",
        sessionId: SESSION_ID,
      }),
      exactPayer,
    );
  }
});

test("reports exact frozen enrollment readiness without exposing enrollment authority data", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });

  const notReady = await relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 0,
  });
  assert.deepEqual(notReady, {
    paymentMoved: false,
    ready: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  });
  assert.equal(Object.isFrozen(notReady), true);

  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const ready = await relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 0,
  });
  assert.deepEqual(ready, {
    ...notReady,
    ready: true,
  });
  const encoded = JSON.stringify(ready);
  for (const secret of [
    "digest",
    "receipt",
    "capability",
    "address",
    "key",
    PAYER_CAPABILITY.toString("hex"),
    PAYEE_CAPABILITY.toString("hex"),
  ]) {
    assert.equal(encoded.includes(secret), false, secret);
  }
});

test("long-poll enrollment readiness waits for durable payee bootstrap and times out boundedly", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const pending = relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 30_000,
  });
  assert.equal(
    await Promise.race([
      pending.then(() => "settled"),
      new Promise((resolve) =>
        setTimeout(() => resolve("pending"), 25),
      ),
    ]),
    "pending",
  );
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  assert.deepEqual(await pending, {
    paymentMoved: false,
    ready: true,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  });

  const { store: timeoutStore } = await storeFixture(t);
  await registerRole(timeoutStore, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay: timeoutRelay } =
    relayFixture(timeoutStore);
  await bootstrapRole(timeoutRelay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const started = Date.now();
  assert.deepEqual(
    await timeoutRelay.readEnrollmentReadiness({
      sessionId: SESSION_ID,
      waitMs: 15,
    }),
    {
      paymentMoved: false,
      ready: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema:
        "clockchain.bilateral-enrollment-readiness/v1",
      sessionId: SESSION_ID,
    },
  );
  assert.ok(Date.now() - started >= 8);
});

test("enrollment readiness ignores unrelated session event notifications until peer bootstrap", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const pending = relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 30_000,
  });
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await relay.appendEvent({
    body: canonicalBytes(failure),
  });
  assert.equal(
    await Promise.race([
      pending.then(() => "settled"),
      new Promise((resolve) =>
        setTimeout(() => resolve("pending"), 25),
      ),
    ]),
    "pending",
  );
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  assert.deepEqual(await pending, {
    paymentMoved: false,
    ready: true,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    schema:
      "clockchain.bilateral-enrollment-readiness/v1",
    sessionId: SESSION_ID,
  });
});

test("enrollment readiness timeout returns false without treating timeout as notification", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  let payeeReads = 0;
  const timeoutStore = storeFacade(store, {
    async readEnrollment(input) {
      if (input.role === "payer") {
        return {
          bytes: Buffer.from("payer-placeholder"),
          digest: "a".repeat(64),
          receiptBytes: Buffer.from("receipt-placeholder"),
        };
      }
      payeeReads += 1;
      const error = new Error("payee pending");
      error.code =
        payeeReads === 1
          ? "COORDINATION_ENROLLMENT_NOT_FOUND"
          : "COORDINATION_IO";
      throw error;
    },
  });
  const { relay } = relayFixture(timeoutStore);
  assert.deepEqual(
    await relay.readEnrollmentReadiness({
      sessionId: SESSION_ID,
      waitMs: 15,
    }),
    {
      paymentMoved: false,
      ready: false,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      schema:
        "clockchain.bilateral-enrollment-readiness/v1",
      sessionId: SESSION_ID,
    },
  );
  assert.equal(payeeReads, 1);
});

test("notifies enrollment readiness only after successful capability consumption and receipt verification", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  let verifyReceipts = true;
  const pair = generateKeyPairSync("ed25519");
  const receipt = {
    signer: Object.freeze({
      certificateSha256: "c".repeat(64),
      signatureAlgorithm: "ed25519",
      sign(preimage) {
        return sign(null, preimage, pair.privateKey);
      },
      verify(preimage, signature) {
        return (
          verifyReceipts &&
          verify(null, preimage, pair.publicKey, signature)
        );
      },
    }),
  };
  const { relay } = relayFixture(store, { receipt });
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const pending = relay.readEnrollmentReadiness({
    sessionId: SESSION_ID,
    waitMs: 30_000,
  });
  verifyReceipts = false;
  await assert.rejects(
    bootstrapRole(relay, {
      capability: PAYEE_CAPABILITY,
      coordination: payeeCoordination,
      invitationPrivateKeys: invitationKeys.payee,
      preflight: payeePreflight,
      role: "payee",
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(
    await Promise.race([
      pending.then(() => "settled"),
      new Promise((resolve) =>
        setTimeout(() => resolve("pending"), 25),
      ),
    ]),
    "pending",
  );
  verifyReceipts = true;
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  assert.equal((await pending).ready, true);
});

test("enrollment readiness fails closed for malformed input and non-pending store errors", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  const aborted = new AbortController();
  aborted.abort();
  for (const input of [
    { sessionId: SESSION_ID, waitMs: -1 },
    { sessionId: SESSION_ID, waitMs: 30_001 },
    { sessionId: SESSION_ID, waitMs: 1.5 },
    { sessionId: SESSION_ID, waitMs: "0" },
    { extra: true, sessionId: SESSION_ID, waitMs: 0 },
    Object.defineProperty({ waitMs: 0 }, "sessionId", {
      enumerable: true,
      get() {
        return SESSION_ID;
      },
    }),
    { sessionId: SESSION_ID, signal: {}, waitMs: 0 },
    { sessionId: SESSION_ID, signal: aborted.signal, waitMs: 0 },
    Object.defineProperty(
      { sessionId: SESSION_ID, waitMs: 0 },
      "signal",
      {
        enumerable: true,
        get() {
          return new AbortController().signal;
        },
      },
    ),
  ]) {
    await assert.rejects(
      () => relay.readEnrollmentReadiness(input),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }

  const pendingRelay = relayFixture(storeFacade(store, {
    async readEnrollment(input) {
      if (input.role === "payer") {
        return {
          bytes: Buffer.from("payer-secret"),
          digest: "a".repeat(64),
          receiptBytes: Buffer.from("payer-receipt"),
        };
      }
      const error = new Error("pending");
      error.code = "COORDINATION_ENROLLMENT_NOT_FOUND";
      throw error;
    },
  })).relay;
  assert.equal(
    (
      await pendingRelay.readEnrollmentReadiness({
        sessionId: SESSION_ID,
        waitMs: 0,
      })
    ).ready,
    false,
  );

  const closedRelay = relayFixture(storeFacade(store, {
    async readEnrollment() {
      const error = new Error("storage unavailable");
      error.code = "COORDINATION_IO";
      throw error;
    },
  })).relay;
  await assert.rejects(
    () =>
      closedRelay.readEnrollmentReadiness({
        sessionId: SESSION_ID,
        waitMs: 0,
      }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("bootstraps exact enrollment once and returns the persisted verified receipt on retry", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { receipt, relay } = relayFixture(store);
  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const input = {
    body: bootstrapBody(PAYER_CAPABILITY, enrollment),
  };
  const first = await relay.bootstrap(input);
  const retry = await relay.bootstrap(input);
  const restartedRelay = relayFixture(store, {
    receipt,
  }).relay;
  const restartRetry = await restartedRelay.bootstrap(
    input,
  );
  assert.deepEqual(retry, first);
  assert.deepEqual(restartRetry, first);
  assert.equal(first.schema, RECEIPT_SCHEMA);
  assert.equal(first.paymentMoved, false);
  assert.equal(first.repositorySha, REPOSITORY_SHA);
  assert.equal(first.role, "payer");
  assert.equal(receipt.signCalls, 1);
  assert.deepEqual(
    await store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    {
      bytes: canonicalBytes(enrollment),
      digest: sha256(canonicalBytes(enrollment)),
      receiptBytes: stableBytes(first),
    },
  );
});

test("rejects a conflicting enrollment without replacing its durable receipt", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { receipt, relay } = relayFixture(store);
  const firstEnrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const first = await relay.bootstrap({
    body: bootstrapBody(
      PAYER_CAPABILITY,
      firstEnrollment,
    ),
  });
  const conflictingEnrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payer",
  });
  await assert.rejects(
    relay.bootstrap({
      body: bootstrapBody(
        PAYER_CAPABILITY,
        conflictingEnrollment,
      ),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(receipt.signCalls, 1);
  assert.deepEqual(
    await relay.bootstrap({
      body: bootstrapBody(
        PAYER_CAPABILITY,
        firstEnrollment,
      ),
    }),
    first,
  );
});

test("rejects wrong invitation recovery before consuming or signing a receipt", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { receipt, relay } = relayFixture(store);
  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    invitationSigners: invitationKeys.payee,
    preflight: payerPreflight,
    role: "payer",
  });
  await assert.rejects(
    relay.bootstrap({
      body: bootstrapBody(PAYER_CAPABILITY, enrollment),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(receipt.signCalls, 0);
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_ENROLLMENT_NOT_FOUND" },
  );
});

test("rejects a raw capability hidden in signed enrollment before consumption or persistence", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { receipt, relay } = relayFixture(store);
  const rawCapability =
    PAYER_CAPABILITY.toString("hex");
  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    preflightKeyId: rawCapability,
    role: "payer",
  });
  assert.equal(
    canonicalBytes(enrollment).includes(
      Buffer.from(rawCapability),
    ),
    true,
  );
  await assert.rejects(
    relay.bootstrap({
      body: bootstrapBody(
        PAYER_CAPABILITY,
        enrollment,
      ),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(receipt.signCalls, 0);
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_ENROLLMENT_NOT_FOUND" },
  );
});

test("rejects capability bytes and alternate encodings in signed enrollment before consumption", async (t) => {
  const capability = Buffer.alloc(32, 0xab);
  const scenarios = [
    {
      preflightPublicKey:
        capability.toString("base64"),
      releaseId: RELEASE_ID,
    },
    {
      releaseId: capability.toString("base64"),
    },
    {
      releaseId:
        capability.toString("base64url"),
    },
  ];
  for (const scenario of scenarios) {
    const { store } = await storeFixture(t);
    await registerRole(store, {
      capability,
      releaseId: scenario.releaseId,
      role: "payer",
    });
    const { receipt, relay } = relayFixture(store);
    const enrollment = await enrollmentFixture({
      capability,
      coordination: payerCoordination,
      invitationPrivateKeys:
        invitationKeys.payer,
      preflight: payerPreflight,
      ...scenario,
      role: "payer",
    });
    await assert.rejects(
      relay.bootstrap({
        body: bootstrapBody(
          capability,
          enrollment,
        ),
      }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
    assert.equal(receipt.signCalls, 0);
    await assert.rejects(
      store.readEnrollment({
        role: "payer",
        sessionId: SESSION_ID,
      }),
      { code: "COORDINATION_ENROLLMENT_NOT_FOUND" },
    );
  }
});

test("rejects an uppercase raw capability hidden in signed enrollment before consumption", async (t) => {
  const { store } = await storeFixture(t);
  const capability = Buffer.alloc(32, 0xab);
  const releaseId =
    capability.toString("hex").toUpperCase();
  await registerRole(store, {
    capability,
    releaseId,
    role: "payer",
  });
  const { receipt, relay } = relayFixture(store);
  const enrollment = await enrollmentFixture({
    capability,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    releaseId,
    role: "payer",
  });
  await assert.rejects(
    relay.bootstrap({
      body: bootstrapBody(
        capability,
        enrollment,
      ),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(receipt.signCalls, 0);
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_ENROLLMENT_NOT_FOUND" },
  );
});

test("rejects malformed, noncanonical, extra, mismatched, and oversized bootstrap bodies", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const exact = bootstrapBody(PAYER_CAPABILITY, enrollment);
  for (const body of [
    Buffer.from(`${exact.toString("utf8")}\n`),
    canonicalBytes({
      capability: PAYER_CAPABILITY.toString("hex"),
      enrollment,
      extra: false,
    }),
    bootstrapBody(PAYEE_CAPABILITY, enrollment),
    Buffer.alloc(65_537, 0x61),
  ]) {
    await assert.rejects(
      relay.bootstrap({ body }),
      {
        code: "COORDINATION_RELAY_INVALID",
        message:
          "Coordination relay operation failed safely.",
      },
    );
  }
});

test("serializes opposite-role duplicate bootstrap checks with capability consumption", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  const payer = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const payee = await enrollmentFixture({
    capability: PAYEE_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const results = await Promise.allSettled([
    relay.bootstrap({
      body: bootstrapBody(PAYER_CAPABILITY, payer),
    }),
    relay.bootstrap({
      body: bootstrapBody(PAYEE_CAPABILITY, payee),
    }),
  ]);
  assert.equal(
    results.filter(({ status }) => status === "fulfilled")
      .length,
    1,
  );
  assert.equal(
    results.find(({ status }) => status === "rejected")
      .reason.code,
    "COORDINATION_RELAY_INVALID",
  );
});

test("rejects duplicate invitation addresses across durable role enrollments", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  await registerRole(store, {
    capability: PAYEE_CAPABILITY,
    role: "payee",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const payee = await enrollmentFixture({
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: {
      rehearsal: invitationKeys.payer.rehearsal,
      stakeholder: invitationKeys.payee.stakeholder,
    },
    preflight: payeePreflight,
    role: "payee",
  });
  await assert.rejects(
    relay.bootstrap({
      body: bootstrapBody(PAYEE_CAPABILITY, payee),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("requires the receipt signer to verify before persistence and re-verifies returned durable bytes", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const receipt = makeReceiptSigner({
    verifyResult: false,
  });
  const { relay } = relayFixture(store, { receipt });
  await assert.rejects(
    bootstrapRole(relay, {
      capability: PAYER_CAPABILITY,
      coordination: payerCoordination,
      invitationPrivateKeys: invitationKeys.payer,
      preflight: payerPreflight,
      role: "payer",
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  await assert.rejects(
    store.readEnrollment({
      role: "payer",
      sessionId: SESSION_ID,
    }),
    { code: "COORDINATION_ENROLLMENT_NOT_FOUND" },
  );
});

test("shares one receipt schema, preimage, creation, and verification contract with clients", async () => {
  const source = await readFile(
    new URL(
      "../src/bilateral/coordination/relay.mjs",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(
    source,
    /from "\.\/receipt\.mjs";/,
  );
  assert.doesNotMatch(
    source,
    /function (?:createReceiptBytes|parseAndVerifyReceipt|receiptPreimage|receiptUnsigned)\(/,
  );
});

test("rejects a persisted receipt whose returned signature no longer verifies", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const corruptingStore = storeFacade(store, {
    async consumeCapability(input) {
      const consumed = await store.consumeCapability(input);
      const receipt = JSON.parse(
        consumed.receiptBytes.toString("utf8"),
      );
      const signature = Buffer.from(
        receipt.signature,
        "base64",
      );
      signature[0] ^= 0x01;
      receipt.signature = signature.toString("base64");
      return Object.freeze({
        ...consumed,
        receiptBytes: stableBytes(receipt),
      });
    },
  });
  const { relay } = relayFixture(corruptingStore);
  await assert.rejects(
    bootstrapRole(relay, {
      capability: PAYER_CAPABILITY,
      coordination: payerCoordination,
      invitationPrivateKeys: invitationKeys.payer,
      preflight: payerPreflight,
      role: "payer",
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("accepts role events only under the durable enrollment key and exact keyId", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const wrongKeyId = eventFixture({
    coordination: payerCoordination,
    keyId: "arbitrary-alias",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await assert.rejects(
    relay.appendEvent({
      body: canonicalBytes(wrongKeyId),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.deepEqual(
    await store.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    [],
  );
});

test("rejects durable role authority returned outside the event scope", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const payeeEnrollment = await enrollmentFixture({
    capability: PAYEE_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const { signature: _signature, ...payeeUnsigned } =
    payeeEnrollment;
  const wrongScopeEnrollment = signedEnrollment(
    {
      ...payeeUnsigned,
      coordinationKey: {
        ...payeeUnsigned.coordinationKey,
        keyId: "payer-coordination",
      },
    },
    payerCoordination,
  );
  const wrongScopeStore = storeFacade(store, {
    async readEnrollment() {
      const bytes = canonicalBytes(wrongScopeEnrollment);
      return Object.freeze({
        bytes,
        digest: sha256(bytes),
      });
    },
  });
  const { relay } = relayFixture(wrongScopeStore);
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await assert.rejects(
    relay.appendEvent({
      body: canonicalBytes(failure),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.deepEqual(
    await store.readEvents({
      after: null,
      sessionId: SESSION_ID,
    }),
    [],
  );
});

test("resolves operator authority only from the closed frozen repository path", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const calls = [];
  const { relay } = relayFixture(store, {
    resolver: repositoryResolver(calls),
  });
  const event = eventFixture({
    coordination: operator,
    keyId: OPERATOR_KEY_ID,
    kind: "TERMINAL_ABORT",
    role: "operator",
  });
  assert.deepEqual(
    await relay.appendEvent({
      body: canonicalBytes(event),
    }),
    event,
  );
  assert.deepEqual(
    await relay.appendEvent({
      body: canonicalBytes(event),
    }),
    event,
  );
  assert.deepEqual(calls, [
    {
      keyId: OPERATOR_KEY_ID,
      repositoryPath:
        `docs/operator-keys/${OPERATOR_KEY_ID}.pub`,
      repositorySha: REPOSITORY_SHA,
    },
    {
      keyId: OPERATOR_KEY_ID,
      repositoryPath:
        `docs/operator-keys/${OPERATOR_KEY_ID}.pub`,
      repositorySha: REPOSITORY_SHA,
    },
  ]);
  assert.equal(
    (
      await relay.readSessionView({
        sessionId: SESSION_ID,
      })
    ).state,
    "ABORTED",
  );
  assert.equal(
    (
      await store.readEvents({
        after: null,
        sessionId: SESSION_ID,
      })
    ).length,
    1,
  );
});

test("accepts only a canonical raw repository operator key line", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const event = eventFixture({
    coordination: operator,
    keyId: OPERATOR_KEY_ID,
    kind: "TERMINAL_ABORT",
    role: "operator",
  });
  const raw = rawPublicKey(operator);
  for (const value of [
    `${raw}\r\n`,
    `${raw}\n\n`,
    operator.publicKey.export({
      format: "pem",
      type: "spki",
    }),
  ]) {
    const { relay } = relayFixture(store, {
      resolver: async () => value,
    });
    await assert.rejects(
      relay.appendEvent({
        body: canonicalBytes(event),
      }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
});

test("binds descriptor READY and both ACCEPTED references to one exact artifact", async () => {
  const descriptorA = descriptorFixture();
  const descriptorB = descriptorFixture({
    sessionId: "11112233445566778899aabbccddeeff",
  });
  const descriptorC = descriptorFixture({
    sessionId: "22112233445566778899aabbccddeeff",
  });
  const artifacts = descriptorArtifactMap(
    descriptorA,
    descriptorB,
    descriptorC,
  );
  const digestA = sha256(canonicalBytes(descriptorA));
  const digestB = sha256(canonicalBytes(descriptorB));
  const digestC = sha256(canonicalBytes(descriptorC));
  const validator = descriptorValidator(artifacts);
  await validator.validate(
    eventFixture({
      artifactDigest: digestA,
      coordination: operator,
      keyId: OPERATOR_KEY_ID,
      kind: "REHEARSAL_DESCRIPTOR_READY",
      role: "operator",
      subjectRun: "rehearsal",
    }),
  );
  await assert.rejects(
    validator.validate(
      eventFixture({
        artifactDigest: digestB,
        coordination: payerCoordination,
        keyId: "payer-coordination",
        kind: "DESCRIPTOR_ACCEPTED",
        role: "payer",
        subjectRun: "rehearsal",
      }),
    ),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  await validator.validate(
    eventFixture({
      artifactDigest: digestA,
      coordination: payerCoordination,
      keyId: "payer-coordination",
      kind: "DESCRIPTOR_ACCEPTED",
      role: "payer",
      subjectRun: "rehearsal",
    }),
  );
  await assert.rejects(
    validator.validate(
      eventFixture({
        artifactDigest: digestC,
        coordination: payeeCoordination,
        keyId: "payee-coordination",
        kind: "DESCRIPTOR_ACCEPTED",
        role: "payee",
        subjectRun: "rehearsal",
      }),
    ),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  await validator.validate(
    eventFixture({
      artifactDigest: digestA,
      coordination: payeeCoordination,
      keyId: "payee-coordination",
      kind: "DESCRIPTOR_ACCEPTED",
      role: "payee",
      subjectRun: "rehearsal",
    }),
  );
});

test("rejects null, wrong-repository, wrong-run, wrong-key, and reused-session descriptor transitions", async () => {
  const descriptorA = descriptorFixture();
  const wrongRepository = descriptorFixture({
    repositorySha: "f".repeat(40),
  });
  const wrongKey = descriptorFixture({
    keyId: "other-repository-key",
  });
  const artifacts = descriptorArtifactMap(
    descriptorA,
    wrongRepository,
    wrongKey,
  );
  const ready = (artifactDigest, overrides = {}) =>
    eventFixture({
      artifactDigest,
      coordination: operator,
      keyId: OPERATOR_KEY_ID,
      kind: "REHEARSAL_DESCRIPTOR_READY",
      role: "operator",
      subjectRun: "rehearsal",
      ...overrides,
    });
  for (const event of [
    ready(null),
    ready(sha256(canonicalBytes(wrongRepository))),
    ready(sha256(canonicalBytes(wrongKey))),
    ready(sha256(canonicalBytes(descriptorA)), {
      subjectRun: "stakeholder",
    }),
  ]) {
    await assert.rejects(
      descriptorValidator(artifacts).validate(event),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
  const validator = descriptorValidator(artifacts);
  const digestA = sha256(canonicalBytes(descriptorA));
  await validator.validate(ready(digestA));
  await assert.rejects(
    validator.validate(
      eventFixture({
        artifactDigest: null,
        coordination: payerCoordination,
        keyId: "payer-coordination",
        kind: "DESCRIPTOR_ACCEPTED",
        role: "payer",
        subjectRun: "rehearsal",
      }),
    ),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  await assert.rejects(
    validator.validate(
      eventFixture({
        artifactDigest: digestA,
        coordination: operator,
        keyId: OPERATOR_KEY_ID,
        kind: "STAKEHOLDER_DESCRIPTOR_READY",
        role: "operator",
        subjectRun: "stakeholder",
      }),
    ),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("public relay rejects the first unsupported prerequisite even with a null artifact", async (t) => {
  const { store } = await storeFixture(t);
  for (const [role, capability] of [
    ["payer", PAYER_CAPABILITY],
    ["payee", PAYEE_CAPABILITY],
  ]) {
    await registerRole(store, { capability, role });
  }
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const buildEvent = eventBuilder();
  for (const input of [
    {
      kind: "ENROLLMENT_CONFIRMED",
      role: "payer",
    },
    {
      kind: "ENROLLMENT_CONFIRMED",
      role: "payee",
    },
    {
      kind: "ENROLLMENT_RECEIPT",
      role: "operator",
    },
    {
      kind: "WAIT_FOR_FUNDING",
      role: "operator",
    },
    {
      kind: "FUNDING_INPUTS_READY",
      role: "payer",
    },
    {
      kind: "FUNDING_INPUTS_READY",
      role: "payee",
    },
  ]) {
    const event = buildEvent(input);
    await relay.appendEvent({
      body: canonicalBytes(event),
    });
  }
  const unsupported = buildEvent({
    kind: "TOKEN_READY",
    role: "payer",
  });
  await assert.rejects(
    relay.appendEvent({
      body: canonicalBytes(unsupported),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  assert.equal(
    (
      await store.readEvents({
        after: null,
        sessionId: SESSION_ID,
      })
    ).length,
    6,
  );
});

test("rejects receipt misuse, unknown kinds, wrong authority, and post-abort events", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  const receipt = await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await assert.rejects(
    relay.appendEvent({
      body: canonicalBytes(receipt),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
  for (const event of [
    eventFixture({
      coordination: payerCoordination,
      keyId: "payer-coordination",
      kind: "UNKNOWN_EVENT",
      role: "payer",
    }),
    eventFixture({
      coordination: payerCoordination,
      keyId: "payer-coordination",
      kind: "ENROLLMENT_RECEIPT",
      role: "payer",
    }),
    eventFixture({
      coordination: operator,
      keyId: OPERATOR_KEY_ID,
      kind: "VERIFICATION_PASSED",
      role: "operator",
      subjectRun: "rehearsal",
    }),
  ]) {
    await assert.rejects(
      relay.appendEvent({
        body: canonicalBytes(event),
      }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
  const abort = eventFixture({
    coordination: operator,
    keyId: OPERATOR_KEY_ID,
    kind: "TERMINAL_ABORT",
    role: "operator",
  });
  await relay.appendEvent({
    body: canonicalBytes(abort),
  });
  const afterAbort = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "ENROLLMENT_CONFIRMED",
    role: "payer",
  });
  await assert.rejects(
    relay.appendEvent({
      body: canonicalBytes(afterAbort),
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("serializes replay, reduction, and append across concurrent senders", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const roleFailure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  const operatorAbort = eventFixture({
    coordination: operator,
    keyId: OPERATOR_KEY_ID,
    kind: "TERMINAL_ABORT",
    role: "operator",
  });
  const results = await Promise.allSettled([
    relay.appendEvent({
      body: canonicalBytes(roleFailure),
    }),
    relay.appendEvent({
      body: canonicalBytes(operatorAbort),
    }),
  ]);
  assert.equal(
    results.filter(({ status }) => status === "fulfilled")
      .length,
    1,
  );
  assert.equal(
    (
      await store.readEvents({
        after: null,
        sessionId: SESSION_ID,
      })
    ).length,
    1,
  );
});

test("replays the complete session view under the same role authorities", async (t) => {
  const { store } = await storeFixture(t);
  for (const [role, capability] of [
    ["payer", PAYER_CAPABILITY],
    ["payee", PAYEE_CAPABILITY],
  ]) {
    await registerRole(store, { capability, role });
  }
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  await bootstrapRole(relay, {
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const payerEvent = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "ENROLLMENT_CONFIRMED",
    role: "payer",
  });
  const payeeEvent = eventFixture({
    coordination: payeeCoordination,
    keyId: "payee-coordination",
    kind: "ENROLLMENT_CONFIRMED",
    role: "payee",
  });
  await relay.appendEvent({
    body: canonicalBytes(payerEvent),
  });
  await relay.appendEvent({
    body: canonicalBytes(payeeEvent),
  });
  assert.equal(
    (
      await relay.readSessionView({
        sessionId: SESSION_ID,
      })
    ).state,
    "ADDRESSES_READY",
  );
  assert.deepEqual(
    await relay.readEvents({
      after: null,
      sessionId: SESSION_ID,
      waitMs: 0,
    }),
    [payerEvent, payeeEvent],
  );
});

test("long-poll reads wake after a newly accepted event and time out boundedly", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  const { relay } = relayFixture(store);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const pending = relay.readEvents({
    after: null,
    sessionId: SESSION_ID,
    waitMs: 100,
  });
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await new Promise((resolve) => setTimeout(resolve, 10));
  await relay.appendEvent({
    body: canonicalBytes(failure),
  });
  assert.deepEqual(await pending, [failure]);
  const started = Date.now();
  assert.deepEqual(
    await relay.readEvents({
      after: failure.eventDigest,
      sessionId: SESSION_ID,
      waitMs: 15,
    }),
    [],
  );
  assert.ok(Date.now() - started >= 8);
});

test("long-poll registration cannot miss an append during its initial read", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  let releaseInitialRead;
  const initialReadReleased = new Promise((resolve) => {
    releaseInitialRead = resolve;
  });
  let markInitialReadStarted;
  const initialReadStarted = new Promise((resolve) => {
    markInitialReadStarted = resolve;
  });
  let firstRead = true;
  const delayedReadStore = storeFacade(store, {
    async readEvents(input) {
      const snapshot = await store.readEvents(input);
      if (firstRead) {
        firstRead = false;
        markInitialReadStarted();
        await initialReadReleased;
      }
      return snapshot;
    },
  });
  const { relay } = relayFixture(delayedReadStore);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const pending = relay.readEvents({
    after: null,
    sessionId: SESSION_ID,
    waitMs: 150,
  });
  await initialReadStarted;
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await relay.appendEvent({
    body: canonicalBytes(failure),
  });
  const started = Date.now();
  releaseInitialRead();
  assert.deepEqual(await pending, [failure]);
  assert.ok(Date.now() - started < 100);
});

test("aborting a long poll removes its waiter without a later reread", async (t) => {
  const { store } = await storeFixture(t);
  await registerRole(store, {
    capability: PAYER_CAPABILITY,
    role: "payer",
  });
  let readCount = 0;
  let markFirstRead;
  const firstRead = new Promise((resolve) => {
    markFirstRead = resolve;
  });
  const countedStore = storeFacade(store, {
    async readEvents(input) {
      readCount += 1;
      const result = await store.readEvents(input);
      if (readCount === 1) {
        markFirstRead();
      }
      return result;
    },
  });
  const { relay } = relayFixture(countedStore);
  await bootstrapRole(relay, {
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const alreadyAborted = new AbortController();
  alreadyAborted.abort();
  for (const signal of [
    {},
    alreadyAborted.signal,
  ]) {
    await assert.rejects(
      relay.readEvents({
        after: null,
        sessionId: SESSION_ID,
        signal,
        waitMs: 1_000,
      }),
      { code: "COORDINATION_RELAY_INVALID" },
    );
  }
  assert.equal(readCount, 0);
  const controller = new AbortController();
  const pending = relay.readEvents({
    after: null,
    sessionId: SESSION_ID,
    signal: controller.signal,
    waitMs: 1_000,
  });
  const rejected = assert.rejects(pending, {
    code: "COORDINATION_RELAY_INVALID",
  });
  await firstRead;
  controller.abort();
  await rejected;
  assert.equal(readCount, 1);
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  await relay.appendEvent({
    body: canonicalBytes(failure),
  });
  await new Promise((resolve) => setTimeout(resolve, 25));
  assert.equal(readCount, 1);
});

test("stores and reads exact content-addressed artifacts through the service", async (t) => {
  const { store } = await storeFixture(t);
  const { relay } = relayFixture(store);
  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const body = canonicalBytes(enrollment);
  const digest = sha256(body);
  assert.deepEqual(
    await relay.putArtifact({
      artifactType: "coordination-enrollment",
      body,
      expectedDigest: digest,
    }),
    {
      artifactType: "coordination-enrollment",
      byteLength: String(body.length),
      digest,
    },
  );
  assert.deepEqual(
    await relay.getArtifact({ digest }),
    body,
  );
  await assert.rejects(
    relay.putArtifact({
      artifactType: "coordination-enrollment",
      body,
      expectedDigest: digest,
      secretCanaries: [],
    }),
    { code: "COORDINATION_RELAY_INVALID" },
  );
});

test("pins fixed HTTPS deadlines and rejects every non-exact CLI flag surface before startup", async () => {
  assert.equal(RELAY_HEADER_TIMEOUT_MS, 5_000);
  assert.equal(RELAY_BODY_TIMEOUT_MS, 5_000);
  assert.equal(MAX_RELAY_WAIT_MS, 30_000);
  assert.equal(RELAY_TOTAL_TIMEOUT_MS, 40_000);
  assert.ok(
    RELAY_TOTAL_TIMEOUT_MS >= MAX_RELAY_WAIT_MS + 5_000,
  );
  assert.equal(
    RELAY_REPOSITORY_ROOT,
    resolve(
      fileURLToPath(new URL("../", import.meta.url)),
    ),
  );
  assert.doesNotMatch(
    await readFile(
      new URL("../bin/handshake-relay.mjs", import.meta.url),
      "utf8",
    ),
    /process\.cwd\(\)/,
  );
  const exact = relayArguments({
    certificatePath: "/tmp/certificate.pem",
    port: 8443,
    privateKeyPath: "/tmp/private-key.pem",
    state: "/tmp/relay-state",
  });
  await assert.rejects(
    relayMainProduction(exact),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );
  for (const arguments_ of [
    [],
    exact.slice(2),
    [...exact, "--plaintext"],
    [...exact, "--host", "127.0.0.2"],
    relayArguments({
      certificatePath: "/tmp/certificate.pem",
      host: "0.0.0.0",
      port: 8443,
      privateKeyPath: "/tmp/private-key.pem",
      state: "/tmp/relay-state",
    }),
    relayArguments({
      certificatePath: "/tmp/certificate.pem",
      host: "::",
      port: 8443,
      privateKeyPath: "/tmp/private-key.pem",
      state: "/tmp/relay-state",
    }),
  ]) {
    await assert.rejects(
      relayMain(arguments_),
      {
        code: "COORDINATION_RELAY_STARTUP_INVALID",
        message: "Handshake relay startup failed safely.",
      },
    );
  }

  let checkoutProbes = 0;
  for (const host of [
    "0:0:0:0:0:0:0:1",
    "2001:0DB8::1",
    "2001:db8:0:0:0:0:0:1",
  ]) {
    await assert.rejects(
      relayMain(
        relayArguments({
          certificatePath: "/tmp/certificate.pem",
          host,
          port: 8443,
          privateKeyPath: "/tmp/private-key.pem",
          state: "/tmp/relay-state",
        }),
        {
          checkoutProbe() {
            checkoutProbes += 1;
            return cleanCheckoutProbe();
          },
        },
      ),
      { code: "COORDINATION_RELAY_STARTUP_INVALID" },
    );
  }
  assert.equal(checkoutProbes, 0);

  await assert.rejects(
    relayMain(
      relayArguments({
        certificatePath: "/tmp/certificate.pem",
        host: "2001:db8::1",
        port: 8443,
        privateKeyPath: "/tmp/private-key.pem",
        state: "/tmp/relay-state",
      }),
      {
        checkoutProbe() {
          checkoutProbes += 1;
          return cleanCheckoutProbe();
        },
      },
    ),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );
  assert.equal(checkoutProbes, 1);
  const relaySource = await readFile(
    new URL("../bin/handshake-relay.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    relaySource,
    /isIP\(advertisedHost\) === 6\s*\? `\[\$\{advertisedHost\}\]:\$\{port\}`/,
  );
});

test("accepts only canonical port zero and reports the bound relay address without main output", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  for (const port of ["00", "01", "-1", "+0", "1.0", "65536"]) {
    await assert.rejects(
      relayMain(
        relayArguments({
          certificatePath: tls.certificatePath,
          port,
          privateKeyPath: tls.privateKeyPath,
          state,
        }),
        { checkoutProbe: cleanCheckoutProbe },
      ),
      { code: "COORDINATION_RELAY_STARTUP_INVALID" },
    );
  }
  const writes = [];
  const originalWrite = process.stdout.write;
  let running;
  process.stdout.write = (chunk, ...rest) => {
    writes.push([chunk, rest]);
    return true;
  };
  try {
    running = await relayMain(
      relayArguments({
        certificatePath: tls.certificatePath,
        port: 0,
        privateKeyPath: tls.privateKeyPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    );
  } finally {
    process.stdout.write = originalWrite;
  }
  t.after(() => running?.close().catch(() => {}));
  assert.deepEqual(writes, []);
  assert.equal(running.address.host, "127.0.0.1");
  assert.ok(Number.isSafeInteger(running.address.port) && running.address.port > 0);
  const response = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `127.0.0.1:${running.address.port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port: running.address.port,
  });
  assert.equal(response.statusCode, 200);
  assert.equal(
    relayReadinessLine(running),
    `{"host":"127.0.0.1","paymentMoved":false,"pid":${process.pid},"port":${running.address.port},"schema":"clockchain.bilateral-relay-ready/v1"}\n`,
  );
  await running.close();
  await running.close();
});

test("binds relay locally while validating client Host against required advertised address", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const port = await availablePort();
  let running;
  try {
    running = await relayMain(
      relayArguments({
        advertisedHost: "127.0.0.1",
        certificatePath: tls.certificatePath,
        host: "127.0.0.1",
        port,
        privateKeyPath: tls.privateKeyPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    );
  } finally {
    t.after(() => running?.close().catch(() => {}));
  }
  assert.equal(running.address.host, "127.0.0.1");
  assert.equal(running.address.port, port);
  const accepted = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `127.0.0.1:${port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port,
  });
  assert.equal(accepted.statusCode, 200);
  const rejected = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `127.0.0.2:${port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port,
  });
  assert.equal(rejected.statusCode, 400);
  await running.close();
});

test("accepts a canonical advertised DNS name only when the TLS certificate covers it", async (t) => {
  const advertisedHost = "relay.example.test";
  const tls = await tlsFixture(t, "ed25519", advertisedHost);
  const state = await privateRoot(t);
  const port = await availablePort();
  const running = await relayMainProduction(
    relayArguments({
      advertisedHost,
      certificatePath: tls.certificatePath,
      host: "127.0.0.1",
      port,
      privateKeyPath: tls.privateKeyPath,
      state,
    }),
    { checkoutProbe: cleanCheckoutProbe },
  );
  t.after(() => running.close().catch(() => {}));
  const accepted = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `${advertisedHost}:${port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port,
    servername: advertisedHost,
  });
  assert.equal(accepted.statusCode, 200);
  await running.close();
});

test("allows wildcard bind while still enforcing the concrete advertised Host", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const port = await availablePort();
  let running;
  try {
    running = await relayMain(
      relayArguments({
        advertisedHost: "127.0.0.1",
        certificatePath: tls.certificatePath,
        host: "0.0.0.0",
        port,
        privateKeyPath: tls.privateKeyPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    );
  } finally {
    t.after(() => running?.close().catch(() => {}));
  }
  assert.equal(running.address.host, "0.0.0.0");
  assert.equal(running.address.port, port);
  const accepted = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `127.0.0.1:${port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port,
  });
  assert.equal(accepted.statusCode, 200);
  const localMismatch = await httpsRequest({
    ca: tls.certificate,
    headers: { host: `127.0.0.2:${port}` },
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/events?waitMs=0`,
    port,
  });
  assert.equal(localMismatch.statusCode, 400);
  await running.close();
});

test("production checkout attestation ignores poisoned Git repository, index, worktree, config, executable, and locale environment", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const poisonRoot = await privateRoot(t);
  const cleanClone = join(poisonRoot, "clean-clone");
  const cleanArchive = join(poisonRoot, "clean-checkout.tar");
  await execFile(
    "/usr/bin/git",
    [
      "-C",
      RELAY_REPOSITORY_ROOT,
      "archive",
      "--format=tar",
      "--output",
      cleanArchive,
      "HEAD",
    ],
  );
  await mkdir(cleanClone, { mode: 0o700 });
  await execFile("/usr/bin/tar", ["-xf", cleanArchive, "-C", cleanClone]);
  await rm(cleanArchive, { force: true });
  await execFile("/usr/bin/git", ["-C", cleanClone, "init", "--quiet"]);
  await execFile("/usr/bin/git", ["-C", cleanClone, "add", "--all"]);
  await execFile(
    "/usr/bin/git",
    [
      "-C",
      cleanClone,
      "-c",
      "user.email=relay-e2e@example.invalid",
      "-c",
      "user.name=Relay E2E",
      "commit",
      "--quiet",
      "-m",
      "relay poisoned checkout fixture",
    ],
  );
  const { stdout: repositoryShaOutput } = await execFile(
    "/usr/bin/git",
    ["-C", cleanClone, "rev-parse", "--verify", "HEAD"],
    { encoding: "utf8" },
  );
  const repositorySha = repositoryShaOutput.trim();

  const dirtySentinel = join(
    RELAY_REPOSITORY_ROOT,
    `relay-checkout-integrity-${process.pid}-${Date.now()}`,
  );
  await writeFile(dirtySentinel, "dirty\n", {
    flag: "wx",
    mode: 0o600,
  });
  t.after(() => rm(dirtySentinel, { force: true }));
  const { stdout: dirtyStatus } = await execFile(
    "/usr/bin/git",
    [
      "-C",
      RELAY_REPOSITORY_ROOT,
      "status",
      "--porcelain=v1",
      "--untracked-files=normal",
      "--",
      dirtySentinel,
    ],
    { encoding: "utf8" },
  );
  assert.notEqual(dirtyStatus, "");

  const fakeHome = join(poisonRoot, "home");
  const fakeXdg = join(poisonRoot, "xdg");
  const fakeBin = join(poisonRoot, "bin");
  await Promise.all([
    mkdir(fakeHome),
    mkdir(join(fakeXdg, "git"), { recursive: true }),
    mkdir(fakeBin),
  ]);
  const config = `[core]\n\tworktree = ${cleanClone}\n`;
  const systemConfig = join(poisonRoot, "system.gitconfig");
  const globalConfig = join(poisonRoot, "global.gitconfig");
  await Promise.all([
    writeFile(join(fakeHome, ".gitconfig"), config),
    writeFile(join(fakeXdg, "git", "config"), config),
    writeFile(systemConfig, config),
    writeFile(globalConfig, config),
    writeFile(
      join(fakeBin, "git"),
      '#!/bin/sh\nexec /usr/bin/git "$@"\n',
      { mode: 0o700 },
    ),
  ]);

  const host = "127.0.0.1";
  const port = await availablePort();
  const child = spawn(
    process.execPath,
    [
      fileURLToPath(
        new URL("../bin/handshake-relay.mjs", import.meta.url),
      ),
      ...relayArguments({
        certificatePath: tls.certificatePath,
        host,
        port,
        privateKeyPath: tls.privateKeyPath,
        repositorySha,
        state,
      }),
    ],
    {
      env: {
        ...process.env,
        GIT_ALTERNATE_OBJECT_DIRECTORIES: join(
          cleanClone,
          ".git",
          "objects",
        ),
        GIT_CEILING_DIRECTORIES: poisonRoot,
        GIT_COMMON_DIR: join(cleanClone, ".git"),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_GLOBAL: globalConfig,
        GIT_CONFIG_KEY_0: "core.worktree",
        GIT_CONFIG_NOSYSTEM: "0",
        GIT_CONFIG_SYSTEM: systemConfig,
        GIT_CONFIG_VALUE_0: cleanClone,
        GIT_DIR: join(cleanClone, ".git"),
        GIT_DISCOVERY_ACROSS_FILESYSTEM: "1",
        GIT_INDEX_FILE: join(cleanClone, ".git", "index"),
        GIT_NO_REPLACE_OBJECTS: "0",
        GIT_OBJECT_DIRECTORY: join(
          cleanClone,
          ".git",
          "objects",
        ),
        GIT_OPTIONAL_LOCKS: "0",
        GIT_WORK_TREE: cleanClone,
        HOME: fakeHome,
        LANG: "poisoned_LOCALE",
        LC_ALL: "poisoned_LOCALE",
        PATH: fakeBin,
        XDG_CONFIG_HOME: fakeXdg,
      },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
    }
  });

  assert.deepEqual(
    await observeRelayChild(child, host, port),
    {
      code: 1,
      kind: "exit",
      signal: null,
      stderr: "COORDINATION_RELAY_STARTUP_INVALID\n",
    },
  );
});

test("TLS reads pin nonblocking no-follow handles and full pathname identity", async () => {
  const source = await readFile(
    new URL("../bin/handshake-relay.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /fsConstants\.O_NONBLOCK/);
  for (const field of [
    "dev",
    "ino",
    "mode",
    "nlink",
    "uid",
    "gid",
    "rdev",
    "size",
    "mtimeMs",
    "ctimeMs",
  ]) {
    assert.match(
      source,
      new RegExp(
        `left\\.${field} === right\\.${field}`,
      ),
    );
  }
  assert.match(
    source,
    /const pathnameAfter = await lstat\(path\)/,
  );
  assert.doesNotMatch(
    source,
    /handle\\?\\.close\\(\\)\\.catch/,
  );
});

test("rejects a TLS FIFO without blocking startup", async (t) => {
  const tls = await tlsFixture(t);
  const fifoPath = join(tls.root, "tls-certificate.fifo");
  await execFile("mkfifo", [fifoPath]);
  const state = await privateRoot(t);
  const startup = relayMain(
    relayArguments({
      certificatePath: fifoPath,
      port: await availablePort(),
      privateKeyPath: tls.privateKeyPath,
      state,
    }),
    { checkoutProbe: cleanCheckoutProbe },
  );
  await assert.rejects(
    Promise.race([
      startup,
      new Promise((_, reject) => {
        setTimeout(
          () => reject(new Error("FIFO read blocked")),
          500,
        );
      }),
    ]),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );
});

test("rejects nonprivate state, symlinked TLS keys, certificate mismatch, and injected production transport", async (t) => {
  const tls = await tlsFixture(t);
  const otherTls = await tlsFixture(t, "ecdsa-sha256");
  const port = await availablePort();
  const state = await privateRoot(t);
  const exact = relayArguments({
    certificatePath: tls.certificatePath,
    port,
    privateKeyPath: tls.privateKeyPath,
    state,
  });

  await chmod(state, 0o755);
  await assert.rejects(
    relayMain(exact, {
      checkoutProbe: cleanCheckoutProbe,
    }),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );
  await chmod(state, 0o700);

  const symlinkPath = join(tls.root, "tls-key-link.pem");
  await symlink(tls.privateKeyPath, symlinkPath);
  await assert.rejects(
    relayMain(
      relayArguments({
        certificatePath: tls.certificatePath,
        port,
        privateKeyPath: symlinkPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    ),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );

  await assert.rejects(
    relayMain(
      relayArguments({
        certificatePath: tls.certificatePath,
        port,
        privateKeyPath: otherTls.privateKeyPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    ),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );

  await assert.rejects(
    relayMain(exact, {
      checkoutProbe: cleanCheckoutProbe,
      createServer() {
        throw new Error("production transport injection");
      },
    }),
    { code: "COORDINATION_RELAY_STARTUP_INVALID" },
  );
});

test("rejects dirty and wrong immutable checkouts before opening relay state", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const arguments_ = relayArguments({
    certificatePath: tls.certificatePath,
    port: await availablePort(),
    privateKeyPath: tls.privateKeyPath,
    state,
  });
  for (const result of [
    {
      clean: false,
      repositorySha: REPOSITORY_SHA,
    },
    {
      clean: true,
      repositorySha: "f".repeat(40),
    },
  ]) {
    await assert.rejects(
      relayMain(arguments_, {
        checkoutProbe: async () => result,
      }),
      { code: "COORDINATION_RELAY_STARTUP_INVALID" },
    );
  }
});

test("uses immutable task provenance instead of a Git checkout in AWS mode", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const calls = [];
  const leaseCalls = [];
  const ownerLease = {
    async acquire(input) {
      leaseCalls.push(["acquire", input]);
      return {
        async assertCurrent() {
          leaseCalls.push(["assert"]);
        },
        async release() {
          leaseCalls.push(["release"]);
        },
      };
    },
  };
  const verified = Object.freeze({
    imageDigest: `sha256:${"b".repeat(64)}`,
    operatorPublicKey: rawPublicKey(operator),
    repositorySha: REPOSITORY_SHA,
    sourceTreeSha256: "c".repeat(64),
  });
  const provenanceProvider = {
    async assertRepository(input) {
      calls.push(["repository", input]);
      return verified;
    },
    async verify(input) {
      calls.push(["operator", input]);
      return verified;
    },
  };
  const running = await relayMain(
    relayArguments({
      certificatePath: tls.certificatePath,
      port: await availablePort(),
      privateKeyPath: tls.privateKeyPath,
      state,
    }),
    { ownerLease, provenanceProvider },
  );
  t.after(() => running.close().catch(() => {}));
  const registration = capabilityRegistration({
    capabilities: {
      payee: {
        capabilityDigest: sha256(PAYEE_CAPABILITY),
        expiresAtMs: String(Date.now() + 60_000),
      },
      payer: {
        capabilityDigest: sha256(PAYER_CAPABILITY),
        expiresAtMs: String(Date.now() + 120_000),
      },
    },
  });
  const response = await httpsRequest({
    body: canonicalBytes(registration),
    ca: tls.certificate,
    headers: { "content-type": "application/json" },
    method: "POST",
    path: "/v1/capabilities",
    port: running.address.port,
  });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [
    ["repository", { repositorySha: REPOSITORY_SHA }],
    ["operator", {
      operatorKeyId: OPERATOR_KEY_ID,
      repositorySha: REPOSITORY_SHA,
    }],
  ]);
  await running.close();
  assert.deepEqual(leaseCalls[0], [
    "acquire",
    { root: state },
  ]);
  assert.equal(
    leaseCalls.some(([operation]) =>
      operation === "assert"),
    true,
  );
  assert.deepEqual(leaseCalls.at(-1), ["release"]);
});

for (const signatureAlgorithm of [
  "ed25519",
  "ecdsa-sha256",
  "rsa-pss-sha256",
]) {
  test(`uses the real TLS ${signatureAlgorithm} key for HTTPS and receipt signing`, async (t) => {
    const tls = await tlsFixture(t, signatureAlgorithm);
    const state = await privateRoot(t);
    const initializer = await openCoordinationStore({
      now: () => NOW_MS,
      repositorySha: REPOSITORY_SHA,
      root: state,
    });
    await registerRole(initializer, {
      capability: PAYER_CAPABILITY,
      expiresAtMs: String(Date.now() + 60_000),
      role: "payer",
    });
    await initializer.close();
    const port = await availablePort();
    const running = await relayMain(
      relayArguments({
        certificatePath: tls.certificatePath,
        port,
        privateKeyPath: tls.privateKeyPath,
        state,
      }),
      { checkoutProbe: cleanCheckoutProbe },
    );
    t.after(() => running.close().catch(() => {}));
    const enrollment = await enrollmentFixture({
      capability: PAYER_CAPABILITY,
      coordination: payerCoordination,
      invitationPrivateKeys: invitationKeys.payer,
      preflight: payerPreflight,
      role: "payer",
    });
    const body = bootstrapBody(
      PAYER_CAPABILITY,
      enrollment,
    );
    const response = await httpsRequest({
      body,
      ca: tls.certificate,
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
      path: "/v1/bootstrap",
      port,
    });
    assert.equal(response.statusCode, 200);
    assert.equal(
      response.headers["content-type"],
      "application/json",
    );
    assert.equal(
      JSON.parse(response.body).signatureAlgorithm,
      signatureAlgorithm,
    );
    await running.close();
  });
}

test("serves only the closed HTTPS route, method, query, header, and body surface", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const initializer = await openCoordinationStore({
    now: () => NOW_MS,
    repositorySha: REPOSITORY_SHA,
    root: state,
  });
  await registerRole(initializer, {
    capability: PAYER_CAPABILITY,
    expiresAtMs: String(Date.now() + 60_000),
    role: "payer",
  });
  await registerRole(initializer, {
    capability: PAYEE_CAPABILITY,
    expiresAtMs: String(Date.now() + 60_000),
    role: "payee",
  });
  await initializer.close();
  const port = await availablePort();
  const running = await relayMain(
    relayArguments({
      certificatePath: tls.certificatePath,
      port,
      privateKeyPath: tls.privateKeyPath,
      state,
    }),
    { checkoutProbe: cleanCheckoutProbe },
  );
  t.after(() => running.close().catch(() => {}));

  const enrollment = await enrollmentFixture({
    capability: PAYER_CAPABILITY,
    coordination: payerCoordination,
    invitationPrivateKeys: invitationKeys.payer,
    preflight: payerPreflight,
    role: "payer",
  });
  const enrollmentBody = canonicalBytes(enrollment);
  const enrollmentDigest = sha256(enrollmentBody);
  const uploaded = await httpsRequest({
    body: enrollmentBody,
    ca: tls.certificate,
    headers: {
      "content-type": "application/octet-stream",
      "x-clockchain-artifact-type":
        "coordination-enrollment",
    },
    method: "PUT",
    path: `/v1/artifacts/${enrollmentDigest}`,
    port,
  });
  assert.equal(uploaded.statusCode, 200);
  const downloaded = await httpsRequest({
    ca: tls.certificate,
    method: "GET",
    path: `/v1/artifacts/${enrollmentDigest}`,
    port,
  });
  assert.equal(downloaded.statusCode, 200);
  assert.equal(
    downloaded.headers["content-type"],
    "application/octet-stream",
  );
  assert.deepEqual(downloaded.body, enrollmentBody);

  const bootstrapResponse = await httpsRequest({
    body: bootstrapBody(PAYER_CAPABILITY, enrollment),
    ca: tls.certificate,
    headers: {
      "content-type": "application/json",
    },
    method: "POST",
    path: "/v1/bootstrap",
    port,
  });
  assert.equal(bootstrapResponse.statusCode, 200);
  const payeeEnrollment = await enrollmentFixture({
    capability: PAYEE_CAPABILITY,
    coordination: payeeCoordination,
    invitationPrivateKeys: invitationKeys.payee,
    preflight: payeePreflight,
    role: "payee",
  });
  const payeeBootstrapResponse = await httpsRequest({
    body: bootstrapBody(
      PAYEE_CAPABILITY,
      payeeEnrollment,
    ),
    ca: tls.certificate,
    headers: {
      "content-type": "application/json",
    },
    method: "POST",
    path: "/v1/bootstrap",
    port,
  });
  assert.equal(payeeBootstrapResponse.statusCode, 200);
  const enrollmentSetResponse = await httpsRequest({
    ca: tls.certificate,
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/enrollments`,
    port,
  });
  assert.equal(enrollmentSetResponse.statusCode, 200);
  assert.equal(
    enrollmentSetResponse.headers["content-type"],
    "application/json",
  );
  assert.deepEqual(
    JSON.parse(enrollmentSetResponse.body),
    parseCoordinationEnrollmentSet(
      enrollmentSetResponse.body,
    ),
  );
  const failure = eventFixture({
    coordination: payerCoordination,
    keyId: "payer-coordination",
    kind: "TERMINAL_FAILURE",
    role: "payer",
  });
  const eventResponse = await httpsRequest({
    body: canonicalBytes(failure),
    ca: tls.certificate,
    headers: {
      "content-type": "application/json",
    },
    method: "POST",
    path: "/v1/events",
    port,
  });
  assert.equal(eventResponse.statusCode, 200);
  const eventsResponse = await httpsRequest({
    ca: tls.certificate,
    method: "GET",
    path:
      `/v1/sessions/${SESSION_ID}/events?` +
      "waitMs=0",
    port,
  });
  assert.deepEqual(
    JSON.parse(eventsResponse.body),
    [failure],
  );
  const viewResponse = await httpsRequest({
    ca: tls.certificate,
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/view`,
    port,
  });
  assert.equal(JSON.parse(viewResponse.body).state, "ABORTED");

  await new Promise((resolveAbort, rejectAbort) => {
    const request = https.request({
      ca: tls.certificate,
      host: "127.0.0.1",
      method: "GET",
      path:
        `/v1/sessions/${SESSION_ID}/events?` +
        `after=${failure.eventDigest}&waitMs=30000`,
      port,
      rejectUnauthorized: true,
    });
    const timeout = setTimeout(() => {
      rejectAbort(
        new Error("HTTPS long poll did not abort promptly"),
      );
    }, 1_000);
    request.once("response", () => {
      clearTimeout(timeout);
      rejectAbort(
        new Error("aborted long poll returned a response"),
      );
    });
    request.once("error", () => {
      clearTimeout(timeout);
      resolveAbort();
    });
    request.end();
    setTimeout(() => {
      request.destroy(new Error("test disconnect"));
    }, 25);
  });
  const postAbortView = await httpsRequest({
    ca: tls.certificate,
    method: "GET",
    path: `/v1/sessions/${SESSION_ID}/view`,
    port,
  });
  assert.equal(
    JSON.parse(postAbortView.body).state,
    "ABORTED",
  );

  const canary = "HTTP_ERROR_SECRET_CANARY";
  for (const request of [
    {
      method: "GET",
      path: `/unknown/${canary}`,
    },
    {
      method: "GET",
      path: "/v1/bootstrap",
    },
    {
      body: Buffer.from("{}"),
      headers: {
        "content-length": "2",
        "content-type": "application/json",
      },
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view`,
    },
    {
      body: Buffer.from("{}"),
      headers: {
        "content-type": "text/plain",
      },
      method: "POST",
      path: "/v1/bootstrap",
    },
    {
      body: Buffer.alloc(65_537, 0x61),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
      path: "/v1/bootstrap",
    },
    {
      body: bootstrapBody(PAYER_CAPABILITY, enrollment),
      headers: {
        "content-type": "application/json",
      },
      method: "POST",
      path: "/v1/bootstrap?redirect=https://example.test",
    },
    {
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/view?`,
    },
    {
      method: "GET",
      path:
        `/v1/sessions/${SESSION_ID}/enrollments?` +
        "advisoryStatus=ready",
    },
    {
      body: Buffer.from("{}"),
      headers: {
        "content-length": "2",
        "content-type": "application/json",
      },
      method: "GET",
      path: `/v1/sessions/${SESSION_ID}/enrollments`,
    },
    {
      method: "GET",
      path:
        `/v1/sessions/${SESSION_ID}/events?` +
        "waitMs=%30",
    },
    {
      body: enrollmentBody,
      headers: {
        "content-type": "application/octet-stream",
        "x-clockchain-artifact-type": [
          "coordination-enrollment",
          "coordination-enrollment",
        ],
      },
      method: "PUT",
      path: `/v1/artifacts/${enrollmentDigest}`,
    },
  ]) {
    const response = await httpsRequest({
      ca: tls.certificate,
      port,
      ...request,
    });
    assert.ok(response.statusCode >= 400);
    assert.equal(
      response.headers["content-type"],
      "application/json",
    );
    assert.deepEqual(JSON.parse(response.body), {
      code: "COORDINATION_RELAY_REQUEST_INVALID",
      paymentMoved: false,
    });
    assert.doesNotMatch(
      response.body.toString("utf8"),
      new RegExp(canary),
    );
  }

  const expectedHost = `127.0.0.1:${port}`;
  for (const request of [
    "GET /junk/../v1/sessions/" +
      `${SESSION_ID}/view HTTP/1.1\r\n` +
      `Host: ${expectedHost}\r\n` +
      "Connection: close\r\n\r\n",
    `GET /v1/sessions/${SESSION_ID}/view HTTP/1.1\r\n` +
      `Host: ${expectedHost}\r\n` +
      `Host: ${expectedHost}\r\n` +
      "Connection: close\r\n\r\n",
  ]) {
    const response = await rawTlsRequest({
      ca: tls.certificate,
      port,
      request,
    });
    assert.match(response, /^HTTP\/1\.1 400 /);
    assert.match(
      response,
      /\{"code":"COORDINATION_RELAY_REQUEST_INVALID","paymentMoved":false\}$/,
    );
  }
  await running.close();
});
