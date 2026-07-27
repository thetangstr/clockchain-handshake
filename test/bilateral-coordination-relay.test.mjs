import assert from "node:assert/strict";
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
} from "../src/bilateral/descriptor.mjs";
import {
  createCoordinationEnvelope,
} from "../src/bilateral/coordination/envelope.mjs";
import {
  coordinationEnrollmentSignaturePreimage,
  invitationProofPreimage,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  openCoordinationStore,
} from "../src/bilateral/coordination/storage.mjs";
import {
  MAX_RELAY_WAIT_MS,
  createDescriptorArtifactTransitionValidator,
  createRelayService,
} from "../src/bilateral/coordination/relay.mjs";
import {
  RELAY_BODY_TIMEOUT_MS,
  RELAY_HEADER_TIMEOUT_MS,
  RELAY_REPOSITORY_ROOT,
  RELAY_TOTAL_TIMEOUT_MS,
  main as relayMain,
} from "../bin/handshake-relay.mjs";

const REPOSITORY_SHA = "e".repeat(40);
const SESSION_ID = "8f953393-86d0-4f99-9d6a-102f525fbecd";
const RELEASE_ID = "release-a";
const NOW_MS = 1_785_120_000_000;
const RECEIPT_SCHEMA =
  "clockchain.bilateral-coordination-receipt/v1";
const OPERATOR_KEY_ID = "relay-test-operator";
const PAYER_CAPABILITY = Buffer.alloc(32, 0x41);
const PAYEE_CAPABILITY = Buffer.alloc(32, 0x42);
const execFile = promisify(execFileCallback);

const payerCoordination = generateKeyPairSync("ed25519");
const payerPreflight = generateKeyPairSync("ed25519");
const payeeCoordination = generateKeyPairSync("ed25519");
const payeePreflight = generateKeyPairSync("ed25519");
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
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
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
  return new Promise((resolveListener) => {
    const deadline = Date.now() + 3_000;
    const attempt = () => {
      const socket = net.createConnection({ host, port });
      socket.once("connect", () => {
        socket.destroy();
        resolveListener({ kind: "listening" });
      });
      socket.once("error", () => {
        socket.destroy();
        if (Date.now() >= deadline) {
          resolveListener({ kind: "listener-timeout" });
          return;
        }
        setTimeout(attempt, 20);
      });
    };
    attempt();
  });
}

async function observeRelayChild(child, host, port) {
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const exit = new Promise((resolveExit) => {
    child.once("exit", (code, signal) => {
      resolveExit({
        code,
        kind: "exit",
        signal,
        stderr,
      });
    });
  });
  const outcome = await Promise.race([
    exit,
    waitForTcpListener(host, port),
  ]);
  if (outcome.kind !== "exit") {
    child.kill("SIGTERM");
    await exit;
  }
  return outcome;
}

function relayArguments({
  certificatePath,
  host = "127.0.0.1",
  port,
  privateKeyPath,
  repositorySha = REPOSITORY_SHA,
  state,
}) {
  return [
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
    releaseId = RELEASE_ID,
    role,
  },
) {
  return store.registerCapability({
    capabilityDigest: sha256(capability),
    expiresAtMs: String(NOW_MS + 60_000),
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
      schema:
        "clockchain.bilateral-session-descriptor/v1",
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
    "bootstrap",
    "getArtifact",
    "putArtifact",
    "readEvents",
    "readSessionView",
  ]);
  assert.equal(Object.isFrozen(relay), true);
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
  const corruptingStore = Object.freeze({
    appendEvent: store.appendEvent,
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
    getArtifact: store.getArtifact,
    putArtifact: store.putArtifact,
    readEnrollment: store.readEnrollment,
    readEvents: store.readEvents,
    readReleaseView: store.readReleaseView,
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
  const wrongScopeStore = Object.freeze({
    appendEvent: store.appendEvent,
    consumeCapability: store.consumeCapability,
    getArtifact: store.getArtifact,
    putArtifact: store.putArtifact,
    async readEnrollment() {
      const bytes = canonicalBytes(wrongScopeEnrollment);
      return Object.freeze({
        bytes,
        digest: sha256(bytes),
      });
    },
    readEvents: store.readEvents,
    readReleaseView: store.readReleaseView,
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
  const delayedReadStore = Object.freeze({
    appendEvent: store.appendEvent,
    consumeCapability: store.consumeCapability,
    getArtifact: store.getArtifact,
    putArtifact: store.putArtifact,
    readEnrollment: store.readEnrollment,
    async readEvents(input) {
      const snapshot = await store.readEvents(input);
      if (firstRead) {
        firstRead = false;
        markInitialReadStarted();
        await initialReadReleased;
      }
      return snapshot;
    },
    readReleaseView: store.readReleaseView,
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
  const countedStore = Object.freeze({
    appendEvent: store.appendEvent,
    consumeCapability: store.consumeCapability,
    getArtifact: store.getArtifact,
    putArtifact: store.putArtifact,
    readEnrollment: store.readEnrollment,
    async readEvents(input) {
      readCount += 1;
      const result = await store.readEvents(input);
      if (readCount === 1) {
        markFirstRead();
      }
      return result;
    },
    readReleaseView: store.readReleaseView,
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
    /isIP\(host\) === 6\s*\? `\[\$\{host\}\]:\$\{port\}`/,
  );
});

test("production checkout attestation ignores poisoned Git repository, index, worktree, config, executable, and locale environment", async (t) => {
  const tls = await tlsFixture(t);
  const state = await privateRoot(t);
  const poisonRoot = await privateRoot(t);
  const cleanClone = join(poisonRoot, "clean-clone");
  await execFile(
    "/usr/bin/git",
    [
      "clone",
      "--no-hardlinks",
      "--quiet",
      RELAY_REPOSITORY_ROOT,
      cleanClone,
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
