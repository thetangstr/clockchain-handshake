import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { main as runRequestPayment } from "../bin/handshake-request-payment.mjs";
import {
  createLaunchManifest,
  readLaunchManifest as realReadLaunchManifest,
} from "../src/bilateral/coordination/manifest.mjs";
import { runHybridLocalOperator } from "../src/bilateral/local-demo/operator-runtime.mjs";
import { bootstrapClaimFingerprint } from "../src/bilateral/local-mcp/bootstrap-broker.mjs";
import { sealRequestorBootstrapManifest } from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import { buildPaymentIntakeToolResult } from "../src/bilateral/local-mcp/payment-intake.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";
import {
  createSignedRequestorDiscovery,
  REQUESTOR_DISCOVERY_SCHEMA,
} from "../scripts/publish-requestor-discovery.mjs";

const REPOSITORY_ROOT = resolve(new URL("../", import.meta.url).pathname);
const REPOSITORY_SHA = "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-aaaaaaaaaaaaaaaa";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const OPERATOR_KEY_ID = "operator-yang";
const REQUESTOR_DISCOVERY_URL = "https://clockchain.example.test/requestor-discovery.json";
const PAYER_MCP_PUBLIC_URL = "https://127.0.0.1:9443/mcp";
const CERTIFICATE_URL = "https://clockchain.example.test/payer-mcp.crt";
const CAPABILITY = "ab".repeat(32);
const AUTHORIZED = "AUTHORIZED";
const IMAGE_DIGEST =
  `570035913370.dkr.ecr.us-west-2.amazonaws.com/clockchain-handshake@sha256:${"a".repeat(64)}`;
const INTAKE_INPUT_SCHEMA = "clockchain.payer-mcp-payment-intake/v1";
const HANDSHAKE_SEQUENCE = Object.freeze(["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"]);

function rawEd25519PublicKey(pair) {
  return pair.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("base64");
}

function paymentInput(intakeRequestId) {
  return Object.freeze({
    amount: Object.freeze({ currency: "USD", value: "100" }),
    intakeRequestId,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: INTAKE_INPUT_SCHEMA,
  });
}

function assertPaymentNeverMoved(value) {
  if (Array.isArray(value)) {
    for (const entry of value) assertPaymentNeverMoved(entry);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (key === "paymentMoved") assert.equal(child, false);
      assertPaymentNeverMoved(child);
    }
  }
}

async function waitFor(predicate, label) {
  const deadline = Date.now() + 5_000;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() >= deadline) throw new Error(`deadline waiting for ${label}`);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
  }
}

function sealedBrokerResponse({ claim, manifestBytes, operator }) {
  const context = Object.freeze({
    claimNonce: claim.claimNonce,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  const unsigned = Object.freeze({
    claimFingerprint: bootstrapClaimFingerprint(claim),
    context,
    envelope: sealRequestorBootstrapManifest({
      context,
      manifestBytes,
      requestorPublicKey: claim.requestorPublicKey,
    }),
    paymentMoved: false,
    repositorySha: REPOSITORY_SHA,
    schema: "clockchain.requestor-bootstrap-broker-response/v1",
    status: "SEALED",
  });
  return Object.freeze({
    ...unsigned,
    signature: Object.freeze({
      algorithm: "ed25519",
      keyId: OPERATOR_KEY_ID,
      value: sign(
        null,
        Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(unsigned)), "utf8"),
        operator.privateKey,
      ).toString("base64"),
    }),
  });
}

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(tmpdir(), "hybrid-local-process-e2e-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  const certificatePath = join(root, "payer-mcp.crt");
  const keyPath = join(root, "payer-mcp.key");
  execFileSync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "ed25519",
    "-keyout",
    keyPath,
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
  const certificateFingerprint =
    createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex");
  const operator = generateKeyPairSync("ed25519");
  const discovery = createSignedRequestorDiscovery({
    schema: REQUESTOR_DISCOVERY_SCHEMA,
    paymentMoved: false,
    imageDigest: IMAGE_DIGEST,
    releaseId: RELEASE_ID,
    sessionId: options.discoverySessionId ?? SESSION_ID,
    repositorySha: REPOSITORY_SHA,
    publicUrl: PAYER_MCP_PUBLIC_URL,
    certificateUrl: CERTIFICATE_URL,
    certificateFingerprint: options.wrongCertificatePin ? "f".repeat(64) : certificateFingerprint,
    operatorKeyId: OPERATOR_KEY_ID,
    runMode: "hybrid-local",
    expiresAtMs: String(Date.now() + 60_000),
    operatorPrivateKey: operator.privateKey,
  });
  const { manifest } = createLaunchManifest({
    expectedTlsFingerprint: certificateFingerprint,
    nowMs: Date.now(),
    operatorKeyId: OPERATOR_KEY_ID,
    payerMcpIntakeCapability: CAPABILITY,
    randomBytes: () => Buffer.alloc(32, 9),
    relayUrl: "https://8.8.8.8:8443",
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    role: "payee",
    sessionId: SESSION_ID,
    tlsCertificatePem,
  }, { allowTestAddresses: true });
  const manifestBytes =
    Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(manifest)), "utf8");
  const config = Object.freeze({
    funding: Object.freeze({
      journalDirectory: join(root, "funding-journal"),
      keystoreFile: join(root, "treasury.json"),
    }),
    operator: Object.freeze({
      clockchainTokenFile: join(root, "clockchain-token"),
      keyId: OPERATOR_KEY_ID,
      privateKeyFile: join(root, "operator.pem"),
      rpcUrlFile: join(root, "sepolia-rpc"),
    }),
    payerMcp: Object.freeze({
      publicUrl: PAYER_MCP_PUBLIC_URL,
      tlsCertificateFile: certificatePath,
    }),
    paymentMoved: false,
    publishing: Object.freeze({
      requestorDiscoveryUrl: REQUESTOR_DISCOVERY_URL,
    }),
    repositorySha: REPOSITORY_SHA,
  });
  const release = Object.freeze({
    manifests: Object.freeze([
      Object.freeze({ path: join(root, "release", "payer.launch.json"), role: "payer" }),
      Object.freeze({ path: join(root, "release", "payee.launch.json"), role: "payee" }),
    ]),
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
  });
  return {
    certificateFingerprint,
    config,
    discovery,
    manifestBytes,
    operator,
    operatorPublicKey: rawEd25519PublicKey(operator),
    release,
    root,
    stateRoot: join(root, "operator-state"),
    tlsCertificatePem,
  };
}

function service(name, calls, extra = {}) {
  return Object.freeze({
    ...extra,
    async stop() {
      calls.push(`stop:${name}`);
    },
    waitForExit() {
      return new Promise(() => {});
    },
  });
}

function createHarness(fx, options = {}) {
  const milestones = [];
  const statuses = [];
  const calls = [];
  const anchors = [];
  const publicHistory = [];
  const fundingBatches = [];
  const verifierOutputs = [];
  let pendingClaim = null;
  let sealed = null;
  let handoffResolve;
  const handoff = new Promise((resolvePromise) => {
    handoffResolve = resolvePromise;
  });
  const paths = Object.freeze({
    bootstrapBrokerCapabilityFile: join(fx.root, "broker.capability"),
    bootstrapBrokerStateRoot: join(fx.root, "broker"),
    payerStateRoot: join(fx.root, "payer"),
    relayStateRoot: join(fx.root, "relay"),
    releaseRoot: join(fx.root, "release"),
  });
  const transition = (kind) => Object.freeze({
    digest: createHash("sha256").update(kind).digest("hex"),
    kind,
    paymentMoved: false,
    role: kind === "ACCEPTED" ? "requestor" : "payer",
  });
  const dependencies = Object.freeze({
    async createStateRoot() {
      calls.push("createStateRoot");
      return paths;
    },
    async startRelay() {
      calls.push("startRelay");
      return service("relay", calls);
    },
    async startPublicEdge() {
      calls.push("startPublicEdge");
      return service("public-edge", calls);
    },
    async probeCoordinationEdge() {
      calls.push("probeCoordinationEdge");
      if (options.wrongPublicEdgePin) throw new Error("wrong public pin");
      return Object.freeze({ paymentMoved: false, ready: true });
    },
    async startCoordinator() {
      calls.push("startCoordinator");
      return service("coordinator", calls, {
        release: fx.release,
        async waitForTerminal() {
          calls.push("freshVerifier");
          await waitFor(() => anchors.length >= 3, "three anchors");
          const visibleAnchors = options.fourthAnchor
            ? [...anchors, transition("FOURTH")]
            : anchors;
          if (
            visibleAnchors.length !== 3 ||
            visibleAnchors.map(({ kind }) => kind).join(">") !== HANDSHAKE_SEQUENCE.join(">")
          ) {
            throw new Error("fresh verifier rejected anchor sequence");
          }
          verifierOutputs.push(AUTHORIZED);
          publicHistory.push(Object.freeze({
            anchors: visibleAnchors,
            outcome: AUTHORIZED,
            paymentMoved: false,
            source: "fresh-aggregate-verifier",
          }));
          return Object.freeze({ paymentMoved: false, status: "VERIFICATION_PASSED" });
        },
      });
    },
    async startConsole() {
      calls.push("startConsole");
      return service("console", calls);
    },
    async startBootstrapBroker() {
      calls.push("startBootstrapBroker");
      return service("bootstrap-broker", calls, {
        async approveRequestor() {
          calls.push("approveRequestor");
          if (options.wrongCertificatePin) throw new Error("requestor rejected certificate pin");
          await waitFor(() => pendingClaim, "pending bootstrap claim");
          if (sealed !== null) throw new Error("duplicate bootstrap approval");
          sealed = sealedBrokerResponse({
            claim: pendingClaim,
            manifestBytes: fx.manifestBytes,
            operator: fx.operator,
          });
          if (options.duplicateApproval) throw new Error("duplicate bootstrap approval");
          return Object.freeze({ paymentMoved: false, status: "APPROVED" });
        },
        capabilityFile: paths.bootstrapBrokerCapabilityFile,
        url: "http://127.0.0.1:9555",
      });
    },
    async startPayer() {
      calls.push("startPayer");
      return service("payer", calls);
    },
    async waitForPayerMcpReady() {
      calls.push("waitForPayerMcpReady");
      milestones.push("PAYER_MCP_READY");
      return Object.freeze({
        paymentMoved: false,
        status: "PAYER_MCP_READY",
        url: PAYER_MCP_PUBLIC_URL,
      });
    },
    async waitForPublicEdge() {
      calls.push("waitForPublicEdge");
      return Object.freeze({
        coordinationReady: true,
        payerMcpReady: true,
        paymentMoved: false,
      });
    },
    async publishRequestorDiscovery() {
      calls.push("publishRequestorDiscovery");
      return Object.freeze({
        discoveryUrl: REQUESTOR_DISCOVERY_URL,
        paymentMoved: false,
      });
    },
    async runFunding() {
      calls.push("runFunding");
      if (options.replayedFunding) throw new Error("funding replay rejected");
      const batch = Object.freeze({
        addresses: Object.freeze([
          "0x0000000000000000000000000000000000000001",
          "0x0000000000000000000000000000000000000002",
          "0x0000000000000000000000000000000000000003",
          "0x0000000000000000000000000000000000000004",
        ]),
        amountEth: "0.01",
        paymentMoved: false,
      });
      fundingBatches.push(batch);
      return Object.freeze({ paymentMoved: false, status: "FUNDING_CONFIRMED" });
    },
    writeFailureRecord(record) {
      calls.push(`writeFailureRecord:${record.service}`);
    },
    writeStatus(value) {
      statuses.push(value);
      if (value.stage === "REQUESTOR_HANDOFF_READY") handoffResolve();
    },
  });
  const requestorDependencies = Object.freeze({
    async inspectRepository(repositoryRoot) {
      assert.equal(repositoryRoot, REPOSITORY_ROOT);
      return Object.freeze({ clean: true, detached: true, head: REPOSITORY_SHA });
    },
    async fetchJson(url) {
      assert.equal(url, REQUESTOR_DISCOVERY_URL);
      return fx.discovery;
    },
    async fetchText(url) {
      assert.equal(url, CERTIFICATE_URL);
      return fx.tlsCertificatePem;
    },
    async readOperatorPublicKey(repositorySha, keyId) {
      assert.equal(repositorySha, REPOSITORY_SHA);
      assert.equal(keyId, OPERATOR_KEY_ID);
      return fx.operatorPublicKey;
    },
    async requestBootstrap(input) {
      calls.push("requestBootstrap");
      pendingClaim = input.claim;
      return sealed ?? Object.freeze({
        claimFingerprint: bootstrapClaimFingerprint(input.claim),
        paymentMoved: false,
        repositorySha: REPOSITORY_SHA,
        schema: "clockchain.requestor-bootstrap-broker-response/v1",
        status: "PENDING_APPROVAL",
      });
    },
    async requestPayment(input) {
      calls.push("requestPayment");
      assert.equal(input.capability, CAPABILITY);
      assert.equal(input.mcpUrl, PAYER_MCP_PUBLIC_URL);
      assert.equal(input.tlsFingerprint, fx.certificateFingerprint);
      const result = buildPaymentIntakeToolResult({
        repositorySha: REPOSITORY_SHA,
        toolInput: paymentInput(input.intakeRequestId),
      }).structuredContent;
      milestones.push(result.status);
      return result;
    },
    async readLaunchManifest(path) {
      calls.push("readLaunchManifest");
      try {
        return await realReadLaunchManifest(path);
      } catch (error) {
        calls.push(`readLaunchManifest:${error.name}:${error.code}`);
        throw error;
      }
    },
    async runSupervisor(input) {
      calls.push("requestorSupervisor");
      assert.equal(input.runMode, "local-two-run");
      milestones.push("REQUESTOR_SUPERVISOR_START");
      for (const kind of HANDSHAKE_SEQUENCE) {
        const anchor = transition(kind);
        anchors.push(anchor);
        milestones.push(kind);
      }
      return Object.freeze({ paymentMoved: false, status: "REQUESTOR_COMPLETE" });
    },
    async sleep() {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 5));
    },
    writeStatus(value) {
      assert.equal(value.status, "HANDSHAKE_REQUIRED");
      assert.deepEqual(value.authorizationSequence, HANDSHAKE_SEQUENCE);
      assert.equal(value.nextAction, "START_REQUESTOR_SUPERVISOR");
      assert.equal(value.paymentMoved, false);
    },
  });
  return Object.freeze({
    anchors,
    calls,
    dependencies,
    fundingBatches,
    handoff,
    milestones,
    publicHistory,
    requestorDependencies,
    statuses,
    verifierOutputs,
  });
}

async function runHappyPath(t) {
  const fx = await fixture(t);
  const harness = createHarness(fx);
  const operator = runHybridLocalOperator({
    config: fx.config,
    stateRoot: fx.stateRoot,
  }, harness.dependencies);
  operator.catch(() => {});
  await harness.handoff;
  const requestorState = join(fx.root, "requestor-state");
  let requestor;
  try {
    requestor = await runRequestPayment([
      "--discovery-url", REQUESTOR_DISCOVERY_URL,
      "--state", requestorState,
    ], harness.requestorDependencies);
  } catch (error) {
    assert.fail(`${error.message}; calls=${JSON.stringify(harness.calls)}`);
  }
  assert.deepEqual(requestor, { paymentMoved: false, status: "REQUESTOR_COMPLETE" });
  assert.deepEqual(await operator, { paymentMoved: false, status: "VERIFICATION_PASSED" });
  return { fx, harness, requestorState };
}

test("hybrid local operator and one-shot Requestor complete exactly three verified anchors", async (t) => {
  const { harness, requestorState } = await runHappyPath(t);

  assert.deepEqual(harness.milestones, [
    "PAYER_MCP_READY",
    "HANDSHAKE_REQUIRED",
    "REQUESTOR_SUPERVISOR_START",
    "PROPOSED",
    "ACCEPTED",
    "ACKNOWLEDGED",
  ]);
  assert.deepEqual(harness.anchors.map(({ kind }) => kind), HANDSHAKE_SEQUENCE);
  assert.deepEqual(harness.anchors.map(({ role }) => role), ["payer", "requestor", "payer"]);
  assert.equal(harness.anchors.length, 3);
  assert.equal(harness.verifierOutputs.join("\n"), AUTHORIZED);
  assert.equal(JSON.stringify(harness.statuses).includes(AUTHORIZED), false);
  assert.equal(harness.fundingBatches.length, 1);
  assert.equal(harness.fundingBatches[0].addresses.length, 4);
  assert.equal(new Set(harness.fundingBatches[0].addresses).size, 4);
  assert.deepEqual(harness.publicHistory.map(({ outcome }) => outcome), [AUTHORIZED]);
  assert.deepEqual(harness.publicHistory[0].anchors.map(({ kind }) => kind), HANDSHAKE_SEQUENCE);
  assert.deepEqual(
    harness.calls.filter((call) => call.startsWith("stop:")),
    [
      "stop:payer",
      "stop:bootstrap-broker",
      "stop:console",
      "stop:coordinator",
      "stop:public-edge",
      "stop:relay",
    ],
  );
  const bootstrapManifest = join(`${requestorState}.bootstrap`, "payee.launch.json");
  assert.equal((await lstat(bootstrapManifest)).mode & 0o777, 0o600);
  assertPaymentNeverMoved({
    anchors: harness.anchors,
    fundingBatches: harness.fundingBatches,
    publicHistory: harness.publicHistory,
    statuses: harness.statuses,
  });
});

async function assertFailsClosed(t, options) {
  const fx = await fixture(t, options);
  const harness = createHarness(fx, options);
  const operator = runHybridLocalOperator({
    config: fx.config,
    stateRoot: fx.stateRoot,
  }, harness.dependencies);
  operator.catch(() => {});
  if (!options.wrongPublicEdgePin) {
    await harness.handoff;
    const requestorRun = runRequestPayment([
        "--discovery-url", REQUESTOR_DISCOVERY_URL,
        "--state", join(fx.root, "requestor-state"),
      ], harness.requestorDependencies);
    if (options.wrongCertificatePin) {
      await assert.rejects(requestorRun, /Request payment startup failed safely/);
    } else {
      assert.deepEqual(await requestorRun, {
        paymentMoved: false,
        status: "REQUESTOR_COMPLETE",
      });
    }
  }
  await assert.rejects(operator, /Hybrid local operator stopped safely\./);
  assert.equal(harness.verifierOutputs.length, 0);
  assert.equal(harness.publicHistory.length, 0);
  assert.equal(JSON.stringify(harness.statuses).includes(AUTHORIZED), false);
  assertPaymentNeverMoved({
    anchors: harness.anchors,
    fundingBatches: harness.fundingBatches,
    statuses: harness.statuses,
  });
}

test("fails closed when the public TLS certificate pin is wrong", async (t) => {
  await assertFailsClosed(t, { wrongCertificatePin: true });
});

test("fails closed when bootstrap approval is duplicated", async (t) => {
  await assertFailsClosed(t, { duplicateApproval: true });
});

test("fails closed when funding is replayed before verification", async (t) => {
  await assertFailsClosed(t, { replayedFunding: true });
});

test("fails closed when a fourth anchor appears before the fresh verifier verdict", async (t) => {
  await assertFailsClosed(t, { fourthAnchor: true });
});
