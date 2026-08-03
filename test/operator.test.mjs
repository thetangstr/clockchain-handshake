import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer } from "node:net";
import {
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  generatePrivateKey,
  privateKeyToAccount,
} from "viem/accounts";

import {
  createSignedEnvelope,
  dSession,
  rawPublicKeyBase64FromPem,
  REGISTRY_ADDRESS,
} from "../src/core/descriptor.mjs";
import {
  BILATERAL_PROTOCOL_ID,
} from "../src/core/mandate-construction.mjs";
import {
  payerMandateDigest,
  signPayerMandate,
} from "../src/core/payer-mandate.mjs";
import {
  paymentRequestDigest,
  signPaymentRequest,
} from "../src/core/payment-request.mjs";
import { createRelayClient } from "../src/relay/client.mjs";
import { createRelayServer } from "../src/relay/server.mjs";
import {
  verifyDiscoveryDocument,
} from "../src/roles/discovery.mjs";
import {
  OPERATOR_CONFIG_SCHEMA,
  OPERATOR_SESSION_SCHEMA,
  OperatorError,
  runOperator,
  validateOperatorConfig,
} from "../src/roles/operator.mjs";

const PAYER = privateKeyToAccount(generatePrivateKey());
const PAYEE = privateKeyToAccount(generatePrivateKey());
const KEY_ID = "operator-test";
const REPOSITORY_SHA =
  "0123456789abcdef0123456789abcdef01234567";
const KIT_MANIFEST_DIGEST = "c".repeat(64);
const PROMPT_SHA256 = "a".repeat(64);

function sleep(milliseconds) {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
}

function captureStdout() {
  const lines = [];
  return {
    lines,
    text: () => lines.join(""),
    write(chunk) {
      lines.push(String(chunk));
      return true;
    },
  };
}

function pinFixture() {
  return {
    chainId: "11155111",
    clockchainUrl: "https://mcp.clockchain.network/mcp",
    generatedAtMs: "1784923000000",
    kitManifestDigest: KIT_MANIFEST_DIGEST,
    kitRepoUrl:
      "https://github.com/thetangstr/clockchain-handshake.git",
    protocolVersion: BILATERAL_PROTOCOL_ID,
    registry: REGISTRY_ADDRESS,
    repositorySha: REPOSITORY_SHA,
    schema: "handshake-release/v1",
  };
}

function configFor(relayUrl) {
  return {
    operatorKeyId: KEY_ID,
    relayUrl,
    rpcUrlFile: "/tmp/operator-test-rpc",
    schema: OPERATOR_CONFIG_SCHEMA,
    treasuryAddress: `0x${"3".repeat(40)}`,
    treasuryKeystoreFile: "/tmp/operator-test-keystore",
    treasuryPasswordFile: "/tmp/operator-test-password",
  };
}

async function intentEnvelopes() {
  const sessionId = "00112233-4455-6677-8899-aabbccddeeff";
  const mandate = {
    amount: { currency: "USD", value: "100" },
    expiresAtMs: "1784923800000",
    intakeDigest: "b".repeat(64),
    intakeRequestId:
      "22222222-3333-4444-8555-666666666666",
    invoiceReferencePrefix: "INV-",
    issuedAtMs: "1784923100000",
    payee: {
      address: PAYEE.address.toLowerCase(),
      agentId: "4242",
    },
    payer: {
      address: PAYER.address.toLowerCase(),
      agentId: "9001",
    },
    paymentMoved: false,
    protocol: BILATERAL_PROTOCOL_ID,
    purpose: "Invoice settlement",
    releaseId: "release-1",
    repositorySha: REPOSITORY_SHA,
    requestEndpoint:
      `/v1/sessions/${sessionId}/payment-requests`,
    schema: "clockchain.bilateral-payer-mandate/v1",
    sessionId,
    subjectRun: "stakeholder",
  };
  const mandateEnvelope = await signPayerMandate({
    mandate,
    signMessage: (raw) =>
      PAYER.signMessage({ message: { raw } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: mandate.amount,
      createdAtMs: "1784923150000",
      expiresAtMs: "1784923700000",
      intakeDigest: mandate.intakeDigest,
      intakeRequestId: mandate.intakeRequestId,
      invoiceReference: "INV-0001",
      mandateDigest: payerMandateDigest(mandateEnvelope),
      payee: mandate.payee,
      payer: mandate.payer,
      paymentMoved: false,
      protocol: mandate.protocol,
      purpose: mandate.purpose,
      releaseId: mandate.releaseId,
      repositorySha: mandate.repositorySha,
      requestId: "00000000-0000-4000-8000-000000000001",
      schema: "clockchain.bilateral-payment-request/v1",
      sessionId,
      subjectRun: mandate.subjectRun,
    },
    signMessage: (raw) =>
      PAYEE.signMessage({ message: { raw } }),
  });
  return Object.freeze({ mandateEnvelope, requestEnvelope });
}

function descriptorFromInputs(inputs) {
  return {
    amountOptions: [{ currency: "USD", value: "100" }],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: inputs.mandateDigest,
    namespace: "cbv1",
    payee: {
      address: inputs.payee.address,
      agentId: inputs.payee.agentId,
      displayName: "Requestor",
      role: "payee",
    },
    payer: {
      address: inputs.payer.address,
      agentId: inputs.payer.agentId,
      displayName: "Payer",
      role: "payer",
    },
    paymentMoved: false,
    promptSha256: inputs.promptSha256,
    protocol: BILATERAL_PROTOCOL_ID,
    protocolVersion: "1",
    registry: REGISTRY_ADDRESS,
    repositorySha: inputs.repositorySha,
    requestDigest: inputs.requestDigest,
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: "00112233445566778899aabbccddeeff",
    settlement: "not-executed",
  };
}

async function withRelay(t, run) {
  const stateDir = await mkdtemp(
    join(tmpdir(), "operator-relay-"),
  );
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const server = createRelayServer({ stateDir });
  const address = await server.listen();
  t.after(() => server.close());
  await run({
    relayUrl: `http://127.0.0.1:${address.port}`,
    server,
    stateDir,
  });
}

async function waitForDiscovery(relayUrl, sessionId) {
  const relay = createRelayClient({ relayUrl });
  for (;;) {
    try {
      return await relay.getDiscovery(sessionId);
    } catch {
      await sleep(25);
    }
  }
}

async function waitForMessage(relay, sessionId, kind, role) {
  let cursor = 0;
  for (;;) {
    const page = await relay.pollMessages({
      after: cursor,
      sessionId,
      waitMs: 0,
    });
    cursor = page.next;
    const found = page.messages.find(
      (message) =>
        message.kind === kind && message.role === role,
    );
    if (found !== undefined) return found;
    await sleep(25);
  }
}

async function awaitSessionStateFile(stateDir) {
  for (;;) {
    try {
      const state = JSON.parse(
        await readFile(
          join(stateDir, "operator-session.json"),
          "utf8",
        ),
      );
      if (state.subRuns !== undefined) return state;
    } catch {
      // not written yet
    }
    await sleep(25);
  }
}

function fakeDeps(overrides = {}) {
  const calls = {
    buildDescriptor: [],
    fund: [],
    register: [],
    spawn: [],
  };
  let agentCounter = 9000;
  const deps = {
    evidencePollIntervalMs: 25,
    buildDescriptor: async (inputs) => {
      calls.buildDescriptor.push(inputs);
      const descriptor = descriptorFromInputs(inputs);
      const envelope = createSignedEnvelope(descriptor, {
        keyId: KEY_ID,
        privateKeyPem: overrides.operatorPrivateKeyPem,
      });
      return { dSession: dSession(descriptor), envelope };
    },
    fundBatch: async ({ recordPath }) => {
      calls.fund.push(
        JSON.parse(await readFile(recordPath, "utf8")),
      );
    },
    preflight: async () => {},
    promptSha256: PROMPT_SHA256,
    publicClient: {
      getBalance: async () => 0n,
      getTransactionCount: async () => 0,
    },
    registerIdentity: async ({ expectedAddress }) => {
      agentCounter += 1;
      calls.register.push(expectedAddress);
      return {
        address: expectedAddress,
        agentId: String(agentCounter),
      };
    },
    releasePin: pinFixture(),
    spawnProcess: ({ script, args }) => {
      calls.spawn.push({ args, script });
      return {
        exited: Promise.resolve(0),
        kill: () => {},
      };
    },
    ...overrides,
  };
  return { calls, deps };
}

async function driveSession(relayUrl, sessionId, { live }) {
  const relay = createRelayClient({ relayUrl });
  const { mandateEnvelope, requestEnvelope } =
    await intentEnvelopes();
  await waitForDiscovery(relayUrl, sessionId);
  let payeeSeq = 0;
  const sendPayee = (kind, body) =>
    relay.sendMessage({
      body,
      kind,
      role: "payee",
      senderKey: "driver-payee",
      seq: payeeSeq,
      sessionId,
      sig: "78",
    }).then(() => {
      payeeSeq += 1;
    });
  if (live) {
    await sendPayee("identity-announce", {
      address: PAYEE.address.toLowerCase(),
    });
    await waitForMessage(
      relay,
      sessionId,
      "funding-confirmed",
      "operator",
    );
  }
  await sendPayee("party-ready", {
    address: PAYEE.address.toLowerCase(),
    agentId: "4242",
  });
  await relay.sendMessage({
    body: { envelope: mandateEnvelope },
    kind: "mandate-published",
    role: "payer",
    senderKey: "driver-payer",
    seq: 0,
    sessionId,
    sig: "78",
  });
  await sendPayee("payment-request-signed", {
    envelope: requestEnvelope,
  });
  await waitForMessage(
    relay,
    sessionId,
    "descriptor-published",
    "operator",
  );
  const triple = { json: "{}", markdown: "m", marker: "k" };
  await relay.putEvidence(sessionId, "payer", triple);
  await relay.putEvidence(sessionId, "payee", triple);
}

test("operator config validation", () => {
  const valid = configFor("http://127.0.0.1:8787");
  assert.equal(
    validateOperatorConfig(valid).relayUrl,
    "http://127.0.0.1:8787",
  );
  assert.equal(
    validateOperatorConfig({
      ...valid,
      relayUrl: "https://relay.example.com/",
    }).relayUrl,
    "https://relay.example.com",
  );
  const rejects = (patch) => {
    assert.throws(
      () => validateOperatorConfig({ ...valid, ...patch }),
      (error) => {
        assert.ok(error instanceof OperatorError);
        assert.equal(error.code, "CONFIG_SHAPE");
        return true;
      },
    );
  };
  rejects({ schema: "other" });
  rejects({ relayUrl: "http://192.168.1.10:8787" });
  rejects({ operatorKeyId: "Bad Key" });
  rejects({ treasuryAddress: "0x1234" });
  rejects({ treasuryKeystoreFile: "relative/path" });
  rejects({ extra: "field" });
});

test(
  "full operator dry-run drives both sub-runs end to end",
  async (t) => {
    const { privateKey, publicKey } =
      generateKeyPairSync("ed25519");
    const operatorPrivateKeyPem = privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
    const operatorPublicKey = rawPublicKeyBase64FromPem(
      publicKey.export({ format: "pem", type: "spki" }),
    );
    await withRelay(t, async ({ relayUrl }) => {
      const stateDir = await mkdtemp(
        join(tmpdir(), "operator-state-"),
      );
      t.after(() =>
        rm(stateDir, { recursive: true, force: true }),
      );
      const stdout = captureStdout();
      const { calls, deps } = fakeDeps({
        operatorPrivateKeyPem,
        stdout,
      });
      const config = configFor(relayUrl);
      const operatorPromise = runOperator({
        config,
        deps,
        stateDir,
      });
      const state = await awaitSessionStateFile(stateDir);
      await driveSession(
        relayUrl,
        state.subRuns.rehearsal.sessionId,
        { live: false },
      );
      await driveSession(
        relayUrl,
        state.subRuns.stakeholder.sessionId,
        { live: true },
      );
      await operatorPromise;

      assert.match(stdout.text(), /OPERATOR_RUN_COMPLETE/);
      assert.match(stdout.text(), /REQUESTOR_HANDOFF/);

      // Two funding batches: batch A covers four generated keys;
      // batch B leads with the announced requestor address followed
      // by three fresh reserves — active participants can never
      // reappear because funding records require nonce 0.
      assert.equal(calls.fund.length, 2);
      assert.equal(calls.fund[0].addresses.length, 4);
      assert.equal(
        calls.fund[1].addresses[0],
        PAYEE.address.toLowerCase(),
      );
      for (const address of calls.fund[1].addresses.slice(1)) {
        assert.ok(!calls.fund[0].addresses.includes(address));
      }

      // Both payer identities registered once each.
      assert.equal(calls.register.length, 2);

      // One descriptor per sub-run, each after the signed
      // payment request existed.
      assert.equal(calls.buildDescriptor.length, 2);
      assert.match(
        calls.buildDescriptor[0].mandateDigest,
        /^[0-9a-f]{64}$/,
      );
      assert.equal(
        calls.buildDescriptor[0].promptSha256,
        PROMPT_SHA256,
      );

      // Fresh verifier subprocess per sub-run.
      const verifierSpawns = calls.spawn.filter((call) =>
        call.script.endsWith("run.mjs")
      );
      assert.equal(verifierSpawns.length, 2);
      assert.deepEqual(
        verifierSpawns.map((call) =>
          call.args[call.args.indexOf("--subject-run") + 1]
        ),
        ["rehearsal", "stakeholder"],
      );

      // Signed discovery documents verify against the
      // operator public key.
      const relay = createRelayClient({ relayUrl });
      for (const subRun of ["rehearsal", "stakeholder"]) {
        const sessionId = state.subRuns[subRun].sessionId;
        const document = await relay.getDiscovery(sessionId);
        const verified = verifyDiscoveryDocument({
          document,
          expectedPublicKey: operatorPublicKey,
          nowMs: Date.now(),
        });
        assert.equal(verified.sessionId, sessionId);
        assert.equal(verified.subjectRun, subRun);
        const messages = await relay.pollMessages({
          sessionId,
          waitMs: 0,
        });
        assert.ok(
          messages.messages.some(
            (message) =>
              message.kind === "descriptor-published" &&
              message.role === "operator",
          ),
        );
      }
    });
  },
);

test(
  "a funding batch diverging from its persisted binding fails as FUNDING_REPLAYED",
  async (t) => {
    const { privateKey } = generateKeyPairSync("ed25519");
    await withRelay(t, async ({ relayUrl }) => {
      const stateDir = await mkdtemp(
        join(tmpdir(), "operator-replay-"),
      );
      t.after(() =>
        rm(stateDir, { recursive: true, force: true }),
      );
      const sessionState = {
        funding: {
          "batch-a": {
            addresses: [
              `0x${"1".repeat(40)}`,
              `0x${"2".repeat(40)}`,
              `0x${"4".repeat(40)}`,
              `0x${"5".repeat(40)}`,
            ],
            completed: false,
          },
          "batch-b": null,
        },
        operatorKeyId: KEY_ID,
        relayUrl,
        schema: OPERATOR_SESSION_SCHEMA,
        subRuns: {
          rehearsal: {
            discovery: null,
            payerAgentId: null,
            sessionId: crypto.randomUUID(),
          },
          stakeholder: {
            discovery: null,
            payerAgentId: null,
            sessionId: crypto.randomUUID(),
          },
        },
      };
      await writeFile(
        join(stateDir, "operator-session.json"),
        JSON.stringify(sessionState),
        { encoding: "utf8", mode: 0o600 },
      );
      const { deps } = fakeDeps({
        operatorPrivateKeyPem: privateKey.export({
          format: "pem",
          type: "pkcs8",
        }),
        stdout: captureStdout(),
      });
      await assert.rejects(
        runOperator({
          config: configFor(relayUrl),
          deps,
          stateDir,
        }),
        (error) => {
          assert.ok(error instanceof OperatorError);
          assert.equal(error.code, "FUNDING_REPLAYED");
          return true;
        },
      );
    });
  },
);

test(
  "restart with a journaled relay adopts prior state and skips completed funding",
  async (t) => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const operatorPrivateKeyPem = privateKey.export({
      format: "pem",
      type: "pkcs8",
    });
    const relayStateDir = await mkdtemp(
      join(tmpdir(), "operator-restart-relay-"),
    );
    t.after(() =>
      rm(relayStateDir, { recursive: true, force: true }),
    );
    const stateDir = await mkdtemp(
      join(tmpdir(), "operator-restart-state-"),
    );
    t.after(() =>
      rm(stateDir, { recursive: true, force: true }),
    );

    // Both servers bind the same loopback port so the persisted
    // operator state sees an identical relayUrl across the restart.
    const freePort = await new Promise((resolvePort) => {
      const probe = createServer();
      probe.listen(0, "127.0.0.1", () => {
        const { port } = probe.address();
        probe.close(() => resolvePort(port));
      });
    });
    const relayUrl = `http://127.0.0.1:${freePort}`;

    // First run: full dry-run against the first server.
    const firstServer = createRelayServer({
      port: freePort,
      stateDir: relayStateDir,
    });
    await firstServer.listen();
    const first = fakeDeps({
      operatorPrivateKeyPem,
      stdout: captureStdout(),
    });
    const firstRun = runOperator({
      config: configFor(relayUrl),
      deps: first.deps,
      stateDir,
    });
    const state = await awaitSessionStateFile(stateDir);
    await driveSession(
      relayUrl,
      state.subRuns.rehearsal.sessionId,
      { live: false },
    );
    await driveSession(
      relayUrl,
      state.subRuns.stakeholder.sessionId,
      { live: true },
    );
    await firstRun;
    await firstServer.close();

    // Restart: fresh server over the journaled relay state,
    // same operator state directory. No driver needed — every
    // artifact is adopted from the relay journal.
    const secondServer = createRelayServer({
      port: freePort,
      stateDir: relayStateDir,
    });
    await secondServer.listen();
    t.after(() => secondServer.close());
    const second = fakeDeps({
      operatorPrivateKeyPem,
      stdout: captureStdout(),
    });
    await runOperator({
      config: configFor(relayUrl),
      deps: second.deps,
      stateDir,
    });

    assert.equal(second.calls.fund.length, 0);
    assert.equal(second.calls.register.length, 0);
    assert.equal(second.calls.buildDescriptor.length, 0);
    const verifierSpawns = second.calls.spawn.filter(
      (call) => call.script.endsWith("run.mjs"),
    );
    assert.equal(verifierSpawns.length, 2);
  },
);
