import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, X509Certificate } from "node:crypto";
import { constants } from "node:fs";
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { promisify } from "node:util";
import { privateKeyToAccount } from "viem/accounts";

import {
  COORDINATOR_CLI_FLAGS,
  createCoordinatorRuntimeDependencies,
  deriveDescriptorSessionId,
  loadOrCreateCoordinatorRelease,
  parseCoordinatorArguments,
  publishConsoleState,
  readCoordinatorRuntimeConfig,
  runChildWithDeadline,
  runPinnedVerifierChild,
  readVerifierContext,
  readCoordinatorState,
  stagePackage,
  validateVerifierPackageBinding,
  validatePinnedDescriptorEnvelope,
  createWatcherLifecycle,
  createCoordinatorDescriptor,
  watcherLine,
  runCoordinatorUntilComplete,
  writeVerifierContext,
} from "../src/bilateral/coordination/coordinator-runtime.mjs";
import { createSignedEnvelope, dSession, rawPublicKeyBase64FromPem } from "../src/bilateral/descriptor.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { payerMandateDigest, signPayerMandate } from "../src/bilateral/payer-mandate.mjs";
import { paymentRequestDigest, signPaymentRequest } from "../src/bilateral/payment-request.mjs";
import { COORDINATOR_STATE_SCHEMA, runCoordinator as runCoordinatorCore } from "../src/bilateral/coordination/coordinator.mjs";
import { validateFundingRecord } from "../src/bilateral/funding/record.mjs";
import { publishAwsVerifierHandoff } from "../infra/aws/runtime/coordinator-operator-handoff.mjs";

const execFile = promisify(execFileCallback);

const VALUES = Object.freeze({
  "--clockchain-token-file": "/private/token",
  "--operator-key-id": "clockchain-demo-2026",
  "--operator-private-key": "/private/operator.pem",
  "--release-root": "/private/release",
  "--relay-url": "https://127.0.0.1:8443",
  "--repository-sha": "a".repeat(40),
  "--rpc-url-file": "/private/rpc",
  "--tls-certificate": "/public/relay.pem",
  "--tls-fingerprint": "b".repeat(64),
});
const INTENT_DIGESTS = Object.freeze({
  mandateDigest: "c".repeat(64),
  requestDigest: "d".repeat(64),
});
const INTENT_PAYER = privateKeyToAccount(`0x${"1".repeat(64)}`);
const INTENT_PAYEE = privateKeyToAccount(`0x${"2".repeat(64)}`);
const INTENT_SESSION_ID = "11111111-2222-4333-8444-555555555555";
const INTAKE_DIGEST = "b".repeat(64);
const INTAKE_REQUEST_ID = "22222222-3333-4444-8555-666666666666";
const INTENT_NOW_MS = 1785294300000;
const FUNDING_ADDRESSES = Object.freeze([
  "0x1111111111111111111111111111111111111111",
  "0x2222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333",
  "0x4444444444444444444444444444444444444444",
]);

function fundingAdmissionClient({ balances = FUNDING_ADDRESSES.map(() => 0n), nonces = FUNDING_ADDRESSES.map(() => 0n), calls = [] } = {}) {
  return {
    calls,
    client: {
      async getBalance({ address }) {
        calls.push(["getBalance", address]);
        return balances[FUNDING_ADDRESSES.indexOf(address)];
      },
      async getTransactionCount({ address, blockTag }) {
        calls.push(["getTransactionCount", address, blockTag]);
        return nonces[FUNDING_ADDRESSES.indexOf(address)];
      },
    },
  };
}

function expectedFundingRecord(addresses = FUNDING_ADDRESSES) {
  return {
    addresses: [...addresses],
    paymentMoved: false,
    participants: addresses.map((address) => ({
      address,
      balanceWei: "0",
      nonce: "0",
    })),
    schema: "clockchain.bilateral-funding-addresses/v1",
  };
}

function relayPackage(name, content) {
  return canonicalBytes({
    files: [{
      byteLength: String(content.length),
      contentBase64: content.toString("base64"),
      name,
      sha256: createHash("sha256").update(content).digest("hex"),
    }],
    paymentMoved: false,
    schema: "clockchain.bilateral-relay-package/v1",
  });
}

function intentParties() {
  return {
    payer: { address: INTENT_PAYER.address.toLowerCase(), agentId: "101", displayName: "Iris", role: "payer" },
    payee: { address: INTENT_PAYEE.address.toLowerCase(), agentId: "202", displayName: "Billie", role: "payee" },
  };
}

async function signedIntents({ amount = "100", repositorySha = "b".repeat(40), requestOverrides = {} } = {}) {
  const parties = intentParties();
  const mandateEnvelope = await signPayerMandate({
    mandate: {
      amount: { currency: "USD", value: amount }, expiresAtMs: "1785297600000", invoiceReferencePrefix: "TREL-", issuedAtMs: "1785294000000",
      intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID,
      payee: { address: parties.payee.address, agentId: parties.payee.agentId }, payer: { address: parties.payer.address, agentId: parties.payer.agentId }, paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1", purpose: "freight-services", releaseId: "2026-07-28-live-demo", repositorySha,
      requestEndpoint: `/v1/sessions/${INTENT_SESSION_ID}/payment-requests`, schema: "clockchain.bilateral-payer-mandate/v1", sessionId: INTENT_SESSION_ID, subjectRun: "stakeholder",
    },
    signMessage: (bytes) => INTENT_PAYER.signMessage({ message: { raw: bytes } }),
  });
  const requestEnvelope = await signPaymentRequest({
    request: {
      amount: { currency: "USD", value: amount }, createdAtMs: "1785294300000", expiresAtMs: "1785297000000", invoiceReference: "TREL-2026-0001", mandateDigest: payerMandateDigest(mandateEnvelope),
      intakeDigest: INTAKE_DIGEST, intakeRequestId: INTAKE_REQUEST_ID,
      payee: { address: parties.payee.address, agentId: parties.payee.agentId }, payer: { address: parties.payer.address, agentId: parties.payer.agentId }, paymentMoved: false,
      protocol: "clockchain.bilateral-authorization/v1", purpose: "freight-services", releaseId: "2026-07-28-live-demo", repositorySha, requestId: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
      schema: "clockchain.bilateral-payment-request/v1", sessionId: INTENT_SESSION_ID, subjectRun: "stakeholder", ...requestOverrides,
    },
    signMessage: (bytes) => INTENT_PAYEE.signMessage({ message: { raw: bytes } }),
  });
  return { mandateEnvelope, parties, requestEnvelope };
}

test("coordinator runtime accepts each required flag exactly once and nothing else", () => {
  const argv = COORDINATOR_CLI_FLAGS.flatMap((flag) => [flag, VALUES[flag]]);
  assert.deepEqual(Object.fromEntries(Object.entries(parseCoordinatorArguments(argv))), VALUES);
  for (const hostile of [
    argv.slice(0, -2),
    [...argv, "--unexpected", "value"],
    [...argv.slice(0, -2), "--relay-url", "https://127.0.0.1:8443"],
  ]) assert.throws(() => parseCoordinatorArguments(hostile));
});

test("coordinator runtime advances one core state at a time and rejects no progress", async () => {
  const calls = [];
  const config = Object.freeze({ releaseRoot: "/release" });
  let state = "BOOTSTRAPPING";
  const result = await runCoordinatorUntilComplete(config, {
    loadOrCreateRelease: async () => ({ state }),
    runCoordinator: async () => {
      calls.push(state);
      state = state === "BOOTSTRAPPING" ? "COMPLETE" : state;
      return Object.freeze({ state, paymentMoved: false });
    },
  });
  assert.equal(result.state, "COMPLETE");
  assert.deepEqual(calls, ["BOOTSTRAPPING", "COMPLETE"]);
  await assert.rejects(runCoordinatorUntilComplete(config, {
    loadOrCreateRelease: async () => ({ state: "BOOTSTRAPPING" }),
    runCoordinator: async () => ({ state: "BOOTSTRAPPING", paymentMoved: false }),
  }));
});

test("coordinator runtime validates and threads abort signals into the core loop", async () => {
  const signal = new AbortController().signal;
  let observed;
  const result = await runCoordinatorUntilComplete(Object.freeze({}), {
    abortSignal: signal,
    loadOrCreateRelease: async () => ({ state: "BOOTSTRAPPING" }),
    runCoordinator: async ({ abortSignal }) => {
      observed = abortSignal;
      return Object.freeze({
        paymentMoved: false,
        state: "COMPLETE",
      });
    },
  });
  assert.equal(result.state, "COMPLETE");
  assert.equal(observed, signal);
  await assert.rejects(
    runCoordinatorUntilComplete(Object.freeze({}), {
      abortSignal: {},
      loadOrCreateRelease: async () => ({ state: "COMPLETE" }),
      runCoordinator: async () => ({
        paymentMoved: false,
        state: "COMPLETE",
      }),
    }),
    /Coordinator startup failed safely/,
  );
  const spoof = {
    aborted: false,
    addEventListener() {},
    removeEventListener() {},
  };
  Object.setPrototypeOf(spoof, AbortSignal.prototype);
  await assert.rejects(
    runCoordinatorUntilComplete(Object.freeze({}), {
      abortSignal: spoof,
      loadOrCreateRelease: async () => ({ state: "COMPLETE" }),
      runCoordinator: async () => ({
        paymentMoved: false,
        state: "COMPLETE",
      }),
    }),
    /Coordinator startup failed safely/,
  );
});

test("coordinator runtime aborts before advancing the loop and drains watchers", async () => {
  const controller = new AbortController();
  controller.abort();
  const calls = [];
  await assert.rejects(
    runCoordinatorUntilComplete(Object.freeze({}), {
      abortSignal: controller.signal,
      loadOrCreateRelease: async () => {
        calls.push("load");
        return {
          releaseId: "release-a",
          repositorySha: "a".repeat(40),
          sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
          state: "BOOTSTRAPPING",
        };
      },
      runCoordinator: async () => {
        calls.push("run");
        return {
          paymentMoved: false,
          state: "COMPLETE",
        };
      },
      runtime: {
        runDependencies() {
          return {
            async drainWatchers() {
              calls.push("drain");
            },
          };
        },
      },
    }),
    /Coordinator startup failed safely/,
  );
  assert.deepEqual(calls, ["load", "drain"]);
});

test("runtime derives stable, distinct descriptor session ids per run", () => {
  const release = { releaseId: "release-a", repositorySha: "a".repeat(40), sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" };
  const rehearsal = deriveDescriptorSessionId({ ...release, subjectRun: "rehearsal" });
  assert.equal(rehearsal, "793e061bacd955333d0e0f5017da773d");
  assert.equal(rehearsal, deriveDescriptorSessionId({ ...release, subjectRun: "rehearsal" }));
  assert.notEqual(rehearsal, deriveDescriptorSessionId({ ...release, subjectRun: "stakeholder" }));
  for (const hostile of [
    null,
    [],
    { ...release },
    { ...release, extra: true, subjectRun: "rehearsal" },
    { ...release, releaseId: "", subjectRun: "rehearsal" },
    { ...release, releaseId: " release-a", subjectRun: "rehearsal" },
    { ...release, releaseId: "r".repeat(257), subjectRun: "rehearsal" },
    { ...release, repositorySha: "A".repeat(40), subjectRun: "rehearsal" },
    { ...release, repositorySha: "a".repeat(39), subjectRun: "rehearsal" },
    { ...release, sessionId: "8f95339386d04f999d6a102f525fbecd", subjectRun: "rehearsal" },
    { ...release, sessionId: "8f953393-86d0-0f99-9d6a-102f525fbecd", subjectRun: "rehearsal" },
    { ...release, subjectRun: "release" },
    Object.defineProperties({}, {
      releaseId: { enumerable: true, get: () => release.releaseId },
      repositorySha: { enumerable: true, value: release.repositorySha },
      sessionId: { enumerable: true, value: release.sessionId },
      subjectRun: { enumerable: true, value: "rehearsal" },
    }),
  ]) assert.throws(() => deriveDescriptorSessionId(hostile));
});

test("production runtime exposes real bridges and relay START remains the role authority", async () => {
  const config = Object.freeze({
    clockchainToken: "token",
    operatorIdentity: Object.freeze({ keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }),
    operatorPublicKey: "public",
    releaseRoot: Object.freeze({ path: "/release" }),
    repositorySha: "a".repeat(40),
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "b".repeat(64),
  });
  const client = Object.freeze({
    appendOperatorEvent: async () => {}, appendVerifiedEvent: async () => {}, createVerifiedEvent: async () => {},
    getArtifact: async () => Buffer.from("{}"), putArtifact: async () => ({ digest: "c".repeat(64) }),
    readEnrollmentSet: async () => Buffer.from("{}"), readEvents: async () => [], readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }), readVerifierPublication: async () => null,
  });
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => client,
    createTransport: () => ({}),
    now: () => 0,
    sleeper: async () => {},
  });
  const bridges = runtime.runDependencies({ releaseId: "release-a", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" });
  assert.equal(bridges, runtime.runDependencies({ releaseId: "release-a", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }));
  for (const name of ["createPreflightPlan", "runAggregatePreflight", "validateArtifact", "waitForPreflightParticipant", "waitForIdentityPackage", "createDescriptor", "launchVerifier", "startRole", "startWatcher", "validatePublishedBilateralVerdict", "waitForDescriptorAcceptance", "validateRehearsalPackage", "waitForRolePackage", "waitForRoleStarted"]) assert.notEqual(bridges[name], undefined);
  await bridges.startRole({ role: "payee", subjectRun: "rehearsal" });
});

test("runtime omits undefined abort signal from raw event polling", async () => {
  const calls = [];
  const runtime = createCoordinatorRuntimeDependencies(Object.freeze({
    clockchainToken: "token",
    operatorIdentity: Object.freeze({ keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }),
    operatorPublicKey: "public",
    releaseRoot: Object.freeze({ path: "/release" }),
    repositorySha: "a".repeat(40),
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "b".repeat(64),
  }), {
    createClient: () => ({
      readEvents: async (input) => {
        assert.equal(Object.hasOwn(input, "signal"), false);
        calls.push(input);
        return [
          { artifactDigest: "c".repeat(64), kind: "IDENTITY_PACKAGE_READY", role: "payer", subjectRun: "release" },
          { artifactDigest: "d".repeat(64), kind: "IDENTITY_PACKAGE_READY", role: "payee", subjectRun: "release" },
        ];
      },
    }),
    createTransport: () => ({}),
    now: () => 0,
    sleeper: async () => {},
  });

  await runtime.runDependencies({ releaseId: "release-a", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).waitForIdentityPackage({ subjectRun: "release" });
  assert.deepEqual(calls, [
    { after: null, waitMs: 30_000 },
    { after: null, waitMs: 30_000 },
  ]);
});

test("runtime publishes one canonical private funding address file and validates it on restart", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runtime-funding-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const config = Object.freeze({
    clockchainToken: "token",
    operatorIdentity: Object.freeze({ keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }),
    operatorPublicKey: "public",
    releaseRoot: Object.freeze({ before, handle, path: rootPath }),
    repositorySha: "a".repeat(40),
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "b".repeat(64),
  });
  const output = [];
  const admission = fundingAdmissionClient();
  const runtime = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createFundingAdmissionClient: () => admission.client, createTransport: () => ({}), output: (line) => output.push(line) });
  await runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(FUNDING_ADDRESSES);
  const path = join(rootPath, "funding-addresses.json");
  const bytes = await readFile(path);
  const record = JSON.parse(bytes.toString("utf8"));
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  assert.deepEqual(record, expectedFundingRecord());
  assert.deepEqual(validateFundingRecord(record), expectedFundingRecord());
  assert.equal(bytes.toString("utf8"), `${JSON.stringify(expectedFundingRecord())}\n`);
  assert.deepEqual(output, [bytes.toString("utf8")]);
  assert.deepEqual(admission.calls, FUNDING_ADDRESSES.flatMap((address) => [
    ["getBalance", address],
    ["getTransactionCount", address, "latest"],
  ]));

  const restartOutput = [];
  const restarted = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createFundingAdmissionClient: () => assert.fail("restart must not inspect live admission facts"), createTransport: () => ({}), output: (line) => restartOutput.push(line) });
  await restarted.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(FUNDING_ADDRESSES);
  assert.equal((await readFile(path)).equals(bytes), true);
  assert.deepEqual(restartOutput, [bytes.toString("utf8")]);

  const hostile = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createFundingAdmissionClient: () => fundingAdmissionClient().client, createTransport: () => ({}) });
  await assert.rejects(hostile.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses([...FUNDING_ADDRESSES].reverse()));
});

test("runtime rejects nonzero funding admission facts before publication", async (t) => {
  for (const [name, overrides] of [
    ["balance", { balances: [1n, 0n, 0n, 0n] }],
    ["nonce", { nonces: [1n, 0n, 0n, 0n] }],
  ]) {
    const rootPath = await mkdtemp(join(tmpdir(), `coordinator-runtime-funding-${name}-`));
    await chmod(rootPath, 0o700);
    const before = await lstat(rootPath);
    const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
    t.after(() => handle.close());
    t.after(() => rm(rootPath, { recursive: true, force: true }));
    const config = Object.freeze({
      clockchainToken: "token",
      operatorIdentity: Object.freeze({ keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }),
      operatorPublicKey: "public",
      releaseRoot: Object.freeze({ before, handle, path: rootPath }),
      repositorySha: "a".repeat(40),
      relayUrl: "https://127.0.0.1:8443",
      rpcUrl: "https://127.0.0.1/",
      tlsCertificatePem: "certificate",
      tlsFingerprint: "b".repeat(64),
    });
    const admission = fundingAdmissionClient(overrides);
    const runtime = createCoordinatorRuntimeDependencies(config, {
      createClient: () => ({}),
      createFundingAdmissionClient: () => admission.client,
      createTransport: () => ({}),
    });

    await assert.rejects(
      runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(FUNDING_ADDRESSES),
    );
    await assert.rejects(readFile(join(rootPath, "funding-addresses.json")), { code: "ENOENT" });
  }
});

test("runtime rejects stale funding address temporaries before publishing", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runtime-funding-stale-"));
  await chmod(rootPath, 0o700);
  await writeFile(join(rootPath, ".funding-addresses-stale.tmp"), "{}", { mode: 0o600 });
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const config = {
    clockchainToken: "token",
    operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" },
    operatorPublicKey: "public",
    releaseRoot: { before, handle, path: rootPath },
    repositorySha: "a".repeat(40),
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "b".repeat(64),
  };
  const runtime = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createTransport: () => ({}) });
  await assert.rejects(async () => runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses([
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
  ]));
});

test("runtime rejects funding address publication when the destination appears after absence validation", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runtime-funding-race-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const config = {
    clockchainToken: "token",
    operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" },
    operatorPublicKey: "public",
    releaseRoot: { before, handle, path: rootPath },
    repositorySha: "a".repeat(40),
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "b".repeat(64),
  };
  const addresses = [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
  ];
  let raced = false;
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({}),
    createFundingAdmissionClient: () => fundingAdmissionClient().client,
    createTransport: () => ({}),
    fundingFileSystem: {
      link: async (temporary, path) => {
        raced = true;
        await writeFile(path, "{}", { mode: 0o600 });
        return link(temporary, path);
      },
      lstat,
      open,
      readdir,
      unlink,
    },
  });

  await assert.rejects(runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(addresses));
  assert.equal(raced, true);
  assert.equal(await readFile(join(rootPath, "funding-addresses.json"), "utf8"), "{}");
});

test("console state replaces rehearsal with stakeholder state and reuses exact restart bytes", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-console-state-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const root = { before, handle, path: rootPath };
  const rehearsal = { padding: "x".repeat(512), paymentMoved: false, subjectRun: "rehearsal" };
  const stakeholder = { paymentMoved: false, subjectRun: "stakeholder" };
  const path = await publishConsoleState(root, rehearsal);
  const rehearsalStat = await lstat(path);
  assert.equal(await readFile(path, "utf8"), `${JSON.stringify(rehearsal)}\n`);

  assert.equal(await publishConsoleState(root, rehearsal), path);
  const restartStat = await lstat(path);
  assert.equal(restartStat.dev, rehearsalStat.dev);
  assert.equal(restartStat.ino, rehearsalStat.ino);

  assert.equal(await publishConsoleState(root, stakeholder), path);
  assert.equal(await readFile(path, "utf8"), `${JSON.stringify(stakeholder)}\n`);
  const stakeholderStat = await lstat(path);
  assert.notEqual(stakeholderStat.ino, rehearsalStat.ino);
  assert.equal(stakeholderStat.mode & 0o777, 0o600);
});

test("console state rejects symlink and destination-appearance races", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-console-race-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const root = { before, handle, path: rootPath };
  const path = join(rootPath, "console-state.json");
  const target = join(rootPath, "target.json");
  await writeFile(target, "untouched", { mode: 0o600 });
  await symlink(target, path);
  await assert.rejects(publishConsoleState(root, { paymentMoved: false, subjectRun: "rehearsal" }));
  assert.equal(await readFile(target, "utf8"), "untouched");
  await unlink(path);

  let destinationChecks = 0;
  const fileSystem = {
    link,
    async lstat(path_) {
      if (path_ === path) {
        destinationChecks += 1;
        if (destinationChecks === 2) await writeFile(path, "raced", { mode: 0o600 });
      }
      return lstat(path_);
    },
    open,
    readdir,
    unlink,
  };
  await assert.rejects(publishConsoleState(root, { paymentMoved: false, subjectRun: "rehearsal" }, fileSystem));
  assert.equal(await readFile(path, "utf8"), "raced");
});

test("runtime release dependencies satisfy the coordinator release contract", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runtime-release-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const certificatePath = join(rootPath, "relay.pem");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(rootPath, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const keyPair = generateKeyPairSync("ed25519");
  const config = Object.freeze({
    clockchainToken: "token",
    operatorIdentity: Object.freeze({
      keyId: "clockchain-demo-2026",
      privateKeyPem: keyPair.privateKey.export({ format: "pem", type: "pkcs8" }),
      publicKey: rawPublicKeyBase64FromPem(keyPair.publicKey.export({ format: "pem", type: "spki" })),
    }),
    operatorPublicKey: rawPublicKeyBase64FromPem(keyPair.publicKey.export({ format: "pem", type: "spki" })),
    releaseRoot: Object.freeze({ before, handle, path: rootPath }),
    repositorySha: "a".repeat(40),
    relayUrl: "https://32.186.198.119:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem,
    tlsFingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
  });
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({
      registerCapabilitySet: async ({ registration }) => ({
        capabilities: registration.capabilities,
        paymentMoved: false,
        registrationDigest: "c".repeat(64),
        releaseId: registration.releaseId,
        repositorySha: registration.repositorySha,
        requestDigest: "d".repeat(64),
        schema: "clockchain.bilateral-capability-registration-receipt/v1",
        sessionId: registration.sessionId,
      }),
    }),
    createTransport: () => ({}),
    releaseIdentity: {
      releaseId:
        "release-bd7662a5eeb41614",
      sessionId:
        "11111111-1111-4111-8111-111111111111",
    },
  });

  const release = await loadOrCreateCoordinatorRelease(config, { runtime });

  assert.equal(release.state, "BOOTSTRAPPING");
  assert.equal(
    release.releaseId,
    "release-bd7662a5eeb41614",
  );
  assert.equal(
    release.sessionId,
    "11111111-1111-4111-8111-111111111111",
  );
  assert.equal((await readCoordinatorState(config.releaseRoot)).releaseId, release.releaseId);
});

test("runtime run dependencies cross the coordinator's exact validation boundary", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runtime-run-"));
  await chmod(rootPath, 0o700);
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const certificatePath = join(rootPath, "relay.pem");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(rootPath, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const keyPair = generateKeyPairSync("ed25519");
  const publicKey = rawPublicKeyBase64FromPem(keyPair.publicKey.export({ format: "pem", type: "spki" }));
  const config = Object.freeze({
    clockchainToken: "token",
    operatorIdentity: Object.freeze({ keyId: "clockchain-demo-2026", privateKeyPem: keyPair.privateKey.export({ format: "pem", type: "pkcs8" }), publicKey }),
    operatorPublicKey: publicKey,
    releaseRoot: Object.freeze({ before, handle, path: rootPath }),
    repositorySha: "a".repeat(40),
    relayUrl: "https://32.186.198.119:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem,
    tlsFingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
  });
  let enrollmentReads = 0;
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({
      appendOperatorEvent: async () => {}, appendVerifiedEvent: async () => {}, createVerifiedEvent: async () => {}, getArtifact: async () => Buffer.from("{}"), putArtifact: async () => ({ digest: "c".repeat(64) }),
      readEnrollmentSet: async () => { enrollmentReads += 1; return Buffer.from("{}"); }, readEvents: async () => [], readSessionView: async () => ({ facts: { enrollmentConfirmed: { payee: true, payer: true } }, paymentMoved: false }), readVerifierPublication: async () => null,
      registerCapabilitySet: async ({ registration }) => ({ capabilities: registration.capabilities, paymentMoved: false, registrationDigest: "c".repeat(64), releaseId: registration.releaseId, repositorySha: registration.repositorySha, requestDigest: "d".repeat(64), schema: "clockchain.bilateral-capability-registration-receipt/v1", sessionId: registration.sessionId }),
    }),
    createTransport: () => ({}),
  });
  const release = await loadOrCreateCoordinatorRelease(config, { runtime });

  await assert.rejects(runCoordinatorCore({ dependencies: runtime.runDependencies(release), release, releaseRoot: rootPath }));

  assert.equal(enrollmentReads, 1);
});

test("runtime rejects a substituted certificate before it trusts any private input", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "coordinator-runtime-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const certificatePath = join(root, "relay.pem"); const keyPath = join(root, "operator.pem");
  const tokenPath = join(root, "token"); const rpcPath = join(root, "rpc"); const releaseRoot = join(root, "release");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(root, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const pair = generateKeyPairSync("ed25519"); await writeFile(keyPath, pair.privateKey.export({ format: "pem", type: "pkcs8" })); await writeFile(tokenPath, "token"); await writeFile(rpcPath, "https://127.0.0.1/\n");
  await Promise.all([chmod(keyPath, 0o600), chmod(tokenPath, 0o600), chmod(rpcPath, 0o600)]);
  const fingerprint = createHash("sha256").update(new X509Certificate(await readFile(certificatePath, "utf8")).raw).digest("hex");
  const values = { ...VALUES, "--clockchain-token-file": tokenPath, "--operator-private-key": keyPath, "--release-root": releaseRoot, "--rpc-url-file": rpcPath, "--tls-certificate": certificatePath, "--tls-fingerprint": "0".repeat(64) };
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  await assert.rejects(readCoordinatorRuntimeConfig(values, { gitInspector: { head: "a".repeat(40), operatorKey: async () => publicKey } }));
  values["--tls-fingerprint"] = fingerprint;
  const config = await readCoordinatorRuntimeConfig(values, { gitInspector: { head: "a".repeat(40), operatorKey: async () => publicKey } });
  assert.equal(config.tlsFingerprint, fingerprint);
  const dnsConfig =
    await readCoordinatorRuntimeConfig(
      {
        ...values,
        "--release-root":
          join(root, "dns-release"),
        "--relay-url":
          "https://relay.example.test:8443",
      },
      {
        gitInspector: {
          head: "a".repeat(40),
          operatorKey: async () => publicKey,
        },
      },
    );
  assert.equal(
    dnsConfig.relayUrl,
    "https://relay.example.test:8443",
  );
  await dnsConfig.releaseRoot.handle.close();
  const runtime = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createTransport: () => ({}) });
  const originalNow = Date.now;
  Date.now = () => 1;
  try {
    await Promise.all([
      runtime.createReleaseDependencies.writeState({ state: { paymentMoved: false, state: "TEST-A" } }),
      runtime.createReleaseDependencies.writeState({ state: { paymentMoved: false, state: "TEST-B" } }),
    ]);
    await runtime.createReleaseDependencies.writeState({ state: { paymentMoved: false, state: "TEST-C" } });
  } finally { Date.now = originalNow; }
  await mkdir(join(releaseRoot, "child"), { mode: 0o700 });
  await rename(releaseRoot, `${releaseRoot}-replaced`);
  await mkdir(releaseRoot, { mode: 0o700 });
  await assert.rejects(runtime.createReleaseDependencies.writeState({ state: { paymentMoved: false, state: "REPLACED" } }));
  await config.releaseRoot.handle.close();
});

test("runtime re-normalizes an accepted RPC endpoint before immutable preflight work", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "coordinator-runtime-rpc-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const certificatePath = join(root, "relay.pem"); const keyPath = join(root, "operator.pem");
  const tokenPath = join(root, "token"); const rpcPath = join(root, "rpc"); const releaseRoot = join(root, "release");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(root, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const pair = generateKeyPairSync("ed25519");
  await Promise.all([
    writeFile(keyPath, pair.privateKey.export({ format: "pem", type: "pkcs8" })), writeFile(tokenPath, "token"), writeFile(rpcPath, "http://127.0.0.1:8545\n"),
  ]);
  await Promise.all([chmod(keyPath, 0o600), chmod(tokenPath, 0o600), chmod(rpcPath, 0o600)]);
  const fingerprint = createHash("sha256").update(new X509Certificate(await readFile(certificatePath, "utf8")).raw).digest("hex");
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  const provenanceCalls = [];
  const provenanceProvider = {
    async verify(input) {
      provenanceCalls.push(input);
      return {
        imageDigest: `sha256:${"b".repeat(64)}`,
        operatorPublicKey: publicKey,
        repositorySha: "a".repeat(40),
        sourceTreeSha256: "c".repeat(64),
      };
    },
  };
  const config = await readCoordinatorRuntimeConfig({ ...VALUES, "--clockchain-token-file": tokenPath, "--operator-private-key": keyPath, "--release-root": releaseRoot, "--rpc-url-file": rpcPath, "--tls-certificate": certificatePath, "--tls-fingerprint": fingerprint }, { provenanceProvider });
  t.after(() => config.releaseRoot.handle.close());
  assert.equal(config.rpcUrl, "http://127.0.0.1:8545/");
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({
      getArtifact: async () => Buffer.from("token commitment"),
      readEnrollmentSet: async () => Buffer.from("{}"),
      readEvents: async () => [
        { artifactDigest: "c".repeat(64), kind: "TOKEN_READY", role: "payer", subjectRun: "release" },
        { artifactDigest: "d".repeat(64), kind: "TOKEN_READY", role: "payee", subjectRun: "release" },
      ],
    }),
    createTransport: () => ({}),
    provenanceProvider,
    preflightMain: async (argv) => {
      const output = argv[argv.indexOf("--output") + 1];
      await writeFile(join(output, "probe-plan.json"), "{}", { mode: 0o600 });
    },
    validateArtifactWithFacts: async () => ({ facts: {} }),
    verifyCoordinationPreparationSet: async () => ({ participants: { payer: {}, payee: {} } }),
  });
  const bridges = runtime.runDependencies({ releaseId: "release-a", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" });
  const args = { enrollments: { payer: {}, payee: {} }, repositorySha: "a".repeat(40) };

  assert.deepEqual(await bridges.createPreflightPlan(args), Buffer.from("{}"));
  assert.equal(provenanceCalls.length >= 2, true);
  assert.deepEqual(provenanceCalls[0], {
    operatorKeyId: VALUES["--operator-key-id"],
    repositorySha: "a".repeat(40),
  });
  await writeFile(rpcPath, "http://127.0.0.1:8546\n");
  await assert.rejects(bridges.createPreflightPlan(args));
});

test("runtime source never carries the authorizing output literal", async () => {
  const source = await import("node:fs/promises").then(({ readFile }) => readFile(new URL("../src/bilateral/coordination/coordinator-runtime.mjs", import.meta.url), "utf8"));
  assert.equal(source.includes("AUTH" + "ORIZED"), false);
});

test("verifier child deadline escalates from TERM to KILL for an ignoring child", async () => {
  const started = Date.now();
  const result = await runChildWithDeadline([
    "-e",
    "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)",
  ], 20, 20);
  assert.equal(result, null);
  assert.ok(Date.now() - started < 1_000);
});

test("pinned verifier runner rejects a root replaced by a successful child", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-runner-")); await chmod(rootPath, 0o700);
  const before = await lstat(rootPath); const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const root = { before, handle, path: rootPath }; t.after(() => handle.close()); t.after(() => rm(rootPath, { force: true, recursive: true })); t.after(() => rm(`${rootPath}-old`, { force: true, recursive: true }));
  await assert.rejects(runPinnedVerifierChild(root, [], 1, async () => { await rename(rootPath, `${rootPath}-old`); await mkdir(rootPath, { mode: 0o700 }); return 0; }));
});

test("loaded coordinator state rejects a replaced pinned root", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-state-root-")); await chmod(rootPath, 0o700);
  const before = await lstat(rootPath); const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0)); const root = { before, handle, path: rootPath };
  t.after(() => handle.close()); t.after(() => rm(rootPath, { force: true, recursive: true })); t.after(() => rm(`${rootPath}-old`, { force: true, recursive: true }));
  await rename(rootPath, `${rootPath}-old`); await mkdir(rootPath, { mode: 0o700 });
  await assert.rejects(readCoordinatorState(root));
});

test("durable verifier context is canonical and rejects tampering after a fresh read", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "coordinator-context-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  t.after(() => rm(`${root}-replacement`, { recursive: true, force: true }));
  await chmod(root, 0o700); const before = await lstat(root); const handle = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const pinned = { before, handle, path: root };
  t.after(() => handle.close());
  const context = {
    descriptorDigest: "a".repeat(64), outputDirectory: join(root, "verifier", "rehearsal"),
    mandateDigest: "e".repeat(64),
    packageDigests: { payer: "b".repeat(64), payee: "c".repeat(64) }, paymentMoved: false,
    publicationDigest: "d".repeat(64), releaseId: "release-a", repositorySha: "e".repeat(40),
    requestDigest: "f".repeat(64),
    schema: "clockchain.bilateral-coordinator-verifier-context/v1", sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", subjectRun: "rehearsal",
  };
  await writeVerifierContext(pinned, "context.json", context);
  assert.deepEqual(await readVerifierContext(pinned, "context.json"), context);
  await writeFile(join(root, "context.json"), "{", { mode: 0o600 });
  await assert.rejects(readVerifierContext(pinned, "context.json"), /Coordinator startup failed safely/);
  await writeFile(join(root, "context.json"), `${JSON.stringify(context)}\n`, { mode: 0o600 });
  await assert.rejects(readVerifierContext(pinned, "context.json"));
  await rename(root, `${root}-replacement`); await mkdir(root, { mode: 0o700 });
  await assert.rejects(readVerifierContext(pinned, "context.json"));
});

test("a persisted COMPLETE release is reconciled by the real coordinator bridge before it is accepted", async () => {
  let calls = 0;
  const result = await runCoordinatorUntilComplete({ releaseRoot: "/release" }, {
    loadOrCreateRelease: async () => ({ paymentMoved: false, repositorySha: "a".repeat(40), state: "COMPLETE" }),
    runCoordinator: async () => { calls += 1; return { paymentMoved: false, repositorySha: "a".repeat(40), state: "COMPLETE" }; },
  });
  assert.equal(result.state, "COMPLETE");
  assert.equal(calls, 1);
  await assert.rejects(runCoordinatorUntilComplete({ releaseRoot: "/release" }, {
    loadOrCreateRelease: async () => ({ paymentMoved: false, state: "COMPLETE" }),
    runCoordinator: async () => ({ paymentMoved: false, state: "WAITING" }),
  }));
});

test("package staging exposes an exact-reuse seam for adversarial filesystem regressions", () => {
  assert.equal(typeof stagePackage, "function");
});

test("staging reuses only an exact complete private package", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-stage-"));
  await chmod(rootPath, 0o700);
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  t.after(() => rm(`${rootPath}-replaced`, { recursive: true, force: true }));
  const content = Buffer.from("fixture");
  const bytes = canonicalBytes({ files: [{ byteLength: String(content.length), contentBase64: content.toString("base64"), name: "result.json", sha256: createHash("sha256").update(content).digest("hex") }], paymentMoved: false, schema: "clockchain.bilateral-relay-package/v1" });
  const before = await lstat(rootPath); const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const root = { before, handle, path: rootPath };
  t.after(() => handle.close());
  const accept = async () => ({ facts: {} });
  const directory = await stagePackage(root, "package", "party-result-package", bytes, { validate: accept });
  assert.equal(await stagePackage(root, "package", "party-result-package", bytes, { validate: accept }), directory);
  await writeFile(join(directory, "extra"), "x", { mode: 0o600 });
  await assert.rejects(stagePackage(root, "package", "party-result-package", bytes, { validate: accept }));
  await mkdir(join(rootPath, "partial"), { mode: 0o700 });
  await assert.rejects(stagePackage(root, "partial", "party-result-package", bytes, { validate: accept }));
  for (const [name, create] of [
    ["symlink", async (directory_) => symlink(join(rootPath, "outside"), join(directory_, "result.json"))],
    ["hardlink", async (directory_) => link(join(rootPath, "outside"), join(directory_, "result.json"))],
  ]) {
    await writeFile(join(rootPath, "outside"), content, { mode: 0o600 });
    const hostile = join(rootPath, name); await mkdir(hostile, { mode: 0o700 }); await create(hostile);
    await assert.rejects(stagePackage(root, name, "party-result-package", bytes, { validate: accept }));
    await rm(join(rootPath, "outside"));
  }
  await rename(rootPath, `${rootPath}-replaced`); await mkdir(rootPath, { mode: 0o700 });
  await assert.rejects(stagePackage(root, "replacement", "party-result-package", bytes, { validate: accept }));
});

test("verifier package binding requires the exact role, repository, session, and address", () => {
  const descriptor = { payee: { address: "0x2222222222222222222222222222222222222222" }, payer: { address: "0x1111111111111111111111111111111111111111" } };
  const base = { repositorySha: "a".repeat(40), role: "payer", sessionDigest: "b".repeat(64), signature: { address: descriptor.payer.address } };
  assert.doesNotThrow(() => validateVerifierPackageBinding({ descriptor, party: base, repositorySha: "a".repeat(40), role: "payer", sessionDigest: "b".repeat(64) }));
  for (const change of [
    { role: "payee" }, { repositorySha: "c".repeat(40) }, { sessionDigest: "d".repeat(64) }, { signature: { address: descriptor.payee.address } },
  ]) assert.throws(() => validateVerifierPackageBinding({ descriptor, party: { ...base, ...change }, repositorySha: "a".repeat(40), role: "payer", sessionDigest: "b".repeat(64) }));
});

test("production verifier publication adoption does not run a coordinator verifier child", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-aws-verifier-"));
  await chmod(rootPath, 0o700);
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const certificatePath = join(rootPath, "relay.pem");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(rootPath, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tokenPath = join(rootPath, "token");
  const rpcPath = join(rootPath, "rpc");
  const operatorKeyPath = join(rootPath, "operator.pem");
  await writeFile(tokenPath, "clockchain-token", { mode: 0o600 });
  await writeFile(rpcPath, "https://127.0.0.1/\n", { mode: 0o600 });
  const pair = generateKeyPairSync("ed25519");
  const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  await writeFile(operatorKeyPath, privateKeyPem, { mode: 0o600 });
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  const release = {
    repositorySha: "a".repeat(40),
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
  };
  release.releaseId = `release-${createHash("sha256").update(release.sessionId, "utf8").digest("hex").slice(0, 16)}`;
  const mandateBytes = Buffer.from('{"mandate":{"paymentMoved":false}}\n');
  const requestBytes = Buffer.from('{"request":{"paymentMoved":false}}\n');
  const mandateDigest = createHash("sha256").update(mandateBytes).digest("hex");
  const requestDigest = createHash("sha256").update(requestBytes).digest("hex");
  const descriptor = {
    amountOptions: [{ currency: "USD", value: "100" }],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest,
    namespace: "cbv1",
    payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Billie", role: "payee" },
    payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Iris", role: "payer" },
    paymentMoved: false,
    promptSha256: "c".repeat(64),
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: release.repositorySha,
    requestDigest,
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: deriveDescriptorSessionId({ ...release, subjectRun: "stakeholder" }),
    settlement: "not-executed",
  };
  const descriptorBytes = canonicalBytes(createSignedEnvelope(descriptor, { keyId: "clockchain-demo-2026", privateKeyPem }));
  const descriptorDigest = createHash("sha256").update(descriptorBytes).digest("hex");
  const payerPackage = relayPackage("payer-result.json", Buffer.from("payer-result"));
  const payeePackage = relayPackage("payee-result.json", Buffer.from("payee-result"));
  const payerPackageDigest = createHash("sha256").update(payerPackage).digest("hex");
  const payeePackageDigest = createHash("sha256").update(payeePackage).digest("hex");
  const artifactByDigest = new Map([
    [descriptorDigest, descriptorBytes],
    [mandateDigest, mandateBytes],
    [requestDigest, requestBytes],
    [payerPackageDigest, payerPackage],
    [payeePackageDigest, payeePackage],
  ]);
  const evidenceDigest = createHash("sha256").update(canonicalBytes({
    descriptorDigest,
    mandateDigest: descriptor.mandateDigest,
    packageDigests: { payee: payeePackageDigest, payer: payerPackageDigest },
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    requestDigest: descriptor.requestDigest,
    sessionId: release.sessionId,
    subjectRun: "stakeholder",
  })).digest("hex");
  const coordinatorState = {
    capabilityDigests: ["1".repeat(64), "2".repeat(64)],
    checkpoints: [
      { action: "STAKEHOLDER_DESCRIPTOR", artifactDigest: descriptorDigest, eventDigest: "3".repeat(64), role: "operator", status: "EVENT_APPENDED", subjectRun: "stakeholder" },
      { action: "ROLE_PACKAGE", artifactDigest: payerPackageDigest, eventDigest: "4".repeat(64), role: "payer", status: "EVENT_APPENDED", subjectRun: "stakeholder" },
      { action: "ROLE_PACKAGE", artifactDigest: payeePackageDigest, eventDigest: "5".repeat(64), role: "payee", status: "EVENT_APPENDED", subjectRun: "stakeholder" },
    ],
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: release.sessionId,
    state: "STAKEHOLDER_PACKAGES_READY",
  };
  await writeFile(join(rootPath, "coordinator-state.json"), `${JSON.stringify(coordinatorState)}\n`, { mode: 0o600 });
  const publication = {
    attemptId: "11111111-1111-4111-8111-111111111111",
    evidenceDigest,
    paymentMoved: false,
    publicationDigest: "f".repeat(64),
    repositorySha: release.repositorySha,
    revision: 9,
    schema: "clockchain.aws-verifier-task-publication/v1",
    status: "VERIFICATION_PASSED",
    taskArn:
      "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111",
    writtenAtMs: "2000000000000",
  };
  const handoffs = [];
  const stagedEvidence = new Map();
  const localHandoffPath = join(rootPath, "aws-verifier-handoff-stakeholder.json");
  const expectedHandoffPath = `/var/lib/clockchain/operator/releases/${release.releaseId}/verifier-handoff-stakeholder.json`;
  const publishVerifierHandoff = async (input) => {
    assert.deepEqual(Reflect.ownKeys(input), ["evidence", "handoff", "path"]);
    assert.equal(input.path, expectedHandoffPath);
    assert.deepEqual(Reflect.ownKeys(input.evidence), [
      "descriptorBytes",
      "payeePackageBytes",
      "payerMandateBytes",
      "payerPackageBytes",
      "paymentRequestBytes",
    ]);
    assert.deepEqual(Reflect.ownKeys(input.handoff), [
      "descriptorDigest",
      "descriptorPath",
      "evidenceDigest",
      "mandateDigest",
      "payerMandatePath",
      "payeeResultsPath",
      "payerResultsPath",
      "paymentMoved",
      "paymentRequestPath",
      "publicationPath",
      "releaseId",
      "repositorySha",
      "requestDigest",
      "schema",
      "sessionDigest",
      "sessionId",
      "subjectRun",
    ]);
    const exactEvidence = [
      [input.handoff.descriptorPath, input.evidence.descriptorBytes, input.handoff.descriptorDigest],
      [input.handoff.payerMandatePath, input.evidence.payerMandateBytes, input.handoff.mandateDigest],
      [input.handoff.paymentRequestPath, input.evidence.paymentRequestBytes, input.handoff.requestDigest],
      [input.handoff.payerResultsPath, input.evidence.payerPackageBytes, payerPackageDigest],
      [input.handoff.payeeResultsPath, input.evidence.payeePackageBytes, payeePackageDigest],
    ];
    for (const [path, bytes, expectedDigest] of exactEvidence) {
      const prior = stagedEvidence.get(path);
      if (prior !== undefined && !prior.equals(bytes)) throw new Error(`changed evidence for ${path}`);
      assert.equal(createHash("sha256").update(bytes).digest("hex"), expectedDigest);
      stagedEvidence.set(path, Buffer.from(bytes));
    }
    const published = await publishAwsVerifierHandoff({
      path: localHandoffPath,
      handoff: input.handoff,
    });
    handoffs.push(input);
    return published;
  };
  const verdictValidations = [];
  const runtime = createCoordinatorRuntimeDependencies({
    clockchainToken: "clockchain-token",
    clockchainTokenPath: tokenPath,
    operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem, publicKey },
    operatorPrivateKeyPath: operatorKeyPath,
    operatorPublicKey: publicKey,
    releaseRoot: { before, handle, path: rootPath },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    rpcUrlPath: rpcPath,
    tlsCertificatePath: certificatePath,
    tlsCertificatePem,
    tlsFingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
  }, {
    createClient: () => ({
      getArtifact: async ({ digest }) => artifactByDigest.get(digest),
      readEvents: async () => [
        { artifactDigest: mandateDigest, kind: "PAYER_MANDATE_READY", role: "payer", subjectRun: "stakeholder" },
        { artifactDigest: requestDigest, kind: "PAYMENT_REQUEST_READY", role: "payee", subjectRun: "stakeholder" },
      ],
    }),
    createTransport: () => ({}),
    provenanceProvider: {
      async verify() {
        return {
          imageDigest: null,
          operatorPublicKey: publicKey,
          repositorySha: release.repositorySha,
          sourceTreeSha256: "1".repeat(64),
        };
      },
    },
    runVerifierChild: async () => assert.fail("coordinator must not run the local verifier child in AWS publication adoption"),
    publishVerifierHandoff,
    validateVerdictPublication: async (input) => {
      verdictValidations.push(input);
      return {
        publicationDigest: publication.publicationDigest,
        status: "VERIFICATION_PASSED",
      };
    },
    validateArtifactWithFacts: async ({ artifactType, bytes, expectedDigest }) => {
      assert.equal(createHash("sha256").update(bytes).digest("hex"), expectedDigest);
      if (artifactType === "signed-descriptor") return { facts: createSignedEnvelope(descriptor, { keyId: "clockchain-demo-2026", privateKeyPem }) };
      if (artifactType === "party-result-package") {
        return {
          facts: {
            partyResult: {
              paymentMoved: false,
              repositorySha: release.repositorySha,
              role: expectedDigest === payerPackageDigest ? "payer" : "payee",
              sessionDigest: dSession(descriptor),
              signature: { address: expectedDigest === payerPackageDigest ? descriptor.payer.address : descriptor.payee.address },
            },
          },
        };
      }
      return { facts: {} };
    },
    verifierPublication: publication,
  });
  const prepared = await runtime.runDependencies({ ...release, state: "STAKEHOLDER_PACKAGES_READY" }).prepareVerifierHandoff({
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    sessionId: release.sessionId,
    subjectRun: "stakeholder",
  });
  await assert.rejects(
    publishVerifierHandoff({
      ...handoffs[0],
      evidence: {
        ...handoffs[0].evidence,
        descriptorBytes: Buffer.from("changed descriptor bytes"),
      },
    }),
    /changed evidence/,
  );
  await assert.rejects(
    publishVerifierHandoff({
      ...handoffs[0],
      handoff: {
        ...handoffs[0].handoff,
        evidenceDigest: "e".repeat(64),
      },
    }),
    /AWS coordinator operator handoff failed safely/,
  );
  const adopted = await runtime.runDependencies({ ...release, state: "STAKEHOLDER_PACKAGES_READY" }).prepareVerifierHandoff({
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    sessionId: release.sessionId,
    subjectRun: "stakeholder",
  });
  assert.deepEqual(adopted, prepared);
  const result = await runtime.runDependencies(release).launchVerifier({
    descriptorDigest,
    outputDirectory: join(rootPath, "verifier", "stakeholder"),
    packageDigests: { payee: payeePackageDigest, payer: payerPackageDigest },
    subjectRun: "stakeholder",
  });
  assert.equal(result.result.publicationDigest, publication.publicationDigest);
  assert.equal(result.result.status, "VERIFICATION_PASSED");
  assert.equal(handoffs.length, 3);
  assert.deepEqual(handoffs[1].handoff, handoffs[0].handoff);
  assert.deepEqual(handoffs[2].handoff, handoffs[0].handoff);
  assert.equal(handoffs[0].path, `/var/lib/clockchain/operator/releases/${release.releaseId}/verifier-handoff-stakeholder.json`);
  assert.equal(handoffs[0].handoff.descriptorPath, `/var/lib/clockchain/evidence/releases/${release.releaseId}/stakeholder/descriptor.json`);
  assert.equal(handoffs[0].handoff.payerMandatePath, `/var/lib/clockchain/evidence/releases/${release.releaseId}/stakeholder/payer-mandate.json`);
  assert.equal(handoffs[0].handoff.paymentRequestPath, `/var/lib/clockchain/evidence/releases/${release.releaseId}/stakeholder/payment-request.json`);
  assert.equal(handoffs[0].handoff.payerResultsPath, `/var/lib/clockchain/evidence/releases/${release.releaseId}/stakeholder/payer-results`);
  assert.equal(handoffs[0].handoff.payeeResultsPath, `/var/lib/clockchain/evidence/releases/${release.releaseId}/stakeholder/payee-results`);
  assert.equal(handoffs[0].handoff.publicationPath, `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/stakeholder-publication.json`);
  assert.equal(handoffs[0].handoff.paymentMoved, false);
  assert.equal(handoffs[0].handoff.evidenceDigest, evidenceDigest);
  assert.deepEqual(verdictValidations, [{
    mandateDigest: descriptor.mandateDigest,
    outputDirectory: `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/11111111-1111-4111-8111-111111111111`,
    repositorySha: release.repositorySha,
    requestDigest: descriptor.requestDigest,
    sessionDigest: dSession(descriptor),
  }]);
});

test("restarted aws verifier context drives console state from the attempt output root", async (t) => {
  const rootPath = await mkdtemp(join(tmpdir(), "coordinator-aws-console-restart-"));
  await chmod(rootPath, 0o700);
  t.after(() => rm(rootPath, { recursive: true, force: true }));
  const certificatePath = join(rootPath, "relay.pem");
  await execFile("openssl", ["req", "-x509", "-newkey", "ed25519", "-keyout", join(rootPath, "relay.key"), "-out", certificatePath, "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"]);
  const tlsCertificatePem = await readFile(certificatePath, "utf8");
  const tokenPath = join(rootPath, "token");
  const rpcPath = join(rootPath, "rpc");
  const operatorKeyPath = join(rootPath, "operator.pem");
  await writeFile(tokenPath, "clockchain-token", { mode: 0o600 });
  await writeFile(rpcPath, "https://127.0.0.1/\n", { mode: 0o600 });
  const pair = generateKeyPairSync("ed25519");
  const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  await writeFile(operatorKeyPath, privateKeyPem, { mode: 0o600 });
  const before = await lstat(rootPath);
  const handle = await open(rootPath, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  t.after(() => handle.close());
  const release = {
    releaseId: "release-3f336b4ac8e4e682",
    repositorySha: "a".repeat(40),
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
  };
  const { mandateEnvelope, requestEnvelope } = await signedIntents({ repositorySha: release.repositorySha });
  const mandateBytes = canonicalBytes(mandateEnvelope);
  const requestBytes = canonicalBytes(requestEnvelope);
  const mandateArtifactDigest = createHash("sha256").update(mandateBytes).digest("hex");
  const requestArtifactDigest = createHash("sha256").update(requestBytes).digest("hex");
  const descriptor = {
    amountOptions: [{ currency: "USD", value: "100" }],
    chainId: "11155111",
    expirySeconds: "600",
    mandateDigest: payerMandateDigest(mandateEnvelope),
    namespace: "cbv1",
    payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Billie", role: "payee" },
    payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Iris", role: "payer" },
    paymentMoved: false,
    promptSha256: "c".repeat(64),
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha: release.repositorySha,
    requestDigest: paymentRequestDigest(requestEnvelope),
    schema: "clockchain.bilateral-session-descriptor/v2",
    sessionId: deriveDescriptorSessionId({ ...release, subjectRun: "stakeholder" }),
    settlement: "not-executed",
  };
  const descriptorBytes = canonicalBytes(createSignedEnvelope(descriptor, { keyId: "clockchain-demo-2026", privateKeyPem }));
  const descriptorDigest = createHash("sha256").update(descriptorBytes).digest("hex");
  const attemptId = "11111111-1111-4111-8111-111111111111";
  const attemptRoot = `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/${attemptId}`;
  const localFallback = join(rootPath, "verifier", "stakeholder");
  await mkdir(localFallback, { recursive: true, mode: 0o700 });
  await writeFile(join(localFallback, "bilateral-verdict.json"), '{"paymentMoved":false,"transitions":[]}\n', { mode: 0o600 });
  const context = {
    descriptorDigest,
    mandateDigest: descriptor.mandateDigest,
    outputDirectory: attemptRoot,
    packageDigests: { payee: "2".repeat(64), payer: "1".repeat(64) },
    paymentMoved: false,
    publicationDigest: "f".repeat(64),
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    requestDigest: descriptor.requestDigest,
    schema: "clockchain.bilateral-coordinator-verifier-context/v1",
    sessionId: release.sessionId,
    subjectRun: "stakeholder",
  };
  await writeVerifierContext({ before, handle, path: rootPath }, ".verifier-context-stakeholder.json", context);
  const verdict = {
    paymentMoved: false,
    transitions: [
      { blockHeight: "10", digest: "a".repeat(64), ledgerId: "00000000-0000-4000-8000-000000000001" },
      { blockHeight: "11", digest: "b".repeat(64), ledgerId: "00000000-0000-4000-8000-000000000002" },
      { blockHeight: "12", digest: "c".repeat(64), ledgerId: "00000000-0000-4000-8000-000000000003" },
    ],
  };
  const readerCalls = [];
  const publicStages = [];
  const readEventCalls = [];
  const validationCalls = [];
  const abortSignal = new AbortController().signal;
  const runtime = createCoordinatorRuntimeDependencies({
    clockchainToken: "clockchain-token",
    clockchainTokenPath: tokenPath,
    operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem, publicKey },
    operatorPrivateKeyPath: operatorKeyPath,
    operatorPublicKey: publicKey,
    releaseRoot: { before, handle, path: rootPath },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    rpcUrlPath: rpcPath,
    tlsCertificatePath: certificatePath,
    tlsCertificatePem,
    tlsFingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
  }, {
    abortSignal,
    createClient: () => ({
      getArtifact: async ({ artifactType, digest }) => {
        if (artifactType === "signed-descriptor" && digest === descriptorDigest) return descriptorBytes;
        if (artifactType === "payer-mandate" && digest === mandateArtifactDigest) return mandateBytes;
        if (artifactType === "payment-request" && digest === requestArtifactDigest) return requestBytes;
        return Buffer.from("{}\n");
      },
      readEvents: async (input) => {
        readEventCalls.push(input);
        return [
          { artifactDigest: mandateArtifactDigest, kind: "PAYER_MANDATE_READY", role: "payer", subjectRun: "stakeholder" },
          { artifactDigest: requestArtifactDigest, kind: "PAYMENT_REQUEST_READY", role: "payee", subjectRun: "stakeholder" },
          { artifactDigest: null, kind: "PAYMENT_REQUEST_MATCHED", role: "payer", subjectRun: "stakeholder" },
        ];
      },
    }),
    createTransport: () => ({}),
    now: () => 1_785_294_400_000,
    provenanceProvider: {
      async verify() {
        return {
          imageDigest: null,
          operatorPublicKey: publicKey,
          repositorySha: release.repositorySha,
          sourceTreeSha256: "1".repeat(64),
        };
      },
    },
    publicStager: {
      async stageSnapshot(input) {
        assert.match(
          await readFile(join(rootPath, "console-state.json"), "utf8"),
          /"state":"STAKEHOLDER_VERIFIED"/,
        );
        publicStages.push(input);
      },
    },
    readVerifierVerdictBytes: async ({ outputDirectory }) => {
      readerCalls.push(outputDirectory);
      assert.equal(outputDirectory, attemptRoot);
      assert.notEqual(outputDirectory, localFallback);
      return Buffer.from(`${JSON.stringify(verdict)}\n`);
    },
    sleeper: async () => {},
    validateArtifactWithFacts: async ({ artifactType }) => {
      if (artifactType === "signed-descriptor") return { facts: createSignedEnvelope(descriptor, { keyId: "clockchain-demo-2026", privateKeyPem }) };
      if (artifactType === "payer-mandate") return { facts: mandateEnvelope };
      if (artifactType === "payment-request") return { facts: requestEnvelope };
      return { facts: {} };
    },
    validateVerdictPublication: async (input) => {
      validationCalls.push(input);
      assert.equal(input.outputDirectory, attemptRoot);
      assert.notEqual(input.outputDirectory, localFallback);
      return {
        publicationDigest: context.publicationDigest,
        status: "VERIFICATION_PASSED",
      };
    },
    watchBilateralSession: async ({ output }) => {
      output({
        paymentMoved: false,
        state: "ACKNOWLEDGED",
        terminal: null,
        transitions: [
          { blockHeight: "10", cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000001", slot: "proposal", verified: true },
          { blockHeight: "11", cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000002", slot: "acceptance", verified: true },
          { blockHeight: "12", cardinality: "1", ledgerId: "00000000-0000-4000-8000-000000000003", slot: "acknowledgment", verified: true },
        ],
      });
    },
  });
  await runtime.runDependencies({ ...release, state: "STAKEHOLDER_VERIFIED" }).writeConsoleState({
    lifecycleView: {
      paymentMoved: false,
      releaseId: release.releaseId,
      repositorySha: release.repositorySha,
      sessionId: release.sessionId,
      state: "STAKEHOLDER_VERIFIED",
    },
    subjectRun: "stakeholder",
  });
  assert.deepEqual(readerCalls, [attemptRoot]);
  assert.deepEqual(readEventCalls, [
    { after: null, signal: abortSignal, waitMs: 30_000 },
    { after: null, signal: abortSignal, waitMs: 30_000 },
    { after: null, signal: abortSignal, waitMs: 0 },
  ]);
  assert.deepEqual(validationCalls.map((call) => call.outputDirectory), [attemptRoot]);
  assert.equal(publicStages.length, 1);
  assert.equal(publicStages[0].completedAtMs, 1_785_294_400_000);
  assert.equal(publicStages[0].nowMs, 1_785_294_400_000);
  assert.equal(publicStages[0].verifierPublicationValidated, true);
  assert.equal(publicStages[0].snapshot.runStatus, "VERIFIED");
  assert.equal(publicStages[0].snapshot.verifier.status, "VERIFIED");
  assert.deepEqual(
    publicStages[0].snapshot.anchors.map(({ explorerUrl }) => explorerUrl),
    [
      "https://sepolia.etherscan.io/block/10",
      "https://sepolia.etherscan.io/block/11",
      "https://sepolia.etherscan.io/block/12",
    ],
  );

  const badContext = {
    ...context,
    outputDirectory: `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/not-a-uuid`,
  };
  await writeVerifierContext({ before, handle, path: rootPath }, ".verifier-context-stakeholder.json", badContext);
  const nonStringContext = {
    ...context,
    outputDirectory: 123,
  };
  await writeFile(
    join(rootPath, ".verifier-context-stakeholder.json"),
    `${JSON.stringify(nonStringContext)}\n`,
    { mode: 0o600 },
  );
  let typeErrorReaderCalled = false;
  await assert.rejects(
    runtime.runDependencies({ ...release, state: "STAKEHOLDER_VERIFIED" }).writeConsoleState({
      lifecycleView: {
        paymentMoved: false,
        releaseId: release.releaseId,
        repositorySha: release.repositorySha,
        sessionId: release.sessionId,
        state: "STAKEHOLDER_VERIFIED",
      },
      subjectRun: "stakeholder",
    }),
    /Coordinator startup failed safely/,
  );
  assert.equal(typeErrorReaderCalled, false);
  await writeVerifierContext({ before, handle, path: rootPath }, ".verifier-context-stakeholder.json", badContext);
  let badReaderCalled = false;
  const restartedBadRuntime = createCoordinatorRuntimeDependencies({
    clockchainToken: "clockchain-token",
    clockchainTokenPath: tokenPath,
    operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem, publicKey },
    operatorPrivateKeyPath: operatorKeyPath,
    operatorPublicKey: publicKey,
    releaseRoot: { before, handle, path: rootPath },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    rpcUrlPath: rpcPath,
    tlsCertificatePath: certificatePath,
    tlsCertificatePem,
    tlsFingerprint: createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex"),
  }, {
    createClient: () => ({ getArtifact: async () => descriptorBytes }),
    createTransport: () => ({}),
    readVerifierVerdictBytes: async () => {
      badReaderCalled = true;
      return Buffer.from(`${JSON.stringify(verdict)}\n`);
    },
    validateArtifactWithFacts: async () => ({ facts: createSignedEnvelope(descriptor, { keyId: "clockchain-demo-2026", privateKeyPem }) }),
    validateVerdictPublication: async () => assert.fail("wrong attempt root must fail before publication validation"),
  });
  await assert.rejects(
    restartedBadRuntime.runDependencies({ ...release, state: "STAKEHOLDER_VERIFIED" }).writeConsoleState({
      lifecycleView: {
        paymentMoved: false,
        releaseId: release.releaseId,
        repositorySha: release.repositorySha,
        sessionId: release.sessionId,
        state: "STAKEHOLDER_VERIFIED",
      },
      subjectRun: "stakeholder",
    }),
    /Coordinator startup failed safely/,
  );
  assert.equal(badReaderCalled, false);
});

test("watcher lifecycle starts once, emits bounded observation, and surfaces failure", async () => {
  const output = []; let calls = 0;
  const watcher = createWatcherLifecycle({ run: async () => { calls += 1; return { paymentMoved: false, terminal: null }; } });
  await watcher.start("rehearsal"); await watcher.start("rehearsal");
  assert.equal(calls, 1); assert.deepEqual(output, []); assert.doesNotThrow(() => watcher.assertHealthy("rehearsal"));
  const failing = createWatcherLifecycle({ run: async () => { throw new Error("watch failed"); } });
  await failing.start("stakeholder");
  assert.throws(() => failing.assertHealthy("stakeholder"));
  const terminal = createWatcherLifecycle({ run: async () => ({ paymentMoved: false, terminal: "DUPLICATE" }) });
  await terminal.start("rehearsal");
  assert.throws(() => terminal.assertHealthy("rehearsal"));
});

test("watcher boundary forwards only bounded canonical secret-free snapshots", () => {
  const snapshot = { paymentMoved: false, status: "WAITING" };
  assert.equal(watcherLine(snapshot, "token-canary"), '{"paymentMoved":false,"status":"WAITING"}\n');
  for (const hostile of [{ nested: { paymentMoved: false } }, { paymentMoved: false, text: "token-canary" }, { paymentMoved: false, text: "authorized" }, { paymentMoved: false, text: "x".repeat(20_000) }]) assert.throws(() => watcherLine(hostile, "token-canary"));
  assert.throws(() => watcherLine({ paymentMoved: false, text: 'token"canary' }, 'token"canary'));
});

test("production watcher forwarding rejects a role event after an in-flight watcher failure", async () => {
  let resolveEvents; let rejectWatcher; const output = [];
  const eventGate = new Promise((resolve) => { resolveEvents = resolve; });
  const watcherGate = new Promise((resolve, reject) => { rejectWatcher = reject; });
  const digest = "a".repeat(64);
  const client = { getArtifact: async () => Buffer.from("descriptor"), readEvents: async () => eventGate };
  const config = { clockchainToken: "token-canary", operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }, operatorPublicKey: "public", releaseRoot: { path: "/release" }, repositorySha: "b".repeat(40), relayUrl: "https://127.0.0.1:8443", rpcUrl: "https://127.0.0.1/", tlsCertificatePem: "certificate", tlsFingerprint: "c".repeat(64) };
  const runtime = createCoordinatorRuntimeDependencies(config, { validateArtifactWithFacts: async () => ({ facts: { descriptor: {} } }), createClient: () => client, createTransport: () => ({}), now: () => 0, sleeper: async () => {}, watcherOutput: (line) => output.push(line), watchBilateralSession: async ({ output: emit }) => { emit({ paymentMoved: false, status: "WAITING" }); await watcherGate; } });
  const bridges = runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" });
  await bridges.startWatcher({ descriptorDigest: digest, subjectRun: "rehearsal" });
  assert.deepEqual(output, ['{"paymentMoved":false,"status":"WAITING"}\n']);
  const waiting = bridges.waitForRoleStarted({ role: "payee", subjectRun: "rehearsal" });
  rejectWatcher(new Error("watch failed"));
  resolveEvents([{ artifactDigest: null, kind: "ROLE_STARTED", role: "payee", subjectRun: "rehearsal" }]);
  await assert.rejects(waiting);
});

test("runtime cancels and drains an active watcher when a later coordinator operation fails", async () => {
  let signalStarted; let cancelled = false;
  const watcherStarted = new Promise((resolve_) => { signalStarted = resolve_; });
  const digest = "a".repeat(64);
  const client = { getArtifact: async () => Buffer.from("descriptor") };
  const config = { clockchainToken: "token-canary", operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }, operatorPublicKey: "public", releaseRoot: { path: "/release" }, repositorySha: "b".repeat(40), relayUrl: "https://127.0.0.1:8443", rpcUrl: "https://127.0.0.1/", tlsCertificatePem: "certificate", tlsFingerprint: "c".repeat(64) };
  const runtime = createCoordinatorRuntimeDependencies(config, {
    validateArtifactWithFacts: async () => ({ facts: { descriptor: {} } }), createClient: () => client, createTransport: () => ({}), now: () => 0, sleeper: async () => {},
    watchBilateralSession: ({ signal }) => new Promise((resolve_) => {
      signalStarted();
      signal.addEventListener("abort", () => { cancelled = true; resolve_({ paymentMoved: false, terminal: null }); }, { once: true });
    }),
  });
  const release = { releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", state: "RUNNING" };
  const bridges = runtime.runDependencies(release);
  await bridges.startWatcher({ descriptorDigest: digest, subjectRun: "rehearsal" });
  await watcherStarted;
  await assert.rejects(runCoordinatorUntilComplete(config, {
    loadOrCreateRelease: async () => release,
    runCoordinator: async () => { throw new Error("later coordinator operation failed"); },
    runtime: { runDependencies: () => bridges },
  }), /later coordinator operation failed/);
  assert.equal(cancelled, true);
});

test("bundled watcher cancellation clears its referenced timer before a failing coordinator exits", async () => {
  const runtimeUrl = new URL("../src/bilateral/coordination/coordinator-runtime.mjs", import.meta.url).href;
  const script = `
    import { createCoordinatorRuntimeDependencies, runCoordinatorUntilComplete } from ${JSON.stringify(runtimeUrl)};
    const config = { clockchainToken: "timer-canary", operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }, operatorPublicKey: "public", releaseRoot: { path: "/release" }, repositorySha: "b".repeat(40), relayUrl: "https://127.0.0.1:8443", rpcUrl: "https://127.0.0.1/", tlsCertificatePem: "certificate", tlsFingerprint: "c".repeat(64) };
    const descriptor = { amountOptions: [{ currency: "USD", value: "100" }], chainId: "11155111", expirySeconds: "600", mandateDigest: "c".repeat(64), namespace: "cbv1", payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Billie", role: "payee" }, payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Iris", role: "payer" }, paymentMoved: false, promptSha256: "a".repeat(64), protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1", registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e", repositorySha: config.repositorySha, requestDigest: "d".repeat(64), schema: "clockchain.bilateral-session-descriptor/v2", sessionId: "00112233445566778899aabbccddeeff", settlement: "not-executed" };
    let emitted;
    const output = new Promise((resolve_) => { emitted = resolve_; });
    const runtime = createCoordinatorRuntimeDependencies(config, { validateArtifactWithFacts: async () => ({ facts: { descriptor } }), createClient: () => ({ getArtifact: async () => Buffer.from("descriptor") }), createTransport: () => ({}), createWatcherClient: ({ signal }) => ({ getBlock: async () => [], resolveAgent: async () => [], searchActions: async () => [], verifyCrossParty: async () => { if (signal.aborted) throw new Error("aborted"); return {}; } }), now: () => 0, watcherOutput: () => emitted() });
    const release = { releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", state: "RUNNING" };
    const bridges = runtime.runDependencies(release);
    await bridges.startWatcher({ descriptorDigest: "a".repeat(64), subjectRun: "rehearsal" });
    await output;
    await runCoordinatorUntilComplete(config, { loadOrCreateRelease: async () => release, runCoordinator: async () => { throw new Error("later failure"); }, runtime: { runDependencies: () => bridges } }).catch(() => {});
    if (process.getActiveResourcesInfo().includes("Timeout")) process.exitCode = 1;
  `;
  await execFile(process.execPath, ["--input-type=module", "--eval", script], { timeout: 1_000 });
});

test("default MCP watcher fetch composes finalizer and timeout signals without retrying after abort", async (t) => {
  const originalAny = AbortSignal.any; let capturedSignals; let fetchSignal; let fetchStarted; let fetches = 0; let outputs = 0;
  const started = new Promise((resolve_) => { fetchStarted = resolve_; });
  AbortSignal.any = (signals) => { capturedSignals = [...signals]; return originalAny(signals); };
  t.after(() => { AbortSignal.any = originalAny; });
  const config = { clockchainToken: "mcp-watch-token", operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }, operatorPublicKey: "public", releaseRoot: { path: "/release" }, repositorySha: "b".repeat(40), relayUrl: "https://127.0.0.1:8443", rpcUrl: "https://127.0.0.1/", tlsCertificatePem: "certificate", tlsFingerprint: "c".repeat(64) };
  const descriptor = { amountOptions: [{ currency: "USD", value: "100" }], chainId: "11155111", expirySeconds: "600", mandateDigest: "c".repeat(64), namespace: "cbv1", payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Billie", role: "payee" }, payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Iris", role: "payer" }, paymentMoved: false, promptSha256: "a".repeat(64), protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1", registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e", repositorySha: config.repositorySha, requestDigest: "d".repeat(64), schema: "clockchain.bilateral-session-descriptor/v2", sessionId: "00112233445566778899aabbccddeeff", settlement: "not-executed" };
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({ getArtifact: async () => Buffer.from("descriptor") }), createTransport: () => ({}), validateArtifactWithFacts: async () => ({ facts: { descriptor } }), watcherOutput: () => { outputs += 1; },
    watcherFetch: async (_url, init) => {
      fetches += 1; fetchSignal = init.signal; fetchStarted();
      return new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
    },
  });
  const release = { releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd", state: "RUNNING" };
  const bridges = runtime.runDependencies(release);
  await bridges.startWatcher({ descriptorDigest: "a".repeat(64), subjectRun: "rehearsal" });
  await started;
  await assert.rejects(runCoordinatorUntilComplete(config, { loadOrCreateRelease: async () => release, runCoordinator: async () => { throw new Error("later coordinator failure"); }, runtime: { runDependencies: () => bridges } }), /later coordinator failure/);
  assert.equal(fetches, 1);
  assert.equal(outputs, 0);
  assert.equal(capturedSignals.length, 2);
  assert.notEqual(capturedSignals[0], capturedSignals[1]);
  assert.notEqual(fetchSignal, capturedSignals[0]);
  assert.notEqual(fetchSignal, capturedSignals[1]);
  assert.equal(capturedSignals[0].aborted, true);
  assert.equal(capturedSignals[1].aborted, false);
  assert.equal(fetchSignal.aborted, true);
});

test("stakeholder watcher progress is staged publicly before raw watcher output continues", async () => {
  const digest = "a".repeat(64);
  const release = {
    releaseId: "release-0123456789abcdef",
    repositorySha: "b".repeat(40),
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    state: "RUNNING",
  };
  const calls = [];
  let finished;
  const done = new Promise((resolve_) => {
    finished = resolve_;
  });
  const config = {
    clockchainToken: "token-canary",
    operatorIdentity: {
      keyId: "clockchain-demo-2026",
      privateKeyPem: "private",
      publicKey: "public",
    },
    operatorPublicKey: "public",
    releaseRoot: { path: "/release" },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "c".repeat(64),
  };
  const runtime = createCoordinatorRuntimeDependencies(config, {
    createClient: () => ({
      getArtifact: async () => Buffer.from("descriptor"),
    }),
    createTransport: () => ({}),
    now: () => 2_000_000_000_000,
    publicStager: {
      async stageSnapshot(input) {
        calls.push(["stage", input]);
      },
    },
    validateArtifactWithFacts: async () => ({
      facts: { descriptor: {} },
    }),
    watcherOutput: () => {
      calls.push(["raw-output"]);
    },
    watchBilateralSession: async ({ output }) => {
      await output({
        paymentMoved: false,
        state: "ACCEPTED",
        terminal: null,
        transitions: [
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: "00000000-0000-4000-8000-000000000001",
            slot: "proposal",
            verified: true,
          },
          {
            blockHeight: "102",
            cardinality: "1",
            ledgerId: "00000000-0000-4000-8000-000000000002",
            slot: "acceptance",
            verified: true,
          },
          {
            blockHeight: null,
            cardinality: "0",
            ledgerId: null,
            slot: "acknowledgment",
            verified: false,
          },
        ],
      });
      calls.push(["watcher-continued"]);
      finished();
      return { paymentMoved: false, terminal: null };
    },
  });
  const bridges = runtime.runDependencies(release);

  await bridges.startWatcher({
    descriptorDigest: digest,
    subjectRun: "stakeholder",
  });
  await done;

  assert.equal(calls[0][0], "stage");
  assert.equal(calls[1][0], "raw-output");
  assert.equal(calls[2][0], "watcher-continued");
  assert.deepEqual(calls[0][1], {
    completedAtMs: null,
    nowMs: 2_000_000_000_000,
    snapshot: {
      anchors: [
        {
          block: "101",
          explorerUrl: "https://sepolia.etherscan.io/block/101",
          kind: "PROPOSED",
          signerRole: "Payer",
        },
        {
          block: "102",
          explorerUrl: "https://sepolia.etherscan.io/block/102",
          kind: "ACCEPTED",
          signerRole: "Requestor",
        },
      ],
      currentStep:
        "The Payer is reviewing the Requestor acceptance before acknowledgment.",
      funding: { status: "READY" },
      mcp: { status: "READY" },
      paymentMoved: false,
      payer: { status: "READY" },
      publishedAtMs: "2000000000000",
      relay: { status: "READY" },
      requestor: { status: "READY" },
      runId: "run-0123456789abcdef",
      runStatus: "RUNNING",
      schema: "clockchain.bilateral-public-monitor/v2",
      staleAfterMs: 60_000,
      verifier: { status: "NOT_STARTED" },
    },
    verifierPublicationValidated: false,
  });
});

test("rehearsal watcher progress remains private even when a public stager exists", async () => {
  const release = {
    releaseId: "release-0123456789abcdef",
    repositorySha: "b".repeat(40),
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    state: "RUNNING",
  };
  const calls = [];
  let finished;
  const done = new Promise((resolve_) => {
    finished = resolve_;
  });
  const runtime = createCoordinatorRuntimeDependencies({
    clockchainToken: "token-canary",
    operatorIdentity: {
      keyId: "clockchain-demo-2026",
      privateKeyPem: "private",
      publicKey: "public",
    },
    operatorPublicKey: "public",
    releaseRoot: { path: "/release" },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "c".repeat(64),
  }, {
    createClient: () => ({
      getArtifact: async () => Buffer.from("descriptor"),
    }),
    createTransport: () => ({}),
    now: () => 2_000_000_000_000,
    publicStager: {
      async stageSnapshot(input) {
        calls.push(["stage", input]);
      },
    },
    validateArtifactWithFacts: async () => ({
      facts: { descriptor: {} },
    }),
    watcherOutput: () => {
      calls.push(["raw-output"]);
    },
    watchBilateralSession: async ({ output }) => {
      await output({
        paymentMoved: false,
        state: "PROPOSED",
        terminal: null,
        transitions: [
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: "00000000-0000-4000-8000-000000000001",
            slot: "proposal",
            verified: true,
          },
          {
            blockHeight: null,
            cardinality: "0",
            ledgerId: null,
            slot: "acceptance",
            verified: false,
          },
          {
            blockHeight: null,
            cardinality: "0",
            ledgerId: null,
            slot: "acknowledgment",
            verified: false,
          },
        ],
      });
      finished();
      return { paymentMoved: false, terminal: null };
    },
  });

  await runtime.runDependencies(release).startWatcher({
    descriptorDigest: "a".repeat(64),
    subjectRun: "rehearsal",
  });
  await done;

  assert.deepEqual(calls, [["raw-output"]]);
});

test("public staging rejection fails closed before raw watcher output is emitted", async () => {
  const release = {
    releaseId: "release-0123456789abcdef",
    repositorySha: "b".repeat(40),
    sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd",
    state: "RUNNING",
  };
  let stageAttempted;
  const staged = new Promise((resolve_) => {
    stageAttempted = resolve_;
  });
  let rawOutputCalled = false;
  const runtime = createCoordinatorRuntimeDependencies({
    clockchainToken: "token-canary",
    operatorIdentity: {
      keyId: "clockchain-demo-2026",
      privateKeyPem: "private",
      publicKey: "public",
    },
    operatorPublicKey: "public",
    releaseRoot: { path: "/release" },
    repositorySha: release.repositorySha,
    relayUrl: "https://127.0.0.1:8443",
    rpcUrl: "https://127.0.0.1/",
    tlsCertificatePem: "certificate",
    tlsFingerprint: "c".repeat(64),
  }, {
    createClient: () => ({
      getArtifact: async () => Buffer.from("descriptor"),
    }),
    createTransport: () => ({}),
    now: () => 2_000_000_000_000,
    publicStager: {
      async stageSnapshot() {
        stageAttempted();
        throw new Error("stage rejected");
      },
    },
    validateArtifactWithFacts: async () => ({
      facts: { descriptor: {} },
    }),
    watcherOutput: () => {
      rawOutputCalled = true;
    },
    watchBilateralSession: async ({ output }) => {
      await output({
        paymentMoved: false,
        state: "PROPOSED",
        terminal: null,
        transitions: [
          {
            blockHeight: "101",
            cardinality: "1",
            ledgerId: "00000000-0000-4000-8000-000000000001",
            slot: "proposal",
            verified: true,
          },
          {
            blockHeight: null,
            cardinality: "0",
            ledgerId: null,
            slot: "acceptance",
            verified: false,
          },
          {
            blockHeight: null,
            cardinality: "0",
            ledgerId: null,
            slot: "acknowledgment",
            verified: false,
          },
        ],
      });
      return { paymentMoved: false, terminal: null };
    },
  });
  const bridges = runtime.runDependencies(release);

  await bridges.startWatcher({
    descriptorDigest: "a".repeat(64),
    subjectRun: "stakeholder",
  });
  await staged;
  await new Promise((resolve_) => setImmediate(resolve_));

  assert.equal(rawOutputCalled, false);
  await assert.rejects(
    bridges.waitForRoleStarted({
      role: "payer",
      subjectRun: "stakeholder",
    }),
    /Coordinator startup failed safely/,
  );
});

test("pinned descriptor envelope requires the exact Git operator and derived run binding", () => {
  const pair = generateKeyPairSync("ed25519");
  const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  const pins = { keyId: "clockchain-demo-2026", publicKey, repositorySha: "a".repeat(40), sessionId: "b".repeat(32) };
  const descriptor = { amountOptions: [{ currency: "USD", value: "100" }, { currency: "USD", value: "250" }], chainId: "11155111", expirySeconds: "600", mandateDigest: "b".repeat(64), namespace: "cbv1", payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Iris", role: "payee" }, payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Billy", role: "payer" }, paymentMoved: false, promptSha256: "c".repeat(64), protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1", registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e", repositorySha: pins.repositorySha, requestDigest: "c".repeat(64), schema: "clockchain.bilateral-session-descriptor/v2", sessionId: pins.sessionId, settlement: "not-executed" };
  const signed = (overrides = {}, key = privateKeyPem, keyId = pins.keyId) => createSignedEnvelope({ ...descriptor, ...overrides }, { keyId, privateKeyPem: key });
  assert.doesNotThrow(() => validatePinnedDescriptorEnvelope(signed(), pins));
  const other = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" });
  for (const hostile of [signed({}, other), signed({}, privateKeyPem, "other-key"), signed({ repositorySha: "d".repeat(40) }), signed({ sessionId: "e".repeat(32) })]) assert.throws(() => validatePinnedDescriptorEnvelope(hostile, pins));
});

test("coordinator descriptor derives amount and intent digests only from verified envelopes", async () => {
  const input = { ...(await signedIntents({ amount: "250" })), nowMs: INTENT_NOW_MS, promptSha256: "a".repeat(64), repositorySha: "b".repeat(40), sessionId: "c".repeat(32) };
  const mismatchedIntake = await signedIntents({ amount: "250", requestOverrides: { intakeDigest: "c".repeat(64) } });
  const descriptor = await createCoordinatorDescriptor(input);
  assert.deepEqual(descriptor.amountOptions.map((amount) => Object.fromEntries(Object.entries(amount))), [{ currency: "USD", value: "250" }]);
  assert.equal(descriptor.mandateDigest, payerMandateDigest(input.mandateEnvelope));
  assert.notEqual(descriptor.requestDigest, input.mandateEnvelope.mandate.requestEndpoint);
  for (const hostile of [
    { ...input, mandateEnvelope: undefined },
    { ...input, requestEnvelope: undefined },
    { ...input, requestEnvelope: mismatchedIntake.requestEnvelope },
    { ...input, requestEnvelope: { ...input.requestEnvelope, request: { ...input.requestEnvelope.request, amount: { currency: "USD", value: "251" } } } },
    { ...input, repositorySha: "c".repeat(40) },
    { ...input, parties: { ...input.parties, payer: { ...input.parties.payer, agentId: "999" } } },
    { ...input, nowMs: 1785297600000 },
  ]) await assert.rejects(createCoordinatorDescriptor(hostile));
});
