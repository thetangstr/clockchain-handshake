import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, X509Certificate } from "node:crypto";
import { constants } from "node:fs";
import { chmod, link, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { execFile as execFileCallback } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { promisify } from "node:util";

import {
  COORDINATOR_CLI_FLAGS,
  createCoordinatorRuntimeDependencies,
  deriveDescriptorSessionId,
  loadOrCreateCoordinatorRelease,
  parseCoordinatorArguments,
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
import { createSignedEnvelope, rawPublicKeyBase64FromPem } from "../src/bilateral/descriptor.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { runCoordinator as runCoordinatorCore } from "../src/bilateral/coordination/coordinator.mjs";

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
  const addresses = [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
  ];
  const output = [];
  const runtime = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createTransport: () => ({}), output: (line) => output.push(line) });
  await runtime.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(addresses);
  const path = join(rootPath, "funding-addresses.json");
  const bytes = await readFile(path);
  assert.equal((await lstat(path)).mode & 0o777, 0o600);
  assert.equal(bytes.toString("utf8"), `${JSON.stringify({ addresses, paymentMoved: false, schema: "clockchain.bilateral-funding-addresses/v1" })}\n`);
  assert.deepEqual(output, [bytes.toString("utf8")]);

  const restartOutput = [];
  const restarted = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createTransport: () => ({}), output: (line) => restartOutput.push(line) });
  await restarted.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses(addresses);
  assert.equal((await readFile(path)).equals(bytes), true);
  assert.deepEqual(restartOutput, [bytes.toString("utf8")]);

  const hostile = createCoordinatorRuntimeDependencies(config, { createClient: () => ({}), createTransport: () => ({}) });
  await assert.rejects(hostile.runDependencies({ releaseId: "release-a", repositorySha: config.repositorySha, sessionId: "8f953393-86d0-4f99-9d6a-102f525fbecd" }).displayAddresses([...addresses].reverse()));
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
    relayUrl: "https://127.0.0.1:8443",
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
  });

  const release = await loadOrCreateCoordinatorRelease(config, { runtime });

  assert.equal(release.state, "BOOTSTRAPPING");
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
    relayUrl: "https://127.0.0.1:8443",
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
  const config = await readCoordinatorRuntimeConfig({ ...VALUES, "--clockchain-token-file": tokenPath, "--operator-private-key": keyPath, "--release-root": releaseRoot, "--rpc-url-file": rpcPath, "--tls-certificate": certificatePath, "--tls-fingerprint": fingerprint }, { gitInspector: { head: "a".repeat(40), operatorKey: async () => publicKey } });
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
    gitInspector: { head: "a".repeat(40), operatorKey: async () => publicKey },
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
    packageDigests: { payer: "b".repeat(64), payee: "c".repeat(64) }, paymentMoved: false,
    publicationDigest: "d".repeat(64), releaseId: "release-a", repositorySha: "e".repeat(40),
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
    import { createCoordinatorDescriptor, createCoordinatorRuntimeDependencies, runCoordinatorUntilComplete } from ${JSON.stringify(runtimeUrl)};
    const config = { clockchainToken: "timer-canary", operatorIdentity: { keyId: "clockchain-demo-2026", privateKeyPem: "private", publicKey: "public" }, operatorPublicKey: "public", releaseRoot: { path: "/release" }, repositorySha: "b".repeat(40), relayUrl: "https://127.0.0.1:8443", rpcUrl: "https://127.0.0.1/", tlsCertificatePem: "certificate", tlsFingerprint: "c".repeat(64) };
    const descriptor = createCoordinatorDescriptor({ parties: { payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Billy", role: "payer" }, payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Iris", role: "payee" } }, promptSha256: "a".repeat(64), repositorySha: config.repositorySha, sessionId: "00112233445566778899aabbccddeeff" });
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
  const descriptor = createCoordinatorDescriptor({ parties: { payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Billy", role: "payer" }, payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Iris", role: "payee" } }, promptSha256: "a".repeat(64), repositorySha: config.repositorySha, sessionId: "00112233445566778899aabbccddeeff" });
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

test("pinned descriptor envelope requires the exact Git operator and derived run binding", () => {
  const pair = generateKeyPairSync("ed25519");
  const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const publicKey = rawPublicKeyBase64FromPem(pair.publicKey.export({ format: "pem", type: "spki" }));
  const pins = { keyId: "clockchain-demo-2026", publicKey, repositorySha: "a".repeat(40), sessionId: "b".repeat(32) };
  const descriptor = { amountOptions: [{ currency: "USD", value: "100" }, { currency: "USD", value: "250" }], chainId: "11155111", expirySeconds: "600", namespace: "cbv1", payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Iris", role: "payee" }, payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Billy", role: "payer" }, paymentMoved: false, promptSha256: "c".repeat(64), protocol: "clockchain.bilateral-authorization/v1", protocolVersion: "1", registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e", repositorySha: pins.repositorySha, schema: "clockchain.bilateral-session-descriptor/v1", sessionId: pins.sessionId, settlement: "not-executed" };
  const signed = (overrides = {}, key = privateKeyPem, keyId = pins.keyId) => createSignedEnvelope({ ...descriptor, ...overrides }, { keyId, privateKeyPem: key });
  assert.doesNotThrow(() => validatePinnedDescriptorEnvelope(signed(), pins));
  const other = generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" });
  for (const hostile of [signed({}, other), signed({}, privateKeyPem, "other-key"), signed({ repositorySha: "d".repeat(40) }), signed({ sessionId: "e".repeat(32) })]) assert.throws(() => validatePinnedDescriptorEnvelope(hostile, pins));
});

test("coordinator descriptor permits exactly the USD 100 option", () => {
  const parties = { payer: { address: "0x00112233445566778899aabbccddeeff00112233", agentId: "8677", displayName: "Billy", role: "payer" }, payee: { address: "0xffeeddccbbaa99887766554433221100ffeeddcc", agentId: "8678", displayName: "Iris", role: "payee" } };
  const descriptor = createCoordinatorDescriptor({ parties, promptSha256: "a".repeat(64), repositorySha: "b".repeat(40), sessionId: "c".repeat(32) });
  assert.deepEqual(descriptor.amountOptions, [{ currency: "USD", value: "100" }]);
  assert.throws(() => createCoordinatorDescriptor({ parties: {}, promptSha256: "a".repeat(64), repositorySha: "b".repeat(40), sessionId: "c".repeat(32) }));
});
