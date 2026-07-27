import assert from "node:assert/strict";
import { spawn, execFile as execFileCallback } from "node:child_process";
import { createHash, generateKeyPairSync, X509Certificate } from "node:crypto";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { rawPublicKeyBase64FromPem } from "../src/bilateral/descriptor.mjs";
import { transitionDigest } from "../src/bilateral/messages.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import { createFakeBilateralClockchainHttpClient } from "./helpers/fake-bilateral-clockchain-service.mjs";
import { COORDINATOR_CLI_FLAGS } from "../src/bilateral/coordination/coordinator-runtime.mjs";

const execFile = promisify(execFileCallback);
const ROOT = new URL("../", import.meta.url).pathname;
const COORDINATOR_SCHEMA = "clockchain.bilateral-coordination-process-coordinator/v1";
const AUTHORIZE = "AUTHORIZED";
const PROCESS_PHASE_DEADLINE_MS = 90_000;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const within = (promise, ms) => Promise.race([
  promise,
  new Promise((_resolve, reject) => setTimeout(
    () => reject(new Error("bounded wait expired")),
    ms,
  )),
]);

const DIRECT_PROCESS_ROWS = Object.freeze(["relay restart during long poll", "relay crash"]);
const ADVERSARIAL_CITATIONS = Object.freeze([
  ["capability replay", "test/bilateral-coordination-storage.test.mjs", "test", "fails closed on capability expiry, cross-role use, and conflicting replay"],
  ["cross-role capability", "test/bilateral-coordination-storage.test.mjs", "test", "fails closed on capability expiry, cross-role use, and conflicting replay"],
  ["wrong TLS fingerprint", "test/bilateral-coordination-client.test.mjs", "test", "rejects wrong fingerprints, alternate certificates, hostname mismatch, and redirects"],
  ["plaintext downgrade", "test/bilateral-coordination-operator-client.test.mjs", "test", "operator transport rejects plaintext and a certificate/fingerprint mismatch before requests"],
  ["sequence gap", "test/bilateral-coordination-storage.test.mjs", "test", "implements idempotent event retry and fail-closed sender sequencing"],
  ["previous digest mismatch", "test/bilateral-coordination-storage.test.mjs", "test", "implements idempotent event retry and fail-closed sender sequencing"],
  ["dropped event response", "test/bilateral-coordination-operator-client.test.mjs", "test", "operator transport marks lost mutation responses ambiguous"],
  ["duplicated event response", "test/bilateral-coordination-supervisor.test.mjs", "test", "fails closed on replay ordering and authority substitutions"],
  ["oversized artifact", "test/bilateral-coordination-storage.test.mjs", "test", "rejects noncanonical JSON, archives, unknown types, private keys, and oversized artifacts"],
  ["secret-bearing artifact", "test/bilateral-coordination-storage.test.mjs", "test", "rejects noncanonical JSON, archives, unknown types, private keys, and oversized artifacts"],
  ["marker-incomplete package", "test/bilateral-coordination-storage.test.mjs", "test", "rejects structurally incomplete party-result packages"],
  ["artifact replacement", "test/bilateral-coordination-storage.test.mjs", "test", "rejects artifact replacement and duplicate digest with changed bytes"],
  ["funding mismatch", "test/bilateral-coordination-coordinator.test.mjs", "test", "rejects every malformed funding result before FUNDING_READY"],
  ["nonzero invitation nonce", "test/bilateral-coordination-coordinator.test.mjs", "test", "rejects every malformed funding result before FUNDING_READY"],
  ["token commitment mismatch", "test/bilateral-coordination-storage.test.mjs", "test", "accepts exact signed token commitments and rejects wrong signature, key, SHA, role, extra keys, and canaries"],
  ["preflight key mismatch", "test/bilateral-coordination-storage.test.mjs", "test", "accepts exact signed preflight public keys and rejects wrong signature, key, SHA, role, extra keys, and canaries"],
  ["repository change after preflight", "test/bilateral-roles.test.mjs", "test", "default builder fails provenance closed before secrets, clients, or tokens"],
  ["prompt change after preflight", "test/bilateral-roles.test.mjs", "test", "default builder fails provenance closed before secrets, clients, or tokens"],
  ["ambiguous registration write", "test/bilateral-machine-prep.test.mjs", "test", "registration resumes marker publication from matching durable identity bytes without registration rebroadcast"],
  ["ambiguous Clockchain write", "test/bilateral-operational-e2e.test.mjs", "test", "writer crash recovery is discovery-only after one ambiguous dispatch"],
  ["missing protocol anchor", "test/bilateral-operational-e2e.test.mjs", "scenario", "missing proposal anchor"],
  ["duplicate protocol anchor", "test/bilateral-operational-e2e.test.mjs", "scenario", "duplicate proposal anchor"],
  ["reordered protocol anchor", "test/bilateral-operational-e2e.test.mjs", "scenario", "reordered package transitions"],
  ["expired protocol anchor", "test/bilateral-operational-e2e.test.mjs", "scenario", "late verifier upper bound"],
  ["package and Clockchain divergence", "test/bilateral-operational-e2e.test.mjs", "scenario", "package predecessor divergence"],
  ["advisory status trap", "test/bilateral-operational-e2e.test.mjs", "scenario", "untrusted advisory and package APIs"],
  ["cached timestamp trap", "test/bilateral-operational-e2e.test.mjs", "scenario", "untrusted advisory and package APIs"],
  ["role crash", "test/bilateral-coordination-supervisor.test.mjs", "test", "records an exact recovery manifest for an ambiguous role command"],
  ["coordinator crash", "test/bilateral-coordination-coordinator.test.mjs", "test", "recovers after durable BOOTSTRAPPING state before pending-journal retirement"],
  ["verifier crash", "test/bilateral-coordination-coordinator-runtime.test.mjs", "test", "verifier child deadline escalates from TERM to KILL for an ignoring child"],
  ["verifier marker disagreement", "test/bilateral-coordination-relay.test.mjs", "test", "trusted verifier seam fails closed when its durable claim disagrees with the event"],
]);
const EXPECTED_REHEARSAL_RELAY_EFFECTS = Object.freeze([
  "operator:ENROLLMENT_RECEIPT:release",
  "operator:PREFLIGHT_PLAN_READY:release",
  "operator:REGISTER_REHEARSAL:rehearsal",
  "operator:REHEARSAL_DESCRIPTOR_READY:rehearsal",
  "operator:START_REHEARSAL:rehearsal",
  "operator:VERIFICATION_PASSED:rehearsal",
  "operator:WAIT_FOR_FUNDING:release",
  "payee:DESCRIPTOR_ACCEPTED:rehearsal",
  "payee:ENROLLMENT_CONFIRMED:release",
  "payee:FUNDING_INPUTS_READY:release",
  "payee:IDENTITY_PACKAGE_READY:rehearsal",
  "payee:PREFLIGHT_PARTICIPANT_READY:release",
  "payee:ROLE_PACKAGE_READY:rehearsal",
  "payee:ROLE_STARTED:rehearsal",
  "payee:TOKEN_READY:release",
  "payer:DESCRIPTOR_ACCEPTED:rehearsal",
  "payer:ENROLLMENT_CONFIRMED:release",
  "payer:FUNDING_INPUTS_READY:release",
  "payer:IDENTITY_PACKAGE_READY:rehearsal",
  "payer:PREFLIGHT_PARTICIPANT_READY:release",
  "payer:ROLE_PACKAGE_READY:rehearsal",
  "payer:ROLE_STARTED:rehearsal",
  "payer:TOKEN_READY:release",
].sort());

async function command(file, args, options = {}) { return execFile(file, args, { encoding: "utf8", ...options }); }
function canonicalJson(value) { if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; }
async function canonicalPrivate(path, value) { await writeFile(path, canonicalJson(value), { mode: 0o600 }); await chmod(path, 0o600); }
async function canonicalPrivateExclusive(path, value) { await writeFile(path, canonicalJson(value), { flag: "wx", mode: 0o600 }); await chmod(path, 0o600); }
async function privatePem(path, key) { await writeFile(path, key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 }); await chmod(path, 0o600); }
async function waitFor(path, output) { for (let turn = 0; turn < 100; turn += 1) { try { return JSON.parse(await readFile(path, "utf8")); } catch { if (output?.child.exitCode !== null) throw new Error(`readiness process exited: ${output.output().stderr}`); await sleep(20); } } throw new Error(`readiness missing: ${path}`); }
async function waitForPrivateMarker(path, expected, output) {
  const deadline = Date.now() + PROCESS_PHASE_DEADLINE_MS;
  while (Date.now() < deadline) {
    try {
      const info = await lstat(path);
      assert.equal(info.isFile(), true);
      assert.equal(info.isSymbolicLink(), false);
      assert.equal(info.nlink, 1);
      assert.equal(info.mode & 0o777, 0o600);
      const text = await readFile(path, "utf8");
      assert.equal(text, canonicalJson(expected));
      assert.deepEqual(JSON.parse(text), expected);
      return;
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      if (output?.child.exitCode !== null) {
        throw new Error(`readiness process exited: ${output.output().stderr}`);
      }
      await sleep(20);
    }
  }
  throw new Error(`readiness missing before ${PROCESS_PHASE_DEADLINE_MS}ms: ${path}`);
}
function spawned(args, options) { const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"], ...options }); let stdout = ""; let stderr = ""; child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8"); child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; }); return { child, output: () => ({ stderr, stdout }), wait: () => new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal, stderr, stdout })); }) }; }
function standalone(file, args = []) {
  const { NODE_TEST_CONTEXT, ...environment } = process.env;
  return spawned([file, ...args], { env: environment }).wait();
}
async function stop(process_) { if (process_.exitCode !== null || process_.signalCode !== null) return; process_.kill("SIGTERM"); await Promise.race([new Promise((resolve) => process_.once("close", resolve)), sleep(1_000)]); if (process_.exitCode === null && process_.signalCode === null) { process_.kill("SIGKILL"); await new Promise((resolve) => process_.once("close", resolve)); } }
async function availablePort() { const server = createServer(); await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }); const { port } = server.address(); await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); return port; }
function certificateFingerprint(certificate) { return createHash("sha256").update(new X509Certificate(certificate).raw).digest("hex"); }
async function relayReady(process_) { let buffer = ""; return new Promise((resolve, reject) => { process_.child.stdout.on("data", (chunk) => { buffer += chunk; const end = buffer.indexOf("\n"); if (end >= 0) { try { resolve(JSON.parse(buffer.slice(0, end))); } catch (error) { reject(error); } } }); process_.child.once("error", reject); process_.child.once("close", (code, signal) => { if (!buffer.includes("\n")) reject(new Error(`relay exited before readiness: ${code}/${signal}: ${process_.output().stderr}`)); }); }); }
function pinnedGet({ ca, fingerprint, path, port }) { return new Promise((resolve, reject) => { const request = httpsRequest({ ca, host: "127.0.0.1", method: "GET", path, port, rejectUnauthorized: true, servername: "localhost", headers: { host: `127.0.0.1:${port}` } }, (response) => { const peer = response.socket.getPeerCertificate(true); const actual = peer.raw && createHash("sha256").update(peer.raw).digest("hex"); if (actual !== fingerprint) { response.destroy(); reject(new Error("relay fingerprint mismatch")); return; } const chunks = []; response.on("data", (chunk) => chunks.push(chunk)); response.once("end", () => resolve({ body: Buffer.concat(chunks), statusCode: response.statusCode })); }); request.once("error", reject); request.end(); }); }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function triple(transition) { return { anchoredHash: transition.onChain.anchoredHash, blockHeight: transition.onChain.blockHeight, kind: transition.message.kind, ledgerId: transition.onChain.ledgerId }; }
function assertPaymentNeverMoved(value) { if (Array.isArray(value)) return value.forEach(assertPaymentNeverMoved); if (value !== null && typeof value === "object") { for (const [key, child] of Object.entries(value)) { if (key === "paymentMoved") assert.equal(child, false); assertPaymentNeverMoved(child); } } }
async function assertPrivateFile(path, { canonical = false, pretty = false } = {}) { const info = await lstat(path); assert.equal(info.isFile(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o600); const bytes = await readFile(path); const text = bytes.toString("utf8"); if (canonical) assert.equal(text, canonicalJson(JSON.parse(text))); if (pretty) assert.equal(text, `${JSON.stringify(JSON.parse(text), null, 2)}\n`); return bytes; }
async function assertRoot(path) { const info = await lstat(path); assert.equal(info.isDirectory(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.mode & 0o777, 0o700); }
async function assertCompletion(directory, marker, json, markdown) { const bytes = await assertPrivateFile(join(directory, marker)); const text = bytes.toString("utf8"); assert.equal(text, `${canonicalJson(JSON.parse(text))}\n`); const value = JSON.parse(text); assert.equal(value.jsonSha256, sha256(await readFile(join(directory, json)))); assert.equal(value.markdownSha256, sha256(await readFile(join(directory, markdown)))); }

test("process child is inert when directly discovered by node:test but rejects an empty CLI", async () => {
  const helper = new URL("helpers/bilateral-coordination-child.mjs", import.meta.url).pathname;
  const discovered = await standalone("--test", [helper]);
  assert.equal(discovered.code, 0, discovered.stderr);
  const direct = await standalone(helper);
  assert.notEqual(direct.code, 0);
  assert.match(direct.stderr, /^PROCESS_CHILD_FAILED:dispatch/m);
});

async function createProcessSession(t, { barrier = null } = {}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "bilateral-process-e2e-")));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  const barrierPaths = barrier === null ? null : {
    ready: join(root, "barrier-ready.json"),
    release: join(root, "barrier-release.json"),
  };
  const roleRoots = {
    payer: join(root, "payer-private"),
    payee: join(root, "payee-private"),
  };
  await mkdir(roleRoots.payer, { mode: 0o700 });
  await mkdir(roleRoots.payee, { mode: 0o700 });

  const clone = join(root, "repo");
  const archive = join(root, "repository.tar");
  await command("/usr/bin/git", ["-C", ROOT, "archive", "--format=tar", "--output", archive, "HEAD"]);
  await mkdir(clone, { mode: 0o700 });
  await command("/usr/bin/tar", ["-xf", archive, "-C", clone]);
  await rm(archive, { force: true });
  await command("/usr/bin/git", ["init", "--quiet"], { cwd: clone });
  await writeFile(join(clone, ".git/info/exclude"), "node_modules\n");
  await symlink(join(ROOT, "node_modules"), join(clone, "node_modules"));
  await cp(
    join(ROOT, "test/helpers/bilateral-coordination-child.mjs"),
    join(clone, "test/helpers/bilateral-coordination-child.mjs"),
  );
  await cp(
    join(ROOT, "test/helpers/fake-bilateral-clockchain-service.mjs"),
    join(clone, "test/helpers/fake-bilateral-clockchain-service.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/coordination/artifact.mjs"),
    join(clone, "src/bilateral/coordination/artifact.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/coordination/coordinator-runtime.mjs"),
    join(clone, "src/bilateral/coordination/coordinator-runtime.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/coordination/coordinator.mjs"),
    join(clone, "src/bilateral/coordination/coordinator.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/coordination/supervisor-runtime.mjs"),
    join(clone, "src/bilateral/coordination/supervisor-runtime.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/coordination/supervisor.mjs"),
    join(clone, "src/bilateral/coordination/supervisor.mjs"),
  );
  await cp(
    join(ROOT, "src/bilateral/runner.mjs"),
    join(clone, "src/bilateral/runner.mjs"),
  );

  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const operatorKey = rawPublicKeyBase64FromPem(
    publicKey.export({ format: "pem", type: "spki" }),
  );
  await mkdir(join(clone, "docs/operator-keys"), { recursive: true });
  await writeFile(
    join(clone, "docs/operator-keys/process-e2e-operator.pub"),
    `${operatorKey}\n`,
  );
  await command("/usr/bin/git", ["add", "--all"], { cwd: clone });
  await command(
    "/usr/bin/git",
    ["-c", "user.email=e2e@example.invalid", "-c", "user.name=Process E2E", "commit", "-m", "process e2e fixture"],
    { cwd: clone },
  );
  const repositorySha = (await command("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: clone })).stdout.trim();
  assert.equal((await command("/usr/bin/git", ["status", "--porcelain=v1"], { cwd: clone })).stdout, "");

  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"]);
  await chmod(certificateKey, 0o600);
  const relayFingerprint = certificateFingerprint(await readFile(certificate));

  const fakeState = join(root, "fake-state.json");
  const fakeListen = join(root, "fake-listen.json");
  const fake = spawned([
    "test/helpers/fake-bilateral-clockchain-service.mjs",
    "--state", fakeState,
    "--listen-file", fakeListen,
    "--max-operations", "512",
  ], { cwd: clone });
  t.after(() => stop(fake.child));
  const fakeReady = await waitFor(fakeListen, fake);
  const fakeClient = createFakeBilateralClockchainHttpClient(fakeReady);

  const relayState = join(root, "relay-state");
  await mkdir(relayState, { mode: 0o700 });
  const relay = spawned([
    "bin/handshake-relay.mjs",
    "--host", "127.0.0.1",
    "--port", "0",
    "--repository-sha", repositorySha,
    "--state", relayState,
    "--tls-certificate", certificate,
    "--tls-private-key", certificateKey,
  ], { cwd: clone });
  t.after(() => stop(relay.child));
  let relayBuffer = "";
  const relayLine = await new Promise((resolve, reject) => {
    relay.child.stdout.on("data", (chunk) => {
      relayBuffer += chunk;
      const line = relayBuffer.indexOf("\n");
      if (line >= 0) resolve(relayBuffer.slice(0, line));
    });
    relay.child.once("error", reject);
  });
  const relayReady = JSON.parse(relayLine);

  const releaseRoot = join(root, "operator-release");
  await mkdir(releaseRoot, { mode: 0o700 });
  const operatorPrivateKey = join(root, "operator-private.pem");
  await privatePem(operatorPrivateKey, privateKey);
  const operatorToken = join(root, "operator.token");
  const operatorRpc = join(root, "operator-rpc-url");
  await writeFile(operatorToken, "operator-process-token\n", { mode: 0o600 });
  await writeFile(operatorRpc, "http://127.0.0.1:8545\n", { mode: 0o600 });
  await Promise.all([chmod(operatorToken, 0o600), chmod(operatorRpc, 0o600)]);
  const outputs = {
    payer: join(roleRoots.payer, "rehearsal", "result"),
    payee: join(roleRoots.payee, "rehearsal", "result"),
    verifier: join(releaseRoot, "verifier", "rehearsal"),
  };
  const configurations = {
    payer: join(root, "payer-role.json"),
    payee: join(root, "payee-role.json"),
    verifier: join(root, "verifier.json"),
    coordinator: join(root, "coordinator.json"),
  };
  const logs = Object.fromEntries(["payer", "payee", "verifier"].map((name) => [name, {
    stderr: join(root, `${name}.stderr`),
    stdout: join(root, `${name}.stdout`),
  }]));
  const report = join(root, "coordinator-report.json");
  const coordinatorValues = {
    "--clockchain-token-file": operatorToken,
    "--operator-key-id": "process-e2e-operator",
    "--operator-private-key": operatorPrivateKey,
    "--release-root": releaseRoot,
    "--relay-url": `https://127.0.0.1:${relayReady.port}`,
    "--repository-sha": repositorySha,
    "--rpc-url-file": operatorRpc,
    "--tls-certificate": certificate,
    "--tls-fingerprint": relayFingerprint,
  };
  const coordinatorArguments = COORDINATOR_CLI_FLAGS.flatMap((flag) => [flag, coordinatorValues[flag]]);
  assert.equal(coordinatorArguments.length, COORDINATOR_CLI_FLAGS.length * 2);
  await canonicalPrivate(configurations.coordinator, {
    arguments: coordinatorArguments,
    barrier: barrierPaths,
    children: {
      payer: { agentIds: { rehearsal: "8677", stakeholder: "8679" }, configPath: configurations.payer, logs: logs.payer, stateRoot: roleRoots.payer, token: "payer-process-token" },
      payee: { agentIds: { rehearsal: "8678", stakeholder: "8680" }, configPath: configurations.payee, logs: logs.payee, stateRoot: roleRoots.payee, token: "payee-process-token" },
      verifier: { configPath: configurations.verifier, logs: logs.verifier },
    },
    fake: fakeReady,
    repositoryRoot: clone,
    report,
    schema: COORDINATOR_SCHEMA,
  });

  return {
    barrier: barrierPaths,
    certificate: { key: certificateKey, path: certificate, fingerprint: relayFingerprint },
    clone,
    configurations,
    fake,
    fakeClient,
    fakeReady,
    fakeState,
    logs,
    outputs,
    relay,
    relayReady,
    report,
    repositorySha,
    releaseRoot,
    roleRoots,
    root,
    startCoordinator: () => spawned([
      "test/helpers/bilateral-coordination-child.mjs",
      "coordinator",
      "--configuration", configurations.coordinator,
    ], { cwd: clone }),
    operatorPrivateKey,
    operatorRpc,
    operatorToken,
  };
}

test("real coordinator and supervisors gate one isolated three-transition process session", { concurrency: false }, async (t) => {
  const session = await createProcessSession(t);
  const coordinator = session.startCoordinator();
  const coordinatorExit = await coordinator.wait();
  const roleDiagnostics = await Promise.all(["payer", "payee", "verifier"].flatMap((name) => [
    readFile(session.logs[name].stdout, "utf8").catch(() => ""),
    readFile(session.logs[name].stderr, "utf8").catch(() => ""),
  ]));
  assert.deepEqual(
    { code: coordinatorExit.code, signal: coordinatorExit.signal },
    { code: 0, signal: null },
    `${coordinatorExit.stderr}\n${roleDiagnostics.join("\n")}`,
  );
  const snapshot = JSON.parse(await readFile(session.fakeState, "utf8"));
  const payerResult = JSON.parse(await readFile(join(session.outputs.payer, "party-result.json"), "utf8"));
  const payeeResult = JSON.parse(await readFile(join(session.outputs.payee, "party-result.json"), "utf8"));
  const verdict = JSON.parse(await readFile(join(session.outputs.verifier, "bilateral-verdict.json"), "utf8"));
  const coordinatorReport = JSON.parse(await readFile(session.report, "utf8"));
  assert.match(coordinatorReport.release.releaseId, /^release-[0-9a-f]{16}$/);
  assert.equal(coordinatorReport.release.repositorySha, session.repositorySha);
  assert.match(coordinatorReport.release.sessionId, /^[0-9a-f-]{36}$/);
  assert.ok(Array.isArray(coordinatorReport.authenticatedRelayEvents));
  assert.equal(coordinatorReport.coordinatorState, "REHEARSAL_VERIFIED");
  assert.match(coordinatorReport.verifierPublicationDigest, /^[0-9a-f]{64}$/);
  assert.deepEqual(
    coordinatorReport.authenticatedRelayEvents
      .map((event) => `${event.role}:${event.kind}:${event.subjectRun}`)
      .sort(),
    EXPECTED_REHEARSAL_RELAY_EFFECTS,
  );
  assert.equal(
    new Set(coordinatorReport.authenticatedRelayEvents.map(({ eventDigest }) => eventDigest)).size,
    coordinatorReport.authenticatedRelayEvents.length,
  );
  for (const role of ["operator", "payee", "payer"]) {
    let previousEventDigest = null;
    for (const [index, event] of coordinatorReport.authenticatedRelayEvents.filter((entry) => entry.role === role).entries()) {
      assert.equal(event.sequence, String(index));
      assert.equal(event.previousEventDigest, previousEventDigest);
      assert.equal(event.releaseId, coordinatorReport.release.releaseId);
      assert.equal(event.repositorySha, coordinatorReport.release.repositorySha);
      assert.equal(event.sessionId, coordinatorReport.release.sessionId);
      previousEventDigest = event.eventDigest;
    }
  }
  const verificationEvents = coordinatorReport.authenticatedRelayEvents.filter(({ kind }) => kind === "VERIFICATION_PASSED");
  assert.equal(verificationEvents.length, 1);
  assert.equal(verificationEvents[0].artifactDigest, coordinatorReport.verifierPublicationDigest);
  assert.equal(coordinatorReport.authenticatedRelayEvents.at(-1).eventDigest, verificationEvents[0].eventDigest);
  const counterDelta = Object.fromEntries(Object.keys(coordinatorReport.readCountersAfterVerifier).map((key) => [
    key,
    coordinatorReport.readCountersAfterVerifier[key] - coordinatorReport.readCountersBeforeVerifier[key],
  ]));
  assert.deepEqual(counterDelta, {
    generateAuditTrail: 3,
    getBlock: 5,
    resolveAgent: 5,
    searchActions: 4,
    snapshot: 1,
    verifyCrossParty: 3,
  });
  const pids = [
    session.fake.child.pid,
    session.relay.child.pid,
    coordinatorReport.coordinatorPid,
    coordinatorReport.payee.pid,
    coordinatorReport.payer.pid,
    coordinatorReport.verifier.pid,
  ];
  assert.equal(new Set(pids).size, 6);
  assert.ok(pids.every((pid) => Number.isInteger(pid) && pid > 0));
  for (const value of [snapshot, coordinatorReport, payerResult, payeeResult, verdict]) assertPaymentNeverMoved(value);
  const protocolAnchors = snapshot.calls.logAction.filter(({ asset_reference_id }) => ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(payerResult.sessionDigest, slot)).includes(asset_reference_id));
  assert.deepEqual(protocolAnchors.map(({ asset_reference_id }) => asset_reference_id), ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(payerResult.sessionDigest, slot)));
  assert.equal(protocolAnchors.length, 3);
  assert.equal(snapshot.writeCount, 5);
  assert.equal(snapshot.calls.logAction.length - protocolAnchors.length, 2);
  assert.equal(payerResult.transitions.length, 3);
  assert.ok(payeeResult.transitions.length >= 2);
  assert.deepEqual(payeeResult.transitions.slice(0, 2), payerResult.transitions.slice(0, 2));
  assert.deepEqual(payerResult.transitions.map(({ message }) => message.kind), ["proposal", "acceptance", "acknowledgment"]);
  assert.equal(payerResult.transitions.at(-1).message.outcome, "ACKNOWLEDGED");
  assert.equal(payeeResult.transitions[1].message.decision, "ACCEPT");
  assert.equal(payerResult.localVerdict, "LOCAL_OK");
  assert.equal(payeeResult.localVerdict, "LOCAL_OK");
  assert.equal(verdict.outcome, AUTHORIZE);
  assert.equal(verdict.transitions.length, 3);
  for (const [index, transition] of payerResult.transitions.entries()) {
    const digest = transitionDigest(transition.message);
    assert.equal(transition.digest, digest);
    assert.equal(transition.onChain.anchoredHash, digest);
    assert.equal(protocolAnchors[index].asset_hash, digest);
    assert.deepEqual(transition.message.amount, { currency: "USD", moved: false, value: "100" });
    assert.deepEqual(verdict.transitions[index], {
      anchoredHash: digest,
      blockHeight: transition.onChain.blockHeight,
      blockTimeRaw: transition.blockTimeRaw,
      digest,
      kind: transition.message.kind,
      ledgerId: transition.onChain.ledgerId,
      upperBoundMs: transition.upperBoundMs,
    });
  }
  const [proposal, acceptance, acknowledgment] = payerResult.transitions;
  assert.equal(proposal.message.predecessor, null);
  assert.deepEqual(acceptance.message.predecessor, triple(proposal));
  assert.deepEqual(acknowledgment.message.predecessor, triple(acceptance));
  assert.deepEqual(acknowledgment.message.proposal, triple(proposal));
  assert.equal(new Set(payerResult.transitions.map((transition) => transition.onChain.ledgerId)).size, 3);
  const heights = payerResult.transitions.map((transition) => BigInt(transition.onChain.blockHeight));
  assert.ok(heights[0] < heights[1] && heights[1] < heights[2]);
  const blockTimes = payerResult.transitions.map((transition) => {
    assert.match(transition.blockTimeRaw, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{9}Z$/);
    assert.equal(Number(transition.blockTimeMs), Date.parse(transition.blockTimeRaw));
    return Number(transition.blockTimeMs);
  });
  assert.ok(blockTimes[0] < blockTimes[1] && blockTimes[1] < blockTimes[2]);
  assert.equal(proposal.upperBoundMs, null);
  assert.equal(payerResult.deadlineMs, payeeResult.deadlineMs);
  for (const transition of [acceptance, acknowledgment]) {
    assert.notEqual(transition.upperBoundMs, null);
    assert.ok(Number(transition.upperBoundMs) <= Number(payerResult.deadlineMs));
  }
  const payerCli = JSON.parse(await readFile(session.logs.payer.stdout, "utf8"));
  const payeeCli = JSON.parse(await readFile(session.logs.payee.stdout, "utf8"));
  assert.equal(payerCli.state, "ACKNOWLEDGED");
  assert.equal(payeeCli.state, "ACCEPTED");
  await assertCompletion(session.outputs.payer, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(session.outputs.payee, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(session.outputs.verifier, ".bilateral-verdict.complete.json", "bilateral-verdict.json", "BILATERAL-VERDICT.md");
  const namedLogs = Object.fromEntries(await Promise.all(["payer", "payee", "verifier"].map(async (name) => [name, {
    stderr: await readFile(session.logs[name].stderr, "utf8"),
    stdout: await readFile(session.logs[name].stdout, "utf8"),
  }])));
  assert.equal(namedLogs.verifier.stdout, `${AUTHORIZE}\n`);
  assert.equal(namedLogs.verifier.stderr, "");
  for (const [name, log] of Object.entries(namedLogs)) if (name !== "verifier") { assert.equal(log.stdout.includes(AUTHORIZE), false); assert.equal(log.stderr.includes(AUTHORIZE), false); }
  const fundingLines = coordinatorExit.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)).filter(({ schema }) => schema === "clockchain.bilateral-funding-addresses/v1");
  assert.equal(fundingLines.length, 1);
  assert.equal(fundingLines[0].addresses.length, 4);
  assert.equal(new Set(fundingLines[0].addresses).size, 4);
  assert.ok(fundingLines[0].addresses.every((address) => /^0x[0-9a-f]{40}$/.test(address)));
  assert.equal(coordinatorExit.stdout.includes(AUTHORIZE), false);
  assert.equal(coordinatorExit.stderr.includes(AUTHORIZE), false);
  assert.equal(session.fake.output().stdout.includes(AUTHORIZE), false);
  assert.equal(session.fake.output().stderr.includes(AUTHORIZE), false);
  assert.equal(session.relay.output().stdout.includes(AUTHORIZE), false);
  assert.equal(session.relay.output().stderr.includes(AUTHORIZE), false);
  assert.equal((await readFile(new URL("helpers/bilateral-coordination-child.mjs", import.meta.url), "utf8")).includes(AUTHORIZE), false);
  await assertPrivateFile(session.report, { canonical: true });
  for (const log of Object.values(session.logs)) { await assertPrivateFile(log.stdout); await assertPrivateFile(log.stderr); }
  for (const root of Object.values(session.roleRoots)) await assertRoot(root);
  assert.notEqual(session.roleRoots.payer, session.roleRoots.payee);
  const roleConfigurations = [session.configurations.payer, session.configurations.payee];
  const roleTokens = [join(session.roleRoots.payer, "clockchain.token"), join(session.roleRoots.payee, "clockchain.token")];
  const coordinationKeys = [join(session.roleRoots.payer, "payer-coordination.pem"), join(session.roleRoots.payee, "payee-coordination.pem")];
  const preflightKeys = [join(session.roleRoots.payer, "preflight", "preflight.ed25519.pem"), join(session.roleRoots.payee, "preflight", "preflight.ed25519.pem")];
  const invitationKeys = [
    join(session.roleRoots.payer, "invitation-secret", "payer-rehearsal.secret.json"),
    join(session.roleRoots.payer, "invitation-secret", "payer-stakeholder.secret.json"),
    join(session.roleRoots.payee, "invitation-secret", "payee-rehearsal.secret.json"),
    join(session.roleRoots.payee, "invitation-secret", "payee-stakeholder.secret.json"),
  ];
  const rolePrivatePaths = [...roleConfigurations, ...roleTokens, ...coordinationKeys, ...preflightKeys, ...invitationKeys];
  assert.equal(new Set(rolePrivatePaths).size, rolePrivatePaths.length);
  const canonicalPrivatePaths = new Set(roleConfigurations);
  const prettyPrivatePaths = new Set(invitationKeys);
  for (const path of rolePrivatePaths) await assertPrivateFile(path, {
    canonical: canonicalPrivatePaths.has(path),
    pretty: prettyPrivatePaths.has(path),
  });
  for (const paths of [roleTokens, coordinationKeys, preflightKeys, invitationKeys]) {
    const fingerprints = await Promise.all(paths.map(async (path) => sha256(await readFile(path))));
    assert.equal(new Set(fingerprints).size, paths.length);
  }
  assert.equal(new Set(Object.values(session.outputs)).size, 3);
  for (const output of Object.values(session.outputs)) await assertRoot(output);
  for (const pid of [coordinatorReport.coordinatorPid, coordinatorReport.payer.pid, coordinatorReport.payee.pid, coordinatorReport.verifier.pid]) assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  for (const pid of [session.fake.child.pid, session.relay.child.pid]) assert.doesNotThrow(() => process.kill(pid, 0));
});

test("relay restart during a pinned long poll fails closed and recovers empty state", { concurrency: false }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "bilateral-relay-restart-"));
  await chmod(root, 0o700);
  t.after(() => rm(root, { force: true, recursive: true }));
  const clone = join(root, "repo");
  const archive = join(root, "repository.tar");
  await command("/usr/bin/git", ["-C", ROOT, "archive", "--format=tar", "--output", archive, "HEAD"]);
  await mkdir(clone, { mode: 0o700 });
  await command("/usr/bin/tar", ["-xf", archive, "-C", clone]);
  await rm(archive, { force: true });
  await command("/usr/bin/git", ["init", "--quiet"], { cwd: clone });
  await writeFile(join(clone, ".git/info/exclude"), "node_modules\n");
  await symlink(join(ROOT, "node_modules"), join(clone, "node_modules"));
  await command("/usr/bin/git", ["add", "--all"], { cwd: clone });
  await command(
    "/usr/bin/git",
    ["-c", "user.email=relay-restart@example.invalid", "-c", "user.name=Relay Restart", "commit", "--quiet", "-m", "relay restart fixture"],
    { cwd: clone },
  );
  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"]);
  await chmod(certificateKey, 0o600);
  const ca = await readFile(certificate, "utf8");
  const fingerprint = certificateFingerprint(ca);
  const state = join(root, "relay-state");
  await mkdir(state, { mode: 0o700 });
  const port = await availablePort();
  const repositorySha = (await command("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: clone })).stdout.trim();
  const arguments_ = ["bin/handshake-relay.mjs", "--host", "127.0.0.1", "--port", String(port), "--repository-sha", repositorySha, "--state", state, "--tls-certificate", certificate, "--tls-private-key", certificateKey];
  const first = spawned(arguments_, { cwd: clone });
  t.after(() => stop(first.child));
  assert.equal((await relayReady(first)).port, port);
  const sessionId = "0352cfc8-5393-40d0-828f-61a457fcdd03";
  const pending = pinnedGet({ ca, fingerprint, path: `/v1/sessions/${sessionId}/events?waitMs=30000`, port });
  let settled = false;
  pending.finally(() => { settled = true; }).catch(() => {});
  await sleep(100);
  assert.equal(settled, false);
  await stop(first.child);
  await assert.rejects(within(pending, 1_000));
  await sleep(100);
  const second = spawned(arguments_, { cwd: clone });
  t.after(() => stop(second.child));
  try {
    assert.equal((await relayReady(second)).port, port);
  } catch (error) {
    throw new Error(`${error.message}; state=${(await readdir(state)).join(",")}`);
  }
  const response = await pinnedGet({ ca, fingerprint, path: `/v1/sessions/${sessionId}/events?waitMs=0`, port });
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body.toString("utf8")), []);
});

test("relay crash before verifier fails closed without spawning a verifier", { concurrency: false }, async (t) => {
  const session = await createProcessSession(t, { barrier: true });
  const coordinator = session.startCoordinator();
  t.after(() => stop(coordinator.child));

  await waitForPrivateMarker(session.barrier.ready, {
    schema: COORDINATOR_SCHEMA,
    stage: "roles-complete",
  }, coordinator);
  const beforeCrash = JSON.parse(await readFile(session.fakeState, "utf8"));
  const payerResult = JSON.parse(await readFile(join(session.outputs.payer, "party-result.json"), "utf8"));
  const protocolAnchors = beforeCrash.calls.logAction.filter(({ asset_reference_id }) => ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(payerResult.sessionDigest, slot)).includes(asset_reference_id));
  assert.equal(protocolAnchors.length, 3);

  await stop(session.relay.child);
  await canonicalPrivateExclusive(session.barrier.release, { release: true });

  const coordinatorExit = await within(coordinator.wait(), 15_000);
  assert.notEqual(coordinatorExit.code, 0);
  assert.equal(coordinatorExit.signal, null);
  await assert.rejects(readFile(session.report, "utf8"), { code: "ENOENT" });
  await assert.rejects(lstat(session.logs.verifier.stdout), { code: "ENOENT" });
  await assert.rejects(lstat(session.logs.verifier.stderr), { code: "ENOENT" });
  const existingOutputs = [
    coordinatorExit.stderr,
    coordinatorExit.stdout,
    session.fake.output().stderr,
    session.fake.output().stdout,
    session.relay.output().stderr,
    session.relay.output().stdout,
    await readFile(session.logs.payer.stderr, "utf8"),
    await readFile(session.logs.payer.stdout, "utf8"),
    await readFile(session.logs.payee.stderr, "utf8"),
    await readFile(session.logs.payee.stdout, "utf8"),
  ];
  assert.ok(existingOutputs.every((text) => !text.includes(AUTHORIZE)));
  const afterCrash = JSON.parse(await readFile(session.fakeState, "utf8"));
  assert.equal(afterCrash.calls.logAction.filter(({ asset_reference_id }) => ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(payerResult.sessionDigest, slot)).includes(asset_reference_id)).length, 3);
  assert.equal(afterCrash.writeCount, 5);
});

test("adversarial matrix citations name existing focused coverage", async () => {
  const matrixRows = [
    "capability replay", "cross-role capability", "wrong TLS fingerprint",
    "plaintext downgrade", "sequence gap", "previous digest mismatch",
    "relay restart during long poll", "dropped event response",
    "duplicated event response", "oversized artifact", "secret-bearing artifact",
    "marker-incomplete package", "artifact replacement", "funding mismatch",
    "nonzero invitation nonce", "token commitment mismatch", "preflight key mismatch",
    "repository change after preflight", "prompt change after preflight",
    "ambiguous registration write", "ambiguous Clockchain write", "missing protocol anchor",
    "duplicate protocol anchor", "reordered protocol anchor", "expired protocol anchor",
    "package and Clockchain divergence", "advisory status trap", "cached timestamp trap",
    "role crash", "relay crash", "coordinator crash", "verifier crash",
    "verifier marker disagreement",
  ];
  assert.equal(new Set(matrixRows).size, 33);
  const citedRows = ADVERSARIAL_CITATIONS.map(([row]) => row);
  const executedRows = [...DIRECT_PROCESS_ROWS];
  assert.equal(new Set(citedRows).size, citedRows.length);
  assert.equal(new Set(executedRows).size, executedRows.length);
  assert.deepEqual([...citedRows, ...executedRows].sort((a, b) => matrixRows.indexOf(a) - matrixRows.indexOf(b)), matrixRows);
  for (const [, file, kind, name] of ADVERSARIAL_CITATIONS) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), "utf8");
    const declaration = kind === "test" ? `test(${JSON.stringify(name)}` : `name: ${JSON.stringify(name)}`;
    assert.ok(source.includes(declaration), `${file} must retain exact ${kind} declaration ${name}`);
  }
});
