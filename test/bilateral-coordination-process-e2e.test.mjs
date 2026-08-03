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
import { BOOTSTRAP_BROKER_JOURNAL_FILE } from "../src/bilateral/local-mcp/bootstrap-broker.mjs";
import { decryptInvitation } from "../src/invitation.mjs";

const execFile = promisify(execFileCallback);
const ROOT = new URL("../", import.meta.url).pathname;
const COORDINATOR_SCHEMA = "clockchain.bilateral-coordination-process-coordinator/v1";
const AUTHORIZE = "AUTHORIZED";
const CONSOLE_VERIFICATION_PASSED = "VERIFICATION_PASSED";
const PROCESS_PHASE_DEADLINE_MS = 90_000;
const FAKE_CLOCKCHAIN_BASE_TIME_MS = 1_784_923_200_000;
const SHARED_TEST_CLOCK_MS = FAKE_CLOCKCHAIN_BASE_TIME_MS - 1_000;
const PAYER_MCP_INTAKE_REQUEST_ID = "11111111-2222-4333-8444-555555555555";
assert.equal(new Date(FAKE_CLOCKCHAIN_BASE_TIME_MS).toISOString(), "2026-07-24T20:00:00.000Z");
assert.equal(SHARED_TEST_CLOCK_MS < FAKE_CLOCKCHAIN_BASE_TIME_MS, true);
const PROCESS_FAILURE_SCENARIOS = Object.freeze([
  "missing-mandate",
  "forged-iris-signature",
  "wrong-billie-signer",
  "invoice-prefix-mismatch",
  "request-replay-changed-bytes",
  "expired-mandate",
  "expired-request",
  "descriptor-swap",
  "fourth-write",
  "stale-verifier-publication",
  "mismatched-verifier-publication",
]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function within(promise, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("bounded wait expired")), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const DIRECT_PROCESS_ROWS = Object.freeze(["relay restart during long poll", "relay crash"]);
const AWS_TOPOLOGY_CITATIONS = Object.freeze([
  [
    "test/aws-control-plane-integration.test.mjs",
    "runs the deterministic hosted topology through fresh verification",
  ],
  [
    "test/aws-control-plane-restart.test.mjs",
    "restarts every stateful boundary without replay or regression",
  ],
  [
    "test/aws-control-plane-security.test.mjs",
    "hostile topology inputs fail closed without public or log leakage",
  ],
]);
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
  ["ambiguous Clockchain write", "test/bilateral-operational-e2e.test.mjs", "test", "writer crash recovery adopts the landed anchor after one ambiguous dispatch"],
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
  "payee:PAYMENT_REQUEST_READY:rehearsal",
  "payee:PREFLIGHT_PARTICIPANT_READY:release",
  "payee:ROLE_PACKAGE_READY:rehearsal",
  "payee:ROLE_STARTED:rehearsal",
  "payee:TOKEN_READY:release",
  "payer:DESCRIPTOR_ACCEPTED:rehearsal",
  "payer:ENROLLMENT_CONFIRMED:release",
  "payer:FUNDING_INPUTS_READY:release",
  "payer:IDENTITY_PACKAGE_READY:rehearsal",
  "payer:PAYER_MANDATE_READY:rehearsal",
  "payer:PAYMENT_REQUEST_MATCHED:rehearsal",
  "payer:PREFLIGHT_PARTICIPANT_READY:release",
  "payer:ROLE_PACKAGE_READY:rehearsal",
  "payer:ROLE_STARTED:rehearsal",
  "payer:TOKEN_READY:release",
].sort());
const EXPECTED_TWO_RUN_RELAY_EFFECTS = Object.freeze([
  ...EXPECTED_REHEARSAL_RELAY_EFFECTS,
  "operator:REGISTER_STAKEHOLDER:stakeholder",
  "operator:STAKEHOLDER_DESCRIPTOR_READY:stakeholder",
  "operator:START_STAKEHOLDER:stakeholder",
  "operator:VERIFICATION_PASSED:stakeholder",
  "operator:COMPLETE_RELEASE:release",
  "payee:DESCRIPTOR_ACCEPTED:stakeholder",
  "payee:IDENTITY_PACKAGE_READY:stakeholder",
  "payee:PAYMENT_REQUEST_READY:stakeholder",
  "payee:ROLE_PACKAGE_READY:stakeholder",
  "payee:ROLE_STARTED:stakeholder",
  "payer:DESCRIPTOR_ACCEPTED:stakeholder",
  "payer:IDENTITY_PACKAGE_READY:stakeholder",
  "payer:PAYER_MANDATE_READY:stakeholder",
  "payer:PAYMENT_REQUEST_MATCHED:stakeholder",
  "payer:ROLE_PACKAGE_READY:stakeholder",
  "payer:ROLE_STARTED:stakeholder",
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
      if (output?.child.exitCode !== null || output?.child.signalCode !== null) {
        throw new Error(`readiness process exited: ${output.output().stderr}`);
      }
      await sleep(20);
    }
  }
  throw new Error(
    `readiness missing before ${PROCESS_PHASE_DEADLINE_MS}ms: ${path}; `
    + `child=${output?.child.exitCode ?? "running"}/${output?.child.signalCode ?? "none"}`,
  );
}
function spawned(args, options) {
  const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"], ...options });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
  return { child, output: () => ({ stderr, stdout }), wait: () => completion };
}
function standalone(file, args = []) {
  const { NODE_TEST_CONTEXT, ...environment } = process.env;
  return spawned([file, ...args], { env: environment }).wait();
}
async function stop(process_) { if (process_.exitCode !== null || process_.signalCode !== null) return; process_.kill("SIGTERM"); await Promise.race([new Promise((resolve) => process_.once("close", resolve)), sleep(1_000)]); if (process_.exitCode === null && process_.signalCode === null) { process_.kill("SIGKILL"); await new Promise((resolve) => process_.once("close", resolve)); } }
async function descendantPids(rootPid) {
  const { stdout } = await execFile("/bin/ps", ["-axo", "pid=,ppid="]);
  const children = new Map();
  for (const line of stdout.trim().split("\n")) {
    const match = /^\s*([0-9]+)\s+([0-9]+)\s*$/.exec(line);
    if (match === null) continue;
    const pid = Number(match[1]);
    const ppid = Number(match[2]);
    if (!children.has(ppid)) children.set(ppid, []);
    children.get(ppid).push(pid);
  }
  const descendants = [];
  const pending = [rootPid];
  while (pending.length > 0) {
    const parent = pending.pop();
    for (const child of children.get(parent) ?? []) {
      descendants.push(child);
      pending.push(child);
    }
  }
  return descendants;
}
async function stopGroup(process_) {
  if (!Number.isInteger(process_?.pid) || process_.pid <= 0) return;
  const descendants = await descendantPids(process_.pid);
  for (const pid of [process_.pid, ...descendants.reverse()]) {
    try { process.kill(pid, "SIGTERM"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
  }
  await Promise.race([
    process_.exitCode !== null || process_.signalCode !== null ? Promise.resolve() : new Promise((resolve) => process_.once("close", resolve)),
    sleep(1_000),
  ]);
  for (const pid of [process_.pid, ...descendants]) {
    try { process.kill(pid, "SIGKILL"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
  }
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const live = [process_.pid, ...descendants].filter((pid) => {
      try { process.kill(pid, 0); return true; } catch (error) { if (error?.code === "ESRCH") return false; throw error; }
    });
    if (live.length === 0) return;
    await sleep(10);
  }
  throw new Error("coordinator descendant cleanup deadline expired");
}
async function stopPids(pids) {
  for (const signal of ["SIGTERM", "SIGKILL"]) {
    for (const pid of pids) {
      try { process.kill(pid, signal); } catch (error) { if (error?.code !== "ESRCH") throw error; }
    }
    if (signal === "SIGTERM") await sleep(1_000);
  }
}
async function availablePort() { const server = createServer(); await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }); const { port } = server.address(); await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); return port; }
function certificateFingerprint(certificate) { return createHash("sha256").update(new X509Certificate(certificate).raw).digest("hex"); }
async function relayReady(process_) { let buffer = ""; return new Promise((resolve, reject) => { process_.child.stdout.on("data", (chunk) => { buffer += chunk; const end = buffer.indexOf("\n"); if (end >= 0) { try { resolve(JSON.parse(buffer.slice(0, end))); } catch (error) { reject(error); } } }); process_.child.once("error", reject); process_.child.once("close", (code, signal) => { if (!buffer.includes("\n")) reject(new Error(`relay exited before readiness: ${code}/${signal}: ${process_.output().stderr}`)); }); }); }
function pinnedGet({ ca, fingerprint, path, port }) { return new Promise((resolve, reject) => { const request = httpsRequest({ ca, host: "127.0.0.1", method: "GET", path, port, rejectUnauthorized: true, servername: "localhost", headers: { host: `127.0.0.1:${port}` } }, (response) => { const peer = response.socket.getPeerCertificate(true); const actual = peer.raw && createHash("sha256").update(peer.raw).digest("hex"); if (actual !== fingerprint) { response.destroy(); reject(new Error("relay fingerprint mismatch")); return; } const chunks = []; response.on("data", (chunk) => chunks.push(chunk)); response.once("end", () => resolve({ body: Buffer.concat(chunks), statusCode: response.statusCode })); }); request.once("error", reject); request.end(); }); }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function triple(transition) { return { anchoredHash: transition.onChain.anchoredHash, blockHeight: transition.onChain.blockHeight, kind: transition.message.kind, ledgerId: transition.onChain.ledgerId }; }
function assertPaymentNeverMoved(value) { if (Array.isArray(value)) return value.forEach(assertPaymentNeverMoved); if (value !== null && typeof value === "object") { for (const [key, child] of Object.entries(value)) { if (key === "paymentMoved") assert.equal(child, false); assertPaymentNeverMoved(child); } } }
async function assertOrderedPreflightWrites(session, preflightSnapshot) {
  const [payerReport, payeeReport] = await Promise.all([
    readFile(join(session.roleRoots.payer, "preflight", "participant-report.json"), "utf8"),
    readFile(join(session.roleRoots.payee, "preflight", "participant-report.json"), "utf8"),
  ]).then((reports) => reports.map((report) => JSON.parse(report)));
  const writes = preflightSnapshot.callSequence.filter(({ name }) => name === "logAction").map(({ args }) => args);
  assert.deepEqual(
    writes.map(({ asset_reference_id }) => asset_reference_id),
    [payerReport.report.write.key, payeeReport.report.write.key],
  );
  assert.deepEqual(
    writes.map(({ asset_hash }) => asset_hash),
    [payerReport.report.write.digest, payeeReport.report.write.digest],
  );
  assert.equal(writes.length, 2);
}
async function assertPrivateFile(path, { canonical = false, pretty = false } = {}) { const info = await lstat(path); assert.equal(info.isFile(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o600); const bytes = await readFile(path); const text = bytes.toString("utf8"); if (canonical) assert.equal(text, canonicalJson(JSON.parse(text))); if (pretty) assert.equal(text, `${JSON.stringify(JSON.parse(text), null, 2)}\n`); return bytes; }
async function assertRoot(path) { const info = await lstat(path); assert.equal(info.isDirectory(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.mode & 0o777, 0o700); }
async function assertCompletion(directory, marker, json, markdown) { const bytes = await assertPrivateFile(join(directory, marker)); const text = bytes.toString("utf8"); assert.equal(text, `${canonicalJson(JSON.parse(text))}\n`); const value = JSON.parse(text); assert.equal(value.jsonSha256, sha256(await readFile(join(directory, json)))); assert.equal(value.markdownSha256, sha256(await readFile(join(directory, markdown)))); }
function parseJsonLines(text) { return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
function lastJsonLine(text, predicate = () => true) { return parseJsonLines(text).filter(predicate).at(-1); }

test("process child is inert when directly discovered by node:test but rejects an empty CLI", async () => {
  const helper = new URL("helpers/bilateral-coordination-child.mjs", import.meta.url).pathname;
  const discovered = await standalone("--test", [helper]);
  assert.equal(discovered.code, 0, discovered.stderr);
  const direct = await standalone(helper);
  assert.notEqual(direct.code, 0);
  assert.match(direct.stderr, /^PROCESS_CHILD_FAILED:dispatch/m);
});

async function createProcessSession(t, { barrier = null, coordinatorFirst = barrier === null, fault = null, scenario = "success" } = {}) {
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
    join(ROOT, "test/helpers/bilateral-fixed-clock.mjs"),
    join(clone, "test/helpers/bilateral-fixed-clock.mjs"),
  );
  await cp(
    join(ROOT, "test/helpers/bilateral-relay-child.mjs"),
    join(clone, "test/helpers/bilateral-relay-child.mjs"),
  );
  for (const relative of [
    "src/bilateral/coordination/client.mjs",
    "src/bilateral/coordination/coordinator-runtime.mjs",
    "src/bilateral/coordination/manifest.mjs",
    "src/bilateral/coordination/supervisor-runtime.mjs",
    "src/bilateral/local-mcp/bootstrap-broker.mjs",
  ]) {
    await cp(
      join(ROOT, relative),
      join(clone, relative),
    );
  }
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
  await cp(
    join(ROOT, "bin/handshake-request-payment.mjs"),
    join(clone, "bin/handshake-request-payment.mjs"),
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
  await command("/usr/bin/git", ["update-ref", "--no-deref", "HEAD", repositorySha], { cwd: clone });
  assert.equal((await command("/usr/bin/git", ["status", "--porcelain=v1"], { cwd: clone })).stdout, "");

  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"]);
  await chmod(certificateKey, 0o600);
  const relayFingerprint = certificateFingerprint(await readFile(certificate));
  const payerMcpCertificate = join(root, "payer-mcp-cert.pem");
  const payerMcpCertificateKey = join(root, "payer-mcp-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", payerMcpCertificateKey, "-out", payerMcpCertificate, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"]);
  await Promise.all([chmod(payerMcpCertificate, 0o600), chmod(payerMcpCertificateKey, 0o600)]);
  const payerMcpFingerprint = certificateFingerprint(await readFile(payerMcpCertificate));

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
  const preflightFakeState = join(root, "preflight-fake-state.json");
  const preflightFakeListen = join(root, "preflight-fake-listen.json");
  const preflightFake = spawned([
    "test/helpers/fake-bilateral-clockchain-service.mjs",
    "--state", preflightFakeState,
    "--listen-file", preflightFakeListen,
    "--max-operations", "64",
  ], { cwd: clone });
  t.after(() => stop(preflightFake.child));
  const preflightFakeReady = await waitFor(preflightFakeListen, preflightFake);

  const relayState = join(root, "relay-state");
  await mkdir(relayState, { mode: 0o700 });
  const relayArguments = [
    "test/helpers/bilateral-relay-child.mjs",
    "--advertised-host", "127.0.0.1",
    "--host", "127.0.0.1",
    "--port", "0",
    "--repository-sha", repositorySha,
    "--state", relayState,
    "--tls-certificate", certificate,
    "--tls-private-key", certificateKey,
  ];
  const relayEnvironment = {
    ...process.env,
    CLOCKCHAIN_BILATERAL_TEST_CLOCK_MS: String(SHARED_TEST_CLOCK_MS),
    NODE_OPTIONS: [
      process.env.NODE_OPTIONS,
      `--import=${join(clone, "test/helpers/bilateral-fixed-clock.mjs")}`,
    ].filter(Boolean).join(" "),
  };
  const relay = spawned(relayArguments, {
    cwd: clone,
    env: relayEnvironment,
  });
  t.after(() => stop(relay.child));
  const relayListen = await within(
    relayReady(relay),
    5_000,
  );

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
    "--relay-url": `https://127.0.0.1:${relayListen.port}`,
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
    clockMs: SHARED_TEST_CLOCK_MS,
    coordinatorFirst,
    fake: fakeReady,
    fault,
    payerMcp: {
      certificatePath: payerMcpCertificate,
      fingerprint: payerMcpFingerprint,
      host: "127.0.0.1",
      intakeRequestId: PAYER_MCP_INTAKE_REQUEST_ID,
      privateKeyPath: payerMcpCertificateKey,
    },
    preflightFake: preflightFakeReady,
    repositoryRoot: clone,
    report,
    scenario,
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
    relayReady: relayListen,
    restartRelay: async () => {
      const restartedArguments = [...relayArguments];
      restartedArguments[restartedArguments.indexOf("--port") + 1] = String(relayListen.port);
      const restarted = spawned(restartedArguments, { cwd: clone, env: relayEnvironment });
      t.after(() => stop(restarted.child));
      const ready = await within(relayReady(restarted), 5_000);
      assert.equal(ready.port, relayListen.port);
      return restarted;
    },
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
    preflightFake,
    preflightFakeState,
  };
}

test("coordinator fails fast with sanitized diagnostics when original payer exits before completion", { concurrency: false }, async (t) => {
  const session = await createProcessSession(t, {
    fault: {
      command: "preflight",
      role: "payer",
      subjectRun: "release",
    },
  });
  const coordinator = session.startCoordinator();
  t.after(() => stopGroup(coordinator.child));
  const startedAt = Date.now();
  const exit = await within(coordinator.wait(), 20_000).catch(async (error) => {
    const phase = await readFile(`${session.report}.phase`, "utf8").catch(() => "");
    const roleLogs = await Promise.all(["payer", "payee"].flatMap((role) => [
      readFile(session.logs[role].stdout, "utf8").catch(() => ""),
      readFile(session.logs[role].stderr, "utf8").catch(() => ""),
    ]));
    throw new Error(`${error.message}\nphase=${JSON.stringify(phase.trim())}\ncoordinator=${JSON.stringify(coordinator.output())}\nroles=${roleLogs.join("\n")}`);
  });
  const elapsedMs = Date.now() - startedAt;
  const phase = await readFile(`${session.report}.phase`, "utf8").catch(() => "");
  const roleLogs = await Promise.all(["payer", "payee"].flatMap((role) => [
    readFile(session.logs[role].stdout, "utf8").catch(() => ""),
    readFile(session.logs[role].stderr, "utf8").catch(() => ""),
  ]));
  const diagnosticSurface = [
    exit.stdout,
    exit.stderr,
    phase,
    ...roleLogs,
  ].join("\n");
  assert.notEqual(exit.code, 0);
  assert.equal(exit.signal, null);
  assert.ok(elapsedMs < 20_000, `elapsedMs=${elapsedMs}`);
  assert.match(exit.stderr, /^PROCESS_CHILD_FAILED:coordinator-role-early-exit:ROLE_CHILD_EXITED:/m);
  assert.match(diagnosticSurface, /ROLE_CHILD_EXITED:role=payer;command=preflight;subjectRun=release/);
  assert.equal(diagnosticSurface.includes("subjectRun=rehearsal"), false);
  assert.equal(diagnosticSurface.includes(session.root), false);
  assert.equal(diagnosticSurface.includes(session.operatorToken), false);
  assert.equal(diagnosticSurface.includes(session.operatorPrivateKey), false);
  assert.equal(diagnosticSurface.includes("payer-process-token"), false);
  assert.equal(diagnosticSurface.includes("payee-process-token"), false);
  assert.equal(diagnosticSurface.includes(AUTHORIZE), false);
  await assert.rejects(readFile(session.report, "utf8"), { code: "ENOENT" });
});

test("one long-lived Payer and Requestor span rehearsal and stakeholder with two fresh verifiers", { concurrency: false }, async (t) => {
  const session = await createProcessSession(t);
  const coordinator = session.startCoordinator();
  t.after(() => stopGroup(coordinator.child));
  const readRoleDiagnostics = () => Promise.all(["payer", "payee", "verifier"].flatMap((name) => [
    readFile(session.logs[name].stdout, "utf8").catch(() => ""),
    readFile(session.logs[name].stderr, "utf8").catch(() => ""),
  ]));
  const coordinatorExit = await within(coordinator.wait(), PROCESS_PHASE_DEADLINE_MS).catch(async (error) => {
    const roleDiagnostics = await readRoleDiagnostics();
    const phase = await readFile(`${session.report}.phase`, "utf8").catch(() => "");
    throw new Error(`${error.message}\nphase=${JSON.stringify(phase.trim())}\ncoordinator=${JSON.stringify(coordinator.output())}\nroles=${roleDiagnostics.join("\n")}\nrelay=${JSON.stringify(session.relay.output())}`);
  });
  const roleDiagnostics = await readRoleDiagnostics();
  assert.equal(roleDiagnostics.join("\n").includes("ROLE_CHILD_EXITED"), false);
  assert.equal(roleDiagnostics.join("\n").includes("ROLE_LAUNCHER_FAILED"), false);
  assert.deepEqual(
    { code: coordinatorExit.code, signal: coordinatorExit.signal },
    { code: 0, signal: null },
    `${coordinatorExit.stderr}\n${roleDiagnostics.join("\n")}\n${session.relay.output().stderr}`,
  );
  const snapshot = JSON.parse(await readFile(session.fakeState, "utf8"));
  const payerResult = JSON.parse(await readFile(join(session.outputs.payer, "party-result.json"), "utf8"));
  const payeeResult = JSON.parse(await readFile(join(session.outputs.payee, "party-result.json"), "utf8"));
  const stakeholderOutputs = {
    payee: join(session.roleRoots.payee, "stakeholder", "result"),
    payer: join(session.roleRoots.payer, "stakeholder", "result"),
    verifier: join(session.releaseRoot, "verifier", "stakeholder"),
  };
  const stakeholderPayerResult = JSON.parse(await readFile(join(stakeholderOutputs.payer, "party-result.json"), "utf8"));
  const stakeholderPayeeResult = JSON.parse(await readFile(join(stakeholderOutputs.payee, "party-result.json"), "utf8"));
  const descriptorEnvelope = JSON.parse(await readFile(join(session.roleRoots.payer, "rehearsal", "descriptor.json"), "utf8"));
  const stakeholderDescriptorEnvelope = JSON.parse(await readFile(join(session.roleRoots.payer, "stakeholder", "descriptor.json"), "utf8"));
  const verdict = JSON.parse(await readFile(join(session.outputs.verifier, "bilateral-verdict.json"), "utf8"));
  const stakeholderVerdict = JSON.parse(await readFile(join(stakeholderOutputs.verifier, "bilateral-verdict.json"), "utf8"));
  const coordinatorReport = JSON.parse(await readFile(session.report, "utf8"));
  assert.deepEqual(
    coordinatorReport.mcpMilestones.map(({ stage }) => stage),
    ["PAYER_MCP_READY", "HANDSHAKE_REQUIRED", "REQUESTOR_SUPERVISOR_START"],
  );
  assert.deepEqual(
    [
      coordinatorReport.mcpMilestones[0].stage,
      coordinatorReport.mcpMilestones[1].stage,
      payerResult.transitions[0].message.kind === "proposal" ? "PROPOSED" : null,
      payerResult.transitions[1].message.kind === "acceptance" && payerResult.transitions[1].message.decision === "ACCEPT"
        ? "ACCEPTED"
        : null,
      payerResult.transitions[2].message.outcome,
      verdict.outcome,
    ],
    ["PAYER_MCP_READY", "HANDSHAKE_REQUIRED", "PROPOSED", "ACCEPTED", "ACKNOWLEDGED", "AUTHORIZED"],
  );
  assert.match(coordinatorReport.release.releaseId, /^release-[0-9a-f]{16}$/);
  assert.equal(coordinatorReport.release.repositorySha, session.repositorySha);
  assert.match(coordinatorReport.release.sessionId, /^[0-9a-f-]{36}$/);
  assert.equal(descriptorEnvelope.descriptor.payer.displayName, "Payer");
  assert.equal(descriptorEnvelope.descriptor.payee.displayName, "Requestor");
  assert.equal(stakeholderDescriptorEnvelope.descriptor.payer.displayName, "Payer");
  assert.equal(stakeholderDescriptorEnvelope.descriptor.payee.displayName, "Requestor");
  assert.notEqual(stakeholderDescriptorEnvelope.descriptor.payer.agentId, descriptorEnvelope.descriptor.payer.agentId);
  assert.notEqual(stakeholderDescriptorEnvelope.descriptor.payee.agentId, descriptorEnvelope.descriptor.payee.agentId);
  assert.ok(Array.isArray(coordinatorReport.authenticatedRelayEvents));
  assert.equal(coordinatorReport.coordinatorState, "COMPLETE");
  assert.match(coordinatorReport.verifierPublicationDigest, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(coordinatorReport.verifierPublications).sort(), ["rehearsal", "stakeholder"]);
  assert.equal(coordinatorReport.verifierPublications.rehearsal, coordinatorReport.verifierPublicationDigest);
  assert.match(coordinatorReport.verifierPublications.stakeholder, /^[0-9a-f]{64}$/);
  assert.notEqual(coordinatorReport.verifierPublications.rehearsal, coordinatorReport.verifierPublications.stakeholder);
  assert.deepEqual(
    coordinatorReport.authenticatedRelayEvents
      .map((event) => `${event.role}:${event.kind}:${event.subjectRun}`)
      .sort(),
    EXPECTED_TWO_RUN_RELAY_EFFECTS,
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
  assert.equal(verificationEvents.length, 2);
  assert.deepEqual(
    verificationEvents.map(({ artifactDigest, subjectRun }) => [subjectRun, artifactDigest]),
    [
      ["rehearsal", coordinatorReport.verifierPublications.rehearsal],
      ["stakeholder", coordinatorReport.verifierPublications.stakeholder],
    ],
  );
  assert.ok(
    coordinatorReport.authenticatedRelayEvents.findIndex(({ kind, subjectRun }) => kind === "VERIFICATION_PASSED" && subjectRun === "rehearsal") <
    coordinatorReport.authenticatedRelayEvents.findIndex(({ kind, subjectRun }) => kind === "REGISTER_STAKEHOLDER" && subjectRun === "stakeholder"),
  );
  for (const run of ["rehearsal", "stakeholder"]) {
    const verifier = coordinatorReport.verifiers[run];
    assert.ok(Number.isInteger(verifier.pid) && verifier.pid > 0);
    const counterDelta = Object.fromEntries(Object.keys(verifier.readCountersAfterVerifier).map((key) => [
      key,
      verifier.readCountersAfterVerifier[key] - verifier.readCountersBeforeVerifier[key],
    ]));
    assert.deepEqual(counterDelta, {
      generateAuditTrail: 3,
      getBlock: 5,
      resolveAgent: 5,
      searchActions: 4,
      snapshot: 1,
      verifyCrossParty: 3,
    });
  }
  const pids = [
    session.fake.child.pid,
    session.relay.child.pid,
    coordinatorReport.coordinatorPid,
    coordinatorReport.payee.pid,
    coordinatorReport.payer.pid,
    coordinatorReport.verifiers.rehearsal.pid,
    coordinatorReport.verifiers.stakeholder.pid,
  ];
  assert.notEqual(coordinatorReport.verifiers.rehearsal.pid, coordinatorReport.verifiers.stakeholder.pid);
  assert.equal(new Set(pids).size, 7);
  assert.ok(pids.every((pid) => Number.isInteger(pid) && pid > 0));
  for (const value of [snapshot, coordinatorReport, payerResult, payeeResult, verdict, stakeholderPayerResult, stakeholderPayeeResult, stakeholderVerdict]) assertPaymentNeverMoved(value);
  const protocolReferences = (result) => ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(result.sessionDigest, slot));
  const protocolAnchorsFor = (result) => snapshot.calls.logAction.filter(({ asset_reference_id }) => protocolReferences(result).includes(asset_reference_id));
  const protocolAnchors = protocolAnchorsFor(payerResult);
  const stakeholderProtocolAnchors = protocolAnchorsFor(stakeholderPayerResult);
  assert.deepEqual(protocolAnchors.map(({ asset_reference_id }) => asset_reference_id), protocolReferences(payerResult));
  assert.deepEqual(stakeholderProtocolAnchors.map(({ asset_reference_id }) => asset_reference_id), protocolReferences(stakeholderPayerResult));
  assert.equal(protocolAnchors.length, 3);
  assert.equal(stakeholderProtocolAnchors.length, 3);
  assert.deepEqual(
    snapshot.calls.logAction.map(({ asset_reference_id }) => asset_reference_id),
    [...protocolReferences(payerResult), ...protocolReferences(stakeholderPayerResult)],
  );
  assert.equal(snapshot.writeCount, 6);
  assert.equal(snapshot.calls.logAction.length, 6);
  const preflightSnapshot = JSON.parse(await readFile(session.preflightFakeState, "utf8"));
  assert.equal(preflightSnapshot.writeCount, 2);
  assert.equal(preflightSnapshot.paymentMoved, false);
  await assertOrderedPreflightWrites(session, preflightSnapshot);
  assert.equal(payerResult.transitions.length, 3);
  assert.ok(payeeResult.transitions.length >= 2);
  assert.deepEqual(payeeResult.transitions.slice(0, 2), payerResult.transitions.slice(0, 2));
  assert.deepEqual(payerResult.transitions.map(({ message }) => message.kind), ["proposal", "acceptance", "acknowledgment"]);
  assert.equal(payerResult.transitions.at(-1).message.outcome, "ACKNOWLEDGED");
  assert.equal(payeeResult.transitions[1].message.decision, "ACCEPT");
  assert.equal(stakeholderPayerResult.transitions.length, 3);
  assert.ok(stakeholderPayeeResult.transitions.length >= 2);
  assert.deepEqual(stakeholderPayeeResult.transitions.slice(0, 2), stakeholderPayerResult.transitions.slice(0, 2));
  assert.deepEqual(stakeholderPayerResult.transitions.map(({ message }) => message.kind), ["proposal", "acceptance", "acknowledgment"]);
  assert.equal(stakeholderPayerResult.transitions.at(-1).message.outcome, "ACKNOWLEDGED");
  assert.equal(stakeholderPayeeResult.transitions[1].message.decision, "ACCEPT");
  assert.equal(payerResult.localVerdict, "LOCAL_OK");
  assert.equal(payeeResult.localVerdict, "LOCAL_OK");
  assert.equal(stakeholderPayerResult.localVerdict, "LOCAL_OK");
  assert.equal(stakeholderPayeeResult.localVerdict, "LOCAL_OK");
  assert.equal(verdict.outcome, AUTHORIZE);
  assert.equal(stakeholderVerdict.outcome, AUTHORIZE);
  assert.equal(verdict.transitions.length, 3);
  assert.equal(stakeholderVerdict.transitions.length, 3);
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
  for (const [index, transition] of stakeholderPayerResult.transitions.entries()) {
    const digest = transitionDigest(transition.message);
    assert.equal(transition.digest, digest);
    assert.equal(transition.onChain.anchoredHash, digest);
    assert.equal(stakeholderProtocolAnchors[index].asset_hash, digest);
    assert.deepEqual(transition.message.amount, { currency: "USD", moved: false, value: "100" });
    assert.deepEqual(stakeholderVerdict.transitions[index], {
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
  const [stakeholderProposal, stakeholderAcceptance, stakeholderAcknowledgment] = stakeholderPayerResult.transitions;
  assert.equal(proposal.message.predecessor, null);
  assert.deepEqual(acceptance.message.predecessor, triple(proposal));
  assert.deepEqual(acknowledgment.message.predecessor, triple(acceptance));
  assert.deepEqual(acknowledgment.message.proposal, triple(proposal));
  assert.equal(stakeholderProposal.message.predecessor, null);
  assert.deepEqual(stakeholderAcceptance.message.predecessor, triple(stakeholderProposal));
  assert.deepEqual(stakeholderAcknowledgment.message.predecessor, triple(stakeholderAcceptance));
  assert.deepEqual(stakeholderAcknowledgment.message.proposal, triple(stakeholderProposal));
  assert.equal(new Set(payerResult.transitions.map((transition) => transition.onChain.ledgerId)).size, 3);
  assert.equal(new Set(stakeholderPayerResult.transitions.map((transition) => transition.onChain.ledgerId)).size, 3);
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
  const payerCli = lastJsonLine(await readFile(session.logs.payer.stdout, "utf8"), (line) => Object.hasOwn(line, "state"));
  const payeeCli = lastJsonLine(await readFile(session.logs.payee.stdout, "utf8"), (line) => Object.hasOwn(line, "state"));
  const payerStdoutLines = parseJsonLines(await readFile(session.logs.payer.stdout, "utf8"));
  const payeeStdoutLines = parseJsonLines(await readFile(session.logs.payee.stdout, "utf8"));
  assert.equal(payerStdoutLines.filter((line) => line.status === "PAYER_MCP_READY").length, 1);
  assert.equal(payeeStdoutLines.filter((line) => line.status === "HANDSHAKE_REQUIRED").length, 1);
  assert.equal(payeeStdoutLines.filter((line) => line.status === "REQUESTOR_SUPERVISOR_START").length, 1);
  assert.equal(payerStdoutLines.filter((line) => line.state === "ACKNOWLEDGED" && line.status !== "PARTY_COMPLETE").length, 2);
  assert.equal(payeeStdoutLines.filter((line) => line.state === "ACCEPTED" && line.status !== "PARTY_COMPLETE").length, 2);
  assert.equal(payerCli.state, "ACKNOWLEDGED");
  assert.equal(payeeCli.state, "ACCEPTED");
  const requestorIntakeResult = JSON.parse(await readFile(join(session.roleRoots.payee, "payer-mcp-handshake-required.json"), "utf8"));
  const intakeRequestId = requestorIntakeResult.intakeRequestId;
  assert.match(intakeRequestId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(intakeRequestId, PAYER_MCP_INTAKE_REQUEST_ID);
  const payerIntakeRecord = JSON.parse(await readFile(join(session.roleRoots.payer, "payer-mcp-intake", `${intakeRequestId}.json`), "utf8"));
  assert.deepEqual(await readdir(join(session.roleRoots.payer, "payer-mcp-intake")), [`${intakeRequestId}.json`]);
  assert.equal(payerIntakeRecord.intakeRequestId, intakeRequestId);
  assert.equal(payerIntakeRecord.intakeDigest, requestorIntakeResult.intakeDigest);
  const bootstrapBrokerJournal = JSON.parse(await readFile(join(
    session.roleRoots.payer,
    "requestor-bootstrap-broker",
    BOOTSTRAP_BROKER_JOURNAL_FILE,
  ), "utf8"));
  assert.equal(bootstrapBrokerJournal.schema, "clockchain.requestor-bootstrap-broker-journal/v1");
  assert.equal(bootstrapBrokerJournal.repositorySha, session.repositorySha);
  const bootstrapBrokerClaims = Object.values(bootstrapBrokerJournal.claims);
  assert.equal(bootstrapBrokerClaims.length, 1);
  assert.equal(bootstrapBrokerClaims[0].status, "SEALED");
  assert.equal(bootstrapBrokerClaims[0].paymentMoved, false);
  assert.equal(bootstrapBrokerClaims[0].claim.paymentMoved, false);
  assert.equal(bootstrapBrokerClaims[0].sealedResponse.status, "SEALED");
  assert.equal(bootstrapBrokerClaims[0].sealedResponse.paymentMoved, false);
  const mandate = JSON.parse(await readFile(join(session.roleRoots.payer, "rehearsal", "payer-mandate.json"), "utf8"));
  const request = JSON.parse(await readFile(join(session.roleRoots.payee, "rehearsal", "payment-request.json"), "utf8"));
  const stakeholderMandate = JSON.parse(await readFile(join(session.roleRoots.payer, "stakeholder", "payer-mandate.json"), "utf8"));
  const stakeholderRequest = JSON.parse(await readFile(join(session.roleRoots.payee, "stakeholder", "payment-request.json"), "utf8"));
  assert.equal(mandate.mandate.intakeRequestId, intakeRequestId);
  assert.equal(request.request.intakeRequestId, intakeRequestId);
  assert.equal(stakeholderMandate.mandate.intakeRequestId, intakeRequestId);
  assert.equal(stakeholderRequest.request.intakeRequestId, intakeRequestId);
  assert.equal(mandate.mandate.intakeDigest, payerIntakeRecord.intakeDigest);
  assert.equal(request.request.intakeDigest, payerIntakeRecord.intakeDigest);
  assert.equal(stakeholderMandate.mandate.intakeDigest, payerIntakeRecord.intakeDigest);
  assert.equal(stakeholderRequest.request.intakeDigest, payerIntakeRecord.intakeDigest);
  await assertCompletion(session.outputs.payer, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(session.outputs.payee, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(session.outputs.verifier, ".bilateral-verdict.complete.json", "bilateral-verdict.json", "BILATERAL-VERDICT.md");
  await assertCompletion(stakeholderOutputs.payer, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(stakeholderOutputs.payee, ".party-result.complete.json", "party-result.json", "PARTY-RESULT.md");
  await assertCompletion(stakeholderOutputs.verifier, ".bilateral-verdict.complete.json", "bilateral-verdict.json", "BILATERAL-VERDICT.md");
  const consolePort = await availablePort();
  const startConsole = () => spawned([
    "bin/handshake-console.mjs",
    "--host", "127.0.0.1",
    "--port", String(consolePort),
    "--state-root", session.releaseRoot,
  ], {
    cwd: ROOT,
    env: {
      ...process.env,
      CLOCKCHAIN_BILATERAL_TEST_CLOCK_MS: String(SHARED_TEST_CLOCK_MS),
      NODE_OPTIONS: [
        process.env.NODE_OPTIONS,
        `--import=${join(ROOT, "test/helpers/bilateral-fixed-clock.mjs")}`,
      ].filter(Boolean).join(" "),
    },
  });
  const fetchConsole = async (process_) => {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if (process_.output().stdout === "Handshake console listening.\n") {
        const response = await fetch(`http://127.0.0.1:${consolePort}/v1/console/session`);
        assert.equal(response.status, 200);
        return response.json();
      }
      if (process_.child.exitCode !== null) assert.fail(process_.output().stderr);
      await sleep(10);
    }
    assert.fail("console readiness deadline expired");
  };
  const firstConsole = startConsole();
  t.after(() => stop(firstConsole.child));
  const firstProjection = await fetchConsole(firstConsole);
  await stop(firstConsole.child);
  const restartedConsole = startConsole();
  t.after(() => stop(restartedConsole.child));
  const restartedProjection = await fetchConsole(restartedConsole);
  await stop(restartedConsole.child);
  for (const projection of [firstProjection, restartedProjection]) {
    assert.equal(projection.paymentMoved, false);
    assert.equal(projection.verifier.status, CONSOLE_VERIFICATION_PASSED);
    assert.equal(projection.verifier.advisory, false);
    assert.deepEqual(
      Object.fromEntries(Object.entries(projection.actors).map(([role, actor]) => [role, actor.health])),
      { operator: "UNAVAILABLE", payee: "UNAVAILABLE", payer: "UNAVAILABLE" },
    );
    assert.deepEqual(
      Object.fromEntries(Object.entries(projection.session.observations).map(([service, observation]) => [service, observation.health])),
      { relay: "UNAVAILABLE", watcher: "UNAVAILABLE" },
    );
    assert.deepEqual(projection.anchors.map(({ digest }) => digest), stakeholderPayerResult.transitions.map(({ digest }) => digest));
    assert.equal(projection.session.releaseId, coordinatorReport.release.releaseId);
    assert.equal(projection.session.repositorySha, coordinatorReport.release.repositorySha);
    assert.equal(projection.session.sessionId, coordinatorReport.release.sessionId);
  }
  assert.equal(firstConsole.output().stdout.includes("AUTHORIZED"), false);
  assert.equal(firstConsole.output().stderr.includes("AUTHORIZED"), false);
  assert.equal(restartedConsole.output().stdout.includes("AUTHORIZED"), false);
  assert.equal(restartedConsole.output().stderr.includes("AUTHORIZED"), false);
  await assertPrivateFile(coordinatorReport.consoleStatePath);
  const namedLogs = Object.fromEntries(await Promise.all(["payer", "payee"].map(async (name) => [name, {
    stderr: await readFile(session.logs[name].stderr, "utf8"),
    stdout: await readFile(session.logs[name].stdout, "utf8"),
  }])));
  const verifierLogs = Object.fromEntries(await Promise.all(["rehearsal", "stakeholder"].map(async (run) => [run, {
    stderr: await readFile(coordinatorReport.verifiers[run].logs.stderr, "utf8"),
    stdout: await readFile(coordinatorReport.verifiers[run].logs.stdout, "utf8"),
  }])));
  for (const log of Object.values(verifierLogs)) {
    assert.equal(log.stdout, `${AUTHORIZE}\n`);
    assert.equal(log.stderr, "");
  }
  for (const log of Object.values(namedLogs)) {
    assert.equal(log.stdout.includes(AUTHORIZE), false);
    assert.equal(log.stderr.includes(AUTHORIZE), false);
  }
  const payerStatusLines = parseJsonLines(namedLogs.payer.stdout);
  const payeeStatusLines = parseJsonLines(namedLogs.payee.stdout);
  assert.deepEqual(
    payerStatusLines.filter((line) => line.status === "PARTY_COMPLETE"),
    [{ paymentMoved: false, role: "payer", state: "ACKNOWLEDGED", status: "PARTY_COMPLETE" }],
  );
  assert.deepEqual(
    payeeStatusLines.filter((line) => line.status === "PARTY_COMPLETE"),
    [{ paymentMoved: false, role: "payee", state: "ACCEPTED", status: "PARTY_COMPLETE" }],
  );
  for (const line of [...payerStatusLines, ...payeeStatusLines]) {
    assert.notEqual(line.state, AUTHORIZE);
    assert.notEqual(line.status, AUTHORIZE);
  }
  const fundingLines = coordinatorExit.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)).filter(({ schema }) => schema === "clockchain.bilateral-funding-addresses/v1");
  assert.equal(fundingLines.length, 1);
  assert.equal(fundingLines[0].addresses.length, 4);
  assert.equal(new Set(fundingLines[0].addresses).size, 4);
  assert.ok(fundingLines[0].addresses.every((address) => /^0x[0-9a-f]{40}$/.test(address)));
  const fundingInvitationPaths = {
    payeeRehearsal: join(session.roleRoots.payee, "invitation-secret", "payee-rehearsal.secret.json"),
    payeeStakeholder: join(session.roleRoots.payee, "invitation-secret", "payee-stakeholder.secret.json"),
    payerRehearsal: join(session.roleRoots.payer, "invitation-secret", "payer-rehearsal.secret.json"),
    payerStakeholder: join(session.roleRoots.payer, "invitation-secret", "payer-stakeholder.secret.json"),
  };
  const invitationAddress = async (path) => {
    const secret = JSON.parse(await readFile(path, "utf8"));
    return (await decryptInvitation(secret.bundle, secret.code)).address.toLowerCase();
  };
  assert.deepEqual(fundingLines[0].addresses, [
    await invitationAddress(fundingInvitationPaths.payerRehearsal),
    await invitationAddress(fundingInvitationPaths.payeeRehearsal),
    await invitationAddress(fundingInvitationPaths.payerStakeholder),
    await invitationAddress(fundingInvitationPaths.payeeStakeholder),
  ]);
  const fundingAddressBytes = await assertPrivateFile(join(session.releaseRoot, "funding-addresses.json"));
  assert.equal(fundingAddressBytes.toString("utf8"), `${JSON.stringify(fundingLines[0])}\n`);
  assert.equal(coordinatorExit.stdout.includes(AUTHORIZE), false);
  assert.equal(coordinatorExit.stderr.includes(AUTHORIZE), false);
  assert.equal(session.fake.output().stdout.includes(AUTHORIZE), false);
  assert.equal(session.fake.output().stderr.includes(AUTHORIZE), false);
  assert.equal(session.relay.output().stdout.includes(AUTHORIZE), false);
  assert.equal(session.relay.output().stderr.includes(AUTHORIZE), false);
  const canaries = ["operator-process-token", "payer-process-token", "payee-process-token"];
  const persistedCanarySurfaces = [
    coordinatorExit.stdout,
    coordinatorExit.stderr,
    session.fake.output().stdout,
    session.fake.output().stderr,
    session.relay.output().stdout,
    session.relay.output().stderr,
    JSON.stringify(firstProjection),
    JSON.stringify(restartedProjection),
    await readFile(session.fakeState, "utf8"),
    await readFile(session.preflightFakeState, "utf8"),
    await readFile(coordinatorReport.consoleStatePath, "utf8"),
    await readFile(session.report, "utf8"),
    ...await Promise.all(["payer", "payee"].flatMap((name) => [
      readFile(session.logs[name].stdout, "utf8"),
      readFile(session.logs[name].stderr, "utf8"),
    ])),
    ...await Promise.all(["rehearsal", "stakeholder"].flatMap((run) => [
      readFile(coordinatorReport.verifiers[run].logs.stdout, "utf8"),
      readFile(coordinatorReport.verifiers[run].logs.stderr, "utf8"),
    ])),
    ...(await Promise.all((await readdir(join(session.root, "relay-state"), { recursive: true })).map(async (name) => {
      const path = join(session.root, "relay-state", name);
      const info = await lstat(path);
      return info.isFile() ? readFile(path, "utf8") : "";
    }))),
  ];
  for (const canary of canaries) {
    assert.ok(persistedCanarySurfaces.every((text) => !text.includes(canary)), canary);
  }
  assert.equal((await readFile(new URL("helpers/bilateral-coordination-child.mjs", import.meta.url), "utf8")).includes(AUTHORIZE), false);
  await assertPrivateFile(session.report, { canonical: true });
  for (const log of [session.logs.payer, session.logs.payee, coordinatorReport.verifiers.rehearsal.logs, coordinatorReport.verifiers.stakeholder.logs]) {
    await assertPrivateFile(log.stdout);
    await assertPrivateFile(log.stderr);
  }
  for (const root of Object.values(session.roleRoots)) await assertRoot(root);
  assert.notEqual(session.roleRoots.payer, session.roleRoots.payee);
  const roleConfigurations = [session.configurations.payer, session.configurations.payee];
  const [payerConfiguration, payeeConfiguration] = await Promise.all(roleConfigurations.map(async (path) => JSON.parse(await readFile(path, "utf8"))));
  assert.equal(payeeConfiguration.launchManifestPath, null);
  assert.deepEqual(Object.keys(payeeConfiguration.requestPayment), ["discoveryUrl", "intakeRequestId"]);
  assert.match(payeeConfiguration.requestPayment.discoveryUrl, /^https:\/\/127\.0\.0\.1:[0-9]+\/requestor-discovery\.json$/);
  assert.equal(JSON.stringify(payeeConfiguration.requestPayment).includes("launchManifest"), false);
  assert.equal(JSON.stringify(payeeConfiguration.requestPayment).includes("certificate"), false);
  assert.equal(JSON.stringify(payeeConfiguration.requestPayment).includes("fingerprint"), false);
  assert.equal(JSON.stringify(payeeConfiguration.requestPayment).includes("capability"), false);
  assert.equal(payerConfiguration.payerMcpServer.bootstrapBrokerUrl.startsWith("http://127.0.0.1:"), true);
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
  const outputRoots = [...Object.values(session.outputs), ...Object.values(stakeholderOutputs)];
  assert.equal(new Set(outputRoots).size, 6);
  for (const output of outputRoots) await assertRoot(output);
  for (const pid of [
    coordinatorReport.coordinatorPid,
    coordinatorReport.payer.pid,
    coordinatorReport.payee.pid,
    coordinatorReport.verifiers.rehearsal.pid,
    coordinatorReport.verifiers.stakeholder.pid,
  ]) assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
  for (const pid of [session.fake.child.pid, session.relay.child.pid]) assert.doesNotThrow(() => process.kill(pid, 0));
});

test("relay restarts after mandate and after request fail closed without authorization", { concurrency: false }, async (t) => {
  for (const [scenario, stage] of [
    ["relay-restart-after-mandate", "mandate-ready"],
    ["relay-restart-after-request", "request-ready"],
  ]) {
    await t.test(stage, { concurrency: false }, async (t) => {
      const session = await createProcessSession(t, { barrier: true, scenario });
      const coordinator = session.startCoordinator();
      t.after(() => stopGroup(coordinator.child));
      try {
        await waitForPrivateMarker(session.barrier.ready, {
          schema: COORDINATOR_SCHEMA,
          stage,
        }, coordinator);
      } catch (error) {
        const phase = await readFile(`${session.report}.phase`, "utf8").catch(() => "");
        const roleLogs = await Promise.all(["payer", "payee"].flatMap((role) => [
          readFile(session.logs[role].stdout, "utf8").catch(() => ""),
          readFile(session.logs[role].stderr, "utf8").catch(() => ""),
        ]));
        throw new Error(
          `${scenario}: ${error.message}\nphase=${JSON.stringify(phase.trim())}`
          + `\ncoordinator=${JSON.stringify(coordinator.output())}\nroles=${roleLogs.join("\\n")}`,
        );
      }
      await stop(session.relay.child);
      const restartedRelay = await session.restartRelay();
      await canonicalPrivateExclusive(session.barrier.release, { release: true });
      let exit;
      try {
        exit = await within(coordinator.wait(), PROCESS_PHASE_DEADLINE_MS);
      } catch (error) {
        const roleLogs = await Promise.all(["payer", "payee"].flatMap((role) => [
          readFile(session.logs[role].stdout, "utf8").catch(() => ""),
          readFile(session.logs[role].stderr, "utf8").catch(() => ""),
        ]));
        throw new Error(`${scenario}: ${error.message}\ncoordinator=${JSON.stringify(coordinator.output())}\nroles=${roleLogs.join("\\n")}\nrelay=${JSON.stringify(restartedRelay.output())}`);
      }
      assert.notEqual(exit.code, 0);
      assert.equal(exit.signal, null);
      assert.match(exit.stderr, /^PROCESS_CHILD_FAILED:coordinator-run-rehearsal_identities_ready:/m);
      await assert.rejects(readFile(session.report, "utf8"), { code: "ENOENT" });
      assert.equal(JSON.parse(await readFile(session.fakeState, "utf8")).writeCount, 0);
      for (const output of [exit.stdout, exit.stderr, session.relay.output().stdout, session.relay.output().stderr, restartedRelay.output().stdout, restartedRelay.output().stderr]) {
        assert.equal(output.includes(AUTHORIZE), false);
      }
    });
  }
});

test("coordinator restart before descriptor resumes durable intent state", { concurrency: false }, async (t) => {
  const session = await createProcessSession(t, { barrier: true, scenario: "coordinator-restart-before-descriptor" });
  const first = session.startCoordinator();
  t.after(() => stopGroup(first.child));
  await waitForPrivateMarker(session.barrier.ready, {
    schema: COORDINATOR_SCHEMA,
    stage: "intents-ready",
  }, first);
  const survivingSupervisors = await descendantPids(first.child.pid);
  assert.equal(survivingSupervisors.length, 2);
  t.after(() => stopPids(survivingSupervisors));
  await stop(first.child);
  for (const pid of survivingSupervisors) assert.doesNotThrow(() => process.kill(pid, 0));
  await assert.rejects(readFile(session.report, "utf8"), { code: "ENOENT" });
  await canonicalPrivateExclusive(session.barrier.release, { release: true });
  const restarted = session.startCoordinator();
  t.after(() => stopGroup(restarted.child));
  const exit = await within(restarted.wait(), PROCESS_PHASE_DEADLINE_MS);
  assert.deepEqual(
    { code: exit.code, signal: exit.signal },
    { code: 0, signal: null },
    `${exit.stderr}\n${first.output().stderr}\nphase=${await readFile(`${session.report}.phase`, "utf8").catch(() => "missing")}`,
  );
  const report = JSON.parse(await readFile(session.report, "utf8"));
  assert.equal(report.coordinatorState, "REHEARSAL_VERIFIED");
  assert.equal(JSON.parse(await readFile(session.fakeState, "utf8")).writeCount, 3);
  assert.ok([first.output().stdout, first.output().stderr, exit.stdout, exit.stderr].every((output) => !output.includes(AUTHORIZE)));
  await stopPids(survivingSupervisors);
  for (const pid of survivingSupervisors) assert.throws(() => process.kill(pid, 0), { code: "ESRCH" });
});

test("isolated process faults fail closed before authorizing output", { concurrency: false }, async (t) => {
  const expectedFailurePhases = {
    "missing-mandate": "coordinator-run-(?:preflight_passed|funding_ready)",
    "forged-iris-signature": "coordinator-run-(?:preflight_passed|funding_ready)",
    "wrong-billie-signer": "coordinator-run-(?:preflight_passed|funding_ready)",
    "invoice-prefix-mismatch": "coordinator-run-(?:preflight_passed|funding_ready)",
    "request-replay-changed-bytes": "coordinator-run-(?:preflight_passed|funding_ready)",
    "expired-mandate": "coordinator-run-(?:preflight_passed|funding_ready)",
    "expired-request": "coordinator-run-(?:preflight_passed|funding_ready)",
    "descriptor-swap": "coordinator-verifier",
    "fourth-write": "coordinator-verifier",
    "stale-verifier-publication": "coordinator-verifier-after-snapshot",
    "mismatched-verifier-publication": "coordinator-verifier-after-snapshot",
  };
  for (const scenario of PROCESS_FAILURE_SCENARIOS) {
    await t.test(scenario, { concurrency: false }, async (t) => {
      const session = await createProcessSession(t, { scenario });
      const coordinator = session.startCoordinator();
      t.after(() => stopGroup(coordinator.child));
      const exit = await within(coordinator.wait(), PROCESS_PHASE_DEADLINE_MS);
      assert.notEqual(exit.code, 0, `${scenario} unexpectedly succeeded`);
      assert.equal(exit.signal, null);
      assert.match(exit.stderr, new RegExp(`^PROCESS_CHILD_FAILED:${expectedFailurePhases[scenario]}:`, "m"), scenario);
      const outputs = await Promise.all([
        Promise.resolve(exit.stdout),
        Promise.resolve(exit.stderr),
        ...["payer", "payee", "verifier"].flatMap((name) => [
          readFile(session.logs[name].stdout, "utf8").catch(() => ""),
          readFile(session.logs[name].stderr, "utf8").catch(() => ""),
        ]),
      ]);
      assert.equal(outputs.some((text) => text.includes(AUTHORIZE)), false, scenario);
      const snapshot = await readFile(session.fakeState, "utf8")
        .then((text) => JSON.parse(text))
        .catch((error) => {
          if (error?.code !== "ENOENT") throw error;
          return { paymentMoved: false, writeCount: 0 };
        });
      assert.equal(snapshot.paymentMoved, false, scenario);
      assert.equal(
        snapshot.writeCount,
        ["descriptor-swap", "fourth-write", "stale-verifier-publication", "mismatched-verifier-publication"].includes(scenario) ? 3 : 0,
        scenario,
      );
      assert.equal(JSON.parse(await readFile(session.preflightFakeState, "utf8")).writeCount, 2, scenario);
    });
  }
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
  await cp(
    join(ROOT, "test/helpers/bilateral-relay-child.mjs"),
    join(clone, "test/helpers/bilateral-relay-child.mjs"),
  );
  await command("/usr/bin/git", ["add", "--all"], { cwd: clone });
  await command(
    "/usr/bin/git",
    ["-c", "user.email=relay-restart@example.invalid", "-c", "user.name=Relay Restart", "commit", "--quiet", "-m", "relay restart fixture"],
    { cwd: clone },
  );
  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1"]);
  await chmod(certificateKey, 0o600);
  const ca = await readFile(certificate, "utf8");
  const fingerprint = certificateFingerprint(ca);
  const state = join(root, "relay-state");
  await mkdir(state, { mode: 0o700 });
  const port = await availablePort();
  const repositorySha = (await command("/usr/bin/git", ["rev-parse", "HEAD"], { cwd: clone })).stdout.trim();
  await command("/usr/bin/git", ["update-ref", "--no-deref", "HEAD", repositorySha], { cwd: clone });
  assert.equal((await command("/usr/bin/git", ["status", "--porcelain=v1"], { cwd: clone })).stdout, "");
  const arguments_ = ["test/helpers/bilateral-relay-child.mjs", "--advertised-host", "127.0.0.1", "--host", "127.0.0.1", "--port", String(port), "--repository-sha", repositorySha, "--state", state, "--tls-certificate", certificate, "--tls-private-key", certificateKey];
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
  t.after(() => stopGroup(coordinator.child));

  try {
    await waitForPrivateMarker(session.barrier.ready, {
      schema: COORDINATOR_SCHEMA,
      stage: "roles-complete",
    }, coordinator);
  } catch (error) {
    const phase = await readFile(`${session.report}.phase`, "utf8").catch(() => "");
    const roleLogs = await Promise.all(["payer", "payee"].flatMap((role) => [
      readFile(session.logs[role].stdout, "utf8").catch(() => ""),
      readFile(session.logs[role].stderr, "utf8").catch(() => ""),
    ]));
    throw new Error(
      `relay-crash-before-verifier: ${error.message}\nphase=${JSON.stringify(phase.trim())}`
      + `\ncoordinator=${JSON.stringify(coordinator.output())}\nroles=${roleLogs.join("\\n")}`,
    );
  }
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
  assert.equal(afterCrash.writeCount, 3);
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
  for (const [file, name] of AWS_TOPOLOGY_CITATIONS) {
    const source = await readFile(
      new URL(`../${file}`, import.meta.url),
      "utf8",
    );
    assert.ok(
      source.includes(`test(${JSON.stringify(name)}`),
      `${file} must retain the AWS topology test ${name}`,
    );
  }
});
