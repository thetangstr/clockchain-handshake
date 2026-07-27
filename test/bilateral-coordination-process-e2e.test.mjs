import assert from "node:assert/strict";
import { spawn, execFile as execFileCallback } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, X509Certificate } from "node:crypto";
import { chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { request as httpsRequest } from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { test } from "node:test";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { createSignedEnvelope, dSession, rawPublicKeyBase64FromPem } from "../src/bilateral/descriptor.mjs";
import { transitionDigest } from "../src/bilateral/messages.mjs";
import { sessionKey } from "../src/bilateral/refid.mjs";
import { encryptInvitation } from "../src/invitation.mjs";
import { computeBilateralPromptHash } from "../scripts/hash-bilateral-prompts.mjs";
import { createFakeBilateralClockchainHttpClient } from "./helpers/fake-bilateral-clockchain-service.mjs";

const execFile = promisify(execFileCallback);
const ROOT = new URL("../", import.meta.url).pathname;
const SCHEMA = "clockchain.bilateral-coordination-process-child/v1";
const AUTHORIZE = "AUTHORIZED";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const within = (promise, ms) => Promise.race([
  promise,
  new Promise((_resolve, reject) => setTimeout(
    () => reject(new Error("bounded wait expired")),
    ms,
  )),
]);

const ADVERSARIAL_CITATIONS = Object.freeze([
  ["capability replay", "test/bilateral-coordination-storage.test.mjs", "fails closed on capability expiry, cross-role use, and conflicting replay"],
  ["cross-role capability", "test/bilateral-coordination-storage.test.mjs", "fails closed on capability expiry, cross-role use, and conflicting replay"],
  ["wrong TLS fingerprint", "test/bilateral-coordination-client.test.mjs", "rejects wrong fingerprints, alternate certificates, hostname mismatch, and redirects"],
  ["plaintext downgrade", "test/bilateral-coordination-operator-client.test.mjs", "operator transport rejects plaintext and a certificate/fingerprint mismatch before requests"],
  ["sequence gap", "test/bilateral-coordination-storage.test.mjs", "implements idempotent event retry and fail-closed sender sequencing"],
  ["previous digest mismatch", "test/bilateral-coordination-storage.test.mjs", "implements idempotent event retry and fail-closed sender sequencing"],
  ["dropped event response", "test/bilateral-coordination-operator-client.test.mjs", "operator transport marks lost mutation responses ambiguous"],
  ["duplicated event response", "test/bilateral-coordination-supervisor.test.mjs", "fails closed on replay ordering and authority substitutions"],
  ["oversized artifact", "test/bilateral-coordination-storage.test.mjs", "rejects noncanonical JSON, archives, unknown types, private keys, and oversized artifacts"],
  ["secret-bearing artifact", "test/bilateral-coordination-storage.test.mjs", "rejects noncanonical JSON, archives, unknown types, private keys, and oversized artifacts"],
  ["marker-incomplete package", "test/bilateral-coordination-storage.test.mjs", "rejects structurally incomplete party-result packages"],
  ["artifact replacement", "test/bilateral-coordination-storage.test.mjs", "rejects artifact replacement and duplicate digest with changed bytes"],
  ["funding mismatch", "test/bilateral-coordination-coordinator.test.mjs", "rejects every malformed funding result before FUNDING_READY"],
  ["nonzero invitation nonce", "test/bilateral-coordination-coordinator.test.mjs", "rejects every malformed funding result before FUNDING_READY"],
  ["token commitment mismatch", "test/bilateral-coordination-storage.test.mjs", "accepts exact signed token commitments and rejects wrong signature, key, SHA, role, extra keys, and canaries"],
  ["preflight key mismatch", "test/bilateral-coordination-storage.test.mjs", "accepts exact signed preflight public keys and rejects wrong signature, key, SHA, role, extra keys, and canaries"],
  ["repository change after preflight", "test/bilateral-roles.test.mjs", "default builder fails provenance closed before secrets, clients, or tokens"],
  ["prompt change after preflight", "test/bilateral-roles.test.mjs", "default builder fails provenance closed before secrets, clients, or tokens"],
  ["ambiguous registration write", "test/bilateral-machine-prep.test.mjs", "registration resumes marker publication from matching durable identity bytes without registration rebroadcast"],
  ["ambiguous Clockchain write", "test/bilateral-operational-e2e.test.mjs", "writer crash recovery is discovery-only after one ambiguous dispatch"],
  ["missing protocol anchor", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["duplicate protocol anchor", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["reordered protocol anchor", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["expired protocol anchor", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["package and Clockchain divergence", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["advisory status trap", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["cached timestamp trap", "test/bilateral-operational-e2e.test.mjs", "aggregate verification fails closed across hostile operational evidence"],
  ["role crash", "test/bilateral-coordination-supervisor.test.mjs", "records an exact recovery manifest for an ambiguous role command"],
  ["relay crash", "test/bilateral-coordination-process-e2e.test.mjs", "relay crash before verifier fails closed without spawning a verifier"],
  ["coordinator crash", "test/bilateral-coordination-coordinator.test.mjs", "recovers after durable BOOTSTRAPPING state before pending-journal retirement"],
  ["verifier crash", "test/bilateral-coordination-coordinator-runtime.test.mjs", "verifier child deadline escalates from TERM to KILL for an ignoring child"],
  ["verifier marker disagreement", "test/bilateral-coordination-relay.test.mjs", "trusted verifier seam fails closed when its durable claim disagrees with the event"],
]);

async function command(file, args, options = {}) { return execFile(file, args, { encoding: "utf8", ...options }); }
function canonicalJson(value) { if (value === null || typeof value === "string" || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; }
async function canonicalPrivate(path, value) { await writeFile(path, canonicalJson(value), { mode: 0o600 }); await chmod(path, 0o600); }
async function canonicalPrivateExclusive(path, value) { await writeFile(path, canonicalJson(value), { flag: "wx", mode: 0o600 }); await chmod(path, 0o600); }
async function privatePem(path, key) { await writeFile(path, key.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 }); await chmod(path, 0o600); }
async function waitFor(path, output) { for (let turn = 0; turn < 100; turn += 1) { try { return JSON.parse(await readFile(path, "utf8")); } catch { if (output?.child.exitCode !== null) throw new Error(`readiness process exited: ${output.output().stderr}`); await sleep(20); } } throw new Error(`readiness missing: ${path}`); }
async function waitForPrivateMarker(path, expected, output) {
  for (let turn = 0; turn < 500; turn += 1) {
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
  throw new Error(`readiness missing: ${path}`);
}
function spawned(args, options) { const child = spawn(process.execPath, args, { stdio: ["ignore", "pipe", "pipe"], ...options }); let stdout = ""; let stderr = ""; child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8"); child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; }); return { child, output: () => ({ stderr, stdout }), wait: () => new Promise((resolve, reject) => { child.once("error", reject); child.once("close", (code, signal) => resolve({ code, signal, stderr, stdout })); }) }; }
async function stop(process_) { if (process_.exitCode !== null || process_.signalCode !== null) return; process_.kill("SIGTERM"); await Promise.race([new Promise((resolve) => process_.once("close", resolve)), sleep(1_000)]); if (process_.exitCode === null && process_.signalCode === null) { process_.kill("SIGKILL"); await new Promise((resolve) => process_.once("close", resolve)); } }
async function availablePort() { const server = createServer(); await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); }); const { port } = server.address(); await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())); return port; }
function certificateFingerprint(certificate) { return createHash("sha256").update(new X509Certificate(certificate).raw).digest("hex"); }
async function relayReady(process_) { let buffer = ""; return new Promise((resolve, reject) => { process_.child.stdout.on("data", (chunk) => { buffer += chunk; const end = buffer.indexOf("\n"); if (end >= 0) { try { resolve(JSON.parse(buffer.slice(0, end))); } catch (error) { reject(error); } } }); process_.child.once("error", reject); process_.child.once("close", (code, signal) => { if (!buffer.includes("\n")) reject(new Error(`relay exited before readiness: ${code}/${signal}: ${process_.output().stderr}`)); }); }); }
function pinnedGet({ ca, fingerprint, path, port }) { return new Promise((resolve, reject) => { const request = httpsRequest({ ca, host: "127.0.0.1", method: "GET", path, port, rejectUnauthorized: true, servername: "localhost", headers: { host: `127.0.0.1:${port}` } }, (response) => { const peer = response.socket.getPeerCertificate(true); const actual = peer.raw && createHash("sha256").update(peer.raw).digest("hex"); if (actual !== fingerprint) { response.destroy(); reject(new Error("relay fingerprint mismatch")); return; } const chunks = []; response.on("data", (chunk) => chunks.push(chunk)); response.once("end", () => resolve({ body: Buffer.concat(chunks), statusCode: response.statusCode })); }); request.once("error", reject); request.end(); }); }
function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function triple(transition) { return { anchoredHash: transition.onChain.anchoredHash, blockHeight: transition.onChain.blockHeight, kind: transition.message.kind, ledgerId: transition.onChain.ledgerId }; }
function assertPaymentNeverMoved(value) { if (Array.isArray(value)) return value.forEach(assertPaymentNeverMoved); if (value !== null && typeof value === "object") { for (const [key, child] of Object.entries(value)) { if (key === "paymentMoved") assert.equal(child, false); assertPaymentNeverMoved(child); } } }
async function assertPrivateFile(path, { canonical = false } = {}) { const info = await lstat(path); assert.equal(info.isFile(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.nlink, 1); assert.equal(info.mode & 0o777, 0o600); const bytes = await readFile(path); if (canonical) assert.equal(bytes.toString("utf8"), canonicalJson(JSON.parse(bytes.toString("utf8")))); return bytes; }
async function assertRoot(path) { const info = await lstat(path); assert.equal(info.isDirectory(), true); assert.equal(info.isSymbolicLink(), false); assert.equal(info.mode & 0o777, 0o700); }
async function assertCompletion(directory, marker, json, markdown) { const bytes = await assertPrivateFile(join(directory, marker)); const text = bytes.toString("utf8"); assert.equal(text, `${canonicalJson(JSON.parse(text))}\n`); const value = JSON.parse(text); assert.equal(value.jsonSha256, sha256(await readFile(join(directory, json)))); assert.equal(value.markdownSha256, sha256(await readFile(join(directory, markdown)))); }

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
  await command("git", ["clone", "--no-hardlinks", ROOT, clone]);
  await writeFile(join(clone, ".git/info/exclude"), "node_modules\n");
  await symlink(join(ROOT, "node_modules"), join(clone, "node_modules"));
  await cp(
    join(ROOT, "test/helpers/bilateral-coordination-child.mjs"),
    join(clone, "test/helpers/bilateral-coordination-child.mjs"),
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
  await command(
    "git",
    ["add", "test/helpers/bilateral-coordination-child.mjs", "docs/operator-keys/process-e2e-operator.pub"],
    { cwd: clone },
  );
  await command(
    "git",
    ["-c", "user.email=e2e@example.invalid", "-c", "user.name=Process E2E", "commit", "-m", "process e2e fixture"],
    { cwd: clone },
  );
  const repositorySha = (await command("git", ["rev-parse", "HEAD"], { cwd: clone })).stdout.trim();
  assert.equal((await command("git", ["status", "--porcelain=v1"], { cwd: clone })).stdout, "");

  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=localhost", "-days", "1"]);
  const relayFingerprint = certificateFingerprint(await readFile(certificate));

  const payerPrivateKey = generatePrivateKey();
  const payeePrivateKey = generatePrivateKey();
  const payer = privateKeyToAccount(payerPrivateKey);
  const payee = privateKeyToAccount(payeePrivateKey);
  assert.notEqual(payerPrivateKey, payeePrivateKey);
  assert.notEqual(payer.address.toLowerCase(), payee.address.toLowerCase());
  const owners = {
    "8677": payer.address.toLowerCase(),
    "8678": payee.address.toLowerCase(),
  };
  const invitations = {
    payer: join(roleRoots.payer, "invitation.json"),
    payee: join(roleRoots.payee, "invitation.json"),
  };
  for (const [path, account, privateKeyText, name] of [
    [invitations.payer, payer, payerPrivateKey, "Billy"],
    [invitations.payee, payee, payeePrivateKey, "Iris"],
  ]) {
    const code = randomBytes(24).toString("base64url");
    const bundle = await encryptInvitation({
      address: account.address.toLowerCase(),
      displayName: name,
      privateKey: privateKeyText,
    }, code);
    await canonicalPrivate(path, { bundle, code });
  }
  const tokens = {
    payer: join(roleRoots.payer, "clockchain.token"),
    payee: join(roleRoots.payee, "clockchain.token"),
  };
  await writeFile(tokens.payer, "payer-process-token\n", { mode: 0o600 });
  await writeFile(tokens.payee, "payee-process-token\n", { mode: 0o600 });
  await chmod(tokens.payer, 0o600);
  await chmod(tokens.payee, 0o600);
  const createPrivateKey = async (role, name) => {
    const { privateKey: rolePrivateKey, publicKey: rolePublicKey } = generateKeyPairSync("ed25519");
    const path = join(roleRoots[role], `${name}.pem`);
    await privatePem(path, rolePrivateKey);
    return {
      path,
      publicKey: rawPublicKeyBase64FromPem(rolePublicKey.export({ format: "pem", type: "spki" })),
    };
  };
  const coordinationKeys = {
    payer: await createPrivateKey("payer", "coordination-private"),
    payee: await createPrivateKey("payee", "coordination-private"),
  };
  const preflightKeys = {
    payer: await createPrivateKey("payer", "preflight-private"),
    payee: await createPrivateKey("payee", "preflight-private"),
  };
  assert.equal(new Set([
    coordinationKeys.payer.publicKey,
    coordinationKeys.payee.publicKey,
    preflightKeys.payer.publicKey,
    preflightKeys.payee.publicKey,
  ]).size, 4);

  const promptSha256 = await computeBilateralPromptHash({ repositoryRoot: clone, repositorySha });
  const descriptor = {
    amountOptions: [{ currency: "USD", value: "100" }],
    chainId: "11155111",
    expirySeconds: "600",
    namespace: "cbv1",
    payee: { address: payee.address.toLowerCase(), agentId: "8678", displayName: "Iris", role: "payee" },
    payer: { address: payer.address.toLowerCase(), agentId: "8677", displayName: "Billy", role: "payer" },
    paymentMoved: false,
    promptSha256,
    protocol: "clockchain.bilateral-authorization/v1",
    protocolVersion: "1",
    registry: "0x8004a818bfb912233c491871b3d84c89a494bd9e",
    repositorySha,
    schema: "clockchain.bilateral-session-descriptor/v1",
    sessionId: randomBytes(16).toString("hex"),
    settlement: "not-executed",
  };
  const descriptorPath = join(root, "descriptor.json");
  await canonicalPrivate(descriptorPath, createSignedEnvelope(descriptor, {
    keyId: "process-e2e-operator",
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
  }));

  const fakeState = join(root, "fake-state.json");
  const fakeListen = join(root, "fake-listen.json");
  const fake = spawned([
    "test/helpers/fake-bilateral-clockchain-service.mjs",
    "--state", fakeState,
    "--listen-file", fakeListen,
  ], { cwd: clone });
  t.after(() => stop(fake.child));
  const fakeReady = await waitFor(fakeListen, fake);
  const fakeClient = createFakeBilateralClockchainHttpClient(fakeReady);
  await fakeClient.registerAgent({ agentId: "8677", owner: owners["8677"], status: "active" });
  await fakeClient.registerAgent({ agentId: "8678", owner: owners["8678"], status: "active" });

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

  const outputs = {
    payer: join(roleRoots.payer, "results"),
    payee: join(roleRoots.payee, "results"),
    verifier: join(root, "verifier-results"),
  };
  const configurations = {
    payer: join(roleRoots.payer, "role.json"),
    payee: join(roleRoots.payee, "role.json"),
    verifier: join(root, "verifier.json"),
    coordinator: join(root, "coordinator.json"),
  };
  const logs = Object.fromEntries(["payer", "payee", "verifier"].map((name) => [name, {
    stderr: join(root, `${name}.stderr`),
    stdout: join(root, `${name}.stdout`),
  }]));
  const roleArguments = (token, invitationPath, output) => [
    "--clockchain-token-file", token,
    "--descriptor", descriptorPath,
    "--invitation", invitationPath,
    "--output", output,
    "--i-understand-this-writes-to-clockchain",
  ];
  await canonicalPrivate(configurations.payer, {
    arguments: roleArguments(tokens.payer, invitations.payer, outputs.payer),
    fake: fakeReady,
    owners,
    schema: SCHEMA,
  });
  await canonicalPrivate(configurations.payee, {
    arguments: roleArguments(tokens.payee, invitations.payee, outputs.payee),
    fake: fakeReady,
    owners,
    schema: SCHEMA,
  });
  await canonicalPrivate(configurations.verifier, {
    arguments: [
      "--clockchain-token-file", tokens.payer,
      "--descriptor", descriptorPath,
      "--output", outputs.verifier,
      "--payee-results", outputs.payee,
      "--payer-results", outputs.payer,
      "--rpc-url", "http://127.0.0.1:8545",
    ],
    fake: fakeReady,
    owners,
    schema: SCHEMA,
  });
  const report = join(root, "coordinator-report.json");
  await canonicalPrivate(configurations.coordinator, {
    barrier: barrierPaths,
    children: {
      payer: { logs: logs.payer, mode: "payer", path: configurations.payer },
      payee: { logs: logs.payee, mode: "payee", path: configurations.payee },
      verifier: { logs: logs.verifier, mode: "verifier", path: configurations.verifier },
    },
    fake: fakeReady,
    relay: { ca: certificate, fingerprint: relayFingerprint, port: relayReady.port },
    report,
    schema: SCHEMA,
  });

  return {
    barrier: barrierPaths,
    certificate: { key: certificateKey, path: certificate, fingerprint: relayFingerprint },
    clone,
    configurations,
    coordinationKeys,
    descriptor,
    descriptorPath,
    fake,
    fakeClient,
    fakeReady,
    fakeState,
    invitations,
    logs,
    outputs,
    owners,
    relay,
    relayReady,
    report,
    repositorySha,
    preflightKeys,
    roleRoots,
    root,
    startCoordinator: () => spawned([
      "test/helpers/bilateral-coordination-child.mjs",
      "coordinator",
      "--configuration", configurations.coordinator,
    ], { cwd: clone }),
    tokens,
  };
}

test("real role and verifier CLIs complete one isolated three-transition process session", { concurrency: false }, async (t) => {
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
  for (const value of [session.descriptor, snapshot, coordinatorReport, payerResult, payeeResult, verdict]) assertPaymentNeverMoved(value);
  assert.deepEqual(snapshot.calls.logAction.map(({ asset_reference_id }) => asset_reference_id), ["proposal", "acceptance", "acknowledgment"].map((slot) => sessionKey(dSession(session.descriptor), slot)));
  assert.equal(snapshot.writeCount, 3);
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
    assert.equal(snapshot.calls.logAction[index].asset_hash, digest);
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
  const rolePrivatePaths = [session.invitations.payer, session.invitations.payee, session.tokens.payer, session.tokens.payee, session.configurations.payer, session.configurations.payee, session.coordinationKeys.payer.path, session.coordinationKeys.payee.path, session.preflightKeys.payer.path, session.preflightKeys.payee.path];
  assert.equal(new Set(rolePrivatePaths).size, rolePrivatePaths.length);
  for (const path of rolePrivatePaths) await assertPrivateFile(path, { canonical: path.endsWith(".json") });
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
  await command("git", ["clone", "--no-hardlinks", ROOT, clone]);
  await writeFile(join(clone, ".git/info/exclude"), "node_modules\n");
  await symlink(join(ROOT, "node_modules"), join(clone, "node_modules"));
  const certificate = join(root, "relay-cert.pem");
  const certificateKey = join(root, "relay-key.pem");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", certificateKey, "-out", certificate, "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-days", "1"]);
  await chmod(certificateKey, 0o600);
  const ca = await readFile(certificate, "utf8");
  const fingerprint = certificateFingerprint(ca);
  const state = join(root, "relay-state");
  await mkdir(state, { mode: 0o700 });
  const port = await availablePort();
  const repositorySha = (await command("git", ["rev-parse", "HEAD"], { cwd: clone })).stdout.trim();
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

  await within(waitForPrivateMarker(session.barrier.ready, {
    schema: SCHEMA,
    stage: "roles-complete",
  }, coordinator), 10_000);
  assert.equal(JSON.parse(await readFile(session.fakeState, "utf8")).writeCount, 3);

  await stop(session.relay.child);
  await canonicalPrivateExclusive(session.barrier.release, { release: true });

  const coordinatorExit = await within(coordinator.wait(), 5_000);
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
  assert.equal(JSON.parse(await readFile(session.fakeState, "utf8")).writeCount, 3);
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
  assert.equal(matrixRows.length, 33);
  assert.deepEqual(ADVERSARIAL_CITATIONS.map(([row]) => row), matrixRows.filter((row) => row !== "relay restart during long poll"));
  for (const [, file, name] of ADVERSARIAL_CITATIONS) {
    const source = await readFile(new URL(`../${file}`, import.meta.url), "utf8");
    assert.ok(source.includes(name), `${file} must retain ${name}`);
  }
});
