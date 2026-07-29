import { constants } from "node:fs";
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPinnedHttpsTransport, createCoordinationClient, createResumedCoordinationClient } from "./client.mjs";
import { canonicalBytes } from "../canonical.mjs";
import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { validateActiveLaunchState } from "./manifest.mjs";
import { readLaunchManifest } from "./manifest.mjs";
import { PAYER_MCP_INTAKE_DIRECTORY_NAME, createPayerMcpIntakeStore, scanPayerMcpIntakeDirectory } from "../local-mcp/intake-store.mjs";
import { readRequestorMcpIntake as readDefaultRequestorMcpIntake } from "../local-mcp/client.mjs";
import { createPayerMcpServer as createDefaultPayerMcpServer } from "../local-mcp/server.mjs";
import { createLocalPreflightEnrollment, readAndSignTokenCommitment } from "./preflight.mjs";
import { validateRelayArtifact, validateRelayArtifactWithFacts } from "./artifact.mjs";
import { verifyDescriptorEnvelope } from "../descriptor.mjs";
import { signPayerMandate } from "../payer-mandate.mjs";
import { signPaymentRequest } from "../payment-request.mjs";
import { parseCoordinationEnrollment, parseCoordinationEnrollmentSet } from "./enrollment.mjs";
import { deriveDescriptorSessionId } from "./run-session.mjs";
import { createReceiptVerifierFromCertificate, verifyCoordinationReceipt } from "./receipt.mjs";
import { main as mintBilateralToken } from "../../../scripts/mint-bilateral-token.mjs";
import { decryptInvitation } from "../../invitation.mjs";
import { invitationProofPreimage } from "./enrollment.mjs";
import { privateKeyToAccount } from "viem/accounts";
import { createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";
import { RPC_URL } from "../../constants.mjs";
import { main as createInvitationFiles } from "../../../scripts/create-invitations.mjs";

const MAX_STATE_BYTES = 1_048_576;
const fail = () => { throw new Error("Supervisor private state operation failed safely."); };
const execFileAsync = promisify(execFile);
const SUPERVISOR_REPOSITORY_ROOT = resolve(fileURLToPath(new URL("../../../", import.meta.url)));
const SUPERVISOR_GIT_ENV = Object.freeze(Object.assign(Object.create(null), {
  GIT_ATTR_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_NO_REPLACE_OBJECTS: "1", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin",
}));
const SUPERVISOR_GIT_PREFIX = Object.freeze(["--no-pager", "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-C"]);
const SUPERVISOR_CHILD_COMMANDS = new Set([
  "scripts/probe-bilateral-rendezvous.mjs",
  "scripts/register-bilateral-identity.mjs",
  "bin/handshake-propose.mjs",
  "bin/handshake-accept.mjs",
]);
const SUPERVISOR_CHILD_ENV = Object.freeze(Object.assign(Object.create(null), {
  LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin",
}));
const ROLE_READY_SCHEMA = "clockchain.bilateral-role-ready/v1";
// A role must have enough time to complete its bounded local input and
// identity checks before it can enter the remote protocol.  This is separate
// from a child process lifetime: readiness is a one-time launch boundary.
const ROLE_READY_LIVE_DEADLINE_MS = 30_000;
const expectedUid = process.getuid?.();
const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const hasExactPrivateMetadata = (info) => info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.uid === expectedUid && (info.mode & 0o777) === 0o600;
const canonicalJson = (value) => {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isFinite(value)) fail(); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) fail();
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
};
const canonicalEnrollmentSetBytes = (value) => Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
const relayPackageBytes = (value) => Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
export async function createPrivateRoot(root) {
  if (typeof root !== "string" || expectedUid === undefined) fail();
  try { await mkdir(root, { mode: 0o700 }); } catch (error) { if (error?.code !== "EEXIST") throw error; }
  const handle = await open(root, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const pinned = await handle.stat();
  const current = await lstat(root);
  if (!current.isDirectory() || current.isSymbolicLink() || current.uid !== expectedUid || (current.mode & 0o777) !== 0o700 || !sameIdentity(pinned, current)) { await handle.close(); fail(); }
  const assertPinned = async () => { const currentRoot = await lstat(root); const openedRoot = await handle.stat(); if (!currentRoot.isDirectory() || currentRoot.isSymbolicLink() || currentRoot.uid !== expectedUid || (currentRoot.mode & 0o777) !== 0o700 || !sameIdentity(pinned, currentRoot) || !sameIdentity(pinned, openedRoot)) fail(); };
  const entries = await readdir(root);
  if (entries.some((name) => /^(?:\.supervisor-state|\.retired-launch-manifest|\.supervisor-artifact|\.coordination-identity)-.+\.tmp$/.test(name))) { await handle.close(); fail(); }
  return Object.freeze({ handle, root, assertPinned });
}
const TEMPORARY_PRIVATE_ENTRY = /^(?:\.supervisor-state|\.retired-launch-manifest|\.supervisor-artifact|\.coordination-identity)-.+\.tmp$/;
async function scanExistingPrivateDirectory(directory, allowedDirectories = new Set()) {
  let info;
  try { info = await lstat(directory); } catch (error) { if (error?.code === "ENOENT") return; throw error; }
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== expectedUid || (info.mode & 0o777) !== 0o700) fail();
  const handle = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat(); if (!sameIdentity(info, opened)) fail();
    for (const name of await readdir(directory)) {
      const path = join(directory, name), entry = await lstat(path);
      if (entry.isSymbolicLink() || TEMPORARY_PRIVATE_ENTRY.test(name)) fail();
      if (entry.isDirectory()) {
        if (!allowedDirectories.has(name)) fail();
      }
    }
  } finally { await handle.close(); }
}
export async function scanSupervisorCheckpointDirectories({ checkpoint, stateRoot }) {
  if (!checkpoint || checkpoint.stateRoot !== stateRoot || typeof checkpoint.preflight?.planPath !== "string" || !checkpoint.rehearsal || !checkpoint.stakeholder) fail();
  const directories = new Set([
    stateRoot,
    dirname(checkpoint.preflight.planPath),
    dirname(checkpoint.preflight.outputPath),
    dirname(checkpoint.preflight.privateKeyPath),
    dirname(checkpoint.preflight.publicArtifactPath),
    dirname(checkpoint.rehearsal.descriptorPath), checkpoint.rehearsal.identityDirectory, checkpoint.rehearsal.resultDirectory,
    dirname(checkpoint.stakeholder.descriptorPath), checkpoint.stakeholder.identityDirectory, checkpoint.stakeholder.resultDirectory,
  ]);
  await scanExistingPrivateDirectory(stateRoot, new Set(["preflight", "rehearsal", "stakeholder", "invitation-public", "invitation-secret", PAYER_MCP_INTAKE_DIRECTORY_NAME]));
  try {
    await lstat(join(stateRoot, PAYER_MCP_INTAKE_DIRECTORY_NAME));
    if (checkpoint.role !== "payer") fail();
    await scanPayerMcpIntakeDirectory({ repositorySha: checkpoint.repositorySha, stateRoot });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  await scanExistingPrivateDirectory(dirname(checkpoint.preflight.planPath));
  for (const run of [checkpoint.rehearsal, checkpoint.stakeholder]) {
    await scanExistingPrivateDirectory(dirname(run.descriptorPath), new Set(["identity", "result"]));
    await scanExistingPrivateDirectory(run.identityDirectory);
    await scanExistingPrivateDirectory(run.resultDirectory);
  }
}
async function readPrivateBytes(root, path, maximum = MAX_STATE_BYTES) {
  await root.assertPinned();
  const before = await lstat(path); if (!hasExactPrivateMetadata(before) || before.size > maximum) fail();
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat(); if (!sameIdentity(before, opened) || !hasExactPrivateMetadata(opened)) fail();
    const buffer = Buffer.allocUnsafe(maximum + 1); const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0); if (bytesRead > maximum) fail();
    const bytes = buffer.subarray(0, bytesRead), after = await lstat(path); await root.assertPinned();
    if (!sameIdentity(before, after) || !hasExactPrivateMetadata(after) || after.size !== bytes.length) fail();
    return bytes;
  } finally { await handle.close(); }
}
async function readPinnedPrivateText(path, maximum = MAX_STATE_BYTES, afterFirstRead) {
  if (typeof path !== "string" || path.includes("\0") || resolve(path) !== path) fail();
  let handle;
  try {
    const before = await lstat(path);
    if (!hasExactPrivateMetadata(before) || before.size <= 0 || before.size > maximum) fail();
    handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!hasExactPrivateMetadata(opened) || !sameIdentity(before, opened)) fail();
    const buffer = Buffer.allocUnsafe(before.size + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead !== before.size) fail();
    if (afterFirstRead !== undefined) {
      if (typeof afterFirstRead !== "function") fail();
      await afterFirstRead(Object.freeze({ path }));
    }
    const after = await lstat(path);
    if (!hasExactPrivateMetadata(after) || !sameIdentity(before, after) || after.size !== before.size) fail();
    const reopened = await handle.stat();
    if (!hasExactPrivateMetadata(reopened) || !sameIdentity(before, reopened) || reopened.size !== before.size) fail();
    const second = Buffer.allocUnsafe(before.size + 1);
    const secondRead = await handle.read(second, 0, second.length, 0);
    if (secondRead.bytesRead !== before.size) fail();
    const bytes = buffer.subarray(0, bytesRead);
    const secondBytes = second.subarray(0, secondRead.bytesRead);
    if (!bytes.equals(secondBytes) || createHash("sha256").update(bytes).digest("hex") !== createHash("sha256").update(secondBytes).digest("hex")) fail();
    return bytes.toString("utf8");
  } finally {
    if (handle) await handle.close();
  }
}
async function readPrivateJson(root, path) {
  const bytes = await readPrivateBytes(root, path); const text = bytes.toString("utf8");
  if (!text.endsWith("\n")) fail(); let value; try { value = JSON.parse(text); } catch { fail(); }
  if (`${canonicalJson(value)}\n` !== text) fail(); return value;
}
async function writePrivateBytes(root, target, bytes, prefix = ".supervisor-artifact") {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_STATE_BYTES) fail();
  const temporary = join(root.root, `${prefix}-${randomBytes(16).toString("hex")}.tmp`); let handle;
  try {
    await root.assertPinned(); handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    if (!hasExactPrivateMetadata(await handle.stat())) fail(); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await root.assertPinned(); await rename(temporary, target); await root.handle.sync();
    if (!(await readPrivateBytes(root, target)).equals(bytes)) fail();
  } catch (error) { if (handle) await handle.close(); await unlink(temporary).catch(() => {}); throw error; }
}
async function writePrivateJson(root, target, value, prefix = ".supervisor-state") {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, "utf8"); if (bytes.length > MAX_STATE_BYTES) fail();
  const temporary = join(root.root, `${prefix}-${randomBytes(16).toString("hex")}.tmp`); let handle;
  try {
    await root.assertPinned(); handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    const metadata = await handle.stat(); if (!hasExactPrivateMetadata(metadata)) fail(); await handle.writeFile(bytes); await handle.sync(); await handle.close(); handle = undefined;
    await root.assertPinned(); await rename(temporary, target); await root.assertPinned(); await root.handle.sync();
    const readback = await readPrivateJson(root, target); if (`${canonicalJson(readback)}\n` !== bytes.toString("utf8")) fail();
  } catch (error) { if (handle) await handle.close(); await unlink(temporary).catch(() => {}); throw error; }
}
function createGitInspector(repositoryRoot = SUPERVISOR_REPOSITORY_ROOT) {
  const fixedRoot = resolve(repositoryRoot);
  const run = (arguments_) => execFileAsync("/usr/bin/git", [...SUPERVISOR_GIT_PREFIX, fixedRoot, ...arguments_], { cwd: fixedRoot, encoding: "utf8", env: SUPERVISOR_GIT_ENV, maxBuffer: 8192 });
  return Object.freeze({
    async probe() { const { stdout: head } = await run(["rev-parse", "--verify", "HEAD^{commit}"]); const { stdout: status } = await run(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]); if (!/^[0-9a-f]{40}\n$/.test(head) || status !== "") fail(); return Object.freeze({ clean: true, head: head.slice(0, -1) }); },
    async operatorKey(repositorySha, keyId) { if (!/^[0-9a-f]{40}$/.test(repositorySha) || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(keyId)) fail(); const { stdout } = await run(["show", `${repositorySha}:docs/operator-keys/${keyId}.pub`]); if (!/^[A-Za-z0-9+/]{43}=\n$/.test(stdout)) fail(); return stdout.slice(0, -1); },
  });
}
const childArgv = Object.freeze({
  "scripts/probe-bilateral-rendezvous.mjs": Object.freeze(["participant", "--role", "value", "--plan", "path", "--token-file", "path", "--participant-private-key", "path", "--output", "path"]),
  "scripts/register-bilateral-identity.mjs": Object.freeze(["--invitation", "path", "--output", "path", "--repository-sha", "sha", "--i-understand-this-writes-to-sepolia"]),
  "bin/handshake-propose.mjs": Object.freeze(["--clockchain-token-file", "path", "--descriptor", "path", "--invitation", "path", "--output", "path", "--i-understand-this-writes-to-clockchain"]),
  "bin/handshake-accept.mjs": Object.freeze(["--clockchain-token-file", "path", "--descriptor", "path", "--invitation", "path", "--output", "path", "--i-understand-this-writes-to-clockchain"]),
});
function validPath(value) { return typeof value === "string" && value.startsWith("/") && !value.includes("/../") && !value.endsWith("/..") && !value.includes("\0"); }
function validChildArguments(command, args) {
  const schema = childArgv[command];
  if (!schema || !Array.isArray(args) || args.length !== schema.length) return false;
  for (let index = 0; index < schema.length; index += 1) {
    const expected = schema[index], actual = args[index];
    if (expected === "path" && validPath(actual)) continue;
    if (expected === "value" && ["payer", "payee"].includes(actual)) continue;
    if (expected === "sha" && /^[0-9a-f]{40}$/.test(actual)) continue;
    if (expected === actual) continue;
    return false;
  }
  return true;
}

function roleForCommand(command) {
  if (command === "bin/handshake-propose.mjs") return "payer";
  if (command === "bin/handshake-accept.mjs") return "payee";
  return null;
}

function readinessLine({ nonce, role }) {
  return `${JSON.stringify({ nonce, role, schema: ROLE_READY_SCHEMA })}\n`;
}

function waitForRoleReadiness({ child, nonce, role, readinessDeadlineMs }) {
  const stream = child.stdio[3];
  if (!stream || typeof stream.on !== "function") {
    return Promise.reject(new Error("role readiness pipe missing"));
  }
  return new Promise((resolveReady, rejectReady) => {
    let settled = false;
    let bytes = Buffer.alloc(0);
    let validLine = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      stream.removeListener("data", onData);
      stream.removeListener("end", onClose);
      stream.removeListener("close", onClose);
      stream.removeListener("error", onClose);
      child.removeListener("exit", onExit);
      fn(value);
    };
    const reject = () => finish(rejectReady, new Error("role readiness rejected"));
    const onClose = () => validLine ? finish(resolveReady) : reject();
    const onExit = () => validLine ? undefined : reject();
    const onData = (chunk) => {
      if (!Buffer.isBuffer(chunk) || chunk.length === 0 || bytes.length + chunk.length > 512) return reject();
      bytes = Buffer.concat([bytes, chunk]);
      const newline = bytes.indexOf(0x0a);
      if (newline === -1) return;
      if (newline !== bytes.length - 1 || bytes.toString("utf8") !== readinessLine({ nonce, role })) return reject();
      validLine = true;
    };
    const timeout = setTimeout(reject, readinessDeadlineMs);
    stream.on("data", onData);
    stream.once("end", onClose);
    stream.once("close", onClose);
    stream.once("error", onClose);
    child.once("exit", onExit);
  });
}

export function createSupervisorLauncher({ repositoryRoot = SUPERVISOR_REPOSITORY_ROOT, readinessDeadlineMs = ROLE_READY_LIVE_DEADLINE_MS } = {}) {
  const root = resolve(repositoryRoot);
  if (!Number.isSafeInteger(readinessDeadlineMs) || readinessDeadlineMs < 100 || readinessDeadlineMs > ROLE_READY_LIVE_DEADLINE_MS) fail();
  return async ({ command, args }) => {
    if (!SUPERVISOR_CHILD_COMMANDS.has(command) || !validChildArguments(command, args)) fail();
    const script = resolve(root, command);
    if (!script.startsWith(`${root}/`)) fail();
    let child;
    const role = roleForCommand(command);
    const nonce = role === null ? null : randomBytes(32).toString("hex");
    const env = role === null
      ? SUPERVISOR_CHILD_ENV
      : Object.freeze(Object.assign(Object.create(null), SUPERVISOR_CHILD_ENV, {
        CLOCKCHAIN_BILATERAL_ROLE_READY_FD: "3",
        CLOCKCHAIN_BILATERAL_ROLE_READY_NONCE: nonce,
        CLOCKCHAIN_BILATERAL_ROLE_READY_SCHEMA: ROLE_READY_SCHEMA,
      }));
    try { child = spawn(process.execPath, [script, ...args], { cwd: root, env, shell: false, stdio: role === null ? ["ignore", "ignore", "ignore"] : ["ignore", "ignore", "ignore", "pipe"] }); } catch { return Object.freeze({ ambiguous: true, exitCode: 1 }); }
    const completion = new Promise((resolveCompletion) => {
      let settled = false;
      const settle = (value) => { if (!settled) { settled = true; resolveCompletion(Object.freeze(value)); } };
      child.once("error", () => settle({ ambiguous: true, exitCode: 1 }));
      child.once("exit", (code, signal) => settle({ ambiguous: signal !== null, exitCode: Number.isInteger(code) ? code : 1 }));
    });
    if (role === null) return completion;
    try {
      await waitForRoleReadiness({ child, nonce, role, readinessDeadlineMs });
    } catch {
      child.kill();
      throw new Error("role child did not reach authenticated readiness");
    }
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("role child exited before readiness");
    return Object.freeze({ ambiguous: false, completion, started: true });
  };
}

const packageNames = Object.freeze({
  "identity-package": Object.freeze([".identity.complete.json", "identity.json"]),
  "party-result-package": Object.freeze([".party-result.complete.json", "PARTY-RESULT.md", "party-result.json"]),
  "preflight-participant-report": Object.freeze([".participant-report.complete.json", "participant-report.json"]),
});

async function buildPackage({ artifactType, directory, root }) {
  const names = packageNames[artifactType];
  if (!names || typeof directory !== "string" || dirname(directory) === directory) fail();
  const fileRoot = await createPrivateRoot(directory);
  try {
    const files = [];
    for (const name of names) {
      const bytes = await readPrivateBytes(fileRoot, join(directory, name), MAX_STATE_BYTES);
      files.push(Object.freeze({ byteLength: String(bytes.length), contentBase64: bytes.toString("base64"), name, sha256: createHash("sha256").update(bytes).digest("hex") }));
    }
    const bytes = relayPackageBytes({ files, paymentMoved: false, schema: "clockchain.bilateral-relay-package/v1" });
    await validateRelayArtifact({ artifactType, bytes, expectedDigest: createHash("sha256").update(bytes).digest("hex"), secretCanaries: [] });
    return bytes;
  } finally { await fileRoot.handle.close(); }
}

function enrollmentVerifier({ tlsCertificatePem }) {
  const receiptVerifier = createReceiptVerifierFromCertificate({ tlsCertificatePem });
  return async ({ enrollmentBytes, enrollmentSet, releaseId, repositorySha, sessionId }) => {
    const set = parseCoordinationEnrollmentSet(Buffer.from(enrollmentBytes));
    if (!canonicalEnrollmentSetBytes(set).equals(canonicalEnrollmentSetBytes(enrollmentSet)) || set.releaseId !== releaseId || set.repositorySha !== repositorySha || set.sessionId !== sessionId || set.paymentMoved !== false) fail();
    const seen = new Set();
    for (const role of ["payer", "payee"]) {
      const entry = set.enrollments[role];
      const enrollmentBytes = Buffer.from(entry.enrollmentBase64, "base64");
      const enrollment = parseCoordinationEnrollment(enrollmentBytes);
      if (enrollment.role !== role || createHash("sha256").update(enrollmentBytes).digest("hex") !== entry.enrollmentDigest) fail();
      await verifyCoordinationReceipt({ bytes: Buffer.from(entry.receiptBase64, "base64"), expected: { capabilityDigest: enrollment.capabilityDigest, enrollmentDigest: entry.enrollmentDigest, releaseId, repositorySha, role, sessionId }, verifier: receiptVerifier });
      for (const key of [enrollment.coordinationKey.publicKey, enrollment.preflightKey.publicKey, enrollment.invitations.rehearsal.address, enrollment.invitations.stakeholder.address]) {
        if (seen.has(key)) fail(); seen.add(key);
      }
    }
    return set;
  };
}

function rpcQuantity(value) {
  if (typeof value !== "string" || !/^0x(?:0|[0-9a-f]+)$/i.test(value)) fail();
  return BigInt(value);
}

export function createProductionSepoliaRpc({ createClient = createPublicClient, rpcUrl = RPC_URL } = {}) {
  if (typeof createClient !== "function" || typeof rpcUrl !== "string") fail();
  let endpoint;
  try { endpoint = new URL(rpcUrl); } catch { fail(); }
  if (!endpoint.protocol.startsWith("http") || endpoint.username || endpoint.password || endpoint.hash || endpoint.search || endpoint.pathname !== "/") fail();
  const client = createClient({ chain: sepolia, transport: http(endpoint.href, { retryCount: 0, timeout: 15_000 }) });
  if (!client || typeof client.getBalance !== "function" || typeof client.getTransactionCount !== "function") fail();
  return async ({ method, params }) => {
    if (!Array.isArray(params) || params.length !== 2 || params[1] !== "latest" || typeof params[0] !== "string") fail();
    if (method === "eth_getBalance") return `0x${(await client.getBalance({ address: params[0] })).toString(16)}`;
    if (method === "eth_getTransactionCount") return `0x${(await client.getTransactionCount({ address: params[0], blockTag: "latest" })).toString(16)}`;
    fail();
  };
}

function fundingVerifier(sepoliaRpc) {
  return async ({ addresses, enrollmentSet, repositorySha, role, sessionId }) => {
    if (typeof sepoliaRpc !== "function" || !Array.isArray(addresses) || addresses.length !== 2 || new Set(addresses).size !== 2 || enrollmentSet?.repositorySha !== repositorySha || enrollmentSet?.sessionId !== sessionId || !["payer", "payee"].includes(role)) fail();
    const local = enrollmentSet.enrollments?.[role] && parseCoordinationEnrollment(Buffer.from(enrollmentSet.enrollments[role].enrollmentBase64, "base64"));
    if (!local || !canonicalBytes(addresses).equals(canonicalBytes([local.invitations.rehearsal.address, local.invitations.stakeholder.address]))) fail();
    for (const address of addresses) {
      if (typeof address !== "string" || !/^0x[0-9a-f]{40}$/.test(address)) fail();
      const [balance, nonce] = await Promise.all([sepoliaRpc({ method: "eth_getBalance", params: [address, "latest"] }), sepoliaRpc({ method: "eth_getTransactionCount", params: [address, "latest"] })]);
      const wei = rpcQuantity(balance);
      if (wei < 5_000_000_000_000_000n || wei > 20_000_000_000_000_000n || rpcQuantity(nonce) !== 0n) fail();
    }
    return Object.freeze({ paymentMoved: false });
  };
}

export function createSupervisorStatusLine(value) {
  if (value?.code === "COORDINATION_SUPERVISOR_FAILED") {
    if (!Object.hasOwn(value, "paymentMoved") || value.paymentMoved !== false) fail();
    return `${canonicalJson({ code: "COORDINATION_SUPERVISOR_FAILED", paymentMoved: false })}\n`;
  }
  if (!value || value.paymentMoved !== false || !["payer", "payee"].includes(value.role) || !["WAITING_FOR_PEER", "PEER_READY", "PAYER_MCP_READY"].includes(value.status)) fail();
  if (value.status === "PAYER_MCP_READY") {
    if (value.role !== "payer" || typeof value.url !== "string") fail();
    let url;
    try { url = new URL(value.url); } catch { fail(); }
    if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || url.pathname !== "/mcp") fail();
    return `${canonicalJson({ paymentMoved: false, role: value.role, status: value.status, url: value.url })}\n`;
  }
  return `${canonicalJson({ paymentMoved: false, role: value.role, status: value.status })}\n`;
}

export function createVerifierPublicationVerifier() {
  return async ({ event, releaseId, repositorySha, sessionId }, client) => {
    if (typeof client?.readVerifierPublication !== "function" || !event || event.kind !== "VERIFICATION_PASSED" || event.role !== "operator" || typeof event.artifactDigest !== "string") fail();
    const publication = await client.readVerifierPublication({ subjectRun: event.subjectRun });
    if (!publication || Object.keys(publication).length !== 8 || publication.paymentMoved !== false || publication.publicationDigest !== event.artifactDigest || publication.releaseId !== releaseId || publication.repositorySha !== repositorySha || publication.schema !== "clockchain.bilateral-verifier-publication/v1" || publication.sessionId !== sessionId || publication.status !== "VERIFICATION_PASSED" || publication.subjectRun !== event.subjectRun) fail();
    return true;
  };
}

function fixedArtifactPath(stateRoot, path) {
  if (typeof path !== "string" || ![
    join(stateRoot, "preflight", "plan.json"),
    join(stateRoot, "rehearsal", "descriptor.json"),
    join(stateRoot, "rehearsal", "payer-mandate.json"),
    join(stateRoot, "rehearsal", "payment-request.json"),
    join(stateRoot, "stakeholder", "descriptor.json"),
    join(stateRoot, "stakeholder", "payer-mandate.json"),
    join(stateRoot, "stakeholder", "payment-request.json"),
  ].includes(path)) fail();
  return path;
}
function isIntentArtifactPath(stateRoot, path) {
  return [
    join(stateRoot, "rehearsal", "payer-mandate.json"),
    join(stateRoot, "rehearsal", "payment-request.json"),
    join(stateRoot, "stakeholder", "payer-mandate.json"),
    join(stateRoot, "stakeholder", "payment-request.json"),
  ].includes(path);
}
const stateFile = (root) => join(root, "supervisor-state.json");
export async function createPrivateSupervisorStateStore({ stateRoot }) {
  await privateDirectory(stateRoot);
  return Object.freeze({
    async readState() {
      const root = await createPrivateRoot(stateRoot);
      try { return await readPrivateJson(root, stateFile(stateRoot)); } catch (error) { if (error?.code === "ENOENT") return null; throw error; } finally { await root.handle.close(); }
    },
    async writeState(value) {
      const root = await createPrivateRoot(stateRoot);
      try { await writePrivateJson(root, stateFile(stateRoot), value); } finally { await root.handle.close(); }
    },
    async retireLaunchManifest(path) {
      if (typeof path !== "string") fail();
      const activeRoot = resolve(stateRoot), sourcePath = resolve(path);
      if (sourcePath === activeRoot || sourcePath.startsWith(`${activeRoot}/`)) fail();
      try { await lstat(sourcePath); } catch (error) { if (error?.code === "ENOENT") return; throw error; }
      const root = await createPrivateRoot(stateRoot);
      const sourceRoot = await createPrivateRoot(dirname(sourcePath));
      try {
        const source = await lstat(sourcePath); if (!hasExactPrivateMetadata(source)) fail();
        await readPrivateBytes(sourceRoot, sourcePath);
        const after = await lstat(sourcePath); if (!sameIdentity(source, after) || !hasExactPrivateMetadata(after)) fail();
        await root.assertPinned(); await sourceRoot.assertPinned(); await unlink(sourcePath); await sourceRoot.handle.sync();
        await lstat(sourcePath).then(() => fail(), (error) => { if (error?.code !== "ENOENT") throw error; });
      } finally { await sourceRoot.handle.close(); await root.handle.close(); }
    },
  });
}

async function privateDirectory(root) {
  const pinned = await createPrivateRoot(root);
  try { await pinned.assertPinned(); } finally { await pinned.handle.close(); }
}
async function createFixedRunDirectories(stateRoot) {
  const root = await createPrivateRoot(stateRoot);
  try {
    for (const run of ["rehearsal", "stakeholder"]) {
      const directory = join(stateRoot, run);
      await root.assertPinned();
      try { await mkdir(directory, { mode: 0o700 }); } catch (error) { if (error?.code !== "EEXIST") throw error; }
      await root.assertPinned();
      const pinned = await createPrivateRoot(directory);
      try { await pinned.assertPinned(); } finally { await pinned.handle.close(); }
    }
  } finally { await root.handle.close(); }
}
async function readRegular(path) {
  const root = await createPrivateRoot(dirname(path));
  try { const bytes = await readPrivateBytes(root, path); try { return JSON.parse(bytes.toString("utf8")); } catch { fail(); } } finally { await root.handle.close(); }
}

export async function createCoordinationIdentity({ role, stateRoot }) {
  if (!['payer', 'payee'].includes(role) || typeof stateRoot !== 'string') fail();
  const root = await createPrivateRoot(stateRoot);
  try {
    const path = join(stateRoot, `${role}-coordination.pem`);
    try {
      const pem = await readPrivateJson(root, path);
      if (typeof pem?.privateKeyPem !== 'string') fail();
      const key = await import('node:crypto').then(({ createPrivateKey, createPublicKey }) => createPublicKey(createPrivateKey(pem.privateKeyPem)));
      return Object.freeze({ keyId: `${role}-coordination`, privateKeyPem: pem.privateKeyPem, publicKey: key.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') });
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const pair = generateKeyPairSync('ed25519');
    const privateKeyPem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
    const result = Object.freeze({ keyId: `${role}-coordination`, privateKeyPem, publicKey: pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') });
    await writePrivateJson(root, path, { privateKeyPem }, ".coordination-identity");
    return result;
  } finally { await root.handle.close(); }
}

export function createTransport(manifestOrActive) {
  if (!manifestOrActive || typeof manifestOrActive.relayUrl !== 'string' || typeof manifestOrActive.tlsCertificatePem !== 'string') fail();
  return createPinnedHttpsTransport({ expectedFingerprint: manifestOrActive.expectedTlsFingerprint, relayUrl: manifestOrActive.relayUrl, tlsCertificatePem: manifestOrActive.tlsCertificatePem });
}
export async function verifyRepositoryState({ repositorySha, probe }) {
  if (!/^[0-9a-f]{40}$/.test(repositorySha) || typeof probe !== 'function') fail();
  const result = await probe();
  if (!result || result.head !== repositorySha || result.clean !== true) fail();
  return true;
}
export async function createPreflight({ role, repositorySha, stateRoot, creator = createLocalPreflightEnrollment }) {
  if (!['payer', 'payee'].includes(role) || !/^[0-9a-f]{40}$/.test(repositorySha) || typeof stateRoot !== 'string') fail();
  await privateDirectory(stateRoot);
  const root = join(stateRoot, 'preflight');
  await mkdir(root, { mode: 0o700, recursive: true });
  const info = await lstat(root);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o777) !== 0o700) fail();
  return creator({ outputDirectory: root, repositorySha, role });
}
async function readRawToken(root, path) {
  const bytes = await readPrivateBytes(root, path, 4096);
  if (!/^[!-~]{1,4096}$/.test(bytes.toString('utf8'))) fail();
  return bytes;
}
export async function ensureToken({ role, repositorySha, stateRoot, mint }) {
  if (!['payer', 'payee'].includes(role) || !/^[0-9a-f]{40}$/.test(repositorySha) || typeof stateRoot !== 'string') fail();
  const root = await createPrivateRoot(stateRoot);
  try {
    const tokenPath = join(stateRoot, 'clockchain.token');
    try {
      await readRawToken(root, tokenPath);
      return Object.freeze({ tokenPath });
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    const mintToken = mint ?? (async ({ role: requestedRole, repositorySha: requestedSha, tokenPath: output }) => mintBilateralToken(['--role', requestedRole, '--output', output, '--repository-sha', requestedSha]));
    if (typeof mintToken !== 'function') fail();
    await mintToken({ role, repositorySha, tokenPath });
    await readRawToken(root, tokenPath);
    return Object.freeze({ tokenPath });
  } finally { await root.handle.close(); }
}
export async function loadInvitationProof({ capabilityDigest, releaseId, repositorySha, role, run, sessionId, secretPath }) {
  if (!/^[0-9a-f]{64}$/.test(capabilityDigest) || typeof releaseId !== 'string' || !/^[0-9a-f]{40}$/.test(repositorySha) || !['payer', 'payee'].includes(role) || !['rehearsal', 'stakeholder'].includes(run) || typeof sessionId !== 'string' || typeof secretPath !== 'string') fail();
  const secret = await readRegular(secretPath);
  if (!secret || Object.keys(secret).length !== 2 || !Object.hasOwn(secret, 'bundle') || !Object.hasOwn(secret, 'code') || typeof secret.code !== 'string') fail();
  const payload = await decryptInvitation(secret.bundle, secret.code);
  if (!payload || Object.keys(payload).length !== 3 || typeof payload.privateKey !== 'string' || typeof payload.address !== 'string' || typeof payload.displayName !== 'string') fail();
  const account = privateKeyToAccount(payload.privateKey);
  if (account.address.toLowerCase() !== payload.address.toLowerCase()) fail();
  const address = account.address.toLowerCase();
  const signature = await account.signMessage({ message: { raw: invitationProofPreimage({ address, capabilityDigest, releaseId, repositorySha, role, run, sessionId }) } });
  return Object.freeze({ address, algorithm: 'eip191', secretPath, signature, subjectRun: run });
}
async function loadInvitationAccount({ expectedAddress, secretPath }) {
  if (typeof secretPath !== "string" || typeof expectedAddress !== "string") fail();
  const secret = await readRegular(secretPath);
  if (!secret || Object.keys(secret).length !== 2 || !Object.hasOwn(secret, "bundle") || !Object.hasOwn(secret, "code") || typeof secret.code !== "string") fail();
  const payload = await decryptInvitation(secret.bundle, secret.code);
  if (!payload || Object.keys(payload).length !== 3 || typeof payload.privateKey !== "string" || typeof payload.address !== "string" || typeof payload.displayName !== "string") fail();
  const account = privateKeyToAccount(payload.privateKey);
  if (account.address.toLowerCase() !== payload.address.toLowerCase() || account.address.toLowerCase() !== expectedAddress) fail();
  return account;
}
export async function ensureInvitations({ capabilityDigest, releaseId, repositorySha, role, sessionId, stateRoot, create }) {
  await privateDirectory(stateRoot);
  const publicDirectory = join(stateRoot, 'invitation-public'), secretDirectory = join(stateRoot, 'invitation-secret');
  await mkdir(publicDirectory, { recursive: true, mode: 0o700 }); await mkdir(secretDirectory, { recursive: true, mode: 0o700 });
  const runs = ['rehearsal', 'stakeholder'];
  const paths = runs.map((run) => join(secretDirectory, `${role}-${run}.secret.json`));
  const present = await Promise.all(paths.map(async (path) => { try { await lstat(path); return true; } catch (error) { if (error?.code === 'ENOENT') return false; throw error; } }));
  if (present[0] !== present[1]) fail();
  if (!present[0]) {
    const creator = create ?? (async (input) => createInvitationFiles(input));
    const displayName = role === "payer" ? "Payer" : role === "payee" ? "Requestor" : fail();
    await creator(['--output-public', publicDirectory, '--output-secret', secretDirectory, '--ids', `${role}-rehearsal,${role}-stakeholder`, '--names', `${displayName},${displayName}`]);
  }
  const proofs = await Promise.all(runs.map((run, index) => loadInvitationProof({ capabilityDigest, releaseId, repositorySha, role, run, sessionId, secretPath: paths[index] })));
  if (proofs[0].address === proofs[1].address || proofs[0].secretPath === proofs[1].secretPath || proofs[0].signature === proofs[1].signature) fail();
  return Object.freeze(proofs);
}
export async function createProductionSupervisorDependencies({ createPayerMcpServer = createDefaultPayerMcpServer, launchManifestPath, payerMcpServerOptions, stateRoot, probe, repositoryRoot = SUPERVISOR_REPOSITORY_ROOT, sepoliaRpc, createSepoliaClient } = {}) {
  const store = await createPrivateSupervisorStateStore({ stateRoot });
  await createFixedRunDirectories(stateRoot);
  const repositoryInspector = createGitInspector(repositoryRoot);
  const checkpoint = await store.readState();
  const resumed = checkpoint !== null && checkpoint?.phase !== "LOCAL_SECRETS_READY";
  const manifest = resumed ? null : await readLaunchManifest(launchManifestPath);
  const active = resumed ? await validateActiveLaunchState(checkpoint.activeLaunchState) : null;
  const scope = Object.freeze(resumed
    ? { capabilityDigest: active.capabilityDigest, ...(active.role === "payer" ? { payerMcpIntakeCapabilityDigest: active.payerMcpIntakeCapabilityDigest } : {}), releaseId: active.releaseId, repositorySha: active.repositorySha, role: active.role, sessionId: active.sessionId }
    : { capabilityDigest: createHash('sha256').update(Buffer.from(manifest.bootstrapCapability, 'hex')).digest('hex'), ...(manifest.role === "payer" ? { payerMcpIntakeCapabilityDigest: manifest.payerMcpIntakeCapabilityDigest } : {}), releaseId: manifest.releaseId, repositorySha: manifest.repositorySha, role: manifest.role, sessionId: manifest.sessionId });
  const payerMcpIntakeStore = scope.role === "payer"
    ? await createPayerMcpIntakeStore({ repositorySha: scope.repositorySha, stateRoot })
    : null;
  if (payerMcpServerOptions !== undefined && scope.role !== "payer") fail();
  if (payerMcpServerOptions !== undefined && typeof createPayerMcpServer !== "function") fail();
  const normalizedPayerMcpServerOptions = payerMcpServerOptions === undefined ? null : Object.freeze({
    host: payerMcpServerOptions.host,
    port: payerMcpServerOptions.port,
    tlsCertificatePem: payerMcpServerOptions.tlsCertificatePem ?? await readPinnedPrivateText(payerMcpServerOptions.tlsCertificatePath, MAX_STATE_BYTES, payerMcpServerOptions.afterPinnedTextFirstRead),
    tlsPrivateKeyPem: payerMcpServerOptions.tlsPrivateKeyPem ?? await readPinnedPrivateText(payerMcpServerOptions.tlsPrivateKeyPath, MAX_STATE_BYTES, payerMcpServerOptions.afterPinnedTextFirstRead),
  });
  const payerMcpServer = normalizedPayerMcpServerOptions === null ? null : createPayerMcpServer(Object.freeze({
    ...normalizedPayerMcpServerOptions,
    capabilityDigest: scope.payerMcpIntakeCapabilityDigest,
    intakeStore: payerMcpIntakeStore,
    repositorySha: scope.repositorySha,
  }));
  if (payerMcpServer !== null && (typeof payerMcpServer.start !== "function" || typeof payerMcpServer.stop !== "function")) fail();
  const tlsCertificatePem = resumed ? active.tlsCertificatePem : manifest.tlsCertificatePem;
  const payerMcpIntakeDependencies = payerMcpIntakeStore === null ? {} : {
    async writePayerMcpIntake(input) { return payerMcpIntakeStore.writeIntake(input); },
    async readPayerMcpIntake(input) { return payerMcpIntakeStore.readIntake(input); },
    async readStoredPayerMcpIntake() { return payerMcpIntakeStore.readStoredIntake(); },
    ...(payerMcpServer === null ? {} : {
      async startPayerMcpServer() { return payerMcpServer.start(); },
      async stopPayerMcpServer() { return payerMcpServer.stop(); },
    }),
  };
  const requestorMcpIntakeDependencies = scope.role === "payee"
    ? {
      async readRequestorMcpIntake() {
        return readDefaultRequestorMcpIntake({ repositorySha: scope.repositorySha, stateRoot });
      },
    }
    : {};
  return Object.freeze({
    ...store,
    ...payerMcpIntakeDependencies,
    ...requestorMcpIntakeDependencies,
    scanCheckpointDirectories: scanSupervisorCheckpointDirectories,
    async readLaunchManifest(path) { if (!manifest || path !== launchManifestPath) fail(); return manifest; },
    async verifyRepositoryState(repositorySha) { return verifyRepositoryState({ repositorySha, probe: probe ?? (() => repositoryInspector.probe()) }); },
    async createCoordinationIdentity({ role }) { return createCoordinationIdentity({ role, stateRoot }); },
    async createLocalPreflightEnrollment({ role }) { return createPreflight({ role, repositorySha: scope.repositorySha, stateRoot }); },
    async createInvitations({ role }) { return ensureInvitations({ ...scope, role, stateRoot }); },
    async ensureToken({ role }) { return ensureToken({ role, repositorySha: scope.repositorySha, stateRoot }); },
    requestId() { return randomUUID(); },
    async readAndSignTokenCommitment(input) { return readAndSignTokenCommitment(input); },
    verifyEnrollmentSet: enrollmentVerifier({ tlsCertificatePem }),
    verifyFundingInputs: fundingVerifier(sepoliaRpc ?? createProductionSepoliaRpc({ createClient: createSepoliaClient })),
    verifyVerifierPublication: createVerifierPublicationVerifier(),
    writeStatus(value) { process.stdout.write(createSupervisorStatusLine(value)); },
    launcher: createSupervisorLauncher(),
    async writeArtifactFile({ bytes, path }) {
      fixedArtifactPath(stateRoot, path);
      if (!Buffer.isBuffer(bytes) || !canonicalBytes(JSON.parse(bytes.toString("utf8"))).equals(bytes)) fail();
      const root = await createPrivateRoot(dirname(path));
      try {
        if (isIntentArtifactPath(stateRoot, path)) {
          try {
            const existing = await readPrivateBytes(root, path);
            if (!existing.equals(bytes)) fail();
            return;
          } catch (error) {
            if (error?.code !== "ENOENT") throw error;
          }
        }
        await writePrivateBytes(root, path, bytes);
      } finally { await root.handle.close(); }
    },
    async readArtifactFile({ path }) {
      fixedArtifactPath(stateRoot, path);
      const root = await createPrivateRoot(dirname(path));
      try {
        const bytes = await readPrivateBytes(root, path);
        if (!canonicalBytes(JSON.parse(bytes.toString("utf8"))).equals(bytes)) fail();
        return bytes;
      } finally { await root.handle.close(); }
    },
    async signPayerMandate({ invitationPath, mandate }) {
      const account = await loadInvitationAccount({ expectedAddress: mandate?.payer?.address, secretPath: invitationPath });
      return signPayerMandate({ mandate, signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }) });
    },
    async signPaymentRequest({ invitationPath, request }) {
      const account = await loadInvitationAccount({ expectedAddress: request?.payee?.address, secretPath: invitationPath });
      return signPaymentRequest({ request, signMessage: (bytes) => account.signMessage({ message: { raw: bytes } }) });
    },
    async readArtifactPackage({ artifactType, event, localState }) {
      const directory = artifactType === "preflight-participant-report"
        ? dirname(localState?.preflight?.outputPath ?? "")
        : artifactType === "identity-package"
          ? localState?.[event?.subjectRun]?.identityDirectory
          : localState?.[event?.subjectRun]?.resultDirectory;
      return buildPackage({ artifactType, directory, root: stateRoot });
    },
    validateRelayArtifact,
    async verifyPreflightPlan(bytes, context) {
      const checked = await validateRelayArtifactWithFacts({ artifactType: "preflight-plan", bytes, expectedDigest: context?.artifactDigest, secretCanaries: [] });
      const participant = checked.facts?.plan?.participants?.[context?.role];
      if (!participant || checked.facts.plan.paymentMoved !== false || checked.facts.plan.repositorySha !== context.repositorySha || participant.coordinationPublicKey !== context.coordinationIdentity?.publicKey || participant.publicKey !== context.preflight?.publicArtifact?.publicKey || !canonicalBytes(participant.tokenCommitment).equals(canonicalBytes(context.tokenCommitment))) fail();
      return checked;
    },
    async verifyDescriptor(bytes, context) {
      const checked = await validateRelayArtifactWithFacts({ artifactType: "signed-descriptor", bytes, expectedDigest: createHash("sha256").update(bytes).digest("hex"), secretCanaries: [] });
      const envelope = checked.facts;
      const keyId = envelope?.operator?.keyId;
      const operatorPublicKey = await repositoryInspector.operatorKey(context.repositorySha, keyId);
      const verified = verifyDescriptorEnvelope(envelope, { repositoryPublicKey: operatorPublicKey });
      const descriptor = envelope?.descriptor;
      const expectedDescriptorSessionId = deriveDescriptorSessionId({ releaseId: context.releaseId, repositorySha: context.repositorySha, sessionId: context.sessionId, subjectRun: context.subjectRun });
      if (!descriptor || descriptor.repositorySha !== context.repositorySha || descriptor.paymentMoved !== false || descriptor.sessionId !== expectedDescriptorSessionId || !["rehearsal", "stakeholder"].includes(context.subjectRun)) fail();
      const payer = context.enrollmentSet?.enrollments?.payer && parseCoordinationEnrollment(Buffer.from(context.enrollmentSet.enrollments.payer.enrollmentBase64, "base64"));
      const payee = context.enrollmentSet?.enrollments?.payee && parseCoordinationEnrollment(Buffer.from(context.enrollmentSet.enrollments.payee.enrollmentBase64, "base64"));
      if (!payer || !payee || descriptor.payer.address !== payer.invitations[context.subjectRun].address || descriptor.payee.address !== payee.invitations[context.subjectRun].address) fail();
      return verified;
    },
    async verifyIdentityPackage(bytes, context) {
      const checked = await validateRelayArtifactWithFacts({ artifactType: "identity-package", bytes, expectedDigest: createHash("sha256").update(bytes).digest("hex"), secretCanaries: [] });
      const entry = context?.enrollmentSet?.enrollments?.[context?.role];
      const enrollment = entry && parseCoordinationEnrollment(Buffer.from(entry.enrollmentBase64, "base64"));
      if (!enrollment || checked.facts.identity.address !== enrollment.invitations[context.subjectRun]?.address || checked.facts.identity.repositorySha !== context.repositorySha) fail();
      return checked;
    },
    createTransport,
    createCoordinationClient,
    createResumedCoordinationClient,
    validateActiveLaunchState,
    async resolveOperatorPublicKey(active) {
      if (!active || active.repositorySha !== scope.repositorySha || typeof active.operatorKeyId !== 'string') fail();
      return repositoryInspector.operatorKey(scope.repositorySha, active.operatorKeyId);
    },
  });
}
export { createCoordinationClient, createResumedCoordinationClient, validateActiveLaunchState, createGitInspector, SUPERVISOR_REPOSITORY_ROOT };
