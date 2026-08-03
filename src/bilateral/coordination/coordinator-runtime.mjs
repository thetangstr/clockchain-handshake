import { constants } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, randomUUID, X509Certificate } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { link, lstat, mkdir, open, readdir, rename, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createPublicClient, http } from "viem";
import { sepolia } from "viem/chains";

import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { canonicalBytes } from "../canonical.mjs";
import {
  payerMandateDigest,
  verifyPayerMandate,
} from "../payer-mandate.mjs";
import {
  paymentRequestDigest,
  verifyPaymentRequest,
} from "../payment-request.mjs";
import { BILATERAL_PROTOCOL, DESCRIPTOR_CHAIN_ID, DESCRIPTOR_EXPIRY_SECONDS, DESCRIPTOR_NAMESPACE, DESCRIPTOR_SCHEMA, DESCRIPTOR_SETTLEMENT, PROTOCOL_VERSION, REGISTRY_ADDRESS, createSignedEnvelope, dSession, rawPublicKeyBase64FromPem, validateDescriptor, verifyDescriptorEnvelope } from "../descriptor.mjs";
import { validateRelayArtifactWithFacts } from "./artifact.mjs";
import { createCapabilityRegistration } from "./capability-registration.mjs";
import { parseCoordinationEnrollment, parseCoordinationEnrollmentSet } from "./enrollment.mjs";
import { createCoordinatorRelease, COORDINATOR_STATE_SCHEMA, runCoordinator } from "./coordinator.mjs";
import { createOperatorRelayClient, createPinnedOperatorHttpsTransport } from "./operator-client.mjs";
import { deriveDescriptorSessionId } from "./run-session.mjs";
import { main as preflightMain, verifyCoordinationPreparationSet } from "../../../scripts/probe-bilateral-rendezvous.mjs";
import { computeBilateralPromptHash } from "../../../scripts/hash-bilateral-prompts.mjs";
import { createAwsWatcherProjection, watchBilateralSession } from "../../../scripts/watch-bilateral-session.mjs";
import { validatePublishedBilateralVerdict as validateVerdictPublication } from "../verdict.mjs";
import { createMcpClient } from "../../mcp.mjs";
import { assertSecretFree } from "../../redact.mjs";
import { validateFundingRecord } from "../funding/record.mjs";
import {
  validatePublicEndpoint,
} from "../network-endpoint.mjs";
import {
  buildAwsWatcherPublicMonitorSnapshot,
  buildPublicMonitorSnapshot,
} from "./public-monitor.mjs";
import { buildConsoleProjection } from "./console-projection.mjs";

export const COORDINATOR_CLI_FLAGS = Object.freeze([
  "--clockchain-token-file", "--operator-key-id", "--operator-private-key",
  "--release-root", "--relay-url", "--repository-sha", "--rpc-url-file",
  "--tls-certificate", "--tls-fingerprint",
]);
export const COORDINATOR_FUNDING_INTERVAL_MS = 20_000;
// Stakeholder demos start the operator and the remote participant minutes apart;
// align every wait window with the 30-minute signed-discovery expiry.
export const COORDINATOR_FUNDING_DEADLINE_MS = 30 * 60_000;
const ROOT = resolve(fileURLToPath(new URL("../../../", import.meta.url)));
const MAX_PRIVATE_BYTES = 64 * 1024;
const MAX_CERTIFICATE_BYTES = 1024 * 1024;
const STATE_MAX_BYTES = 64 * 1024;
const MAX_WATCHER_BYTES = 16 * 1024;
const FUNDING_ADDRESSES_FILE_NAME = "funding-addresses.json";
const CONSOLE_STATE_FILE_NAME = "console-state.json";
const FUNDING_ADDRESSES_SCHEMA = "clockchain.bilateral-funding-addresses/v1";
const VERIFIER_CONTEXT_SCHEMA = "clockchain.bilateral-coordinator-verifier-context/v1";
const VERIFIER_PUBLICATION_SCHEMA = "clockchain.bilateral-verifier-publication/v1";
const AWS_VERIFIER_EVIDENCE_SCHEMA = "clockchain.aws-verifier-evidence/v1";
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const ATTEMPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const AWS_PUBLICATION_KEYS = Object.freeze(["attemptId", "evidenceDigest", "paymentMoved", "publicationDigest", "repositorySha", "revision", "schema", "status", "taskArn", "writtenAtMs"]);
const TASK_ARN = /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const GIT_ENV = Object.freeze({ GIT_ATTR_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_SYSTEM: "/dev/null", GIT_NO_REPLACE_OBJECTS: "1", GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" });
const exec = promisify(execFile);
const fail = () => { throw new Error("Coordinator startup failed safely."); };
const sameDirectory = (a, b) => a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.gid === b.gid && a.mode === b.mode && a.isDirectory() && b.isDirectory();
const sameFile = (a, b) => a.dev === b.dev && a.ino === b.ino && a.uid === b.uid && a.gid === b.gid && a.nlink === b.nlink && a.size === b.size && a.mode === b.mode && a.ctimeMs === b.ctimeMs && a.mtimeMs === b.mtimeMs && a.isFile() && b.isFile();
const privateFile = (s) => s.isFile() && !s.isSymbolicLink() && s.uid === process.getuid() && s.nlink === 1 && (s.mode & 0o777) === 0o600;
const publicFile = (s) => s.isFile() && !s.isSymbolicLink() && s.nlink === 1;
const privateRoot = (s) => s.isDirectory() && !s.isSymbolicLink() && s.uid === process.getuid() && (s.mode & 0o777) === 0o700;
const relayPackageBytes = (value) => Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
function assertFundingAddresses(addresses) {
  if (!Array.isArray(addresses) || addresses.length !== 4 || new Set(addresses).size !== 4 || addresses.some((address) => !ADDRESS.test(address))) fail();
}
function fundingAddressBytes(record) {
  return Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
}
function validateExistingFundingRecord(bytes, addresses) {
  let parsed;
  try { parsed = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  let record;
  try { record = validateFundingRecord(parsed); } catch { fail(); }
  if (JSON.stringify(record) !== JSON.stringify(parsed) || JSON.stringify(record.addresses) !== JSON.stringify(addresses) || !bytes.equals(fundingAddressBytes(record))) fail();
  return record;
}
function admissionQuantity(value) {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === "string" && /^(?:0|[1-9][0-9]*)$/.test(value)) return BigInt(value);
  fail();
}
function createFundingAdmissionInspector({ createClient = createPublicClient, rpcUrl }) {
  if (typeof createClient !== "function" || typeof rpcUrl !== "string") fail();
  const client = createClient({ chain: sepolia, transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }) });
  if (!client || typeof client.getBalance !== "function" || typeof client.getTransactionCount !== "function") fail();
  return async (addresses) => {
    assertFundingAddresses(addresses);
    const participants = [];
    for (const address of addresses) {
      const [balanceWei, nonce] = await Promise.all([
        client.getBalance({ address }),
        client.getTransactionCount({ address, blockTag: "latest" }),
      ]);
      if (admissionQuantity(balanceWei) !== 0n || admissionQuantity(nonce) !== 0n) fail();
      participants.push({ address, balanceWei: "0", nonce: "0" });
    }
    return Object.freeze({
      addresses: Object.freeze([...addresses]),
      paymentMoved: false,
      participants: Object.freeze(participants.map(Object.freeze)),
      schema: FUNDING_ADDRESSES_SCHEMA,
    });
  };
}
function tokenText(bytes) { const text = bytes.toString("utf8"); const value = text.endsWith("\n") ? text.slice(0, -1) : text; if (!/^[!-~]{1,4096}$/.test(value) || value.includes("\r") || value.includes("\n")) fail(); return value; }
function abortableSleep(delay, signal) {
  if (!Number.isSafeInteger(delay) || delay < 0) fail();
  return new Promise((resolve_) => {
    if (signal?.aborted) { resolve_(); return; }
    const timer = setTimeout(done, delay);
    function done() { clearTimeout(timer); signal?.removeEventListener("abort", done); resolve_(); }
    signal?.addEventListener("abort", done, { once: true });
    if (signal?.aborted) done();
  });
}

function validateAbortSignal(value) {
  if (value === undefined) return undefined;
  if (
    !(value instanceof AbortSignal) ||
    Object.getPrototypeOf(value) !== AbortSignal.prototype
  ) {
    fail();
  }
  try {
    const noop = () => {};
    AbortSignal.prototype.addEventListener.call(value, "abort", noop);
    AbortSignal.prototype.removeEventListener.call(value, "abort", noop);
  } catch {
    fail();
  }
  return value;
}

function abortIfRequested(signal) {
  if (signal?.aborted) fail();
}

function combinedAbortSignal(first, second) {
  if (first === undefined) return second;
  if (second === undefined) return first;
  return AbortSignal.any([first, second]);
}

async function writePrivate(path, bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 3_145_728) fail();
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
function fundingFileSystem(value) {
  const methods = ["link", "lstat", "open", "readdir", "unlink"];
  if (value === undefined) return Object.freeze({ link, lstat, open, readdir, unlink });
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).length !== methods.length || methods.some((method) => typeof value[method] !== "function")) fail();
  return Object.freeze(Object.fromEntries(methods.map((method) => [method, value[method]])));
}
async function writePrivateWithFileSystem(path, bytes, fs) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 3_145_728) fail();
  const handle = await fs.open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}
async function publishFundingAddresses(root, addresses, { fs = fundingFileSystem(), inspectAdmission } = {}) {
  assertFundingAddresses(addresses);
  const path = join(root.path, FUNDING_ADDRESSES_FILE_NAME);
  await assertRoot(root, fs);
  const names = await fs.readdir(root.path);
  if (!Array.isArray(names) || names.some((name) => typeof name !== "string" || name.startsWith(".funding-addresses") && name.endsWith(".tmp"))) fail();
  let existing = null;
  try { existing = await readStable(path, 4096, privateFile, fs); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  if (existing !== null) {
    validateExistingFundingRecord(existing, addresses);
    await assertRoot(root, fs);
    return existing;
  }
  if (typeof inspectAdmission !== "function") fail();
  const bytes = fundingAddressBytes(validateFundingRecord(await inspectAdmission(addresses)));
  const temporary = join(root.path, `.${FUNDING_ADDRESSES_FILE_NAME}.${randomUUID()}.tmp`);
  try {
    await writePrivateWithFileSystem(temporary, bytes, fs);
    await assertRoot(root, fs);
    try { await readStable(path, bytes.length + 1, privateFile, fs); fail(); } catch (error) { if (error?.message === "Coordinator startup failed safely.") throw error; if (error?.code !== "ENOENT") fail(); }
    await fs.link(temporary, path);
    await fs.unlink(temporary);
    await root.handle.sync();
    await assertRoot(root, fs);
    if (!(await readStable(path, bytes.length + 1, privateFile, fs)).equals(bytes)) fail();
    return bytes;
  } finally {
    await fs.unlink(temporary).catch(() => {});
  }
}
export async function publishConsoleState(root, value, fs = fundingFileSystem()) {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  if (bytes.length > 65_536) fail();
  assertSecretFree(bytes.toString("utf8"));
  const path = join(root.path, CONSOLE_STATE_FILE_NAME);
  await assertRoot(root, fs);
  let existing = null;
  let destination = null;
  try { existing = await readStable(path, STATE_MAX_BYTES, privateFile, fs); } catch (error) { if (error?.code !== "ENOENT") throw error; }
  if (existing !== null) {
    destination = await fs.lstat(path);
    if (existing.equals(bytes)) {
      await assertRoot(root, fs);
      return path;
    }
  }
  const temporary = join(root.path, `.${CONSOLE_STATE_FILE_NAME}.${randomUUID()}.tmp`);
  try {
    await writePrivateWithFileSystem(temporary, bytes, fs);
    await assertRoot(root, fs);
    if (destination === null) {
      try { await fs.lstat(path); fail(); } catch (error) { if (error?.message === "Coordinator startup failed safely.") throw error; if (error?.code !== "ENOENT") fail(); }
    } else if (!sameFile(destination, await fs.lstat(path))) {
      fail();
    }
    await rename(temporary, path);
    await root.handle.sync();
    await assertRoot(root, fs);
    if (!(await readStable(path, STATE_MAX_BYTES, privateFile, fs)).equals(bytes)) fail();
    return path;
  } finally {
    await fs.unlink(temporary).catch(() => {});
  }
}
async function privateStage(root, name) {
  await assertRoot(root); const path = join(root.path, name); await mkdir(path, { mode: 0o700, recursive: true }); await assertRoot(root); const metadata = await lstat(path); if (!privateRoot(metadata)) fail(); return path;
}
function relayFiles(bytes) {
  let wrapper; try { wrapper = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  if (!wrapper || wrapper.schema !== "clockchain.bilateral-relay-package/v1" || wrapper.paymentMoved !== false || !Array.isArray(wrapper.files)) fail();
  return wrapper.files.map((entry) => { if (!entry || typeof entry.name !== "string" || !/^[.A-Za-z0-9_-]+$/.test(entry.name) || typeof entry.contentBase64 !== "string" || typeof entry.sha256 !== "string" || typeof entry.byteLength !== "string") fail(); const content = Buffer.from(entry.contentBase64, "base64"); if (content.toString("base64") !== entry.contentBase64 || createHash("sha256").update(content).digest("hex") !== entry.sha256 || String(content.length) !== entry.byteLength) fail(); return Object.freeze({ content, name: entry.name }); });
}
export async function stagePackage(root, name, artifactType, bytes, options = {}) {
  await assertRoot(root);
  const digest = createHash("sha256").update(bytes).digest("hex"); await (options.validate ?? validateRelayArtifactWithFacts)({ artifactType, bytes, expectedDigest: digest, secretCanaries: [] });
  const expected = relayFiles(bytes); const directory = join(root.path, name); let created = false;
  try { await mkdir(directory, { mode: 0o700 }); created = true; } catch (error) { if (error?.code !== "EEXIST") throw error; }
  await assertRoot(root);
  const metadata = await lstat(directory); if (!privateRoot(metadata)) fail();
  if (!created) {
    const names = await readdir(directory); if (names.length !== expected.length || names.some((name_) => !expected.some((entry) => entry.name === name_))) fail();
    for (const entry of expected) if (!(await readStable(join(directory, entry.name), entry.content.length + 1, privateFile)).equals(entry.content)) fail();
    await assertRoot(root); return directory;
  }
  try { for (const entry of expected) await writePrivate(join(directory, entry.name), entry.content); } catch (error) { throw error; }
  await assertRoot(root); return directory;
}
export function validateVerifierPackageBinding({ descriptor, party, repositorySha, role, sessionDigest }) {
  if (!descriptor || !party || !["payer", "payee"].includes(role) || party.role !== role || party.repositorySha !== repositorySha || party.sessionDigest !== sessionDigest || party.signature?.address?.toLowerCase() !== descriptor[role]?.address?.toLowerCase()) fail();
}

export async function launchExternalVerifier({
  evidenceDescriptor,
  expectedRevision,
  releaseId,
  repositorySha,
  sessionId,
  verifierLauncher,
}) {
  if (
    !evidenceDescriptor ||
    typeof evidenceDescriptor !== "object" ||
    Array.isArray(evidenceDescriptor) ||
    Object.keys(evidenceDescriptor).length !== 5 ||
    !SHA64.test(evidenceDescriptor.descriptorDigest) ||
    !SHA64.test(evidenceDescriptor.evidenceDigest) ||
    evidenceDescriptor.paymentMoved !== false ||
    evidenceDescriptor.schema !== AWS_VERIFIER_EVIDENCE_SCHEMA ||
    !["rehearsal", "stakeholder"].includes(evidenceDescriptor.subjectRun) ||
    !Number.isSafeInteger(expectedRevision) ||
    expectedRevision < 0 ||
    !/^release-[0-9a-f]{16}$/.test(releaseId) ||
    !SHA40.test(repositorySha) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(sessionId) ||
    !verifierLauncher ||
    typeof verifierLauncher.launch !== "function"
  ) {
    fail();
  }
  let launched;
  try {
    launched = await verifierLauncher.launch({
      evidenceDescriptor,
      expectedRevision,
      releaseId,
      repositorySha,
      sessionId,
    });
  } catch {
    fail();
  }
  if (
    !launched ||
    typeof launched !== "object" ||
    Array.isArray(launched) ||
    Reflect.ownKeys(launched).length !== 4 ||
    !Object.hasOwn(launched, "attemptId") ||
    !Object.hasOwn(launched, "publicationDigest") ||
    !Object.hasOwn(launched, "status") ||
    !Object.hasOwn(launched, "taskArn") ||
    !SHA64.test(launched.publicationDigest) ||
    launched.status !== "VERIFICATION_PASSED" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(launched.attemptId) ||
    !/^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/.test(launched.taskArn)
  ) {
    fail();
  }
  return Object.freeze({
    exitCode: 0,
    publicationDigest: launched.publicationDigest,
    status: launched.status,
    stderr: "",
    stdout: "",
  });
}

function externalVerifierRevision(
  action,
  release,
  subjectRun,
) {
  if (
    !action ||
    typeof action !== "object" ||
    Array.isArray(action) ||
    Object.keys(action).length !== 6 ||
    action.action !== "VERIFY" ||
    !Number.isSafeInteger(
      action.expectedRevision,
    ) ||
    action.expectedRevision < 0 ||
    action.releaseId !== release.releaseId ||
    action.repositorySha !==
      release.repositorySha ||
    action.sessionId !== release.sessionId ||
    action.subjectRun !== subjectRun
  ) {
    fail();
  }
  return action.expectedRevision;
}
export function validatePinnedDescriptorEnvelope(envelope, { keyId, publicKey, repositorySha, sessionId }) {
  if (!envelope?.operator || envelope.operator.keyId !== keyId || envelope.operator.publicKey !== publicKey || envelope.descriptor?.repositorySha !== repositorySha || envelope.descriptor.paymentMoved !== false || envelope.descriptor.sessionId !== sessionId) fail();
  verifyDescriptorEnvelope(envelope, { repositoryPublicKey: publicKey });
}
export async function createCoordinatorDescriptor({ mandateEnvelope, nowMs = Date.now(), parties, promptSha256, repositorySha, requestEnvelope, sessionId }) {
  if (!parties?.payer || !parties?.payee || !SHA40.test(repositorySha) || !SHA64.test(promptSha256) || !/^[0-9a-f]{32}$/.test(sessionId) || !Number.isSafeInteger(nowMs) || nowMs < 0) fail();
  const mandate = mandateEnvelope?.mandate;
  if (!mandate || mandate.repositorySha !== repositorySha || mandate.payer?.address !== parties.payer.address || mandate.payer?.agentId !== parties.payer.agentId || mandate.payee?.address !== parties.payee.address || mandate.payee?.agentId !== parties.payee.agentId || parties.payer.role !== "payer" || parties.payee.role !== "payee") fail();
  const expected = {
    amount: mandate.amount,
    intakeDigest: mandate.intakeDigest,
    intakeRequestId: mandate.intakeRequestId,
    invoiceReferencePrefix: mandate.invoiceReferencePrefix,
    payee: mandate.payee,
    payer: mandate.payer,
    purpose: mandate.purpose,
    releaseId: mandate.releaseId,
    repositorySha,
    sessionId: mandate.sessionId,
    subjectRun: mandate.subjectRun,
  };
  let verifiedMandate;
  let verifiedRequest;
  try {
    verifiedMandate = await verifyPayerMandate({
      envelope: mandateEnvelope,
      expected: { ...expected, requestEndpoint: `/v1/sessions/${expected.sessionId}/payment-requests` },
      nowMs,
    });
    verifiedRequest = await verifyPaymentRequest({
      envelope: requestEnvelope,
      mandateEnvelope,
      expected,
      nowMs,
    });
  } catch { fail(); }
  const mandateDigest = payerMandateDigest(verifiedMandate);
  const requestDigest = paymentRequestDigest(verifiedRequest);
  const descriptor = { amountOptions: [verifiedRequest.request.amount], chainId: DESCRIPTOR_CHAIN_ID, expirySeconds: DESCRIPTOR_EXPIRY_SECONDS, mandateDigest, namespace: DESCRIPTOR_NAMESPACE, payee: parties.payee, payer: parties.payer, paymentMoved: false, promptSha256, protocol: BILATERAL_PROTOCOL, protocolVersion: PROTOCOL_VERSION, registry: REGISTRY_ADDRESS, repositorySha, requestDigest, schema: DESCRIPTOR_SCHEMA, sessionId, settlement: DESCRIPTOR_SETTLEMENT };
  validateDescriptor(descriptor); return descriptor;
}
export function createWatcherLifecycle({ run }) {
  const started = new Set(); const failures = new Map();
  return Object.freeze({
    async start(subjectRun, signal) {
      if (started.has(subjectRun)) return;
      started.add(subjectRun);
      try {
        const result = await run(subjectRun, signal);
        if (result === null || typeof result !== "object" || Array.isArray(result) || Object.getPrototypeOf(result) !== Object.prototype || result.paymentMoved !== false || result.terminal !== null) throw new Error("watcher terminal outcome");
      } catch (error) { failures.set(subjectRun, error); }
    },
    assertHealthy(subjectRun) { if (failures.has(subjectRun)) fail(); },
  });
}
export function watcherLine(snapshot, canary) {
  let canonical;
  if (snapshot === null || typeof snapshot !== "object" || Array.isArray(snapshot) || Object.getPrototypeOf(snapshot) !== Object.prototype || snapshot.paymentMoved !== false) fail();
  try { assertSecretFree(snapshot, [canary]); canonical = JSON.stringify(canonicalizeReceiptEventValue(snapshot)); } catch { fail(); }
  if (Buffer.byteLength(canonical, "utf8") > MAX_WATCHER_BYTES || /authorized/i.test(canonical)) fail();
  return `${canonical}\n`;
}

export function parseCoordinatorArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== COORDINATOR_CLI_FLAGS.length * 2) fail();
  const values = Object.create(null);
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i]; const value = argv[i + 1];
    if (!COORDINATOR_CLI_FLAGS.includes(flag) || Object.hasOwn(values, flag) || typeof value !== "string" || value.length === 0 || value.includes("\0")) fail();
    values[flag] = value;
  }
  if (!COORDINATOR_CLI_FLAGS.every((flag) => Object.hasOwn(values, flag))) fail();
  return Object.freeze(values);
}

export { deriveDescriptorSessionId };

async function readStable(path, maximum, predicate, fs = { lstat, open }) {
  const before = await fs.lstat(path); if (!predicate(before) || before.size > maximum) fail();
  const handle = await fs.open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat(); if (!predicate(opened) || !sameFile(before, opened)) fail();
    const bytes = Buffer.allocUnsafe(before.size + 1); const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
    const after = await fs.lstat(path); if (bytesRead !== before.size || !sameFile(before, after) || !sameFile(before, await handle.stat())) fail();
    return bytes.subarray(0, bytesRead);
  } finally { await handle.close(); }
}
async function pinRoot(path, fs = { lstat, mkdir, open }) {
  await fs.mkdir(path, { mode: 0o700, recursive: true });
  const before = await fs.lstat(path); if (!privateRoot(before)) fail();
  const handle = await fs.open(path, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
  const opened = await handle.stat(); if (!privateRoot(opened) || !sameDirectory(before, opened)) { await handle.close(); fail(); }
  return Object.freeze({ handle, path, before });
}
async function assertRoot(root, fs = { lstat }) { const current = await fs.lstat(root.path); if (!privateRoot(current) || !sameDirectory(root.before, current) || !sameDirectory(root.before, await root.handle.stat())) fail(); }
function canonical(value) { return Buffer.from(`${JSON.stringify(canonicalizeReceiptEventValue(value))}\n`, "utf8"); }
async function readState(root, fs = { lstat, open }) {
  await assertRoot(root);
  let bytes;
  try { bytes = await readStable(join(root.path, "coordinator-state.json"), STATE_MAX_BYTES, privateFile, fs); } catch (error) { if (error?.code === "ENOENT") { await assertRoot(root); return null; } throw error; }
  let state; try { state = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  const keys = ["capabilityDigests", "checkpoints", "paymentMoved", "releaseId", "repositorySha", "schema", "sessionId", "state"];
  if (!state || Object.keys(state).length !== keys.length || keys.some((key) => !Object.hasOwn(state, key)) || !bytes.equals(canonical(state)) || state.schema !== COORDINATOR_STATE_SCHEMA || state.paymentMoved !== false || !SHA40.test(state.repositorySha) || !Array.isArray(state.capabilityDigests) || state.capabilityDigests.length !== 2 || state.capabilityDigests.some((d) => !SHA64.test(d))) fail();
  await assertRoot(root); return Object.freeze(state);
}
export async function readCoordinatorState(root) { return readState(root); }
async function writeState(root, state, fs = { open, rename, unlink }) {
  await assertRoot(root); const bytes = canonical(state); const temporary = join(root.path, `.coordinator-state-${randomUUID()}.tmp`);
  let file;
  try { file = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600); await file.writeFile(bytes); await file.sync(); await file.close(); file = undefined; await assertRoot(root); await fs.rename(temporary, join(root.path, "coordinator-state.json")); await root.handle.sync(); } catch (error) { if (file) await file.close(); await fs.unlink(temporary).catch(() => {}); throw error; }
}
export async function writeVerifierContext(root, name, value) {
  if (typeof name !== "string" || name.includes("/") || name.includes("\\")) fail();
  const path = join(root.path, name); if (dirname(path) !== root.path) fail();
  await assertRoot(root); const bytes = canonical(value); const temporary = join(root.path, `.${name}.${randomUUID()}.tmp`);
  try { await writePrivate(temporary, bytes); await assertRoot(root); await rename(temporary, path); await assertRoot(root); await root.handle.sync(); if (!(await readStable(path, STATE_MAX_BYTES, privateFile)).equals(bytes)) fail(); await assertRoot(root); } finally { await unlink(temporary).catch(() => {}); }
}
export async function readVerifierContext(root, name) {
  if (typeof name !== "string" || name.includes("/") || name.includes("\\")) fail();
  const path = join(root.path, name); if (dirname(path) !== root.path) fail(); await assertRoot(root);
  const bytes = await readStable(path, STATE_MAX_BYTES, privateFile);
  let value; try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(); }
  const keys = ["descriptorDigest", "mandateDigest", "outputDirectory", "packageDigests", "paymentMoved", "publicationDigest", "releaseId", "repositorySha", "requestDigest", "schema", "sessionId", "subjectRun"];
  if (!value || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)) || !SHA64.test(value.descriptorDigest) || !SHA64.test(value.mandateDigest) || typeof value.outputDirectory !== "string" || !SHA64.test(value.packageDigests?.payer) || !SHA64.test(value.packageDigests?.payee) || !SHA64.test(value.publicationDigest) || !SHA64.test(value.requestDigest) || value.paymentMoved !== false || value.schema !== VERIFIER_CONTEXT_SCHEMA || !["rehearsal", "stakeholder"].includes(value.subjectRun) || !canonical(value).equals(bytes)) fail();
  await assertRoot(root); return Object.freeze(value);
}
export async function runChildWithDeadline(args, deadlineMs = COORDINATOR_FUNDING_DEADLINE_MS, graceMs = 5_000) {
  return new Promise((resolve_) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, env: GIT_ENV, stdio: ["ignore", "inherit", "inherit"] }); let settled = false;
    const finish = (value) => { if (!settled) { settled = true; clearTimeout(term); clearTimeout(kill); resolve_(value); } };
    const term = setTimeout(() => child.kill("SIGTERM"), deadlineMs);
    const kill = setTimeout(() => child.kill("SIGKILL"), deadlineMs + graceMs);
    child.once("error", () => { child.kill("SIGTERM"); finish(null); });
    child.once("close", (code, signal) => finish(signal === null && code === 0 ? 0 : null));
  });
}
export async function runPinnedVerifierChild(root, args, deadline, runner = runChildWithDeadline) {
  await assertRoot(root);
  try { return await runner(args, deadline); } finally { await assertRoot(root); }
}
function relayUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
    if (parsed.port === "") fail();
    const endpoint = validatePublicEndpoint(
      `${value}/`,
      {
        allowedPaths: ["/"],
        allowTestAddresses: true,
        defaultPort: Number(parsed.port),
        protocols: ["https:"],
      },
    );
    return endpoint.url.slice(0, -1);
  } catch {
    fail();
  }
}
function rpcEndpoint(value) { let endpoint; try { endpoint = new URL(value); } catch { fail(); } if (!/^https?:$/.test(endpoint.protocol) || endpoint.username || endpoint.password || endpoint.hash || endpoint.search || endpoint.pathname !== "/") fail(); return endpoint.href; }
async function gitInspector(repositoryRoot = ROOT) {
  const run = (args) => exec("/usr/bin/git", ["--no-pager", "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-c", "core.hooksPath=/dev/null", "-C", repositoryRoot, ...args], { cwd: repositoryRoot, encoding: "utf8", env: GIT_ENV, maxBuffer: 8192 });
  const [{ stdout: head }, { stdout: status }] = await Promise.all([run(["rev-parse", "--verify", "HEAD^{commit}"]), run(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"])]);
  if (!SHA40.test(head.trim()) || status !== "") fail();
  return Object.freeze({ head: head.trim(), async operatorKey(sha, id) { if (!SHA40.test(sha) || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) fail(); const { stdout } = await run(["show", `${sha}:docs/operator-keys/${id}.pub`]); if (!/^[A-Za-z0-9+/]{43}=\n$/.test(stdout)) fail(); return stdout.slice(0, -1); } });
}

async function verifyTaskProvenance(dependencies, operatorKeyId, repositorySha) {
  const provider = dependencies.provenanceProvider;
  if (provider === undefined) {
    const inspector = dependencies.gitInspector ?? await gitInspector(dependencies.repositoryRoot ?? ROOT);
    if (inspector.head !== repositorySha) fail();
    const operatorPublicKey = await inspector.operatorKey(repositorySha, operatorKeyId);
    return Object.freeze({ operatorPublicKey, repositorySha });
  }
  if (!provider || typeof provider !== "object" || typeof provider.verify !== "function") fail();
  let result;
  try {
    result = await provider.verify({ operatorKeyId, repositorySha });
  } catch {
    fail();
  }
  const keys = ["imageDigest", "operatorPublicKey", "repositorySha", "sourceTreeSha256"];
  if (
    !result ||
    typeof result !== "object" ||
    Array.isArray(result) ||
    Object.getPrototypeOf(result) !== Object.prototype ||
    Object.keys(result).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(result, key)) ||
    result.repositorySha !== repositorySha ||
    !/^[A-Za-z0-9+/]{43}=$/.test(result.operatorPublicKey) ||
    Buffer.from(result.operatorPublicKey, "base64").length !== 32 ||
    !SHA64.test(result.sourceTreeSha256) ||
    !(result.imageDigest === null || /^sha256:[0-9a-f]{64}$/.test(result.imageDigest))
  ) {
    fail();
  }
  return Object.freeze({ ...result });
}

export async function readCoordinatorRuntimeConfig(values, dependencies = {}) {
  const input = parseCoordinatorArguments(COORDINATOR_CLI_FLAGS.flatMap((flag) => [flag, values[flag]]));
  if (!SHA40.test(input["--repository-sha"]) || !SHA64.test(input["--tls-fingerprint"])) fail();
  const fs = dependencies.fs ?? { lstat, mkdir, open, rename, unlink };
  const root = await pinRoot(input["--release-root"], fs);
  try {
    const [token, privateKeyPem, rpcUrl, certificate] = await Promise.all([
      readStable(input["--clockchain-token-file"], MAX_PRIVATE_BYTES, privateFile, fs), readStable(input["--operator-private-key"], MAX_PRIVATE_BYTES, privateFile, fs), readStable(input["--rpc-url-file"], MAX_PRIVATE_BYTES, privateFile, fs), readStable(input["--tls-certificate"], MAX_CERTIFICATE_BYTES, publicFile, fs),
    ]);
    const relay = relayUrl(input["--relay-url"]); const endpoint = rpcEndpoint(rpcUrl.toString("utf8").trim());
    const pem = certificate.toString("utf8"); const fingerprint = createHash("sha256").update(new X509Certificate(pem).raw).digest("hex"); if (fingerprint !== input["--tls-fingerprint"]) fail();
    let actualKey; try { actualKey = rawPublicKeyBase64FromPem(createPublicKey(createPrivateKey(privateKeyPem)).export({ format: "pem", type: "spki" })); } catch { fail(); }
    const provenance = await verifyTaskProvenance(dependencies, input["--operator-key-id"], input["--repository-sha"]);
    const pinned = provenance.operatorPublicKey;
    if (pinned !== actualKey) fail();
    return Object.freeze({ clockchainToken: tokenText(token), clockchainTokenPath: input["--clockchain-token-file"], operatorIdentity: Object.freeze({ keyId: input["--operator-key-id"], privateKeyPem: privateKeyPem.toString("utf8"), publicKey: actualKey }), operatorPrivateKeyPath: input["--operator-private-key"], releaseRoot: root, relayUrl: relay, repositorySha: input["--repository-sha"], rpcUrl: endpoint, rpcUrlPath: input["--rpc-url-file"], tlsCertificatePem: pem, tlsCertificatePath: input["--tls-certificate"], tlsFingerprint: fingerprint, operatorPublicKey: pinned });
  } catch (error) { await root.handle.close(); throw error; }
}

export function createProductionFundingWaiter({ createClient = createPublicClient, intervalMs = COORDINATOR_FUNDING_INTERVAL_MS, now = Date.now, rpcUrl, sleeper = (ms) => new Promise((resolve_) => setTimeout(resolve_, ms)) }) {
  if (typeof createClient !== "function" || !Number.isSafeInteger(intervalMs) || intervalMs < 1000 || intervalMs > COORDINATOR_FUNDING_INTERVAL_MS || typeof rpcUrl !== "string") fail();
  const client = createClient({ chain: sepolia, transport: http(rpcUrl, { retryCount: 0, timeout: 15_000 }) }); if (!client || typeof client.getBalance !== "function" || typeof client.getTransactionCount !== "function") fail();
  return async (addresses) => {
    if (!Array.isArray(addresses) || addresses.length !== 4 || new Set(addresses).size !== 4 || addresses.some((a) => typeof a !== "string" || !ADDRESS.test(a))) fail();
    const deadline = now() + COORDINATOR_FUNDING_DEADLINE_MS;
    for (;;) {
      const records = await Promise.all(addresses.map(async (address) => ({ address, balanceWei: (await client.getBalance({ address })).toString(), nonce: (await client.getTransactionCount({ address, blockTag: "latest" })).toString(), paymentMoved: false })));
      if (records.every((r) => BigInt(r.balanceWei) >= 5_000_000_000_000_000n && BigInt(r.balanceWei) <= 20_000_000_000_000_000n && r.nonce === "0")) return Object.freeze(records.map(Object.freeze));
      if (now() >= deadline) fail(); await sleeper(Math.min(intervalMs, Math.max(1, deadline - now())));
    }
  };
}

export function createCoordinatorRuntimeDependencies(config, dependencies = {}) {
  if (!config || typeof config !== "object" || !config.releaseRoot?.path || !config.operatorIdentity || !SHA40.test(config.repositorySha)) fail();
  const abortSignal = validateAbortSignal(dependencies.abortSignal);
  const releaseIdentity =
    dependencies.releaseIdentity;
  if (
    releaseIdentity !== undefined &&
    (
      releaseIdentity === null ||
      typeof releaseIdentity !== "object" ||
      Array.isArray(releaseIdentity) ||
      Object.getPrototypeOf(
        releaseIdentity,
      ) !== Object.prototype ||
      Reflect.ownKeys(
        releaseIdentity,
      ).length !== 2 ||
      !Object.hasOwn(
        releaseIdentity,
        "releaseId",
      ) ||
      !Object.hasOwn(
        releaseIdentity,
        "sessionId",
      ) ||
      !/^release-[0-9a-f]{16}$/.test(
        releaseIdentity.releaseId,
      ) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
        releaseIdentity.sessionId,
      ) ||
      releaseIdentity.releaseId !==
        `release-${createHash("sha256").update(releaseIdentity.sessionId, "utf8").digest("hex").slice(0, 16)}`
    )
  ) {
    fail();
  }
  if (
    dependencies.createLaunchManifest !== undefined &&
    typeof dependencies.createLaunchManifest !== "function"
  ) fail();
  if (
    dependencies.writeLaunchManifest !== undefined &&
    typeof dependencies.writeLaunchManifest !== "function"
  ) fail();
  const publicStager = dependencies.publicStager;
  if (
    publicStager !== undefined &&
    (
      publicStager === null ||
      typeof publicStager !== "object" ||
      Array.isArray(publicStager) ||
      typeof publicStager.stageSnapshot !== "function"
    )
  ) fail();
  const transport = (dependencies.createTransport ?? createPinnedOperatorHttpsTransport)({ expectedFingerprint: config.tlsFingerprint, relayUrl: config.relayUrl, tlsCertificatePem: config.tlsCertificatePem });
  const artifactValidator = dependencies.validateArtifactWithFacts ?? validateRelayArtifactWithFacts;
  const verdictPublicationValidator = dependencies.validateVerdictPublication ?? validateVerdictPublication;
  if (typeof verdictPublicationValidator !== "function") fail();
  const verifierVerdictReader = dependencies.readVerifierVerdictBytes ?? (async ({ outputDirectory }) => readStable(join(outputDirectory, "bilateral-verdict.json"), 1_048_576, privateFile));
  if (typeof verifierVerdictReader !== "function") fail();
  const clientFor = (release) => (dependencies.createClient ?? createOperatorRelayClient)({ operatorIdentity: config.operatorIdentity, releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, transport });
  let newRelease = null;
  const watcherSnapshots = new Map();
  const now = dependencies.now ?? Date.now;
  const sleeper = dependencies.sleeper ?? ((ms) => new Promise((resolve_) => setTimeout(resolve_, ms)));
  if (typeof now !== "function" || typeof sleeper !== "function") fail();
  const sleep = (delay) => abortSignal === undefined
    ? sleeper(delay)
    : abortableSleep(delay, abortSignal);
  const eventReadInput = (input) => abortSignal === undefined ? input : { ...input, signal: abortSignal };
  const waitForRawEvent = async (client, release, { artifactDigest, kinds, role, subjectRun }) => {
    if (!Array.isArray(kinds) || kinds.length === 0 || !["payer", "payee"].includes(role) || !["release", "rehearsal", "stakeholder"].includes(subjectRun)) fail();
    const deadline = now() + COORDINATOR_FUNDING_DEADLINE_MS;
    for (;;) {
      abortIfRequested(abortSignal);
      const events = await client.readEvents(eventReadInput({ after: null, waitMs: 30_000 }));
      abortIfRequested(abortSignal);
      const matched = events.filter((event) => event.role === role && event.subjectRun === subjectRun && kinds.includes(event.kind) && (artifactDigest === undefined || event.artifactDigest === artifactDigest));
      if (matched.length === 1) return Object.freeze(matched[0]);
      if (matched.length > 1 || now() >= deadline) fail();
      await sleep(Math.min(COORDINATOR_FUNDING_INTERVAL_MS, Math.max(1, deadline - now())));
    }
  };
  const immutable = async () => {
    const provenance = await verifyTaskProvenance(dependencies, config.operatorIdentity.keyId, config.repositorySha);
    if (provenance.operatorPublicKey !== config.operatorIdentity.publicKey) fail();
    const token = await readStable(config.clockchainTokenPath, MAX_PRIVATE_BYTES, privateFile);
    const key = await readStable(config.operatorPrivateKeyPath, MAX_PRIVATE_BYTES, privateFile);
    if (tokenText(token) !== config.clockchainToken || key.toString("utf8") !== config.operatorIdentity.privateKeyPem) fail();
    const rpc = await readStable(config.rpcUrlPath, MAX_PRIVATE_BYTES, privateFile); const certificate = await readStable(config.tlsCertificatePath, MAX_CERTIFICATE_BYTES, publicFile);
    if (rpcEndpoint(rpc.toString("utf8").trim()) !== config.rpcUrl || createHash("sha256").update(new X509Certificate(certificate.toString("utf8")).raw).digest("hex") !== config.tlsFingerprint) fail();
  };
  const state = { readState: () => readState(config.releaseRoot), writeState: ({ state: value }) => writeState(config.releaseRoot, value) };
  const runDependencyCache = new Map();
  return Object.freeze({
    createReleaseDependencies: Object.freeze({
      ...(dependencies.createLaunchManifest === undefined
        ? {}
        : {
            createLaunchManifest:
              dependencies.createLaunchManifest,
          }),
      ...(dependencies.writeLaunchManifest === undefined
        ? {}
        : {
            writeLaunchManifest:
              dependencies.writeLaunchManifest,
          }),
      now,
      randomUUID: () => {
        const sessionId =
          releaseIdentity?.sessionId ??
          randomUUID();
        newRelease = Object.freeze({
          releaseId:
            releaseIdentity?.releaseId ??
            `release-${createHash("sha256").update(sessionId, "utf8").digest("hex").slice(0, 16)}`,
          sessionId,
        });
        return sessionId;
      },
      prepareCapabilityRegistration: async ({ capabilities }) => {
        if (newRelease === null) fail();
        return createCapabilityRegistration({ capabilities, operatorKeyId: config.operatorIdentity.keyId, paymentMoved: false, privateKeyPem: config.operatorIdentity.privateKeyPem, releaseId: newRelease.releaseId, repositorySha: config.repositorySha, sessionId: newRelease.sessionId });
      },
      registerCapabilitySet: async ({ registration }) => clientFor(registration).registerCapabilitySet({ registration }),
      writeState: state.writeState,
    }),
    runDependencies: (release) => {
      const key = `${release?.releaseId}:${release?.repositorySha}:${release?.sessionId}`;
      if (runDependencyCache.has(key)) return runDependencyCache.get(key);
      const client = clientFor(release); const watcherDescriptors = new Map(); const watcherControllers = new Map(); const watcherTasks = new Map(); const cached = new Map(); const verifierContexts = new Map(); let displayedFunding = false;
      const watcherOutput = dependencies.watcherOutput ?? ((line) => process.stdout.write(line));
      const publicRunId = `run-${release.releaseId.slice("release-".length)}`;
      const stagePublicWatcherSnapshot = async (subjectRun, snapshot) => {
        if (publicStager === undefined || subjectRun !== "stakeholder") return;
        const observedAtMs = now();
        const projection = createAwsWatcherProjection(snapshot, {
          observedAtMs,
          releaseId: release.releaseId,
          repositorySha: config.repositorySha,
          sessionId: release.sessionId,
          subjectRun,
        });
        const publicSnapshot = buildAwsWatcherPublicMonitorSnapshot(
          projection,
          {
            nowMs: observedAtMs,
            publishedAtMs: observedAtMs,
            releaseId: release.releaseId,
            repositorySha: config.repositorySha,
            runId: publicRunId,
            sessionId: release.sessionId,
            staleAfterMs: 60_000,
            subjectRun,
          },
        );
        await publicStager.stageSnapshot({
          completedAtMs: null,
          nowMs: observedAtMs,
          snapshot: publicSnapshot,
          verifierPublicationValidated: false,
        });
      };
      const watcherLifecycle = createWatcherLifecycle({
        run: async (subjectRun, signal) => {
          const descriptor = watcherDescriptors.get(subjectRun); if (!descriptor) fail();
          const combinedSignal = combinedAbortSignal(abortSignal, signal);
          let startedAt;
          const watcherNow = () => { const value = now(); if (startedAt === undefined) startedAt = value; return combinedSignal?.aborted ? startedAt + COORDINATOR_FUNDING_DEADLINE_MS : value; };
          const watcherSleep = (delay) => abortableSleep(delay, combinedSignal);
          const client = (dependencies.createWatcherClient ?? (({ signal: externalSignal, token }) => createMcpClient({ fetchImpl: (url, init = {}) => { const signals = [externalSignal, init.signal].filter((value) => value !== undefined); return (dependencies.watcherFetch ?? globalThis.fetch)(url, { ...init, signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals) }); }, maxAttempts: 1, token })))({ signal: combinedSignal, token: config.clockchainToken });
          return await (dependencies.watchBilateralSession ?? watchBilateralSession)({ advisory: { health: null, status: null }, canaries: [config.clockchainToken], client, descriptor, now: watcherNow, output: async (snapshot) => { await stagePublicWatcherSnapshot(subjectRun, snapshot); const line = watcherLine(snapshot, config.clockchainToken); watcherSnapshots.set(subjectRun, structuredClone(snapshot)); watcherOutput(line); }, signal: combinedSignal, sleeper: watcherSleep, windowMs: COORDINATOR_FUNDING_DEADLINE_MS });
        },
      });
      const freshArtifact = async ({ artifactType, kinds, role, subjectRun }) => {
        const event = await waitForRawEvent(client, release, { kinds, role, subjectRun });
        if (!SHA64.test(event.artifactDigest ?? "")) fail();
        const bytes = await client.getArtifact({ artifactType, digest: event.artifactDigest });
        const checked = await artifactValidator({ artifactType, bytes, expectedDigest: event.artifactDigest, secretCanaries: [] });
        cached.set(`${artifactType}:${event.artifactDigest}`, bytes); return Object.freeze({ bytes, checked, digest: event.artifactDigest });
      };
      const verifiedPreparation = async (coreEnrollments) => {
        const enrollmentSetBytes = await client.readEnrollmentSet();
        const tokenCommitments = Object.create(null);
        for (const role of ["payer", "payee"]) tokenCommitments[role] = (await freshArtifact({ artifactType: "token-commitment", kinds: ["TOKEN_READY"], role, subjectRun: "release" })).checked.facts;
        const prepared = await (dependencies.verifyCoordinationPreparationSet ?? verifyCoordinationPreparationSet)({ capabilityDigests: Object.freeze({ payer: release.capabilityDigests?.[1] ?? coreEnrollments?.payer?.capabilityDigest, payee: release.capabilityDigests?.[0] ?? coreEnrollments?.payee?.capabilityDigest }), enrollmentSetBytes, releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, tlsCertificatePem: config.tlsCertificatePem, tokenCommitments });
        if (!prepared?.participants?.payer || !prepared?.participants?.payee) fail();
        if (coreEnrollments) for (const role of ["payer", "payee"]) if (prepared.participants[role].coordinationPublicKey !== coreEnrollments[role]?.coordinationKey?.publicKey || prepared.participants[role].publicKey !== coreEnrollments[role]?.preflightKey?.publicKey) fail();
        return Object.freeze({ enrollmentSetBytes, prepared });
      };
      const startWatcher = async ({ descriptorDigest, subjectRun }) => {
        if (!SHA64.test(descriptorDigest) || !["rehearsal", "stakeholder"].includes(subjectRun)) fail();
        if (watcherTasks.has(subjectRun)) return;
        const descriptor = await client.getArtifact({ artifactType: "signed-descriptor", digest: descriptorDigest });
        const checked = await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptor, expectedDigest: descriptorDigest, secretCanaries: [] });
        const envelope = checked.facts;
        if (!envelope?.descriptor) fail();
        watcherDescriptors.set(subjectRun, envelope.descriptor);
        const controller = new AbortController(); const task = watcherLifecycle.start(subjectRun, controller.signal);
        watcherControllers.set(subjectRun, controller); watcherTasks.set(subjectRun, task);
        void task.then(() => { watcherControllers.delete(subjectRun); watcherTasks.delete(subjectRun); });
      };
      const assertWatcher = (subjectRun) => watcherLifecycle.assertHealthy(subjectRun);
      const drainWatchers = async () => {
        for (const controller of watcherControllers.values()) controller.abort();
        await Promise.allSettled([...watcherTasks.values()]);
      };
      const prepareVerifierHandoff = async ({ releaseId, repositorySha, sessionId, subjectRun }) => {
        if (releaseId !== release.releaseId || repositorySha !== config.repositorySha || sessionId !== release.sessionId || subjectRun !== "stakeholder" || typeof dependencies.publishVerifierHandoff !== "function") fail();
        await immutable();
        const persisted = await state.readState();
        if (!persisted || persisted.releaseId !== release.releaseId || persisted.repositorySha !== config.repositorySha || persisted.sessionId !== release.sessionId || persisted.state !== "STAKEHOLDER_PACKAGES_READY") fail();
        const descriptorCheckpoint = persisted.checkpoints.find((entry) => entry.action === "STAKEHOLDER_DESCRIPTOR" && entry.role === "operator" && entry.subjectRun === "stakeholder" && entry.status === "EVENT_APPENDED");
        const packageDigests = Object.freeze(Object.fromEntries(["payer", "payee"].map((role) => {
          const entry = persisted.checkpoints.find((candidate) => candidate.action === "ROLE_PACKAGE" && candidate.role === role && candidate.subjectRun === "stakeholder" && candidate.status === "EVENT_APPENDED");
          return [role, entry?.artifactDigest];
        })));
        if (descriptorCheckpoint?.artifactDigest === null || !SHA64.test(descriptorCheckpoint?.artifactDigest ?? "") || !SHA64.test(packageDigests.payer ?? "") || !SHA64.test(packageDigests.payee ?? "")) fail();
        const descriptorDigest = descriptorCheckpoint.artifactDigest;
        const descriptorBytes = await client.getArtifact({ artifactType: "signed-descriptor", digest: descriptorDigest });
        if (!Buffer.isBuffer(descriptorBytes) || createHash("sha256").update(descriptorBytes).digest("hex") !== descriptorDigest) fail();
        const descriptorEnvelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptorBytes, expectedDigest: descriptorDigest, secretCanaries: [] })).facts;
        validatePinnedDescriptorEnvelope(descriptorEnvelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, subjectRun }) });
        const mandateArtifact = await freshArtifact({ artifactType: "payer-mandate", kinds: ["PAYER_MANDATE_READY"], role: "payer", subjectRun });
        const requestArtifact = await freshArtifact({ artifactType: "payment-request", kinds: ["PAYMENT_REQUEST_READY"], role: "payee", subjectRun });
        const packageFor = async (role) => {
          const digest = packageDigests[role];
          const bytes = await client.getArtifact({ artifactType: "party-result-package", digest });
          if (!Buffer.isBuffer(bytes) || createHash("sha256").update(bytes).digest("hex") !== digest) fail();
          const facts = await artifactValidator({ artifactType: "party-result-package", bytes, expectedDigest: digest, secretCanaries: [] }); const party = facts.facts?.partyResult;
          validateVerifierPackageBinding({ descriptor: descriptorEnvelope.descriptor, party, repositorySha: config.repositorySha, role, sessionDigest: dSession(descriptorEnvelope.descriptor) });
          await stagePackage(config.releaseRoot, `verifier-${role}-${digest.slice(0, 16)}`, "party-result-package", bytes, { validate: artifactValidator });
          return bytes;
        };
        const [payerPackageBytes, payeePackageBytes] = await Promise.all([packageFor("payer"), packageFor("payee")]);
        const evidenceDigest = createHash("sha256").update(canonicalBytes({
          descriptorDigest,
          mandateDigest: descriptorEnvelope.descriptor.mandateDigest,
          packageDigests,
          paymentMoved: false,
          releaseId: release.releaseId,
          repositorySha: config.repositorySha,
          requestDigest: descriptorEnvelope.descriptor.requestDigest,
          sessionId: release.sessionId,
          subjectRun,
        })).digest("hex");
        const evidenceRoot = `/var/lib/clockchain/evidence/releases/${release.releaseId}/${subjectRun}`;
        const handoff = Object.freeze({
          descriptorDigest,
          descriptorPath: join(evidenceRoot, "descriptor.json"),
          evidenceDigest,
          mandateDigest: descriptorEnvelope.descriptor.mandateDigest,
          payerMandatePath: join(evidenceRoot, "payer-mandate.json"),
          payeeResultsPath: join(evidenceRoot, "payee-results"),
          payerResultsPath: join(evidenceRoot, "payer-results"),
          paymentMoved: false,
          paymentRequestPath: join(evidenceRoot, "payment-request.json"),
          publicationPath: `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/${subjectRun}-publication.json`,
          releaseId: release.releaseId,
          repositorySha: config.repositorySha,
          requestDigest: descriptorEnvelope.descriptor.requestDigest,
          schema: "clockchain.aws-verifier-handoff/v1",
          sessionDigest: dSession(descriptorEnvelope.descriptor),
          sessionId: release.sessionId,
          subjectRun,
        });
        return dependencies.publishVerifierHandoff({
          evidence: Object.freeze({
            descriptorBytes,
            payeePackageBytes,
            payerMandateBytes: mandateArtifact.bytes,
            payerPackageBytes,
            paymentRequestBytes: requestArtifact.bytes,
          }),
          handoff,
          path: `/var/lib/clockchain/operator/releases/${release.releaseId}/verifier-handoff-${subjectRun}.json`,
        });
      };
      const runtimeDependencies = Object.freeze({
        appendOperatorEvent: client.appendOperatorEvent, appendVerifiedEvent: client.appendVerifiedEvent, createVerifiedEvent: client.createVerifiedEvent, getArtifact: client.getArtifact, putArtifact: client.putArtifact, readEnrollmentSet: client.readEnrollmentSet, readEvents: (input) => client.readEvents(eventReadInput(input)), readSessionView: (input) => client.readSessionView(abortSignal === undefined ? input : { ...(input ?? {}), signal: abortSignal }), readVerifierPublication: client.readVerifierPublication,
        readState: state.readState, writeState: state.writeState, resolveOperatorPublicKey: async () => config.operatorPublicKey, waitForFunding: dependencies.waitForFunding ?? createProductionFundingWaiter({ now, rpcUrl: config.rpcUrl, sleeper: sleep }), now, sleeper: sleep, displayAddresses: async (addresses) => { if (displayedFunding) fail(); displayedFunding = true; const bytes = await publishFundingAddresses(config.releaseRoot, addresses, { fs: fundingFileSystem(dependencies.fundingFileSystem), inspectAdmission: (publishedAddresses) => createFundingAdmissionInspector({ createClient: dependencies.createFundingAdmissionClient, rpcUrl: config.rpcUrl })(publishedAddresses) }); (dependencies.output ?? ((line) => process.stdout.write(line)))(bytes.toString("utf8")); }, createTransport: () => transport,
        launcher: async () => fail(), verifyMarkerCompleteVerdict: async () => fail(),
        // The coordinator owns lifecycle ordering; this runtime only validates a
        // bounded artifact snapshot and observes authenticated relay effects.
        validateArtifact: artifactValidator,
        waitForPreflightParticipant: async ({ planDigest, role }) => {
          const event = await waitForRawEvent(client, release, { artifactDigest: undefined, kinds: ["PREFLIGHT_PARTICIPANT_READY"], role, subjectRun: "release" });
          const bytes = await client.getArtifact({ artifactType: "preflight-participant-report", digest: event.artifactDigest });
          return Object.freeze({ bytes, digest: createHash("sha256").update(bytes).digest("hex") });
        },
        waitForIdentityPackage: async ({ subjectRun }) => Promise.all(["payer", "payee"].map((role) => waitForRawEvent(client, release, { kinds: ["IDENTITY_PACKAGE_READY"], role, subjectRun }))),
        prepareVerifierHandoff,
        // START_* is the authority delivered to long-lived supervisors.  The
        // operator must never spawn a second local role command.
        startRole: async ({ role, subjectRun }) => { if (!["payer", "payee"].includes(role) || !["rehearsal", "stakeholder"].includes(subjectRun)) fail(); },
        startWatcher, drainWatchers,
        waitForDescriptorAcceptance: async ({ artifactDigest, subjectRun }) => { await Promise.all(["payer", "payee"].map((role) => waitForRawEvent(client, release, { artifactDigest, kinds: ["DESCRIPTOR_ACCEPTED"], role, subjectRun }))); await startWatcher({ descriptorDigest: artifactDigest, subjectRun }); },
        waitForRoleStarted: async ({ role, subjectRun }) => { assertWatcher(subjectRun); const event = await waitForRawEvent(client, release, { artifactDigest: null, kinds: ["ROLE_STARTED"], role, subjectRun }); assertWatcher(subjectRun); return event; },
        waitForRolePackage: async ({ role, subjectRun }) => { assertWatcher(subjectRun); const event = await waitForRawEvent(client, release, { kinds: ["ROLE_PACKAGE_READY"], role, subjectRun }); assertWatcher(subjectRun); return event; },
        createPreflightPlan: async ({ enrollments, repositorySha }) => {
          await immutable(); if (repositorySha !== config.repositorySha || !enrollments?.payer || !enrollments?.payee) fail();
          const artifacts = (await verifiedPreparation(enrollments)).prepared;
          const directory = await privateStage(config.releaseRoot, "preflight-plan");
          await (dependencies.preflightMain ?? preflightMain)(["prepare", "--operator-private-key", config.operatorPrivateKeyPath, "--operator-key-id", config.operatorIdentity.keyId, "--repository-sha", repositorySha, "--output", directory], { prepareArtifacts: async () => artifacts });
          return readStable(join(directory, "probe-plan.json"), 65_536, privateFile);
        },
        runAggregatePreflight: async ({ plan, planBytes, participants, repositorySha }) => {
          await immutable(); if (repositorySha !== config.repositorySha || !Buffer.isBuffer(planBytes) || !participants?.payer || !participants?.payee) fail();
          const root = await privateStage(config.releaseRoot, `preflight-aggregate-${createHash("sha256").update(planBytes).digest("hex").slice(0, 16)}`);
          await writePrivate(join(root, "probe-plan.json"), planBytes);
          const payer = await stagePackage(config.releaseRoot, `participant-payer-${createHash("sha256").update(canonical(participants.payer)).digest("hex").slice(0, 16)}`, "preflight-participant-report", (await freshArtifact({ artifactType: "preflight-participant-report", kinds: ["PREFLIGHT_PARTICIPANT_READY"], role: "payer", subjectRun: "release" })).bytes, { validate: artifactValidator });
          const payee = await stagePackage(config.releaseRoot, `participant-payee-${createHash("sha256").update(canonical(participants.payee)).digest("hex").slice(0, 16)}`, "preflight-participant-report", (await freshArtifact({ artifactType: "preflight-participant-report", kinds: ["PREFLIGHT_PARTICIPANT_READY"], role: "payee", subjectRun: "release" })).bytes, { validate: artifactValidator });
          const output = join(root, "output"); await (dependencies.preflightMain ?? preflightMain)(["aggregate", "--plan", join(root, "probe-plan.json"), "--payer-report-dir", payer, "--payee-report-dir", payee, "--operator-private-key", config.operatorPrivateKeyPath, "--output", output, "--attest-separate-credentials", "--attest-separate-machines"]);
          const report = JSON.parse((await readStable(join(output, "preflight-report.json"), 1_048_576, privateFile)).toString("utf8")); if (report?.report?.outcome !== "RENDEZVOUS_OK") fail();
          const files = [".preflight-report.complete.json", "preflight-report.json"].map(async (name) => { const content = await readStable(join(output, name), 1_048_576, privateFile); return { byteLength: String(content.length), contentBase64: content.toString("base64"), name, sha256: createHash("sha256").update(content).digest("hex") }; });
          return relayPackageBytes({ files: await Promise.all(files), paymentMoved: false, schema: "clockchain.bilateral-relay-package/v1" });
        },
        createDescriptor: async ({ repositorySha, subjectRun }) => {
          await immutable(); if (repositorySha !== config.repositorySha || !["rehearsal", "stakeholder"].includes(subjectRun)) fail();
          const enrolled = parseCoordinationEnrollmentSet((await verifiedPreparation()).enrollmentSetBytes);
          const identities = Object.create(null); for (const role of ["payer", "payee"]) identities[role] = await freshArtifact({ artifactType: "identity-package", kinds: ["IDENTITY_PACKAGE_READY"], role, subjectRun });
          const parties = Object.fromEntries(["payer", "payee"].map((role) => { const identity = identities[role].checked.facts.identity; const enrollment = parseCoordinationEnrollment(Buffer.from(enrolled.enrollments[role].enrollmentBase64, "base64")); if (!identity || identity.repositorySha !== repositorySha || identity.paymentMoved !== false || identity.address !== enrollment.invitations[subjectRun].address || typeof identity.agentId !== "string" || typeof identity.displayName !== "string" || identity.displayName.trim() !== identity.displayName) fail(); return [role, { address: identity.address, agentId: identity.agentId, displayName: identity.displayName, role }]; }));
          const expectedParties = Object.freeze({ payer: Object.freeze({ address: parties.payer.address, agentId: parties.payer.agentId }), payee: Object.freeze({ address: parties.payee.address, agentId: parties.payee.agentId }) });
          const mandateArtifact = await freshArtifact({ artifactType: "payer-mandate", kinds: ["PAYER_MANDATE_READY"], role: "payer", subjectRun });
          const mandateEnvelope = await client.readPayerMandate({ payer: expectedParties.payer, payee: expectedParties.payee, subjectRun });
          if (!Buffer.isBuffer(mandateEnvelope) || !mandateEnvelope.equals(mandateArtifact.bytes)) fail();
          const requestArtifact = await freshArtifact({ artifactType: "payment-request", kinds: ["PAYMENT_REQUEST_READY"], role: "payee", subjectRun });
          let requestId;
          try { requestId = JSON.parse(requestArtifact.bytes.toString("utf8"))?.request?.requestId; } catch { fail(); }
          const requestEnvelope = await client.readPaymentRequest({ payer: expectedParties.payer, payee: expectedParties.payee, requestId, subjectRun });
          if (!Buffer.isBuffer(requestEnvelope) || !requestEnvelope.equals(requestArtifact.bytes)) fail();
          const descriptorSession = deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun });
          const descriptor = await createCoordinatorDescriptor({ mandateEnvelope: JSON.parse(mandateEnvelope.toString("utf8")), nowMs: now(), parties, promptSha256: await (dependencies.computePromptHash ?? computeBilateralPromptHash)({ repositorySha }), repositorySha, requestEnvelope: JSON.parse(requestEnvelope.toString("utf8")), sessionId: descriptorSession }); return canonicalBytes(createSignedEnvelope(descriptor, { keyId: config.operatorIdentity.keyId, privateKeyPem: config.operatorIdentity.privateKeyPem }));
        },
        validateRehearsalPackage: async ({ bytes, descriptorDigest, party, role, subjectRun }) => { if (!Buffer.isBuffer(bytes) || !SHA64.test(descriptorDigest) || !["payer", "payee"].includes(role) || !["rehearsal", "stakeholder"].includes(subjectRun) || party?.role !== role || party.paymentMoved !== false) fail(); const descriptorBytes = await client.getArtifact({ artifactType: "signed-descriptor", digest: descriptorDigest }); const envelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptorBytes, expectedDigest: descriptorDigest, secretCanaries: [] })).facts; const expectedSession = deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, subjectRun }); validatePinnedDescriptorEnvelope(envelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: expectedSession }); if (party.sessionDigest !== dSession(envelope.descriptor) || party.repositorySha !== config.repositorySha || party.signature?.address?.toLowerCase() !== envelope.descriptor[role].address.toLowerCase()) fail(); return true; },
        launchVerifier: async ({ descriptorDigest, outputDirectory, packageDigests, subjectRun }) => {
          assertWatcher(subjectRun); await immutable(); if (!SHA64.test(descriptorDigest) || !packageDigests || !SHA64.test(packageDigests.payer) || !SHA64.test(packageDigests.payee) || !["rehearsal", "stakeholder"].includes(subjectRun)) fail();
          if (outputDirectory !== join(config.releaseRoot.path, "verifier", subjectRun)) fail();
          const root = await privateStage(config.releaseRoot, `verifier-${subjectRun}-${descriptorDigest.slice(0, 16)}`);
          const descriptorBytes = await client.getArtifact({ artifactType: "signed-descriptor", digest: descriptorDigest });
          if (createHash("sha256").update(descriptorBytes).digest("hex") !== descriptorDigest) fail();
          const descriptorEnvelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptorBytes, expectedDigest: descriptorDigest, secretCanaries: [] })).facts;
          const expectedSession = deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, subjectRun });
          validatePinnedDescriptorEnvelope(descriptorEnvelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: expectedSession });
          const descriptorPath = join(root, "descriptor.json"); await writePrivate(descriptorPath, descriptorBytes);
          const mandateArtifact = await freshArtifact({ artifactType: "payer-mandate", kinds: ["PAYER_MANDATE_READY"], role: "payer", subjectRun });
          const requestArtifact = await freshArtifact({ artifactType: "payment-request", kinds: ["PAYMENT_REQUEST_READY"], role: "payee", subjectRun });
          const mandatePath = join(root, "payer-mandate.json"); const requestPath = join(root, "payment-request.json");
          await writePrivate(mandatePath, mandateArtifact.bytes); await writePrivate(requestPath, requestArtifact.bytes);
          await assertRoot(config.releaseRoot);
          const packageFor = async (role) => {
            const digest = packageDigests[role]; const bytes = await client.getArtifact({ artifactType: "party-result-package", digest });
            if (createHash("sha256").update(bytes).digest("hex") !== digest) fail();
            const facts = await artifactValidator({ artifactType: "party-result-package", bytes, expectedDigest: digest, secretCanaries: [] }); const party = facts.facts?.partyResult;
            validateVerifierPackageBinding({ descriptor: descriptorEnvelope.descriptor, party, repositorySha: config.repositorySha, role, sessionDigest: dSession(descriptorEnvelope.descriptor) });
            return Object.freeze({
              bytes,
              directory: await stagePackage(config.releaseRoot, `verifier-${role}-${digest.slice(0, 16)}`, "party-result-package", bytes, { validate: artifactValidator }),
            });
          };
          const [payerPackage, payeePackage] = await Promise.all([packageFor("payer"), packageFor("payee")]);
          const payerDirectory = payerPackage.directory;
          const payeeDirectory = payeePackage.directory;
          await privateStage(config.releaseRoot, "verifier");
          try { await lstat(outputDirectory); fail(); } catch (error) { if (error?.message === "Coordinator startup failed safely.") throw error; if (error?.code !== "ENOENT") fail(); }
          const evidenceDigest = createHash("sha256").update(canonicalBytes({
            descriptorDigest,
            mandateDigest: descriptorEnvelope.descriptor.mandateDigest,
            packageDigests,
            paymentMoved: false,
            releaseId: release.releaseId,
            repositorySha: config.repositorySha,
            requestDigest: descriptorEnvelope.descriptor.requestDigest,
            sessionId: release.sessionId,
            subjectRun,
          })).digest("hex");
          if (dependencies.publishVerifierHandoff !== undefined) {
            if (typeof dependencies.publishVerifierHandoff !== "function") fail();
            const evidenceRoot = `/var/lib/clockchain/evidence/releases/${release.releaseId}/${subjectRun}`;
            await dependencies.publishVerifierHandoff({
              evidence: Object.freeze({
                descriptorBytes,
                payeePackageBytes: payeePackage.bytes,
                payerMandateBytes: mandateArtifact.bytes,
                payerPackageBytes: payerPackage.bytes,
                paymentRequestBytes: requestArtifact.bytes,
              }),
              handoff: Object.freeze({
                descriptorDigest,
                descriptorPath: join(evidenceRoot, "descriptor.json"),
                evidenceDigest,
                mandateDigest: descriptorEnvelope.descriptor.mandateDigest,
                payerMandatePath: join(evidenceRoot, "payer-mandate.json"),
                payeeResultsPath: join(evidenceRoot, "payee-results"),
                payerResultsPath: join(evidenceRoot, "payer-results"),
                paymentMoved: false,
                paymentRequestPath: join(evidenceRoot, "payment-request.json"),
                publicationPath: `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/${subjectRun}-publication.json`,
                releaseId: release.releaseId,
                repositorySha: config.repositorySha,
                requestDigest: descriptorEnvelope.descriptor.requestDigest,
                schema: "clockchain.aws-verifier-handoff/v1",
                sessionDigest: dSession(descriptorEnvelope.descriptor),
                sessionId: release.sessionId,
                subjectRun,
              }),
              path: `/var/lib/clockchain/operator/releases/${release.releaseId}/verifier-handoff-${subjectRun}.json`,
            });
          }
          let verifierResult;
          if (dependencies.verifierPublication !== undefined) {
            const publication = dependencies.verifierPublication;
            if (
              !publication ||
              typeof publication !== "object" ||
              Array.isArray(publication) ||
              Object.getPrototypeOf(publication) !== Object.prototype ||
              Reflect.ownKeys(publication).length !== AWS_PUBLICATION_KEYS.length ||
              AWS_PUBLICATION_KEYS.some((key, index) => Reflect.ownKeys(publication)[index] !== key) ||
              !ATTEMPT_ID.test(publication.attemptId) ||
              publication.evidenceDigest !== evidenceDigest ||
              publication.paymentMoved !== false ||
              !SHA64.test(publication.publicationDigest) ||
              publication.repositorySha !== config.repositorySha ||
              !Number.isSafeInteger(publication.revision) ||
              publication.revision < 0 ||
              publication.schema !== "clockchain.aws-verifier-task-publication/v1" ||
              publication.status !== "VERIFICATION_PASSED" ||
              !TASK_ARN.test(publication.taskArn) ||
              !DECIMAL.test(publication.writtenAtMs)
            ) fail();
            verifierResult = Object.freeze({
              exitCode: 0,
              publicationDigest: publication.publicationDigest,
              status: "VERIFICATION_PASSED",
              stderr: "",
              stdout: "",
            });
          } else if (dependencies.verifierLauncher === undefined) {
            const args = [join(ROOT, "scripts/verify-bilateral-results.mjs"), "--clockchain-token-file", config.clockchainTokenPath, "--descriptor", descriptorPath, "--output", outputDirectory, "--payer-mandate", mandatePath, "--payee-results", payeeDirectory, "--payer-results", payerDirectory, "--payment-request", requestPath, "--rpc-url", config.rpcUrl];
            await assertRoot(config.releaseRoot); const outcome = await runPinnedVerifierChild(config.releaseRoot, args, dependencies.verifierDeadlineMs ?? COORDINATOR_FUNDING_DEADLINE_MS, dependencies.runVerifierChild ?? runChildWithDeadline); if (outcome !== 0) fail();
            verifierResult = Object.freeze({ exitCode: 0, publicationDigest: null, status: null, stderr: "", stdout: "" });
          } else {
            verifierResult = await launchExternalVerifier({
              evidenceDescriptor: Object.freeze({
                descriptorDigest,
                evidenceDigest,
                paymentMoved: false,
                schema: AWS_VERIFIER_EVIDENCE_SCHEMA,
                subjectRun,
              }),
              expectedRevision: externalVerifierRevision(dependencies.verifierAction, release, subjectRun),
              releaseId: release.releaseId,
              repositorySha: config.repositorySha,
              sessionId: release.sessionId,
              verifierLauncher: dependencies.verifierLauncher,
            });
          }
          const envelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: await readStable(descriptorPath, 1_048_576, privateFile), expectedDigest: descriptorDigest, secretCanaries: [] })).facts;
          await immutable(); await assertRoot(config.releaseRoot); validatePinnedDescriptorEnvelope(envelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: expectedSession });
          const publication = dependencies.verifierPublication === undefined
            ? await verdictPublicationValidator({ mandateDigest: envelope.descriptor.mandateDigest, outputDirectory, repositorySha: config.repositorySha, requestDigest: envelope.descriptor.requestDigest, sessionDigest: dSession(envelope.descriptor) })
            : await verdictPublicationValidator({
                mandateDigest: envelope.descriptor.mandateDigest,
                outputDirectory: `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/${dependencies.verifierPublication.attemptId}`,
                repositorySha: config.repositorySha,
                requestDigest: envelope.descriptor.requestDigest,
                sessionDigest: dSession(envelope.descriptor),
              });
          await assertRoot(config.releaseRoot);
          if (
            verifierResult.publicationDigest !== null &&
            verifierResult.publicationDigest !== publication.publicationDigest
          ) fail();
          const contextOutputDirectory = dependencies.verifierPublication === undefined
            ? outputDirectory
            : `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/${dependencies.verifierPublication.attemptId}`;
          const context = Object.freeze({ descriptorDigest, mandateDigest: envelope.descriptor.mandateDigest, outputDirectory: contextOutputDirectory, packageDigests: Object.freeze({ ...packageDigests }), paymentMoved: false, publicationDigest: publication.publicationDigest, releaseId: release.releaseId, repositorySha: config.repositorySha, requestDigest: envelope.descriptor.requestDigest, schema: VERIFIER_CONTEXT_SCHEMA, sessionId: release.sessionId, subjectRun });
          await writeVerifierContext(config.releaseRoot, `.verifier-context-${subjectRun}.json`, context); await assertRoot(config.releaseRoot); verifierContexts.set(outputDirectory, context);
          return Object.freeze({ outputDirectory, result: Object.freeze({ exitCode: 0, publicationDigest: publication.publicationDigest, status: "VERIFICATION_PASSED", stderr: "", stdout: "" }) });
        },
        validatePublishedBilateralVerdict: async ({ outputDirectory, packageDigests, publicationDigest, repositorySha, subjectRun }) => {
          await assertRoot(config.releaseRoot);
          if (outputDirectory !== join(config.releaseRoot.path, "verifier", subjectRun)) fail();
          const context = verifierContexts.get(outputDirectory) ?? await readVerifierContext(config.releaseRoot, `.verifier-context-${subjectRun}.json`);
          const awsAttemptRoot = `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/`;
          const contextIsAwsAttempt = subjectRun === "stakeholder" && context?.outputDirectory?.startsWith(awsAttemptRoot) && ATTEMPT_ID.test(context.outputDirectory.slice(awsAttemptRoot.length));
          await assertRoot(config.releaseRoot); if (!context || !(context.outputDirectory === outputDirectory || contextIsAwsAttempt) || context.publicationDigest !== publicationDigest || context.subjectRun !== subjectRun || context.releaseId !== release.releaseId || context.sessionId !== release.sessionId || repositorySha !== config.repositorySha || JSON.stringify(context.packageDigests) !== JSON.stringify(packageDigests)) fail();
          const descriptor = await client.getArtifact({ artifactType: "signed-descriptor", digest: context.descriptorDigest }); const envelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptor, expectedDigest: context.descriptorDigest, secretCanaries: [] })).facts;
          await assertRoot(config.releaseRoot); await immutable(); await assertRoot(config.releaseRoot); validatePinnedDescriptorEnvelope(envelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, subjectRun }) });
          if (envelope.descriptor.mandateDigest !== context.mandateDigest || envelope.descriptor.requestDigest !== context.requestDigest) fail();
          const publication = await verdictPublicationValidator({ mandateDigest: context.mandateDigest, outputDirectory: context.outputDirectory, repositorySha, requestDigest: context.requestDigest, sessionDigest: dSession(envelope.descriptor) });
          await assertRoot(config.releaseRoot);
          if (
            !publication ||
            Object.keys(publication).length !== 2 ||
            publication.publicationDigest !== publicationDigest ||
            publication.status !== "VERIFICATION_PASSED"
          ) fail();
          return Object.freeze({
            paymentMoved: false,
            publicationDigest,
            releaseId: release.releaseId,
            repositorySha: config.repositorySha,
            schema: VERIFIER_PUBLICATION_SCHEMA,
            sessionId: release.sessionId,
            status: "VERIFICATION_PASSED",
            subjectRun,
          });
        },
        writeConsoleState: async ({ lifecycleView, subjectRun }) => {
          if (!lifecycleView || lifecycleView.paymentMoved !== false || lifecycleView.releaseId !== release.releaseId || lifecycleView.repositorySha !== config.repositorySha || lifecycleView.sessionId !== release.sessionId || lifecycleView.state !== (subjectRun === "rehearsal" ? "REHEARSAL_VERIFIED" : "STAKEHOLDER_VERIFIED")) fail();
          const outputDirectory = join(config.releaseRoot.path, "verifier", subjectRun);
          const context = verifierContexts.get(outputDirectory) ?? await readVerifierContext(config.releaseRoot, `.verifier-context-${subjectRun}.json`);
          if (!context || context.subjectRun !== subjectRun || context.releaseId !== release.releaseId || context.sessionId !== release.sessionId || context.repositorySha !== config.repositorySha) fail();
          const awsAttemptRoot = `/var/lib/clockchain/verifier-output/releases/${release.releaseId}/attempts/`;
          const contextIsAwsAttempt = subjectRun === "stakeholder" && context.outputDirectory.startsWith(awsAttemptRoot) && ATTEMPT_ID.test(context.outputDirectory.slice(awsAttemptRoot.length));
          if (!(context.outputDirectory === outputDirectory || contextIsAwsAttempt)) fail();
          const descriptorBytes = await client.getArtifact({ artifactType: "signed-descriptor", digest: context.descriptorDigest });
          const descriptorEnvelope = (await artifactValidator({ artifactType: "signed-descriptor", bytes: descriptorBytes, expectedDigest: context.descriptorDigest, secretCanaries: [] })).facts;
          validatePinnedDescriptorEnvelope(descriptorEnvelope, { keyId: config.operatorIdentity.keyId, publicKey: config.operatorPublicKey, repositorySha: config.repositorySha, sessionId: deriveDescriptorSessionId({ releaseId: release.releaseId, repositorySha: config.repositorySha, sessionId: release.sessionId, subjectRun }) });
          const mandateArtifact = await freshArtifact({ artifactType: "payer-mandate", kinds: ["PAYER_MANDATE_READY"], role: "payer", subjectRun });
          const requestArtifact = await freshArtifact({ artifactType: "payment-request", kinds: ["PAYMENT_REQUEST_READY"], role: "payee", subjectRun });
          const mandateEnvelope = mandateArtifact.checked.facts;
          const requestEnvelope = requestArtifact.checked.facts;
          if (payerMandateDigest(mandateEnvelope) !== context.mandateDigest || paymentRequestDigest(requestEnvelope) !== context.requestDigest) fail();
          const publication = await verdictPublicationValidator({ mandateDigest: context.mandateDigest, outputDirectory: context.outputDirectory, repositorySha: config.repositorySha, requestDigest: context.requestDigest, sessionDigest: dSession(descriptorEnvelope.descriptor) });
          if (publication.publicationDigest !== context.publicationDigest) fail();
          const verdictBytes = await verifierVerdictReader({ outputDirectory: context.outputDirectory });
          if (!Buffer.isBuffer(verdictBytes) || verdictBytes.length > 1_048_576) fail();
          let verdict; try { verdict = JSON.parse(verdictBytes.toString("utf8")); } catch { fail(); }
          if (verdict?.paymentMoved !== false || !Array.isArray(verdict.transitions) || verdict.transitions.length !== 3) fail();
          const events = await client.readEvents(eventReadInput({ after: null, waitMs: 0 }));
          const fact = (kind) => events.filter((event) => event.kind === kind && event.subjectRun === subjectRun).length === 1;
          if (!fact("PAYER_MANDATE_READY") || !fact("PAYMENT_REQUEST_READY") || !fact("PAYMENT_REQUEST_MATCHED")) fail();
          let watcher = watcherSnapshots.get(subjectRun);
          if (watcher?.state !== "ACKNOWLEDGED") {
            const watcherClient = (dependencies.createWatcherClient ?? (({ signal, token }) => createMcpClient({ fetchImpl: signal === undefined ? undefined : (url, init = {}) => { const signals = [signal, init.signal].filter((value) => value !== undefined); return (dependencies.watcherFetch ?? globalThis.fetch)(url, { ...init, signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals) }); }, maxAttempts: 1, token })))({ signal: abortSignal, token: config.clockchainToken });
            await (dependencies.watchBilateralSession ?? watchBilateralSession)({ advisory: { health: null, status: null }, canaries: [config.clockchainToken], client: watcherClient, descriptor: descriptorEnvelope.descriptor, now, output: (snapshot) => { watcher = structuredClone(snapshot); watcherSnapshots.set(subjectRun, watcher); }, signal: abortSignal, sleeper: sleep, windowMs: 0 });
          }
          if (watcher?.state !== "ACKNOWLEDGED" || watcher.terminal !== null || !Array.isArray(watcher.transitions) || watcher.transitions.length !== 3) fail();
          const nowMs = now();
          const mandateExpiry = Number(mandateEnvelope.mandate.expiresAtMs);
          const requestExpiry = Number(requestEnvelope.request.expiresAtMs);
          if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(mandateExpiry) || !Number.isSafeInteger(requestExpiry) || nowMs >= mandateExpiry || nowMs >= requestExpiry) fail();
          const anchors = verdict.transitions.map((transition, index) => {
            const observed = watcher.transitions[index];
            if (observed?.verified !== true || observed.slot !== ["proposal", "acceptance", "acknowledgment"][index] || observed.cardinality !== "1" || observed.blockHeight !== transition.blockHeight || observed.ledgerId !== transition.ledgerId) fail();
            return Object.freeze({ block: transition.blockHeight, cardinality: observed.cardinality, digest: transition.digest, kind: ["PROPOSED", "ACCEPTED", "ACKNOWLEDGED"][index], ledgerId: observed.ledgerId, verified: true });
          });
          if (anchors.some((anchor) => !SHA64.test(anchor.digest) || !/^(?:0|[1-9][0-9]*)$/.test(anchor.block))) fail();
          const healthExpiry = Math.min(nowMs + 60_000, mandateExpiry, requestExpiry);
          const state = {
            lifecycleView: {
              facts: {
                payerMandateReady: { [subjectRun]: true },
                paymentRequestMatched: { [subjectRun]: true },
                paymentRequestReady: { [subjectRun]: true },
              },
              health: {
                actors: { operator: "UNAVAILABLE", payee: "UNAVAILABLE", payer: "UNAVAILABLE" },
                expiresAtMs: String(healthExpiry),
                observedAtMs: String(nowMs),
                schema: "clockchain.bilateral-console-health/v1",
                services: { relay: "UNAVAILABLE", watcher: "READY" },
              },
              releaseId: release.releaseId,
              repositorySha: config.repositorySha,
              sessionId: release.sessionId,
              state: lifecycleView.state,
            },
            mandate: { mandate: mandateEnvelope.mandate, mandateDigest: context.mandateDigest },
            nowMs,
            request: { request: requestEnvelope.request, requestDigest: context.requestDigest },
            verifierPublication: {
              anchorDigests: anchors.map(({ digest }) => digest),
              descriptorDigest: context.descriptorDigest,
              mandateDigest: context.mandateDigest,
              markerComplete: true,
              packageDigests: context.packageDigests,
              paymentMoved: false,
              publicationDigest: context.publicationDigest,
              releaseId: release.releaseId,
              repositorySha: config.repositorySha,
              requestDigest: context.requestDigest,
              schema: VERIFIER_PUBLICATION_SCHEMA,
              sessionId: release.sessionId,
              status: "VERIFICATION_PASSED",
              subjectRun,
            },
            watcherSnapshot: { anchors, descriptorDigest: context.descriptorDigest, packageDigests: context.packageDigests },
          };
          await assertRoot(config.releaseRoot);
          const consolePath = await publishConsoleState(config.releaseRoot, state);
          if (publicStager !== undefined && subjectRun === "stakeholder") {
            const projection = buildConsoleProjection(state);
            const publicSnapshot = buildPublicMonitorSnapshot(
              projection,
              {
                anchorExplorerUrls: projection.anchors.map(({ block }) => `https://sepolia.etherscan.io/block/${block}`),
                nowMs,
                payerMcpReady: true,
                publishedAtMs: nowMs,
                runId: publicRunId,
                sourceObservedAtMs: projection.deadline.nowMs,
                staleAfterMs: 60_000,
                verifierPublicationValidated: true,
              },
            );
            await publicStager.stageSnapshot({
              completedAtMs: nowMs,
              nowMs,
              snapshot: publicSnapshot,
              verifierPublicationValidated: true,
            });
          }
          return consolePath;
        },
      });
      runDependencyCache.set(key, runtimeDependencies);
      return runtimeDependencies;
    },
  });
}

export async function loadOrCreateCoordinatorRelease(config, dependencies = {}) {
  const runtime = dependencies.runtime ?? createCoordinatorRuntimeDependencies(config, dependencies); const existing = await readState(config.releaseRoot);
  if (existing !== null) return existing;
  return createCoordinatorRelease({ operatorKeyId: config.operatorIdentity.keyId, relayUrl: config.relayUrl, releaseRoot: config.releaseRoot.path, repositorySha: config.repositorySha, tlsCertificatePem: config.tlsCertificatePem, tlsFingerprint: config.tlsFingerprint, dependencies: runtime.createReleaseDependencies });
}

export async function runCoordinatorUntilComplete(config, dependencies = {}) {
  const abortSignal = validateAbortSignal(dependencies.abortSignal);
  const runtime = dependencies.runtime ?? (dependencies.runCoordinator === undefined || dependencies.loadOrCreateRelease === undefined ? createCoordinatorRuntimeDependencies(config, dependencies) : null);
  const load = dependencies.loadOrCreateRelease ?? ((input) => loadOrCreateCoordinatorRelease(input, { ...dependencies, runtime })); const invoke = dependencies.runCoordinator ?? ((input) => runCoordinator({ release: input.release, releaseRoot: config.releaseRoot.path, dependencies: runtime.runDependencies(input.release) }));
  let release; let drainWatchers = async () => {};
  try {
    release = await load(config);
    if (runtime !== null && runtime !== undefined) {
      const drain = runtime.runDependencies(release).drainWatchers;
      if (typeof drain === "function") drainWatchers = drain;
    }
    abortIfRequested(abortSignal);
    const seen = new Set();
    for (let turns = 0; turns < 128; turns += 1) {
      abortIfRequested(abortSignal);
      if (release?.state === "COMPLETE") {
        const reconciled = await invoke({ abortSignal, release });
        abortIfRequested(abortSignal);
        if (!reconciled || reconciled.state !== "COMPLETE" || reconciled.paymentMoved !== false || (release.repositorySha !== undefined && reconciled.repositorySha !== release.repositorySha)) fail();
        return Object.freeze({ ...release, ...reconciled });
      }
      const fingerprint = (() => { try { return createHash("sha256").update(canonical(release)).digest("hex"); } catch { fail(); } })();
      if (!release || typeof release.state !== "string" || seen.has(fingerprint)) fail(); seen.add(fingerprint);
      const next = await invoke({ abortSignal, release });
      abortIfRequested(abortSignal);
      if (!next || next.paymentMoved !== false || typeof next.state !== "string" || next.state === "ABORTED") fail(); release = Object.freeze({ ...release, ...next });
    }
    fail();
  } finally { await drainWatchers(); }
}
