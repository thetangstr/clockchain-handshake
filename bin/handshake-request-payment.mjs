#!/usr/bin/env node
import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { link, lstat, mkdir, open, readFile, unlink } from "node:fs/promises";
import https from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";
import { X509Certificate } from "node:crypto";

import { readLaunchManifest } from "../src/bilateral/coordination/manifest.mjs";
import { createProductionSupervisorDependencies } from "../src/bilateral/coordination/supervisor-runtime.mjs";
import { runSupervisor } from "../src/bilateral/coordination/supervisor.mjs";
import {
  requestBootstrapThroughPayerMcp,
  requestPaymentThroughPayerMcp,
} from "../src/bilateral/local-mcp/client.mjs";
import {
  createRequestorBootstrapKey,
  openRequestorBootstrapEnvelope,
} from "../src/bilateral/local-mcp/bootstrap-envelope.mjs";
import { bootstrapClaimFingerprint } from "../src/bilateral/local-mcp/bootstrap-broker.mjs";
import { verifySignedRequestorDiscovery } from "../scripts/publish-requestor-discovery.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";

export const REQUEST_PAYMENT_CLI_FLAGS = Object.freeze([
  "--discovery-url",
  "--intake-request-id",
  "--state",
]);

const execFileAsync = promisify(execFile);
const FAILURE_LINE = '{"code":"REQUEST_PAYMENT_FAILED","paymentMoved":false}\n';
const HANDSHAKE_REQUIRED_LINE = '{"paymentMoved":false,"status":"HANDSHAKE_REQUIRED"}\n';
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REQUEST_PAYMENT_REPOSITORY_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
const GIT_ENV = Object.freeze(Object.assign(Object.create(null), {
  GIT_ATTR_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_TERMINAL_PROMPT: "0",
  LANG: "C",
  LC_ALL: "C",
  PATH: "/usr/bin:/bin",
}));
const GIT_PREFIX = Object.freeze(["--no-pager", "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-C"]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_FETCH_BYTES = 262_144;

function fail() {
  throw new Error("Request payment startup failed safely.");
}

function sanitize(error) {
  if (error?.message === "Request payment startup failed safely.") throw error;
  fail();
}

function parseArguments(arguments_) {
  if (!Array.isArray(arguments_) || arguments_.length !== REQUEST_PAYMENT_CLI_FLAGS.length * 2) fail();
  const parsed = Object.create(null);
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (!REQUEST_PAYMENT_CLI_FLAGS.includes(flag) || typeof value !== "string" || value.length === 0 || Object.hasOwn(parsed, flag)) fail();
    parsed[flag] = value;
  }
  if (REQUEST_PAYMENT_CLI_FLAGS.some((flag) => !Object.hasOwn(parsed, flag))) fail();
  const stateRoot = absolutePrivatePath(parsed["--state"]);
  return Object.freeze({
    discoveryUrl: httpsUrl(parsed["--discovery-url"]),
    intakeRequestId: parsed["--intake-request-id"],
    stateRoot,
  });
}

function absolutePrivatePath(value) {
  if (typeof value !== "string" || value.length === 0 || resolve(value) !== value || value === "/") fail();
  return value;
}

function httpsUrl(value, requiredPath = null) {
  if (typeof value !== "string") fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") fail();
  if (requiredPath !== null && url.pathname !== requiredPath) fail();
  return url.href;
}

function bootstrapUrl(publicUrl) {
  const url = new URL(httpsUrl(publicUrl, "/mcp"));
  url.pathname = "/bootstrap";
  return url.href;
}

async function inspectRepository(repositoryRoot = REQUEST_PAYMENT_REPOSITORY_ROOT) {
  const cwd = resolve(repositoryRoot);
  const git = (arguments_) => execFileAsync("/usr/bin/git", arguments_, {
    cwd,
    encoding: "utf8",
    env: GIT_ENV,
    maxBuffer: 8192,
  });
  const run = (arguments_) => git([...GIT_PREFIX, cwd, ...arguments_]);
  const { stdout: head } = await run(["rev-parse", "--verify", "HEAD^{commit}"]);
  const { stdout: status } = await run(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"]);
  let detached = false;
  try {
    await run(["symbolic-ref", "-q", "HEAD"]);
  } catch (error) {
    detached = error?.code === 1;
  }
  const normalizedHead = head.trim();
  if (!SHA_PATTERN.test(normalizedHead)) fail();
  return Object.freeze({ clean: status === "", detached, head: normalizedHead });
}

function validateRepositoryProof(value) {
  if (!value || value.clean !== true || value.detached !== true || typeof value.head !== "string" || !SHA_PATTERN.test(value.head)) fail();
  return value.head;
}

function ed25519PublicKeyFromRawBase64(value) {
  if (typeof value !== "string") fail();
  const raw = Buffer.from(value, "base64");
  if (raw.length !== 32 || raw.toString("base64") !== value) fail();
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

async function defaultFetchText(url) {
  const parsed = new URL(httpsUrl(url));
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = https.request({
      agent: false,
      host: parsed.hostname,
      method: "GET",
      path: parsed.pathname,
      port: parsed.port === "" ? 443 : Number(parsed.port),
      rejectUnauthorized: true,
      timeout: 10_000,
    }, (response) => {
      if (response.statusCode !== 200 || response.headers.location !== undefined) {
        response.resume();
        rejectPromise(new Error("bad response"));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_FETCH_BYTES) response.destroy(new Error("too large"));
        else chunks.push(chunk);
      });
      response.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    });
    req.once("timeout", () => req.destroy(new Error("timeout")));
    req.once("error", rejectPromise);
    req.end();
  });
}

async function defaultFetchJson(url) {
  const text = await defaultFetchText(url);
  if (text.length === 0 || text.length > MAX_FETCH_BYTES) fail();
  return JSON.parse(text);
}

async function ensurePrivateDirectory(path) {
  await mkdir(path, { mode: 0o700, recursive: false }).catch((error) => {
    if (error?.code !== "EEXIST") throw error;
  });
  const stats = await lstat(path);
  if (!stats.isDirectory() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o700) fail();
}

async function readPrivateText(path) {
  const stats = await lstat(path);
  if (!stats.isFile() || stats.isSymbolicLink() || stats.nlink !== 1 || (stats.mode & 0o777) !== 0o600 || stats.size <= 0 || stats.size > 65_536) fail();
  const handle = await open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    if (opened.dev !== stats.dev || opened.ino !== stats.ino || opened.size !== stats.size || (opened.mode & 0o777) !== 0o600) fail();
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

async function writePrivateFile(path, bytes) {
  const temporary = join(dirname(path), `.requestor-bootstrap-${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await link(temporary, path);
    await unlink(temporary);
    const stats = await lstat(path);
    if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o777) !== 0o600 || stats.size !== bytes.length) fail();
  } catch (error) {
    if (handle) await handle.close();
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

async function loadOrCreateRequestorKey(root) {
  const path = join(root, "requestor-bootstrap-key.json");
  try {
    const existing = JSON.parse(await readPrivateText(path));
    if (typeof existing.publicKey !== "string" || !existing.privateKey) fail();
    return existing;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const key = createRequestorBootstrapKey();
  await writePrivateFile(path, Buffer.from(`${JSON.stringify(key)}\n`, "utf8"));
  return key;
}

async function loadOrCreateClaim({ requestorPublicKey, root, repositorySha }) {
  const path = join(root, "claim.json");
  try {
    const existing = JSON.parse(await readPrivateText(path));
    if (
      !UUID_V4_PATTERN.test(existing.claimNonce) ||
      existing.paymentMoved !== false ||
      existing.repositorySha !== repositorySha ||
      existing.requestorPublicKey !== requestorPublicKey
    ) {
      fail();
    }
    return Object.freeze({
      claimNonce: existing.claimNonce,
      paymentMoved: false,
      repositorySha: existing.repositorySha,
      requestorPublicKey: existing.requestorPublicKey,
    });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const claim = Object.freeze({
    claimNonce: randomUUID(),
    paymentMoved: false,
    repositorySha,
    requestorPublicKey,
  });
  if (!UUID_V4_PATTERN.test(claim.claimNonce)) fail();
  await writePrivateFile(path, Buffer.from(`${JSON.stringify(claim)}\n`, "utf8"));
  return claim;
}

function verifySealedBrokerResponse({ claim, discovery, operatorPublicKey, sealed }) {
  if (sealed?.status !== "SEALED" || sealed.paymentMoved !== false || sealed.repositorySha !== discovery.repositorySha || sealed.claimFingerprint !== bootstrapClaimFingerprint(claim)) fail();
  if (sealed.context?.claimNonce !== claim.claimNonce || sealed.context?.releaseId !== discovery.releaseId || sealed.context?.repositorySha !== discovery.repositorySha || sealed.context?.sessionId !== discovery.sessionId || sealed.context?.paymentMoved !== false) fail();
  const { signature, ...unsigned } = sealed;
  if (signature?.algorithm !== "ed25519" || signature.keyId !== discovery.operatorKeyId || typeof signature.value !== "string") fail();
  const signatureBytes = Buffer.from(signature.value, "base64");
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== signature.value) fail();
  if (!verify(null, Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(unsigned)), "utf8"), operatorPublicKey, signatureBytes)) fail();
  return sealed;
}

export async function main(arguments_ = process.argv.slice(2), dependencies = {}) {
  try {
    const parsed = parseArguments(arguments_);
    const inspect = dependencies.inspectRepository ?? inspectRepository;
    if (typeof inspect !== "function") fail();
    const verifiedHead = validateRepositoryProof(await inspect(REQUEST_PAYMENT_REPOSITORY_ROOT));
    const fetchJson = dependencies.fetchJson ?? defaultFetchJson;
    const fetchText = dependencies.fetchText ?? defaultFetchText;
    const discoveryRaw = await fetchJson(parsed.discoveryUrl);
    const readOperatorPublicKey = dependencies.readOperatorPublicKey ?? (async (repositorySha, keyId) => {
      const path = join(REQUEST_PAYMENT_REPOSITORY_ROOT, "docs", "operator-keys", `${keyId}.pub`);
      if (repositorySha !== verifiedHead) fail();
      return (await readFile(path, "utf8")).trim();
    });
    const operatorPublicKey = ed25519PublicKeyFromRawBase64(await readOperatorPublicKey(verifiedHead, discoveryRaw.operatorKeyId));
    const discovery = verifySignedRequestorDiscovery({
      discovery: discoveryRaw,
      nowMs: Date.now(),
      operatorPublicKey,
      repositorySha: verifiedHead,
    });
    const tlsCertificatePem = await fetchText(discovery.certificateUrl);
    const tlsFingerprint = createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex");
    if (tlsFingerprint !== discovery.certificateFingerprint) fail();
    const bootstrapRoot = `${parsed.stateRoot}.bootstrap`;
    await ensurePrivateDirectory(bootstrapRoot);
    const requestorKey = await loadOrCreateRequestorKey(bootstrapRoot);
    const claim = await loadOrCreateClaim({ requestorPublicKey: requestorKey.publicKey, repositorySha: verifiedHead, root: bootstrapRoot });
    const requestBootstrap = dependencies.requestBootstrap ?? requestBootstrapThroughPayerMcp;
    let sealed;
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const response = await requestBootstrap({
        bootstrapUrl: bootstrapUrl(discovery.publicUrl),
        claim,
        repositorySha: verifiedHead,
        tlsCertificatePem,
        tlsFingerprint,
      });
      if (response?.status === "SEALED") {
        sealed = response;
        break;
      }
      if (response?.status !== "PENDING_APPROVAL") fail();
    }
    if (sealed === undefined) fail();
    const verifiedSealed = verifySealedBrokerResponse({ claim, discovery, operatorPublicKey, sealed });
    const manifestBytes = openRequestorBootstrapEnvelope({
      context: verifiedSealed.context,
      envelope: verifiedSealed.envelope,
      requestorPrivateKey: requestorKey.privateKey,
    });
    const manifestPath = join(bootstrapRoot, "payee.launch.json");
    await writePrivateFile(manifestPath, manifestBytes);
    const reader = dependencies.readLaunchManifest ?? readLaunchManifest;
    const manifest = await reader(manifestPath);
    if (
      manifest?.role !== "payee" ||
      manifest.payerMcpIntakeCapability === undefined ||
      manifest.repositorySha !== verifiedHead ||
      manifest.releaseId !== discovery.releaseId ||
      manifest.sessionId !== discovery.sessionId ||
      manifest.expectedTlsFingerprint !== discovery.certificateFingerprint ||
      Number(manifest.expiresAtMs) <= Date.now()
    ) {
      fail();
    }
    const requestPayment = dependencies.requestPayment ?? requestPaymentThroughPayerMcp;
    const intakeResult = await requestPayment({
      capability: manifest.payerMcpIntakeCapability,
      intakeRequestId: parsed.intakeRequestId,
      mcpUrl: discovery.publicUrl,
      repositorySha: manifest.repositorySha,
      stateRoot: parsed.stateRoot,
      tlsCertificatePem,
      tlsFingerprint,
    });
    if (intakeResult?.status !== "HANDSHAKE_REQUIRED" || intakeResult.paymentMoved !== false) fail();
    const writeStatus = dependencies.writeStatus ?? (() => process.stdout.write(HANDSHAKE_REQUIRED_LINE));
    writeStatus(Object.freeze({ paymentMoved: false, status: "HANDSHAKE_REQUIRED" }));
    const supervisor = dependencies.runSupervisor ?? (async (input) => runSupervisor({
      launchManifestPath: input.launchManifestPath,
      stateRoot: input.stateRoot,
      dependencies: await (dependencies.createSupervisorDependencies ?? createProductionSupervisorDependencies)({
        launchManifestPath: input.launchManifestPath,
        stateRoot: input.stateRoot,
      }),
    }));
    return await supervisor({
      launchManifestPath: manifestPath,
      stateRoot: parsed.stateRoot,
    });
  } catch (error) {
    sanitize(error);
  }
  fail();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => {
    process.stdout.write(FAILURE_LINE);
    process.exitCode = 1;
  });
}
