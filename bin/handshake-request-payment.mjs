#!/usr/bin/env node
import { execFile } from "node:child_process";
import https from "node:https";
import { join, resolve } from "node:path";
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
import {
  parseRequestorDiscoveryWire,
  validateRequestorDiscoveryCandidate,
  verifySignedRequestorDiscovery,
} from "../scripts/publish-requestor-discovery.mjs";
import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { inspectParticipantPrerequisites } from "../src/bilateral/platform-tools.mjs";
import {
  preparePrivateDirectory,
  readPrivateText,
  writePrivateFile,
} from "../src/bilateral/private-path.mjs";
import { canonicalizeReceiptEventValue } from "../src/canonical.mjs";

export const REQUEST_PAYMENT_CLI_FLAGS = Object.freeze([
  "--discovery-url",
  "--state",
]);

const execFileAsync = promisify(execFile);
const FAILURE_LINE = '{"code":"REQUEST_PAYMENT_FAILED","paymentMoved":false}\n';
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const INTAKE_REQUEST_SCHEMA = "clockchain.requestor-intake-request/v1";
const REQUEST_PAYMENT_REPOSITORY_ROOT = resolve(fileURLToPath(new URL("../", import.meta.url)));
const GIT_PREFIX = Object.freeze(["--no-pager", "--no-replace-objects", "-c", "core.attributesFile=/dev/null", "-c", "core.excludesFile=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-C"]);
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_FETCH_BYTES = 262_144;
const BOOTSTRAP_POLL_MS = 2_000;
const BOOTSTRAP_MAX_WAIT_MS = 300_000;

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

function gitEnvironment(activePlatform = process.platform) {
  const nullDevice = activePlatform === "win32" ? "NUL" : "/dev/null";
  const environment = Object.assign(Object.create(null), {
    GIT_ATTR_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_SYSTEM: nullDevice,
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_TERMINAL_PROMPT: "0",
    LANG: "C",
    LC_ALL: "C",
  });
  for (const name of [
    "COMSPEC",
    "HOMEDRIVE",
    "HOMEPATH",
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
  ]) {
    if (typeof process.env[name] === "string") environment[name] = process.env[name];
  }
  return Object.freeze(environment);
}

async function inspectRepository(
  repositoryRoot = REQUEST_PAYMENT_REPOSITORY_ROOT,
  {
    gitCommand,
    platform = process.platform,
  } = {},
) {
  if (typeof gitCommand !== "string" || gitCommand.length === 0) fail();
  const cwd = resolve(repositoryRoot);
  const git = (arguments_) => execFileAsync(gitCommand, arguments_, {
    cwd,
    encoding: "utf8",
    env: gitEnvironment(platform),
    maxBuffer: 8192,
    windowsHide: true,
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

async function defaultFetchText(url, expectedContentType) {
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
      const contentType = String(response.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
      if (response.statusCode !== 200 || response.headers.location !== undefined || contentType !== expectedContentType) {
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
  const text = await defaultFetchText(url, "application/json");
  if (text.length === 0 || text.length > MAX_FETCH_BYTES) fail();
  return parseRequestorDiscoveryWire(text);
}

async function defaultFetchCertificate(url) {
  return await defaultFetchText(url, "application/x-pem-file");
}

function discoveryFromFetch(value) {
  if (typeof value === "string") return parseRequestorDiscoveryWire(value);
  return value;
}

async function readReviewedOperatorPublicKey(
  repositorySha,
  keyId,
  repositoryRoot = REQUEST_PAYMENT_REPOSITORY_ROOT,
  {
    gitCommand,
    platform = process.platform,
  } = {},
) {
  if (typeof repositorySha !== "string" || !SHA_PATTERN.test(repositorySha) || typeof keyId !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(keyId)) fail();
  if (typeof gitCommand !== "string" || gitCommand.length === 0) fail();
  const cwd = resolve(repositoryRoot);
  const { stdout } = await execFileAsync(
    gitCommand,
    [...GIT_PREFIX, cwd, "show", `${repositorySha}:docs/operator-keys/${keyId}.pub`],
    {
      cwd,
      encoding: "utf8",
      env: gitEnvironment(platform),
      maxBuffer: 8192,
      windowsHide: true,
    },
  );
  const text = stdout.trim();
  ed25519PublicKeyFromRawBase64(text);
  return text;
}

function privatePathOptions({ activePlatform, runIcacls }) {
  return Object.freeze({
    platform: activePlatform,
    ...(runIcacls === undefined ? {} : { runIcacls }),
  });
}

async function loadOrCreateRequestorKey(root, options) {
  const path = join(root, "requestor-bootstrap-key.json");
  try {
    const existing = JSON.parse(await readPrivateText({ path, ...options }));
    if (typeof existing.publicKey !== "string" || !existing.privateKey) fail();
    return existing;
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const key = createRequestorBootstrapKey();
  await writePrivateFile({
    bytes: Buffer.from(`${JSON.stringify(key)}\n`, "utf8"),
    path,
    ...options,
  });
  return key;
}

async function loadOrCreateClaim({ randomUuid, requestorPublicKey, root, repositorySha }, options) {
  const path = join(root, "claim.json");
  try {
    const existing = JSON.parse(await readPrivateText({ path, ...options }));
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
    claimNonce: randomUuid(),
    paymentMoved: false,
    repositorySha,
    requestorPublicKey,
  });
  if (!UUID_V4_PATTERN.test(claim.claimNonce)) fail();
  await writePrivateFile({
    bytes: Buffer.from(`${JSON.stringify(claim)}\n`, "utf8"),
    path,
    ...options,
  });
  return claim;
}

async function loadOrCreateIntakeRequest({ claimNonce, randomUuid, root }, options) {
  const path = join(root, "requestor-intake-request.json");
  try {
    const text = await readPrivateText({ path, ...options });
    const existing = JSON.parse(text);
    if (
      existing === null ||
      typeof existing !== "object" ||
      Array.isArray(existing) ||
      Object.getPrototypeOf(existing) !== Object.prototype ||
      JSON.stringify(existing) + "\n" !== text ||
      JSON.stringify(Object.keys(existing)) !==
      JSON.stringify(["intakeRequestId", "paymentMoved", "schema"]) ||
      !UUID_V4_PATTERN.test(existing.intakeRequestId) ||
      existing.intakeRequestId === claimNonce ||
      existing.paymentMoved !== false ||
      existing.schema !== INTAKE_REQUEST_SCHEMA
    ) {
      fail();
    }
    return Object.freeze(existing);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const record = Object.freeze({
    intakeRequestId: randomUuid(),
    paymentMoved: false,
    schema: INTAKE_REQUEST_SCHEMA,
  });
  if (!UUID_V4_PATTERN.test(record.intakeRequestId) || record.intakeRequestId === claimNonce) fail();
  await writePrivateFile({
    bytes: Buffer.from(`${JSON.stringify(record)}\n`, "utf8"),
    path,
    ...options,
  });
  return record;
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
    if (dependencies === null || typeof dependencies !== "object" || Array.isArray(dependencies)) fail();
    const activePlatform = dependencies.platform ?? process.platform;
    const inspectPrerequisites =
      dependencies.inspectPrerequisites ??
      ((input) => inspectParticipantPrerequisites(input));
    if (typeof inspectPrerequisites !== "function") fail();
    const prerequisites = await inspectPrerequisites({
      platform: activePlatform,
      role: "requestor",
    });
    if (
      prerequisites === null ||
      typeof prerequisites !== "object" ||
      typeof prerequisites.git?.command !== "string" ||
      prerequisites.git.command.length === 0
    ) {
      fail();
    }
    const inspect =
      dependencies.inspectRepository ??
      ((repositoryRoot) =>
        inspectRepository(repositoryRoot, {
          gitCommand: prerequisites.git.command,
          platform: activePlatform,
        }));
    if (typeof inspect !== "function") fail();
    const verifiedHead = validateRepositoryProof(await inspect(REQUEST_PAYMENT_REPOSITORY_ROOT));
    const fetchJson = dependencies.fetchJson ?? defaultFetchJson;
    const fetchCertificate = dependencies.fetchCertificate ?? dependencies.fetchText ?? defaultFetchCertificate;
    const nowMs = dependencies.nowMs ?? Date.now;
    const randomUuid = dependencies.randomUUID ?? randomUUID;
    const sleep = dependencies.sleep ?? ((ms) => new Promise((resolvePromise) => setTimeout(resolvePromise, ms)));
    if (typeof nowMs !== "function" || typeof randomUuid !== "function" || typeof sleep !== "function") fail();
    const discoveryRaw = discoveryFromFetch(await fetchJson(parsed.discoveryUrl));
    const discoveryCandidate = validateRequestorDiscoveryCandidate({
      discovery: discoveryRaw,
      nowMs: nowMs(),
      repositorySha: verifiedHead,
    });
    const readOperatorPublicKey =
      dependencies.readOperatorPublicKey ??
      ((repositorySha, keyId) =>
        readReviewedOperatorPublicKey(
          repositorySha,
          keyId,
          REQUEST_PAYMENT_REPOSITORY_ROOT,
          {
            gitCommand: prerequisites.git.command,
            platform: activePlatform,
          },
        ));
    const operatorPublicKey = ed25519PublicKeyFromRawBase64(await readOperatorPublicKey(verifiedHead, discoveryCandidate.operatorKeyId));
    const discovery = verifySignedRequestorDiscovery({
      discovery: discoveryCandidate,
      nowMs: nowMs(),
      operatorPublicKey,
      repositorySha: verifiedHead,
    });
    const tlsCertificatePem = await fetchCertificate(discovery.certificateUrl);
    const tlsFingerprint = createHash("sha256").update(new X509Certificate(tlsCertificatePem).raw).digest("hex");
    if (tlsFingerprint !== discovery.certificateFingerprint) fail();
    const bootstrapRoot = `${parsed.stateRoot}.bootstrap`;
    const pathOptions = privatePathOptions({
      activePlatform,
      runIcacls: dependencies.runIcacls,
    });
    await preparePrivateDirectory({ path: bootstrapRoot, ...pathOptions });
    const requestorKey = await loadOrCreateRequestorKey(bootstrapRoot, pathOptions);
    const claim = await loadOrCreateClaim({
      randomUuid,
      requestorPublicKey: requestorKey.publicKey,
      repositorySha: verifiedHead,
      root: bootstrapRoot,
    }, pathOptions);
    const intakeRequest = await loadOrCreateIntakeRequest({
      claimNonce: claim.claimNonce,
      randomUuid,
      root: bootstrapRoot,
    }, pathOptions);
    const requestBootstrap = dependencies.requestBootstrap ?? requestBootstrapThroughPayerMcp;
    let sealed;
    const approvalDeadlineMs = Math.min(Number(discovery.expiresAtMs), nowMs() + BOOTSTRAP_MAX_WAIT_MS);
    for (;;) {
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
      const nextPollMs = nowMs() + BOOTSTRAP_POLL_MS;
      if (nextPollMs > approvalDeadlineMs) fail();
      await sleep(BOOTSTRAP_POLL_MS);
    }
    if (sealed === undefined) fail();
    const verifiedSealed = verifySealedBrokerResponse({ claim, discovery, operatorPublicKey, sealed });
    const manifestBytes = openRequestorBootstrapEnvelope({
      context: verifiedSealed.context,
      envelope: verifiedSealed.envelope,
      requestorPrivateKey: requestorKey.privateKey,
    });
    const manifestPath = join(bootstrapRoot, "payee.launch.json");
    await writePrivateFile({
      bytes: manifestBytes,
      path: manifestPath,
      ...pathOptions,
    });
    const reader = dependencies.readLaunchManifest ?? readLaunchManifest;
    const manifest = await reader(manifestPath);
    if (
      manifest?.role !== "payee" ||
      manifest.payerMcpIntakeCapability === undefined ||
      manifest.repositorySha !== verifiedHead ||
      manifest.releaseId !== discovery.releaseId ||
      manifest.sessionId !== discovery.sessionId ||
      Number(manifest.expiresAtMs) <= nowMs()
    ) {
      fail();
    }
    const requestPayment = dependencies.requestPayment ?? requestPaymentThroughPayerMcp;
    const intakeResult = await requestPayment({
      capability: manifest.payerMcpIntakeCapability,
      intakeRequestId: intakeRequest.intakeRequestId,
      mcpUrl: discovery.publicUrl,
      repositorySha: manifest.repositorySha,
      stateRoot: parsed.stateRoot,
      tlsCertificatePem,
      tlsFingerprint,
    });
    if (intakeResult?.status !== "HANDSHAKE_REQUIRED" || intakeResult.paymentMoved !== false) fail();
    const writeStatus = dependencies.writeStatus ?? ((value) => process.stdout.write(`${canonicalBytes(value).toString("utf8")}\n`));
    writeStatus(intakeResult);
    const supervisor = dependencies.runSupervisor ?? (async (input) => runSupervisor({
      launchManifestPath: input.launchManifestPath,
      runMode: input.runMode,
      stateRoot: input.stateRoot,
      dependencies: await (dependencies.createSupervisorDependencies ?? createProductionSupervisorDependencies)({
        launchManifestPath: input.launchManifestPath,
        stateRoot: input.stateRoot,
      }),
    }));
    return await supervisor({
      launchManifestPath: manifestPath,
      runMode: "aws-stakeholder-only",
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
