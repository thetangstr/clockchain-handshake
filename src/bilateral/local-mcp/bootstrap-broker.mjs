import {
  constants as fsConstants,
} from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import http from "node:http";
import {
  createPrivateKey,
  createPublicKey,
  createHash,
  randomUUID,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import {
  dirname,
  resolve,
} from "node:path";
import { types } from "node:util";

import { canonicalBytes } from "../canonical.mjs";
import { validateLaunchManifest } from "../coordination/manifest.mjs";
import { sealRequestorBootstrapManifest } from "./bootstrap-envelope.mjs";
import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { KEY_ID_PATTERN } from "../descriptor.mjs";
import {
  requestorBootstrapClaimFingerprint,
  validateRequestorBootstrapClaim,
} from "../aws/bootstrap-state.mjs";

export const BOOTSTRAP_BROKER_JOURNAL_FILE =
  "bootstrap-broker-journal.json";
const BOOTSTRAP_BROKER_LOCK_FILE =
  "bootstrap-broker-seal.lock";
export const BOOTSTRAP_BROKER_RESPONSE_SCHEMA =
  "clockchain.requestor-bootstrap-broker-response/v1";

const CREATE_KEYS = Object.freeze([
  "capabilityFile",
  "host",
  "manifestPath",
  "operatorKeyId",
  "operatorPrivateKeyPath",
  "port",
  "repositorySha",
  "stateRoot",
]);
const APPROVE_KEYS = Object.freeze([
  "claimFingerprint",
  "stateRoot",
]);
const JOURNAL_SCHEMA =
  "clockchain.requestor-bootstrap-broker-journal/v1";
const SHA40_PATTERN = /^[0-9a-f]{40}$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_BODY_BYTES = 16_384;
const MAX_MANIFEST_BYTES = 131_072;
const stateMutexes = new Map();

export class BootstrapBrokerError extends Error {
  constructor() {
    super("Requestor bootstrap broker failed safely.");
    this.name = "BootstrapBrokerError";
    this.category = "verification";
    this.code = "REQUESTOR_BOOTSTRAP_BROKER_INVALID";
  }
}

function invalid() {
  throw new BootstrapBrokerError();
}

function exactDataObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value)
  ) {
    invalid();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      invalid();
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function stable(value) {
  return canonicalBytes(value);
}

function durableBytes(value) {
  try {
    return Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
  } catch {
    invalid();
  }
}

async function withStateMutex(stateRoot, operation) {
  const previous = stateMutexes.get(stateRoot) ?? Promise.resolve();
  let release;
  const current = new Promise((resolvePromise) => {
    release = resolvePromise;
  });
  const chain = previous.then(() => current, () => current);
  stateMutexes.set(stateRoot, chain);
  await previous;
  try {
    return await operation();
  } finally {
    release();
    if (stateMutexes.get(stateRoot) === chain) {
      stateMutexes.delete(stateRoot);
    }
  }
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function privateRegular(stats, maxSize = 131_072) {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    (stats.mode & 0o777) === 0o600 &&
    stats.size > 0 &&
    stats.size <= maxSize
  );
}

function loopbackHost(value) {
  if (value !== "127.0.0.1" && value !== "::1" && value !== "localhost") {
    invalid();
  }
  return value;
}

function portNumber(value) {
  if (
    !Number.isInteger(value) ||
    value < 0 ||
    value > 65_535
  ) {
    invalid();
  }
  return value;
}

function absolutePath(value) {
  if (typeof value !== "string" || value.length === 0) invalid();
  const normalized = resolve(value);
  if (normalized !== value) invalid();
  return normalized;
}

function repositorySha(value) {
  if (typeof value !== "string" || !SHA40_PATTERN.test(value)) invalid();
  return value;
}

function canonicalClaim(value) {
  try {
    return validateRequestorBootstrapClaim(value);
  } catch {
    invalid();
  }
}

export function bootstrapClaimFingerprint(value) {
  try {
    return requestorBootstrapClaimFingerprint(
      canonicalClaim(value),
    );
  } catch {
    invalid();
  }
}

async function ensurePrivateRoot(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
  const stats = await lstat(path);
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o777) !== 0o700
  ) {
    invalid();
  }
}

async function readCapability(path) {
  const normalized = absolutePath(path);
  const before = await lstat(normalized);
  if (!privateRegular(before, 1_024)) invalid();
  const handle = await open(
    normalized,
    fsConstants.O_RDONLY |
      (fsConstants.O_NOFOLLOW ?? 0) |
      fsConstants.O_NONBLOCK,
  );
  try {
    const after = await handle.stat();
    if (!sameIdentity(before, after)) invalid();
    const bytes = await readFile(handle, "utf8");
    const value = bytes.trim();
    if (value.length !== bytes.length - 1 || !CAPABILITY_PATTERN.test(value)) {
      invalid();
    }
    return value;
  } finally {
    await handle.close();
  }
}

async function readOperatorPrivateKey(path) {
  const normalized = absolutePath(path);
  const before = await lstat(normalized);
  if (!privateRegular(before, 8_192)) invalid();
  const handle = await open(
    normalized,
    fsConstants.O_RDONLY |
      (fsConstants.O_NOFOLLOW ?? 0) |
      fsConstants.O_NONBLOCK,
  );
  try {
    const after = await handle.stat();
    if (!sameIdentity(before, after)) invalid();
    const pem = await readFile(handle, "utf8");
    if (
      pem.length === 0 ||
      Buffer.byteLength(pem, "utf8") !== before.size ||
      pem.trimEnd() !== pem.slice(0, -1) ||
      !pem.endsWith("\n")
    ) {
      invalid();
    }
    let key;
    try {
      key = createPrivateKey(pem);
    } catch {
      invalid();
    }
    if (
      key.asymmetricKeyType !== "ed25519" ||
      key.export({ format: "pem", type: "pkcs8" }) !== pem
    ) {
      invalid();
    }
    return key;
  } finally {
    await handle.close();
  }
}

async function readJsonFile(path, fallback) {
  try {
    const bytes = await readFile(path);
    if (bytes.length === 0 || bytes.length > 262_144) invalid();
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (!durableBytes(parsed).equals(bytes)) invalid();
    return parsed;
  } catch (error) {
    if (error?.code === "ENOENT") return fallback;
    if (error instanceof BootstrapBrokerError) throw error;
    invalid();
  }
}

async function writeJsonFile(path, value) {
  const bytes = durableBytes(value);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const handle = await open(
    temporary,
    fsConstants.O_RDWR |
      fsConstants.O_CREAT |
      fsConstants.O_EXCL |
      (fsConstants.O_NOFOLLOW ?? 0),
    0o600,
  );
  let failure;
  try {
    await handle.write(bytes, 0, bytes.length, 0);
    await handle.sync();
  } catch (error) {
    failure = error;
  }
  try {
    await handle.close();
  } catch (error) {
    failure ??= error;
  }
  if (failure !== undefined) {
    throw failure;
  }
  await rename(temporary, path);
  const directory = await open(dirname(path), fsConstants.O_RDONLY);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function withSealLock(stateRoot, operation) {
  const lockPath = joinPath(stateRoot, BOOTSTRAP_BROKER_LOCK_FILE);
  let handle;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      handle = await open(
        lockPath,
        fsConstants.O_RDWR |
          fsConstants.O_CREAT |
          fsConstants.O_EXCL |
          (fsConstants.O_NOFOLLOW ?? 0),
        0o600,
      );
      break;
    } catch (error) {
      if (error?.code !== "EEXIST" || attempt > 0) invalid();
      let stats;
      try {
        stats = await lstat(lockPath);
      } catch {
        continue;
      }
      if (
        !privateRegular(stats, 1_024) ||
        Date.now() - stats.mtimeMs <= 30_000
      ) {
        invalid();
      }
      await unlink(lockPath);
    }
  }
  if (handle === undefined) invalid();
  let failure;
  try {
    const lease = durableBytes({
      createdAtMs: String(Date.now()),
      paymentMoved: false,
      pid: String(process.pid),
      schema: "clockchain.requestor-bootstrap-broker-lock/v1",
    });
    await handle.write(lease, 0, lease.length, 0);
    await handle.sync();
    return await operation();
  } catch (error) {
    failure = error;
  } finally {
    try {
      await handle.close();
    } catch (error) {
      failure ??= error;
    }
    try {
      await unlink(lockPath);
    } catch (error) {
      if (error?.code !== "ENOENT") failure ??= error;
    }
  }
  throw failure;
}

function emptyJournal(repositoryShaValue) {
  return Object.freeze({
    claims: {},
    repositorySha: repositoryShaValue,
    schema: JOURNAL_SCHEMA,
  });
}

function exactKeySet(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value)
  ) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
  ) {
    invalid();
  }
  return value;
}

function validateContext(value, claim, repositoryShaValue) {
  exactKeySet(value, ["claimNonce", "paymentMoved", "releaseId", "repositorySha", "sessionId"]);
  if (
    value.claimNonce !== claim.claimNonce ||
    value.paymentMoved !== false ||
    typeof value.releaseId !== "string" ||
    value.releaseId.length === 0 ||
    value.releaseId.length > 256 ||
    value.releaseId.trim() !== value.releaseId ||
    value.repositorySha !== repositoryShaValue ||
    typeof value.sessionId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.sessionId)
  ) {
    invalid();
  }
}

function validateEnvelope(value) {
  exactKeySet(value, [
    "algorithm",
    "ciphertextBase64url",
    "ephemeralPublicKey",
    "ivBase64url",
    "paymentMoved",
    "schema",
    "tagBase64url",
  ]);
  for (const key of ["ciphertextBase64url", "ephemeralPublicKey", "ivBase64url", "tagBase64url"]) {
    if (
      typeof value[key] !== "string" ||
      value[key].length === 0 ||
      !BASE64URL_PATTERN.test(value[key]) ||
      value[key].includes("=") ||
      Buffer.from(value[key], "base64url").toString("base64url") !== value[key]
    ) {
      invalid();
    }
  }
  if (
    value.algorithm !== "X25519-HKDF-SHA256-AES-256-GCM" ||
    value.paymentMoved !== false ||
    value.schema !== "clockchain.requestor-bootstrap-envelope/v1" ||
    Buffer.from(value.ephemeralPublicKey, "base64url").length !== 32 ||
    Buffer.from(value.ivBase64url, "base64url").length !== 12 ||
    Buffer.from(value.tagBase64url, "base64url").length !== 16 ||
    Buffer.from(value.ciphertextBase64url, "base64url").length > 65_536
  ) {
    invalid();
  }
}

function validateSignature(value, response, operatorKeyId, operatorPublicKey) {
  exactKeySet(value, ["algorithm", "keyId", "value"]);
  if (
    value.algorithm !== "ed25519" ||
    value.keyId !== operatorKeyId ||
    typeof value.value !== "string" ||
    !BASE64_PATTERN.test(value.value)
  ) {
    invalid();
  }
  const signature = Buffer.from(value.value, "base64");
  if (
    signature.length !== 64 ||
    signature.toString("base64") !== value.value
  ) {
    invalid();
  }
  if (operatorPublicKey !== undefined) {
    const { signature: _signature, ...unsigned } = response;
    if (!verify(null, durableBytes(unsigned), operatorPublicKey, signature)) {
      invalid();
    }
  }
}

function validateSealedResponse(value, {
  claim,
  claimFingerprint,
  operatorKeyId,
  operatorPublicKey,
  repositorySha: repositoryShaValue,
}) {
  exactKeySet(value, [
    "claimFingerprint",
    "context",
    "envelope",
    "paymentMoved",
    "repositorySha",
    "schema",
    "signature",
    "status",
  ]);
  if (
    value.claimFingerprint !== claimFingerprint ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositoryShaValue ||
    value.schema !== BOOTSTRAP_BROKER_RESPONSE_SCHEMA ||
    value.status !== "SEALED"
  ) {
    invalid();
  }
  validateContext(value.context, claim, repositoryShaValue);
  validateEnvelope(value.envelope);
  validateSignature(value.signature, value, operatorKeyId, operatorPublicKey);
}

function validateJournal(value, {
  operatorKeyId,
  operatorPublicKey,
  repositorySha: repositoryShaValue,
} = {}) {
  exactKeySet(value, ["claims", "repositorySha", "schema"]);
  if (
    value.schema !== JOURNAL_SCHEMA ||
    (repositoryShaValue !== undefined &&
      value.repositorySha !== repositoryShaValue) ||
    value.claims === null ||
    typeof value.claims !== "object" ||
    Array.isArray(value.claims) ||
    types.isProxy(value.claims)
  ) {
    invalid();
  }
  for (const [fingerprint, entry] of Object.entries(value.claims)) {
    if (!HEX64_PATTERN.test(fingerprint)) invalid();
    exactKeySet(entry, entry.status === "PENDING_APPROVAL"
      ? ["claim", "claimDigest", "claimFingerprint", "paymentMoved", "status"]
      : entry.status === "APPROVED"
        ? ["approvedAtMs", "claim", "claimDigest", "claimFingerprint", "paymentMoved", "status"]
        : entry.status === "SEALED"
          ? ["approvedAtMs", "claim", "claimDigest", "claimFingerprint", "paymentMoved", "sealedResponse", "sealedResponseDigest", "status"]
          : []);
    const claim = canonicalClaim(entry.claim);
    const claimFingerprint = bootstrapClaimFingerprint(claim);
    if (
      fingerprint !== claimFingerprint ||
      entry.claimFingerprint !== claimFingerprint ||
      entry.claimDigest !== claimFingerprint ||
      entry.paymentMoved !== false
    ) {
      invalid();
    }
    if (entry.status === "APPROVED" || entry.status === "SEALED") {
      if (
        typeof entry.approvedAtMs !== "string" ||
        !/^(?:0|[1-9][0-9]*)$/.test(entry.approvedAtMs)
      ) {
        invalid();
      }
    }
    if (entry.status === "SEALED") {
      if (typeof entry.sealedResponseDigest !== "string" || !HEX64_PATTERN.test(entry.sealedResponseDigest)) {
        invalid();
      }
      validateSealedResponse(entry.sealedResponse, {
        claim,
        claimFingerprint,
        operatorKeyId,
        operatorPublicKey,
        repositorySha: repositoryShaValue ?? value.repositorySha,
      });
      if (sha256(durableBytes(entry.sealedResponse)) !== entry.sealedResponseDigest) {
        invalid();
      }
    }
  }
  return value;
}

async function readJournal(stateRoot, repositoryShaValue, options = {}) {
  return validateJournal(
    await readJsonFile(
      joinPath(stateRoot, BOOTSTRAP_BROKER_JOURNAL_FILE),
      emptyJournal(repositoryShaValue),
    ),
    {
      ...options,
      repositorySha: repositoryShaValue,
    },
  );
}

async function writeJournal(stateRoot, journal) {
  await writeJsonFile(joinPath(stateRoot, BOOTSTRAP_BROKER_JOURNAL_FILE), journal);
}

function joinPath(root, file) {
  return resolve(root, file);
}

async function parseCanonicalBody(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) invalid();
    chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length === 0) invalid();
  const text = bytes.toString("utf8");
  if (Buffer.byteLength(text, "utf8") !== bytes.length) invalid();
  const parsed = JSON.parse(text);
  if (!stable(parsed).equals(bytes)) invalid();
  return canonicalClaim(parsed);
}

function pendingResponse({ claimFingerprint, repositorySha }) {
  return Object.freeze({
    claimFingerprint,
    paymentMoved: false,
    repositorySha,
    schema: BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
    status: "PENDING_APPROVAL",
  });
}

function sealedResponse({ claimFingerprint, context, envelope, repositorySha }) {
  return Object.freeze({
    claimFingerprint,
    context,
    envelope,
    paymentMoved: false,
    repositorySha,
    schema: BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
    status: "SEALED",
  });
}

function manifestContext({ claim, manifest }) {
  return Object.freeze({
    claimNonce: claim.claimNonce,
    paymentMoved: false,
    releaseId: manifest.releaseId,
    repositorySha: manifest.repositorySha,
    sessionId: manifest.sessionId,
  });
}

function safeHttpError(response, status) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json",
  });
  response.end(stable({
    error: "REQUESTOR_BOOTSTRAP_BROKER_INVALID",
    paymentMoved: false,
    schema: BOOTSTRAP_BROKER_RESPONSE_SCHEMA,
    status: "FAILED",
  }));
}

function writeHttpJson(response, status, value) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json",
  });
  response.end(durableBytes(value));
}

function authorize(request, capability) {
  const header = request.headers.authorization;
  const prefix = "Bearer ";
  if (typeof header !== "string" || !header.startsWith(prefix)) return false;
  const supplied = header.slice(prefix.length);
  if (!CAPABILITY_PATTERN.test(supplied)) return false;
  return timingSafeEqual(Buffer.from(supplied, "hex"), Buffer.from(capability, "hex"));
}

async function readPinnedLaunchManifest(manifestPath, expectedStats = undefined) {
  const before = await lstat(manifestPath);
  if (!privateRegular(before, MAX_MANIFEST_BYTES)) invalid();
  if (expectedStats !== undefined && !sameIdentity(before, expectedStats)) invalid();
  const handle = await open(
    manifestPath,
    fsConstants.O_RDONLY |
      (fsConstants.O_NOFOLLOW ?? 0) |
      fsConstants.O_NONBLOCK,
  );
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) invalid();
    const output = Buffer.alloc(MAX_MANIFEST_BYTES + 1);
    let offset = 0;
    for (;;) {
      const { bytesRead } = await handle.read(
        output,
        offset,
        output.length - offset,
        offset,
      );
      offset += bytesRead;
      if (bytesRead === 0 || offset === output.length) break;
    }
    const after = await handle.stat();
    const pathnameAfter = await lstat(manifestPath);
    if (
      offset !== before.size ||
      offset === 0 ||
      offset > MAX_MANIFEST_BYTES ||
      !sameIdentity(before, after) ||
      !sameIdentity(before, pathnameAfter)
    ) {
      invalid();
    }
    const bytes = Buffer.from(output.subarray(0, offset));
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) invalid();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      invalid();
    }
    if (!durableBytes(parsed).equals(bytes)) invalid();
    return Object.freeze({
      bytes,
      manifest: validateLaunchManifest(parsed),
      stats: before,
    });
  } finally {
    await handle.close();
  }
}

function assertManifestUnexpired(manifest) {
  const expiresAtMs = Number(manifest.expiresAtMs);
  if (
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= Date.now()
  ) {
    invalid();
  }
}

function signatureValue({ operatorPrivateKey, response }) {
  return sign(null, durableBytes(response), operatorPrivateKey).toString("base64");
}

function assertSignatureValue(value) {
  if (
    typeof value !== "string" ||
    !BASE64_PATTERN.test(value) ||
    Buffer.from(value, "base64").length !== 64 ||
    Buffer.from(value, "base64").toString("base64") !== value
  ) {
    invalid();
  }
  return value;
}

function signSealedResponse({ operatorKeyId, operatorPrivateKey, response }) {
  const signature = assertSignatureValue(signatureValue({
    operatorPrivateKey,
    response,
  }));
  return Object.freeze({
    ...response,
    signature: Object.freeze({
      algorithm: "ed25519",
      keyId: operatorKeyId,
      value: signature,
    }),
  });
}

async function sealApprovedClaim({
  claim,
  claimFingerprint,
  manifestPath,
  manifestStats,
  operatorKeyId,
  operatorPrivateKey,
  repositorySha,
  stateRoot,
}) {
  const { bytes: rawManifestBytes, manifest } =
    await readPinnedLaunchManifest(manifestPath, manifestStats);
  if (
    manifest.role !== "payee" ||
    manifest.repositorySha !== repositorySha ||
    manifest.operatorKeyId !== operatorKeyId
  ) {
    invalid();
  }
  assertManifestUnexpired(manifest);
  const context = manifestContext({ claim, manifest });
  const envelope = sealRequestorBootstrapManifest({
    context,
    manifestBytes: rawManifestBytes,
    requestorPublicKey: claim.requestorPublicKey,
  });
  const response = signSealedResponse({
    operatorKeyId,
    operatorPrivateKey,
    response: sealedResponse({
      claimFingerprint,
      context,
      envelope,
      repositorySha,
    }),
  });
  const journal = await readJournal(stateRoot, repositorySha, {
    operatorKeyId,
    operatorPublicKey: createPublicKey(operatorPrivateKey),
  });
  const existing = journal.claims[claimFingerprint];
  if (existing?.sealedResponse !== undefined) {
    return existing.sealedResponse;
  }
  journal.claims[claimFingerprint] = {
    ...existing,
    sealedResponse: response,
    sealedResponseDigest: sha256(durableBytes(response)),
    status: "SEALED",
  };
  await writeJournal(stateRoot, journal);
  return response;
}

export function createBootstrapBroker(input) {
  const config = exactDataObject(input, CREATE_KEYS);
  const host = loopbackHost(config.host);
  const manifestPath = absolutePath(config.manifestPath);
  const operatorKeyId = config.operatorKeyId;
  if (typeof operatorKeyId !== "string" || !KEY_ID_PATTERN.test(operatorKeyId)) {
    invalid();
  }
  const operatorPrivateKeyPath = absolutePath(config.operatorPrivateKeyPath);
  const stateRoot = absolutePath(config.stateRoot);
  const repositoryShaValue = repositorySha(config.repositorySha);
  const port = portNumber(config.port);
  const capabilityFile = absolutePath(config.capabilityFile);
  let server;
  let capability;
  let manifestStats;
  let operatorPrivateKey;
  let operatorPublicKey;

  return Object.freeze({
    async start() {
      if (server !== undefined) invalid();
      await ensurePrivateRoot(stateRoot);
      capability = await readCapability(capabilityFile);
      operatorPrivateKey = await readOperatorPrivateKey(operatorPrivateKeyPath);
      operatorPublicKey = createPublicKey(operatorPrivateKey);
      const snapshot = await readPinnedLaunchManifest(manifestPath);
      manifestStats = snapshot.stats;
      const manifest = snapshot.manifest;
      if (
        manifest.role !== "payee" ||
        manifest.repositorySha !== repositoryShaValue ||
        manifest.operatorKeyId !== operatorKeyId
      ) {
        invalid();
      }
      assertManifestUnexpired(manifest);
      await writeJournal(
        stateRoot,
        await readJournal(stateRoot, repositoryShaValue, {
          operatorKeyId,
          operatorPublicKey,
        }),
      );
      server = http.createServer(async (request, response) => {
        try {
          if (
            request.method !== "POST" ||
            request.url !== "/claim"
          ) {
            safeHttpError(response, 404);
            return;
          }
          if (!authorize(request, capability)) {
            safeHttpError(response, 401);
            return;
          }
          const claim = await parseCanonicalBody(request);
          if (claim.repositorySha !== repositoryShaValue) {
            safeHttpError(response, 400);
            return;
          }
          await withStateMutex(stateRoot, async () => {
            const claimFingerprint = bootstrapClaimFingerprint(claim);
            const journal = await readJournal(stateRoot, repositoryShaValue, {
              operatorKeyId,
              operatorPublicKey,
            });
            const fingerprints = Object.keys(journal.claims);
            const existing = journal.claims[claimFingerprint];
            if (
              existing === undefined &&
              fingerprints.length > 0
            ) {
              safeHttpError(response, 409);
              return;
            }
            if (existing === undefined) {
              journal.claims[claimFingerprint] = {
                claim,
                claimDigest: claimFingerprint,
                claimFingerprint,
                paymentMoved: false,
                status: "PENDING_APPROVAL",
              };
              await writeJournal(stateRoot, journal);
              writeHttpJson(response, 202, pendingResponse({
                claimFingerprint,
                repositorySha: repositoryShaValue,
              }));
              return;
            }
            if (existing.sealedResponse !== undefined) {
              writeHttpJson(response, 200, existing.sealedResponse);
              return;
            }
            if (existing.status !== "APPROVED") {
              writeHttpJson(response, 202, pendingResponse({
                claimFingerprint,
                repositorySha: repositoryShaValue,
              }));
              return;
            }
            const sealed = await withSealLock(stateRoot, async () => {
              const lockedJournal = await readJournal(stateRoot, repositoryShaValue, {
                operatorKeyId,
                operatorPublicKey,
              });
              const lockedExisting = lockedJournal.claims[claimFingerprint];
              if (lockedExisting?.sealedResponse !== undefined) {
                return lockedExisting.sealedResponse;
              }
              if (lockedExisting?.status !== "APPROVED") invalid();
              return sealApprovedClaim({
                claim,
                claimFingerprint,
                manifestPath,
                manifestStats,
                operatorKeyId,
                operatorPrivateKey,
                repositorySha: repositoryShaValue,
                stateRoot,
              });
            });
            writeHttpJson(response, 200, sealed);
          });
        } catch {
          safeHttpError(response, 400);
        }
      });
      await new Promise((resolvePromise, reject) => {
        server.once("error", reject);
        server.listen(port, host, resolvePromise);
      });
      const address = server.address();
      return Object.freeze({
        host,
        port: address.port,
        url: `http://${host}:${address.port}`,
      });
    },
    async stop() {
      if (server === undefined) return;
      const closing = server;
      server = undefined;
      await new Promise((resolvePromise, reject) => {
        closing.close((error) =>
          error === undefined ? resolvePromise() : reject(error),
        );
      });
    },
  });
}

export async function approveBootstrapClaim(input) {
  const data = exactDataObject(input, APPROVE_KEYS);
  if (
    typeof data.claimFingerprint !== "string" ||
    !HEX64_PATTERN.test(data.claimFingerprint)
  ) {
    invalid();
  }
  const stateRoot = absolutePath(data.stateRoot);
  const journal = validateJournal(
    await readJsonFile(joinPath(stateRoot, BOOTSTRAP_BROKER_JOURNAL_FILE), null),
  );
  const entry = journal.claims[data.claimFingerprint];
  if (
    entry === undefined ||
    entry.claimFingerprint !== data.claimFingerprint ||
    entry.status !== "PENDING_APPROVAL"
  ) {
    invalid();
  }
  entry.status = "APPROVED";
  entry.approvedAtMs = String(Date.now());
  await writeJournal(stateRoot, journal);
  return Object.freeze({
    claimFingerprint: data.claimFingerprint,
    paymentMoved: false,
    status: "APPROVED",
  });
}
