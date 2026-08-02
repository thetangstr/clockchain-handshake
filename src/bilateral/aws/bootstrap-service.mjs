import {
  createHash,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import {
  constants as fsConstants,
} from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  rename,
  unlink,
} from "node:fs/promises";
import http from "node:http";
import {
  dirname,
  resolve,
} from "node:path";
import { types } from "node:util";

import {
  approveBootstrapClaimState,
  bootstrapStateClaim,
  consumeBootstrapClaim,
  sealBootstrapClaim,
  submitPayerBootstrapClaim,
  submitRequestorBootstrapClaim,
  validateBootstrapState,
} from "./bootstrap-state.mjs";
import {
  requestorBootstrapClaimFingerprint,
} from "./bootstrap-state.mjs";
import {
  payerBootstrapClaimFingerprint,
} from "../local-mcp/payer-bootstrap-envelope.mjs";

const CAPABILITY_PATTERN = /^[0-9a-f]{64}$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const KEY_ID_PATTERN =
  /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;
const MAX_BODY_BYTES = 262_144;
const MAX_RESPONSE_BYTES = 262_144;
const REQUEST_TIMEOUT_MS = 10_000;
const PAYER_SUBMISSION_KEYS = Object.freeze([
  "claim",
  "paymentMoved",
  "pollCapability",
]);
const PAYER_DELIVERY_KEYS = Object.freeze([
  "claimFingerprint",
  "packageResponse",
  "paymentMoved",
  "status",
]);
const PAYER_PACKAGE_RESPONSE_KEYS = Object.freeze([
  "claimFingerprint",
  "envelope",
  "expiresAtMs",
  "operatorKeyId",
  "paymentMoved",
  "schema",
  "signature",
]);
const REQUESTOR_DELIVERY_KEYS = Object.freeze([
  "claimFingerprint",
  "context",
  "envelope",
  "paymentMoved",
  "repositorySha",
  "schema",
  "signature",
  "status",
]);
const ENVELOPE_KEYS = Object.freeze([
  "algorithm",
  "ciphertextBase64url",
  "ephemeralPublicKey",
  "ivBase64url",
  "paymentMoved",
  "schema",
  "tagBase64url",
]);
const SIGNATURE_KEYS = Object.freeze([
  "algorithm",
  "keyId",
  "value",
]);
const SECRET_KEY_PATTERN =
  /(?:capability|invitation|manifest|private(?:key|path)?|token|evidence)/i;

export class AwsBootstrapServiceError extends Error {
  constructor() {
    super("AWS bootstrap service failed safely.");
    this.name = "AwsBootstrapServiceError";
    this.code = "AWS_BOOTSTRAP_SERVICE_INVALID";
    this.category = "verification";
  }
}

function invalid() {
  throw new AwsBootstrapServiceError();
}

function sanitize(error) {
  if (error instanceof AwsBootstrapServiceError) throw error;
  invalid();
}

function exactObject(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    ![Object.prototype, null].includes(
      Object.getPrototypeOf(value),
    )
  ) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    invalid();
  }
  return value;
}

function capability(value) {
  if (
    typeof value !== "string" ||
    !CAPABILITY_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function capabilityDigest(value) {
  return createHash("sha256")
    .update(capability(value))
    .digest("hex");
}

function safeInteger(value, { maximum, minimum }) {
  if (
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    invalid();
  }
  return value;
}

function hostName(value) {
  if (
    value !== "0.0.0.0" &&
    value !== "127.0.0.1" &&
    value !== "::" &&
    value !== "::1"
  ) {
    invalid();
  }
  return value;
}

function portNumber(value) {
  return safeInteger(value, {
    maximum: 65_535,
    minimum: 0,
  });
}

function canonicalJsonBytes(value) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    invalid();
  }
  const bytes = Buffer.from(text, "utf8");
  if (
    bytes.length === 0 ||
    bytes.length > MAX_RESPONSE_BYTES
  ) {
    invalid();
  }
  return bytes;
}

function parseCanonicalJson(bytes) {
  let value;
  const text = bytes.toString("utf8");
  if (
    Buffer.byteLength(text, "utf8") !== bytes.length
  ) {
    invalid();
  }
  try {
    value = JSON.parse(text);
  } catch {
    invalid();
  }
  if (JSON.stringify(value) !== text) invalid();
  return value;
}

function containsSecretKey(value) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return false;
  }
  if (Array.isArray(value)) {
    return value.some(containsSecretKey);
  }
  return Reflect.ownKeys(value).some(
    (key) =>
      typeof key !== "string" ||
      SECRET_KEY_PATTERN.test(key) ||
      containsSecretKey(value[key]),
  );
}

function sealedResponseBytes(value) {
  if (
    value?.paymentMoved !== false ||
    containsSecretKey(value)
  ) {
    invalid();
  }
  return canonicalJsonBytes(value);
}

function exactBase64url(
  value,
  decodedLength = null,
  maximumLength = null,
) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=")
  ) {
    invalid();
  }
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.toString("base64url") !== value ||
    (
      decodedLength !== null &&
      decoded.length !== decodedLength
    ) ||
    (
      maximumLength !== null &&
      decoded.length > maximumLength
    )
  ) {
    invalid();
  }
}

function validateEnvelope(value, expectedSchema) {
  exactObject(value, ENVELOPE_KEYS);
  if (
    value.algorithm !==
      "X25519-HKDF-SHA256-AES-256-GCM" ||
    value.paymentMoved !== false ||
    value.schema !== expectedSchema
  ) {
    invalid();
  }
  exactBase64url(
    value.ciphertextBase64url,
    null,
    65_536,
  );
  exactBase64url(value.ephemeralPublicKey, 32);
  exactBase64url(value.ivBase64url, 12);
  exactBase64url(value.tagBase64url, 16);
}

function validateSignature(value, operatorKeyId) {
  exactObject(value, SIGNATURE_KEYS);
  if (
    value.algorithm !== "ed25519" ||
    value.keyId !== operatorKeyId ||
    typeof operatorKeyId !== "string" ||
    !KEY_ID_PATTERN.test(operatorKeyId) ||
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
}

function validateRoleSealedResponse(value, entry) {
  if (entry?.role === "payer") {
    exactObject(value, PAYER_DELIVERY_KEYS);
    const packageResponse = exactObject(
      value.packageResponse,
      PAYER_PACKAGE_RESPONSE_KEYS,
    );
    if (
      value.claimFingerprint !==
        entry.claimFingerprint ||
      value.paymentMoved !== false ||
      value.status !== "SEALED" ||
      packageResponse.claimFingerprint !==
        entry.claimFingerprint ||
      packageResponse.paymentMoved !== false ||
      packageResponse.schema !==
        "clockchain.payer-bootstrap-response/v1" ||
      typeof packageResponse.expiresAtMs !==
        "string" ||
      !/^(?:0|[1-9][0-9]*)$/.test(
        packageResponse.expiresAtMs,
      ) ||
      typeof packageResponse.operatorKeyId !==
        "string"
    ) {
      invalid();
    }
    validateEnvelope(
      packageResponse.envelope,
      "clockchain.payer-bootstrap-package/v1",
    );
    validateSignature(
      packageResponse.signature,
      packageResponse.operatorKeyId,
    );
    return;
  }
  if (entry?.role === "requestor") {
    exactObject(value, REQUESTOR_DELIVERY_KEYS);
    if (
      value.claimFingerprint !==
        entry.claimFingerprint ||
      value.paymentMoved !== false ||
      value.repositorySha !==
        entry.claim.repositorySha ||
      value.schema !==
        "clockchain.requestor-bootstrap-broker-response/v1" ||
      value.status !== "SEALED"
    ) {
      invalid();
    }
    exactObject(value.context, [
      "claimNonce",
      "paymentMoved",
      "releaseId",
      "repositorySha",
      "sessionId",
    ]);
    if (
      value.context.claimNonce !==
        entry.claim.claimNonce ||
      value.context.paymentMoved !== false ||
      value.context.releaseId !== entry.releaseId ||
      value.context.repositorySha !==
        entry.claim.repositorySha ||
      value.context.sessionId !== entry.sessionId
    ) {
      invalid();
    }
    validateEnvelope(
      value.envelope,
      "clockchain.requestor-bootstrap-envelope/v1",
    );
    validateSignature(
      value.signature,
      value.signature?.keyId,
    );
    return;
  }
  invalid();
}

function fixedFailure() {
  return {
    error: "AWS_BOOTSTRAP_SERVICE_FAILED",
    paymentMoved: false,
    status: "FAILED",
  };
}

function writeJson(response, statusCode, value) {
  const bytes = canonicalJsonBytes(value);
  response.writeHead(statusCode, {
    "cache-control": "no-store",
    "content-length": String(bytes.length),
    "content-type": "application/json",
  });
  response.end(bytes);
}

function safeFailure(response, statusCode) {
  writeJson(response, statusCode, fixedFailure());
}

async function readBody(request) {
  const contentType = request.headers["content-type"];
  if (contentType !== "application/json") invalid();
  const declared = request.headers["content-length"];
  if (
    declared !== undefined &&
    (
      !/^(?:0|[1-9][0-9]*)$/.test(declared) ||
      Number(declared) > MAX_BODY_BYTES
    )
  ) {
    const error = new AwsBootstrapServiceError();
    error.httpStatus = 413;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new AwsBootstrapServiceError();
      error.httpStatus = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (total === 0) invalid();
  return parseCanonicalJson(Buffer.concat(chunks));
}

function bearer(request) {
  const value = request.headers.authorization;
  if (
    typeof value !== "string" ||
    !value.startsWith("Bearer ") ||
    value.length !== 71
  ) {
    invalid();
  }
  return capability(value.slice(7));
}

function authorized(request, expectedDigest) {
  let actual;
  try {
    actual = capabilityDigest(bearer(request));
  } catch {
    return false;
  }
  return timingSafeEqual(
    Buffer.from(actual, "hex"),
    Buffer.from(expectedDigest, "hex"),
  );
}

function pathMatch(pathname, role) {
  const prefix = `/v1/${role}-claims/`;
  if (!pathname.startsWith(prefix)) return null;
  const fingerprint = pathname.slice(prefix.length);
  return FINGERPRINT_PATTERN.test(fingerprint)
    ? fingerprint
    : null;
}

function pendingResponse(entry, repositorySha) {
  if (entry.role === "payer") {
    return {
      claimFingerprint: entry.claimFingerprint,
      paymentMoved: false,
      status: "PENDING",
    };
  }
  return {
    claimFingerprint: entry.claimFingerprint,
    paymentMoved: false,
    repositorySha,
    schema:
      "clockchain.requestor-bootstrap-broker-response/v1",
    status: "PENDING_APPROVAL",
  };
}

function storedResponse(entry) {
  if (
    typeof entry.sealedResponseBase64 !== "string"
  ) {
    invalid();
  }
  const bytes = Buffer.from(
    entry.sealedResponseBase64,
    "base64",
  );
  const value = parseCanonicalJson(bytes);
  if (
    value.paymentMoved !== false ||
    containsSecretKey(value)
  ) {
    invalid();
  }
  return { bytes, value };
}

function validateStore(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    typeof value.readState !== "function" ||
    typeof value.writeState !== "function"
  ) {
    invalid();
  }
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    resolve(value) !== value
  ) {
    invalid();
  }
  return value;
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

async function validatePrivateDirectory(path) {
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

async function readStateFile(path) {
  let before;
  try {
    before = await lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    invalid();
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    before.size <= 0 ||
    before.size > MAX_RESPONSE_BYTES
  ) {
    invalid();
  }
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const after = await handle.stat();
    if (!sameIdentity(before, after)) invalid();
    const bytes = await handle.readFile();
    const afterRead = await handle.stat();
    if (
      bytes.length !== before.size ||
      !sameIdentity(before, afterRead)
    ) {
      invalid();
    }
    return validateBootstrapState(
      parseCanonicalJson(bytes),
    );
  } catch (error) {
    sanitize(error);
  } finally {
    await handle?.close();
  }
}

async function writeNewFile(path, bytes) {
  const handle = await open(
    path,
    fsConstants.O_WRONLY |
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
  if (failure !== undefined) throw failure;
}

async function syncDirectory(path) {
  const handle = await open(
    path,
    fsConstants.O_RDONLY,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function sameRun(left, right) {
  return (
    left.paymentMoved === false &&
    right.paymentMoved === false &&
    left.releaseId === right.releaseId &&
    left.repositorySha === right.repositorySha &&
    left.schema === right.schema &&
    left.sessionId === right.sessionId
  );
}

export async function createAwsBootstrapStateFileStore({
  initialState,
  statePath,
} = {}) {
  try {
    const initial = validateBootstrapState(initialState);
    const path = absolutePath(statePath);
    const directory = dirname(path);
    await validatePrivateDirectory(directory);
    let current = await readStateFile(path);
    if (current === null) {
      try {
        await writeNewFile(
          path,
          canonicalJsonBytes(initial),
        );
        await syncDirectory(directory);
        current = initial;
      } catch (error) {
        if (error?.code !== "EEXIST") throw error;
        current = await readStateFile(path);
      }
    }
    if (
      current === null ||
      !sameRun(current, initial)
    ) {
      invalid();
    }
    const lockPath = `${path}.lock`;
    return Object.freeze({
      async readState() {
        try {
          const state = await readStateFile(path);
          if (
            state === null ||
            !sameRun(state, initial)
          ) {
            invalid();
          }
          return state;
        } catch (error) {
          sanitize(error);
        }
      },

      async writeState({
        expectedRevision,
        state,
      } = {}) {
        let lock;
        try {
          if (
            typeof expectedRevision !== "string" ||
            !/^(?:0|[1-9][0-9]*)$/.test(
              expectedRevision,
            ) ||
            BigInt(expectedRevision) >
              BigInt(Number.MAX_SAFE_INTEGER)
          ) {
            invalid();
          }
          lock = await open(
            lockPath,
            fsConstants.O_WRONLY |
              fsConstants.O_CREAT |
              fsConstants.O_EXCL |
              (fsConstants.O_NOFOLLOW ?? 0),
            0o600,
          );
          await lock.writeFile(
            `${expectedRevision}\n`,
            "utf8",
          );
          await lock.sync();
          const before = await readStateFile(path);
          if (
            before === null ||
            before.revision !== expectedRevision
          ) {
            return false;
          }
          const next = validateBootstrapState(state);
          if (
            !sameRun(before, next) ||
            BigInt(next.revision) !==
              BigInt(before.revision) + 1n
          ) {
            invalid();
          }
          const temporary =
            `${path}.${randomUUID()}.tmp`;
          try {
            await writeNewFile(
              temporary,
              canonicalJsonBytes(next),
            );
            await rename(temporary, path);
            await syncDirectory(directory);
          } catch (error) {
            try {
              await unlink(temporary);
            } catch (unlinkError) {
              if (unlinkError?.code !== "ENOENT") {
                throw unlinkError;
              }
            }
            throw error;
          }
          return true;
        } catch (error) {
          sanitize(error);
        } finally {
          if (lock !== undefined) {
            try {
              await lock.close();
            } finally {
              try {
                await unlink(lockPath);
              } catch (error) {
                if (error?.code !== "ENOENT") throw error;
              }
            }
          }
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}

export function createAwsBootstrapService({
  brokerCapabilityDigest,
  claimExpiresAfterMs,
  createHttpServer = http.createServer,
  host,
  nowMs = Date.now,
  port,
  store,
} = {}) {
  try {
    if (
      typeof brokerCapabilityDigest !== "string" ||
      !DIGEST_PATTERN.test(brokerCapabilityDigest) ||
      typeof createHttpServer !== "function" ||
      typeof nowMs !== "function"
    ) {
      invalid();
    }
    const brokerDigest = brokerCapabilityDigest;
    const expiresAfter = safeInteger(
      claimExpiresAfterMs,
      { maximum: 30 * 60_000, minimum: 1_000 },
    );
    const bindHost = hostName(host);
    const bindPort = portNumber(port);
    const durableStore = validateStore(store);
    let server;
    let queue = Promise.resolve();

    function serialized(operation) {
      const result = queue.then(operation, operation);
      queue = result.catch(() => {});
      return result;
    }

    async function commit(operation) {
      return serialized(async () => {
        const current = await durableStore.readState();
        const next = operation(current);
        if (next === current) return current;
        const written = await durableStore.writeState({
          expectedRevision: current.revision,
          state: next,
        });
        if (written !== true) invalid();
        return next;
      });
    }

    async function submitPayer(value) {
      exactObject(value, PAYER_SUBMISSION_KEYS);
      if (value.paymentMoved !== false) invalid();
      const pollDigest = capabilityDigest(
        value.pollCapability,
      );
      const fingerprint =
        payerBootstrapClaimFingerprint(value.claim);
      return commit((state) => {
        const existing = state.claims[fingerprint];
        if (
          existing === undefined &&
          Object.values(state.claims).some(
            (entry) => entry.role === "payer",
          )
        ) {
          const error = new AwsBootstrapServiceError();
          error.httpStatus = 409;
          throw error;
        }
        return submitPayerBootstrapClaim({
          authCapabilityDigest: pollDigest,
          claim: value.claim,
          expectedRevision: state.revision,
          expiresAtMs:
            existing?.expiresAtMs ??
            String(nowMs() + expiresAfter),
          nowMs: nowMs(),
          state,
        });
      });
    }

    async function submitRequestor(value) {
      const fingerprint =
        requestorBootstrapClaimFingerprint(value);
      return commit((state) => {
        const existing = state.claims[fingerprint];
        if (
          existing === undefined &&
          Object.values(state.claims).some(
            (entry) => entry.role === "requestor",
          )
        ) {
          const error = new AwsBootstrapServiceError();
          error.httpStatus = 409;
          throw error;
        }
        return submitRequestorBootstrapClaim({
          authCapabilityDigest: brokerDigest,
          claim: value,
          expectedRevision: state.revision,
          expiresAtMs:
            existing?.expiresAtMs ??
            String(nowMs() + expiresAfter),
          nowMs: nowMs(),
          releaseId: state.releaseId,
          sessionId: state.sessionId,
          state,
        });
      });
    }

    async function deliver({
      authCapabilityDigest,
      fingerprint,
      role,
    }) {
      return serialized(async () => {
        let state = await durableStore.readState();
        let entry = bootstrapStateClaim({
          authCapabilityDigest,
          claimFingerprint: fingerprint,
          nowMs: nowMs(),
          state,
        });
        if (entry.role !== role) invalid();
        if (
          entry.status === "PENDING" ||
          entry.status === "APPROVED"
        ) {
          return {
            body: pendingResponse(
              entry,
              state.repositorySha,
            ),
            statusCode:
              role === "payer" ? 200 : 202,
          };
        }
        if (entry.status === "SEALED") {
          const next = consumeBootstrapClaim({
            authCapabilityDigest,
            claimFingerprint: fingerprint,
            expectedRevision: state.revision,
            nowMs: nowMs(),
            state,
          });
          const written =
            await durableStore.writeState({
              expectedRevision: state.revision,
              state: next,
            });
          if (written !== true) invalid();
          state = next;
          entry = state.claims[fingerprint];
        }
        if (entry.status !== "CONSUMED") invalid();
        const response = storedResponse(entry);
        return {
          body: response.value,
          bytes: response.bytes,
          statusCode: 200,
        };
      });
    }

    async function handleRequest(request, response) {
      try {
        request.setTimeout(
          REQUEST_TIMEOUT_MS,
          () => request.destroy(),
        );
        const url = new URL(
          request.url,
          "http://bootstrap.invalid",
        );
        if (
          url.search !== "" ||
          url.hash !== ""
        ) {
          safeFailure(response, 404);
          return;
        }
        if (url.pathname === "/health") {
          if (request.method !== "GET") {
            safeFailure(response, 405);
            return;
          }
          writeJson(response, 200, {
            paymentMoved: false,
            status: "HEALTHY",
          });
          return;
        }
        if (url.pathname === "/v1/payer-claims") {
          if (request.method !== "POST") {
            safeFailure(response, 405);
            return;
          }
          const state = await submitPayer(
            await readBody(request),
          );
          const claim = Object.values(state.claims)
            .find((entry) => entry.role === "payer");
          writeJson(
            response,
            200,
            pendingResponse(
              claim,
              state.repositorySha,
            ),
          );
          return;
        }
        if (url.pathname === "/v1/requestor-claims") {
          if (request.method !== "POST") {
            safeFailure(response, 405);
            return;
          }
          if (!authorized(request, brokerDigest)) {
            safeFailure(response, 401);
            return;
          }
          const value = await readBody(request);
          const state = await submitRequestor(value);
          const fingerprint =
            requestorBootstrapClaimFingerprint(value);
          const entry = state.claims[fingerprint];
          if (
            entry.status === "SEALED" ||
            entry.status === "CONSUMED"
          ) {
            const delivered = await deliver({
              authCapabilityDigest: brokerDigest,
              fingerprint,
              role: "requestor",
            });
            writeJson(
              response,
              delivered.statusCode,
              delivered.body,
            );
            return;
          }
          writeJson(
            response,
            202,
            pendingResponse(
              entry,
              state.repositorySha,
            ),
          );
          return;
        }
        const payerFingerprint =
          pathMatch(url.pathname, "payer");
        if (payerFingerprint !== null) {
          if (request.method !== "GET") {
            safeFailure(response, 405);
            return;
          }
          let pollDigest;
          try {
            pollDigest =
              capabilityDigest(bearer(request));
          } catch {
            safeFailure(response, 401);
            return;
          }
          const snapshot =
            await durableStore.readState();
          const payerEntry =
            snapshot.claims[payerFingerprint];
          if (
            payerEntry === undefined ||
            payerEntry.role !== "payer" ||
            payerEntry.authCapabilityDigest !==
              pollDigest
          ) {
            safeFailure(response, 401);
            return;
          }
          const delivered = await deliver({
            authCapabilityDigest: pollDigest,
            fingerprint: payerFingerprint,
            role: "payer",
          });
          writeJson(
            response,
            delivered.statusCode,
            delivered.body,
          );
          return;
        }
        const requestorFingerprint =
          pathMatch(url.pathname, "requestor");
        if (requestorFingerprint !== null) {
          if (request.method !== "GET") {
            safeFailure(response, 405);
            return;
          }
          if (!authorized(request, brokerDigest)) {
            safeFailure(response, 401);
            return;
          }
          const delivered = await deliver({
            authCapabilityDigest: brokerDigest,
            fingerprint: requestorFingerprint,
            role: "requestor",
          });
          writeJson(
            response,
            delivered.statusCode,
            delivered.body,
          );
          return;
        }
        safeFailure(response, 404);
      } catch (error) {
        safeFailure(
          response,
          error?.httpStatus ?? 400,
        );
      }
    }

    return Object.freeze({
      async approveClaim({
        claimFingerprint,
        expectedRevision,
        paymentMoved,
      } = {}) {
        try {
          if (paymentMoved !== false) invalid();
          return await commit((state) =>
            approveBootstrapClaimState({
              claimFingerprint,
              expectedRevision,
              nowMs: nowMs(),
              state,
            }));
        } catch (error) {
          sanitize(error);
        }
      },

      async sealClaim({
        claimFingerprint,
        expectedRevision,
        paymentMoved,
        response,
      } = {}) {
        try {
          if (paymentMoved !== false) invalid();
          return await commit((state) => {
            const entry =
              state.claims[claimFingerprint];
            validateRoleSealedResponse(
              response,
              entry,
            );
            const responseBytes =
              sealedResponseBytes(response);
            return sealBootstrapClaim({
              claimFingerprint,
              expectedRevision,
              nowMs: nowMs(),
              responseBytes,
              state,
            });
          });
        } catch (error) {
          sanitize(error);
        }
      },

      async start() {
        try {
          if (server !== undefined) invalid();
          server = createHttpServer(handleRequest);
          await new Promise(
            (resolvePromise, rejectPromise) => {
              server.once("error", rejectPromise);
              server.listen(
                bindPort,
                bindHost,
                resolvePromise,
              );
            },
          );
          const address = server.address();
          if (
            typeof address !== "object" ||
            address === null
          ) {
            invalid();
          }
          const authority = address.family === "IPv6"
            ? `[${address.address}]:${address.port}`
            : `${address.address}:${address.port}`;
          return Object.freeze({
            host: address.address,
            port: address.port,
            url: `http://${authority}`,
          });
        } catch (error) {
          sanitize(error);
        }
      },

      async stop() {
        if (server === undefined) return;
        const closing = server;
        server = undefined;
        await new Promise(
          (resolvePromise, rejectPromise) => {
            closing.close((error) =>
              error === undefined
                ? resolvePromise()
                : rejectPromise(error));
          },
        );
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
