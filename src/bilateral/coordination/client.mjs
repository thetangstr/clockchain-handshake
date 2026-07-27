import {
  createHash,
  createPrivateKey,
  createPublicKey,
  timingSafeEqual,
} from "node:crypto";
import https from "node:https";
import {
  isIP,
} from "node:net";
import {
  checkServerIdentity as checkTlsServerIdentity,
} from "node:tls";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  canonicalBytes,
} from "../canonical.mjs";
import {
  KEY_ID_PATTERN,
} from "../descriptor.mjs";
import {
  ARTIFACT_POLICIES,
  validateRelayArtifact,
} from "./artifact.mjs";
import {
  COORDINATION_ENVELOPE_SCHEMA,
  createCoordinationEnvelope,
  eventDigest,
  verifyCoordinationEnvelope,
} from "./envelope.mjs";
import {
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
  verifyCoordinationEnrollment,
} from "./enrollment.mjs";
import {
  RELEASE_STATES,
  initialReleaseView,
} from "./lifecycle.mjs";
import {
  createActiveLaunchState,
  validateActiveLaunchState,
  validateLaunchManifest,
} from "./manifest.mjs";
import {
  COORDINATION_RECEIPT_SCHEMA,
  createReceiptVerifierFromCertificate,
  verifyCoordinationReceipt,
} from "./receipt.mjs";

export const CLIENT_CONNECT_TIMEOUT_MS = 5_000;
export const CLIENT_HEADER_TIMEOUT_MS = 5_000;
export const CLIENT_BODY_TIMEOUT_MS = 5_000;
export const CLIENT_TOTAL_TIMEOUT_MS = 45_000;
export const MAX_CLIENT_JSON_RESPONSE_BYTES = 3_145_728;

const MAX_CLIENT_ARTIFACT_RESPONSE_BYTES = 3_145_728;
const MAX_CLIENT_EVENTS = 4_096;
const TRANSPORT_KEYS = Object.freeze([
  "expectedFingerprint",
  "relayUrl",
  "tlsCertificatePem",
]);
const TRANSPORT_REQUEST_KEYS = Object.freeze([
  "body",
  "method",
  "path",
]);
const TRANSPORT_REQUEST_KEYS_WITH_SIGNAL = Object.freeze([
  ...TRANSPORT_REQUEST_KEYS,
  "signal",
]);
const TRANSPORT_PUT_KEYS = Object.freeze([
  "artifactType",
  "body",
  "method",
  "path",
]);
const TRANSPORT_PUT_KEYS_WITH_SIGNAL = Object.freeze([
  ...TRANSPORT_PUT_KEYS,
  "signal",
]);
const CLIENT_KEYS = Object.freeze([
  "coordinationIdentity",
  "manifest",
  "transport",
]);
const RESUMED_CLIENT_KEYS = Object.freeze([
  "activeLaunchState",
  "coordinationIdentity",
  "senderState",
  "transport",
]);
const IDENTITY_KEYS = Object.freeze([
  "keyId",
  "privateKeyPem",
  "publicKey",
]);
const SENDER_STATE_KEYS = Object.freeze([
  "previousEventDigest",
  "sequence",
]);
const TRANSPORT_METHOD_KEYS = Object.freeze([
  "request",
  "verifyReceipt",
]);
const RESPONSE_KEYS = Object.freeze([
  "body",
  "contentType",
  "statusCode",
]);
const BOOTSTRAP_KEYS = Object.freeze(["enrollment"]);
const BOOTSTRAP_KEYS_WITH_SIGNAL = Object.freeze([
  "enrollment",
  "signal",
]);
const APPEND_KEYS = Object.freeze([
  "artifactDigest",
  "kind",
  "subjectRun",
]);
const APPEND_KEYS_WITH_SIGNAL = Object.freeze([
  ...APPEND_KEYS,
  "signal",
]);
const PUT_KEYS = Object.freeze([
  "artifactType",
  "bytes",
  "expectedDigest",
]);
const PUT_KEYS_WITH_SIGNAL = Object.freeze([
  ...PUT_KEYS,
  "signal",
]);
const GET_KEYS = Object.freeze([
  "artifactType",
  "digest",
]);
const GET_KEYS_WITH_SIGNAL = Object.freeze([
  ...GET_KEYS,
  "signal",
]);
const READ_EVENTS_KEYS = Object.freeze([
  "after",
  "waitMs",
]);
const READ_EVENTS_KEYS_WITH_SIGNAL = Object.freeze([
  ...READ_EVENTS_KEYS,
  "signal",
]);
const RECEIPT_EXPECTED_KEYS = Object.freeze([
  "capabilityDigest",
  "enrollmentDigest",
  "releaseId",
  "repositorySha",
  "role",
  "sessionId",
]);
const RECEIPT_KEYS = Object.freeze([
  "capabilityDigest",
  "certificateSha256",
  "enrollmentDigest",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "role",
  "schema",
  "sessionId",
  "signature",
  "signatureAlgorithm",
]);
const ARTIFACT_ACK_KEYS = Object.freeze([
  "artifactType",
  "byteLength",
  "digest",
]);
const VIEW_KEYS = Object.freeze([
  "facts",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "sessionId",
  "state",
]);
const READ_VIEW_KEYS = Object.freeze([]);
const READ_VIEW_KEYS_WITH_SIGNAL = Object.freeze([
  "signal",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const ARTIFACT_TYPE_PATTERN =
  /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const LOCALLY_SUPPORTED_ARTIFACT_TYPES = new Set([
  "coordination-enrollment",
  "failure-summary",
  "identity-package",
  "party-result-package",
  "preflight-aggregate-report",
  "preflight-participant-report",
  "preflight-plan",
  "preflight-public-key",
  "recovery-command-manifest",
  "signed-descriptor",
  "token-commitment",
]);
const RELAY_URL_PATTERN =
  /^https:\/\/(\[[0-9a-fA-F:.]+\]|[0-9.]+):([0-9]{1,5})$/;
const ED25519_SPKI_PREFIX = Buffer.from(
  "302a300506032b6570032100",
  "hex",
);

export class CoordinationClientError extends Error {
  constructor(code = "COORDINATION_CLIENT_INVALID") {
    super("Coordination client operation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code =
      typeof code === "string" &&
      /^COORDINATION_[A-Z_]+$/.test(code)
        ? code
        : "COORDINATION_CLIENT_INVALID";
  }
}

function invalid() {
  throw new CoordinationClientError();
}

function aborted() {
  throw new CoordinationClientError(
    "COORDINATION_CLIENT_ABORTED",
  );
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value);
    return (
      prototype === Object.prototype || prototype === null
    );
  } catch {
    return false;
  }
}

function readExactData(value, keys) {
  if (!isPlainObject(value)) {
    invalid();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    invalid();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      invalid();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      invalid();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return Object.freeze(result);
}

function stableBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(canonicalizeReceiptEventValue(value)),
      "utf8",
    );
  } catch {
    invalid();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSignal(signal) {
  if (
    signal === undefined ||
    !(signal instanceof AbortSignal) ||
    Object.getPrototypeOf(signal) !==
      AbortSignal.prototype
  ) {
    invalid();
  }
  return signal;
}

function keysWithOptionalSignal(
  value,
  withoutSignal,
  withSignal,
) {
  if (!isPlainObject(value)) {
    invalid();
  }
  return Reflect.ownKeys(value).includes("signal")
    ? withSignal
    : withoutSignal;
}

function parseCanonicalJson(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    invalid();
  }
  let parsed;
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      invalid();
    }
    parsed = JSON.parse(text);
    if (!stableBytes(parsed).equals(bytes)) {
      invalid();
    }
  } catch (error) {
    if (error instanceof CoordinationClientError) {
      throw error;
    }
    invalid();
  }
  return parsed;
}

function assertRelayUrl(value) {
  if (typeof value !== "string") {
    invalid();
  }
  const match = RELAY_URL_PATTERN.exec(value);
  if (match === null) {
    invalid();
  }
  const hostname = match[1].startsWith("[")
    ? match[1].slice(1, -1)
    : match[1];
  const port = Number(match[2]);
  if (
    isIP(hostname) === 0 ||
    port < 1 ||
    port > 65_535 ||
    hostname === "0.0.0.0" ||
    hostname === "::"
  ) {
    invalid();
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    invalid();
  }
  if (
    parsed.origin !== value ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    invalid();
  }
  return Object.freeze({
    authority: value.slice("https://".length),
    hostname,
    port,
    url: value,
  });
}

function assertFingerprint(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
  ) {
    invalid();
  }
  return Buffer.from(value, "hex");
}

function rawHeaderValues(rawHeaders, name) {
  const result = [];
  for (
    let index = 0;
    index < rawHeaders.length;
    index += 2
  ) {
    if (
      rawHeaders[index].toLowerCase() === name
    ) {
      result.push(rawHeaders[index + 1]);
    }
  }
  return result;
}

function expectedResponseType(method, path) {
  return method === "GET" &&
    /^\/v1\/artifacts\/[0-9a-f]{64}$/.test(path)
    ? "application/octet-stream"
    : "application/json";
}

function headerWait(path) {
  const match =
    /[?&]waitMs=([0-9]+)(?:&|$)/.exec(path);
  if (match === null) {
    return CLIENT_HEADER_TIMEOUT_MS;
  }
  const waitMs = Number(match[1]);
  return Math.min(
    waitMs + CLIENT_HEADER_TIMEOUT_MS,
    35_000,
  );
}

function validateRequestInput(value) {
  if (!isPlainObject(value)) {
    invalid();
  }
  const ownKeys = Reflect.ownKeys(value);
  const hasSignal = ownKeys.includes("signal");
  const methodDescriptor =
    Object.getOwnPropertyDescriptor(value, "method");
  if (
    methodDescriptor?.enumerable !== true ||
    !Object.hasOwn(methodDescriptor, "value")
  ) {
    invalid();
  }
  const method = methodDescriptor.value;
  const pathDescriptor =
    Object.getOwnPropertyDescriptor(value, "path");
  if (
    pathDescriptor?.enumerable !== true ||
    !Object.hasOwn(pathDescriptor, "value")
  ) {
    invalid();
  }
  const artifactGet =
    method === "GET" &&
    typeof pathDescriptor.value === "string" &&
    /^\/v1\/artifacts\/[0-9a-f]{64}$/.test(
      pathDescriptor.value,
    );
  const keys =
    method === "PUT" || artifactGet
      ? hasSignal
        ? TRANSPORT_PUT_KEYS_WITH_SIGNAL
        : TRANSPORT_PUT_KEYS
      : hasSignal
        ? TRANSPORT_REQUEST_KEYS_WITH_SIGNAL
        : TRANSPORT_REQUEST_KEYS;
  const data = readExactData(value, keys);
  const signal =
    data.signal === undefined
      ? undefined
      : assertSignal(data.signal);
  if (
    typeof data.path !== "string" ||
    data.path.includes("%") ||
    data.path.includes("#") ||
    data.path.includes("..") ||
    data.path.startsWith("//")
  ) {
    invalid();
  }
  if (method === "POST") {
    if (
      data.path !== "/v1/bootstrap" &&
      data.path !== "/v1/events"
    ) {
      invalid();
    }
    if (
      !Buffer.isBuffer(data.body) ||
      data.body.length === 0 ||
      data.body.length > 65_536
    ) {
      invalid();
    }
  } else if (method === "PUT") {
    if (
      !/^\/v1\/artifacts\/[0-9a-f]{64}$/.test(
        data.path,
      ) ||
      typeof data.artifactType !== "string" ||
      !ARTIFACT_TYPE_PATTERN.test(data.artifactType) ||
      ARTIFACT_POLICIES[data.artifactType] ===
        undefined ||
      !Buffer.isBuffer(data.body) ||
      data.body.length === 0 ||
      data.body.length >
        ARTIFACT_POLICIES[data.artifactType].maximum
    ) {
      invalid();
    }
  } else if (method === "GET") {
    const artifact =
      /^\/v1\/artifacts\/[0-9a-f]{64}$/.test(
        data.path,
      );
    const view = new RegExp(
      `^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/view$`,
    ).test(data.path);
    const enrollments = new RegExp(
      `^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/enrollments$`,
    ).test(data.path);
    const events = new RegExp(
      `^/v1/sessions/${UUID_PATTERN.source.slice(1, -1)}/events\\?(?:after=[0-9a-f]{64}&)?waitMs=(?:0|[1-9][0-9]*)$`,
    ).test(data.path);
    if (
      (!artifact &&
        !view &&
        !events &&
        !enrollments) ||
      data.body !== null
    ) {
      invalid();
    }
    if (events) {
      const waitMs = Number(
        /[?&]waitMs=([0-9]+)$/.exec(
          data.path,
        )[1],
      );
      if (
        !Number.isSafeInteger(waitMs) ||
        waitMs > 30_000
      ) {
        invalid();
      }
    }
    if (
      artifact &&
      (
        typeof data.artifactType !== "string" ||
        ARTIFACT_POLICIES[data.artifactType] ===
          undefined
      )
    ) {
      invalid();
    }
  } else {
    invalid();
  }
  return Object.freeze({
    artifactType: data.artifactType,
    body:
      data.body === null
        ? null
        : Buffer.from(data.body),
    method,
    path: data.path,
    signal,
  });
}

function validateResponseMetadata(
  response,
  method,
  path,
  artifactType,
) {
  const contentLengthValues = rawHeaderValues(
    response.rawHeaders,
    "content-length",
  );
  const contentTypeValues = rawHeaderValues(
    response.rawHeaders,
    "content-type",
  );
  for (const forbidden of [
    "content-encoding",
    "location",
    "transfer-encoding",
    "upgrade",
  ]) {
    if (
      rawHeaderValues(response.rawHeaders, forbidden)
        .length !== 0
    ) {
      invalid();
    }
  }
  const contentType = expectedResponseType(
    method,
    path,
  );
  if (
    response.statusCode !== 200 ||
    contentLengthValues.length !== 1 ||
    contentTypeValues.length !== 1 ||
    contentTypeValues[0] !== contentType ||
    !DECIMAL_PATTERN.test(contentLengthValues[0])
  ) {
    invalid();
  }
  const contentLength = Number(contentLengthValues[0]);
  const maximum =
    contentType === "application/json"
      ? MAX_CLIENT_JSON_RESPONSE_BYTES
      : ARTIFACT_POLICIES[artifactType]?.maximum ??
        MAX_CLIENT_ARTIFACT_RESPONSE_BYTES;
  if (
    !Number.isSafeInteger(contentLength) ||
    contentLength > maximum
  ) {
    invalid();
  }
  return Object.freeze({
    contentLength,
    contentType,
    maximum,
  });
}

export function createPinnedHttpsTransport(input) {
  const data = readExactData(input, TRANSPORT_KEYS);
  const endpoint = assertRelayUrl(data.relayUrl);
  const expectedFingerprint = assertFingerprint(
    data.expectedFingerprint,
  );
  let receiptVerifier;
  try {
    receiptVerifier =
      createReceiptVerifierFromCertificate({
        tlsCertificatePem:
          data.tlsCertificatePem,
      });
  } catch {
    invalid();
  }
  if (
    !timingSafeEqual(
      Buffer.from(
        receiptVerifier.certificateSha256,
        "hex",
      ),
      expectedFingerprint,
    )
  ) {
    invalid();
  }
  const tlsCertificatePem =
    data.tlsCertificatePem;

  async function request(value) {
    let requestInput;
    try {
      requestInput = validateRequestInput(value);
    } catch (error) {
      if (error instanceof CoordinationClientError) {
        throw error;
      }
      invalid();
    }
    if (requestInput.signal?.aborted === true) {
      aborted();
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let secure = false;
      let response;
      let connectTimer;
      let headerTimer;
      let bodyTimer;
      let totalTimer;
      let externalAbort;
      let requestHandle;

      const clearTimers = () => {
        for (const timer of [
          connectTimer,
          headerTimer,
          bodyTimer,
          totalTimer,
        ]) {
          clearTimeout(timer);
        }
      };
      const cleanup = () => {
        clearTimers();
        if (
          externalAbort !== undefined &&
          requestInput.signal !== undefined
        ) {
          requestInput.signal.removeEventListener(
            "abort",
            externalAbort,
          );
        }
      };
      const fail = (error, destroy = true) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        if (destroy) {
          response?.destroy();
          requestHandle?.destroy();
        }
        reject(error);
      };
      const failInvalid = () =>
        fail(new CoordinationClientError());
      const failAmbiguous = () =>
        fail(
          new CoordinationClientError(
            "COORDINATION_TRANSPORT_AMBIGUOUS",
          ),
        );
      const failAborted = () =>
        fail(
          new CoordinationClientError(
            "COORDINATION_CLIENT_ABORTED",
          ),
        );

      const headers = Object.create(null);
      if (requestInput.body !== null) {
        headers["content-length"] = String(
          requestInput.body.length,
        );
        headers["content-type"] =
          requestInput.method === "PUT"
            ? "application/octet-stream"
            : "application/json";
      }
      headers.host = endpoint.authority;
      if (requestInput.method === "PUT") {
        headers["x-clockchain-artifact-type"] =
          requestInput.artifactType;
      }

      totalTimer = setTimeout(
        failAmbiguous,
        CLIENT_TOTAL_TIMEOUT_MS,
      );
      connectTimer = setTimeout(
        failAmbiguous,
        CLIENT_CONNECT_TIMEOUT_MS,
      );
      externalAbort = failAborted;
      requestInput.signal?.addEventListener(
        "abort",
        externalAbort,
        { once: true },
      );

      try {
        requestHandle = https.request(
          {
            agent: false,
            ca: tlsCertificatePem,
            checkServerIdentity(hostname, certificate) {
              const standardError =
                checkTlsServerIdentity(
                  hostname,
                  certificate,
                );
              if (standardError !== undefined) {
                return standardError;
              }
              if (!Buffer.isBuffer(certificate?.raw)) {
                return new Error(
                  "Pinned TLS identity verification failed.",
                );
              }
              const actual = createHash("sha256")
                .update(certificate.raw)
                .digest();
              if (
                actual.length !==
                  expectedFingerprint.length ||
                !timingSafeEqual(
                  actual,
                  expectedFingerprint,
                )
              ) {
                return new Error(
                  "Pinned TLS identity verification failed.",
                );
              }
              return undefined;
            },
            headers,
            hostname: endpoint.hostname,
            method: requestInput.method,
            path: requestInput.path,
            port: endpoint.port,
            rejectUnauthorized: true,
          },
          (incoming) => {
            response = incoming;
            clearTimeout(headerTimer);
            let metadata;
            try {
              metadata = validateResponseMetadata(
                incoming,
                requestInput.method,
                requestInput.path,
                requestInput.artifactType,
              );
            } catch {
              failInvalid();
              return;
            }
            const chunks = [];
            let length = 0;
            bodyTimer = setTimeout(
              failAmbiguous,
              CLIENT_BODY_TIMEOUT_MS,
            );
            incoming.on("data", (chunk) => {
              length += chunk.length;
              if (
                length > metadata.maximum ||
                length > metadata.contentLength
              ) {
                failInvalid();
                return;
              }
              chunks.push(Buffer.from(chunk));
            });
            incoming.once("aborted", failAmbiguous);
            incoming.once("error", () => {
              if (!settled) {
                failAmbiguous();
              }
            });
            incoming.once("end", () => {
              if (settled) {
                return;
              }
              const body = Buffer.concat(chunks);
              if (
                body.length !== metadata.contentLength ||
                incoming.complete !== true
              ) {
                failAmbiguous();
                return;
              }
              if (
                metadata.contentType ===
                "application/json"
              ) {
                try {
                  parseCanonicalJson(body);
                } catch {
                  failInvalid();
                  return;
                }
              }
              settled = true;
              cleanup();
              resolve(
                Object.freeze({
                  body,
                  contentType: metadata.contentType,
                  statusCode: 200,
                }),
              );
            });
          },
        );
      } catch {
        failInvalid();
        return;
      }
      requestHandle.once("socket", (socket) => {
        socket.once("secureConnect", () => {
          if (settled) {
            return;
          }
          let peer;
          try {
            peer = socket.getPeerCertificate(true);
          } catch {
            failInvalid();
            return;
          }
          if (
            socket.authorized !== true ||
            !Buffer.isBuffer(peer?.raw)
          ) {
            failInvalid();
            return;
          }
          const actual = createHash("sha256")
            .update(peer.raw)
            .digest();
          if (
            actual.length !==
              expectedFingerprint.length ||
            !timingSafeEqual(
              actual,
              expectedFingerprint,
            )
          ) {
            failInvalid();
            return;
          }
          secure = true;
          clearTimeout(connectTimer);
          headerTimer = setTimeout(
            failAmbiguous,
            headerWait(requestInput.path),
          );
        });
      });
      requestHandle.once("error", (error) => {
        if (settled) {
          return;
        }
        if (requestInput.signal?.aborted === true) {
          failAborted();
        } else if (
          typeof error?.code === "string" &&
          error.code.startsWith("HPE_")
        ) {
          failInvalid();
        } else if (secure) {
          failAmbiguous();
        } else {
          failInvalid();
        }
      });
      requestHandle.end(requestInput.body ?? undefined);
    });
  }

  async function verifyReceipt(bytes, expected) {
    try {
      if (!Buffer.isBuffer(bytes)) {
        invalid();
      }
      const expectedData = readExactData(
        expected,
        RECEIPT_EXPECTED_KEYS,
      );
      return await verifyCoordinationReceipt({
        bytes: Buffer.from(bytes),
        expected: expectedData,
        verifier: receiptVerifier,
      });
    } catch (error) {
      if (error instanceof CoordinationClientError) {
        throw error;
      }
      invalid();
    }
  }

  return Object.freeze({
    request,
    verifyReceipt,
  });
}

function validateTransport(value) {
  const data = readExactData(
    value,
    TRANSPORT_METHOD_KEYS,
  );
  if (
    typeof data.request !== "function" ||
    typeof data.verifyReceipt !== "function"
  ) {
    invalid();
  }
  return Object.freeze({
    request: data.request,
    verifyReceipt: data.verifyReceipt,
  });
}

function validateIdentity(value) {
  const data = readExactData(value, IDENTITY_KEYS);
  if (
    typeof data.keyId !== "string" ||
    !KEY_ID_PATTERN.test(data.keyId) ||
    typeof data.publicKey !== "string" ||
    typeof data.privateKeyPem !== "string" ||
    data.privateKeyPem.length === 0 ||
    Buffer.byteLength(data.privateKeyPem, "utf8") >
      1_024
  ) {
    invalid();
  }
  let privateKey;
  let derived;
  try {
    privateKey = createPrivateKey(data.privateKeyPem);
    if (
      privateKey.asymmetricKeyType !== "ed25519" ||
      privateKey.export({
        format: "pem",
        type: "pkcs8",
      }) !== data.privateKeyPem
    ) {
      invalid();
    }
    const der = createPublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    if (
      der.length !== ED25519_SPKI_PREFIX.length + 32 ||
      !der
        .subarray(0, ED25519_SPKI_PREFIX.length)
        .equals(ED25519_SPKI_PREFIX)
    ) {
      invalid();
    }
    derived = der.subarray(ED25519_SPKI_PREFIX.length);
  } catch (error) {
    if (error instanceof CoordinationClientError) {
      throw error;
    }
    invalid();
  }
  const supplied = Buffer.from(data.publicKey, "base64");
  if (
    supplied.length !== 32 ||
    supplied.toString("base64") !== data.publicKey ||
    !timingSafeEqual(supplied, derived)
  ) {
    invalid();
  }
  return Object.freeze({
    keyId: data.keyId,
    privateKeyPem: data.privateKeyPem,
    publicKey: data.publicKey,
  });
}

function validateSenderState(value) {
  if (value === undefined) {
    return Object.freeze({
      previousEventDigest: null,
      sequence: "0",
    });
  }
  const data = readExactData(value, SENDER_STATE_KEYS);
  if (
    (data.previousEventDigest !== null &&
      (typeof data.previousEventDigest !== "string" ||
        !SHA256_PATTERN.test(
          data.previousEventDigest,
        ))) ||
    typeof data.sequence !== "string" ||
    !DECIMAL_PATTERN.test(data.sequence)
  ) {
    invalid();
  }
  const sequence = Number(data.sequence);
  if (
    !Number.isSafeInteger(sequence) ||
    sequence < 0 ||
    String(sequence) !== data.sequence ||
    (sequence === 0) !==
      (data.previousEventDigest === null)
  ) {
    invalid();
  }
  return Object.freeze({
    previousEventDigest: data.previousEventDigest,
    sequence: data.sequence,
  });
}

function validateInjectedResponse(value, contentType) {
  const data = readExactData(value, RESPONSE_KEYS);
  if (
    data.statusCode !== 200 ||
    data.contentType !== contentType ||
    !Buffer.isBuffer(data.body)
  ) {
    invalid();
  }
  const body = Buffer.from(data.body);
  if (contentType === "application/json") {
    parseCanonicalJson(body);
  }
  return body;
}

async function exactRequest(
  transport,
  request,
) {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const exact = Object.create(null);
    if (request.artifactType !== undefined) {
      exact.artifactType = request.artifactType;
    }
    exact.body =
      request.body === null
        ? null
        : Buffer.from(request.body);
    exact.method = request.method;
    exact.path = request.path;
    if (request.signal !== undefined) {
      exact.signal = request.signal;
    }
    try {
      return await transport.request(exact);
    } catch (error) {
      if (
        attempt === 0 &&
        error instanceof CoordinationClientError &&
        error.code ===
          "COORDINATION_TRANSPORT_AMBIGUOUS"
      ) {
        continue;
      }
      throw error;
    }
  }
  invalid();
}

async function assertArtifactInput(
  artifactType,
  bytes,
  expectedDigest,
) {
  try {
    return await validateRelayArtifact({
      artifactType,
      bytes,
      expectedDigest,
      secretCanaries: [],
    });
  } catch {
    invalid();
  }
}

function enrollmentContainsCapability(
  enrollmentBytes,
  enrollment,
  capability,
) {
  const text = enrollmentBytes.toString("utf8");
  const coordinationKey = Buffer.from(
    enrollment.coordinationKey.publicKey,
    "base64",
  );
  const preflightKey = Buffer.from(
    enrollment.preflightKey.publicKey,
    "base64",
  );
  return (
    text
      .toLowerCase()
      .includes(capability.toString("hex")) ||
    text.includes(capability.toString("base64")) ||
    text.includes(capability.toString("base64url")) ||
    timingSafeEqual(coordinationKey, capability) ||
    timingSafeEqual(preflightKey, capability)
  );
}

function validateAdvisoryEvent(
  value,
  context,
) {
  let digest;
  try {
    digest = eventDigest(value);
  } catch {
    invalid();
  }
  if (
    digest !== value.eventDigest ||
    value.releaseId !== context.releaseId ||
    value.repositorySha !==
      context.repositorySha ||
    value.sessionId !== context.sessionId ||
    value.paymentMoved !== false
  ) {
    invalid();
  }
  return value;
}

function deepFreeze(value) {
  if (
    value !== null &&
    typeof value === "object" &&
    !Object.isFrozen(value)
  ) {
    for (const child of Object.values(value)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value;
}

function validateFacts(value, template) {
  if (template === null) {
    if (
      value !== null &&
      (typeof value !== "string" ||
        !SHA256_PATTERN.test(value))
    ) {
      invalid();
    }
    return value;
  }
  if (typeof template === "boolean") {
    if (typeof value !== "boolean") {
      invalid();
    }
    return value;
  }
  const keys = Object.keys(template);
  const data = readExactData(value, keys);
  const output = {};
  for (const key of keys) {
    output[key] = validateFacts(
      data[key],
      template[key],
    );
  }
  return Object.freeze(output);
}

function createCoordinationClientCore({
  freshManifest,
  identity,
  initialState,
  launchState,
  transport,
}) {
  try {
    let manifest = freshManifest;
    const context = Object.freeze({
      releaseId: launchState.releaseId,
      repositorySha: launchState.repositorySha,
      role: launchState.role,
      sessionId: launchState.sessionId,
    });
    const expectedTlsFingerprint =
      launchState.expectedTlsFingerprint;
    const localReceiptVerifier =
      createReceiptVerifierFromCertificate({
        tlsCertificatePem:
          launchState.tlsCertificatePem,
      });
    let capability =
      manifest === null
        ? null
        : Buffer.from(
            manifest.bootstrapCapability,
            "hex",
          );
    const capabilityDigest =
      capability === null
        ? launchState.capabilityDigest
        : sha256(capability);
    let bootstrapComplete = capability === null;
    let authenticatedLaunchState =
      manifest === null ? launchState : null;
    let previousEventDigest =
      initialState.previousEventDigest;
    let sequence = initialState.sequence;
    let appendQueue = Promise.resolve();

    async function bootstrap(value) {
      try {
        if (bootstrapComplete || capability === null) {
          invalid();
        }
        const keys = keysWithOptionalSignal(
          value,
          BOOTSTRAP_KEYS,
          BOOTSTRAP_KEYS_WITH_SIGNAL,
        );
        const inputData = readExactData(value, keys);
        const signal =
          inputData.signal === undefined
            ? undefined
            : assertSignal(inputData.signal);
        const enrollment =
          verifyCoordinationEnrollment(
            inputData.enrollment,
          );
        if (
          enrollment.capabilityDigest !==
            capabilityDigest ||
          enrollment.coordinationKey.algorithm !==
            "ed25519" ||
          enrollment.coordinationKey.keyId !==
            identity.keyId ||
          enrollment.coordinationKey.publicKey !==
            identity.publicKey ||
          enrollment.preflightKey.keyId !==
            `${context.role}-preflight` ||
          enrollment.paymentMoved !== false ||
          enrollment.releaseId !== context.releaseId ||
          enrollment.repositorySha !==
            context.repositorySha ||
          enrollment.role !== context.role ||
          enrollment.sessionId !== context.sessionId
        ) {
          invalid();
        }
        const enrollmentBytes =
          canonicalBytes(enrollment);
        const capabilityText =
          capability.toString("hex");
        const capabilityCanary =
          Buffer.from(capabilityText, "ascii");
        if (
          enrollmentContainsCapability(
            enrollmentBytes,
            enrollment,
            capability,
          )
        ) {
          invalid();
        }
        const wrapperBytes = canonicalBytes({
          capability: capabilityText,
          enrollment,
        });
        const firstCapability =
          wrapperBytes.indexOf(capabilityCanary);
        if (
          firstCapability < 0 ||
          wrapperBytes.indexOf(
            capabilityCanary,
            firstCapability +
              capabilityCanary.length,
          ) !== -1
        ) {
          invalid();
        }
        const response = await exactRequest(
          transport,
          {
            body: wrapperBytes,
            method: "POST",
            path: "/v1/bootstrap",
            signal,
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/json",
          );
        const authoritativeResponse =
          Buffer.from(responseBytes);
        let receipt;
        let transportReceipt;
        const expectedReceipt = Object.freeze({
          capabilityDigest,
          enrollmentDigest:
            sha256(enrollmentBytes),
          releaseId: context.releaseId,
          repositorySha:
            context.repositorySha,
          role: context.role,
          sessionId: context.sessionId,
        });
        try {
          receipt = await verifyCoordinationReceipt({
            bytes: authoritativeResponse,
            expected: expectedReceipt,
            verifier: localReceiptVerifier,
          });
          transportReceipt =
            await transport.verifyReceipt(
              Buffer.from(authoritativeResponse),
              { ...expectedReceipt },
            );
        } catch {
          invalid();
        }
        const transportReceiptData = readExactData(
          transportReceipt,
          RECEIPT_KEYS,
        );
        const receiptData = readExactData(
          receipt,
          RECEIPT_KEYS,
        );
        if (
          !stableBytes(
            transportReceiptData,
          ).equals(stableBytes(receiptData)) ||
          receiptData.schema !==
            COORDINATION_RECEIPT_SCHEMA ||
          receiptData.paymentMoved !== false ||
          receiptData.capabilityDigest !==
            expectedReceipt.capabilityDigest ||
          receiptData.certificateSha256 !==
            expectedTlsFingerprint ||
          receiptData.enrollmentDigest !==
            expectedReceipt.enrollmentDigest ||
          receiptData.releaseId !==
            expectedReceipt.releaseId ||
          receiptData.repositorySha !==
            expectedReceipt.repositorySha ||
          receiptData.role !== expectedReceipt.role ||
          receiptData.sessionId !==
            expectedReceipt.sessionId
        ) {
          invalid();
        }
        const activeLaunchState =
          await createActiveLaunchState({
            coordinationIdentity: identity,
            enrollment,
            manifest,
            receiptBytes: authoritativeResponse,
          });
        const result = Object.freeze({
          activeLaunchState,
          receipt,
        });
        authenticatedLaunchState =
          activeLaunchState;
        bootstrapComplete = true;
        capability.fill(0);
        capability = null;
        manifest = null;
        wrapperBytes.fill(0);
        return result;
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    function appendEvent(value) {
      if (!bootstrapComplete || capability !== null) {
        return Promise.reject(
          new CoordinationClientError(),
        );
      }
      let prepared;
      try {
        const keys = keysWithOptionalSignal(
          value,
          APPEND_KEYS,
          APPEND_KEYS_WITH_SIGNAL,
        );
        const inputData = readExactData(value, keys);
        prepared = Object.freeze({
          artifactDigest: inputData.artifactDigest,
          kind: inputData.kind,
          signal:
            inputData.signal === undefined
              ? undefined
              : assertSignal(inputData.signal),
          subjectRun: inputData.subjectRun,
        });
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          return Promise.reject(error);
        }
        return Promise.reject(
          new CoordinationClientError(),
        );
      }
      const execute = async () => {
        try {
          if (
            Number(sequence) ===
            Number.MAX_SAFE_INTEGER
          ) {
            invalid();
          }
          const envelope = createCoordinationEnvelope({
            artifactDigest:
              prepared.artifactDigest,
            kind: prepared.kind,
            paymentMoved: false,
            previousEventDigest,
            privateKeyPem: identity.privateKeyPem,
            publicKey: identity.publicKey,
            publicKeyId: identity.keyId,
            releaseId: context.releaseId,
            repositorySha: context.repositorySha,
            role: context.role,
            schema: COORDINATION_ENVELOPE_SCHEMA,
            sequence,
            sessionId: context.sessionId,
            subjectRun: prepared.subjectRun,
          });
          const bytes = canonicalBytes(envelope);
          const response = await exactRequest(
            transport,
            {
              body: bytes,
              method: "POST",
              path: "/v1/events",
              signal: prepared.signal,
            },
          );
          const responseBytes =
            validateInjectedResponse(
              response,
              "application/json",
            );
          if (!responseBytes.equals(bytes)) {
            invalid();
          }
          const echoed = verifyCoordinationEnvelope(
            parseCanonicalJson(responseBytes),
            {
              expectedPublicKey:
                identity.publicKey,
              expectedReleaseId:
                context.releaseId,
              expectedRepositorySha:
                context.repositorySha,
              expectedRole: context.role,
              expectedSessionId:
                context.sessionId,
              expectedSubjectRun:
                prepared.subjectRun,
            },
          );
          previousEventDigest =
            echoed.eventDigest;
          sequence = String(Number(sequence) + 1);
          return echoed;
        } catch (error) {
          if (error instanceof CoordinationClientError) {
            throw error;
          }
          invalid();
        }
      };
      const result = appendQueue.then(execute, execute);
      appendQueue = result.catch(() => {});
      return result;
    }

    async function putArtifact(value) {
      try {
        if (!bootstrapComplete || capability !== null) {
          invalid();
        }
        const keys = keysWithOptionalSignal(
          value,
          PUT_KEYS,
          PUT_KEYS_WITH_SIGNAL,
        );
        const inputData = readExactData(value, keys);
        const signal =
          inputData.signal === undefined
            ? undefined
            : assertSignal(inputData.signal);
        const metadata = await assertArtifactInput(
          inputData.artifactType,
          inputData.bytes,
          inputData.expectedDigest,
        );
        const response = await exactRequest(
          transport,
          {
            artifactType: metadata.artifactType,
            body: Buffer.from(inputData.bytes),
            method: "PUT",
            path: `/v1/artifacts/${metadata.digest}`,
            signal,
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/json",
          );
        const ackData = readExactData(
          parseCanonicalJson(responseBytes),
          ARTIFACT_ACK_KEYS,
        );
        if (
          ackData.artifactType !==
            metadata.artifactType ||
          ackData.byteLength !==
            metadata.byteLength ||
          ackData.digest !== metadata.digest
        ) {
          invalid();
        }
        return Object.freeze({
          artifactType: ackData.artifactType,
          byteLength: ackData.byteLength,
          digest: ackData.digest,
        });
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    async function getArtifact(value) {
      try {
        const keys = keysWithOptionalSignal(
          value,
          GET_KEYS,
          GET_KEYS_WITH_SIGNAL,
        );
        const inputData = readExactData(value, keys);
        const signal =
          inputData.signal === undefined
            ? undefined
            : assertSignal(inputData.signal);
        if (
          typeof inputData.artifactType !== "string" ||
          !LOCALLY_SUPPORTED_ARTIFACT_TYPES.has(
            inputData.artifactType,
          ) ||
          typeof inputData.digest !== "string" ||
          !SHA256_PATTERN.test(inputData.digest)
        ) {
          invalid();
        }
        const response = await exactRequest(
          transport,
          {
            body: null,
            artifactType: inputData.artifactType,
            method: "GET",
            path: `/v1/artifacts/${inputData.digest}`,
            signal,
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/octet-stream",
          );
        await assertArtifactInput(
          inputData.artifactType,
          responseBytes,
          inputData.digest,
        );
        return Buffer.from(responseBytes);
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    async function readEvents(value) {
      try {
        const keys = keysWithOptionalSignal(
          value,
          READ_EVENTS_KEYS,
          READ_EVENTS_KEYS_WITH_SIGNAL,
        );
        const inputData = readExactData(value, keys);
        const signal =
          inputData.signal === undefined
            ? undefined
            : assertSignal(inputData.signal);
        if (
          (inputData.after !== null &&
            (typeof inputData.after !== "string" ||
              !SHA256_PATTERN.test(
                inputData.after,
              ))) ||
          !Number.isSafeInteger(inputData.waitMs) ||
          inputData.waitMs < 0 ||
          inputData.waitMs > 30_000
        ) {
          invalid();
        }
        const after =
          inputData.after === null
            ? ""
            : `after=${inputData.after}&`;
        const response = await exactRequest(
          transport,
          {
            body: null,
            method: "GET",
            path:
              `/v1/sessions/${context.sessionId}/events?` +
              `${after}waitMs=${inputData.waitMs}`,
            signal,
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/json",
          );
        const parsed = parseCanonicalJson(
          responseBytes,
        );
        if (
          !Array.isArray(parsed) ||
          parsed.length > MAX_CLIENT_EVENTS ||
          Reflect.ownKeys(parsed).length !==
            parsed.length + 1
        ) {
          invalid();
        }
        const events = parsed.map((event) =>
          deepFreeze(
            validateAdvisoryEvent(event, context),
          ),
        );
        return Object.freeze(events);
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    async function readEnrollmentSet(value) {
      try {
        if (
          value !== undefined ||
          !bootstrapComplete ||
          capability !== null ||
          authenticatedLaunchState === null
        ) {
          invalid();
        }
        const response = await exactRequest(
          transport,
          {
            body: null,
            method: "GET",
            path:
              `/v1/sessions/${context.sessionId}` +
              "/enrollments",
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/json",
          );
        const set = parseCoordinationEnrollmentSet(
          responseBytes,
        );
        if (
          set.paymentMoved !== false ||
          set.releaseId !== context.releaseId ||
          set.repositorySha !==
            context.repositorySha ||
          set.sessionId !== context.sessionId
        ) {
          invalid();
        }
        for (const role of ["payee", "payer"]) {
          const entry = set.enrollments[role];
          const enrollmentBytes = Buffer.from(
            entry.enrollmentBase64,
            "base64",
          );
          const receiptBytes = Buffer.from(
            entry.receiptBase64,
            "base64",
          );
          const enrollment =
            parseCoordinationEnrollment(
              enrollmentBytes,
            );
          const expected = Object.freeze({
            capabilityDigest:
              enrollment.capabilityDigest,
            enrollmentDigest:
              entry.enrollmentDigest,
            releaseId: context.releaseId,
            repositorySha:
              context.repositorySha,
            role,
            sessionId: context.sessionId,
          });
          let localReceipt;
          let transportReceipt;
          try {
            localReceipt =
              await verifyCoordinationReceipt({
                bytes: Buffer.from(receiptBytes),
                expected,
                verifier: localReceiptVerifier,
              });
            transportReceipt =
              await transport.verifyReceipt(
                Buffer.from(receiptBytes),
                { ...expected },
              );
          } catch {
            invalid();
          }
          const localData = readExactData(
            localReceipt,
            RECEIPT_KEYS,
          );
          const transportData = readExactData(
            transportReceipt,
            RECEIPT_KEYS,
          );
          if (
            !stableBytes(localData).equals(
              stableBytes(transportData),
            ) ||
            localData.schema !==
              COORDINATION_RECEIPT_SCHEMA ||
            localData.paymentMoved !== false ||
            localData.capabilityDigest !==
              enrollment.capabilityDigest ||
            localData.certificateSha256 !==
              expectedTlsFingerprint ||
            localData.enrollmentDigest !==
              entry.enrollmentDigest ||
            localData.releaseId !==
              context.releaseId ||
            localData.repositorySha !==
              context.repositorySha ||
            localData.role !== role ||
            localData.sessionId !==
              context.sessionId
          ) {
            invalid();
          }
        }
        const own =
          set.enrollments[context.role];
        if (
          own.enrollmentBase64 !==
            authenticatedLaunchState.enrollmentBase64 ||
          own.enrollmentDigest !==
            authenticatedLaunchState.enrollmentDigest ||
          own.receiptBase64 !==
            authenticatedLaunchState.receiptBase64
        ) {
          invalid();
        }
        return set;
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    async function readSessionView(value) {
      try {
        const inputData =
          value === undefined
            ? Object.freeze(
                Object.create(null),
              )
            : readExactData(
                value,
                keysWithOptionalSignal(
                  value,
                  READ_VIEW_KEYS,
                  READ_VIEW_KEYS_WITH_SIGNAL,
                ),
              );
        const signal =
          inputData.signal === undefined
            ? undefined
            : assertSignal(inputData.signal);
        const response = await exactRequest(
          transport,
          {
            body: null,
            method: "GET",
            path:
              `/v1/sessions/${context.sessionId}/view`,
            signal,
          },
        );
        const responseBytes =
          validateInjectedResponse(
            response,
            "application/json",
          );
        const data = readExactData(
          parseCanonicalJson(responseBytes),
          VIEW_KEYS,
        );
        if (
          data.releaseId !== context.releaseId ||
          data.repositorySha !==
            context.repositorySha ||
          data.sessionId !== context.sessionId ||
          !RELEASE_STATES.includes(data.state) ||
          data.paymentMoved !== false
        ) {
          invalid();
        }
        const template = initialReleaseView({
          releaseId: context.releaseId,
          repositorySha: context.repositorySha,
          sessionId: context.sessionId,
        });
        return Object.freeze({
          facts: validateFacts(
            data.facts,
            template.facts,
          ),
          paymentMoved: false,
          releaseId: data.releaseId,
          repositorySha: data.repositorySha,
          sessionId: data.sessionId,
          state: data.state,
        });
      } catch (error) {
        if (error instanceof CoordinationClientError) {
          throw error;
        }
        invalid();
      }
    }

    return Object.freeze({
      appendEvent,
      bootstrap,
      getArtifact,
      putArtifact,
      readEnrollmentSet,
      readEvents,
      readSessionView,
    });
  } catch (error) {
    if (error instanceof CoordinationClientError) {
      throw error;
    }
    invalid();
  }
}

export function createCoordinationClient(input) {
  try {
    const data = readExactData(input, CLIENT_KEYS);
    const manifest = validateLaunchManifest(
      data.manifest,
    );
    const identity = validateIdentity(
      data.coordinationIdentity,
    );
    if (
      identity.keyId !==
      `${manifest.role}-coordination`
    ) {
      invalid();
    }
    return createCoordinationClientCore({
      freshManifest: manifest,
      identity,
      initialState: validateSenderState(undefined),
      launchState: manifest,
      transport: validateTransport(data.transport),
    });
  } catch (error) {
    if (error instanceof CoordinationClientError) {
      throw error;
    }
    invalid();
  }
}

export async function createResumedCoordinationClient(
  input,
) {
  try {
    const data = readExactData(
      input,
      RESUMED_CLIENT_KEYS,
    );
    const activeLaunchState =
      await validateActiveLaunchState(
        data.activeLaunchState,
      );
    const identity = validateIdentity(
      data.coordinationIdentity,
    );
    const enrollment = parseCoordinationEnrollment(
      Buffer.from(
        activeLaunchState.enrollmentBase64,
        "base64",
      ),
    );
    if (
      identity.keyId !==
        `${activeLaunchState.role}-coordination` ||
      identity.keyId !==
        enrollment.coordinationKey.keyId ||
      identity.publicKey !==
        enrollment.coordinationKey.publicKey
    ) {
      invalid();
    }
    return createCoordinationClientCore({
      freshManifest: null,
      identity,
      initialState: validateSenderState(
        data.senderState,
      ),
      launchState: activeLaunchState,
      transport: validateTransport(data.transport),
    });
  } catch (error) {
    if (error instanceof CoordinationClientError) {
      throw error;
    }
    invalid();
  }
}
