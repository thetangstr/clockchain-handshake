import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes as cryptoRandomBytes,
  sign,
  verify,
} from "node:crypto";
import { execFile } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
} from "node:fs/promises";
import {
  dirname,
  join,
} from "node:path";
import {
  fileURLToPath,
  pathToFileURL,
} from "node:url";
import { promisify } from "node:util";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import {
  operatorPublicKeyPath,
  publicKeyPemFromRawBase64,
  rawPublicKeyBase64FromPem,
} from "../src/bilateral/descriptor.mjs";
import { probeKey } from "../src/bilateral/refid.mjs";
import {
  McpRateLimitedError,
  createMcpClient,
} from "../src/mcp.mjs";
import { assertSecretFree } from "../src/redact.mjs";
import {
  verifyPreflightKeyEnrollment,
  verifyTokenCommitment,
} from "../src/bilateral/coordination/preflight.mjs";
import {
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
} from "../src/bilateral/coordination/enrollment.mjs";
import {
  createReceiptVerifierFromCertificate,
  verifyCoordinationReceipt,
} from "../src/bilateral/coordination/receipt.mjs";

export const PREFLIGHT_REPORT_SCHEMA =
  "clockchain.bilateral-preflight/v2";
export const PREFLIGHT_PLAN_SCHEMA =
  "clockchain.bilateral-preflight-plan/v1";
export const PREFLIGHT_PARTICIPANT_REPORT_SCHEMA =
  "clockchain.bilateral-preflight-participant/v1";
export const PREFLIGHT_POLL_INTERVAL_MS = 20_000;
export const PREFLIGHT_WINDOW_MS = 120_000;
export const PREFLIGHT_REPOSITORY_ROOT = dirname(
  dirname(fileURLToPath(import.meta.url)),
);

const MAX_WINDOW_MS = 480_000;
const MAX_SECRET_BYTES = 8_192;
const MAX_TOKEN_BYTES = 4_096;
const MAX_PUBLIC_BYTES = 1_048_576;
const TOKEN_PATTERN = /^[!-~]{1,4096}$/;
const PROTOCOL =
  "clockchain.bilateral-authorization/v1";
const PROTOCOL_VERSION = "1";
const PLAN_FILE = "probe-plan.json";
const PARTICIPANT_REPORT_FILE =
  "participant-report.json";
const PARTICIPANT_COMPLETION_FILE =
  ".participant-report.complete.json";
const PARTICIPANT_COMPLETION_SCHEMA =
  "clockchain.bilateral-preflight-participant-completion/v1";
const AGGREGATE_REPORT_FILE =
  "preflight-report.json";
const AGGREGATE_COMPLETION_FILE =
  ".preflight-report.complete.json";
const AGGREGATE_COMPLETION_SCHEMA =
  "clockchain.bilateral-preflight-completion/v1";
const HEIGHT_PATTERN = /^(0|[1-9]\d*)$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SIGNATURE_PATTERN =
  /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/;
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat,
  mkdir,
  open,
});
const PREPARATION_SET_BRAND = new WeakSet();
const execFileAsync = promisify(execFile);

export class BilateralPreflightError extends Error {
  constructor() {
    super("Bilateral preflight failed safely.");
    this.name = "BilateralPreflightError";
    this.code = "BILATERAL_PREFLIGHT_FAILED";
  }
}

function fail() {
  throw new BilateralPreflightError();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  if (!isPlainObject(value)) {
    return false;
  }
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every(
      (key) =>
        typeof key === "string" &&
        expected.includes(key) &&
        Object.getOwnPropertyDescriptor(value, key)?.enumerable ===
          true &&
        Object.hasOwn(
          Object.getOwnPropertyDescriptor(value, key),
          "value",
        ),
    )
  );
}

function assertClient(client) {
  if (
    !isPlainObject(client) ||
    typeof client.logAction !== "function" ||
    typeof client.searchActions !== "function" ||
    typeof client.verifyCrossParty !== "function"
  ) {
    fail();
  }
}

function assertScope(scope) {
  if (
    !exactKeys(scope, [
      "separateCredentialsAttested",
      "separateMachinesAttested",
    ]) ||
    typeof scope.separateCredentialsAttested !== "boolean" ||
    typeof scope.separateMachinesAttested !== "boolean"
  ) {
    fail();
  }
}

function bytesFrom(randomBytes, size) {
  let value;
  try {
    value = randomBytes(size);
  } catch {
    fail();
  }
  if (
    !(
      Buffer.isBuffer(value) ||
      value instanceof Uint8Array
    ) ||
    value.byteLength !== size
  ) {
    fail();
  }
  return Buffer.from(value);
}

function canonicalNow(now, previous = null) {
  let value;
  try {
    value = now();
  } catch {
    fail();
  }
  if (
    !Number.isSafeInteger(value) ||
    value < 0 ||
    (previous !== null && value < previous)
  ) {
    fail();
  }
  return value;
}

function canonicalAnchor(value, expected = {}) {
  if (
    !isPlainObject(value) ||
    typeof value.ledgerId !== "string" ||
    !UUID_PATTERN.test(value.ledgerId) ||
    typeof value.blockHeight !== "string" ||
    !HEIGHT_PATTERN.test(value.blockHeight) ||
    (
      expected.digest !== undefined &&
      value.anchoredHash !== expected.digest
    ) ||
    (
      expected.referenceId !== undefined &&
      value.assetReferenceId !== expected.referenceId
    )
  ) {
    return null;
  }
  return {
    anchoredHash: value.anchoredHash,
    assetReferenceId: value.assetReferenceId,
    blockHeight: value.blockHeight,
    ledgerId: value.ledgerId,
  };
}

function searchAnchor(result, expected) {
  if (!Array.isArray(result)) {
    return { code: "MALFORMED_SEARCH", value: null };
  }
  if (result.length === 0) {
    return { code: null, value: null };
  }
  if (result.length !== 1) {
    return { code: "DUPLICATE", value: null };
  }
  const record = result[0];
  if (
    !exactKeys(record, [
      "ledgerId",
      "assetReferenceId",
      "assetHash",
      "blockHeight",
      "hashType",
    ]) ||
    record.hashType !== "SHA-256" ||
    record.assetHash !== expected.digest
  ) {
    return { code: "BINDING_MISMATCH", value: null };
  }
  const value = canonicalAnchor(
    {
      anchoredHash: record.assetHash,
      assetReferenceId: record.assetReferenceId,
      blockHeight: record.blockHeight,
      ledgerId: record.ledgerId,
    },
    expected,
  );
  return {
    code: value === null ? "BINDING_MISMATCH" : null,
    value,
  };
}

function crossPartyAnchor(result, expected) {
  const onChain = result?.onChain;
  if (
    !isPlainObject(onChain) ||
    onChain.keyless !== true ||
    onChain.verifiedAgainst !== "on-chain block"
  ) {
    return null;
  }
  return canonicalAnchor(onChain, expected);
}

function sameAnchor(left, right) {
  return (
    left.ledgerId === right.ledgerId &&
    left.blockHeight === right.blockHeight &&
    left.anchoredHash === right.anchoredHash &&
    left.assetReferenceId === right.assetReferenceId
  );
}

function safeErrorCode(error) {
  if (
    error instanceof McpRateLimitedError &&
    typeof error.code === "string"
  ) {
    return error.code;
  }
  return "PREFLIGHT_READ_FAILED";
}

function rateLimitObservation(error, observer, channel) {
  if (!(error instanceof McpRateLimitedError)) {
    return null;
  }
  return {
    channel,
    code: safeErrorCode(error),
    observer,
    retryAfterMs:
      Number.isSafeInteger(error.retryAfterMs) &&
      error.retryAfterMs >= 0
        ? String(error.retryAfterMs)
        : null,
    wireShape:
      error.code === "MCP_RATE_LIMITED_BODY"
        ? "body-rate_limited"
        : error.code === "MCP_RATE_LIMIT"
          ? "http-429"
          : "typed-rate-limit",
  };
}

function addUnique(target, value) {
  const encoded = JSON.stringify(value);
  if (!target.some((entry) => JSON.stringify(entry) === encoded)) {
    target.push(value);
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== "object") {
    return value;
  }
  for (const entry of Object.values(value)) {
    deepFreeze(entry);
  }
  return Object.freeze(value);
}

async function observeDirection({
  client,
  digest,
  observer,
  peer,
  referenceId,
  state,
  observations,
  rateLimits,
}) {
  let pendingRateLimit = false;
  let largestRetryAfterMs = 0;

  if (!state.referenceResolved) {
    try {
      const result = searchAnchor(
        await client.searchActions({
          asset_reference_id: referenceId,
        }),
        { digest, referenceId },
      );
      if (result.code !== null) {
        addUnique(observations, {
          channel: "derived-reference-id",
          code: result.code,
          observer,
        });
      } else if (result.value !== null) {
        state.reference = result.value;
        state.referenceResolved = true;
      }
    } catch (error) {
      const rateLimit = rateLimitObservation(
        error,
        observer,
        "derived-reference-id",
      );
      if (rateLimit !== null) {
        addUnique(rateLimits, rateLimit);
        pendingRateLimit = true;
        largestRetryAfterMs = Math.max(
          largestRetryAfterMs,
          Number(rateLimit.retryAfterMs ?? "0"),
        );
      } else {
        addUnique(observations, {
          channel: "derived-reference-id",
          code: safeErrorCode(error),
          observer,
        });
      }
    }
  }

  if (!state.digestResolved) {
    try {
      const anchor = crossPartyAnchor(
        await client.verifyCrossParty({ hash: digest }),
        { digest },
      );
      if (anchor !== null) {
        state.digest = anchor;
        state.digestResolved = true;
      }
    } catch (error) {
      const rateLimit = rateLimitObservation(
        error,
        observer,
        "digest-hash",
      );
      if (rateLimit !== null) {
        addUnique(rateLimits, rateLimit);
        pendingRateLimit = true;
        largestRetryAfterMs = Math.max(
          largestRetryAfterMs,
          Number(rateLimit.retryAfterMs ?? "0"),
        );
      } else {
        addUnique(observations, {
          channel: "digest-hash",
          code: safeErrorCode(error),
          observer,
        });
      }
    }
  }

  if (
    state.referenceResolved &&
    state.digestResolved &&
    !sameAnchor(state.reference, state.digest)
  ) {
    state.conflict = true;
    addUnique(observations, {
      channel: "cross-channel",
      code: "BINDING_MISMATCH",
      observer,
    });
  }

  const candidate = state.reference ?? state.digest;
  if (
    candidate !== null &&
    !state.finalVerified &&
    !state.conflict
  ) {
    try {
      const finalAnchor = crossPartyAnchor(
        await client.verifyCrossParty({
          blockHeight: candidate.blockHeight,
          ledgerId: candidate.ledgerId,
        }),
        { digest, referenceId },
      );
      if (
        finalAnchor !== null &&
        sameAnchor(candidate, finalAnchor)
      ) {
        state.finalVerified = true;
        state.final = finalAnchor;
      } else {
        addUnique(observations, {
          channel: "ledger-height",
          code: "BINDING_MISMATCH",
          observer,
        });
      }
    } catch (error) {
      const rateLimit = rateLimitObservation(
        error,
        observer,
        "ledger-height",
      );
      if (rateLimit !== null) {
        addUnique(rateLimits, rateLimit);
        pendingRateLimit = true;
        largestRetryAfterMs = Math.max(
          largestRetryAfterMs,
          Number(rateLimit.retryAfterMs ?? "0"),
        );
      } else {
        addUnique(observations, {
          channel: "ledger-height",
          code: safeErrorCode(error),
          observer,
        });
      }
    }
  }

  return { largestRetryAfterMs, pendingRateLimit };
}

function directionReport(observer, peer, state) {
  const anchor = state.final;
  return {
    digestResolved: state.digestResolved,
    discoveredBlockHeight: anchor?.blockHeight ?? null,
    discoveredLedgerId: anchor?.ledgerId ?? null,
    finalVerified: state.finalVerified,
    observer,
    peer,
    referenceResolved: state.referenceResolved,
  };
}

function reportChannel(directions) {
  if (directions.some(({ finalVerified }) => !finalVerified)) {
    return "unavailable";
  }
  if (
    directions.every(({ referenceResolved }) => referenceResolved)
  ) {
    return "derived-reference-id";
  }
  if (directions.every(({ digestResolved }) => digestResolved)) {
    return "digest-hash";
  }
  return "mixed";
}

function reportTenancy(payerClient, payeeClient, scope) {
  if (payerClient === payeeClient) {
    return "same-client";
  }
  if (
    scope.separateCredentialsAttested &&
    scope.separateMachinesAttested
  ) {
    return "cross-client";
  }
  return "unknown";
}

function validateSignerResult(value) {
  if (
    !exactKeys(value, ["algorithm", "keyId", "value"]) ||
    value.algorithm !== "ed25519" ||
    typeof value.keyId !== "string" ||
    !KEY_ID_PATTERN.test(value.keyId) ||
    typeof value.value !== "string" ||
    !SIGNATURE_PATTERN.test(value.value) ||
    Buffer.from(value.value, "base64").length !== 64
  ) {
    fail();
  }
  return {
    algorithm: value.algorithm,
    keyId: value.keyId,
    value: value.value,
  };
}

export async function runBilateralPreflight(options) {
  if (!isPlainObject(options)) {
    fail();
  }
  const {
    now,
    payerClient,
    payeeClient,
    pollIntervalMs = PREFLIGHT_POLL_INTERVAL_MS,
    randomBytes = cryptoRandomBytes,
    scope,
    signer,
    sleeper,
    windowMs = PREFLIGHT_WINDOW_MS,
  } = options;
  assertClient(payerClient);
  assertClient(payeeClient);
  assertScope(scope);
  if (
    typeof now !== "function" ||
    typeof randomBytes !== "function" ||
    typeof signer !== "function" ||
    typeof sleeper !== "function" ||
    !Number.isSafeInteger(pollIntervalMs) ||
    pollIntervalMs < PREFLIGHT_POLL_INTERVAL_MS ||
    pollIntervalMs > MAX_WINDOW_MS ||
    !Number.isSafeInteger(windowMs) ||
    windowMs < 0 ||
    windowMs > MAX_WINDOW_MS
  ) {
    fail();
  }

  const nonce = bytesFrom(randomBytes, 16).toString("hex");
  const digests = {
    payer: bytesFrom(randomBytes, 32).toString("hex"),
    payee: bytesFrom(randomBytes, 32).toString("hex"),
  };
  const keys = {
    payer: probeKey(nonce, "payer"),
    payee: probeKey(nonce, "payee"),
  };
  const startedAtMs = canonicalNow(now);
  const deadlineAtMs = startedAtMs + windowMs;
  if (!Number.isSafeInteger(deadlineAtMs)) {
    fail();
  }

  const writes = [];
  const observations = [];
  for (const [role, client] of [
    ["payer", payerClient],
    ["payee", payeeClient],
  ]) {
    try {
      const written = await client.logAction({
        allow_degraded: true,
        asset_hash: digests[role],
        asset_reference_id: keys[role],
        hash_type: "SHA-256",
        idempotency_key: digests[role].slice(0, 32),
        version_number: 1,
        wait: true,
        wait_ms: 20000,
      });
      const anchor = canonicalAnchor({
        anchoredHash: digests[role],
        assetReferenceId: keys[role],
        blockHeight: written?.blockHeight,
        ledgerId: written?.ledgerId,
      }, {
        digest: digests[role],
        referenceId: keys[role],
      });
      if (anchor === null) {
        addUnique(observations, {
          channel: "write",
          code: "MALFORMED_WRITE_RESULT",
          observer: role,
        });
      } else {
        writes.push({
          blockHeight: anchor.blockHeight,
          digest: digests[role],
          key: keys[role],
          ledgerId: anchor.ledgerId,
          role,
        });
      }
    } catch {
      addUnique(observations, {
        channel: "write",
        code: "WRITE_FAILED",
        observer: role,
      });
    }
  }

  const states = {
    payer: {
      conflict: false,
      digest: null,
      digestResolved: false,
      final: null,
      finalVerified: false,
      reference: null,
      referenceResolved: false,
    },
    payee: {
      conflict: false,
      digest: null,
      digestResolved: false,
      final: null,
      finalVerified: false,
      reference: null,
      referenceResolved: false,
    },
  };
  const rateLimits = [];
  const sleeps = [];
  let currentTime = canonicalNow(now, startedAtMs);
  const maximumRounds =
    Math.ceil(windowMs / pollIntervalMs) + 1;

  if (writes.length === 2) {
    for (
      let round = 0;
      round < maximumRounds;
      round += 1
    ) {
      const payerObservation = await observeDirection({
        client: payerClient,
        digest: digests.payee,
        observer: "payer",
        observations,
        peer: "payee",
        rateLimits,
        referenceId: keys.payee,
        state: states.payer,
      });
      const payeeObservation = await observeDirection({
        client: payeeClient,
        digest: digests.payer,
        observer: "payee",
        observations,
        peer: "payer",
        rateLimits,
        referenceId: keys.payer,
        state: states.payee,
      });
      const pendingRateLimit =
        payerObservation.pendingRateLimit ||
        payeeObservation.pendingRateLimit;
      if (
        states.payer.finalVerified &&
        states.payee.finalVerified &&
        !pendingRateLimit
      ) {
        break;
      }

      currentTime = canonicalNow(now, currentTime);
      const remainingMs = deadlineAtMs - currentTime;
      if (remainingMs <= 0 || round + 1 >= maximumRounds) {
        break;
      }
      const requestedDelay = Math.max(
        pollIntervalMs,
        payerObservation.largestRetryAfterMs,
        payeeObservation.largestRetryAfterMs,
      );
      const delay = Math.min(requestedDelay, remainingMs);
      try {
        await sleeper(delay);
      } catch {
        fail();
      }
      sleeps.push(String(delay));
      currentTime = canonicalNow(now, currentTime);
    }
  }

  currentTime = canonicalNow(now, currentTime);
  const directions = [
    directionReport("payer", "payee", states.payer),
    directionReport("payee", "payer", states.payee),
  ];
  const outcome = "RENDEZVOUS_UNAVAILABLE";
  const report = {
    channel: reportChannel(directions),
    completedAtMs: String(currentTime),
    deadlineAtMs: String(deadlineAtMs),
    digests,
    directions,
    keys,
    nonce,
    observations,
    outcome,
    paymentMoved: false,
    rateLimits,
    schema: PREFLIGHT_REPORT_SCHEMA,
    scope: {
      distinctClientObjects: payerClient !== payeeClient,
      separateCredentialsAttested:
        scope.separateCredentialsAttested,
      separateMachinesAttested:
        scope.separateMachinesAttested,
    },
    serializedCadenceMs: String(pollIntervalMs),
    sleeps,
    startedAtMs: String(startedAtMs),
    tenancy: reportTenancy(payerClient, payeeClient, scope),
    windowMs: String(windowMs),
    writes,
  };
  const frozenReport = deepFreeze(report);
  const signature = validateSignerResult(
    await signer(canonicalBytes(frozenReport)),
  );
  return deepFreeze({
    report: frozenReport,
    signature,
  });
}

function parseStageArguments(
  arguments_,
  { allowPrepareArtifactsInjection = false } = {},
) {
  if (
    !Array.isArray(arguments_) ||
    !["prepare", "participant", "aggregate"].includes(
      arguments_[0],
    )
  ) {
    fail();
  }
  const stage = arguments_[0];
  const valueFlags = {
    prepare: [
      "--operator-private-key",
      "--operator-key-id",
      "--repository-sha",
      ...(
        allowPrepareArtifactsInjection
          ? []
          : [
              "--payer-preflight-enrollment",
              "--payee-preflight-enrollment",
              "--payer-token-commitment",
              "--payee-token-commitment",
              "--payer-coordination-public-key",
              "--payee-coordination-public-key",
            ]
      ),
      "--output",
    ],
    participant: [
      "--role",
      "--plan",
      "--token-file",
      "--participant-private-key",
      "--output",
    ],
    aggregate: [
      "--plan",
      "--payer-report-dir",
      "--payee-report-dir",
      "--operator-private-key",
      "--output",
    ],
  }[stage];
  const booleanFlags =
    stage === "aggregate"
      ? [
          "--attest-separate-credentials",
          "--attest-separate-machines",
        ]
      : [];
  const values = new Map();
  const flags = new Set();
  for (
    let index = 1;
    index < arguments_.length;
    index += 1
  ) {
    const argument = arguments_[index];
    if (booleanFlags.includes(argument)) {
      if (flags.has(argument)) {
        fail();
      }
      flags.add(argument);
      continue;
    }
    if (
      !valueFlags.includes(argument) ||
      values.has(argument) ||
      index + 1 >= arguments_.length
    ) {
      fail();
    }
    const value = arguments_[index + 1];
    if (
      typeof value !== "string" ||
      value.length === 0 ||
      value.length > 4096 ||
      value.startsWith("--") ||
      value.includes("\0")
    ) {
      fail();
    }
    values.set(argument, value);
    index += 1;
  }
  if (
    values.size !== valueFlags.length ||
    valueFlags.some((flag) => !values.has(flag)) ||
    (
      flags.has("--attest-separate-machines") &&
      !flags.has("--attest-separate-credentials")
    )
  ) {
    fail();
  }
  if (
    stage === "prepare" &&
    (
      !KEY_ID_PATTERN.test(
        values.get("--operator-key-id"),
      ) ||
      !/^[0-9a-f]{40}$/.test(
        values.get("--repository-sha"),
      )
    )
  ) {
    fail();
  }
  if (
    stage === "participant" &&
    !["payer", "payee"].includes(
      values.get("--role"),
    )
  ) {
    fail();
  }
  return {
    flags,
    stage,
    values,
  };
}

function sameMetadata(before, after) {
  return (
    before.isFile() &&
    after.isFile() &&
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.uid === after.uid &&
    before.gid === after.gid &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs
  );
}

async function readMaximumPlusOne(handle, maximum) {
  const buffer = Buffer.alloc(maximum + 1);
  let offset = 0;
  while (offset < buffer.length) {
    let result;
    try {
      result = await handle.read(
        buffer,
        offset,
        buffer.length - offset,
        offset,
      );
    } catch {
      fail();
    }
    if (
      !isPlainObject(result) ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > buffer.length - offset
    ) {
      fail();
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  return buffer.subarray(0, offset);
}

export async function readBoundedFile(
  path,
  {
    fileSystem = DEFAULT_FILE_SYSTEM,
    maximum = MAX_PUBLIC_BYTES,
    secret = false,
  } = {},
) {
  if (
    typeof path !== "string" ||
    path.length === 0 ||
    !Number.isSafeInteger(maximum) ||
    maximum <= 0 ||
    maximum > MAX_PUBLIC_BYTES ||
    typeof secret !== "boolean" ||
    !isPlainObject(fileSystem) ||
    typeof fileSystem.open !== "function"
  ) {
    fail();
  }
  let handle;
  try {
    handle = await fileSystem.open(path, READ_FLAGS);
    const before = await handle.stat();
    if (
      !before.isFile() ||
      before.size <= 0 ||
      before.size > maximum ||
      (
        secret &&
        process.platform !== "win32" &&
        (before.mode & 0o777) !== 0o600
      )
    ) {
      fail();
    }
    const bytes = await readMaximumPlusOne(
      handle,
      maximum,
    );
    const after = await handle.stat();
    if (
      bytes.length > maximum ||
      bytes.length !== before.size ||
      !sameMetadata(before, after)
    ) {
      fail();
    }
    return bytes;
  } catch (error) {
    if (error instanceof BilateralPreflightError) {
      throw error;
    }
    fail();
  } finally {
    try {
      await handle?.close();
    } catch {
      fail();
    }
  }
}

function activeFileSystem(value) {
  const fileSystem = value ?? DEFAULT_FILE_SYSTEM;
  if (
    !isPlainObject(fileSystem) ||
    typeof fileSystem.lstat !== "function" ||
    typeof fileSystem.mkdir !== "function" ||
    typeof fileSystem.open !== "function"
  ) {
    fail();
  }
  return fileSystem;
}

async function ensurePrivateDirectory(path, fileSystem) {
  let metadata;
  try {
    metadata = await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      fail();
    }
    try {
      await fileSystem.mkdir(path, {
        mode: 0o700,
        recursive: false,
      });
      metadata = await fileSystem.lstat(path);
    } catch {
      fail();
    }
  }
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (
      process.platform !== "win32" &&
      (metadata.mode & 0o777) !== 0o700
    )
  ) {
    fail();
  }
  return metadata;
}

function directoryIdentity(metadata) {
  return Object.freeze({
    dev: metadata.dev,
    gid: metadata.gid,
    ino: metadata.ino,
    mode: metadata.mode,
    nlink: metadata.nlink,
    rdev: metadata.rdev,
    uid: metadata.uid,
  });
}

function sameDirectoryIdentity(metadata, identity) {
  return (
    metadata.dev === identity.dev &&
    metadata.ino === identity.ino &&
    metadata.mode === identity.mode &&
    metadata.uid === identity.uid &&
    metadata.gid === identity.gid &&
    metadata.rdev === identity.rdev
  );
}

function validDirectoryMetadata(
  metadata,
  { pathname = false } = {},
) {
  try {
    return (
      metadata.isDirectory() &&
      (
        !pathname ||
        !metadata.isSymbolicLink()
      ) &&
      metadata.nlink > 0 &&
      (
        process.platform === "win32" ||
        (metadata.mode & 0o777) === 0o700
      )
    );
  } catch {
    return false;
  }
}

async function assertDirectoryBinding(
  binding,
  { allowCreatedEntry = false } = {},
) {
  let pathnameMetadata;
  let handleMetadata;
  try {
    [pathnameMetadata, handleMetadata] =
      await Promise.all([
        binding.fileSystem.lstat(binding.path),
        binding.handle.stat(),
      ]);
  } catch {
    fail();
  }
  if (
    !validDirectoryMetadata(pathnameMetadata, {
      pathname: true,
    }) ||
    !validDirectoryMetadata(handleMetadata) ||
    !sameDirectoryIdentity(
      pathnameMetadata,
      binding.identity,
    ) ||
    !sameDirectoryIdentity(
      handleMetadata,
      binding.identity,
    ) ||
    pathnameMetadata.nlink !==
      handleMetadata.nlink ||
    (
      pathnameMetadata.nlink !==
        binding.identity.nlink &&
      !(
        allowCreatedEntry &&
        pathnameMetadata.nlink ===
          binding.identity.nlink + 1
      )
    )
  ) {
    fail();
  }
  if (
    pathnameMetadata.nlink !==
    binding.identity.nlink
  ) {
    // APFS increments a directory's link count for our new entry.
    // Only the single increment bracketed around that create is accepted.
    binding.identity = Object.freeze({
      ...binding.identity,
      nlink: pathnameMetadata.nlink,
    });
  }
}

async function pinPrivateDirectory(path, fileSystem) {
  // Node has no openat-style relative create, so keep this handle pinned
  // and bracket every pathname operation with identity checks.
  const initial = await ensurePrivateDirectory(
    path,
    fileSystem,
  );
  let handle;
  let failure;
  let binding;
  try {
    handle = await fileSystem.open(
      path,
      DIRECTORY_FLAGS,
    );
    const handleMetadata = await handle.stat();
    const pathnameMetadata =
      await fileSystem.lstat(path);
    const identity = directoryIdentity(initial);
    if (
      !validDirectoryMetadata(handleMetadata) ||
      !validDirectoryMetadata(pathnameMetadata, {
        pathname: true,
      }) ||
      !sameDirectoryIdentity(
        handleMetadata,
        identity,
      ) ||
      !sameDirectoryIdentity(
        pathnameMetadata,
        identity,
      ) ||
      handleMetadata.nlink !== identity.nlink ||
      pathnameMetadata.nlink !== identity.nlink
    ) {
      fail();
    }
    binding = {
      fileSystem,
      handle,
      identity,
      path,
    };
    await assertDirectoryBinding(binding);
  } catch (error) {
    failure =
      error instanceof BilateralPreflightError
        ? error
        : new BilateralPreflightError();
  }
  if (failure !== undefined) {
    try {
      await handle?.close();
    } catch {
      failure = new BilateralPreflightError();
    }
    throw failure;
  }
  return binding;
}

async function closeDirectoryBinding(binding) {
  let failure;
  try {
    await assertDirectoryBinding(binding);
  } catch (error) {
    failure = error;
  }
  try {
    await binding.handle.close();
  } catch {
    failure ??= new BilateralPreflightError();
  }
  try {
    const pathnameMetadata =
      await binding.fileSystem.lstat(binding.path);
    if (
      !validDirectoryMetadata(pathnameMetadata, {
        pathname: true,
      }) ||
      !sameDirectoryIdentity(
        pathnameMetadata,
        binding.identity,
      ) ||
      pathnameMetadata.nlink !==
        binding.identity.nlink
    ) {
      failure ??= new BilateralPreflightError();
    }
  } catch {
    failure ??= new BilateralPreflightError();
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function withPinnedPrivateDirectory(
  path,
  fileSystem,
  operation,
) {
  const binding = await pinPrivateDirectory(
    path,
    fileSystem,
  );
  let result;
  let failure;
  try {
    result = await operation(binding);
  } catch (error) {
    failure =
      error instanceof BilateralPreflightError
        ? error
        : new BilateralPreflightError();
  }
  try {
    await closeDirectoryBinding(binding);
  } catch (error) {
    failure ??=
      error instanceof BilateralPreflightError
        ? error
        : new BilateralPreflightError();
  }
  if (failure !== undefined) {
    throw failure;
  }
  return result;
}

async function syncDirectoryBinding(binding) {
  await assertDirectoryBinding(binding);
  try {
    await binding.handle.sync();
  } catch {
    fail();
  }
  await assertDirectoryBinding(binding);
}

async function writeSyncedExclusive(
  binding,
  file,
  bytes,
  mode = 0o600,
) {
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    dirname(file) !== "." ||
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    mode !== 0o600
  ) {
    fail();
  }
  const path = join(binding.path, file);
  let handle;
  let failure;
  try {
    await assertDirectoryBinding(binding);
    handle = await binding.fileSystem.open(
      path,
      "wx",
      mode,
    );
    await assertDirectoryBinding(binding, {
      allowCreatedEntry: true,
    });
    await assertDirectoryBinding(binding);
    await handle.writeFile(bytes);
    await assertDirectoryBinding(binding);
    await assertDirectoryBinding(binding);
    await handle.sync();
    await assertDirectoryBinding(binding);
    await assertDirectoryBinding(binding);
    await handle.close();
    handle = undefined;
    await assertDirectoryBinding(binding);
  } catch (error) {
    failure =
      error instanceof BilateralPreflightError
        ? error
        : new BilateralPreflightError();
  }
  if (handle !== undefined) {
    try {
      await handle.close();
    } catch {
      failure ??= new BilateralPreflightError();
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  await syncDirectoryBinding(binding);
}

function sha256(bytes) {
  return createHash("sha256")
    .update(bytes)
    .digest("hex");
}

function privateEd25519(privateKeyPem) {
  try {
    const key = createPrivateKey(privateKeyPem);
    if (key.asymmetricKeyType !== "ed25519") {
      fail();
    }
    return key;
  } catch (error) {
    if (error instanceof BilateralPreflightError) {
      throw error;
    }
    fail();
  }
}

function rawPublicFromPrivate(privateKey) {
  try {
    return rawPublicKeyBase64FromPem(
      createPublicKey(privateKey).export({
        format: "pem",
        type: "spki",
      }),
    );
  } catch {
    fail();
  }
}

function signatureValue(payload, privateKey, identity) {
  const value = sign(
    null,
    canonicalBytes(payload),
    privateKey,
  ).toString("base64");
  if (!SIGNATURE_PATTERN.test(value)) {
    fail();
  }
  return {
    algorithm: "ed25519",
    [identity.key]: identity.value,
    value,
  };
}

async function defaultRepositoryPublicKeyResolver({
  repositoryPath,
  repositoryRoot,
  repositorySha,
}) {
  try {
    const result = await execFileAsync(
      "git",
      ["show", `${repositorySha}:${repositoryPath}`],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: 4096,
      },
    );
    return result.stdout.trim();
  } catch {
    fail();
  }
}

async function defaultRepositoryStateResolver(
  {
    repositoryRoot,
    repositorySha,
  },
  runGit,
) {
  try {
    const head = await runGit(
      "git",
      ["rev-parse", "HEAD"],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: 128,
      },
    );
    const status = await runGit(
      "git",
      [
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: MAX_PUBLIC_BYTES,
      },
    );
    await runGit(
      "git",
      [
        "cat-file",
        "-e",
        `${repositorySha}^{commit}`,
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        maxBuffer: 128,
      },
    );
    if (
      !isPlainObject(head) ||
      !isPlainObject(status) ||
      typeof head.stdout !== "string" ||
      typeof status.stdout !== "string"
    ) {
      fail();
    }
    return {
      commitSha: repositorySha,
      headSha: head.stdout.trim(),
      worktreeStatus: status.stdout,
    };
  } catch (error) {
    if (error instanceof BilateralPreflightError) {
      throw error;
    }
    fail();
  }
}

async function verifyRepositoryState(
  repositorySha,
  resolver,
) {
  let state;
  try {
    state = await resolver({
      repositoryRoot: PREFLIGHT_REPOSITORY_ROOT,
      repositorySha,
    });
  } catch (error) {
    if (error instanceof BilateralPreflightError) {
      throw error;
    }
    fail();
  }
  if (
    !exactKeys(state, [
      "commitSha",
      "headSha",
      "worktreeStatus",
    ]) ||
    state.commitSha !== repositorySha ||
    state.headSha !== repositorySha ||
    state.worktreeStatus !== ""
  ) {
    fail();
  }
}

async function repositoryPublicKey(
  keyId,
  repositorySha,
  resolver,
) {
  let repositoryPath;
  try {
    repositoryPath = operatorPublicKeyPath(keyId);
  } catch {
    fail();
  }
  let value;
  try {
    value = await resolver({
      repositoryPath,
      repositoryRoot: PREFLIGHT_REPOSITORY_ROOT,
      repositorySha,
    });
  } catch {
    fail();
  }
  if (
    typeof value !== "string" ||
    value.trim().length === 0
  ) {
    fail();
  }
  return value.trim();
}

function validatePlan(plan) {
  if (
    !exactKeys(plan, [
      "digests",
      "keys",
      "nonce",
      "participants",
      "paymentMoved",
      "protocol",
      "protocolVersion",
      "repositorySha",
      "schema",
      "writeBudget",
    ]) ||
    plan.schema !== PREFLIGHT_PLAN_SCHEMA ||
    plan.protocol !== PROTOCOL ||
    plan.protocolVersion !== PROTOCOL_VERSION ||
    plan.paymentMoved !== false ||
    plan.writeBudget !== "2" ||
    !/^[0-9a-f]{40}$/.test(plan.repositorySha) ||
    !/^[0-9a-f]{32}$/.test(plan.nonce) ||
    !exactKeys(plan.digests, ["payee", "payer"]) ||
    !exactKeys(plan.keys, ["payee", "payer"]) ||
    !exactKeys(plan.participants, ["payee", "payer"])
  ) {
    fail();
  }
  for (const role of ["payer", "payee"]) {
    if (
      !/^[0-9a-f]{64}$/.test(plan.digests[role]) ||
      plan.keys[role] !== probeKey(plan.nonce, role) ||
      !exactKeys(
        plan.participants[role],
        [
          "coordinationPublicKey",
          "publicKey",
          "tokenCommitment",
        ],
      ) ||
      typeof
        plan.participants[role]
          .coordinationPublicKey !== "string" ||
      typeof plan.participants[role].publicKey !== "string"
    ) {
      fail();
    }
    try {
      publicKeyPemFromRawBase64(
        plan.participants[role].publicKey,
      );
      publicKeyPemFromRawBase64(
        plan.participants[role]
          .coordinationPublicKey,
      );
      verifyTokenCommitment(
        plan.participants[role].tokenCommitment,
        {
          coordinationPublicKey:
            plan.participants[role]
              .coordinationPublicKey,
          repositorySha: plan.repositorySha,
          role,
        },
      );
    } catch {
      fail();
    }
    if (
      plan.participants[role].publicKey ===
      plan.participants[role]
        .coordinationPublicKey
    ) {
      fail();
    }
  }
  if (
    plan.digests.payer === plan.digests.payee ||
    plan.keys.payer === plan.keys.payee ||
    plan.participants.payer.publicKey ===
      plan.participants.payee.publicKey ||
    plan.participants.payer.coordinationPublicKey ===
      plan.participants.payee.coordinationPublicKey
  ) {
    fail();
  }
}

async function verifyPlanEnvelope(envelope, resolver) {
  if (
    !exactKeys(envelope, ["operator", "plan"]) ||
    !exactKeys(envelope.operator, [
      "algorithm",
      "keyId",
      "publicKey",
      "signature",
    ]) ||
    envelope.operator.algorithm !== "ed25519" ||
    !KEY_ID_PATTERN.test(envelope.operator.keyId) ||
    typeof envelope.operator.publicKey !== "string" ||
    typeof envelope.operator.signature !== "string" ||
    !SIGNATURE_PATTERN.test(envelope.operator.signature)
  ) {
    fail();
  }
  validatePlan(envelope.plan);
  const pinned = await repositoryPublicKey(
    envelope.operator.keyId,
    envelope.plan.repositorySha,
    resolver,
  );
  if (pinned !== envelope.operator.publicKey) {
    fail();
  }
  let verified;
  try {
    verified = verify(
      null,
      canonicalBytes(envelope.plan),
      createPublicKey(
        publicKeyPemFromRawBase64(pinned),
      ),
      Buffer.from(
        envelope.operator.signature,
        "base64",
      ),
    );
  } catch {
    fail();
  }
  if (!verified) {
    fail();
  }
  return {
    envelope,
    planDigest: sha256(canonicalBytes(envelope.plan)),
  };
}

async function readCanonicalJson(path, fileSystem) {
  const bytes = await readBoundedFile(path, {
    fileSystem,
  });
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!canonicalBytes(value).equals(bytes)) {
    fail();
  }
  return value;
}

function verifiedPreparationParticipant(
  value,
  repositorySha,
  role,
) {
  if (
    !exactKeys(value, [
      "coordinationPublicKey",
      "preflightEnrollment",
      "tokenCommitment",
    ]) ||
    typeof value.coordinationPublicKey !== "string"
  ) {
    fail();
  }
  let enrollment;
  let tokenCommitment;
  try {
    enrollment = verifyPreflightKeyEnrollment(
      value.preflightEnrollment,
      { repositorySha, role },
    );
    tokenCommitment = verifyTokenCommitment(
      value.tokenCommitment,
      {
        coordinationPublicKey:
          value.coordinationPublicKey,
        repositorySha,
        role,
      },
    );
    publicKeyPemFromRawBase64(
      value.coordinationPublicKey,
    );
  } catch {
    fail();
  }
  if (
    enrollment.publicKey ===
    value.coordinationPublicKey
  ) {
    fail();
  }
  return {
    coordinationPublicKey:
      value.coordinationPublicKey,
    publicKey: enrollment.publicKey,
    tokenCommitment,
  };
}

export async function verifyCoordinationPreparationSet(input) {
  if (!exactKeys(input, [
    "capabilityDigests",
    "enrollmentSetBytes",
    "releaseId",
    "repositorySha",
    "sessionId",
    "tlsCertificatePem",
    "tokenCommitments",
  ])) {
    fail();
  }
  if (
    !exactKeys(input.capabilityDigests, ["payee", "payer"]) ||
    !exactKeys(input.tokenCommitments, ["payee", "payer"]) ||
    !Buffer.isBuffer(input.enrollmentSetBytes) ||
    typeof input.releaseId !== "string" ||
    typeof input.repositorySha !== "string" ||
    typeof input.sessionId !== "string" ||
    typeof input.tlsCertificatePem !== "string"
  ) {
    fail();
  }
  let enrollmentSet;
  let verifier;
  try {
    enrollmentSet = parseCoordinationEnrollmentSet(
      Buffer.from(input.enrollmentSetBytes),
    );
    verifier = createReceiptVerifierFromCertificate({
      tlsCertificatePem: input.tlsCertificatePem,
    });
  } catch {
    fail();
  }
  if (
    enrollmentSet.paymentMoved !== false ||
    enrollmentSet.releaseId !== input.releaseId ||
    enrollmentSet.repositorySha !== input.repositorySha ||
    enrollmentSet.sessionId !== input.sessionId ||
    input.capabilityDigests.payer ===
      input.capabilityDigests.payee
  ) {
    fail();
  }
  const participants = {};
  for (const role of ["payer", "payee"]) {
    const entry = enrollmentSet.enrollments[role];
    let tokenCommitment;
    try {
      const enrollmentBytes = Buffer.from(
        entry.enrollmentBase64,
        "base64",
      );
      const roleEnrollment =
        parseCoordinationEnrollment(enrollmentBytes);
      if (
        roleEnrollment.capabilityDigest !==
          input.capabilityDigests[role] ||
        roleEnrollment.paymentMoved !== false ||
        roleEnrollment.releaseId !== input.releaseId ||
        roleEnrollment.repositorySha !== input.repositorySha ||
        roleEnrollment.role !== role ||
        roleEnrollment.sessionId !== input.sessionId
      ) {
        fail();
      }
      await verifyCoordinationReceipt({
        bytes: Buffer.from(entry.receiptBase64, "base64"),
        expected: {
          capabilityDigest: input.capabilityDigests[role],
          enrollmentDigest: entry.enrollmentDigest,
          releaseId: input.releaseId,
          repositorySha: input.repositorySha,
          role,
          sessionId: input.sessionId,
        },
        verifier,
      });
      tokenCommitment = verifyTokenCommitment(
        input.tokenCommitments[role],
        {
          coordinationPublicKey:
            roleEnrollment.coordinationKey.publicKey,
          repositorySha: input.repositorySha,
          role,
        },
      );
      participants[role] = {
        coordinationPublicKey:
          roleEnrollment.coordinationKey.publicKey,
        publicKey: roleEnrollment.preflightKey.publicKey,
        tokenCommitment,
      };
    } catch {
      fail();
    }
  }
  const preparation = deepFreeze({
    participants: {
      payee: participants.payee,
      payer: participants.payer,
    },
  });
  PREPARATION_SET_BRAND.add(preparation);
  return preparation;
}

async function preparationParticipants(
  configuration,
  dependencies,
  fileSystem,
  repositorySha,
) {
  let source;
  const injected = dependencies.prepareArtifacts;
  if (injected !== undefined) {
    if (typeof injected !== "function") {
      fail();
    }
    try {
      source = await injected({ repositorySha });
    } catch {
      fail();
    }
  } else {
    source = {
      payee: {
        coordinationPublicKey:
          configuration.values.get(
            "--payee-coordination-public-key",
          ),
        preflightEnrollment:
          await readCanonicalJson(
            configuration.values.get(
              "--payee-preflight-enrollment",
            ),
            fileSystem,
          ),
        tokenCommitment: await readCanonicalJson(
          configuration.values.get(
            "--payee-token-commitment",
          ),
          fileSystem,
        ),
      },
      payer: {
        coordinationPublicKey:
          configuration.values.get(
            "--payer-coordination-public-key",
          ),
        preflightEnrollment:
          await readCanonicalJson(
            configuration.values.get(
              "--payer-preflight-enrollment",
            ),
            fileSystem,
          ),
        tokenCommitment: await readCanonicalJson(
          configuration.values.get(
            "--payer-token-commitment",
          ),
          fileSystem,
        ),
      },
    };
  }
  if (!exactKeys(source, ["payee", "payer"])) {
    if (PREPARATION_SET_BRAND.has(source)) {
      return source.participants;
    }
    fail();
  }
  const participants = {
    payee: verifiedPreparationParticipant(
      source.payee,
      repositorySha,
      "payee",
    ),
    payer: verifiedPreparationParticipant(
      source.payer,
      repositorySha,
      "payer",
    ),
  };
  const publicKeys = [
    participants.payee.coordinationPublicKey,
    participants.payee.publicKey,
    participants.payer.coordinationPublicKey,
    participants.payer.publicKey,
  ];
  if (new Set(publicKeys).size !== publicKeys.length) {
    fail();
  }
  return participants;
}

async function prepareStage(configuration, dependencies) {
  const randomBytes =
    dependencies.randomBytes ?? cryptoRandomBytes;
  const fileSystem = activeFileSystem(
    dependencies.fileSystem,
  );
  const runGit = dependencies.runGit ?? execFileAsync;
  const resolver =
    dependencies.repositoryPublicKeyResolver ??
    defaultRepositoryPublicKeyResolver;
  const stateResolver =
    dependencies.repositoryStateResolver ??
    ((request) =>
      defaultRepositoryStateResolver(request, runGit));
  if (
    typeof randomBytes !== "function" ||
    typeof resolver !== "function" ||
    typeof stateResolver !== "function" ||
    typeof runGit !== "function"
  ) {
    fail();
  }
  const keyId = configuration.values.get(
    "--operator-key-id",
  );
  const repositorySha = configuration.values.get(
    "--repository-sha",
  );
  await verifyRepositoryState(
    repositorySha,
    stateResolver,
  );
  const participants = await preparationParticipants(
    configuration,
    dependencies,
    fileSystem,
    repositorySha,
  );
  const operatorPrivateKeyPem = (
    await readBoundedFile(
      configuration.values.get(
        "--operator-private-key",
      ),
      {
        fileSystem,
        maximum: MAX_SECRET_BYTES,
        secret: true,
      },
    )
  )
    .toString("utf8")
    .trim();
  const operatorPrivateKey = privateEd25519(
    operatorPrivateKeyPem,
  );
  const operatorPublicKey =
    rawPublicFromPrivate(operatorPrivateKey);
  if (
    await repositoryPublicKey(
      keyId,
      repositorySha,
      resolver,
    ) !== operatorPublicKey
  ) {
    fail();
  }
  const nonce = bytesFrom(randomBytes, 16).toString("hex");
  const plan = {
    digests: {
      payee: bytesFrom(randomBytes, 32).toString("hex"),
      payer: bytesFrom(randomBytes, 32).toString("hex"),
    },
    keys: {
      payee: probeKey(nonce, "payee"),
      payer: probeKey(nonce, "payer"),
    },
    nonce,
    participants,
    paymentMoved: false,
    protocol: PROTOCOL,
    protocolVersion: PROTOCOL_VERSION,
    repositorySha,
    schema: PREFLIGHT_PLAN_SCHEMA,
    writeBudget: "2",
  };
  validatePlan(plan);
  const envelope = {
    operator: {
      algorithm: "ed25519",
      keyId,
      publicKey: operatorPublicKey,
      signature: sign(
        null,
        canonicalBytes(plan),
        operatorPrivateKey,
      ).toString("base64"),
    },
    plan,
  };
  const output = configuration.values.get("--output");
  await withPinnedPrivateDirectory(
    output,
    fileSystem,
    async (binding) => {
      await writeSyncedExclusive(
        binding,
        PLAN_FILE,
        canonicalBytes(envelope),
      );
    },
  );
  return deepFreeze(envelope);
}

function participantObservation(peer, state) {
  return {
    conflict: state.conflict,
    digestAnchor: state.digest,
    digestResolved: state.digestResolved,
    finalAnchor: state.final,
    finalVerified: state.finalVerified,
    peer,
    referenceAnchor: state.reference,
    referenceResolved: state.referenceResolved,
  };
}

function participantChannel(observation) {
  if (
    observation.finalVerified &&
    observation.referenceResolved
  ) {
    return "derived-reference-id";
  }
  if (
    observation.finalVerified &&
    observation.digestResolved
  ) {
    return "digest-hash";
  }
  if (
    observation.referenceResolved ||
    observation.digestResolved
  ) {
    return "mixed";
  }
  return "unavailable";
}

async function publishMarkerCompleteEnvelope(
  binding,
  file,
  completionFile,
  completionSchema,
  envelope,
) {
  const bytes = canonicalBytes(envelope);
  await writeSyncedExclusive(
    binding,
    file,
    bytes,
  );
  await writeSyncedExclusive(
    binding,
    completionFile,
    canonicalBytes({
      fileSha256: sha256(bytes),
      schema: completionSchema,
    }),
  );
}

async function participantStage(
  configuration,
  dependencies,
) {
  const fileSystem = activeFileSystem(
    dependencies.fileSystem,
  );
  const runGit = dependencies.runGit ?? execFileAsync;
  const resolver =
    dependencies.repositoryPublicKeyResolver ??
    defaultRepositoryPublicKeyResolver;
  const stateResolver =
    dependencies.repositoryStateResolver ??
    ((request) =>
      defaultRepositoryStateResolver(request, runGit));
  const createClient =
    dependencies.createClient ?? createMcpClient;
  const now = dependencies.now ?? Date.now;
  const sleeper =
    dependencies.sleeper ??
    ((milliseconds) =>
      new Promise((resolve) =>
        setTimeout(resolve, milliseconds)));
  const windowMs =
    dependencies.windowMs ?? PREFLIGHT_WINDOW_MS;
  if (
    typeof resolver !== "function" ||
    typeof stateResolver !== "function" ||
    typeof createClient !== "function" ||
    typeof now !== "function" ||
    typeof sleeper !== "function" ||
    typeof runGit !== "function" ||
    !Number.isSafeInteger(windowMs) ||
    windowMs < 0 ||
    windowMs > MAX_WINDOW_MS
  ) {
    fail();
  }
  const envelope = await readCanonicalJson(
    configuration.values.get("--plan"),
    fileSystem,
  );
  const verifiedPlan = await verifyPlanEnvelope(
    envelope,
    resolver,
  );
  const plan = envelope.plan;
  await verifyRepositoryState(
    plan.repositorySha,
    stateResolver,
  );
  const role = configuration.values.get("--role");
  const peer = role === "payer" ? "payee" : "payer";
  const participantPrivateKeyPem = (
    await readBoundedFile(
      configuration.values.get(
        "--participant-private-key",
      ),
      {
        fileSystem,
        maximum: MAX_SECRET_BYTES,
        secret: true,
      },
    )
  )
    .toString("utf8")
    .trim();
  const participantPrivateKey = privateEd25519(
    participantPrivateKeyPem,
  );
  if (
    rawPublicFromPrivate(participantPrivateKey) !==
    plan.participants[role].publicKey
  ) {
    fail();
  }
  const tokenBytes =
    await readBoundedFile(
      configuration.values.get("--token-file"),
      {
        fileSystem,
        maximum: MAX_TOKEN_BYTES,
        secret: true,
      },
    );
  const token = tokenBytes.toString("utf8");
  if (
    Buffer.byteLength(token, "utf8") !==
      tokenBytes.length ||
    !TOKEN_PATTERN.test(token) ||
    sha256(tokenBytes) !==
      plan.participants[role].tokenCommitment
        .tokenSha256
  ) {
    fail();
  }
  const output = configuration.values.get("--output");
  return withPinnedPrivateDirectory(
    output,
    fileSystem,
    async (binding) => {
  await writeSyncedExclusive(
    binding,
    "write-intent.json",
    canonicalBytes({
      digest: plan.digests[role],
      planDigest: verifiedPlan.planDigest,
      referenceId: plan.keys[role],
      role,
      schema:
        "clockchain.bilateral-preflight-write-intent/v1",
    }),
  );
  await assertDirectoryBinding(binding);
  const client = createClient({ token });
  assertClient(client);
  await assertDirectoryBinding(binding);
  const startedAtMs = canonicalNow(now);
  const deadlineAtMs = startedAtMs + windowMs;
  if (!Number.isSafeInteger(deadlineAtMs)) {
    fail();
  }
  let written;
  try {
    await assertDirectoryBinding(binding);
    written = await client.logAction({
      allow_degraded: true,
      asset_hash: plan.digests[role],
      asset_reference_id: plan.keys[role],
      hash_type: "SHA-256",
      idempotency_key:
        plan.digests[role].slice(0, 32),
      version_number: 1,
      wait: true,
      wait_ms: PREFLIGHT_POLL_INTERVAL_MS,
    });
    await assertDirectoryBinding(binding);
  } catch {
    fail();
  }
  const write = canonicalAnchor(
    {
      anchoredHash: plan.digests[role],
      assetReferenceId: plan.keys[role],
      blockHeight: written?.blockHeight,
      ledgerId: written?.ledgerId,
    },
    {
      digest: plan.digests[role],
      referenceId: plan.keys[role],
    },
  );
  if (write === null) {
    fail();
  }
  const state = {
    conflict: false,
    digest: null,
    digestResolved: false,
    final: null,
    finalVerified: false,
    reference: null,
    referenceResolved: false,
  };
  const observations = [];
  const rateLimits = [];
  const sleeps = [];
  let currentTime = canonicalNow(now, startedAtMs);
  const maximumRounds =
    Math.ceil(
      windowMs / PREFLIGHT_POLL_INTERVAL_MS,
    ) + 1;
  for (
    let round = 0;
    round < maximumRounds;
    round += 1
  ) {
    const observed = await observeDirection({
      client,
      digest: plan.digests[peer],
      observer: role,
      observations,
      peer,
      rateLimits,
      referenceId: plan.keys[peer],
      state,
    });
    if (
      state.finalVerified &&
      !observed.pendingRateLimit
    ) {
      break;
    }
    currentTime = canonicalNow(now, currentTime);
    const remaining = deadlineAtMs - currentTime;
    if (
      remaining <= 0 ||
      round + 1 >= maximumRounds
    ) {
      break;
    }
    const delay = Math.min(
      remaining,
      Math.max(
        PREFLIGHT_POLL_INTERVAL_MS,
        observed.largestRetryAfterMs,
      ),
    );
    try {
      await sleeper(delay);
    } catch {
      fail();
    }
    sleeps.push(String(delay));
    currentTime = canonicalNow(now, currentTime);
  }
  currentTime = canonicalNow(now, currentTime);
  const peerObservation =
    participantObservation(peer, state);
  const report = {
    channel: participantChannel(peerObservation),
    completedAtMs: String(currentTime),
    deadlineAtMs: String(deadlineAtMs),
    observations,
    paymentMoved: false,
    peerObservation,
    planDigest: verifiedPlan.planDigest,
    rateLimits,
    repositorySha: plan.repositorySha,
    role,
    schema: PREFLIGHT_PARTICIPANT_REPORT_SCHEMA,
    serializedCadenceMs: String(
      PREFLIGHT_POLL_INTERVAL_MS,
    ),
    sleeps,
    startedAtMs: String(startedAtMs),
    tokenCommitment:
      plan.participants[role].tokenCommitment,
    write: {
      ...write,
      digest: plan.digests[role],
      key: plan.keys[role],
      role,
    },
  };
  const signed = {
    report,
    signature: signatureValue(
      report,
      participantPrivateKey,
      { key: "role", value: role },
    ),
  };
  try {
    const {
      tokenCommitment,
      ...publicReport
    } = signed.report;
    const {
      tokenSha256,
      ...publicCommitment
    } = tokenCommitment;
    assertSecretFree(
      {
        report: {
          ...publicReport,
          credentialCommitment: {
            ...publicCommitment,
            credentialSha256: tokenSha256,
          },
        },
        signature: signed.signature,
      },
      [
        token,
        participantPrivateKeyPem,
      ],
    );
  } catch {
    fail();
  }
  await publishMarkerCompleteEnvelope(
    binding,
    PARTICIPANT_REPORT_FILE,
    PARTICIPANT_COMPLETION_FILE,
    PARTICIPANT_COMPLETION_SCHEMA,
    signed,
  );
  return deepFreeze(signed);
    },
  );
}

async function loadMarkerCompleteEnvelope(
  directory,
  file,
  completionFile,
  completionSchema,
  fileSystem,
) {
  const completion = await readCanonicalJson(
    join(directory, completionFile),
    fileSystem,
  );
  if (
    !exactKeys(completion, [
      "fileSha256",
      "schema",
    ]) ||
    completion.schema !== completionSchema ||
    !/^[0-9a-f]{64}$/.test(
      completion.fileSha256,
    )
  ) {
    fail();
  }
  const bytes = await readBoundedFile(
    join(directory, file),
    { fileSystem },
  );
  if (sha256(bytes) !== completion.fileSha256) {
    fail();
  }
  let envelope;
  try {
    envelope = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!canonicalBytes(envelope).equals(bytes)) {
    fail();
  }
  return envelope;
}

function validateParticipantReport(
  envelope,
  plan,
  planDigest,
  role,
) {
  if (
    !exactKeys(envelope, ["report", "signature"]) ||
    !exactKeys(envelope.signature, [
      "algorithm",
      "role",
      "value",
    ]) ||
    envelope.signature.algorithm !== "ed25519" ||
    envelope.signature.role !== role ||
    !SIGNATURE_PATTERN.test(
      envelope.signature.value,
    )
  ) {
    fail();
  }
  const report = envelope.report;
  if (
    !exactKeys(report, [
      "channel",
      "completedAtMs",
      "deadlineAtMs",
      "observations",
      "paymentMoved",
      "peerObservation",
      "planDigest",
      "rateLimits",
      "repositorySha",
      "role",
      "schema",
      "serializedCadenceMs",
      "sleeps",
      "startedAtMs",
      "tokenCommitment",
      "write",
    ]) ||
    report.schema !==
      PREFLIGHT_PARTICIPANT_REPORT_SCHEMA ||
    report.role !== role ||
    report.planDigest !== planDigest ||
    report.repositorySha !== plan.repositorySha ||
    report.paymentMoved !== false ||
    !exactKeys(report.write, [
      "anchoredHash",
      "assetReferenceId",
      "blockHeight",
      "digest",
      "key",
      "ledgerId",
      "role",
    ]) ||
    report.write.role !== role ||
    report.write.digest !== plan.digests[role] ||
    report.write.key !== plan.keys[role] ||
    canonicalAnchor(report.write, {
      digest: plan.digests[role],
      referenceId: plan.keys[role],
    }) === null
  ) {
    fail();
  }
  let verifiedCommitment;
  try {
    verifiedCommitment = verifyTokenCommitment(
      report.tokenCommitment,
      {
        coordinationPublicKey:
          plan.participants[role]
            .coordinationPublicKey,
        repositorySha: plan.repositorySha,
        role,
        tokenSha256:
          plan.participants[role].tokenCommitment
            .tokenSha256,
      },
    );
  } catch {
    fail();
  }
  if (
    !canonicalBytes(verifiedCommitment).equals(
      canonicalBytes(
        plan.participants[role].tokenCommitment,
      ),
    )
  ) {
    fail();
  }
  let signatureVerified;
  try {
    signatureVerified = verify(
      null,
      canonicalBytes(report),
      createPublicKey(
        publicKeyPemFromRawBase64(
          plan.participants[role].publicKey,
        ),
      ),
      Buffer.from(
        envelope.signature.value,
        "base64",
      ),
    );
  } catch {
    fail();
  }
  if (!signatureVerified) {
    fail();
  }
  const peer = role === "payer" ? "payee" : "payer";
  const observation = report.peerObservation;
  if (
    !exactKeys(observation, [
      "conflict",
      "digestAnchor",
      "digestResolved",
      "finalAnchor",
      "finalVerified",
      "peer",
      "referenceAnchor",
      "referenceResolved",
    ]) ||
    observation.peer !== peer ||
    typeof observation.conflict !== "boolean" ||
    typeof observation.digestResolved !== "boolean" ||
    typeof observation.finalVerified !== "boolean" ||
    typeof observation.referenceResolved !== "boolean"
  ) {
    fail();
  }
  for (const [resolved, anchor] of [
    [
      observation.digestResolved,
      observation.digestAnchor,
    ],
    [
      observation.referenceResolved,
      observation.referenceAnchor,
    ],
    [
      observation.finalVerified,
      observation.finalAnchor,
    ],
  ]) {
    if (
      resolved !==
      (canonicalAnchor(anchor ?? {}) !== null)
    ) {
      fail();
    }
  }
  return report;
}

function anchorMatchesWrite(anchor, write) {
  return (
    anchor !== null &&
    anchor.ledgerId === write.ledgerId &&
    anchor.blockHeight === write.blockHeight &&
    anchor.anchoredHash === write.anchoredHash &&
    anchor.assetReferenceId ===
      write.assetReferenceId
  );
}

function assertObservationBindsWrite(observation, write) {
  for (const [resolved, anchor] of [
    [observation.digestResolved, observation.digestAnchor],
    [
      observation.referenceResolved,
      observation.referenceAnchor,
    ],
    [observation.finalVerified, observation.finalAnchor],
  ]) {
    if (resolved && !anchorMatchesWrite(anchor, write)) {
      fail();
    }
  }
}

async function aggregateStage(
  configuration,
  dependencies,
) {
  const fileSystem = activeFileSystem(
    dependencies.fileSystem,
  );
  const runGit = dependencies.runGit ?? execFileAsync;
  const resolver =
    dependencies.repositoryPublicKeyResolver ??
    defaultRepositoryPublicKeyResolver;
  const stateResolver =
    dependencies.repositoryStateResolver ??
    ((request) =>
      defaultRepositoryStateResolver(request, runGit));
  const now = dependencies.now ?? Date.now;
  if (
    typeof resolver !== "function" ||
    typeof stateResolver !== "function" ||
    typeof runGit !== "function" ||
    typeof now !== "function"
  ) {
    fail();
  }
  const planEnvelope = await readCanonicalJson(
    configuration.values.get("--plan"),
    fileSystem,
  );
  const verifiedPlan = await verifyPlanEnvelope(
    planEnvelope,
    resolver,
  );
  const plan = planEnvelope.plan;
  await verifyRepositoryState(
    plan.repositorySha,
    stateResolver,
  );
  const operatorPrivateKeyPem = (
    await readBoundedFile(
      configuration.values.get(
        "--operator-private-key",
      ),
      {
        fileSystem,
        maximum: MAX_SECRET_BYTES,
        secret: true,
      },
    )
  )
    .toString("utf8")
    .trim();
  const operatorPrivateKey = privateEd25519(
    operatorPrivateKeyPem,
  );
  if (
    rawPublicFromPrivate(operatorPrivateKey) !==
    planEnvelope.operator.publicKey
  ) {
    fail();
  }
  const payerEnvelope =
    await loadMarkerCompleteEnvelope(
      configuration.values.get(
        "--payer-report-dir",
      ),
      PARTICIPANT_REPORT_FILE,
      PARTICIPANT_COMPLETION_FILE,
      PARTICIPANT_COMPLETION_SCHEMA,
      fileSystem,
    );
  const payeeEnvelope =
    await loadMarkerCompleteEnvelope(
      configuration.values.get(
        "--payee-report-dir",
      ),
      PARTICIPANT_REPORT_FILE,
      PARTICIPANT_COMPLETION_FILE,
      PARTICIPANT_COMPLETION_SCHEMA,
      fileSystem,
    );
  const payer = validateParticipantReport(
    payerEnvelope,
    plan,
    verifiedPlan.planDigest,
    "payer",
  );
  const payee = validateParticipantReport(
    payeeEnvelope,
    plan,
    verifiedPlan.planDigest,
    "payee",
  );
  if (
    (
      payer.write.ledgerId === payee.write.ledgerId &&
      payer.write.blockHeight === payee.write.blockHeight
    ) ||
    payer.write.digest === payee.write.digest ||
    payer.write.key === payee.write.key
  ) {
    fail();
  }
  assertObservationBindsWrite(
    payer.peerObservation,
    payee.write,
  );
  assertObservationBindsWrite(
    payee.peerObservation,
    payer.write,
  );
  const payerBindsPayee =
    anchorMatchesWrite(
      payer.peerObservation.referenceAnchor,
      payee.write,
    ) &&
    anchorMatchesWrite(
      payer.peerObservation.finalAnchor,
      payee.write,
    );
  const payeeBindsPayer =
    anchorMatchesWrite(
      payee.peerObservation.referenceAnchor,
      payer.write,
    ) &&
    anchorMatchesWrite(
      payee.peerObservation.finalAnchor,
      payer.write,
    );
  const digestBoth =
    payer.peerObservation.digestResolved &&
    payee.peerObservation.digestResolved &&
    payer.peerObservation.finalVerified &&
    payee.peerObservation.finalVerified;
  const referenceBoth =
    payer.peerObservation.referenceResolved &&
    payee.peerObservation.referenceResolved &&
    payer.peerObservation.finalVerified &&
    payee.peerObservation.finalVerified;
  const channel = referenceBoth
    ? "derived-reference-id"
    : digestBoth
      ? "digest-hash"
      : (
          payer.peerObservation.referenceResolved ||
          payee.peerObservation.referenceResolved ||
          payer.peerObservation.digestResolved ||
          payee.peerObservation.digestResolved
        )
        ? "mixed"
        : "unavailable";
  const separateCredentialsAttested =
    configuration.flags.has(
      "--attest-separate-credentials",
    );
  const separateMachinesAttested =
    configuration.flags.has(
      "--attest-separate-machines",
    );
  const success =
    separateCredentialsAttested &&
    separateMachinesAttested &&
    referenceBoth &&
    payerBindsPayee &&
    payeeBindsPayer &&
    !payer.peerObservation.conflict &&
    !payee.peerObservation.conflict;
  const report = {
    channel,
    completedAtMs: String(canonicalNow(now)),
    directions: [
      {
        observer: "payer",
        peer: "payee",
        ...payer.peerObservation,
      },
      {
        observer: "payee",
        peer: "payer",
        ...payee.peerObservation,
      },
    ],
    outcome: success
      ? "RENDEZVOUS_OK"
      : "RENDEZVOUS_UNAVAILABLE",
    paymentMoved: false,
    planDigest: verifiedPlan.planDigest,
    protocol: plan.protocol,
    protocolVersion: plan.protocolVersion,
    repositorySha: plan.repositorySha,
    schema: PREFLIGHT_REPORT_SCHEMA,
    scope: {
      separateCredentialsAttested,
      separateMachinesAttested,
    },
    tenancy:
      separateCredentialsAttested &&
      separateMachinesAttested
        ? "cross-client"
        : "unknown",
    writes: [payer.write, payee.write],
  };
  const signed = {
    report,
    signature: signatureValue(
      report,
      operatorPrivateKey,
      {
        key: "keyId",
        value: planEnvelope.operator.keyId,
      },
    ),
  };
  try {
    assertSecretFree(signed, [
      operatorPrivateKeyPem,
    ]);
  } catch {
    fail();
  }
  const output = configuration.values.get("--output");
  return withPinnedPrivateDirectory(
    output,
    fileSystem,
    async (binding) => {
      await publishMarkerCompleteEnvelope(
        binding,
        AGGREGATE_REPORT_FILE,
        AGGREGATE_COMPLETION_FILE,
        AGGREGATE_COMPLETION_SCHEMA,
        signed,
      );
      return deepFreeze(signed);
    },
  );
}

export async function main(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  if (!isPlainObject(dependencies)) {
    fail();
  }
  const configuration = parseStageArguments(arguments_, {
    allowPrepareArtifactsInjection:
      typeof dependencies.prepareArtifacts ===
      "function",
  });
  if (configuration.stage === "prepare") {
    return prepareStage(configuration, dependencies);
  }
  if (configuration.stage === "participant") {
    return participantStage(configuration, dependencies);
  }
  return aggregateStage(configuration, dependencies);
}

export async function runCli(
  arguments_ = process.argv.slice(2),
  dependencies = {},
) {
  const {
    output = (line) => process.stdout.write(line),
    writeError = (line) => process.stderr.write(line),
  } = dependencies;
  try {
    const envelope = await main(arguments_, dependencies);
    output(`${JSON.stringify(envelope)}\n`);
    if (arguments_[0] !== "aggregate") {
      return 0;
    }
    return envelope.report.outcome === "RENDEZVOUS_OK"
      ? 0
      : 2;
  } catch {
    writeError("Bilateral preflight failed safely.\n");
    return 1;
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = await runCli();
}
