import { createHash } from "node:crypto";
import {
  constants as fsConstants,
} from "node:fs";
import {
  lstat as nodeLstat,
  open as nodeOpen,
} from "node:fs/promises";
import { dirname } from "node:path";
import { types } from "node:util";

import {
  deadlineMs as proposalDeadline,
  isWithinDeadline,
  liveUpperBoundMs,
} from "./blocktime.mjs";
import { canonicalBytes } from "./canonical.mjs";
import { writePartyResult } from "./evidence.mjs";
import {
  transitionDigest,
} from "./messages.mjs";
import {
  ProtocolFailureError,
  createRunnerStateMachine,
  verifyTransition,
} from "./protocol.mjs";
import { sessionKey } from "./refid.mjs";
import {
  McpNetworkError,
  McpRateLimitedError,
} from "./clockchain.mjs";

export const WRITE_INTENT_MARKER_KEYS = Object.freeze([
  "sessionDigest",
  "slot",
  "digest",
  "referenceId",
]);
export const RUNNER_OUTCOME_KEYS = Object.freeze([
  "deadlineMs",
  "discoveryOnly",
  "markerCreated",
  "source",
  "state",
  "transition",
]);
export const MIN_POLL_INTERVAL_MS = 20_000;

// A failed dispatch is ambiguous: the anchor may or may not have landed.
// Re-dispatch is only safe after discovery confirms the record is absent,
// and the server deduplicates on the exact idempotency key. Bound the
// reconciliation so a transient transport failure cannot kill a run, while
// a persistent one still fails closed well inside the 10-minute expiry.
export const MAX_WRITE_DISPATCH_ATTEMPTS = 3;
export const WRITE_RETRY_BACKOFF_MS = Object.freeze([2_000, 5_000]);
// Role agents poll while the counterparty is still starting; align with the
// 30-minute signed-discovery expiry for staggered human-driven demos.
export const MAX_POLL_DURATION_MS = 30 * 60_000;

const HASH_PATTERN = /^[0-9a-f]{64}$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_PATH_LENGTH = 4096;
const MAX_MARKER_BYTES = 1024;
const DEFAULT_FILE_SYSTEM = Object.freeze({
  lstat: nodeLstat,
  open: nodeOpen,
});
const FILE_SYSTEM_KEYS = new Set(["lstat", "open"]);
const WRITE_INPUT_KEYS = new Set([
  "client",
  "directoryPin",
  "fileSystem",
  "markerPath",
  "message",
  "proposalDeadlineMs",
  "sleeper",
  "stateMachine",
]);
const DIRECTORY_METADATA_KEYS = Object.freeze([
  "dev",
  "ino",
  "mode",
  "nlink",
  "uid",
  "gid",
  "rdev",
]);
const PINNED_IDENTITY_KEYS = Object.freeze([
  "dev",
  "ino",
  "mode",
  "uid",
  "gid",
  "rdev",
]);
const FILE_METADATA_KEYS = Object.freeze([
  ...DIRECTORY_METADATA_KEYS,
  "size",
  "mtimeMs",
  "ctimeMs",
]);
const OUTPUT_DIRECTORY_PIN_STATES = new WeakMap();
const POLL_INPUT_KEYS = new Set([
  "client",
  "jitter",
  "message",
  "monotonicNow",
  "pollDurationMs",
  "proposalDeadlineMs",
  "sleeper",
  "stateMachine",
]);
const CLIENT_METHODS = Object.freeze([
  "getBlock",
  "logAction",
  "resolveAgent",
  "searchActions",
  "verifyCrossParty",
]);
const DEFINITE_PRE_DISPATCH_REFUSAL_CODES = new Set([
  "BILATERAL_WRITE_REFUSED_BEFORE_DISPATCH",
  "FAKE_WRITE_REFUSED",
]);

function terminal(code) {
  return new ProtocolFailureError(
    "Bilateral runner orchestration failed closed.",
    code,
  );
}

function safeInstanceOf(value, constructor) {
  try {
    return value instanceof constructor;
  } catch {
    return false;
  }
}

function safeErrorCode(error) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(
      error,
      "code",
    );
    return descriptor !== undefined &&
      Object.hasOwn(descriptor, "value") &&
      typeof descriptor.value === "string"
      ? descriptor.value
      : null;
  } catch {
    return null;
  }
}

function isDefinitePreDispatchRefusal(error) {
  const code = safeErrorCode(error);
  return code !== null &&
    DEFINITE_PRE_DISPATCH_REFUSAL_CODES.has(code);
}

function isPlainRecord(value) {
  try {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      !types.isProxy(value) &&
      Object.getPrototypeOf(value) === Object.prototype
    );
  } catch {
    return false;
  }
}

function dataProperty(value, key) {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor !== undefined &&
      Object.hasOwn(descriptor, "value")
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function methodProperty(value, key) {
  try {
    if (
      value === null ||
      (
        typeof value !== "object" &&
        typeof value !== "function"
      ) ||
      types.isProxy(value)
    ) {
      return null;
    }
    const method = value[key];
    return typeof method === "function" ? method : null;
  } catch {
    return null;
  }
}

function snapshotAllowedInput(input, allowed, required) {
  if (!isPlainRecord(input)) {
    throw terminal("FAILED");
  }
  let keys;
  try {
    keys = Reflect.ownKeys(input);
  } catch {
    throw terminal("FAILED");
  }
  if (
    keys.some(
      (key) =>
        typeof key !== "string" || !allowed.has(key),
    ) ||
    required.some((key) => !keys.includes(key))
  ) {
    throw terminal("FAILED");
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw terminal("FAILED");
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function exactDataSnapshot(value, keys) {
  if (!isPlainRecord(value)) {
    return null;
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    return null;
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !keys.every((key) => ownKeys.includes(key))
  ) {
    return null;
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value")
    ) {
      return null;
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function activeFileSystem(fileSystem) {
  if (fileSystem === undefined) {
    return DEFAULT_FILE_SYSTEM;
  }
  if (!isPlainRecord(fileSystem)) {
    throw terminal("FAILED");
  }
  const active = { ...DEFAULT_FILE_SYSTEM };
  for (const key of Reflect.ownKeys(fileSystem)) {
    const descriptor = Object.getOwnPropertyDescriptor(
      fileSystem,
      key,
    );
    if (
      typeof key !== "string" ||
      !FILE_SYSTEM_KEYS.has(key) ||
      descriptor === undefined ||
      !Object.hasOwn(descriptor, "value") ||
      typeof descriptor.value !== "function"
    ) {
      throw terminal("FAILED");
    }
    active[key] = descriptor.value;
  }
  return Object.freeze(active);
}

function validateMarker(marker) {
  const snapshot = exactDataSnapshot(
    marker,
    WRITE_INTENT_MARKER_KEYS,
  );
  if (
    snapshot === null ||
    typeof snapshot.sessionDigest !== "string" ||
    !HASH_PATTERN.test(snapshot.sessionDigest) ||
    !["proposal", "acceptance", "acknowledgment"].includes(
      snapshot.slot,
    ) ||
    typeof snapshot.digest !== "string" ||
    !HASH_PATTERN.test(snapshot.digest) ||
    typeof snapshot.referenceId !== "string" ||
    snapshot.referenceId !==
      sessionKey(snapshot.sessionDigest, snapshot.slot)
  ) {
    throw terminal("FAILED");
  }
  return Object.freeze({
    sessionDigest: snapshot.sessionDigest,
    slot: snapshot.slot,
    digest: snapshot.digest,
    referenceId: snapshot.referenceId,
  });
}

function validateMarkerPath(markerPath) {
  if (
    typeof markerPath !== "string" ||
    markerPath.length === 0 ||
    markerPath.length > MAX_PATH_LENGTH ||
    markerPath.includes("\0")
  ) {
    throw terminal("FAILED");
  }
  return markerPath;
}

function metadataSnapshot(stats, keys, kind) {
  if (
    stats === null ||
    typeof stats !== "object" ||
    keys.some((key) => stats[key] === undefined)
  ) {
    throw terminal("FAILED");
  }
  const typeMethod = methodProperty(
    stats,
    kind === "directory" ? "isDirectory" : "isFile",
  );
  if (
    typeMethod === null ||
    typeMethod.call(stats) !== true
  ) {
    throw terminal("FAILED");
  }
  if (
    process.platform !== "win32" &&
    (
      (stats.mode & 0o777) !==
        (kind === "directory" ? 0o700 : 0o600) ||
      (
        typeof process.getuid === "function" &&
        Number.isSafeInteger(stats.uid) &&
        stats.uid !== process.getuid()
      )
    )
  ) {
    throw terminal("FAILED");
  }
  if (
    kind === "file" &&
    (
      !Number.isSafeInteger(stats.size) ||
      stats.size <= 0 ||
      stats.size > MAX_MARKER_BYTES
    )
  ) {
    throw terminal("FAILED");
  }
  return Object.freeze(
    Object.fromEntries(keys.map((key) => [key, stats[key]])),
  );
}

function sameMetadata(left, right, keys) {
  return keys.every((key) => left[key] === right[key]);
}

async function assertPinnedOutputDirectory(pin) {
  const state = OUTPUT_DIRECTORY_PIN_STATES.get(pin);
  if (state === undefined || state.closed) {
    throw terminal("FAILED");
  }
  let pathMetadata;
  let handleMetadata;
  try {
    pathMetadata = metadataSnapshot(
      await state.fileSystem.lstat(state.directory),
      DIRECTORY_METADATA_KEYS,
      "directory",
    );
    handleMetadata = metadataSnapshot(
      await methodProperty(state.handle, "stat").call(
        state.handle,
      ),
      DIRECTORY_METADATA_KEYS,
      "directory",
    );
  } catch (error) {
    throw safeInstanceOf(error, ProtocolFailureError)
      ? error
      : terminal("FAILED");
  }
  if (
    !sameMetadata(
      state.metadata,
      pathMetadata,
      PINNED_IDENTITY_KEYS,
    ) ||
    !sameMetadata(
      pathMetadata,
      handleMetadata,
      PINNED_IDENTITY_KEYS,
    )
  ) {
    throw terminal("FAILED");
  }
}

async function syncPinnedOutputDirectory(pin) {
  const state = OUTPUT_DIRECTORY_PIN_STATES.get(pin);
  if (state === undefined || state.closed) {
    throw terminal("FAILED");
  }
  await assertPinnedOutputDirectory(pin);
  try {
    await methodProperty(state.handle, "sync").call(
      state.handle,
    );
  } catch {
    throw terminal("FAILED");
  }
  await assertPinnedOutputDirectory(pin);
}

export async function pinOutputDirectory(input) {
  const snapshot = snapshotAllowedInput(
    input,
    new Set(["directory", "fileSystem"]),
    ["directory"],
  );
  const directory = validateMarkerPath(snapshot.directory);
  const fileSystem = activeFileSystem(snapshot.fileSystem);
  let before;
  let handle;
  try {
    before = metadataSnapshot(
      await fileSystem.lstat(directory),
      DIRECTORY_METADATA_KEYS,
      "directory",
    );
    handle = await fileSystem.open(
      directory,
      fsConstants.O_RDONLY |
        (fsConstants.O_DIRECTORY ?? 0) |
        (fsConstants.O_NOFOLLOW ?? 0),
    );
    if (
      handle === null ||
      typeof handle !== "object" ||
      methodProperty(handle, "stat") === null ||
      methodProperty(handle, "sync") === null ||
      methodProperty(handle, "close") === null
    ) {
      throw terminal("FAILED");
    }
    const opened = metadataSnapshot(
      await methodProperty(handle, "stat").call(handle),
      DIRECTORY_METADATA_KEYS,
      "directory",
    );
    const after = metadataSnapshot(
      await fileSystem.lstat(directory),
      DIRECTORY_METADATA_KEYS,
      "directory",
    );
    if (
      !sameMetadata(before, opened, PINNED_IDENTITY_KEYS) ||
      !sameMetadata(before, after, PINNED_IDENTITY_KEYS)
    ) {
      throw terminal("FAILED");
    }
  } catch (error) {
    try {
      await handle?.close();
    } catch {
      // The fixed pinning failure remains authoritative.
    }
    throw safeInstanceOf(error, ProtocolFailureError)
      ? error
      : terminal("FAILED");
  }
  const pin = Object.freeze({
    assertCurrent: () => assertPinnedOutputDirectory(pin),
    close: () => closePinnedOutputDirectory(pin),
    directory,
    sync: () => syncPinnedOutputDirectory(pin),
  });
  OUTPUT_DIRECTORY_PIN_STATES.set(pin, {
    closed: false,
    directory,
    fileSystem,
    handle,
    metadata: before,
  });
  return pin;
}

export async function closePinnedOutputDirectory(pin) {
  const state = OUTPUT_DIRECTORY_PIN_STATES.get(pin);
  if (state === undefined) {
    throw terminal("FAILED");
  }
  if (state.closed) {
    return;
  }
  state.closed = true;
  try {
    await closeHandle(state.handle);
  } catch {
    throw terminal("FAILED");
  }
}

function validatedDirectoryPin(pin, markerPath) {
  if (
    !OUTPUT_DIRECTORY_PIN_STATES.has(pin) ||
    dataProperty(pin, "directory") !== dirname(markerPath)
  ) {
    throw terminal("FAILED");
  }
  return pin;
}

async function closeHandle(handle) {
  try {
    const close = methodProperty(handle, "close");
    if (close === null) {
      throw terminal("FAILED");
    }
    await close.call(handle);
  } catch {
    throw terminal("FAILED");
  }
}

export async function createWriteIntentMarker(input) {
  const snapshot = snapshotAllowedInput(
    input,
    new Set([
      "directoryPin",
      "fileSystem",
      "marker",
      "markerPath",
    ]),
    ["marker", "markerPath"],
  );
  const marker = validateMarker(snapshot.marker);
  const markerPath = validateMarkerPath(snapshot.markerPath);
  const fileSystem = activeFileSystem(snapshot.fileSystem);
  let ownedPin;
  const directoryPin =
    snapshot.directoryPin === undefined
      ? (ownedPin = await pinOutputDirectory({
          directory: dirname(markerPath),
          fileSystem,
        }))
      : validatedDirectoryPin(
          snapshot.directoryPin,
          markerPath,
        );
  let primaryFailure;
  try {
    await assertPinnedOutputDirectory(directoryPin);
    let handle;
    try {
      handle = await fileSystem.open(markerPath, "wx", 0o600);
    } catch (error) {
      if (safeErrorCode(error) === "EEXIST") {
        return false;
      }
      throw error;
    }
    let markerFailure;
    try {
      await assertPinnedOutputDirectory(directoryPin);
      if (
        handle === null ||
        typeof handle !== "object" ||
        methodProperty(handle, "writeFile") === null ||
        methodProperty(handle, "sync") === null ||
        methodProperty(handle, "close") === null
      ) {
        throw terminal("FAILED");
      }
      await methodProperty(handle, "writeFile").call(
        handle,
        `${canonicalBytes(marker).toString("utf8")}\n`,
      );
      await methodProperty(handle, "sync").call(handle);
    } catch (error) {
      markerFailure =
        safeInstanceOf(error, ProtocolFailureError)
          ? error
          : terminal("FAILED");
    }
    try {
      await closeHandle(handle);
    } catch (error) {
      markerFailure ??= error;
    }
    if (markerFailure !== undefined) {
      throw markerFailure;
    }
    await assertPinnedOutputDirectory(directoryPin);
    await syncPinnedOutputDirectory(directoryPin);
    return true;
  } catch (error) {
    primaryFailure =
      safeInstanceOf(error, ProtocolFailureError)
        ? error
        : terminal("FAILED");
    throw primaryFailure;
  } finally {
    if (ownedPin !== undefined) {
      try {
        await closePinnedOutputDirectory(ownedPin);
      } catch (error) {
        if (primaryFailure === undefined) {
          throw error;
        }
      }
    }
  }
}

function sameMarker(actual, expected) {
  return WRITE_INTENT_MARKER_KEYS.every(
    (key) => actual[key] === expected[key],
  );
}

async function readMarkerBytes(handle) {
  const bytes = Buffer.alloc(MAX_MARKER_BYTES + 1);
  let offset = 0;
  while (offset < bytes.length) {
    const result = await methodProperty(handle, "read").call(
      handle,
      bytes,
      offset,
      bytes.length - offset,
      offset,
    );
    if (
      result === null ||
      typeof result !== "object" ||
      result.buffer !== bytes ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > bytes.length - offset
    ) {
      throw terminal("FAILED");
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  return bytes.subarray(0, offset);
}

async function inspectMarker(
  fileSystem,
  directoryPin,
  markerPath,
  expected,
) {
  await assertPinnedOutputDirectory(directoryPin);
  let stats;
  try {
    stats = await fileSystem.lstat(markerPath);
  } catch (error) {
    if (safeErrorCode(error) === "ENOENT") {
      await assertPinnedOutputDirectory(directoryPin);
      return false;
    }
    throw terminal("FAILED");
  }
  const before = metadataSnapshot(
    stats,
    FILE_METADATA_KEYS,
    "file",
  );
  await assertPinnedOutputDirectory(directoryPin);

  let handle;
  try {
    handle = await fileSystem.open(
      markerPath,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        (fsConstants.O_NONBLOCK ?? 0),
    );
    await assertPinnedOutputDirectory(directoryPin);
  } catch {
    throw terminal("FAILED");
  }
  let bytes;
  let failure = null;
  try {
    const read = methodProperty(handle, "read");
    if (
      read === null ||
      methodProperty(handle, "stat") === null ||
      methodProperty(handle, "close") === null
    ) {
      throw terminal("FAILED");
    }
    const opened = metadataSnapshot(
      await methodProperty(handle, "stat").call(handle),
      FILE_METADATA_KEYS,
      "file",
    );
    if (
      !sameMetadata(before, opened, FILE_METADATA_KEYS)
    ) {
      throw terminal("FAILED");
    }
    bytes = await readMarkerBytes(handle);
    const after = metadataSnapshot(
      await methodProperty(handle, "stat").call(handle),
      FILE_METADATA_KEYS,
      "file",
    );
    if (
      bytes.length > MAX_MARKER_BYTES ||
      bytes.length !== before.size ||
      !sameMetadata(before, after, FILE_METADATA_KEYS)
    ) {
      throw terminal("FAILED");
    }
  } catch (error) {
    failure = safeInstanceOf(error, ProtocolFailureError)
      ? error
      : terminal("FAILED");
  }
  try {
    await closeHandle(handle);
  } catch (error) {
    failure ??= error;
  }
  if (failure !== null) {
    throw failure;
  }
  await assertPinnedOutputDirectory(directoryPin);
  const text = bytes.toString("utf8");
  if (
    !text.endsWith("\n")
  ) {
    throw terminal("FAILED");
  }
  let parsed;
  try {
    parsed = validateMarker(JSON.parse(text));
    if (
      `${canonicalBytes(parsed).toString("utf8")}\n` !== text
    ) {
      throw terminal("FAILED");
    }
  } catch {
    throw terminal("FAILED");
  }
  if (!sameMarker(parsed, expected)) {
    throw terminal("BINDING_MISMATCH");
  }
  return true;
}

function clientMethods(client) {
  if (!isPlainRecord(client)) {
    throw terminal("FAILED");
  }
  const methods = {};
  for (const name of CLIENT_METHODS) {
    const method = dataProperty(client, name);
    if (typeof method !== "function") {
      throw terminal("FAILED");
    }
    methods[name] = method;
  }
  return methods;
}

function rateLimitBody(value) {
  return (
    isPlainRecord(value) &&
    dataProperty(value, "error") === "rate_limited"
  );
}

function searchRecord(record) {
  if (!isPlainRecord(record)) {
    throw terminal("FAILED");
  }
  const assetHash = dataProperty(record, "assetHash");
  const assetReferenceId = dataProperty(
    record,
    "assetReferenceId",
  );
  const blockHeight = dataProperty(record, "blockHeight");
  const hashType = dataProperty(record, "hashType");
  const ledgerId = dataProperty(record, "ledgerId");
  if (
    typeof assetHash !== "string" ||
    !HASH_PATTERN.test(assetHash) ||
    typeof assetReferenceId !== "string" ||
    assetReferenceId.length === 0 ||
    typeof blockHeight !== "string" ||
    !DECIMAL_PATTERN.test(blockHeight) ||
    hashType !== "SHA-256" ||
    typeof ledgerId !== "string" ||
    !UUID_PATTERN.test(ledgerId)
  ) {
    throw terminal("FAILED");
  }
  return Object.freeze({
    assetHash,
    assetReferenceId,
    blockHeight,
    hashType,
    ledgerId,
  });
}

function classifySearch(result, expected) {
  if (!Array.isArray(result) || types.isProxy(result)) {
    throw terminal(
      rateLimitBody(result) ? "RATE_BLOCKED" : "FAILED",
    );
  }
  const length = dataProperty(result, "length");
  if (!Number.isSafeInteger(length) || length < 0) {
    throw terminal("FAILED");
  }
  if (length === 0) {
    return null;
  }
  if (length > 1) {
    throw terminal("DUPLICATE");
  }
  const descriptor = Object.getOwnPropertyDescriptor(result, "0");
  if (
    descriptor === undefined ||
    !Object.hasOwn(descriptor, "value")
  ) {
    throw terminal("FAILED");
  }
  const record = searchRecord(descriptor.value);
  if (record.assetReferenceId !== expected.referenceId) {
    throw terminal("FAILED");
  }
  if (record.assetHash !== expected.digest) {
    throw terminal("BINDING_MISMATCH");
  }
  return record;
}

async function searchOnce(client, methods, expected) {
  let result;
  try {
    result = await methods.searchActions.call(client, {
      asset_reference_id: expected.referenceId,
    });
  } catch (error) {
    if (safeInstanceOf(error, McpRateLimitedError)) {
      throw terminal("RATE_BLOCKED");
    }
    throw terminal("FAILED");
  }
  return classifySearch(result, expected);
}

function messageAndBinding(message) {
  let detached;
  let digest;
  let referenceId;
  try {
    detached = JSON.parse(canonicalBytes(message).toString("utf8"));
    digest = transitionDigest(detached);
    referenceId = sessionKey(
      detached.sessionDigest,
      detached.kind,
    );
  } catch {
    throw terminal("FAILED");
  }
  return Object.freeze({
    digest,
    message: detached,
    referenceId,
    sessionDigest: detached.sessionDigest,
    slot: detached.kind,
  });
}

function idempotencyKey(sessionDigest, slot) {
  return createHash("sha256")
    .update(`${sessionDigest}|${slot}`, "utf8")
    .digest("hex")
    .slice(0, 32);
}

function exactWriteArgs(binding) {
  return Object.freeze({
    allow_degraded: true,
    asset_hash: binding.digest,
    asset_reference_id: binding.referenceId,
    hash_type: "SHA-256",
    idempotency_key: idempotencyKey(
      binding.sessionDigest,
      binding.slot,
    ),
    version_number: 1,
    wait: true,
    wait_ms: MIN_POLL_INTERVAL_MS,
  });
}

function canonicalDeadline(value) {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0
  ) {
    return value;
  }
  if (
    typeof value === "string" &&
    DECIMAL_PATTERN.test(value)
  ) {
    const numeric = Number(value);
    if (Number.isSafeInteger(numeric)) {
      return numeric;
    }
  }
  throw terminal("FAILED");
}

function advanceState(stateMachine, kind) {
  const target = {
    proposal: "PROPOSED",
    acceptance: "ACCEPTED",
    acknowledgment: "ACKNOWLEDGED",
  }[kind];
  try {
    if (
      kind === "proposal" &&
      stateMachine.state === "UNSTARTED"
    ) {
      stateMachine.advance("RENDEZVOUS_OK");
    }
    stateMachine.advance(target);
  } catch {
    throw terminal("FAILED");
  }
}

function freezeTransition(binding, verified, deadlineValue) {
  const upperBound =
    binding.slot === "proposal"
      ? null
      : liveUpperBoundMs(verified.blockTimeMs);
  if (
    upperBound !== null &&
    !isWithinDeadline(upperBound, deadlineValue)
  ) {
    throw terminal("EXPIRED");
  }
  const onChain = Object.freeze({
    anchoredHash: verified.anchoredHash,
    blockHeight: verified.blockHeight,
    ledgerId: verified.ledgerId,
  });
  return Object.freeze({
    blockTimeMs: String(verified.blockTimeMs),
    blockTimeRaw: verified.blockTimeRaw,
    digest: binding.digest,
    message: Object.freeze(binding.message),
    onChain,
    upperBoundMs:
      upperBound === null ? null : String(upperBound),
  });
}

async function verifiedOutcome({
  binding,
  client,
  deadlineValue,
  markerCreated,
  source,
  stateMachine,
}) {
  const verified = await verifyTransition({
    client,
    expectedDigest: binding.digest,
    message: binding.message,
    referenceId: binding.referenceId,
  });
  const effectiveDeadline =
    binding.slot === "proposal"
      ? proposalDeadline(verified.blockTimeMs)
      : canonicalDeadline(deadlineValue);
  const transition = freezeTransition(
    binding,
    verified,
    effectiveDeadline,
  );
  advanceState(stateMachine, binding.slot);
  return Object.freeze({
    deadlineMs: String(effectiveDeadline),
    discoveryOnly: true,
    markerCreated,
    source,
    state: stateMachine.state,
    transition,
  });
}

function pendingOutcome(stateMachine, deadlineValue) {
  return Object.freeze({
    deadlineMs:
      deadlineValue === undefined
        ? null
        : String(canonicalDeadline(deadlineValue)),
    discoveryOnly: true,
    markerCreated: false,
    source: "pending",
    state: stateMachine.state,
    transition: null,
  });
}

function failStateMachine(stateMachine, error) {
  if (
    safeInstanceOf(error, ProtocolFailureError) &&
    !stateMachine.isTerminal()
  ) {
    try {
      stateMachine.fail(error.terminalCode);
    } catch {
      // Preserve the original fixed terminal result.
    }
  }
  throw error;
}

export async function writeOrAdoptTransition(input) {
  let snapshot;
  let stateMachine;
  let ownedPin;
  let primaryFailure;
  try {
    snapshot = snapshotAllowedInput(
      input,
      WRITE_INPUT_KEYS,
      ["client", "markerPath", "message"],
    );
    stateMachine =
      snapshot.stateMachine ?? createRunnerStateMachine();
    if (
      stateMachine === null ||
      typeof stateMachine !== "object" ||
      typeof dataProperty(stateMachine, "advance") !== "function" ||
      typeof dataProperty(stateMachine, "fail") !== "function" ||
      typeof dataProperty(stateMachine, "isTerminal") !== "function"
    ) {
      throw terminal("FAILED");
    }
    const markerPath = validateMarkerPath(snapshot.markerPath);
    const fileSystem = activeFileSystem(snapshot.fileSystem);
    const directoryPin =
      snapshot.directoryPin === undefined
        ? (ownedPin = await pinOutputDirectory({
            directory: dirname(markerPath),
            fileSystem,
          }))
        : validatedDirectoryPin(
            snapshot.directoryPin,
            markerPath,
          );
    await assertPinnedOutputDirectory(directoryPin);
    const binding = messageAndBinding(snapshot.message);
    const marker = validateMarker({
      sessionDigest: binding.sessionDigest,
      slot: binding.slot,
      digest: binding.digest,
      referenceId: binding.referenceId,
    });
    const methods = clientMethods(snapshot.client);
    const existingMarker = await inspectMarker(
      fileSystem,
      directoryPin,
      markerPath,
      marker,
    );
    const existingRecord = await searchOnce(
      snapshot.client,
      methods,
      binding,
    );
    if (existingRecord !== null) {
      return await verifiedOutcome({
        binding,
        client: snapshot.client,
        deadlineValue: snapshot.proposalDeadlineMs,
        markerCreated: false,
        source: "adopted",
        stateMachine,
      });
    }
    if (existingMarker) {
      return pendingOutcome(
        stateMachine,
        snapshot.proposalDeadlineMs,
      );
    }

    const markerCreated = await createWriteIntentMarker({
      directoryPin,
      fileSystem,
      marker,
      markerPath,
    });
    if (!markerCreated) {
      await assertPinnedOutputDirectory(directoryPin);
      const racedRecord = await searchOnce(
        snapshot.client,
        methods,
        binding,
      );
      if (racedRecord === null) {
        return pendingOutcome(
          stateMachine,
          snapshot.proposalDeadlineMs,
        );
      }
      return await verifiedOutcome({
        binding,
        client: snapshot.client,
        deadlineValue: snapshot.proposalDeadlineMs,
        markerCreated: false,
        source: "adopted",
        stateMachine,
      });
    }

    let written;
    await assertPinnedOutputDirectory(directoryPin);
    const sleeper = snapshot.sleeper ?? defaultSleeper;
    if (typeof sleeper !== "function") {
      throw terminal("FAILED");
    }
    let attempt = 0;
    while (true) {
      attempt += 1;
      try {
        written = await methods.logAction.call(
          snapshot.client,
          exactWriteArgs(binding),
        );
        break;
      } catch (error) {
        if (isDefinitePreDispatchRefusal(error)) {
          throw terminal("FAILED");
        }
        if (attempt >= MAX_WRITE_DISPATCH_ATTEMPTS) {
          throw terminal("AMBIGUOUS_WRITE");
        }
        // Reconcile before re-dispatch: only a confirmed-absent
        // discovery proves the anchor never landed. A discovery error
        // fails closed rather than dispatching blind.
        let discovered;
        try {
          discovered = await searchOnce(
            snapshot.client,
            methods,
            binding,
          );
        } catch {
          throw terminal("AMBIGUOUS_WRITE");
        }
        if (discovered !== null) {
          return await verifiedOutcome({
            binding,
            client: snapshot.client,
            deadlineValue: snapshot.proposalDeadlineMs,
            markerCreated: true,
            source: "adopted",
            stateMachine,
          });
        }
        try {
          await sleeper(
            WRITE_RETRY_BACKOFF_MS[attempt - 1] ??
              WRITE_RETRY_BACKOFF_MS[WRITE_RETRY_BACKOFF_MS.length - 1],
          );
        } catch {
          throw terminal("FAILED");
        }
      }
    }
    if (
      !isPlainRecord(written) ||
      typeof dataProperty(written, "ledgerId") !== "string" ||
      !UUID_PATTERN.test(dataProperty(written, "ledgerId")) ||
      (
        typeof dataProperty(written, "blockHeight") !== "string" &&
        typeof dataProperty(written, "blockHeight") !== "number"
      ) ||
      (
        typeof dataProperty(written, "blockHeight") === "string" &&
        !DECIMAL_PATTERN.test(dataProperty(written, "blockHeight"))
      ) ||
      (
        typeof dataProperty(written, "blockHeight") === "number" &&
        (
          !Number.isSafeInteger(
            dataProperty(written, "blockHeight"),
          ) ||
          dataProperty(written, "blockHeight") < 0
        )
      )
    ) {
      throw terminal("AMBIGUOUS_WRITE");
    }
    return await verifiedOutcome({
      binding,
      client: snapshot.client,
      deadlineValue: snapshot.proposalDeadlineMs,
      markerCreated: true,
      source: "written",
      stateMachine,
    });
  } catch (error) {
    const failure = safeInstanceOf(error, ProtocolFailureError)
      ? error
      : terminal("FAILED");
    primaryFailure = failure;
    if (stateMachine !== undefined) {
      failStateMachine(stateMachine, failure);
    }
    throw failure;
  } finally {
    if (ownedPin !== undefined) {
      try {
        await closePinnedOutputDirectory(ownedPin);
      } catch (error) {
        if (primaryFailure === undefined) {
          throw error;
        }
      }
    }
  }
}

function defaultMonotonicNow() {
  return performance.now();
}

async function defaultSleeper(delayMs) {
  await new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

function defaultJitter() {
  return Math.floor(Math.random() * 1001);
}

function monotonicReading(monotonicNow) {
  let value;
  try {
    value = monotonicNow();
  } catch {
    throw terminal("FAILED");
  }
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value < 0
  ) {
    throw terminal("FAILED");
  }
  return value;
}

function pollDuration(value) {
  if (value === undefined) {
    return MAX_POLL_DURATION_MS;
  }
  if (
    !Number.isSafeInteger(value) ||
    value < MIN_POLL_INTERVAL_MS ||
    value > MAX_POLL_DURATION_MS
  ) {
    throw terminal("FAILED");
  }
  return value;
}

function retryAfter(error) {
  try {
    const value = error.retryAfterMs;
    return Number.isSafeInteger(value) && value >= 0
      ? value
      : 0;
  } catch {
    return 0;
  }
}

async function pollingSearch(client, methods, binding) {
  let result;
  try {
    result = await methods.searchActions.call(client, {
      asset_reference_id: binding.referenceId,
    });
  } catch (error) {
    if (safeInstanceOf(error, McpRateLimitedError)) {
      return {
        kind: "rate",
        retryAfterMs: retryAfter(error),
      };
    }
    if (safeInstanceOf(error, McpNetworkError)) {
      return { kind: "network", retryAfterMs: 0 };
    }
    throw terminal("FAILED");
  }
  if (rateLimitBody(result)) {
    return {
      kind: "rate",
      retryAfterMs: MIN_POLL_INTERVAL_MS,
    };
  }
  const record = classifySearch(result, binding);
  return record === null
    ? { kind: "empty", retryAfterMs: 0 }
    : { kind: "record", record, retryAfterMs: 0 };
}

function terminalForPollObservation(kind) {
  if (kind === "rate") {
    return terminal("RATE_BLOCKED");
  }
  if (kind === "network") {
    return terminal("FAILED");
  }
  return terminal("EXPIRED");
}

export async function pollForTransition(input) {
  let stateMachine;
  try {
    const snapshot = snapshotAllowedInput(
      input,
      POLL_INPUT_KEYS,
      ["client", "message"],
    );
    stateMachine =
      snapshot.stateMachine ?? createRunnerStateMachine();
    if (
      stateMachine === null ||
      typeof stateMachine !== "object" ||
      typeof dataProperty(stateMachine, "advance") !== "function" ||
      typeof dataProperty(stateMachine, "fail") !== "function" ||
      typeof dataProperty(stateMachine, "isTerminal") !== "function"
    ) {
      throw terminal("FAILED");
    }
    const monotonicNow =
      snapshot.monotonicNow ?? defaultMonotonicNow;
    const sleeper = snapshot.sleeper ?? defaultSleeper;
    const jitter = snapshot.jitter ?? defaultJitter;
    if (
      typeof monotonicNow !== "function" ||
      typeof sleeper !== "function" ||
      typeof jitter !== "function"
    ) {
      throw terminal("FAILED");
    }
    const duration = pollDuration(snapshot.pollDurationMs);
    const binding = messageAndBinding(snapshot.message);
    const methods = clientMethods(snapshot.client);
    const startedAt = monotonicReading(monotonicNow);
    let observation = "empty";
    let attempt = 0;

    while (true) {
      const beforeSearch = monotonicReading(monotonicNow);
      const elapsed = beforeSearch - startedAt;
      if (
        !Number.isFinite(elapsed) ||
        elapsed < 0 ||
        elapsed >= duration
      ) {
        throw terminalForPollObservation(observation);
      }

      const discovered = await pollingSearch(
        snapshot.client,
        methods,
        binding,
      );
      observation = discovered.kind;
      if (discovered.kind === "record") {
        return await verifiedOutcome({
          binding,
          client: snapshot.client,
          deadlineValue: snapshot.proposalDeadlineMs,
          markerCreated: false,
          source: "discovered",
          stateMachine,
        });
      }

      const afterSearch = monotonicReading(monotonicNow);
      const remaining = duration - (afterSearch - startedAt);
      if (!Number.isFinite(remaining) || remaining <= 0) {
        throw terminalForPollObservation(observation);
      }
      const baseDelay = Math.max(
        MIN_POLL_INTERVAL_MS,
        discovered.retryAfterMs,
      );
      let jitterMs;
      try {
        jitterMs = jitter({
          attempt,
          baseDelayMs: baseDelay,
          remainingMs: remaining,
        });
      } catch {
        throw terminal("FAILED");
      }
      if (
        !Number.isSafeInteger(jitterMs) ||
        jitterMs < 0 ||
        jitterMs > MIN_POLL_INTERVAL_MS
      ) {
        throw terminal("FAILED");
      }
      const delayMs = Math.min(
        remaining,
        baseDelay + jitterMs,
      );
      try {
        await sleeper(delayMs);
      } catch {
        throw terminal("FAILED");
      }
      const afterSleep = monotonicReading(monotonicNow);
      if (afterSleep <= afterSearch) {
        throw terminal("FAILED");
      }
      attempt += 1;
    }
  } catch (error) {
    const failure = safeInstanceOf(error, ProtocolFailureError)
      ? error
      : terminal("FAILED");
    if (stateMachine !== undefined) {
      failStateMachine(stateMachine, failure);
    }
    throw failure;
  }
}

export async function publishPartyEvidence(options) {
  try {
    return await writePartyResult(options);
  } catch (error) {
    if (safeInstanceOf(error, ProtocolFailureError)) {
      throw error;
    }
    throw terminal("FAILED");
  }
}
