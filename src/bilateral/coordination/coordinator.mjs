import {
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { join } from "node:path";
import {
  constants as fsConstants,
  lstat,
  open,
  readdir,
  rename,
  unlink,
} from "node:fs/promises";

import { canonicalizeReceiptEventValue } from "../../canonical.mjs";
import { canonicalBytes } from "../canonical.mjs";

import {
  createLaunchManifest,
  validateLaunchManifest,
  writeLaunchManifest as writePrivateLaunchManifest,
} from "./manifest.mjs";
import {
  parseCoordinationEnrollment,
  parseCoordinationEnrollmentSet,
} from "./enrollment.mjs";
import {
  verifyCoordinationEnvelope,
} from "./envelope.mjs";
import {
  initialReleaseView,
  reduceReleaseEvent,
  RUN_MODES,
} from "./lifecycle.mjs";

export const COORDINATOR_STATE_SCHEMA =
  "clockchain.bilateral-coordinator-state/v1";

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const RELEASE_INPUT_KEYS = Object.freeze([
  "operatorKeyId",
  "relayUrl",
  "releaseRoot",
  "repositorySha",
  "tlsCertificatePem",
  "tlsFingerprint",
]);
const RELEASE_INPUT_KEYS_WITH_DEPENDENCIES = Object.freeze([
  "dependencies",
  ...RELEASE_INPUT_KEYS,
]);
const RELEASE_DEPENDENCY_KEYS = Object.freeze([
  "createLaunchManifest",
  "fileSystem",
  "now",
  "prepareCapabilityRegistration",
  "randomBytes",
  "randomUUID",
  "registerCapabilitySet",
  "writeLaunchManifest",
  "writeState",
]);
const STATE_FILE_NAME = "coordinator-state.json";
const CAPABILITY_PENDING_FILE_NAME = "capability-registration.pending.json";
const CAPABILITY_PENDING_SCHEMA =
  "clockchain.bilateral-capability-registration-pending/v1";
const MAX_STATE_BYTES = 64 * 1024;
const MAX_PENDING_BYTES = 512 * 1024;
const VERIFIER_RESULT_KEYS = Object.freeze([
  "exitCode",
  "publicationDigest",
  "status",
  "stderr",
  "stdout",
]);
const VERIFIER_PUBLICATION_KEYS = Object.freeze([
  "paymentMoved", "publicationDigest", "releaseId", "repositorySha",
  "schema", "sessionId", "status", "subjectRun",
]);
const VERIFIER_PUBLICATION_SCHEMA =
  "clockchain.bilateral-verifier-publication/v1";
const CAPABILITY_SET_RECEIPT_KEYS = Object.freeze([
  "capabilities", "paymentMoved", "registrationDigest",
  "releaseId", "repositorySha", "requestDigest", "schema", "sessionId",
]);
const CAPABILITY_SET_RECEIPT_SCHEMA =
  "clockchain.bilateral-capability-registration-receipt/v1";
const CAPABILITY_PENDING_KEYS = Object.freeze([
  "context", "entries", "receipt", "registration", "schema",
]);
const CAPABILITY_PENDING_CONTEXT_KEYS = Object.freeze([
  "operatorKeyId", "relayUrl", "repositorySha", "tlsCertificatePem",
  "tlsFingerprint",
]);
const CAPABILITY_PENDING_ENTRY_KEYS = Object.freeze([
  "capabilityDigest", "manifest", "role",
]);
const RUN_INPUT_KEYS = Object.freeze([
  "dependencies",
  "release",
  "releaseRoot",
]);
const RUN_INPUT_WITH_MODE_KEYS = Object.freeze([
  "dependencies",
  "release",
  "releaseRoot",
  "runMode",
]);
const RUN_DEPENDENCY_KEYS = Object.freeze([
  "appendOperatorEvent", "createTransport", "displayAddresses", "launcher",
  "now", "putArtifact", "readEnrollmentSet", "readEvents", "readSessionView",
  "readState", "sleeper", "verifyMarkerCompleteVerdict", "waitForFunding", "writeState",
]);
const REPLAY_DEPENDENCY_KEYS = Object.freeze([
  "readVerifierPublication",
  "resolveOperatorPublicKey",
]);
const PREFLIGHT_DEPENDENCY_KEYS = Object.freeze([
  "createPreflightPlan",
  "getArtifact",
  "runAggregatePreflight",
  "validateArtifact",
  "waitForPreflightParticipant",
]);
const REHEARSAL_IDENTITY_DEPENDENCY_KEYS = Object.freeze([
  "getArtifact",
  "waitForIdentityPackage",
]);
const RUN_ORCHESTRATION_DEPENDENCY_KEYS = Object.freeze([
  "appendVerifiedEvent", "createDescriptor", "createVerifiedEvent", "launchVerifier", "startRole",
  "startWatcher", "validatePublishedBilateralVerdict", "waitForDescriptorAcceptance",
  "validateRehearsalPackage", "waitForRolePackage", "waitForRoleStarted",
]);
const RUN_OPTIONAL_DEPENDENCY_KEYS = Object.freeze(["drainWatchers", "prepareVerifierHandoff", "writeConsoleState"]);
const SUCCESS_STATUS = "VERIFICATION_PASSED";
const FUNDING_RECORD_KEYS = Object.freeze([
  "address",
  "balanceWei",
  "nonce",
  "paymentMoved",
]);
const COORDINATOR_STATE_KEYS = Object.freeze([
  "capabilityDigests",
  "checkpoints",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "state",
]);
const CHECKPOINT_KEYS = Object.freeze([
  "action", "artifactDigest", "eventDigest", "role", "status", "subjectRun",
]);
const CHECKPOINT_ACTIONS = new Set([
  "ENROLLMENT_RECEIPT", "WAIT_FOR_FUNDING",
  "PREFLIGHT_PLAN", "PREFLIGHT_PARTICIPANT", "PREFLIGHT_AGGREGATE", "REGISTER_REHEARSAL", "REGISTER_STAKEHOLDER", "IDENTITY_PACKAGE",
  "REHEARSAL_DESCRIPTOR", "STAKEHOLDER_DESCRIPTOR", "START_REHEARSAL", "START_STAKEHOLDER",
  "PAYEE_ROLE_START", "PAYER_ROLE_START", "ROLE_STARTED", "ROLE_PACKAGE",
  "REHEARSAL_VERDICT", "STAKEHOLDER_VERDICT", "COMPLETE_RELEASE",
]);
const CHECKPOINT_STATUSES = new Set([
  "BEFORE_CHILD", "CHILD_COMPLETE", "ARTIFACT_STORED", "VERDICT_VALIDATED", "EVENT_APPENDED",
]);
const COORDINATOR_STATES = new Set([
  "BOOTSTRAPPING", "ADDRESSES_READY", "FUNDING_READY", "PREFLIGHT_PASSED",
  "REHEARSAL_IDENTITIES_READY", "REHEARSAL_DESCRIPTOR_READY", "REHEARSAL_PACKAGES_READY", "REHEARSAL_VERIFIED",
  "STAKEHOLDER_IDENTITIES_READY", "STAKEHOLDER_DESCRIPTOR_READY", "STAKEHOLDER_PACKAGES_READY", "STAKEHOLDER_VERIFIED", "COMPLETE",
]);
// Stakeholder demos start the operator and the remote participant minutes apart;
// align with the 30-minute signed-discovery expiry.
const FUNDING_READINESS_DEADLINE_MS = 30 * 60_000;
const FUNDING_READINESS_INTERVAL_MS = 20_000;
const INTENT_READINESS_DEADLINE_MS = 90_000;
const INTENT_READINESS_INTERVAL_MS = 100;
const INTENT_READINESS_MAX_ATTEMPTS = 900;
const ADVISORY_SESSION_NOT_FOUND_CODE = "COORDINATION_SESSION_NOT_FOUND";
const AUTHENTICATED_EVENT_KEYS = Object.freeze([
  "artifactDigest", "eventDigest", "kind", "paymentMoved", "previousEventDigest",
  "releaseId", "repositorySha", "role", "schema", "sequence", "sessionId",
  "signature", "subjectRun",
]);
const REQUIRED_INTENTS = Object.freeze([
  Object.freeze({ kind: "PAYER_MANDATE_READY", role: "payer", artifact: "sha256" }),
  Object.freeze({ kind: "PAYMENT_REQUEST_READY", role: "payee", artifact: "sha256" }),
  Object.freeze({ kind: "PAYMENT_REQUEST_MATCHED", role: "payer", artifact: "null" }),
]);

export class CoordinationCoordinatorError extends Error {
  constructor() {
    super("Coordinator operation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = "COORDINATION_COORDINATOR_INVALID";
  }
}

function invalid() {
  throw new CoordinationCoordinatorError();
}

function normalizeRunMode(value) {
  if (value === undefined) return "local-two-run";
  if (!RUN_MODES.includes(value)) invalid();
  return value;
}

export function validateCoordinatorIntentReadiness(events, subjectRun) {
  if (!Array.isArray(events) || !["rehearsal", "stakeholder"].includes(subjectRun)) invalid();
  const bound = REQUIRED_INTENTS.map(({ artifact, kind, role }) => {
    const matches = events
      .map((event, index) => ({ event, index }))
      .filter(({ event }) => event?.kind === kind && event?.subjectRun === subjectRun);
    if (
      matches.length > 1 ||
      matches.some(({ event }) => event.role !== role) ||
      matches.some(({ event }) => artifact === "sha256"
        ? !SHA256_PATTERN.test(event.artifactDigest)
        : event.artifactDigest !== null)
    ) invalid();
    return matches;
  });
  if (!bound.every((matches) => matches.length === 1)) return false;
  if (!(bound[0][0].index < bound[1][0].index && bound[1][0].index < bound[2][0].index)) invalid();
  return true;
}

export async function waitForVerifiedCoordinatorIntentReadiness({
  now,
  readEvents,
  sleeper,
  subjectRun,
}) {
  if (
    typeof now !== "function" ||
    typeof readEvents !== "function" ||
    typeof sleeper !== "function" ||
    !["rehearsal", "stakeholder"].includes(subjectRun)
  ) invalid();
  let intentNow = now();
  if (!Number.isSafeInteger(intentNow) || intentNow < 0 || intentNow > Number.MAX_SAFE_INTEGER - INTENT_READINESS_DEADLINE_MS) invalid();
  const deadline = intentNow + INTENT_READINESS_DEADLINE_MS;
  for (let attempt = 0; attempt < INTENT_READINESS_MAX_ATTEMPTS; attempt += 1) {
    if (validateCoordinatorIntentReadiness(await readEvents(), subjectRun)) return;
    const nextNow = now();
    if (!Number.isSafeInteger(nextNow) || nextNow < intentNow || nextNow > Number.MAX_SAFE_INTEGER) invalid();
    intentNow = nextNow;
    if (intentNow >= deadline || attempt === INTENT_READINESS_MAX_ATTEMPTS - 1) invalid();
    await sleeper(INTENT_READINESS_INTERVAL_MS);
  }
  invalid();
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exact(value, keys) {
  if (!isPlainObject(value)) invalid();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string" || !keys.includes(key))
  ) invalid();
  const output = Object.create(null);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function exactSubset(value, keys) {
  if (!isPlainObject(value)) invalid();
  const output = Object.create(null);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !keys.includes(key)) invalid();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value")) invalid();
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function checkpoints(value) {
  if (!Array.isArray(value) || Reflect.ownKeys(value).length !== value.length + 1) invalid();
  const seen = new Set();
  const previous = new Map();
  const output = value.map((entry) => {
    const data = exact(entry, CHECKPOINT_KEYS);
    if (!CHECKPOINT_ACTIONS.has(data.action) || !CHECKPOINT_STATUSES.has(data.status) || !["operator", "payer", "payee"].includes(data.role) || !["release", "rehearsal", "stakeholder"].includes(data.subjectRun) || !(data.artifactDigest === null || (typeof data.artifactDigest === "string" && SHA256_PATTERN.test(data.artifactDigest))) || !(data.eventDigest === null || (typeof data.eventDigest === "string" && SHA256_PATTERN.test(data.eventDigest)))) invalid();
    const order = [...CHECKPOINT_STATUSES].indexOf(data.status);
    const key = `${data.action}:${data.role}:${data.subjectRun}`;
    if (order < (previous.get(key) ?? -1) || seen.has(`${key}:${data.status}`)) invalid();
    seen.add(`${key}:${data.status}`); previous.set(key, order);
    return data;
  });
  return Object.freeze(output);
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function writePublicState({ releaseRoot, state }) {
  const { fileSystem = defaultFileSystem, random = randomBytes } = arguments[0];
  let bytes;
  try {
    bytes = Buffer.from(
      `${JSON.stringify(canonicalizeReceiptEventValue(state))}\n`,
      "utf8",
    );
  } catch {
    invalid();
  }
  if (
    typeof releaseRoot !== "string" ||
    releaseRoot.length === 0 ||
    releaseRoot.includes("\0") ||
    bytes.length === 0 ||
    bytes.length > MAX_STATE_BYTES
  ) invalid();
  const fs = readStateFileSystem(fileSystem);
  let root;
  try {
    root = await pinPrivateRoot(releaseRoot, fs);
  } catch (error) {
    if (error instanceof CoordinationCoordinatorError) throw error;
    invalid();
  }
  const path = join(releaseRoot, STATE_FILE_NAME);
  let temporary;
  let handle;
  let failure;
  try {
    const exists = await existingPrivateState(path, fs);
    if ((state.state === "BOOTSTRAPPING") === exists) invalid();
    const nonce = random(16);
    if (!Buffer.isBuffer(nonce) || nonce.length !== 16) invalid();
    temporary = join(releaseRoot, `.${STATE_FILE_NAME}.${nonce.toString("hex")}.tmp`);
    handle = await fs.open(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const created = await handle.stat();
    if (!validPrivateStateFile(created, 0)) invalid();
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(bytesWritten) || bytesWritten <= 0) invalid();
      offset += bytesWritten;
    }
    await handle.sync();
    await handle.close();
    handle = undefined;
    await assertPinnedRoot(root, fs);
    await fs.rename(temporary, path);
    temporary = undefined;
    await root.handle.sync();
    await assertPinnedRoot(root, fs);
    await assertExactStateBytes(path, bytes, fs);
  } catch (error) {
    failure = error instanceof CoordinationCoordinatorError ? error : new CoordinationCoordinatorError();
  }
  try {
    if (handle !== undefined) await handle.close();
  } catch {
    failure ??= new CoordinationCoordinatorError();
  }
  try {
    if (temporary !== undefined) await fs.unlink(temporary);
  } catch {
    failure ??= new CoordinationCoordinatorError();
  }
  try {
    await root.handle.close();
  } catch {
    failure ??= new CoordinationCoordinatorError();
  }
  if (failure !== undefined) throw failure;
}

const defaultFileSystem = Object.freeze({ lstat, open, rename, unlink });

function readStateFileSystem(value) {
  const methods = ["lstat", "open", "rename", "unlink"];
  if (!isPlainObject(value) || Reflect.ownKeys(value).length !== methods.length) invalid();
  const output = Object.create(null);
  for (const method of methods) {
    const descriptor = Object.getOwnPropertyDescriptor(value, method);
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") invalid();
    output[method] = descriptor.value;
  }
  return Object.freeze(output);
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.uid === right.uid && left.gid === right.gid &&
    left.rdev === right.rdev && left.size === right.size && left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs;
}

function sameNode(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.uid === right.uid && left.gid === right.gid && left.rdev === right.rdev;
}

function sameRootNode(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.rdev === right.rdev;
}

function validPrivateRoot(metadata) {
  return metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === process.getuid() &&
    (metadata.mode & 0o777) === 0o700;
}

function validPrivateStateFile(metadata, size) {
  return metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 &&
    metadata.uid === process.getuid() && (metadata.mode & 0o777) === 0o600 &&
    metadata.size === size && size <= MAX_STATE_BYTES;
}

async function pinPrivateRoot(path, fs) {
  const before = await fs.lstat(path);
  if (!validPrivateRoot(before)) invalid();
  const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0) |
    (fsConstants.O_NOFOLLOW ?? 0) | fsConstants.O_NONBLOCK);
  try {
    const opened = await handle.stat();
    if (!validPrivateRoot(opened) || !sameIdentity(before, opened)) invalid();
    return Object.freeze({ before, handle, path });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertPinnedRoot(root, fs) {
  const opened = await root.handle.stat();
  const pathname = await fs.lstat(root.path);
  if (!validPrivateRoot(opened) || !validPrivateRoot(pathname) || !sameRootNode(opened, pathname) || !sameRootNode(root.before, opened)) invalid();
}

async function existingPrivateState(path, fs) {
  try {
    const before = await fs.lstat(path);
    if (!validPrivateStateFile(before, before.size) || before.size === 0) invalid();
    const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | fsConstants.O_NONBLOCK);
    try {
      const opened = await handle.stat();
      if (!sameIdentity(before, opened)) invalid();
      const bytes = Buffer.alloc(before.size + 1);
      let offset = 0;
      while (offset < bytes.length) {
        const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      const after = await handle.stat();
      const pathname = await fs.lstat(path);
      if (offset !== before.size || !sameIdentity(before, after) || !sameIdentity(before, pathname)) invalid();
      let state;
      try {
        const text = bytes.subarray(0, offset).toString("utf8");
        if (Buffer.byteLength(text, "utf8") !== offset) invalid();
        state = exact(JSON.parse(text), COORDINATOR_STATE_KEYS);
        if (!Buffer.from(`${JSON.stringify(canonicalizeReceiptEventValue(state))}\n`, "utf8").equals(bytes.subarray(0, offset))) invalid();
      } catch (error) {
        if (error instanceof CoordinationCoordinatorError) throw error;
        invalid();
      }
      if (
        state.schema !== COORDINATOR_STATE_SCHEMA ||
        state.paymentMoved !== false ||
        typeof state.releaseId !== "string" ||
        typeof state.sessionId !== "string" ||
        !REPOSITORY_SHA_PATTERN.test(state.repositorySha) ||
        !COORDINATOR_STATES.has(state.state) ||
        !Array.isArray(state.capabilityDigests) || state.capabilityDigests.length !== 2 ||
        state.capabilityDigests.some((item) => typeof item !== "string" || !SHA256_PATTERN.test(item))
      ) invalid();
    } finally {
      await handle.close();
    }
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function readCoordinatorPublicState(path, fs) {
  const bytes = await readPrivateFile(path, fs, MAX_STATE_BYTES);
  if (bytes === null) return null;
  let state;
  try {
    const text = bytes.toString("utf8");
    if (!text.endsWith("\n")) invalid();
    state = exact(JSON.parse(text), COORDINATOR_STATE_KEYS);
    const expected = Buffer.from(`${JSON.stringify(canonicalizeReceiptEventValue(state))}\n`, "utf8");
    if (!bytes.equals(expected)) invalid();
  } catch (error) {
    if (error instanceof CoordinationCoordinatorError) throw error;
    invalid();
  }
  if (state.schema !== COORDINATOR_STATE_SCHEMA || state.paymentMoved !== false || !COORDINATOR_STATES.has(state.state) || !Array.isArray(state.capabilityDigests) || state.capabilityDigests.length !== 2) invalid();
  checkpoints(state.checkpoints);
  return state;
}

async function assertExactStateBytes(path, expected, fs) {
  const before = await fs.lstat(path);
  if (!validPrivateStateFile(before, expected.length)) invalid();
  const handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | fsConstants.O_NONBLOCK);
  try {
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) invalid();
    const actual = Buffer.alloc(expected.length + 1);
    let offset = 0;
    while (offset < actual.length) {
      const { bytesRead } = await handle.read(actual, offset, actual.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    const pathname = await fs.lstat(path);
    if (offset !== expected.length || !actual.subarray(0, offset).equals(expected) || !sameIdentity(before, after) || !sameIdentity(before, pathname)) invalid();
  } finally {
    await handle.close();
  }
}

function canonicalPrivateBytes(value, maximum) {
  let bytes;
  try {
    bytes = Buffer.from(JSON.stringify(canonicalizeReceiptEventValue(value)), "utf8");
  } catch {
    invalid();
  }
  if (bytes.length === 0 || bytes.length > maximum) invalid();
  return bytes;
}

async function readPrivateFile(path, fs, maximum) {
  let before;
  try {
    before = await fs.lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    invalid();
  }
  if (!validPrivateStateFile(before, before.size) || before.size === 0 || before.size > maximum) invalid();
  let handle;
  try {
    handle = await fs.open(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | fsConstants.O_NONBLOCK);
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) invalid();
    const bytes = Buffer.alloc(before.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    const after = await handle.stat();
    const pathname = await fs.lstat(path);
    if (offset !== before.size || !sameIdentity(before, after) || !sameIdentity(before, pathname)) invalid();
    return bytes.subarray(0, offset);
  } catch (error) {
    if (error instanceof CoordinationCoordinatorError) throw error;
    invalid();
  } finally {
    try { await handle?.close(); } catch { invalid(); }
  }
}

async function writeNewPrivateFile({ fileSystem, path, random, releaseRoot, value }) {
  const bytes = canonicalPrivateBytes(value, MAX_PENDING_BYTES);
  const fs = readStateFileSystem(fileSystem);
  let root;
  let temporary;
  let handle;
  try {
    root = await pinPrivateRoot(releaseRoot, fs);
    if (await readPrivateFile(path, fs, MAX_PENDING_BYTES) !== null) invalid();
    const nonce = random(16);
    if (!Buffer.isBuffer(nonce) || nonce.length < 16) invalid();
    temporary = join(releaseRoot, `.${CAPABILITY_PENDING_FILE_NAME}.${nonce.subarray(0, 16).toString("hex")}.tmp`);
    handle = await fs.open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
    if (!validPrivateStateFile(await handle.stat(), 0)) invalid();
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(bytesWritten) || bytesWritten <= 0) invalid();
      offset += bytesWritten;
    }
    await handle.sync();
    await handle.close(); handle = undefined;
    await assertPinnedRoot(root, fs);
    await fs.rename(temporary, path); temporary = undefined;
    await root.handle.sync();
    await assertPinnedRoot(root, fs);
    const actual = await readPrivateFile(path, fs, MAX_PENDING_BYTES);
    if (actual === null || !actual.equals(bytes)) invalid();
  } catch (error) {
    if (error instanceof CoordinationCoordinatorError) throw error;
    invalid();
  } finally {
    try { await handle?.close(); } catch { invalid(); }
    try { if (temporary !== undefined) await fs.unlink(temporary); } catch { invalid(); }
    try { await root?.handle.close(); } catch { invalid(); }
  }
}

async function replacePrivateFile({ fileSystem, path, random, releaseRoot, value }) {
  const current = await readPrivateFile(path, readStateFileSystem(fileSystem), MAX_PENDING_BYTES);
  if (current === null) return writeNewPrivateFile({ fileSystem, path, random, releaseRoot, value });
  // Replacing is only used for the journal's receipt transition.  Remove no
  // authority: retain the original file if the replacement cannot become durable.
  const fs = readStateFileSystem(fileSystem);
  const root = await pinPrivateRoot(releaseRoot, fs);
  try {
    const bytes = canonicalPrivateBytes(value, MAX_PENDING_BYTES);
    const nonce = random(16);
    if (!Buffer.isBuffer(nonce) || nonce.length < 16) invalid();
    const temporary = join(releaseRoot, `.${CAPABILITY_PENDING_FILE_NAME}.${nonce.subarray(0, 16).toString("hex")}.tmp`);
    let handle;
    try {
      handle = await fs.open(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0), 0o600);
      if (!validPrivateStateFile(await handle.stat(), 0)) invalid();
      let offset = 0;
      while (offset < bytes.length) { const written = await handle.write(bytes, offset, bytes.length - offset, offset); if (!Number.isInteger(written.bytesWritten) || written.bytesWritten <= 0) invalid(); offset += written.bytesWritten; }
      await handle.sync(); await handle.close(); handle = undefined;
      await assertPinnedRoot(root, fs); await fs.rename(temporary, path); await root.handle.sync(); await assertPinnedRoot(root, fs);
      const actual = await readPrivateFile(path, fs, MAX_PENDING_BYTES); if (actual === null || !actual.equals(bytes)) invalid();
    } finally {
      try { await handle?.close(); } catch { invalid(); }
      try { await fs.unlink(temporary); } catch (error) { if (error?.code !== "ENOENT") invalid(); }
    }
  } finally { try { await root.handle.close(); } catch { invalid(); } }
}

async function unlinkPrivateFile({ fileSystem, path, releaseRoot }) {
  const fs = readStateFileSystem(fileSystem);
  const root = await pinPrivateRoot(releaseRoot, fs);
  try {
    if (await readPrivateFile(path, fs, MAX_PENDING_BYTES) === null) invalid();
    await assertPinnedRoot(root, fs);
    await fs.unlink(path);
    await root.handle.sync();
    await assertPinnedRoot(root, fs);
    if (await readPrivateFile(path, fs, MAX_PENDING_BYTES) !== null) invalid();
  } finally { try { await root.handle.close(); } catch { invalid(); } }
}

async function rejectStalePendingTemporaries({ fileSystem, releaseRoot }) {
  const fs = readStateFileSystem(fileSystem);
  let root;
  try {
    root = await pinPrivateRoot(releaseRoot, fs);
    const names = await readdir(releaseRoot);
    if (!Array.isArray(names) || names.some((name) => typeof name !== "string" || name.startsWith(`.${CAPABILITY_PENDING_FILE_NAME}.`) && name.endsWith(".tmp"))) invalid();
    await assertPinnedRoot(root, fs);
  } catch (error) {
    if (error instanceof CoordinationCoordinatorError) throw error;
    invalid();
  } finally { try { await root?.handle.close(); } catch { invalid(); } }
}

function fundingRecord(value, address) {
  const data = exact(value, FUNDING_RECORD_KEYS);
  if (
    data.address !== address ||
    typeof data.balanceWei !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(data.balanceWei) ||
    BigInt(data.balanceWei) < 5_000_000_000_000_000n ||
    BigInt(data.balanceWei) > 20_000_000_000_000_000n ||
    data.nonce !== "0" ||
    data.paymentMoved !== false
  ) invalid();
  return data;
}

function sameCanonical(left, right) {
  return JSON.stringify(canonicalizeReceiptEventValue(left)) ===
    JSON.stringify(canonicalizeReceiptEventValue(right));
}

function capabilitySetReceipt(value, { capabilities, releaseId, repositorySha, sessionId }) {
  const receipt = exact(value, CAPABILITY_SET_RECEIPT_KEYS);
  if (
    receipt.schema !== CAPABILITY_SET_RECEIPT_SCHEMA ||
    receipt.paymentMoved !== false ||
    receipt.releaseId !== releaseId ||
    receipt.repositorySha !== repositorySha ||
    receipt.sessionId !== sessionId ||
    !SHA256_PATTERN.test(receipt.registrationDigest) ||
    !SHA256_PATTERN.test(receipt.requestDigest) ||
    !sameCanonical(receipt.capabilities, capabilities)
  ) invalid();
  return receipt;
}

function pendingContext(value) {
  const data = exact(value, CAPABILITY_PENDING_CONTEXT_KEYS);
  if (typeof data.operatorKeyId !== "string" || data.operatorKeyId.length === 0 ||
      typeof data.relayUrl !== "string" || data.relayUrl.length === 0 ||
      !REPOSITORY_SHA_PATTERN.test(data.repositorySha) ||
      typeof data.tlsCertificatePem !== "string" || data.tlsCertificatePem.length === 0 ||
      !SHA256_PATTERN.test(data.tlsFingerprint)) invalid();
  return data;
}

function pendingJournal(value, expectedContext, { parsedManifests = false } = {}) {
  const data = exact(value, CAPABILITY_PENDING_KEYS);
  if (data.schema !== CAPABILITY_PENDING_SCHEMA || !sameCanonical(pendingContext(data.context), expectedContext) || !Array.isArray(data.entries) || data.entries.length !== 2) invalid();
  const entries = data.entries.map((entry, index) => {
    const parsed = exact(entry, CAPABILITY_PENDING_ENTRY_KEYS);
    const role = index === 0 ? "payee" : "payer";
    if (parsed.role !== role || !SHA256_PATTERN.test(parsed.capabilityDigest) || !isPlainObject(parsed.manifest)) invalid();
    if (!parsedManifests) return parsed;
    let manifest;
    try { manifest = validateLaunchManifest(parsed.manifest); } catch { invalid(); }
    if (
      manifest.role !== role ||
      parsed.capabilityDigest !==
        digest(Buffer.from(manifest.bootstrapCapability, "hex"))
    ) invalid();
    return deepFreeze({ ...parsed, manifest });
  });
  if (entries[0].capabilityDigest === entries[1].capabilityDigest || entries[0].manifest.bootstrapCapability === entries[1].manifest.bootstrapCapability) invalid();
  validateMcpIntakePair(entries);
  const registration = exact(data.registration, ["capabilities", "operatorKeyId", "paymentMoved", "releaseId", "repositorySha", "schema", "sessionId", "signature"]);
  const capabilities = {
    payee: { capabilityDigest: entries[0].capabilityDigest, expiresAtMs: entries[0].manifest.expiresAtMs },
    payer: { capabilityDigest: entries[1].capabilityDigest, expiresAtMs: entries[1].manifest.expiresAtMs },
  };
  if (registration.operatorKeyId !== expectedContext.operatorKeyId || registration.paymentMoved !== false || !sameCanonical(registration.capabilities, capabilities)) invalid();
  if (data.receipt !== null) capabilitySetReceipt(data.receipt, registration);
  return deepFreeze({ context: expectedContext, entries, receipt: data.receipt, registration, schema: CAPABILITY_PENDING_SCHEMA });
}

function validateMcpIntakePair(entries) {
  const payerMcpIntakeCapability =
    entries[0].manifest.payerMcpIntakeCapability;
  if (
    typeof payerMcpIntakeCapability !== "string" ||
    !/^[0-9a-f]{64}$/.test(payerMcpIntakeCapability) ||
    Object.hasOwn(entries[0].manifest, "payerMcpIntakeCapabilityDigest") ||
    Object.hasOwn(entries[1].manifest, "payerMcpIntakeCapability") ||
    entries[1].manifest.payerMcpIntakeCapabilityDigest !==
      digest(Buffer.from(payerMcpIntakeCapability, "hex")) ||
    entries[0].manifest.bootstrapCapability ===
      payerMcpIntakeCapability ||
    entries[1].manifest.bootstrapCapability ===
      payerMcpIntakeCapability
  ) invalid();
}

async function existingManifestMatches({ fileSystem, manifest, path }) {
  const bytes = await readPrivateFile(path, readStateFileSystem(fileSystem), MAX_PENDING_BYTES);
  if (bytes === null) return false;
  return bytes.equals(canonicalPrivateBytes(manifest, MAX_PENDING_BYTES));
}

async function preflightPassed({ dependencies, enrollmentSet, persisted, release, releaseRoot }) {
  for (const key of PREFLIGHT_DEPENDENCY_KEYS) {
    if (typeof dependencies[key] !== "function") invalid();
  }
  const enrollments = Object.freeze({
    payer: parseCoordinationEnrollment(Buffer.from(enrollmentSet.enrollments.payer.enrollmentBase64, "base64")),
    payee: parseCoordinationEnrollment(Buffer.from(enrollmentSet.enrollments.payee.enrollmentBase64, "base64")),
  });
  const priorPlan = persisted.checkpoints.filter((entry) => entry.action === "PREFLIGHT_PLAN" && entry.role === "operator" && entry.subjectRun === "release").at(-1);
  let planBytes;
  if (priorPlan?.status === "CHILD_COMPLETE" || priorPlan?.status === "ARTIFACT_STORED" || priorPlan?.status === "EVENT_APPENDED") {
    if (priorPlan.artifactDigest === null) invalid();
    planBytes = await dependencies.getArtifact({ artifactType: "preflight-plan", digest: priorPlan.artifactDigest });
  } else {
    const before = priorPlan?.status === "BEFORE_CHILD"
      ? persisted
      : descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_PLAN", artifactDigest: null, eventDigest: null, role: "operator", status: "BEFORE_CHILD", subjectRun: "release" })], release, state: "FUNDING_READY" });
    if (before !== persisted) await dependencies.writeState({ releaseRoot, state: before });
    planBytes = await dependencies.createPreflightPlan({ enrollments, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId });
    if (!Buffer.isBuffer(planBytes)) invalid();
    const child = descriptorState({ checkpoints: [...before.checkpoints, Object.freeze({ action: "PREFLIGHT_PLAN", artifactDigest: digest(planBytes), eventDigest: null, role: "operator", status: "CHILD_COMPLETE", subjectRun: "release" })], release, state: "FUNDING_READY" });
    await dependencies.writeState({ releaseRoot, state: child });
    persisted = child;
  }
  if (!Buffer.isBuffer(planBytes)) invalid();
  const planDigest = digest(planBytes);
  const planArtifact = await dependencies.validateArtifact({ artifactType: "preflight-plan", bytes: planBytes, expectedDigest: planDigest, secretCanaries: [] });
  const plan = planArtifact?.facts?.plan;
  if (planArtifact?.digest !== planDigest || !isPlainObject(plan) || plan.repositorySha !== release.repositorySha || !isPlainObject(plan.participants)) invalid();
  for (const role of ["payer", "payee"]) {
    const participant = plan.participants[role];
    if (!isPlainObject(participant) || participant.coordinationPublicKey !== enrollments[role].coordinationKey.publicKey || participant.publicKey !== enrollments[role].preflightKey.publicKey || !isPlainObject(participant.tokenCommitment)) invalid();
  }
  const planCheckpoint = persisted.checkpoints.filter((entry) => entry.action === "PREFLIGHT_PLAN" && entry.role === "operator" && entry.subjectRun === "release").at(-1);
  if (planCheckpoint?.status === "CHILD_COMPLETE") {
    const published = await dependencies.putArtifact({ artifactType: "preflight-plan", bytes: planBytes, expectedDigest: planDigest });
    if (published?.digest !== planDigest) invalid();
    persisted = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_PLAN", artifactDigest: planDigest, eventDigest: null, role: "operator", status: "ARTIFACT_STORED", subjectRun: "release" })], release, state: "FUNDING_READY" });
    await dependencies.writeState({ releaseRoot, state: persisted });
  }
  const storedPlan = persisted.checkpoints.filter((entry) => entry.action === "PREFLIGHT_PLAN" && entry.role === "operator" && entry.subjectRun === "release").at(-1);
  if (storedPlan?.status === "ARTIFACT_STORED") {
    const event = await adoptOrAppendOperatorEvent({ dependencies, input: { artifactDigest: planDigest, kind: "PREFLIGHT_PLAN_READY", releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun: "release" }, release });
    persisted = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_PLAN", artifactDigest: planDigest, eventDigest: event.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" })], release, state: "FUNDING_READY" });
    await dependencies.writeState({ releaseRoot, state: persisted });
  }
  const reports = Object.create(null);
  for (const role of ["payer", "payee"]) {
    let checkpoint = persisted.checkpoints.filter((entry) => entry.action === "PREFLIGHT_PARTICIPANT" && entry.role === role && entry.subjectRun === "release").at(-1);
    let bytes;
    if (["CHILD_COMPLETE", "ARTIFACT_STORED"].includes(checkpoint?.status)) {
      if (checkpoint.artifactDigest === null) invalid();
      bytes = await dependencies.getArtifact({ artifactType: "preflight-participant-report", digest: checkpoint.artifactDigest });
    } else {
      const before = checkpoint?.status === "BEFORE_CHILD"
        ? persisted
        : descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_PARTICIPANT", artifactDigest: null, eventDigest: null, role, status: "BEFORE_CHILD", subjectRun: "release" })], release, state: "FUNDING_READY" });
      if (before !== persisted) await dependencies.writeState({ releaseRoot, state: before });
      const awaited = exact(await dependencies.waitForPreflightParticipant({ planDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, role, sessionId: release.sessionId }), ["bytes", "digest"]);
      if (!Buffer.isBuffer(awaited.bytes) || awaited.digest !== digest(awaited.bytes)) invalid();
      bytes = awaited.bytes;
      persisted = descriptorState({ checkpoints: [...before.checkpoints, Object.freeze({ action: "PREFLIGHT_PARTICIPANT", artifactDigest: awaited.digest, eventDigest: null, role, status: "CHILD_COMPLETE", subjectRun: "release" })], release, state: "FUNDING_READY" });
      await dependencies.writeState({ releaseRoot, state: persisted });
      checkpoint = persisted.checkpoints.at(-1);
    }
    if (!Buffer.isBuffer(bytes) || checkpoint?.artifactDigest !== digest(bytes)) invalid();
    const artifact = await dependencies.validateArtifact({ artifactType: "preflight-participant-report", bytes, expectedDigest: checkpoint.artifactDigest, secretCanaries: [] });
    const report = artifact?.facts?.participantReport?.report;
    const signature = artifact?.facts?.participantReport?.signature;
    if (artifact?.digest !== checkpoint.artifactDigest || !isPlainObject(report) || !isPlainObject(signature) || report.role !== role || signature.role !== role || report.repositorySha !== release.repositorySha || report.planDigest !== digest(canonicalBytes(plan)) || !sameCanonical(report.tokenCommitment, plan.participants[role].tokenCommitment) || report.write?.digest !== plan.digests?.[role] || report.write?.key !== plan.keys?.[role]) invalid();
    if (checkpoint.status === "CHILD_COMPLETE") {
      const published = await dependencies.putArtifact({ artifactType: "preflight-participant-report", bytes, expectedDigest: checkpoint.artifactDigest });
      if (published?.digest !== checkpoint.artifactDigest) invalid();
      persisted = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_PARTICIPANT", artifactDigest: checkpoint.artifactDigest, eventDigest: null, role, status: "ARTIFACT_STORED", subjectRun: "release" })], release, state: "FUNDING_READY" });
      await dependencies.writeState({ releaseRoot, state: persisted });
    }
    reports[role] = report;
  }
  let aggregateCheckpoint = persisted.checkpoints.filter((entry) => entry.action === "PREFLIGHT_AGGREGATE" && entry.role === "operator" && entry.subjectRun === "release").at(-1);
  let aggregateBytes;
  if (["CHILD_COMPLETE", "ARTIFACT_STORED"].includes(aggregateCheckpoint?.status)) {
    if (aggregateCheckpoint.artifactDigest === null) invalid();
    aggregateBytes = await dependencies.getArtifact({ artifactType: "preflight-aggregate-report", digest: aggregateCheckpoint.artifactDigest });
  } else {
    const before = aggregateCheckpoint?.status === "BEFORE_CHILD"
      ? persisted
      : descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_AGGREGATE", artifactDigest: null, eventDigest: null, role: "operator", status: "BEFORE_CHILD", subjectRun: "release" })], release, state: "FUNDING_READY" });
    if (before !== persisted) await dependencies.writeState({ releaseRoot, state: before });
    aggregateBytes = await dependencies.runAggregatePreflight({ plan, planBytes, participants: Object.freeze(reports), releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId });
    if (!Buffer.isBuffer(aggregateBytes)) invalid();
    persisted = descriptorState({ checkpoints: [...before.checkpoints, Object.freeze({ action: "PREFLIGHT_AGGREGATE", artifactDigest: digest(aggregateBytes), eventDigest: null, role: "operator", status: "CHILD_COMPLETE", subjectRun: "release" })], release, state: "FUNDING_READY" });
    await dependencies.writeState({ releaseRoot, state: persisted });
    aggregateCheckpoint = persisted.checkpoints.at(-1);
  }
  if (!Buffer.isBuffer(aggregateBytes) || aggregateCheckpoint?.artifactDigest !== digest(aggregateBytes)) invalid();
  const aggregate = await dependencies.validateArtifact({ artifactType: "preflight-aggregate-report", bytes: aggregateBytes, expectedDigest: aggregateCheckpoint.artifactDigest, secretCanaries: [] });
  const report = aggregate?.facts?.aggregateReport?.report;
  if (aggregate?.digest !== aggregateCheckpoint.artifactDigest || !isPlainObject(report) || report.repositorySha !== release.repositorySha || report.planDigest !== digest(canonicalBytes(plan)) || !Array.isArray(report.writes) || report.writes.length !== 2 || !sameCanonical(report.writes[0], reports.payer.write) || !sameCanonical(report.writes[1], reports.payee.write)) invalid();
  if (aggregateCheckpoint.status === "CHILD_COMPLETE") {
    const published = await dependencies.putArtifact({ artifactType: "preflight-aggregate-report", bytes: aggregateBytes, expectedDigest: aggregateCheckpoint.artifactDigest });
    if (published?.digest !== aggregateCheckpoint.artifactDigest) invalid();
    persisted = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "PREFLIGHT_AGGREGATE", artifactDigest: aggregateCheckpoint.artifactDigest, eventDigest: null, role: "operator", status: "ARTIFACT_STORED", subjectRun: "release" })], release, state: "PREFLIGHT_PASSED" });
    await dependencies.writeState({ releaseRoot, state: persisted });
  }
  return deepFreeze({ ...persisted, preflightAggregateDigest: aggregateCheckpoint.artifactDigest, preflightPlanDigest: planDigest });
}

async function runIdentities({ dependencies, enrollments, persisted, release, releaseRoot, subjectRun }) {
  for (const key of REHEARSAL_IDENTITY_DEPENDENCY_KEYS) if (typeof dependencies[key] !== "function") invalid();
  const aggregate = persisted.checkpoints.find((entry) => entry.action === "PREFLIGHT_AGGREGATE" && entry.status === "ARTIFACT_STORED" && entry.role === "operator" && entry.subjectRun === "release");
  if (aggregate === undefined || aggregate.artifactDigest === null) invalid();
  let events = await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId });
  if (!Array.isArray(events)) invalid();
  const authenticated = events.map((event) => exact(event, AUTHENTICATED_EVENT_KEYS));
  for (const event of authenticated) if (event.releaseId !== release.releaseId || event.repositorySha !== release.repositorySha || event.sessionId !== release.sessionId || event.paymentMoved !== false || !SHA256_PATTERN.test(event.eventDigest)) invalid();
  const action = subjectRun === "rehearsal" ? "REGISTER_REHEARSAL" : "REGISTER_STAKEHOLDER";
  const nextState = subjectRun === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY";
  const registrationArtifactDigest = subjectRun === "rehearsal" ? aggregate.artifactDigest : null;
  const registered = persisted.checkpoints.find((entry) => entry.action === action && entry.status === "EVENT_APPENDED" && entry.subjectRun === subjectRun);
  let registrationEventDigest;
  if (registered !== undefined) {
    if (registered.artifactDigest !== registrationArtifactDigest || registered.eventDigest === null || !authenticated.some((event) => event.eventDigest === registered.eventDigest && event.kind === action && event.role === "operator" && event.subjectRun === subjectRun && event.artifactDigest === registrationArtifactDigest)) invalid();
    registrationEventDigest = registered.eventDigest;
  } else {
    const returned = await adoptOrAppendOperatorEvent({ dependencies, input: { artifactDigest: registrationArtifactDigest, kind: action, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun }, release });
    if (returned.kind !== action || returned.role !== "operator" || returned.subjectRun !== subjectRun || returned.artifactDigest !== registrationArtifactDigest || returned.releaseId !== release.releaseId || returned.repositorySha !== release.repositorySha || returned.sessionId !== release.sessionId || returned.paymentMoved !== false || !SHA256_PATTERN.test(returned.eventDigest)) invalid();
    registrationEventDigest = returned.eventDigest;
    const registeredState = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action, artifactDigest: registrationArtifactDigest, eventDigest: registrationEventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun })], release, state: subjectRun === "rehearsal" ? "PREFLIGHT_PASSED" : persisted.state });
    await dependencies.writeState({ releaseRoot, state: registeredState });
    persisted = registeredState;
    await dependencies.waitForIdentityPackage({ releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun });
    events = await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId });
  }
  const ready = events.map((event) => exact(event, AUTHENTICATED_EVENT_KEYS)).filter((event) => event.kind === "IDENTITY_PACKAGE_READY" && event.subjectRun === subjectRun);
  if (ready.length !== 2 || new Set(ready.map((event) => event.role)).size !== 2) invalid();
  const journal = [...persisted.checkpoints];
  for (const role of ["payer", "payee"]) {
    const event = ready.find((entry) => entry.role === role);
    if (!SHA256_PATTERN.test(event?.artifactDigest)) invalid();
    const bytes = await dependencies.getArtifact({ artifactType: "identity-package", digest: event.artifactDigest });
    if (!Buffer.isBuffer(bytes)) invalid();
    const artifact = await dependencies.validateArtifact({ artifactType: "identity-package", bytes, expectedDigest: event.artifactDigest, secretCanaries: [] });
    const identity = artifact?.facts?.identity;
    if (artifact?.digest !== event.artifactDigest || !isPlainObject(identity) || identity.repositorySha !== release.repositorySha || identity.address?.toLowerCase() !== enrollments[role].invitations[subjectRun].address.toLowerCase()) invalid();
    journal.push(Object.freeze({ action: "IDENTITY_PACKAGE", artifactDigest: event.artifactDigest, eventDigest: typeof event.eventDigest === "string" ? event.eventDigest : null, role, status: "EVENT_APPENDED", subjectRun }));
  }
  const state = deepFreeze({ capabilityDigests: release.capabilityDigests, checkpoints: checkpoints(journal), paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha, schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId, state: nextState });
  await dependencies.writeState({ releaseRoot, state });
  return state;
}

async function beginDescriptor({ dependencies, persisted, release, releaseRoot, subjectRun }) {
  for (const key of RUN_ORCHESTRATION_DEPENDENCY_KEYS.filter((key) => !["createVerifiedEvent", "readVerifiedRawEvents", "validateRehearsalPackage"].includes(key))) {
    if (typeof dependencies[key] !== "function") invalid();
  }
  const action = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR" : "STAKEHOLDER_DESCRIPTOR";
  await waitForVerifiedCoordinatorIntentReadiness({
    now: dependencies.now,
    readEvents: async () => checkedAuthenticatedEvents(
      await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
      release,
    ),
    sleeper: dependencies.sleeper,
    subjectRun,
  });
  const existing = persisted.checkpoints.filter((entry) => entry.action === action && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (existing?.status === "EVENT_APPENDED") return awaitDescriptorAcceptance({ dependencies, persisted, release, releaseRoot, subjectRun, action });
  if (existing?.status === "ARTIFACT_STORED") {
    const appended = await appendDescriptorReady({ dependencies, persisted, release, releaseRoot, subjectRun, action });
    return awaitDescriptorAcceptance({ dependencies, persisted: appended, release, releaseRoot, subjectRun, action });
  }
  if (existing?.status === "CHILD_COMPLETE") {
    const stored = await storeDescriptor({ dependencies, persisted, release, releaseRoot, subjectRun, action });
    const appended = await appendDescriptorReady({ dependencies, persisted: stored, release, releaseRoot, subjectRun, action });
    return awaitDescriptorAcceptance({ dependencies, persisted: appended, release, releaseRoot, subjectRun, action });
  }
  const before = existing === undefined ? deepFreeze({
    capabilityDigests: release.capabilityDigests,
    checkpoints: checkpoints([...persisted.checkpoints, Object.freeze({ action, artifactDigest: null, eventDigest: null, role: "operator", status: "BEFORE_CHILD", subjectRun })]),
    paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId,
    state: subjectRun === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY",
  }) : persisted;
  if (existing === undefined) await dependencies.writeState({ releaseRoot, state: before });
  const bytes = await dependencies.createDescriptor({
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    sessionId: release.sessionId,
    subjectRun,
  });
  if (!Buffer.isBuffer(bytes)) invalid();
  const artifactDigest = digest(bytes);
  const state = deepFreeze({
    capabilityDigests: release.capabilityDigests,
    checkpoints: checkpoints([...before.checkpoints, Object.freeze({ action, artifactDigest, eventDigest: null, role: "operator", status: "CHILD_COMPLETE", subjectRun })]),
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: release.sessionId,
    state: subjectRun === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY",
  });
  await dependencies.writeState({ releaseRoot, state });
  return state;
}

function descriptorState({ checkpoints: journal, release, state }) {
  return deepFreeze({ capabilityDigests: release.capabilityDigests, checkpoints: checkpoints(journal), paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha, schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId, state });
}

function checkedAuthenticatedEvents(events, release) {
  if (!Array.isArray(events)) invalid();
  return events.map((event) => {
    const value = exact(event, AUTHENTICATED_EVENT_KEYS);
    if (value.releaseId !== release.releaseId || value.repositorySha !== release.repositorySha || value.sessionId !== release.sessionId || value.paymentMoved !== false || !SHA256_PATTERN.test(value.eventDigest)) invalid();
    return value;
  });
}

function verifierPublicationMatchesEvent(publication, event) {
  const claim = exact(publication, VERIFIER_PUBLICATION_KEYS);
  return claim.schema === VERIFIER_PUBLICATION_SCHEMA &&
    claim.paymentMoved === false &&
    claim.publicationDigest === event.artifactDigest &&
    claim.releaseId === event.releaseId &&
    claim.repositorySha === event.repositorySha &&
    claim.sessionId === event.sessionId &&
    claim.status === SUCCESS_STATUS &&
    claim.subjectRun === event.subjectRun;
}

const LIFECYCLE_STATE_RANK = Object.freeze({
  BOOTSTRAPPING: 0, ADDRESSES_READY: 1, FUNDING_READY: 2, PREFLIGHT_PASSED: 3,
  REHEARSAL_IDENTITIES_READY: 4, REHEARSAL_DESCRIPTOR_READY: 5, REHEARSAL_PACKAGES_READY: 6,
  REHEARSAL_VERIFIED: 7, STAKEHOLDER_IDENTITIES_READY: 8, STAKEHOLDER_DESCRIPTOR_READY: 9,
  STAKEHOLDER_PACKAGES_READY: 10, STAKEHOLDER_VERIFIED: 11, COMPLETE: 12,
});

function lifecycleRankForCoordinatorState(state) {
  if (state === "REHEARSAL_PACKAGES_READY" || state === "REHEARSAL_RUNNING") return LIFECYCLE_STATE_RANK.REHEARSAL_PACKAGES_READY;
  if (state === "STAKEHOLDER_PACKAGES_READY" || state === "STAKEHOLDER_RUNNING") return LIFECYCLE_STATE_RANK.STAKEHOLDER_PACKAGES_READY;
  return LIFECYCLE_STATE_RANK[state];
}

function assertReconciledPersistedState({ persisted, replay }) {
  if (persisted === null) return;
  const persistedRank = lifecycleRankForCoordinatorState(persisted.state);
  const replayRank = lifecycleRankForCoordinatorState(replay.view.state);
  if (!Number.isInteger(persistedRank) || !Number.isInteger(replayRank) || persistedRank > replayRank) invalid();
  const canonical = replayCheckpoints(replay.events);
  for (const checkpoint of persisted.checkpoints) {
    if (checkpoint.status !== "EVENT_APPENDED") continue;
    const matched = canonical.filter((candidate) => candidate.eventDigest === checkpoint.eventDigest);
    if (
      matched.length !== 1 ||
      matched[0].action !== checkpoint.action ||
      matched[0].artifactDigest !== checkpoint.artifactDigest ||
      matched[0].role !== checkpoint.role ||
      matched[0].subjectRun !== checkpoint.subjectRun
    ) invalid();
  }
}

function replayCheckpoints(events) {
  const descriptorDigest = new Map();
  for (const event of events) {
    if (event.kind === "REHEARSAL_DESCRIPTOR_READY" || event.kind === "STAKEHOLDER_DESCRIPTOR_READY") {
      if (!SHA256_PATTERN.test(event.artifactDigest)) invalid();
      descriptorDigest.set(event.subjectRun, event.artifactDigest);
    }
  }
  return Object.freeze(events.map((event) => checkpointFromReplayEvent(event, descriptorDigest)).filter((checkpoint) => checkpoint !== null));
}

function checkpointFromReplayEvent(event, descriptorDigest) {
  const operatorActions = {
    COMPLETE_RELEASE: "COMPLETE_RELEASE",
    ENROLLMENT_RECEIPT: "ENROLLMENT_RECEIPT",
    PREFLIGHT_PLAN_READY: "PREFLIGHT_PLAN",
    REGISTER_REHEARSAL: "REGISTER_REHEARSAL",
    REGISTER_STAKEHOLDER: "REGISTER_STAKEHOLDER",
    REHEARSAL_DESCRIPTOR_READY: "REHEARSAL_DESCRIPTOR",
    STAKEHOLDER_DESCRIPTOR_READY: "STAKEHOLDER_DESCRIPTOR",
    START_REHEARSAL: "START_REHEARSAL",
    START_STAKEHOLDER: "START_STAKEHOLDER",
    VERIFICATION_PASSED: event.subjectRun === "rehearsal" ? "REHEARSAL_VERDICT" : "STAKEHOLDER_VERDICT",
    WAIT_FOR_FUNDING: "WAIT_FOR_FUNDING",
  };
  let action = event.role === "operator" ? operatorActions[event.kind] : undefined;
  if (event.kind === "IDENTITY_PACKAGE_READY") action = "IDENTITY_PACKAGE";
  if (event.kind === "ROLE_PACKAGE_READY") action = "ROLE_PACKAGE";
  if (event.kind === "ROLE_STARTED") action = "ROLE_STARTED";
  if (action === undefined) return null;
  const descriptorBound = event.kind === "ROLE_STARTED" || event.kind === "START_REHEARSAL" || event.kind === "START_STAKEHOLDER";
  const artifactDigest = descriptorBound ? descriptorDigest.get(event.subjectRun) : event.artifactDigest;
  if (descriptorBound && !SHA256_PATTERN.test(artifactDigest)) invalid();
  return Object.freeze({ action, artifactDigest, eventDigest: event.eventDigest, role: event.role, status: "EVENT_APPENDED", subjectRun: event.subjectRun });
}

function adoptReplayState({ persisted, release, replay }) {
  // A brand-new coordinator must still independently observe its local funding
  // check.  Replay can fill gaps only after a durable local release state exists.
  if (persisted === null) return null;
  const initial = persisted;
  const existing = new Set(initial.checkpoints.filter((item) => item.status === "EVENT_APPENDED").map((item) => `${item.action}:${item.role}:${item.subjectRun}`));
  const existingStatus = new Set(initial.checkpoints.map((item) => `${item.action}:${item.role}:${item.subjectRun}:${item.status}`));
  const appended = [];
  const canonical = replayCheckpoints(replay.events);
  for (const checkpoint of canonical) {
    if (checkpoint === null) continue;
    const key = `${checkpoint.action}:${checkpoint.role}:${checkpoint.subjectRun}`;
    if (existing.has(key)) continue;
    if (checkpoint.action === "ROLE_STARTED") {
      const launchedAction = checkpoint.role === "payee" ? "PAYEE_ROLE_START" : "PAYER_ROLE_START";
      const launchKey = `${launchedAction}:${checkpoint.role}:${checkpoint.subjectRun}`;
      if (!existingStatus.has(`${launchKey}:CHILD_COMPLETE`)) {
        existing.add(launchKey);
        existingStatus.add(`${launchKey}:CHILD_COMPLETE`);
        appended.push(Object.freeze({ action: launchedAction, artifactDigest: checkpoint.artifactDigest, eventDigest: null, role: checkpoint.role, status: "CHILD_COMPLETE", subjectRun: checkpoint.subjectRun }));
      }
      existing.add(key);
      appended.push(checkpoint);
    } else {
      existing.add(key); appended.push(checkpoint);
    }
  }
  if (appended.length === 0) return persisted;
  const all = [...initial.checkpoints, ...appended];
  const has = (action, role, subjectRun) => all.some((item) => item.action === action && item.role === role && item.subjectRun === subjectRun && item.status === "EVENT_APPENDED");
  const both = (action, subjectRun) => ["payee", "payer"].every((role) => has(action, role, subjectRun));
  let state = initial.state;
  // This is deliberately the closest phase whose irreversible relay effects
  // are all present.  Missing local preflight/descriptor artifacts never get
  // invented from the advisory view.
  if (has("COMPLETE_RELEASE", "operator", "release")) state = "COMPLETE";
  else if (has("STAKEHOLDER_VERDICT", "operator", "stakeholder")) state = "STAKEHOLDER_VERIFIED";
  else if (both("ROLE_PACKAGE", "stakeholder")) state = "STAKEHOLDER_PACKAGES_READY";
  else if (has("STAKEHOLDER_DESCRIPTOR", "operator", "stakeholder")) state = "STAKEHOLDER_DESCRIPTOR_READY";
  else if (both("IDENTITY_PACKAGE", "stakeholder")) state = "STAKEHOLDER_IDENTITIES_READY";
  else if (has("REHEARSAL_VERDICT", "operator", "rehearsal")) state = "REHEARSAL_VERIFIED";
  else if (both("ROLE_PACKAGE", "rehearsal")) state = "REHEARSAL_PACKAGES_READY";
  else if (has("REHEARSAL_DESCRIPTOR", "operator", "rehearsal")) state = "REHEARSAL_DESCRIPTOR_READY";
  else if (both("IDENTITY_PACKAGE", "rehearsal")) state = "REHEARSAL_IDENTITIES_READY";
  else if (replay.view.state === "FUNDING_READY") state = "FUNDING_READY";
  if (lifecycleRankForCoordinatorState(state) < lifecycleRankForCoordinatorState(initial.state)) invalid();
  return descriptorState({ checkpoints: all, release, state });
}

async function adoptOrAppendOperatorEvent({ dependencies, input, release }) {
  const matching = async () => checkedAuthenticatedEvents(
    await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
    release,
  ).filter((event) =>
    event.kind === input.kind &&
    event.role === "operator" &&
    event.subjectRun === input.subjectRun &&
    event.artifactDigest === input.artifactDigest,
  );
  const existing = await matching();
  if (existing.length > 1) invalid();
  if (existing.length === 1) return existing[0];
  // A transport acknowledgement is never relay authority.  It may be forged,
  // stale, or lost after a durable append; only the next verified raw replay
  // can make the command visible to the workflow.
  await dependencies.appendOperatorEvent({
    artifactDigest: input.artifactDigest,
    kind: input.kind,
    subjectRun: input.subjectRun,
  });
  const adopted = await matching();
  if (adopted.length !== 1) invalid();
  return adopted[0];
}

async function authenticateCoordinatorReplay({ dependencies, enrollments, events, release, runMode = "local-two-run" }) {
  if (!Array.isArray(events)) invalid();
  runMode = normalizeRunMode(runMode);
  let view;
  try {
    view = initialReleaseView({ releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId });
  } catch {
    invalid();
  }
  if (events.length === 0) return Object.freeze({ events: Object.freeze([]), view });
  if (typeof dependencies.resolveOperatorPublicKey !== "function" || typeof dependencies.readVerifierPublication !== "function") invalid();
  const operatorPublicKey = await dependencies.resolveOperatorPublicKey({ repositorySha: release.repositorySha });
  if (typeof operatorPublicKey !== "string") invalid();
  const expectedByRole = Object.freeze({
    operator: operatorPublicKey,
    payer: enrollments.payer.coordinationKey.publicKey,
    payee: enrollments.payee.coordinationKey.publicKey,
  });
  const senders = new Map();
  const seenDigests = new Set();
  for (const raw of events) {
    const candidate = exact(raw, AUTHENTICATED_EVENT_KEYS);
    const expectedPublicKey = expectedByRole[candidate.role];
    if (expectedPublicKey === undefined) invalid();
    let event;
    try {
      event = verifyCoordinationEnvelope(candidate, {
        expectedPublicKey,
        expectedReleaseId: release.releaseId,
        expectedRepositorySha: release.repositorySha,
        expectedRole: candidate.role,
        expectedSessionId: release.sessionId,
        expectedSubjectRun: candidate.subjectRun,
      });
    } catch {
      invalid();
    }
    if (seenDigests.has(event.eventDigest)) invalid();
    seenDigests.add(event.eventDigest);
    const sender = senders.get(event.role) ?? { previousEventDigest: null, sequence: 0n };
    if (event.sequence !== sender.sequence.toString() || event.previousEventDigest !== sender.previousEventDigest) invalid();
    senders.set(event.role, { previousEventDigest: event.eventDigest, sequence: sender.sequence + 1n });
    const options = { expectedPublicKey, runMode };
    if (event.kind === "VERIFICATION_PASSED") {
      const publication = await dependencies.readVerifierPublication({ subjectRun: event.subjectRun });
      if (publication === null || !verifierPublicationMatchesEvent(publication, event)) invalid();
      options.verifierPublicationVerified = true;
    }
    try {
      view = reduceReleaseEvent(view, event, options);
    } catch {
      invalid();
    }
  }
  return Object.freeze({ events: Object.freeze([...events]), view });
}

async function assertDurableVerifierCheckpoint({ dependencies, persisted, release, subjectRun }) {
  if (typeof dependencies.readVerifiedRawEvents !== "function") invalid();
  const action = subjectRun === "rehearsal" ? "REHEARSAL_VERDICT" : "STAKEHOLDER_VERDICT";
  const checkpoint = persisted.checkpoints.filter((entry) =>
    entry.action === action &&
    entry.role === "operator" &&
    entry.subjectRun === subjectRun &&
    entry.status === "EVENT_APPENDED",
  ).at(-1);
  if (checkpoint === undefined || checkpoint.artifactDigest === null || checkpoint.eventDigest === null) invalid();
  const events = checkedAuthenticatedEvents(
    await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
    release,
  );
  const matching = events.filter((event) =>
    event.kind === "VERIFICATION_PASSED" &&
    event.role === "operator" &&
    event.subjectRun === subjectRun &&
    event.artifactDigest === checkpoint.artifactDigest &&
    event.eventDigest === checkpoint.eventDigest,
  );
  if (matching.length !== 1) invalid();
}

async function storeDescriptor({ dependencies, persisted, release, releaseRoot, subjectRun, action }) {
  if (typeof dependencies.createDescriptor !== "function" || typeof dependencies.validateArtifact !== "function") invalid();
  const child = persisted.checkpoints.filter((entry) => entry.action === action && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (child?.status !== "CHILD_COMPLETE" || child.artifactDigest === null) invalid();
  const bytes = await dependencies.createDescriptor({
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    sessionId: release.sessionId,
    subjectRun,
  });
  if (!Buffer.isBuffer(bytes) || digest(bytes) !== child.artifactDigest) invalid();
  const artifact = await dependencies.validateArtifact({ artifactType: "signed-descriptor", bytes, expectedDigest: child.artifactDigest, secretCanaries: [] });
  const descriptor = artifact?.facts?.descriptor;
  if (artifact?.digest !== child.artifactDigest || !isPlainObject(descriptor) || descriptor.paymentMoved !== false || descriptor.repositorySha !== release.repositorySha || !/^[0-9a-f]{32}$/.test(descriptor.sessionId)) invalid();
  const stored = await dependencies.putArtifact({ artifactType: "signed-descriptor", bytes, expectedDigest: child.artifactDigest });
  if (stored?.digest !== child.artifactDigest) invalid();
  const state = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action, artifactDigest: child.artifactDigest, eventDigest: null, role: "operator", status: "ARTIFACT_STORED", subjectRun })], release, state: subjectRun === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY" });
  await dependencies.writeState({ releaseRoot, state });
  return state;
}

async function appendDescriptorReady({ dependencies, persisted, release, releaseRoot, subjectRun, action }) {
  const stored = persisted.checkpoints.filter((entry) => entry.action === action && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (stored?.status !== "ARTIFACT_STORED" || stored.artifactDigest === null) invalid();
  const kind = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY";
  const returned = await adoptOrAppendOperatorEvent({ dependencies, input: { artifactDigest: stored.artifactDigest, kind, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun }, release });
  if (returned.kind !== kind || returned.role !== "operator" || returned.subjectRun !== subjectRun || returned.artifactDigest !== stored.artifactDigest || returned.paymentMoved !== false || returned.releaseId !== release.releaseId || returned.repositorySha !== release.repositorySha || returned.sessionId !== release.sessionId || !SHA256_PATTERN.test(returned.eventDigest)) invalid();
  const state = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action, artifactDigest: stored.artifactDigest, eventDigest: returned.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun })], release, state: subjectRun === "rehearsal" ? "REHEARSAL_IDENTITIES_READY" : "STAKEHOLDER_IDENTITIES_READY" });
  await dependencies.writeState({ releaseRoot, state });
  return state;
}

async function awaitDescriptorAcceptance({ dependencies, persisted, release, releaseRoot, subjectRun, action }) {
  if (typeof dependencies.readVerifiedRawEvents !== "function" || typeof dependencies.waitForDescriptorAcceptance !== "function") invalid();
  const event = persisted.checkpoints.filter((entry) => entry.action === action && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (event?.status !== "EVENT_APPENDED" || event.artifactDigest === null || event.eventDigest === null) invalid();
  const kind = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY";
  const assertReplay = (entries) => {
    const events = checkedAuthenticatedEvents(entries, release);
    const ready = events.filter((item) => item.kind === kind && item.role === "operator" && item.subjectRun === subjectRun);
    if (ready.length !== 1 || ready[0].eventDigest !== event.eventDigest || ready[0].artifactDigest !== event.artifactDigest) invalid();
    const accepted = events.filter((item) => item.kind === "DESCRIPTOR_ACCEPTED" && item.subjectRun === subjectRun);
    if (accepted.length !== 2 || new Set(accepted.map((item) => item.role)).size !== 2 || accepted.some((item) => !["payee", "payer"].includes(item.role) || item.artifactDigest !== event.artifactDigest)) invalid();
  };
  const initial = await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId });
  checkedAuthenticatedEvents(initial, release);
  await dependencies.waitForDescriptorAcceptance({ artifactDigest: event.artifactDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun });
  assertReplay(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }));
  const state = descriptorState({ checkpoints: persisted.checkpoints, release, state: subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY" });
  await dependencies.writeState({ releaseRoot, state });
  return state;
}

async function beginRoles({ dependencies, persisted, release, releaseRoot, subjectRun }) {
  for (const key of RUN_ORCHESTRATION_DEPENDENCY_KEYS.filter((key) => !["createVerifiedEvent", "readVerifiedRawEvents", "validateRehearsalPackage"].includes(key))) if (typeof dependencies[key] !== "function") invalid();
  const descriptorAction = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR" : "STAKEHOLDER_DESCRIPTOR";
  const startAction = subjectRun === "rehearsal" ? "START_REHEARSAL" : "START_STAKEHOLDER";
  const descriptorKind = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY";
  const readyState = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR_READY" : "STAKEHOLDER_DESCRIPTOR_READY";
  const packageState = subjectRun === "rehearsal" ? "REHEARSAL_PACKAGES_READY" : "STAKEHOLDER_PACKAGES_READY";
  const descriptor = persisted.checkpoints.filter((entry) => entry.action === descriptorAction && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (descriptor?.status !== "EVENT_APPENDED" || descriptor.artifactDigest === null || descriptor.eventDigest === null) invalid();
  const replay = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release);
  const ready = replay.filter((item) => item.kind === descriptorKind && item.role === "operator" && item.subjectRun === subjectRun);
  const accepted = replay.filter((item) => item.kind === "DESCRIPTOR_ACCEPTED" && item.subjectRun === subjectRun);
  if (ready.length !== 1 || ready[0].eventDigest !== descriptor.eventDigest || ready[0].artifactDigest !== descriptor.artifactDigest || accepted.length !== 2 || new Set(accepted.map((item) => item.role)).size !== 2 || accepted.some((item) => !["payee", "payer"].includes(item.role) || item.artifactDigest !== descriptor.artifactDigest)) invalid();
  const started = persisted.checkpoints.filter((entry) => entry.action === startAction && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  let afterStart = persisted;
  if (started === undefined) {
    const returned = await adoptOrAppendOperatorEvent({ dependencies, input: { artifactDigest: null, kind: startAction, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun }, release });
    if (returned.kind !== startAction || returned.role !== "operator" || returned.subjectRun !== subjectRun || returned.artifactDigest !== null || returned.releaseId !== release.releaseId || returned.repositorySha !== release.repositorySha || returned.sessionId !== release.sessionId || returned.paymentMoved !== false || !SHA256_PATTERN.test(returned.eventDigest)) invalid();
    const state = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: startAction, artifactDigest: descriptor.artifactDigest, eventDigest: returned.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun })], release, state: readyState });
    await dependencies.writeState({ releaseRoot, state });
    afterStart = state;
  } else {
    const startEvents = replay.filter((item) => item.kind === startAction && item.role === "operator" && item.subjectRun === subjectRun);
    if (started.status !== "EVENT_APPENDED" || started.artifactDigest !== descriptor.artifactDigest || started.eventDigest === null || startEvents.length !== 1 || startEvents[0].eventDigest !== started.eventDigest || startEvents[0].artifactDigest !== null) invalid();
  }
  async function start(role) {
    const action = role === "payee" ? "PAYEE_ROLE_START" : "PAYER_ROLE_START";
    let current = afterStart.checkpoints.filter((entry) => entry.action === action && entry.role === role && entry.subjectRun === subjectRun).at(-1);
    if (current?.status === "BEFORE_CHILD") {
      const proven = checkedAuthenticatedEvents(
        await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
        release,
      ).filter((item) =>
        item.kind === "ROLE_STARTED" &&
        item.role === role &&
        item.subjectRun === subjectRun &&
        item.artifactDigest === null,
      );
      // A persisted intent is deliberately not permission to launch again.
      // Only the signed relay effect proves that the original child escaped.
      if (proven.length !== 1) invalid();
      afterStart = descriptorState({
        checkpoints: [
          ...afterStart.checkpoints,
          Object.freeze({ action, artifactDigest: descriptor.artifactDigest, eventDigest: null, role, status: "CHILD_COMPLETE", subjectRun }),
          Object.freeze({ action: "ROLE_STARTED", artifactDigest: descriptor.artifactDigest, eventDigest: proven[0].eventDigest, role, status: "EVENT_APPENDED", subjectRun }),
        ],
        release,
        state: readyState,
      });
      await dependencies.writeState({ releaseRoot, state: afterStart });
      current = afterStart.checkpoints.filter((entry) => entry.action === action && entry.role === role && entry.subjectRun === subjectRun).at(-1);
    }
    if (current?.status !== "CHILD_COMPLETE") {
      const before = descriptorState({ checkpoints: [...afterStart.checkpoints, Object.freeze({ action, artifactDigest: descriptor.artifactDigest, eventDigest: null, role, status: "BEFORE_CHILD", subjectRun })], release, state: readyState });
      await dependencies.writeState({ releaseRoot, state: before });
      await dependencies.startRole({ artifactDigest: descriptor.artifactDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, role, sessionId: release.sessionId, subjectRun });
      afterStart = descriptorState({ checkpoints: [...before.checkpoints, Object.freeze({ action, artifactDigest: descriptor.artifactDigest, eventDigest: null, role, status: "CHILD_COMPLETE", subjectRun })], release, state: readyState });
      await dependencies.writeState({ releaseRoot, state: afterStart });
    }
    const observed = afterStart.checkpoints.filter((entry) => entry.action === "ROLE_STARTED" && entry.role === role && entry.subjectRun === subjectRun).at(-1);
    if (observed?.status !== "EVENT_APPENDED") {
      await dependencies.waitForRoleStarted({ artifactDigest: descriptor.artifactDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, role, sessionId: release.sessionId, subjectRun });
      const matching = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release).filter((item) => item.kind === "ROLE_STARTED" && item.role === role && item.subjectRun === subjectRun && item.artifactDigest === null);
      if (matching.length !== 1) invalid();
      afterStart = descriptorState({ checkpoints: [...afterStart.checkpoints, Object.freeze({ action: "ROLE_STARTED", artifactDigest: descriptor.artifactDigest, eventDigest: matching[0].eventDigest, role, status: "EVENT_APPENDED", subjectRun })], release, state: readyState });
      await dependencies.writeState({ releaseRoot, state: afterStart });
    }
  }
  await start("payee");
  await start("payer");
  for (const role of ["payee", "payer"]) {
    const current = afterStart.checkpoints.filter((entry) => entry.action === "ROLE_PACKAGE" && entry.role === role && entry.subjectRun === subjectRun).at(-1);
    if (current?.status === "EVENT_APPENDED") continue;
    await dependencies.waitForRolePackage({ artifactDigest: descriptor.artifactDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, role, sessionId: release.sessionId, subjectRun });
    const matching = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release).filter((item) => item.kind === "ROLE_PACKAGE_READY" && item.role === role && item.subjectRun === subjectRun && item.artifactDigest !== null);
    if (matching.length !== 1 || !SHA256_PATTERN.test(matching[0].artifactDigest)) invalid();
    const bytes = await dependencies.getArtifact({ artifactType: "party-result-package", digest: matching[0].artifactDigest });
    if (!Buffer.isBuffer(bytes)) invalid();
    const artifact = await dependencies.validateArtifact({ artifactType: "party-result-package", bytes, expectedDigest: matching[0].artifactDigest, secretCanaries: [] });
    const party = artifact?.facts?.partyResult;
    if (artifact?.digest !== matching[0].artifactDigest || !isPlainObject(party) || party.role !== role || party.repositorySha !== release.repositorySha || !SHA256_PATTERN.test(party.sessionDigest) || party.paymentMoved !== false) invalid();
    if (typeof dependencies.validateRehearsalPackage !== "function" || await dependencies.validateRehearsalPackage({ artifactDigest: matching[0].artifactDigest, bytes, descriptorDigest: descriptor.artifactDigest, party, release: Object.freeze({ releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId }), role, subjectRun }) !== true) invalid();
    afterStart = descriptorState({ checkpoints: [...afterStart.checkpoints, Object.freeze({ action: "ROLE_PACKAGE", artifactDigest: matching[0].artifactDigest, eventDigest: matching[0].eventDigest, role, status: "EVENT_APPENDED", subjectRun })], release, state: readyState });
    await dependencies.writeState({ releaseRoot, state: afterStart });
  }
  const complete = descriptorState({ checkpoints: afterStart.checkpoints, release, state: packageState });
  await dependencies.writeState({ releaseRoot, state: complete });
  return complete;
}

export function validateVerifierChildResult(input) {
  const value = exact(input, VERIFIER_RESULT_KEYS);
  if (
    value.exitCode !== 0 ||
    value.status !== SUCCESS_STATUS ||
    typeof value.publicationDigest !== "string" ||
    !SHA256_PATTERN.test(value.publicationDigest) ||
    value.stdout !== "" ||
    value.stderr !== ""
  ) invalid();
  return Object.freeze({
    publicationDigest: value.publicationDigest,
    status: SUCCESS_STATUS,
  });
}

async function verifyRun({ dependencies, persisted, release, releaseRoot, subjectRun }) {
  for (const key of ["appendVerifiedEvent", "createVerifiedEvent", "launchVerifier", "readVerifiedRawEvents", "validatePublishedBilateralVerdict"]) if (typeof dependencies[key] !== "function") invalid();
  const descriptorAction = subjectRun === "rehearsal" ? "REHEARSAL_DESCRIPTOR" : "STAKEHOLDER_DESCRIPTOR";
  const verdictAction = subjectRun === "rehearsal" ? "REHEARSAL_VERDICT" : "STAKEHOLDER_VERDICT";
  const packageState = subjectRun === "rehearsal" ? "REHEARSAL_PACKAGES_READY" : "STAKEHOLDER_PACKAGES_READY";
  const verifiedState = subjectRun === "rehearsal" ? "REHEARSAL_VERIFIED" : "STAKEHOLDER_VERIFIED";
  const descriptor = persisted.checkpoints.find((entry) => entry.action === descriptorAction && entry.role === "operator" && entry.subjectRun === subjectRun && entry.status === "EVENT_APPENDED");
  const packages = Object.fromEntries(["payee", "payer"].map((role) => {
    const entry = persisted.checkpoints.find((candidate) => candidate.action === "ROLE_PACKAGE" && candidate.role === role && candidate.subjectRun === subjectRun && candidate.status === "EVENT_APPENDED");
    return [role, entry?.artifactDigest];
  }));
  if (descriptor?.artifactDigest === null || !SHA256_PATTERN.test(packages.payee) || !SHA256_PATTERN.test(packages.payer)) invalid();
  const existing = persisted.checkpoints.filter((entry) => entry.action === verdictAction && entry.role === "operator" && entry.subjectRun === subjectRun).at(-1);
  if (existing?.status === "EVENT_APPENDED") {
    const replay = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release);
    const matched = replay.filter((event) => event.kind === "VERIFICATION_PASSED" && event.role === "operator" && event.subjectRun === subjectRun && event.eventDigest === existing.eventDigest && event.artifactDigest === existing.artifactDigest);
    if (matched.length !== 1) invalid();
    const verified = descriptorState({ checkpoints: persisted.checkpoints, release, state: verifiedState });
    await dependencies.writeState({ releaseRoot, state: verified });
    if (typeof dependencies.writeConsoleState === "function") {
      await dependencies.writeConsoleState({
        lifecycleView: verified,
        subjectRun,
      });
    }
    return verified;
  }
  let state = persisted;
  const outputDirectory = join(releaseRoot, "verifier", subjectRun);
  let publicationDigest;
  if (existing?.status === "BEFORE_CHILD") {
    const replay = checkedAuthenticatedEvents(
      await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
      release,
    );
    const proven = replay.filter((event) =>
      event.kind === "VERIFICATION_PASSED" &&
      event.role === "operator" &&
      event.subjectRun === subjectRun &&
      SHA256_PATTERN.test(event.artifactDigest),
    );
    // A verifier process may have escaped before writing its local result.
    // Its signed, publication-backed relay event is the sole safe adoption
    // proof; otherwise a second launch would be an ambiguous duplicate.
    if (proven.length !== 1) invalid();
    state = descriptorState({
      checkpoints: [...persisted.checkpoints, Object.freeze({ action: verdictAction, artifactDigest: proven[0].artifactDigest, eventDigest: proven[0].eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun })],
      release,
      state: packageState,
    });
    await dependencies.writeState({ releaseRoot, state });
    return verifyRun({ dependencies, persisted: state, release, releaseRoot, subjectRun });
  }
  if (existing === undefined) {
    state = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: verdictAction, artifactDigest: descriptor.artifactDigest, eventDigest: null, role: "operator", status: "BEFORE_CHILD", subjectRun })], release, state: packageState });
    await dependencies.writeState({ releaseRoot, state });
    const launched = exact(await dependencies.launchVerifier({ descriptorDigest: descriptor.artifactDigest, outputDirectory, packageDigests: Object.freeze(packages), releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun }), ["outputDirectory", "result"]);
    if (launched.outputDirectory !== outputDirectory) invalid();
    const child = validateVerifierChildResult(launched.result);
    publicationDigest = child.publicationDigest;
    state = descriptorState({ checkpoints: [...state.checkpoints, Object.freeze({ action: verdictAction, artifactDigest: publicationDigest, eventDigest: null, role: "operator", status: "CHILD_COMPLETE", subjectRun })], release, state: packageState });
    await dependencies.writeState({ releaseRoot, state });
  } else if (existing.status === "CHILD_COMPLETE" || existing.status === "VERDICT_VALIDATED") {
    if (!SHA256_PATTERN.test(existing.artifactDigest)) invalid();
    publicationDigest = existing.artifactDigest;
  } else {
    invalid();
  }
  const publication = exact(
    await dependencies.validatePublishedBilateralVerdict({
      outputDirectory,
      packageDigests: Object.freeze(packages),
      publicationDigest,
      releaseId: release.releaseId,
      repositorySha: release.repositorySha,
      sessionId: release.sessionId,
      subjectRun,
    }),
    VERIFIER_PUBLICATION_KEYS,
  );
  if (
    publication.paymentMoved !== false ||
    publication.publicationDigest !== publicationDigest ||
    publication.releaseId !== release.releaseId ||
    publication.repositorySha !== release.repositorySha ||
    publication.schema !== VERIFIER_PUBLICATION_SCHEMA ||
    publication.sessionId !== release.sessionId ||
    publication.status !== SUCCESS_STATUS ||
    publication.subjectRun !== subjectRun
  ) invalid();
  if (existing?.status !== "VERDICT_VALIDATED") {
    state = descriptorState({ checkpoints: [...state.checkpoints, Object.freeze({ action: verdictAction, artifactDigest: publicationDigest, eventDigest: null, role: "operator", status: "VERDICT_VALIDATED", subjectRun })], release, state: packageState });
    await dependencies.writeState({ releaseRoot, state });
  }
  const event = exact(await dependencies.createVerifiedEvent({ artifactDigest: publicationDigest, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun }), AUTHENTICATED_EVENT_KEYS);
  if (event.kind !== "VERIFICATION_PASSED" || event.role !== "operator" || event.subjectRun !== subjectRun || event.artifactDigest !== publicationDigest || event.paymentMoved !== false || !SHA256_PATTERN.test(event.eventDigest)) invalid();
  const replay = checkedAuthenticatedEvents(
    await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
    release,
  );
  const adopted = replay.filter((candidate) => candidate.eventDigest === event.eventDigest && candidate.kind === "VERIFICATION_PASSED" && candidate.role === "operator" && candidate.subjectRun === subjectRun && candidate.artifactDigest === publicationDigest);
  if (adopted.length > 1) invalid();
  if (adopted.length === 0) {
    // The atomic relay write response is only an acknowledgement.  Re-read the
    // signed log (which also rechecks the durable verifier publication) before
    // accepting the event as authority.
    await dependencies.appendVerifiedEvent({ event, publication });
  }
  const appendedReplay = checkedAuthenticatedEvents(
    await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }),
    release,
  ).filter((candidate) =>
    candidate.eventDigest === event.eventDigest &&
    candidate.kind === "VERIFICATION_PASSED" &&
    candidate.role === "operator" &&
    candidate.subjectRun === subjectRun &&
    candidate.artifactDigest === publicationDigest,
  );
  if (appendedReplay.length !== 1) invalid();
  const appended = appendedReplay[0];
  state = descriptorState({ checkpoints: [...state.checkpoints, Object.freeze({ action: verdictAction, artifactDigest: publicationDigest, eventDigest: appended.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun })], release, state: packageState });
  await dependencies.writeState({ releaseRoot, state });
  return verifyRun({ dependencies, persisted: state, release, releaseRoot, subjectRun });
}

async function completeRelease({ dependencies, persisted, release, releaseRoot }) {
  if (typeof dependencies.appendOperatorEvent !== "function" || typeof dependencies.readVerifiedRawEvents !== "function") invalid();
  const existing = persisted.checkpoints.filter((entry) => entry.action === "COMPLETE_RELEASE" && entry.role === "operator" && entry.subjectRun === "release").at(-1);
  if (existing?.status === "EVENT_APPENDED") {
    const events = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release);
    const matching = events.filter((event) => event.kind === "COMPLETE_RELEASE" && event.role === "operator" && event.subjectRun === "release" && event.eventDigest === existing.eventDigest && event.artifactDigest === null);
    if (matching.length !== 1) invalid();
    // The verified completion event is relay authority, but the operator's
    // terminal gate reads only the durable state file.  Persist COMPLETE so a
    // process exit or restart cannot strand the release at STAKEHOLDER_VERIFIED.
    const state = descriptorState({ checkpoints: persisted.checkpoints, release, state: "COMPLETE" });
    await dependencies.writeState({ releaseRoot, state });
    return state;
  }
  if (existing !== undefined) invalid();
  const returned = await adoptOrAppendOperatorEvent({ dependencies, input: { artifactDigest: null, kind: "COMPLETE_RELEASE", releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun: "release" }, release });
  if (returned.kind !== "COMPLETE_RELEASE" || returned.role !== "operator" || returned.subjectRun !== "release" || returned.artifactDigest !== null || returned.paymentMoved !== false || returned.releaseId !== release.releaseId || returned.repositorySha !== release.repositorySha || returned.sessionId !== release.sessionId || !SHA256_PATTERN.test(returned.eventDigest)) invalid();
  const state = descriptorState({ checkpoints: [...persisted.checkpoints, Object.freeze({ action: "COMPLETE_RELEASE", artifactDigest: null, eventDigest: returned.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" })], release, state: "STAKEHOLDER_VERIFIED" });
  await dependencies.writeState({ releaseRoot, state });
  return completeRelease({ dependencies, persisted: state, release, releaseRoot });
}

async function admitFundingLifecycle({ dependencies, persisted, release, releaseRoot }) {
  let state = persisted ?? descriptorState({ checkpoints: [], release, state: "ADDRESSES_READY" });
  for (const [action, kind] of [["ENROLLMENT_RECEIPT", "ENROLLMENT_RECEIPT"], ["WAIT_FOR_FUNDING", "WAIT_FOR_FUNDING"]]) {
    const current = state.checkpoints.filter((entry) => entry.action === action && entry.role === "operator" && entry.subjectRun === "release").at(-1);
    if (current?.status === "EVENT_APPENDED") continue;
    if (current !== undefined) invalid();
    const event = await adoptOrAppendOperatorEvent({
      dependencies,
      input: { artifactDigest: null, kind, releaseId: release.releaseId, repositorySha: release.repositorySha, sessionId: release.sessionId, subjectRun: "release" },
      release,
    });
    if (event.kind !== kind || event.role !== "operator" || event.subjectRun !== "release" || event.artifactDigest !== null || event.releaseId !== release.releaseId || event.repositorySha !== release.repositorySha || event.sessionId !== release.sessionId || event.paymentMoved !== false || !SHA256_PATTERN.test(event.eventDigest)) invalid();
    state = descriptorState({ checkpoints: [...state.checkpoints, Object.freeze({ action, artifactDigest: null, eventDigest: event.eventDigest, role: "operator", status: "EVENT_APPENDED", subjectRun: "release" })], release, state: "ADDRESSES_READY" });
    await dependencies.writeState({ releaseRoot, state });
  }
  return state;
}

async function assertRoleFundingReadiness({ dependencies, release }) {
  if (typeof dependencies.now !== "function" || typeof dependencies.readVerifiedRawEvents !== "function" || typeof dependencies.sleeper !== "function") invalid();
  let attempts = 0;
  let deadline;
  for (;;) {
    const events = checkedAuthenticatedEvents(await dependencies.readVerifiedRawEvents({ sessionId: release.sessionId }), release);
    let complete = true;
    for (const [kind, artifact] of [["ENROLLMENT_CONFIRMED", null], ["FUNDING_INPUTS_READY", null], ["TOKEN_READY", "digest"]]) {
      const matching = events.filter((event) => event.kind === kind && event.subjectRun === "release");
      if (matching.length > 2 || new Set(matching.map((event) => event.role)).size !== matching.length || matching.some((event) => !["payer", "payee"].includes(event.role) || (artifact === null ? event.artifactDigest !== null : !SHA256_PATTERN.test(event.artifactDigest)))) invalid();
      if (matching.length !== 2) complete = false;
    }
    if (complete) return events;
    const current = dependencies.now();
    if (!Number.isSafeInteger(current) || current < 0) invalid();
    deadline ??= current + FUNDING_READINESS_DEADLINE_MS;
    if (current >= deadline || attempts >= FUNDING_READINESS_DEADLINE_MS / FUNDING_READINESS_INTERVAL_MS) invalid();
    attempts += 1;
    await dependencies.sleeper(Math.min(FUNDING_READINESS_INTERVAL_MS, Math.max(1, deadline - current)));
  }
}

async function waitForAdvisoryEnrollmentReadiness({ dependencies }) {
  if (typeof dependencies.now !== "function" || typeof dependencies.readSessionView !== "function" || typeof dependencies.sleeper !== "function") invalid();
  let attempts = 0;
  let deadline;
  let previous;
  for (;;) {
    const current = dependencies.now();
    if (!Number.isSafeInteger(current) || current < 0 || (previous !== undefined && current < previous)) invalid();
    previous = current;
    deadline ??= current + FUNDING_READINESS_DEADLINE_MS;
    let view;
    try {
      view = await dependencies.readSessionView();
    } catch (error) {
      if (error?.code !== ADVISORY_SESSION_NOT_FOUND_CODE) throw error;
      view = null;
    }
    if (view === null) {
      if (current >= deadline || attempts >= FUNDING_READINESS_DEADLINE_MS / FUNDING_READINESS_INTERVAL_MS) invalid();
      attempts += 1;
      await dependencies.sleeper(Math.min(FUNDING_READINESS_INTERVAL_MS, Math.max(1, deadline - current)));
      continue;
    }
    if (!isPlainObject(view) || view.paymentMoved !== false || !isPlainObject(view.facts) || !isPlainObject(view.facts.enrollmentConfirmed)) invalid();
    const confirmed = view.facts.enrollmentConfirmed;
    if (confirmed.payee === true && confirmed.payer === true) return;
    if (confirmed.payee !== false && confirmed.payee !== true) invalid();
    if (confirmed.payer !== false && confirmed.payer !== true) invalid();
    if (current >= deadline || attempts >= FUNDING_READINESS_DEADLINE_MS / FUNDING_READINESS_INTERVAL_MS) invalid();
    attempts += 1;
    await dependencies.sleeper(Math.min(FUNDING_READINESS_INTERVAL_MS, Math.max(1, deadline - current)));
  }
}

export async function createCoordinatorRelease(input) {
  const keys = isPlainObject(input) && Reflect.ownKeys(input).includes("dependencies")
    ? RELEASE_INPUT_KEYS_WITH_DEPENDENCIES
    : RELEASE_INPUT_KEYS;
  const value = exact(input, keys);
  if (
    typeof value.operatorKeyId !== "string" ||
    value.operatorKeyId.length === 0 ||
    typeof value.relayUrl !== "string" ||
    typeof value.releaseRoot !== "string" ||
    value.releaseRoot.length === 0 ||
    typeof value.tlsCertificatePem !== "string" ||
    value.tlsCertificatePem.length === 0 ||
    typeof value.tlsFingerprint !== "string" ||
    !SHA256_PATTERN.test(value.tlsFingerprint) ||
    typeof value.repositorySha !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value.repositorySha)
  ) invalid();
  const defaults = {
    createLaunchManifest,
    fileSystem: defaultFileSystem,
    now: Date.now,
    randomBytes,
    randomUUID,
    writeLaunchManifest: async (path, manifest) =>
      writePrivateLaunchManifest(path, manifest),
  };
  if (value.dependencies === undefined) invalid();
  const injected = exactSubset(value.dependencies, RELEASE_DEPENDENCY_KEYS);
  if (typeof injected.registerCapabilitySet !== "function" || typeof injected.prepareCapabilityRegistration !== "function") invalid();
  const dependencies = { ...defaults, ...injected };
  if (dependencies.writeState === undefined) {
    dependencies.writeState = ({ releaseRoot, state }) => writePublicState({
      fileSystem: dependencies.fileSystem,
      random: dependencies.randomBytes,
      releaseRoot,
      state,
    });
  }
  for (const key of RELEASE_DEPENDENCY_KEYS.filter((key) => key !== "fileSystem")) {
    if (typeof dependencies[key] !== "function") invalid();
  }
  readStateFileSystem(dependencies.fileSystem);
  const context = pendingContext({ operatorKeyId: value.operatorKeyId, relayUrl: value.relayUrl, repositorySha: value.repositorySha, tlsCertificatePem: value.tlsCertificatePem, tlsFingerprint: value.tlsFingerprint });
  const pendingPath = join(value.releaseRoot, CAPABILITY_PENDING_FILE_NAME);
  await rejectStalePendingTemporaries({ fileSystem: dependencies.fileSystem, releaseRoot: value.releaseRoot });
  let journal;
  const pendingBytes = await readPrivateFile(pendingPath, dependencies.fileSystem, MAX_PENDING_BYTES);
  if (pendingBytes !== null) {
    let parsed;
    try { parsed = JSON.parse(pendingBytes.toString("utf8")); } catch { invalid(); }
    if (!pendingBytes.equals(canonicalPrivateBytes(parsed, MAX_PENDING_BYTES))) invalid();
    journal = pendingJournal(parsed, context, { parsedManifests: true });
  } else {
    const sessionId = dependencies.randomUUID();
    const releaseId = `release-${digest(Buffer.from(sessionId, "utf8")).slice(0, 16)}`;
    const nowMs = dependencies.now();
    let payerMcpIntakeCapability;
    try { payerMcpIntakeCapability = dependencies.randomBytes(32); } catch { invalid(); }
    if (!Buffer.isBuffer(payerMcpIntakeCapability) || payerMcpIntakeCapability.length !== 32) invalid();
    const payerMcpIntakeCapabilityHex = payerMcpIntakeCapability.toString("hex");
    const payerMcpIntakeCapabilityDigest = digest(payerMcpIntakeCapability);
    const generated = ["payee", "payer"].map((role) => dependencies.createLaunchManifest({
      expectedTlsFingerprint: value.tlsFingerprint,
      nowMs,
      operatorKeyId: value.operatorKeyId,
      ...(role === "payee"
        ? { payerMcpIntakeCapability: payerMcpIntakeCapabilityHex }
        : { payerMcpIntakeCapabilityDigest }),
      randomBytes: dependencies.randomBytes,
      relayUrl: value.relayUrl,
      releaseId,
      repositorySha: value.repositorySha,
      role,
      sessionId,
      tlsCertificatePem: value.tlsCertificatePem,
    }));
    const draftEntries = generated.map(({ capabilityDigest, manifest }) => ({ capabilityDigest, manifest, role: manifest.role }));
    const capabilities = { payee: { capabilityDigest: draftEntries[0].capabilityDigest, expiresAtMs: draftEntries[0].manifest.expiresAtMs }, payer: { capabilityDigest: draftEntries[1].capabilityDigest, expiresAtMs: draftEntries[1].manifest.expiresAtMs } };
    let registration;
    try { registration = await dependencies.prepareCapabilityRegistration({ capabilities }); } catch { invalid(); }
    journal = pendingJournal({ context, entries: draftEntries, receipt: null, registration, schema: CAPABILITY_PENDING_SCHEMA }, context);
    await writeNewPrivateFile({ fileSystem: dependencies.fileSystem, path: pendingPath, random: dependencies.randomBytes, releaseRoot: value.releaseRoot, value: journal });
  }
  const releaseId = journal.registration.releaseId;
  const sessionId = journal.registration.sessionId;
  const entries = journal.entries.map((entry) => ({ ...entry, path: join(value.releaseRoot, `${entry.role}.launch.json`) }));
  if (
    entries.length !== 2 ||
    entries[0].role !== "payee" ||
    entries[1].role !== "payer" ||
    entries[0].capabilityDigest === entries[1].capabilityDigest ||
    entries[0].manifest.bootstrapCapability ===
      entries[1].manifest.bootstrapCapability
  ) invalid();
  validateMcpIntakePair(entries);
  for (const entry of entries) {
    if (
      !SHA256_PATTERN.test(entry.capabilityDigest) ||
      entry.manifest.role !== entry.role ||
      entry.manifest.releaseId !== releaseId ||
      entry.manifest.sessionId !== sessionId ||
      entry.manifest.repositorySha !== value.repositorySha ||
      entry.manifest.operatorKeyId !== value.operatorKeyId ||
      entry.manifest.expectedTlsFingerprint !== value.tlsFingerprint ||
      entry.manifest.tlsCertificatePem !== value.tlsCertificatePem
    ) invalid();
  }
  let receipt = journal.receipt;
  if (receipt === null) {
    try { receipt = capabilitySetReceipt(await dependencies.registerCapabilitySet({ registration: journal.registration }), journal.registration); } catch { invalid(); }
    journal = deepFreeze({ ...journal, receipt });
    await replacePrivateFile({ fileSystem: dependencies.fileSystem, path: pendingPath, random: dependencies.randomBytes, releaseRoot: value.releaseRoot, value: journal });
  }
  const publicState = deepFreeze({
    capabilityDigests: entries.map(({ capabilityDigest }) => capabilityDigest),
    checkpoints: [],
    paymentMoved: false,
    releaseId,
    repositorySha: value.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId,
    state: "BOOTSTRAPPING",
  });
  const existingPublicState = await readCoordinatorPublicState(join(value.releaseRoot, STATE_FILE_NAME), dependencies.fileSystem);
  if (existingPublicState !== null && !sameCanonical(existingPublicState, publicState)) invalid();
  for (const entry of entries) {
    const exists = await existingManifestMatches({ fileSystem: dependencies.fileSystem, manifest: entry.manifest, path: entry.path });
    if (!exists) await dependencies.writeLaunchManifest(entry.path, entry.manifest);
    if (await readPrivateFile(entry.path, dependencies.fileSystem, MAX_PENDING_BYTES) !== null && !(await existingManifestMatches({ fileSystem: dependencies.fileSystem, manifest: entry.manifest, path: entry.path }))) invalid();
  }
  if (existingPublicState === null) await dependencies.writeState({ releaseRoot: value.releaseRoot, state: publicState });
  await unlinkPrivateFile({ fileSystem: dependencies.fileSystem, path: pendingPath, releaseRoot: value.releaseRoot });
  return deepFreeze({
    capabilityDigests: entries.map(({ capabilityDigest }) => capabilityDigest),
    checkpoints: [],
    manifests: entries,
    paymentMoved: false,
    releaseId,
    repositorySha: value.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId,
    state: "BOOTSTRAPPING",
  });
}

export async function runCoordinator(input) {
  const value = exact(
    input,
    isPlainObject(input) && Object.hasOwn(input, "runMode")
      ? RUN_INPUT_WITH_MODE_KEYS
      : RUN_INPUT_KEYS,
  );
  const runMode = normalizeRunMode(value.runMode);
  const release = value.release;
  const dependencies = exactSubset(value.dependencies, [
    ...RUN_DEPENDENCY_KEYS,
    ...REPLAY_DEPENDENCY_KEYS,
    ...PREFLIGHT_DEPENDENCY_KEYS,
    ...REHEARSAL_IDENTITY_DEPENDENCY_KEYS,
    ...RUN_ORCHESTRATION_DEPENDENCY_KEYS,
    ...RUN_OPTIONAL_DEPENDENCY_KEYS,
  ]);
  if (!isPlainObject(release) || release.schema !== COORDINATOR_STATE_SCHEMA || release.paymentMoved !== false || !Array.isArray(release.capabilityDigests) || release.capabilityDigests.length !== 2 || typeof value.releaseRoot !== "string" || value.releaseRoot.length === 0) invalid();
  for (const key of [...RUN_DEPENDENCY_KEYS, ...REPLAY_DEPENDENCY_KEYS]) {
    if (typeof dependencies[key] !== "function") invalid();
  }
  let persisted = await dependencies.readState({ releaseRoot: value.releaseRoot });
  if (persisted !== null) {
    const persistedState = exact(persisted, COORDINATOR_STATE_KEYS);
    checkpoints(persistedState.checkpoints);
    if (
      persistedState.schema !== COORDINATOR_STATE_SCHEMA ||
      persistedState.releaseId !== release.releaseId ||
      persistedState.repositorySha !== release.repositorySha ||
      persistedState.sessionId !== release.sessionId ||
      persistedState.paymentMoved !== false ||
      !COORDINATOR_STATES.has(persistedState.state)
    ) invalid();
  }
  await waitForAdvisoryEnrollmentReadiness({ dependencies });
  const enrollmentSetBytes = await dependencies.readEnrollmentSet();
  let enrollmentSet;
  try {
    enrollmentSet = parseCoordinationEnrollmentSet(enrollmentSetBytes);
  } catch {
    invalid();
  }
  if (
    enrollmentSet.paymentMoved !== false ||
    enrollmentSet.releaseId !== release.releaseId ||
    enrollmentSet.repositorySha !== release.repositorySha ||
    enrollmentSet.sessionId !== release.sessionId
  ) invalid();
  const enrollmentFor = (role) => {
    const entry = enrollmentSet?.enrollments?.[role];
    if (!isPlainObject(entry) || typeof entry.enrollmentBase64 !== "string") invalid();
    return parseCoordinationEnrollment(Buffer.from(entry.enrollmentBase64, "base64"));
  };
  const payee = enrollmentFor("payee");
  const payer = enrollmentFor("payer");
  const events = await dependencies.readEvents({ after: null, waitMs: 0 });
  if (!Array.isArray(events)) invalid();
  const replay = await authenticateCoordinatorReplay({
    dependencies,
    enrollments: Object.freeze({ payer, payee }),
    events,
    release,
    runMode,
  });
  if (replay.view.paymentMoved !== false) invalid();
  const authenticatedDependencies = Object.freeze({
    ...dependencies,
    readVerifiedRawEvents: async () => {
      const raw = await dependencies.readEvents({ after: null, waitMs: 0 });
      return (await authenticateCoordinatorReplay({
        dependencies,
        enrollments: Object.freeze({ payer, payee }),
        events: raw,
        release,
        runMode,
      })).events;
    },
  });
  assertReconciledPersistedState({ persisted, replay });
  const replayAdopted = adoptReplayState({ persisted, release, replay });
  if (replayAdopted !== persisted) {
    await dependencies.writeState({ releaseRoot: value.releaseRoot, state: replayAdopted });
    persisted = replayAdopted;
    return deepFreeze({ capabilityDigests: release.capabilityDigests, checkpoints: persisted.checkpoints, events: events.length, paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha, schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId, state: persisted.state });
  }
  const addresses = [payer.invitations.rehearsal.address, payee.invitations.rehearsal.address, payer.invitations.stakeholder.address, payee.invitations.stakeholder.address];
  if (
    addresses.some((address) => typeof address !== "string" || !/^0x[0-9a-f]{40}$/.test(address)) ||
    new Set(addresses).size !== 4
  ) invalid();
  if (runMode === "local-two-run" && ["REHEARSAL_VERIFIED", "STAKEHOLDER_IDENTITIES_READY", "STAKEHOLDER_DESCRIPTOR_READY", "STAKEHOLDER_PACKAGES_READY", "STAKEHOLDER_VERIFIED", "COMPLETE"].includes(persisted?.state)) {
    await assertDurableVerifierCheckpoint({ dependencies: authenticatedDependencies, persisted, release, subjectRun: "rehearsal" });
  }
  if (["STAKEHOLDER_VERIFIED", "COMPLETE"].includes(persisted?.state)) {
    await assertDurableVerifierCheckpoint({ dependencies: authenticatedDependencies, persisted, release, subjectRun: "stakeholder" });
  }
  if (persisted?.state === "FUNDING_READY") {
    return preflightPassed({
      dependencies: authenticatedDependencies,
      enrollmentSet,
      persisted,
      release,
      releaseRoot: value.releaseRoot,
    });
  }
  if (persisted?.state === "PREFLIGHT_PASSED") return runIdentities({ dependencies: authenticatedDependencies, enrollments: { payer, payee }, persisted, release, releaseRoot: value.releaseRoot, subjectRun: runMode === "aws-stakeholder-only" ? "stakeholder" : "rehearsal" });
  if (persisted?.state === "REHEARSAL_IDENTITIES_READY") {
    if (authenticatedDependencies.createDescriptor !== undefined) return beginDescriptor({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "rehearsal" });
    return deepFreeze({ capabilityDigests: release.capabilityDigests, checkpoints: persisted.checkpoints, events: events.length, paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha, schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId, state: "REHEARSAL_IDENTITIES_READY" });
  }
  if (persisted?.state === "REHEARSAL_DESCRIPTOR_READY") {
    if (authenticatedDependencies.startRole !== undefined) return beginRoles({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "rehearsal" });
    return deepFreeze({ capabilityDigests: release.capabilityDigests, checkpoints: persisted.checkpoints, events: events.length, paymentMoved: false, releaseId: release.releaseId, repositorySha: release.repositorySha, schema: COORDINATOR_STATE_SCHEMA, sessionId: release.sessionId, state: "REHEARSAL_DESCRIPTOR_READY" });
  }
  if (persisted?.state === "REHEARSAL_PACKAGES_READY") return verifyRun({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "rehearsal" });
  if (persisted?.state === "REHEARSAL_VERIFIED") return runIdentities({ dependencies: authenticatedDependencies, enrollments: { payer, payee }, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "stakeholder" });
  if (persisted?.state === "STAKEHOLDER_IDENTITIES_READY") return beginDescriptor({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "stakeholder" });
  if (persisted?.state === "STAKEHOLDER_DESCRIPTOR_READY") return beginRoles({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "stakeholder" });
  if (persisted?.state === "STAKEHOLDER_PACKAGES_READY") return verifyRun({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot, subjectRun: "stakeholder" });
  if (persisted?.state === "STAKEHOLDER_VERIFIED") return completeRelease({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot });
  if (persisted?.state === "COMPLETE") return completeRelease({ dependencies: authenticatedDependencies, persisted, release, releaseRoot: value.releaseRoot });
  let fundingState = persisted;
  if (persisted?.state !== "ADDRESSES_READY") {
    await dependencies.displayAddresses(addresses);
    fundingState = descriptorState({ checkpoints: [], release, state: "ADDRESSES_READY" });
    await dependencies.writeState({ releaseRoot: value.releaseRoot, state: fundingState });
  }
  fundingState = await admitFundingLifecycle({ dependencies: authenticatedDependencies, persisted: fundingState, release, releaseRoot: value.releaseRoot });
  const funding = await dependencies.waitForFunding(addresses);
  if (!Array.isArray(funding) || funding.length !== 4) invalid();
  for (let index = 0; index < addresses.length; index += 1) {
    fundingRecord(funding[index], addresses[index]);
  }
  await assertRoleFundingReadiness({ dependencies: authenticatedDependencies, release });
  const fundingReplay = await authenticateCoordinatorReplay({ dependencies, enrollments: Object.freeze({ payer, payee }), events: await dependencies.readEvents({ after: null, waitMs: 0 }), release, runMode });
  if (fundingReplay.view.state !== "FUNDING_READY") invalid();
  const readyState = descriptorState({ checkpoints: fundingState.checkpoints, release, state: "FUNDING_READY" });
  await dependencies.writeState({ releaseRoot: value.releaseRoot, state: readyState });
  const funded = deepFreeze({
    capabilityDigests: release.capabilityDigests,
    checkpoints: readyState.checkpoints,
    events: events.length,
    paymentMoved: false,
    releaseId: release.releaseId,
    repositorySha: release.repositorySha,
    schema: COORDINATOR_STATE_SCHEMA,
    sessionId: release.sessionId,
    state: "FUNDING_READY",
  });
  return funded;
}
