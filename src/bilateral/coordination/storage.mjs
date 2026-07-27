import {
  constants as fsConstants,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  unlink,
} from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";

import {
  canonicalizeReceiptEventValue,
} from "../../canonical.mjs";
import {
  SENSITIVE_KEY,
  assertSecretFree,
} from "../../redact.mjs";
import {
  eventDigest as coordinationEventDigest,
} from "./envelope.mjs";
import {
  validateRelayArtifact,
} from "./artifact.mjs";
import {
  parseCoordinationEnrollment,
} from "./enrollment.mjs";

export const COORDINATION_OWNER_LOCK_LIMITATION =
  "Node.js 22 provides no kernel advisory file lock; simultaneous removal of both hard-linked owner lease paths is outside this store's exclusion guarantee.";

const STORE_SCHEMA =
  "clockchain.bilateral-coordination-store/v1";
const OWNER_SCHEMA =
  "clockchain.bilateral-store-owner/v1";
const RECORD_SCHEMA =
  "clockchain.bilateral-coordination-record/v1";
const SNAPSHOT_SCHEMA =
  "clockchain.bilateral-coordination-snapshot/v1";
const RECEIPT_SCHEMA =
  "clockchain.bilateral-coordination-receipt/v1";
const METADATA_FILE = "metadata.json";
const JOURNAL_FILE = "journal.log";
const SNAPSHOT_FILE = "snapshot.json";
const SNAPSHOT_TEMP_FILE = ".snapshot.tmp";
const OWNER_FILE = ".store-owner.json";
const OWNER_GUARD_FILE = ".store-owner.guard";
const ARTIFACTS_DIRECTORY = "artifacts";
const MAX_METADATA_BYTES = 4_096;
const MAX_OWNER_BYTES = 1_024;
const MAX_SNAPSHOT_BYTES = 65_536;
const MAX_RECORD_BYTES = 262_144;
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;
const MAX_RECEIPT_BYTES = 65_536;
const MAX_RECEIPT_SIGNATURE_BYTES = 1_024;
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
const RECEIPT_SIGNATURE_ALGORITHMS = new Set([
  "ecdsa-sha256",
  "ed25519",
  "rsa-pss-sha256",
]);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PRINTABLE_ASCII_PATTERN = /^[ -~]+$/;
const BASE64_PATTERN =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const PRIVATE_MATERIAL_PATTERN =
  /-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----|(?:private.?key|secret|token|authorization|invite.?code|ciphertext)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9+/_-]{16,}/i;
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const JOURNAL_FLAGS =
  fsConstants.O_RDWR |
  fsConstants.O_APPEND |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const CREATE_FLAGS =
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  fsConstants.O_WRONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const DEFAULT_FILE_SYSTEM = Object.freeze({
  link,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  unlink,
});
const FILE_SYSTEM_KEYS = Object.freeze([
  "link",
  "lstat",
  "mkdir",
  "open",
  "readdir",
  "rename",
  "unlink",
]);
const STORE_METHODS = Object.freeze([
  "appendEvent",
  "close",
  "consumeCapability",
  "getArtifact",
  "putArtifact",
  "readEnrollment",
  "readEvents",
  "readReleaseView",
  "registerCapability",
]);

export class CoordinationStorageError extends Error {
  constructor(code = "COORDINATION_STORAGE_INVALID") {
    super("Coordination storage operation failed safely.");
    this.name = new.target.name;
    this.category = "verification";
    this.code = code;
  }
}

function fail(code) {
  throw new CoordinationStorageError(code);
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
    fail();
  }
  let ownKeys;
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    fail();
  }
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some(
      (key) =>
        typeof key !== "string" || !keys.includes(key),
    )
  ) {
    fail();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      fail();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return Object.freeze(result);
}

function readAllowedData(value, allowed, required) {
  if (!isPlainObject(value)) {
    fail();
  }
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    fail();
  }
  if (
    keys.some(
      (key) =>
        typeof key !== "string" || !allowed.includes(key),
    ) ||
    required.some((key) => !keys.includes(key))
  ) {
    fail();
  }
  const result = Object.create(null);
  for (const key of keys) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      fail();
    }
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    Object.defineProperty(result, key, {
      enumerable: true,
      value: descriptor.value,
    });
  }
  return Object.freeze(result);
}

function canonicalBytes(value) {
  try {
    return Buffer.from(
      JSON.stringify(canonicalizeReceiptEventValue(value)),
      "utf8",
    );
  } catch {
    fail();
  }
}

function parseCanonical(bytes) {
  try {
    const text = bytes.toString("utf8");
    if (Buffer.byteLength(text, "utf8") !== bytes.length) {
      fail();
    }
    const parsed = JSON.parse(text);
    if (!canonicalBytes(parsed).equals(bytes)) {
      fail();
    }
    return parsed;
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertSha256(value) {
  if (
    typeof value !== "string" ||
    !SHA256_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function assertRepositorySha(value) {
  if (
    typeof value !== "string" ||
    !REPOSITORY_SHA_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function assertSessionId(value) {
  if (
    typeof value !== "string" ||
    !UUID_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function assertReleaseId(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    !PRINTABLE_ASCII_PATTERN.test(value) ||
    value.trim() !== value
  ) {
    fail();
  }
  return value;
}

function assertRole(value) {
  if (value !== "payer" && value !== "payee") {
    fail();
  }
  return value;
}

function assertDecimal(value) {
  if (
    typeof value !== "string" ||
    !DECIMAL_PATTERN.test(value)
  ) {
    fail();
  }
  return value;
}

function numericDecimal(value) {
  assertDecimal(value);
  try {
    return BigInt(value);
  } catch {
    fail();
  }
}

function assertEpochMs(value) {
  const numeric = numericDecimal(value);
  if (
    value.length > 16 ||
    numeric > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  return value;
}

function activeFileSystem(value) {
  const fileSystem = readExactData(
    value ?? DEFAULT_FILE_SYSTEM,
    FILE_SYSTEM_KEYS,
  );
  if (
    FILE_SYSTEM_KEYS.some(
      (name) => typeof fileSystem[name] !== "function",
    )
  ) {
    fail();
  }
  return fileSystem;
}

function activeNow(value) {
  const now = value ?? Date.now;
  if (typeof now !== "function") {
    fail();
  }
  return () => {
    let result;
    try {
      result = now();
    } catch {
      fail();
    }
    if (!Number.isSafeInteger(result) || result < 0) {
      fail();
    }
    return result;
  };
}

function validDirectory(metadata, pathname = false) {
  try {
    return (
      metadata.isDirectory() &&
      (!pathname || !metadata.isSymbolicLink()) &&
      metadata.nlink > 0 &&
      (process.platform === "win32" ||
        (metadata.mode & 0o777) === 0o700) &&
      (typeof process.getuid !== "function" ||
        metadata.uid === process.getuid())
    );
  } catch {
    return false;
  }
}

function validPrivateFile(
  metadata,
  pathname = false,
  links = 1,
) {
  try {
    return (
      metadata.isFile() &&
      (!pathname || !metadata.isSymbolicLink()) &&
      metadata.nlink === links &&
      (process.platform === "win32" ||
        (metadata.mode & 0o777) === 0o600) &&
      (typeof process.getuid !== "function" ||
        metadata.uid === process.getuid())
    );
  } catch {
    return false;
  }
}

function identity(metadata) {
  return Object.freeze({
    dev: metadata.dev,
    gid: metadata.gid,
    ino: metadata.ino,
    mode: metadata.mode,
    rdev: metadata.rdev,
    uid: metadata.uid,
  });
}

function sameIdentity(metadata, expected) {
  return (
    metadata.dev === expected.dev &&
    metadata.ino === expected.ino &&
    metadata.mode === expected.mode &&
    metadata.uid === expected.uid &&
    metadata.gid === expected.gid &&
    metadata.rdev === expected.rdev
  );
}

async function createOrPinRoot(root, fileSystem) {
  if (
    typeof root !== "string" ||
    root.length === 0 ||
    basename(root) === "." ||
    basename(root) === ".."
  ) {
    fail();
  }
  let pathnameMetadata;
  try {
    pathnameMetadata = await fileSystem.lstat(root);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      fail();
    }
    try {
      await fileSystem.mkdir(root, {
        mode: 0o700,
        recursive: false,
      });
      pathnameMetadata = await fileSystem.lstat(root);
    } catch {
      fail();
    }
  }
  if (!validDirectory(pathnameMetadata, true)) {
    fail();
  }
  let handle;
  try {
    handle = await fileSystem.open(root, DIRECTORY_FLAGS);
    const handleMetadata = await handle.stat();
    if (
      !validDirectory(handleMetadata) ||
      !sameIdentity(
        pathnameMetadata,
        identity(handleMetadata),
      )
    ) {
      fail();
    }
    return {
      fileSystem,
      handle,
      identity: identity(handleMetadata),
      path: root,
    };
  } catch (error) {
    try {
      await handle?.close();
    } catch {
      // The fixed storage failure below supersedes close detail.
    }
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

async function pinExistingDirectory(
  path,
  fileSystem,
) {
  let pathnameMetadata;
  let handle;
  try {
    pathnameMetadata = await fileSystem.lstat(path);
    if (!validDirectory(pathnameMetadata, true)) {
      fail();
    }
    handle = await fileSystem.open(path, DIRECTORY_FLAGS);
    const handleMetadata = await handle.stat();
    const pinned = identity(handleMetadata);
    if (
      !validDirectory(handleMetadata) ||
      !sameIdentity(pathnameMetadata, pinned)
    ) {
      fail();
    }
    return {
      fileSystem,
      handle,
      identity: pinned,
      path,
    };
  } catch (error) {
    try {
      await handle?.close();
    } catch {
      // The validation error remains fixed.
    }
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

async function assertDirectory(binding) {
  try {
    const [pathnameMetadata, handleMetadata] =
      await Promise.all([
        binding.fileSystem.lstat(binding.path),
        binding.handle.stat(),
      ]);
    if (
      !validDirectory(pathnameMetadata, true) ||
      !validDirectory(handleMetadata) ||
      !sameIdentity(pathnameMetadata, binding.identity) ||
      !sameIdentity(handleMetadata, binding.identity)
    ) {
      fail();
    }
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

async function syncDirectory(binding) {
  await assertDirectory(binding);
  try {
    await binding.handle.sync();
  } catch {
    fail();
  }
  await assertDirectory(binding);
}

async function closeDirectory(binding) {
  let failure;
  try {
    await assertDirectory(binding);
  } catch (error) {
    failure = error;
  }
  try {
    await binding.handle.close();
  } catch {
    failure ??= new CoordinationStorageError();
  }
  if (failure !== undefined) {
    throw failure;
  }
}

function sameFileMetadata(left, right, links = 1) {
  return (
    validPrivateFile(left, true, links) &&
    validPrivateFile(right, false, links) &&
    sameIdentity(left, identity(right)) &&
    left.size === right.size
  );
}

async function readMaximumPlusOne(
  handle,
  maximum,
) {
  if (
    !Number.isSafeInteger(maximum) ||
    maximum < 0
  ) {
    fail();
  }
  const bytes = Buffer.alloc(maximum + 1);
  let offset = 0;
  while (offset < bytes.length) {
    let result;
    try {
      result = await handle.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
    } catch {
      fail();
    }
    if (
      !isPlainObject(result) ||
      !Number.isSafeInteger(result.bytesRead) ||
      result.bytesRead < 0 ||
      result.bytesRead > bytes.length - offset
    ) {
      fail();
    }
    if (result.bytesRead === 0) {
      break;
    }
    offset += result.bytesRead;
  }
  if (offset > maximum) {
    fail();
  }
  return bytes.subarray(0, offset);
}

async function readPinnedFile(
  path,
  maximum,
  fileSystem,
  { links = 1 } = {},
) {
  let handle;
  let failure;
  let bytes;
  try {
    const before = await fileSystem.lstat(path);
    if (
      !validPrivateFile(before, true, links) ||
      before.size < 0 ||
      before.size > maximum
    ) {
      fail();
    }
    handle = await fileSystem.open(path, READ_FLAGS);
    const opened = await handle.stat();
    if (
      !sameFileMetadata(before, opened, links) ||
      opened.size > maximum
    ) {
      fail();
    }
    bytes = await readMaximumPlusOne(handle, maximum);
    const [afterHandle, afterPath] = await Promise.all([
      handle.stat(),
      fileSystem.lstat(path),
    ]);
    if (
      bytes.length !== opened.size ||
      !sameFileMetadata(opened, afterHandle, links) ||
      !sameFileMetadata(afterPath, afterHandle, links)
    ) {
      fail();
    }
  } catch (error) {
    failure =
      error instanceof CoordinationStorageError
        ? error
        : new CoordinationStorageError();
  }
  if (handle !== undefined) {
    try {
      await handle.close();
    } catch {
      failure ??= new CoordinationStorageError();
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  return bytes;
}

async function createSyncedFile(
  path,
  bytes,
  fileSystem,
  { keepOpen = false } = {},
) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
    fail();
  }
  let handle;
  let failure;
  try {
    handle = await fileSystem.open(
      path,
      CREATE_FLAGS,
      0o600,
    );
    const opened = await handle.stat();
    if (!validPrivateFile(opened)) {
      fail();
    }
    await handle.writeFile(bytes);
    await handle.sync();
    const after = await handle.stat();
    const pathnameMetadata = await fileSystem.lstat(path);
    if (
      after.size !== bytes.length ||
      !sameFileMetadata(pathnameMetadata, after)
    ) {
      fail();
    }
    if (keepOpen) {
      return {
        handle,
        identity: identity(after),
      };
    }
    await handle.close();
    handle = undefined;
  } catch (error) {
    failure =
      error instanceof CoordinationStorageError
        ? error
        : new CoordinationStorageError();
  }
  if (handle !== undefined) {
    try {
      await handle.close();
    } catch {
      failure ??= new CoordinationStorageError();
    }
  }
  if (failure !== undefined) {
    throw failure;
  }
  return undefined;
}

async function verifyExistingFile(
  path,
  fileSystem,
  expectedIdentity,
) {
  try {
    const metadata = await fileSystem.lstat(path);
    if (
      !validPrivateFile(metadata, true) ||
      (expectedIdentity !== undefined &&
        !sameIdentity(metadata, expectedIdentity))
    ) {
      fail();
    }
    return metadata;
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

function deadPid(pid) {
  let numeric;
  try {
    numeric = Number(numericDecimal(pid));
  } catch {
    fail();
  }
  if (
    !Number.isSafeInteger(numeric) ||
    numeric <= 0
  ) {
    fail();
  }
  try {
    process.kill(numeric, 0);
    return false;
  } catch (error) {
    if (error?.code === "ESRCH") {
      return true;
    }
    return false;
  }
}

async function reclaimDeadOwner(root, fileSystem) {
  const paths = [
    join(root.path, OWNER_FILE),
    join(root.path, OWNER_GUARD_FILE),
  ];
  const entries = [];
  for (const path of paths) {
    try {
      entries.push({
        metadata: await fileSystem.lstat(path),
        path,
      });
    } catch (error) {
      if (error?.code !== "ENOENT") {
        fail();
      }
    }
  }
  if (entries.length === 0) {
    return;
  }
  const links = entries.length;
  if (
    entries.some(
      ({ metadata }) =>
        !validPrivateFile(metadata, true, links),
    ) ||
    (entries.length === 2 &&
      !sameIdentity(
        entries[0].metadata,
        identity(entries[1].metadata),
      ))
  ) {
    fail();
  }
  const bytes = await readPinnedFile(
    entries[0].path,
    MAX_OWNER_BYTES,
    fileSystem,
    { links },
  );
  const owner = readExactData(
    parseCanonical(bytes),
    ["pid", "schema"],
  );
  if (
    owner.schema !== OWNER_SCHEMA ||
    !deadPid(owner.pid)
  ) {
    fail();
  }
  await assertDirectory(root);
  for (const entry of entries) {
    let metadata;
    try {
      metadata = await fileSystem.lstat(entry.path);
    } catch {
      fail();
    }
    if (
      !validPrivateFile(metadata, true, links) ||
      !sameIdentity(
        metadata,
        identity(entry.metadata),
      )
    ) {
      fail();
    }
  }
  for (const entry of entries) {
    try {
      await fileSystem.unlink(entry.path);
    } catch {
      fail();
    }
  }
  await syncDirectory(root);
}

async function assertOwnerBinding(owner, fileSystem) {
  try {
    const [primary, guard, opened] = await Promise.all([
      fileSystem.lstat(owner.path),
      fileSystem.lstat(owner.guardPath),
      owner.handle.stat(),
    ]);
    if (
      !validPrivateFile(primary, true, 2) ||
      !validPrivateFile(guard, true, 2) ||
      !validPrivateFile(opened, false, 2) ||
      !sameIdentity(primary, owner.identity) ||
      !sameIdentity(guard, owner.identity) ||
      !sameIdentity(opened, owner.identity)
    ) {
      fail();
    }
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

async function acquireOwner(root, fileSystem) {
  await reclaimDeadOwner(root, fileSystem);
  await assertDirectory(root);
  const path = join(root.path, OWNER_FILE);
  const guardPath = join(root.path, OWNER_GUARD_FILE);
  const created = await createSyncedFile(
    path,
    canonicalBytes({
      pid: String(process.pid),
      schema: OWNER_SCHEMA,
    }),
    fileSystem,
    { keepOpen: true },
  );
  const owner = {
    ...created,
    guardPath,
    path,
  };
  try {
    await fileSystem.link(path, guardPath);
    await syncDirectory(root);
    await assertOwnerBinding(owner, fileSystem);
    return owner;
  } catch (error) {
    try {
      await created.handle.close();
    } catch {
      // Fixed failure below.
    }
    let rootCurrent = true;
    try {
      await assertDirectory(root);
    } catch {
      rootCurrent = false;
    }
    for (const cleanupPath of rootCurrent
      ? [guardPath, path]
      : []) {
      try {
        const metadata =
          await fileSystem.lstat(cleanupPath);
        if (
          metadata.isFile() &&
          sameIdentity(metadata, created.identity)
        ) {
          await fileSystem.unlink(cleanupPath);
        }
      } catch (cleanupError) {
        if (cleanupError?.code !== "ENOENT") {
          // Fixed failure below.
        }
      }
    }
    if (rootCurrent) {
      try {
        await syncDirectory(root);
      } catch {
        // Fixed failure below.
      }
    }
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

function emptyState() {
  return {
    capabilityScopes: new Map(),
    capabilities: new Map(),
    eventDigests: new Map(),
    events: [],
    senders: new Map(),
    sessions: new Map(),
  };
}

function cloneState(state) {
  return {
    capabilityScopes: new Map(state.capabilityScopes),
    capabilities: new Map(
      [...state.capabilities].map(
        ([digest, value]) => [
          digest,
          {
            consumption: value.consumption,
            registration: value.registration,
          },
        ],
      ),
    ),
    eventDigests: new Map(state.eventDigests),
    events: [...state.events],
    senders: new Map(
      [...state.senders].map(([key, sender]) => [
        key,
        {
          bySequence: new Map(sender.bySequence),
          lastDigest: sender.lastDigest,
          nextSequence: sender.nextSequence,
        },
      ]),
    ),
    sessions: new Map(state.sessions),
  };
}

function cloneEvent(event) {
  return Object.freeze({
    artifactDigest: event.artifactDigest,
    eventDigest: event.eventDigest,
    kind: event.kind,
    paymentMoved: event.paymentMoved,
    previousEventDigest: event.previousEventDigest,
    releaseId: event.releaseId,
    repositorySha: event.repositorySha,
    role: event.role,
    schema: event.schema,
    sequence: event.sequence,
    sessionId: event.sessionId,
    signature: Object.freeze({
      algorithm: event.signature.algorithm,
      keyId: event.signature.keyId,
      publicKey: event.signature.publicKey,
      value: event.signature.value,
    }),
    subjectRun: event.subjectRun,
  });
}

function validateEvent(
  value,
  repositorySha,
  { replayState } = {},
) {
  if (!isPlainObject(value)) {
    fail();
  }
  const embeddedDigest =
    Object.getOwnPropertyDescriptor(
      value,
      "eventDigest",
    )?.value;
  if (
    typeof embeddedDigest === "string" &&
    replayState?.eventDigests.has(embeddedDigest)
  ) {
    const existing =
      replayState.eventDigests.get(embeddedDigest);
    const same =
      existing.releaseId === value.releaseId &&
      existing.repositorySha === value.repositorySha &&
      existing.role === value.role &&
      existing.sequence === value.sequence &&
      existing.sessionId === value.sessionId &&
      existing.subjectRun === value.subjectRun;
    if (!same) {
      fail("EVENT_REPLAY");
    }
  }
  let bytes;
  let parsed;
  let digest;
  try {
    bytes = canonicalBytes(value);
    if (bytes.length > 65_536) {
      fail();
    }
    parsed = JSON.parse(bytes.toString("utf8"));
    digest = coordinationEventDigest(parsed);
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
  if (
    parsed.repositorySha !== repositorySha ||
    parsed.paymentMoved !== false ||
    digest !== parsed.eventDigest
  ) {
    fail();
  }
  return cloneEvent(parsed);
}

function capabilityRegistration(value) {
  const data = readExactData(value, [
    "capabilityDigest",
    "expiresAtMs",
    "releaseId",
    "role",
    "sessionId",
  ]);
  return Object.freeze({
    capabilityDigest: assertSha256(
      data.capabilityDigest,
    ),
    expiresAtMs: assertEpochMs(data.expiresAtMs),
    releaseId: assertReleaseId(data.releaseId),
    role: assertRole(data.role),
    sessionId: assertSessionId(data.sessionId),
  });
}

function capabilityConsumption(value) {
  const data = readExactData(value, [
    "capabilityDigest",
    "enrollmentBase64",
    "enrollmentDigest",
    "receiptBase64",
    "receiptDigest",
  ]);
  if (
    typeof data.enrollmentBase64 !== "string" ||
    !BASE64_PATTERN.test(data.enrollmentBase64) ||
    typeof data.receiptBase64 !== "string" ||
    !BASE64_PATTERN.test(data.receiptBase64)
  ) {
    fail();
  }
  const enrollmentBytes = Buffer.from(
    data.enrollmentBase64,
    "base64",
  );
  const receiptBytes = Buffer.from(
    data.receiptBase64,
    "base64",
  );
  if (
    enrollmentBytes.length === 0 ||
    enrollmentBytes.length > 65_536 ||
    enrollmentBytes.toString("base64") !==
      data.enrollmentBase64 ||
    sha256(enrollmentBytes) !== data.enrollmentDigest ||
    receiptBytes.length === 0 ||
    receiptBytes.length > MAX_RECEIPT_BYTES ||
    receiptBytes.toString("base64") !==
      data.receiptBase64 ||
    sha256(receiptBytes) !== data.receiptDigest
  ) {
    fail();
  }
  return Object.freeze({
    capabilityDigest: assertSha256(
      data.capabilityDigest,
    ),
    enrollmentBytes,
    enrollmentDigest: assertSha256(
      data.enrollmentDigest,
    ),
    receiptBytes,
    receiptDigest: assertSha256(data.receiptDigest),
  });
}

function senderKey(event) {
  return `${event.sessionId}\n${event.role}`;
}

function sameRegistration(left, right) {
  return (
    left.capabilityDigest === right.capabilityDigest &&
    left.expiresAtMs === right.expiresAtMs &&
    left.releaseId === right.releaseId &&
    left.role === right.role &&
    left.sessionId === right.sessionId
  );
}

function sameEvent(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function applyCapabilityRegistration(
  state,
  registration,
  loading,
) {
  const scope = `${registration.sessionId}\n${registration.role}`;
  const scopedDigest = state.capabilityScopes.get(scope);
  const releaseId = state.sessions.get(
    registration.sessionId,
  );
  if (
    (scopedDigest !== undefined &&
      scopedDigest !== registration.capabilityDigest) ||
    (releaseId !== undefined &&
      releaseId !== registration.releaseId)
  ) {
    fail(
      loading ? undefined : "CAPABILITY_REPLAY",
    );
  }
  const existing = state.capabilities.get(
    registration.capabilityDigest,
  );
  if (existing !== undefined) {
    if (
      !sameRegistration(
        existing.registration,
        registration,
      ) ||
      loading
    ) {
      fail(
        loading
          ? undefined
          : "CAPABILITY_REPLAY",
      );
    }
    return existing.registration;
  }
  state.capabilities.set(registration.capabilityDigest, {
    consumption: null,
    registration,
  });
  state.capabilityScopes.set(
    scope,
    registration.capabilityDigest,
  );
  state.sessions.set(
    registration.sessionId,
    registration.releaseId,
  );
  return registration;
}

function applyCapabilityConsumption(
  state,
  consumption,
  loading,
) {
  const capability = state.capabilities.get(
    consumption.capabilityDigest,
  );
  if (
    capability === undefined ||
    capability.consumption !== null
  ) {
    if (
      !loading &&
      capability?.consumption !== null &&
      capability?.consumption.enrollmentDigest ===
        consumption.enrollmentDigest &&
      capability.consumption.enrollmentBytes.equals(
        consumption.enrollmentBytes,
      ) &&
      capability.consumption.receiptDigest ===
        consumption.receiptDigest &&
      capability.consumption.receiptBytes.equals(
        consumption.receiptBytes,
      )
    ) {
      return capability.consumption;
    }
    fail(
      loading ? undefined : "CAPABILITY_REPLAY",
    );
  }
  capability.consumption = consumption;
  return consumption;
}

function applyEvent(state, event, loading) {
  const knownDigest = state.eventDigests.get(
    event.eventDigest,
  );
  if (knownDigest !== undefined) {
    if (
      !loading &&
      sameEvent(knownDigest, event)
    ) {
      return knownDigest;
    }
    fail(loading ? undefined : "EVENT_REPLAY");
  }
  const releaseId = state.sessions.get(event.sessionId);
  if (
    releaseId !== undefined &&
    releaseId !== event.releaseId
  ) {
    fail();
  }
  const key = senderKey(event);
  const sender = state.senders.get(key) ?? {
    bySequence: new Map(),
    lastDigest: null,
    nextSequence: 0n,
  };
  const sequence = numericDecimal(event.sequence);
  const existing = sender.bySequence.get(event.sequence);
  if (existing !== undefined) {
    if (
      !loading &&
      existing.eventDigest === event.eventDigest &&
      sameEvent(existing, event)
    ) {
      return existing;
    }
    fail(
      loading
        ? undefined
        : "EVENT_SEQUENCE_CONFLICT",
    );
  }
  if (sequence !== sender.nextSequence) {
    fail(
      loading ? undefined : "EVENT_SEQUENCE_GAP",
    );
  }
  if (event.previousEventDigest !== sender.lastDigest) {
    fail(
      loading
        ? undefined
        : "EVENT_CHAIN_DIVERGENCE",
    );
  }
  sender.bySequence.set(event.sequence, event);
  sender.lastDigest = event.eventDigest;
  sender.nextSequence += 1n;
  state.senders.set(key, sender);
  state.eventDigests.set(event.eventDigest, event);
  state.events.push(event);
  state.sessions.set(event.sessionId, event.releaseId);
  return event;
}

function payloadFor(type, value) {
  return Object.freeze({ type, value });
}

function validatePayload(payload, state, repositorySha) {
  const data = readExactData(payload, ["type", "value"]);
  if (data.type === "CAPABILITY_REGISTERED") {
    return payloadFor(
      data.type,
      capabilityRegistration(data.value),
    );
  }
  if (data.type === "CAPABILITY_CONSUMED") {
    const consumption = capabilityConsumption(
      data.value,
    );
    const capability = state.capabilities.get(
      consumption.capabilityDigest,
    );
    if (capability === undefined) {
      fail();
    }
    validatedEnrollmentBytes(
      consumption.enrollmentBytes,
      {
        enrollmentDigest:
          consumption.enrollmentDigest,
        expectedCapabilityDigest:
          consumption.capabilityDigest,
        registration: capability.registration,
        repositorySha,
      },
    );
    opaqueReceiptBytes(consumption.receiptBytes, {
      enrollmentDigest:
        consumption.enrollmentDigest,
      expectedCapabilityDigest:
        consumption.capabilityDigest,
      registration: capability.registration,
      repositorySha,
    });
    return payloadFor(
      data.type,
      consumption,
    );
  }
  if (data.type === "EVENT_APPENDED") {
    return payloadFor(
      data.type,
      validateEvent(data.value, repositorySha, {
        replayState: state,
      }),
    );
  }
  fail();
}

function applyPayload(
  state,
  payload,
  { loading = false } = {},
) {
  if (payload.type === "CAPABILITY_REGISTERED") {
    return applyCapabilityRegistration(
      state,
      payload.value,
      loading,
    );
  }
  if (payload.type === "CAPABILITY_CONSUMED") {
    return applyCapabilityConsumption(
      state,
      payload.value,
      loading,
    );
  }
  if (payload.type === "EVENT_APPENDED") {
    return applyEvent(state, payload.value, loading);
  }
  fail();
}

function recordBody({
  index,
  payload,
  previousRecordDigest,
}) {
  return Object.freeze({
    index,
    payload,
    previousRecordDigest,
    schema: RECORD_SCHEMA,
  });
}

function makeRecord(payload, records) {
  const body = recordBody({
    index: String(records.length),
    payload,
    previousRecordDigest:
      records.length === 0
        ? null
        : records.at(-1).recordDigest,
  });
  return Object.freeze({
    ...body,
    recordDigest: sha256(canonicalBytes(body)),
  });
}

function frameRecord(record) {
  const bytes = canonicalBytes(record);
  if (bytes.length === 0 || bytes.length > MAX_RECORD_BYTES) {
    fail();
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length);
  return Buffer.concat([header, bytes]);
}

function stateSummary(state) {
  const capabilities = [...state.capabilities.values()]
    .map(({ registration, consumption }) => ({
      capabilityDigest: registration.capabilityDigest,
      consumption:
        consumption === null
          ? null
          : {
              enrollmentDigest:
                consumption.enrollmentDigest,
              receiptDigest: consumption.receiptDigest,
            },
      expiresAtMs: registration.expiresAtMs,
      releaseId: registration.releaseId,
      role: registration.role,
      sessionId: registration.sessionId,
    }))
    .sort((left, right) =>
      left.capabilityDigest.localeCompare(
        right.capabilityDigest,
      ),
    );
  return Object.freeze({
    capabilities,
    eventDigests: state.events.map(
      (event) => event.eventDigest,
    ),
    sessions: [...state.sessions.entries()]
      .map(([sessionId, releaseId]) => ({
        releaseId,
        sessionId,
      }))
      .sort((left, right) =>
        left.sessionId.localeCompare(right.sessionId),
      ),
  });
}

function stateDigest(state) {
  return sha256(canonicalBytes(stateSummary(state)));
}

function snapshotValue(
  repositorySha,
  records,
  state,
) {
  return Object.freeze({
    lastRecordDigest:
      records.length === 0
        ? null
        : records.at(-1).recordDigest,
    recordCount: String(records.length),
    repositorySha,
    schema: SNAPSHOT_SCHEMA,
    stateDigest: stateDigest(state),
  });
}

function parseRecord(
  value,
  state,
  records,
  repositorySha,
) {
  const data = readExactData(value, [
    "index",
    "payload",
    "previousRecordDigest",
    "recordDigest",
    "schema",
  ]);
  if (
    data.schema !== RECORD_SCHEMA ||
    data.index !== String(records.length) ||
    (data.previousRecordDigest !== null &&
      !SHA256_PATTERN.test(data.previousRecordDigest)) ||
    data.previousRecordDigest !==
      (records.length === 0
        ? null
        : records.at(-1).recordDigest)
  ) {
    fail();
  }
  validatePayload(
    data.payload,
    state,
    repositorySha,
  );
  const body = recordBody({
    index: data.index,
    payload: data.payload,
    previousRecordDigest:
      data.previousRecordDigest,
  });
  if (
    assertSha256(data.recordDigest) !==
    sha256(canonicalBytes(body))
  ) {
    fail();
  }
  return Object.freeze({
    ...body,
    recordDigest: data.recordDigest,
  });
}

function parseJournal(bytes, repositorySha) {
  if (bytes.length > MAX_JOURNAL_BYTES) {
    fail();
  }
  const state = emptyState();
  const records = [];
  const checkpoints = [
    {
      lastRecordDigest: null,
      stateDigest: stateDigest(state),
    },
  ];
  let offset = 0;
  while (offset < bytes.length) {
    if (bytes.length - offset < 4) {
      fail();
    }
    const length = bytes.readUInt32BE(offset);
    offset += 4;
    if (
      length === 0 ||
      length > MAX_RECORD_BYTES ||
      bytes.length - offset < length
    ) {
      fail();
    }
    const recordBytes = bytes.subarray(
      offset,
      offset + length,
    );
    offset += length;
    const parsed = parseCanonical(recordBytes);
    const record = parseRecord(
      parsed,
      state,
      records,
      repositorySha,
    );
    const payload = validatePayload(
      record.payload,
      state,
      repositorySha,
    );
    applyPayload(state, payload, {
      loading: true,
    });
    records.push(record);
    checkpoints.push({
      lastRecordDigest: record.recordDigest,
      stateDigest: stateDigest(state),
    });
  }
  return { checkpoints, records, state };
}

function parseSnapshot(
  bytes,
  repositorySha,
  checkpoints,
) {
  const data = readExactData(parseCanonical(bytes), [
    "lastRecordDigest",
    "recordCount",
    "repositorySha",
    "schema",
    "stateDigest",
  ]);
  if (
    data.schema !== SNAPSHOT_SCHEMA ||
    data.repositorySha !== repositorySha ||
    (data.lastRecordDigest !== null &&
      !SHA256_PATTERN.test(data.lastRecordDigest)) ||
    !SHA256_PATTERN.test(data.stateDigest)
  ) {
    fail();
  }
  const count = numericDecimal(data.recordCount);
  if (count > BigInt(checkpoints.length - 1)) {
    fail();
  }
  const checkpoint = checkpoints[Number(count)];
  if (
    checkpoint.lastRecordDigest !==
      data.lastRecordDigest ||
    checkpoint.stateDigest !== data.stateDigest
  ) {
    fail();
  }
  return Number(count);
}

async function writeSnapshot(
  root,
  fileSystem,
  repositorySha,
  records,
  state,
) {
  const temporary = join(root.path, SNAPSHOT_TEMP_FILE);
  const destination = join(root.path, SNAPSHOT_FILE);
  const expectedBytes = canonicalBytes(
    snapshotValue(repositorySha, records, state),
  );
  await assertDirectory(root);
  try {
    await fileSystem.lstat(temporary);
    fail();
  } catch (error) {
    if (
      error instanceof CoordinationStorageError ||
      error?.code !== "ENOENT"
    ) {
      if (error instanceof CoordinationStorageError) {
        throw error;
      }
      fail();
    }
  }
  await createSyncedFile(
    temporary,
    expectedBytes,
    fileSystem,
  );
  await assertDirectory(root);
  try {
    await verifyExistingFile(
      destination,
      fileSystem,
    );
  } catch (error) {
    try {
      await fileSystem.lstat(destination);
      throw error;
    } catch (metadataError) {
      if (metadataError?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  try {
    await fileSystem.rename(temporary, destination);
  } catch {
    fail();
  }
  await syncDirectory(root);
  const reread = await readPinnedFile(
    destination,
    MAX_SNAPSHOT_BYTES,
    fileSystem,
  );
  if (!reread.equals(expectedBytes)) {
    fail();
  }
  await assertDirectory(root);
  await verifyExistingFile(destination, fileSystem);
}

async function discardDerivedFile(
  root,
  fileSystem,
  name,
) {
  const path = join(root.path, name);
  let metadata;
  try {
    metadata = await fileSystem.lstat(path);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    fail();
  }
  if (!validPrivateFile(metadata, true)) {
    fail();
  }
  await assertDirectory(root);
  await verifyExistingFile(
    path,
    fileSystem,
    identity(metadata),
  );
  try {
    await fileSystem.unlink(path);
  } catch {
    fail();
  }
  await syncDirectory(root);
}

async function createDirectoryIn(
  parent,
  path,
  fileSystem,
) {
  await assertDirectory(parent);
  try {
    await fileSystem.mkdir(path, {
      mode: 0o700,
      recursive: false,
    });
  } catch {
    fail();
  }
  await syncDirectory(parent);
  const binding = await pinExistingDirectory(
    path,
    fileSystem,
  );
  await closeDirectory(binding);
}

async function initializeStore(
  root,
  repositorySha,
  fileSystem,
  completedSteps = 0,
) {
  if (completedSteps < 1) {
    await createSyncedFile(
      join(root.path, METADATA_FILE),
      canonicalBytes({
        repositorySha,
        schema: STORE_SCHEMA,
      }),
      fileSystem,
    );
    await syncDirectory(root);
  }
  if (completedSteps < 2) {
    await createSyncedFile(
      join(root.path, JOURNAL_FILE),
      Buffer.from([0]),
      fileSystem,
    );
  }
  if (completedSteps <= 2) {
    // A journal is allowed to be empty. The one-byte initializer is
    // truncated through the pinned handle before first use.
    let journal;
    try {
      journal = await fileSystem.open(
        join(root.path, JOURNAL_FILE),
        fsConstants.O_RDWR |
          (fsConstants.O_NOFOLLOW ?? 0),
      );
      await journal.truncate(0);
      await journal.sync();
      await journal.close();
      journal = undefined;
    } catch {
      try {
        await journal?.close();
      } catch {
        // Fixed failure below.
      }
      fail();
    }
    await syncDirectory(root);
  }
  if (completedSteps < 3) {
    await createDirectoryIn(
      root,
      join(root.path, ARTIFACTS_DIRECTORY),
      fileSystem,
    );
  }
  if (completedSteps < 4) {
    await createSyncedFile(
      join(root.path, SNAPSHOT_FILE),
      canonicalBytes(
        snapshotValue(
          repositorySha,
          [],
          emptyState(),
        ),
      ),
      fileSystem,
    );
    await syncDirectory(root);
  }
}

async function inspectInitializationState(
  root,
  repositorySha,
  fileSystem,
) {
  let entries;
  try {
    entries = await fileSystem.readdir(root.path);
  } catch {
    fail();
  }
  const allowed = new Set([
    ARTIFACTS_DIRECTORY,
    JOURNAL_FILE,
    METADATA_FILE,
    OWNER_FILE,
    OWNER_GUARD_FILE,
    SNAPSHOT_FILE,
    SNAPSHOT_TEMP_FILE,
  ]);
  if (entries.some((entry) => !allowed.has(entry))) {
    fail();
  }
  const present = new Set(entries);
  const ordered = [
    METADATA_FILE,
    JOURNAL_FILE,
    ARTIFACTS_DIRECTORY,
    SNAPSHOT_FILE,
  ];
  let completedSteps = 0;
  while (
    completedSteps < ordered.length &&
    present.has(ordered[completedSteps])
  ) {
    completedSteps += 1;
  }
  if (
    ordered
      .slice(completedSteps)
      .some((entry) => present.has(entry)) ||
    (present.has(SNAPSHOT_TEMP_FILE) &&
      completedSteps < 3)
  ) {
    fail();
  }
  if (completedSteps >= 1) {
    const metadata = readExactData(
      parseCanonical(
        await readPinnedFile(
          join(root.path, METADATA_FILE),
          MAX_METADATA_BYTES,
          fileSystem,
        ),
      ),
      ["repositorySha", "schema"],
    );
    if (
      metadata.schema !== STORE_SCHEMA ||
      metadata.repositorySha !== repositorySha
    ) {
      fail();
    }
  }
  if (completedSteps >= 2) {
    const journal = await readPinnedFile(
      join(root.path, JOURNAL_FILE),
      MAX_JOURNAL_BYTES,
      fileSystem,
    );
    if (
      completedSteps < 3 &&
      !(
        journal.length === 0 ||
        (
          journal.length === 1 &&
          journal[0] === 0
        )
      )
    ) {
      fail();
    }
  }
  if (completedSteps >= 3) {
    const artifacts = await pinExistingDirectory(
      join(root.path, ARTIFACTS_DIRECTORY),
      fileSystem,
    );
    try {
      const artifactEntries = await fileSystem.readdir(
        artifacts.path,
      );
      await assertDirectory(artifacts);
      if (
        completedSteps < 4 &&
        artifactEntries.length !== 0
      ) {
        fail();
      }
    } finally {
      await closeDirectory(artifacts);
    }
  }
  return completedSteps;
}

async function validateStoreShape(
  root,
  repositorySha,
  fileSystem,
) {
  let entries;
  try {
    entries = await fileSystem.readdir(root.path);
  } catch {
    fail();
  }
  const allowed = new Set([
    ARTIFACTS_DIRECTORY,
    JOURNAL_FILE,
    METADATA_FILE,
    OWNER_FILE,
    OWNER_GUARD_FILE,
    SNAPSHOT_FILE,
    SNAPSHOT_TEMP_FILE,
  ]);
  if (
    entries.some((entry) => !allowed.has(entry)) ||
    ![
      ARTIFACTS_DIRECTORY,
      JOURNAL_FILE,
      METADATA_FILE,
    ].every((entry) => entries.includes(entry))
  ) {
    fail();
  }
  const metadata = readExactData(
    parseCanonical(
      await readPinnedFile(
        join(root.path, METADATA_FILE),
        MAX_METADATA_BYTES,
        fileSystem,
      ),
    ),
    ["repositorySha", "schema"],
  );
  if (
    metadata.schema !== STORE_SCHEMA ||
    metadata.repositorySha !== repositorySha
  ) {
    fail();
  }
  await validateArtifactTree(root, fileSystem);
}

async function validateArtifactTree(root, fileSystem) {
  const artifacts = await pinExistingDirectory(
    join(root.path, ARTIFACTS_DIRECTORY),
    fileSystem,
  );
  let failure;
  try {
    await assertDirectory(root);
    const prefixes = await fileSystem.readdir(
      artifacts.path,
    );
    if (
      prefixes.length > 256 ||
      prefixes.some(
        (prefix) => !/^[0-9a-f]{2}$/.test(prefix),
      )
    ) {
      fail();
    }
    let fileCount = 0;
    for (const prefix of prefixes) {
      const directory = await pinExistingDirectory(
        join(artifacts.path, prefix),
        fileSystem,
      );
      try {
        let files = await fileSystem.readdir(
          directory.path,
        );
        fileCount += files.length;
        if (
          fileCount > 4_096 ||
          files.some(
            (file) =>
              !(
                (SHA256_PATTERN.test(file) &&
                  file.startsWith(prefix)) ||
                (new RegExp(
                  `^\\.${prefix}[0-9a-f]{62}\\.tmp$`,
                ).test(file))
              ),
          )
        ) {
          fail();
        }
        for (const file of files.filter((entry) =>
          entry.startsWith("."),
        )) {
          const digest = file.slice(1, -4);
          const temporaryPath = join(
            directory.path,
            file,
          );
          const finalPath = join(
            directory.path,
            digest,
          );
          let temporaryMetadata;
          try {
            temporaryMetadata =
              await fileSystem.lstat(temporaryPath);
          } catch {
            fail();
          }
          let finalMetadata;
          try {
            finalMetadata =
              await fileSystem.lstat(finalPath);
          } catch (error) {
            if (error?.code !== "ENOENT") {
              fail();
            }
          }
          const links =
            finalMetadata === undefined ? 1 : 2;
          if (
            !validPrivateFile(
              temporaryMetadata,
              true,
              links,
            ) ||
            (finalMetadata !== undefined &&
              (!validPrivateFile(
                finalMetadata,
                true,
                2,
              ) ||
                !sameIdentity(
                  temporaryMetadata,
                  identity(finalMetadata),
                )))
          ) {
            fail();
          }
          await assertDirectory(directory);
          try {
            await fileSystem.unlink(temporaryPath);
          } catch {
            fail();
          }
          await syncDirectory(directory);
        }
        files = await fileSystem.readdir(directory.path);
        for (const file of files) {
          if (
            !SHA256_PATTERN.test(file) ||
            !file.startsWith(prefix)
          ) {
            fail();
          }
          const bytes = await readPinnedFile(
            join(directory.path, file),
            3_145_728,
            fileSystem,
          );
          if (sha256(bytes) !== file) {
            fail();
          }
        }
        await assertDirectory(directory);
      } finally {
        await closeDirectory(directory);
      }
    }
    await assertDirectory(artifacts);
    await assertDirectory(root);
  } catch (error) {
    failure =
      error instanceof CoordinationStorageError
        ? error
        : new CoordinationStorageError();
  }
  try {
    await closeDirectory(artifacts);
  } catch (error) {
    failure ??= error;
  }
  if (failure !== undefined) {
    throw failure;
  }
}

async function openJournal(
  root,
  fileSystem,
) {
  const path = join(root.path, JOURNAL_FILE);
  let handle;
  try {
    const before = await fileSystem.lstat(path);
    if (!validPrivateFile(before, true)) {
      fail();
    }
    handle = await fileSystem.open(path, JOURNAL_FLAGS);
    const opened = await handle.stat();
    if (!sameFileMetadata(before, opened)) {
      fail();
    }
    return {
      handle,
      identity: identity(opened),
      path,
    };
  } catch (error) {
    try {
      await handle?.close();
    } catch {
      // Fixed storage failure below.
    }
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

async function readOpenJournal(journal, fileSystem) {
  try {
    const [opened, pathnameMetadata] =
      await Promise.all([
        journal.handle.stat(),
        fileSystem.lstat(journal.path),
      ]);
    if (
      !validPrivateFile(opened) ||
      !validPrivateFile(pathnameMetadata, true) ||
      !sameIdentity(opened, journal.identity) ||
      !sameIdentity(pathnameMetadata, journal.identity) ||
      opened.size > MAX_JOURNAL_BYTES
    ) {
      fail();
    }
    const bytes = await readMaximumPlusOne(
      journal.handle,
      MAX_JOURNAL_BYTES,
    );
    const [afterHandle, afterPath] = await Promise.all([
      journal.handle.stat(),
      fileSystem.lstat(journal.path),
    ]);
    if (
      bytes.length !== opened.size ||
      !sameFileMetadata(opened, afterHandle) ||
      !sameFileMetadata(afterPath, afterHandle) ||
      !sameIdentity(afterHandle, journal.identity)
    ) {
      fail();
    }
    return bytes;
  } catch (error) {
    if (error instanceof CoordinationStorageError) {
      throw error;
    }
    fail();
  }
}

function capabilityBytes(value) {
  if (Buffer.isBuffer(value) && value.length === 32) {
    return Buffer.from(value);
  }
  if (
    typeof value === "string" &&
    /^[0-9a-f]{64}$/.test(value)
  ) {
    return Buffer.from(value, "hex");
  }
  fail();
}

function capabilityTextRepresentations(rawCapability) {
  const base64 = rawCapability.toString("base64");
  const base64url = rawCapability.toString("base64url");
  const representations = new Set([
    rawCapability.toString("hex"),
    rawCapability.toString("hex").toUpperCase(),
    base64,
    base64.replace(/=+$/, ""),
    base64url,
    `${base64url}${"=".repeat(
      (4 - (base64url.length % 4)) % 4,
    )}`,
  ]);
  const utf8 = rawCapability.toString("utf8");
  if (
    Buffer.from(utf8, "utf8").equals(rawCapability)
  ) {
    representations.add(utf8);
  }
  return representations;
}

function assertReceiptContainsNoSecrets(
  parsed,
  rawCapability,
) {
  try {
    assertSecretFree(parsed);
  } catch {
    fail();
  }
  const representations =
    rawCapability === undefined
      ? new Set()
      : capabilityTextRepresentations(rawCapability);
  const pending = [parsed];
  let remaining = 4_096;
  while (pending.length > 0) {
    if (remaining === 0) {
      fail();
    }
    remaining -= 1;
    const value = pending.pop();
    if (typeof value === "string") {
      if (
        PRIVATE_MATERIAL_PATTERN.test(value) ||
        [...representations].some(
          (representation) =>
            representation.length > 0 &&
            value.includes(representation),
        )
      ) {
        fail();
      }
      continue;
    }
    if (Array.isArray(value)) {
      if (
        rawCapability !== undefined &&
        value.length === rawCapability.length &&
        value.every(
          (entry, index) =>
            Number.isInteger(entry) &&
            entry === rawCapability[index],
        )
      ) {
        fail();
      }
      pending.push(...value);
      continue;
    }
    if (isPlainObject(value)) {
      for (const [key, entry] of Object.entries(value)) {
        if (SENSITIVE_KEY.test(key)) {
          fail();
        }
        pending.push(entry);
      }
    }
  }
}

function opaqueReceiptBytes(
  value,
  {
    enrollmentDigest,
    expectedCapabilityDigest,
    rawCapability,
    registration,
    repositorySha,
  },
) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > MAX_RECEIPT_BYTES
  ) {
    fail();
  }
  const bytes = Buffer.from(value);
  const parsed = parseCanonical(bytes);
  const data = readExactData(parsed, RECEIPT_KEYS);
  const signature =
    typeof data.signature === "string" &&
    BASE64_PATTERN.test(data.signature)
      ? Buffer.from(data.signature, "base64")
      : Buffer.alloc(0);
  if (
    data.schema !== RECEIPT_SCHEMA ||
    data.paymentMoved !== false ||
    data.capabilityDigest !==
      expectedCapabilityDigest ||
    data.enrollmentDigest !== enrollmentDigest ||
    data.releaseId !== registration.releaseId ||
    data.repositorySha !== repositorySha ||
    data.role !== registration.role ||
    data.sessionId !== registration.sessionId ||
    assertSha256(data.capabilityDigest) !==
      expectedCapabilityDigest ||
    assertSha256(data.certificateSha256) !==
      data.certificateSha256 ||
    assertSha256(data.enrollmentDigest) !==
      enrollmentDigest ||
    signature.length === 0 ||
    signature.length >
      MAX_RECEIPT_SIGNATURE_BYTES ||
    signature.toString("base64") !== data.signature ||
    !RECEIPT_SIGNATURE_ALGORITHMS.has(
      data.signatureAlgorithm,
    )
  ) {
    fail();
  }
  assertReceiptContainsNoSecrets(
    parsed,
    rawCapability,
  );
  return bytes;
}

function boundedEnrollmentBytes(value) {
  if (
    !Buffer.isBuffer(value) ||
    value.length === 0 ||
    value.length > 65_536
  ) {
    fail();
  }
  return Buffer.from(value);
}

function validatedEnrollmentBytes(
  value,
  {
    enrollmentDigest,
    expectedCapabilityDigest,
    registration,
    repositorySha,
  },
) {
  const bytes = boundedEnrollmentBytes(value);
  let enrollment;
  try {
    enrollment = parseCoordinationEnrollment(bytes);
  } catch {
    fail();
  }
  if (
    sha256(bytes) !== enrollmentDigest ||
    enrollment.capabilityDigest !==
      expectedCapabilityDigest ||
    enrollment.releaseId !== registration.releaseId ||
    enrollment.repositorySha !== repositorySha ||
    enrollment.role !== registration.role ||
    enrollment.sessionId !== registration.sessionId
  ) {
    fail();
  }
  return bytes;
}

function consumptionResult(consumption) {
  return Object.freeze({
    capabilityDigest: consumption.capabilityDigest,
    enrollmentBytes: Buffer.from(
      consumption.enrollmentBytes,
    ),
    enrollmentDigest: consumption.enrollmentDigest,
    receiptBytes: Buffer.from(consumption.receiptBytes),
  });
}

function publicRegistration(registration) {
  return Object.freeze({ ...registration });
}

function frozenEvents(events) {
  return Object.freeze(events.map(cloneEvent));
}

async function ensureArtifactDirectory(
  root,
  fileSystem,
) {
  await assertDirectory(root);
  return pinExistingDirectory(
    join(root.path, ARTIFACTS_DIRECTORY),
    fileSystem,
  );
}

async function ensurePrefixDirectory(
  artifacts,
  prefix,
  fileSystem,
) {
  const path = join(artifacts.path, prefix);
  try {
    return await pinExistingDirectory(path, fileSystem);
  } catch (error) {
    try {
      await fileSystem.lstat(path);
      throw error;
    } catch (metadataError) {
      if (metadataError?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  await createDirectoryIn(
    artifacts,
    path,
    fileSystem,
  );
  return pinExistingDirectory(path, fileSystem);
}

async function removeArtifactTemporary(
  directory,
  temporaryPath,
  finalPath,
  fileSystem,
) {
  let temporaryMetadata;
  try {
    temporaryMetadata =
      await fileSystem.lstat(temporaryPath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    fail();
  }
  let finalMetadata;
  try {
    finalMetadata = await fileSystem.lstat(finalPath);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      fail();
    }
  }
  const links = finalMetadata === undefined ? 1 : 2;
  if (
    !validPrivateFile(
      temporaryMetadata,
      true,
      links,
    ) ||
    (finalMetadata !== undefined &&
      (!validPrivateFile(finalMetadata, true, 2) ||
        !sameIdentity(
          temporaryMetadata,
          identity(finalMetadata),
        )))
  ) {
    fail();
  }
  await assertDirectory(directory);
  try {
    await fileSystem.unlink(temporaryPath);
  } catch {
    fail();
  }
  await syncDirectory(directory);
}

async function writeArtifact(
  root,
  fileSystem,
  digest,
  bytes,
) {
  const artifacts = await ensureArtifactDirectory(
    root,
    fileSystem,
  );
  let prefix;
  try {
    prefix = await ensurePrefixDirectory(
      artifacts,
      digest.slice(0, 2),
      fileSystem,
    );
    await assertDirectory(root);
    await assertDirectory(artifacts);
    await assertDirectory(prefix);
    const path = join(prefix.path, digest);
    const temporaryPath = join(
      prefix.path,
      `.${digest}.tmp`,
    );
    await removeArtifactTemporary(
      prefix,
      temporaryPath,
      path,
      fileSystem,
    );
    try {
      const existing = await readPinnedFile(
        path,
        bytes.length,
        fileSystem,
      );
      if (
        sha256(existing) !== digest ||
        !existing.equals(bytes)
      ) {
        fail();
      }
      return;
    } catch (error) {
      try {
        await fileSystem.lstat(path);
        throw error;
      } catch (metadataError) {
        if (metadataError?.code !== "ENOENT") {
          throw error;
        }
      }
    }
    await createSyncedFile(
      temporaryPath,
      bytes,
      fileSystem,
    );
    await assertDirectory(root);
    await assertDirectory(artifacts);
    await assertDirectory(prefix);
    const reread = await readPinnedFile(
      temporaryPath,
      bytes.length,
      fileSystem,
    );
    if (
      sha256(reread) !== digest ||
      !reread.equals(bytes)
    ) {
      fail();
    }
    let temporaryMetadata;
    try {
      temporaryMetadata =
        await fileSystem.lstat(temporaryPath);
      if (
        !validPrivateFile(temporaryMetadata, true)
      ) {
        fail();
      }
      await fileSystem.link(temporaryPath, path);
    } catch (error) {
      let finalMetadata;
      let currentTemporary;
      try {
        [currentTemporary, finalMetadata] =
          await Promise.all([
            fileSystem.lstat(temporaryPath),
            fileSystem.lstat(path),
          ]);
      } catch {
        fail();
      }
      if (
        !validPrivateFile(
          currentTemporary,
          true,
          2,
        ) ||
        !validPrivateFile(finalMetadata, true, 2) ||
        !sameIdentity(
          currentTemporary,
          identity(finalMetadata),
        )
      ) {
        fail();
      }
    }
    await syncDirectory(prefix);
    const [linkedTemporary, linkedFinal] =
      await Promise.all([
        fileSystem.lstat(temporaryPath),
        fileSystem.lstat(path),
      ]);
    if (
      !validPrivateFile(
        linkedTemporary,
        true,
        2,
      ) ||
      !validPrivateFile(linkedFinal, true, 2) ||
      !sameIdentity(
        linkedTemporary,
        identity(linkedFinal),
      )
    ) {
      fail();
    }
    try {
      await fileSystem.unlink(temporaryPath);
    } catch {
      fail();
    }
    await syncDirectory(prefix);
    const finalBytes = await readPinnedFile(
      path,
      bytes.length,
      fileSystem,
    );
    if (
      sha256(finalBytes) !== digest ||
      !finalBytes.equals(bytes)
    ) {
      fail();
    }
    await syncDirectory(artifacts);
    await syncDirectory(root);
  } finally {
    let failure;
    try {
      if (prefix !== undefined) {
        await closeDirectory(prefix);
      }
    } catch (error) {
      failure = error;
    }
    try {
      await closeDirectory(artifacts);
    } catch (error) {
      failure ??= error;
    }
    if (failure !== undefined) {
      throw failure;
    }
  }
}

async function readArtifact(
  root,
  fileSystem,
  digest,
) {
  const artifacts = await ensureArtifactDirectory(
    root,
    fileSystem,
  );
  let prefix;
  let result;
  let failure;
  try {
    prefix = await pinExistingDirectory(
      join(artifacts.path, digest.slice(0, 2)),
      fileSystem,
    );
    await assertDirectory(root);
    await assertDirectory(artifacts);
    await assertDirectory(prefix);
    result = await readPinnedFile(
      join(prefix.path, digest),
      3_145_728,
      fileSystem,
    );
    if (sha256(result) !== digest) {
      fail();
    }
    await assertDirectory(prefix);
    await assertDirectory(artifacts);
    await assertDirectory(root);
  } catch (error) {
    failure =
      error instanceof CoordinationStorageError
        ? error
        : new CoordinationStorageError();
  }
  try {
    if (prefix !== undefined) {
      await closeDirectory(prefix);
    }
  } catch (error) {
    failure ??= error;
  }
  try {
    await closeDirectory(artifacts);
  } catch (error) {
    failure ??= error;
  }
  if (failure !== undefined) {
    throw failure;
  }
  return Buffer.from(result);
}

export async function openCoordinationStore(input) {
  const options = readAllowedData(
    input,
    ["fileSystem", "now", "repositorySha", "root"],
    ["repositorySha", "root"],
  );
  const repositorySha = assertRepositorySha(
    options.repositorySha,
  );
  const fileSystem = activeFileSystem(
    options.fileSystem,
  );
  const now = activeNow(options.now);
  const root = await createOrPinRoot(
    options.root,
    fileSystem,
  );
  let owner;
  let journal;
  let failure;
  try {
    const completedInitialization =
      await inspectInitializationState(
        root,
        repositorySha,
        fileSystem,
      );
    owner = await acquireOwner(root, fileSystem);
    if (completedInitialization < 4) {
      await initializeStore(
        root,
        repositorySha,
        fileSystem,
        completedInitialization,
      );
    }
    await validateStoreShape(
      root,
      repositorySha,
      fileSystem,
    );
    journal = await openJournal(root, fileSystem);
    const loaded = parseJournal(
      await readOpenJournal(journal, fileSystem),
      repositorySha,
    );
    await discardDerivedFile(
      root,
      fileSystem,
      SNAPSHOT_TEMP_FILE,
    );
    let snapshotCurrent = false;
    try {
      const snapshotBytes = await readPinnedFile(
        join(root.path, SNAPSHOT_FILE),
        MAX_SNAPSHOT_BYTES,
        fileSystem,
      );
      snapshotCurrent =
        parseSnapshot(
        snapshotBytes,
        repositorySha,
        loaded.checkpoints,
        ) === loaded.records.length;
    } catch (error) {
      try {
        const metadata = await fileSystem.lstat(
          join(root.path, SNAPSHOT_FILE),
        );
        if (!validPrivateFile(metadata, true)) {
          throw error;
        }
      } catch (metadataError) {
        if (metadataError?.code !== "ENOENT") {
          throw error;
        }
        snapshotCurrent = false;
      }
    }
    if (!snapshotCurrent) {
      await discardDerivedFile(
        root,
        fileSystem,
        SNAPSHOT_FILE,
      );
      await writeSnapshot(
        root,
        fileSystem,
        repositorySha,
        loaded.records,
        loaded.state,
      );
    }

    let closed = false;
    let closing = false;
    let closePromise;
    let poisoned = false;
    let queue = Promise.resolve();
    const records = loaded.records;
    const state = loaded.state;

    function assertOpen() {
      if (closed) {
        fail("COORDINATION_STORAGE_CLOSED");
      }
      if (poisoned) {
        fail();
      }
    }

    function serialize(action) {
      if (closing || closed) {
        return Promise.reject(
          new CoordinationStorageError(
            "COORDINATION_STORAGE_CLOSED",
          ),
        );
      }
      const execute = async () => {
        let actionError;
        let result;
        try {
          assertOpen();
          await assertDirectory(root);
          await assertOwnerBinding(owner, fileSystem);
          result = await action();
        } catch (error) {
          actionError = error;
        }
        try {
          await assertOwnerBinding(owner, fileSystem);
          await assertDirectory(root);
        } catch {
          poisoned = true;
          fail();
        }
        if (actionError !== undefined) {
          if (
            actionError instanceof CoordinationStorageError
          ) {
            throw actionError;
          }
          fail();
        }
        return result;
      };
      const result = queue.then(execute, execute);
      queue = result.catch(() => {});
      return result;
    }

    async function assertJournalSize(expectedSize) {
      const [pathnameMetadata, opened] =
        await Promise.all([
          fileSystem.lstat(journal.path),
          journal.handle.stat(),
        ]);
      if (
        !validPrivateFile(pathnameMetadata, true) ||
        !validPrivateFile(opened) ||
        !sameIdentity(
          pathnameMetadata,
          journal.identity,
        ) ||
        !sameIdentity(opened, journal.identity) ||
        pathnameMetadata.size !== expectedSize ||
        opened.size !== expectedSize
      ) {
        fail();
      }
    }

    async function assertJournalTruth(
      expectedSize,
      expectedCount,
      expectedLastDigest,
    ) {
      await assertJournalSize(expectedSize);
      const durable = parseJournal(
        await readOpenJournal(journal, fileSystem),
        repositorySha,
      );
      if (
        durable.records.length !== expectedCount ||
        (
          durable.records.at(-1)?.recordDigest ??
          null
        ) !== expectedLastDigest
      ) {
        fail();
      }
    }

    async function appendPayload(payload) {
      assertOpen();
      await assertDirectory(root);
      const validatedPayload = validatePayload(
        payload,
        state,
        repositorySha,
      );
      applyPayload(
        cloneState(state),
        validatedPayload,
      );
      const record = makeRecord(payload, records);
      const frame = frameRecord(record);
      try {
        const pathnameMetadata =
          await fileSystem.lstat(journal.path);
        const opened = await journal.handle.stat();
        if (
          !validPrivateFile(pathnameMetadata, true) ||
          !validPrivateFile(opened) ||
          !sameIdentity(
            pathnameMetadata,
            journal.identity,
          ) ||
          !sameIdentity(opened, journal.identity) ||
          opened.size + frame.length >
            MAX_JOURNAL_BYTES
        ) {
          fail();
        }
        const expectedSize = opened.size + frame.length;
        await journal.handle.writeFile(frame);
        await journal.handle.sync();
        await assertJournalTruth(
          expectedSize,
          records.length + 1,
          record.recordDigest,
        );
        await syncDirectory(root);
        const applied = applyPayload(
          state,
          validatedPayload,
        );
        records.push(record);
        await writeSnapshot(
          root,
          fileSystem,
          repositorySha,
          records,
          state,
        );
        await assertJournalTruth(
          expectedSize,
          records.length,
          record.recordDigest,
        );
        await assertDirectory(root);
        return applied;
      } catch (error) {
        poisoned = true;
        if (error instanceof CoordinationStorageError) {
          throw error;
        }
        fail();
      }
    }

    async function registerCapability(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const registration = capabilityRegistration(value);
        const existing = state.capabilities.get(
          registration.capabilityDigest,
        );
        if (existing !== undefined) {
          if (
            !sameRegistration(
              existing.registration,
              registration,
            )
          ) {
            fail("CAPABILITY_REPLAY");
          }
          return publicRegistration(
            existing.registration,
          );
        }
        const accepted = await appendPayload(
          payloadFor(
            "CAPABILITY_REGISTERED",
            registration,
          ),
        );
        return publicRegistration(accepted);
      });
    }

    async function consumeCapability(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const keys = Reflect.ownKeys(value ?? {});
        const scoped =
          keys.includes("releaseId") ||
          keys.includes("role") ||
          keys.includes("sessionId");
        const data = readExactData(
          value,
          scoped
            ? [
                "capability",
                "enrollmentBytes",
                "enrollmentDigest",
                "receiptFactory",
                "releaseId",
                "role",
                "sessionId",
              ]
            : [
                "capability",
                "enrollmentBytes",
                "enrollmentDigest",
                "receiptFactory",
              ],
        );
        const rawCapability = capabilityBytes(
          data.capability,
        );
        const digest = sha256(rawCapability);
        const capability = state.capabilities.get(digest);
        if (capability === undefined) {
          fail("CAPABILITY_SCOPE");
        }
        if (
          scoped &&
          (data.releaseId !==
            capability.registration.releaseId ||
            data.role !== capability.registration.role ||
            data.sessionId !==
              capability.registration.sessionId)
        ) {
          fail("CAPABILITY_SCOPE");
        }
        const enrollmentDigest = assertSha256(
          data.enrollmentDigest,
        );
        const enrollmentBytes =
          boundedEnrollmentBytes(
            data.enrollmentBytes,
          );
        if (capability.consumption !== null) {
          if (
            capability.consumption.enrollmentDigest !==
              enrollmentDigest ||
            !capability.consumption.enrollmentBytes.equals(
              enrollmentBytes,
            )
          ) {
            fail("CAPABILITY_REPLAY");
          }
          return consumptionResult(
            capability.consumption,
          );
        }
        validatedEnrollmentBytes(
          enrollmentBytes,
          {
            enrollmentDigest,
            expectedCapabilityDigest: digest,
            registration:
              capability.registration,
            repositorySha,
          },
        );
        if (
          numericDecimal(
            capability.registration.expiresAtMs,
          ) <= BigInt(now())
        ) {
          fail("CAPABILITY_EXPIRED");
        }
        if (typeof data.receiptFactory !== "function") {
          fail();
        }
        const factoryContext = Object.freeze({
          capabilityDigest: digest,
          enrollmentDigest,
          releaseId:
            capability.registration.releaseId,
          repositorySha,
          role: capability.registration.role,
          sessionId:
            capability.registration.sessionId,
        });
        let candidateReceipt;
        try {
          candidateReceipt = await data.receiptFactory(
            factoryContext,
          );
        } catch {
          fail();
        }
        const receiptBytes = opaqueReceiptBytes(
          candidateReceipt,
          {
            enrollmentDigest,
            expectedCapabilityDigest: digest,
            rawCapability,
            registration:
              capability.registration,
            repositorySha,
          },
        );
        const consumption = capabilityConsumption({
          capabilityDigest: digest,
          enrollmentBase64:
            enrollmentBytes.toString("base64"),
          enrollmentDigest,
          receiptBase64: receiptBytes.toString("base64"),
          receiptDigest: sha256(receiptBytes),
        });
        const accepted = await appendPayload(
          payloadFor(
            "CAPABILITY_CONSUMED",
            {
              capabilityDigest: consumption.capabilityDigest,
              enrollmentBase64:
                consumption.enrollmentBytes.toString(
                  "base64",
                ),
              enrollmentDigest: consumption.enrollmentDigest,
              receiptBase64:
                consumption.receiptBytes.toString("base64"),
              receiptDigest: consumption.receiptDigest,
            },
          ),
        );
        return consumptionResult(accepted);
      });
    }

    async function readEnrollment(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const data = readExactData(value, [
          "role",
          "sessionId",
        ]);
        const role = assertRole(data.role);
        const sessionId = assertSessionId(
          data.sessionId,
        );
        const capabilityDigest =
          state.capabilityScopes.get(
            `${sessionId}\n${role}`,
          );
        const consumption =
          capabilityDigest === undefined
            ? null
            : state.capabilities.get(
                capabilityDigest,
              )?.consumption;
        if (consumption === null || consumption === undefined) {
          fail("COORDINATION_ENROLLMENT_NOT_FOUND");
        }
        return Object.freeze({
          bytes: Buffer.from(
            consumption.enrollmentBytes,
          ),
          digest: consumption.enrollmentDigest,
          receiptBytes: Buffer.from(
            consumption.receiptBytes,
          ),
        });
      });
    }

    async function appendEvent(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const embeddedDigest =
          isPlainObject(value)
            ? Object.getOwnPropertyDescriptor(
                value,
                "eventDigest",
              )?.value
            : undefined;
        if (
          typeof embeddedDigest === "string" &&
          state.eventDigests.has(embeddedDigest)
        ) {
          const existing =
            state.eventDigests.get(embeddedDigest);
          if (sameEvent(existing, value)) {
            return cloneEvent(existing);
          }
          fail("EVENT_REPLAY");
        }
        const acceptedEvent = validateEvent(
          value,
          repositorySha,
          { replayState: state },
        );
        const key = senderKey(acceptedEvent);
        const sender = state.senders.get(key);
        const existing =
          sender?.bySequence.get(acceptedEvent.sequence);
        if (existing !== undefined) {
          if (
            existing.eventDigest ===
              acceptedEvent.eventDigest &&
            sameEvent(existing, acceptedEvent)
          ) {
            return cloneEvent(existing);
          }
          fail("EVENT_SEQUENCE_CONFLICT");
        }
        const sequence = numericDecimal(
          acceptedEvent.sequence,
        );
        const next = sender?.nextSequence ?? 0n;
        if (sequence !== next) {
          fail("EVENT_SEQUENCE_GAP");
        }
        if (
          acceptedEvent.previousEventDigest !==
          (sender?.lastDigest ?? null)
        ) {
          fail("EVENT_CHAIN_DIVERGENCE");
        }
        const accepted = await appendPayload(
          payloadFor("EVENT_APPENDED", acceptedEvent),
        );
        return cloneEvent(accepted);
      });
    }

    async function readEvents(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const data = readExactData(value, [
          "after",
          "sessionId",
        ]);
        const sessionId = assertSessionId(
          data.sessionId,
        );
        if (
          data.after !== null &&
          (typeof data.after !== "string" ||
            !SHA256_PATTERN.test(data.after))
        ) {
          fail();
        }
        const events = state.events.filter(
          (event) => event.sessionId === sessionId,
        );
        if (data.after === null) {
          return frozenEvents(events);
        }
        const index = events.findIndex(
          (event) => event.eventDigest === data.after,
        );
        if (index === -1) {
          fail();
        }
        return frozenEvents(events.slice(index + 1));
      });
    }

    async function readReleaseView(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const data = readExactData(value, ["sessionId"]);
        const sessionId = assertSessionId(
          data.sessionId,
        );
        return Object.freeze({
          events: frozenEvents(
            state.events.filter(
              (event) =>
                event.sessionId === sessionId,
            ),
          ),
          paymentMoved: false,
          releaseId:
            state.sessions.get(sessionId) ?? null,
          repositorySha,
          sessionId,
        });
      });
    }

    async function putArtifact(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const data = readExactData(value, [
          "artifactType",
          "bytes",
          "expectedDigest",
          "secretCanaries",
        ]);
        if (!Buffer.isBuffer(data.bytes)) {
          fail();
        }
        const bytes = Buffer.from(data.bytes);
        let metadata;
        try {
          metadata = validateRelayArtifact({
            artifactType: data.artifactType,
            bytes,
            expectedDigest: data.expectedDigest,
            secretCanaries: data.secretCanaries,
          });
        } catch {
          fail();
        }
        await writeArtifact(
          root,
          fileSystem,
          metadata.digest,
          bytes,
        );
        return metadata;
      });
    }

    async function getArtifact(value) {
      return serialize(async () => {
        assertOpen();
        await assertDirectory(root);
        const digest = assertSha256(value);
        return readArtifact(root, fileSystem, digest);
      });
    }

    function close() {
      if (closePromise !== undefined) {
        return closePromise;
      }
      closing = true;
      const admitted = queue;
      closePromise = (async () => {
        await admitted;
        closed = true;
        let closeFailure;
        try {
          await journal.handle.sync();
        } catch {
          closeFailure = new CoordinationStorageError();
        }
        try {
          await journal.handle.close();
        } catch {
          closeFailure ??= new CoordinationStorageError();
        }
        try {
          await assertDirectory(root);
          await assertOwnerBinding(owner, fileSystem);
          await owner.handle.sync();
          await owner.handle.close();
          await fileSystem.unlink(owner.path);
          await fileSystem.unlink(owner.guardPath);
          await syncDirectory(root);
        } catch {
          closeFailure ??= new CoordinationStorageError();
        }
        try {
          await root.handle.close();
        } catch {
          closeFailure ??= new CoordinationStorageError();
        }
        if (closeFailure !== undefined) {
          throw closeFailure;
        }
      })();
      return closePromise;
    }

    const store = {
      appendEvent,
      close,
      consumeCapability,
      getArtifact,
      putArtifact,
      readEnrollment,
      readEvents,
      readReleaseView,
      registerCapability,
    };
    if (
      !Object.keys(store).every((key) =>
        STORE_METHODS.includes(key),
      )
    ) {
      fail();
    }
    return Object.freeze(store);
  } catch (error) {
    failure =
      error instanceof CoordinationStorageError
        ? error
        : new CoordinationStorageError();
  }

  if (journal !== undefined) {
    try {
      await journal.handle.close();
    } catch {
      failure ??= new CoordinationStorageError();
    }
  }
  if (owner !== undefined) {
    let safeToUnlink = false;
    try {
      await assertDirectory(root);
      await assertOwnerBinding(owner, fileSystem);
      safeToUnlink = true;
    } catch {
      failure ??= new CoordinationStorageError();
    }
    try {
      await owner.handle.close();
    } catch {
      failure ??= new CoordinationStorageError();
    }
    if (safeToUnlink) {
      try {
        await fileSystem.unlink(owner.path);
        await fileSystem.unlink(owner.guardPath);
        await syncDirectory(root);
      } catch {
        failure ??= new CoordinationStorageError();
      }
    }
  }
  try {
    await root.handle.close();
  } catch {
    failure ??= new CoordinationStorageError();
  }
  throw failure;
}
