import {
  constants as fsConstants,
} from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  rename,
  rm,
  rmdir,
  unlink,
} from "node:fs/promises";
import {
  dirname,
  join,
  resolve,
} from "node:path";
import { types } from "node:util";

export const AWS_EFS_LEASE_SCHEMA =
  "clockchain.aws-efs-lease/v1";
export const AWS_EFS_LEASE_FILE = "lease.json";

const RECORD_KEYS = Object.freeze([
  "acquiredAtMs",
  "expiresAtMs",
  "leaseNonce",
  "ownerTaskArn",
  "schema",
]);
const UUID_V4_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_ARN_PATTERN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_RECORD_BYTES = 2_048;
const DIRECTORY_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_DIRECTORY ?? 0) |
  (fsConstants.O_NOFOLLOW ?? 0);
const READ_FLAGS =
  fsConstants.O_RDONLY |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);
const CREATE_FLAGS =
  fsConstants.O_WRONLY |
  fsConstants.O_CREAT |
  fsConstants.O_EXCL |
  (fsConstants.O_NOFOLLOW ?? 0) |
  (fsConstants.O_NONBLOCK ?? 0);

export class AwsEfsLeaseError extends Error {
  constructor() {
    super("AWS EFS lease failed safely.");
    this.name = "AwsEfsLeaseError";
    this.code = "AWS_EFS_LEASE_INVALID";
    this.category = "verification";
  }
}

export function createHeartbeatOwnerLease({
  cancel = clearTimeout,
  intervalMs,
  lease,
  schedule = setTimeout,
} = {}) {
  try {
    if (
      lease === null ||
      typeof lease !== "object" ||
      Array.isArray(lease) ||
      types.isProxy(lease) ||
      typeof lease.acquire !== "function" ||
      typeof schedule !== "function" ||
      typeof cancel !== "function" ||
      !Number.isSafeInteger(intervalMs) ||
      intervalMs < 250 ||
      intervalMs > 60_000
    ) {
      invalid();
    }
    return Object.freeze({
      async acquire(input) {
        try {
          const underlying =
            await lease.acquire(input);
          if (
            underlying === null ||
            typeof underlying !== "object" ||
            Array.isArray(underlying) ||
            types.isProxy(underlying) ||
            typeof underlying.assertCurrent !==
              "function" ||
            typeof underlying.heartbeat !==
              "function" ||
            typeof underlying.release !== "function"
          ) {
            invalid();
          }
          let active = true;
          let failure = null;
          let timer;
          let inFlight = Promise.resolve();
          const arm = (callback) => {
            try {
              timer = schedule(
                callback,
                intervalMs,
              );
              timer?.unref?.();
            } catch (error) {
              failure = error;
            }
          };
          const tick = () => {
            if (!active || failure !== null) return;
            inFlight = Promise.resolve()
              .then(() => underlying.heartbeat())
              .catch((error) => {
                failure = error;
              })
              .finally(() => {
                if (active && failure === null) {
                  arm(tick);
                }
              });
            return inFlight;
          };
          arm(tick);
          if (failure !== null) {
            try {
              await underlying.release();
            } catch {
              // The fixed lease failure below is authoritative.
            }
            invalid();
          }
          return Object.freeze({
            async assertCurrent() {
              try {
                if (!active || failure !== null) {
                  invalid();
                }
                await underlying.assertCurrent();
                if (failure !== null) invalid();
              } catch (error) {
                sanitize(error);
              }
            },
            async release() {
              try {
                if (!active) invalid();
                active = false;
                cancel(timer);
                await inFlight;
                let releaseFailure;
                try {
                  await underlying.release();
                } catch (error) {
                  releaseFailure = error;
                }
                if (
                  failure !== null ||
                  releaseFailure !== undefined
                ) {
                  invalid();
                }
              } catch (error) {
                sanitize(error);
              }
            },
          });
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}

function invalid() {
  throw new AwsEfsLeaseError();
}

function sanitize(error) {
  if (error instanceof AwsEfsLeaseError) throw error;
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

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !DECIMAL_PATTERN.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    invalid();
  }
  return value;
}

function clock(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    invalid();
  }
  return value;
}

function taskArn(value) {
  if (
    typeof value !== "string" ||
    !TASK_ARN_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function nonce(value) {
  if (
    typeof value !== "string" ||
    !UUID_V4_PATTERN.test(value)
  ) {
    invalid();
  }
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    resolve(value) !== value ||
    dirname(value) === value
  ) {
    invalid();
  }
  return value;
}

function identity(stats) {
  return Object.freeze({
    ctimeMs: stats.ctimeMs,
    dev: stats.dev,
    gid: stats.gid,
    ino: stats.ino,
    mode: stats.mode,
    mtimeMs: stats.mtimeMs,
    uid: stats.uid,
  });
}

function sameIdentity(stats, expected) {
  return (
    stats.ctimeMs === expected.ctimeMs &&
    stats.dev === expected.dev &&
    stats.gid === expected.gid &&
    stats.ino === expected.ino &&
    stats.mode === expected.mode &&
    stats.mtimeMs === expected.mtimeMs &&
    stats.uid === expected.uid
  );
}

function sameDirectoryIdentity(stats, expected) {
  return (
    stats.dev === expected.dev &&
    stats.gid === expected.gid &&
    stats.ino === expected.ino &&
    stats.mode === expected.mode &&
    stats.uid === expected.uid
  );
}

function privateDirectory(stats) {
  return (
    stats.isDirectory() &&
    !stats.isSymbolicLink() &&
    (stats.mode & 0o777) === 0o700
  );
}

function privateFile(stats) {
  return (
    stats.isFile() &&
    !stats.isSymbolicLink() &&
    stats.nlink === 1 &&
    (stats.mode & 0o777) === 0o600 &&
    stats.size > 0 &&
    stats.size <= MAX_RECORD_BYTES
  );
}

function recordSnapshot(value) {
  const record = exactObject(value, RECORD_KEYS);
  timestamp(record.acquiredAtMs);
  timestamp(record.expiresAtMs);
  if (
    Number(record.expiresAtMs) <=
      Number(record.acquiredAtMs) ||
    nonce(record.leaseNonce) !==
      record.leaseNonce ||
    taskArn(record.ownerTaskArn) !==
      record.ownerTaskArn ||
    record.schema !== AWS_EFS_LEASE_SCHEMA
  ) {
    invalid();
  }
  return Object.freeze({
    acquiredAtMs: record.acquiredAtMs,
    expiresAtMs: record.expiresAtMs,
    leaseNonce: record.leaseNonce,
    ownerTaskArn: record.ownerTaskArn,
    schema: AWS_EFS_LEASE_SCHEMA,
  });
}

function recordBytes(value) {
  const record = recordSnapshot(value);
  const bytes = Buffer.from(
    JSON.stringify(record),
    "utf8",
  );
  if (
    bytes.length === 0 ||
    bytes.length > MAX_RECORD_BYTES
  ) {
    invalid();
  }
  return bytes;
}

function parseRecord(bytes) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length === 0 ||
    bytes.length > MAX_RECORD_BYTES
  ) {
    invalid();
  }
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
  const record = recordSnapshot(value);
  if (!recordBytes(record).equals(bytes)) invalid();
  return record;
}

async function syncDirectory(handle) {
  await handle.sync();
}

async function writeNewFile(path, bytes) {
  let handle;
  try {
    handle = await open(path, CREATE_FLAGS, 0o600);
    const opened = await handle.stat();
    if (!privateFile(opened) && opened.size !== 0) {
      invalid();
    }
    await handle.write(bytes, 0, bytes.length, 0);
    await handle.sync();
    const after = await handle.stat();
    if (
      !privateFile(after) ||
      after.size !== bytes.length
    ) {
      invalid();
    }
  } catch (error) {
    sanitize(error);
  } finally {
    await handle?.close();
  }
}

async function readPinnedRecord(path) {
  let handle;
  try {
    const before = await lstat(path);
    if (!privateFile(before)) invalid();
    handle = await open(path, READ_FLAGS);
    const opened = await handle.stat();
    if (
      !privateFile(opened) ||
      !sameIdentity(
        opened,
        identity(before),
      )
    ) {
      invalid();
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    const pathname = await lstat(path);
    if (
      bytes.length !== before.size ||
      !sameIdentity(after, identity(before)) ||
      !sameIdentity(pathname, identity(before))
    ) {
      invalid();
    }
    return Object.freeze({
      identity: identity(before),
      record: parseRecord(bytes),
    });
  } catch (error) {
    sanitize(error);
  } finally {
    await handle?.close();
  }
}

async function inspectLease(path) {
  let directoryHandle;
  try {
    const before = await lstat(path);
    if (!privateDirectory(before)) invalid();
    directoryHandle = await open(
      path,
      DIRECTORY_FLAGS,
    );
    const opened = await directoryHandle.stat();
    if (
      !privateDirectory(opened) ||
      !sameDirectoryIdentity(
        opened,
        identity(before),
      )
    ) {
      invalid();
    }
    const pinned = await readPinnedRecord(
      join(path, AWS_EFS_LEASE_FILE),
    );
    const after = await lstat(path);
    if (
      !sameDirectoryIdentity(
        after,
        identity(before),
      )
    ) {
      invalid();
    }
    return {
      directoryHandle,
      directoryIdentity: identity(before),
      record: pinned.record,
      recordIdentity: pinned.identity,
    };
  } catch (error) {
    await directoryHandle?.close();
    sanitize(error);
  }
}

async function assertSnapshot(path, snapshot) {
  const current = await inspectLease(path);
  try {
    if (
      !sameDirectoryIdentity(
        await snapshot.directoryHandle.stat(),
        snapshot.directoryIdentity,
      ) ||
      !sameDirectoryIdentity(
        await current.directoryHandle.stat(),
        snapshot.directoryIdentity,
      ) ||
      current.record.leaseNonce !==
        snapshot.record.leaseNonce ||
      current.record.ownerTaskArn !==
        snapshot.record.ownerTaskArn ||
      current.record.acquiredAtMs !==
        snapshot.record.acquiredAtMs ||
      current.record.expiresAtMs !==
        snapshot.record.expiresAtMs ||
      !sameIdentity(
        current.recordIdentity,
        snapshot.recordIdentity,
      )
    ) {
      invalid();
    }
    return current;
  } catch (error) {
    sanitize(error);
  } finally {
    await current.directoryHandle.close();
  }
}

async function initializeLease({
  acquiredAtMs,
  leaseNonce,
  leasePath,
  ownerTaskArn,
  ttlMs,
}) {
  await mkdir(leasePath, { mode: 0o700 });
  await chmod(leasePath, 0o700);
  let directoryHandle;
  try {
    directoryHandle = await open(
      leasePath,
      DIRECTORY_FLAGS,
    );
    const stats = await directoryHandle.stat();
    if (!privateDirectory(stats)) invalid();
    const record = recordSnapshot({
      acquiredAtMs: String(acquiredAtMs),
      expiresAtMs: String(acquiredAtMs + ttlMs),
      leaseNonce,
      ownerTaskArn,
      schema: AWS_EFS_LEASE_SCHEMA,
    });
    await writeNewFile(
      join(leasePath, AWS_EFS_LEASE_FILE),
      recordBytes(record),
    );
    await syncDirectory(directoryHandle);
    await directoryHandle.close();
    directoryHandle = undefined;
    return inspectLease(leasePath);
  } catch (error) {
    await directoryHandle?.close();
    sanitize(error);
  }
}

export function createAwsEfsLeaseManager({
  leasePath,
  nowMs = Date.now,
  ownerTaskArn,
  randomUUID,
  ttlMs,
} = {}) {
  try {
    const path = absolutePath(leasePath);
    const owner = taskArn(ownerTaskArn);
    if (
      typeof nowMs !== "function" ||
      typeof randomUUID !== "function" ||
      !Number.isSafeInteger(ttlMs) ||
      ttlMs < 1_000 ||
      ttlMs > 300_000
    ) {
      invalid();
    }
    const ttl = ttlMs;
    return Object.freeze({
      async acquire() {
        try {
          const acquiredAt = clock(nowMs());
          const leaseNonce = nonce(randomUUID());
          let snapshot;
          try {
            snapshot = await initializeLease({
              acquiredAtMs: acquiredAt,
              leaseNonce,
              leasePath: path,
              ownerTaskArn: owner,
              ttlMs: ttl,
            });
          } catch (error) {
            if (error?.cause?.code !== "EEXIST") {
              let exists = false;
              try {
                await lstat(path);
                exists = true;
              } catch (lookupError) {
                if (lookupError?.code !== "ENOENT") {
                  throw error;
                }
              }
              if (!exists) throw error;
            }
            const expired = await inspectLease(path);
            if (
              acquiredAt <
                Number(expired.record.acquiredAtMs) ||
              acquiredAt <
                Number(expired.record.expiresAtMs)
            ) {
              await expired.directoryHandle.close();
              invalid();
            }
            const tombstone =
              `${path}.expired-${leaseNonce}`;
            try {
              await rename(path, tombstone);
              const moved = await lstat(tombstone);
              if (
                !sameDirectoryIdentity(
                  moved,
                  expired.directoryIdentity,
                )
              ) {
                invalid();
              }
            } finally {
              await expired.directoryHandle.close();
            }
            snapshot = await initializeLease({
              acquiredAtMs: acquiredAt,
              leaseNonce,
              leasePath: path,
              ownerTaskArn: owner,
              ttlMs: ttl,
            });
            await rm(tombstone, {
              force: false,
              recursive: true,
            });
          }

          let active = true;
          const handle = {
            get record() {
              return snapshot.record;
            },

            async assertCurrent() {
              try {
                if (!active) invalid();
                await assertSnapshot(path, snapshot);
                const current = clock(nowMs());
                if (
                  current <
                    Number(
                      snapshot.record.acquiredAtMs,
                    ) ||
                  current >=
                    Number(
                      snapshot.record.expiresAtMs,
                    )
                ) {
                  invalid();
                }
                return snapshot.record;
              } catch (error) {
                sanitize(error);
              }
            },

            async heartbeat() {
              try {
                if (!active) invalid();
                const current = clock(nowMs());
                const previousHeartbeat =
                  Number(
                    snapshot.record.expiresAtMs,
                  ) - ttl;
                if (
                  current < previousHeartbeat ||
                  current >=
                    Number(
                      snapshot.record.expiresAtMs,
                    )
                ) {
                  invalid();
                }
                await assertSnapshot(path, snapshot);
                const next = recordSnapshot({
                  acquiredAtMs:
                    snapshot.record.acquiredAtMs,
                  expiresAtMs: String(current + ttl),
                  leaseNonce:
                    snapshot.record.leaseNonce,
                  ownerTaskArn:
                    snapshot.record.ownerTaskArn,
                  schema: AWS_EFS_LEASE_SCHEMA,
                });
                const temporary = join(
                  path,
                  `.lease-${next.leaseNonce}.tmp`,
                );
                try {
                  await writeNewFile(
                    temporary,
                    recordBytes(next),
                  );
                  await assertSnapshot(path, snapshot);
                  await rename(
                    temporary,
                    join(path, AWS_EFS_LEASE_FILE),
                  );
                  await syncDirectory(
                    snapshot.directoryHandle,
                  );
                } finally {
                  try {
                    await unlink(temporary);
                  } catch (error) {
                    if (error?.code !== "ENOENT") {
                      throw error;
                    }
                  }
                }
                const replacement =
                  await inspectLease(path);
                if (
                  !sameDirectoryIdentity(
                    await replacement.directoryHandle.stat(),
                    snapshot.directoryIdentity,
                  ) ||
                  replacement.record.leaseNonce !==
                    next.leaseNonce ||
                  replacement.record.expiresAtMs !==
                    next.expiresAtMs
                ) {
                  await replacement.directoryHandle.close();
                  invalid();
                }
                await snapshot.directoryHandle.close();
                snapshot = replacement;
                return snapshot.record;
              } catch (error) {
                sanitize(error);
              }
            },

            async release() {
              try {
                if (!active) invalid();
                await assertSnapshot(path, snapshot);
                await unlink(
                  join(path, AWS_EFS_LEASE_FILE),
                );
                await syncDirectory(
                  snapshot.directoryHandle,
                );
                await snapshot.directoryHandle.close();
                await rmdir(path);
                active = false;
              } catch (error) {
                sanitize(error);
              }
            },
          };
          return Object.freeze(handle);
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
