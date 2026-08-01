import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  rename,
  rm,
} from "node:fs/promises";
import {
  dirname,
  isAbsolute,
  join,
  normalize,
} from "node:path";

export const PAYER_TUNNEL_HEALTH_SCHEMA =
  "clockchain.payer-tunnel-health/v1";

const KEYS = Object.freeze([
  "schema",
  "releaseId",
  "repositorySha",
  "sessionId",
  "claimFingerprint",
  "mcpTlsFingerprint",
  "observedAtMs",
  "expiresAtMs",
  "paymentMoved",
  "status",
]);
const READY_STATUS = "READY";
const STATUSES = new Set([
  "ABORTED",
  "EXPIRED",
  "READY",
  "STOPPED",
  "TOMBSTONED",
  "UNHEALTHY",
  "WAITING",
]);
const SHA256 = /^[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RELEASE_ID =
  /^release-[A-Za-z0-9._-]{1,96}$/;
const TIMESTAMP =
  /^(?:0|[1-9][0-9]*)$/;
const MAX_BYTES = 131_072;

export class TunnelHealthProjectionError extends Error {
  constructor() {
    super(
      "Tunnel health projection failed safely.",
    );
    this.name = "TunnelHealthProjectionError";
    this.code = "TUNNEL_HEALTH_PROJECTION_FAILED";
    this.category = "verification";
  }
}

function fail() {
  throw new TunnelHealthProjectionError();
}

function timestamp(value) {
  const text =
    typeof value === "number" ? String(value) : value;
  if (
    typeof text !== "string" ||
    !TIMESTAMP.test(text) ||
    BigInt(text) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  return text;
}

function optionalSha(value) {
  if (value === null) return null;
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail();
  }
  return value;
}

function optionalBoundString(value, pattern) {
  if (value === null) return null;
  if (
    typeof value !== "string" ||
    !pattern.test(value)
  ) {
    fail();
  }
  return value;
}

export function tunnelHealthProjection(input) {
  try {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      fail();
    }
    const observedAtMs = timestamp(input.observedAtMs);
    const expiresAtMs = timestamp(input.expiresAtMs);
    if (BigInt(observedAtMs) > BigInt(expiresAtMs)) {
      fail();
    }
    const status = input.status;
    if (
      typeof status !== "string" ||
      !STATUSES.has(status) ||
      input.paymentMoved !== false
    ) {
      fail();
    }
    const projection = Object.freeze({
      schema: PAYER_TUNNEL_HEALTH_SCHEMA,
      releaseId: optionalBoundString(
        input.releaseId,
        RELEASE_ID,
      ),
      repositorySha: optionalBoundString(
        input.repositorySha,
        SHA40,
      ),
      sessionId: optionalBoundString(
        input.sessionId,
        UUID_V4,
      ),
      claimFingerprint: optionalSha(
        input.claimFingerprint,
      ),
      mcpTlsFingerprint: optionalSha(
        input.mcpTlsFingerprint,
      ),
      observedAtMs,
      expiresAtMs,
      paymentMoved: false,
      status,
    });
    if (
      status === READY_STATUS &&
      (projection.releaseId === null ||
        projection.repositorySha === null ||
        projection.sessionId === null ||
        projection.claimFingerprint === null ||
        projection.mcpTlsFingerprint === null)
    ) {
      fail();
    }
    return projection;
  } catch (error) {
    if (error instanceof TunnelHealthProjectionError) {
      throw error;
    }
    fail();
  }
}

export function isPayerMcpReadyProjection(value) {
  try {
    const projection = tunnelHealthProjection(value);
    return (
      projection.schema ===
        PAYER_TUNNEL_HEALTH_SCHEMA &&
      projection.paymentMoved === false &&
      projection.status === READY_STATUS &&
      projection.releaseId !== null &&
      projection.repositorySha !== null &&
      projection.sessionId !== null &&
      projection.claimFingerprint !== null &&
      projection.mcpTlsFingerprint !== null
    );
  } catch {
    return false;
  }
}

function canonicalJson(value) {
  return `${JSON.stringify(
    Object.fromEntries(
      KEYS.map((key) => [key, value[key]]),
    ),
  )}\n`;
}

function validatePath(path) {
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    normalize(path) !== path ||
    path.includes("\0")
  ) {
    fail();
  }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function sameStableFile(left, right) {
  return (
    left.isFile() &&
    right.isFile() &&
    !left.isSymbolicLink() &&
    !right.isSymbolicLink() &&
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.ctimeMs === right.ctimeMs &&
    left.mtimeMs === right.mtimeMs
  );
}

async function existingFileIdentity(path) {
  const stats = await lstat(path).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  if (stats === null) return null;
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1
  ) {
    fail();
  }
  return stats;
}

async function existingPrivateFile(path) {
  const stats = await lstat(path).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  if (stats === null) return null;
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    stats.nlink !== 1 ||
    (stats.mode & 0o777) !== 0o600 ||
    stats.size <= 0 ||
    stats.size > MAX_BYTES
  ) {
    fail();
  }
  return stats;
}

export async function writeTunnelHealthProjection(
  path,
  input,
) {
  validatePath(path);
  const projection = tunnelHealthProjection(input);
  const body = canonicalJson(projection);
  const directory = dirname(path);
  await mkdir(directory, {
    mode: 0o700,
    recursive: true,
  });
  const before = await existingFileIdentity(path);
  const temporary = join(
    directory,
    `.tunnel-health-${process.pid}-${Date.now()}.next`,
  );
  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.writeFile(body, "utf8");
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    const current = await existingFileIdentity(path);
    if (
      (before === null && current !== null) ||
      (before !== null &&
        (current === null ||
          !sameFile(before, current)))
    ) {
      fail();
    }
    await rename(temporary, path);
    await chmod(path, 0o600);
    const after = await existingFileIdentity(path);
    if (after === null) fail();
    const directoryHandle = await open(
      directory,
      constants.O_RDONLY |
        (constants.O_DIRECTORY ?? 0) |
        (constants.O_NOFOLLOW ?? 0),
    );
    try {
      await directoryHandle.sync();
    } finally {
      await directoryHandle.close();
    }
    return projection;
  } catch (error) {
    await handle?.close().catch(() => {});
    await rm(temporary, { force: true }).catch(
      () => {},
    );
    if (error instanceof TunnelHealthProjectionError) {
      throw error;
    }
    fail();
  }
}

export async function readTunnelHealthProjection(path) {
  try {
    validatePath(path);
    const before = await existingPrivateFile(path);
    if (before === null) return null;
    const handle = await open(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = await handle.stat();
      if (
        (opened.mode & 0o777) !== 0o600 ||
        opened.nlink !== 1 ||
        !sameStableFile(before, opened)
      ) {
        fail();
      }
      const bytes = await handle.readFile();
      const after = await lstat(path);
      const final = await handle.stat();
      if (
        bytes.length !== before.size ||
        after.size !== before.size ||
        final.size !== before.size ||
        after.nlink !== 1 ||
        final.nlink !== 1 ||
        (after.mode & 0o777) !== 0o600 ||
        (final.mode & 0o777) !== 0o600 ||
        !sameStableFile(before, after) ||
        !sameStableFile(before, final)
      ) {
        fail();
      }
      const text = bytes.toString("utf8");
      if (!text.endsWith("\n")) fail();
      let value;
      try {
        value = JSON.parse(text.slice(0, -1));
      } catch {
        fail();
      }
      const projection = tunnelHealthProjection(value);
      if (canonicalJson(projection) !== text) fail();
      return projection;
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof TunnelHealthProjectionError) {
      throw error;
    }
    fail();
  }
}
