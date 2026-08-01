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
import { types } from "node:util";

import {
  payerBootstrapClaimFingerprint,
  validatePayerBootstrapClaim,
} from "../local-mcp/payer-bootstrap-envelope.mjs";

export const APPROVED_PAYER_PUBLIC_SCHEMA =
  "clockchain.aws-approved-payer-public/v1";

const INPUT_KEYS = Object.freeze([
  "claim",
  "claimFingerprint",
  "expiresAtMs",
  "nowMs",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const KEYS = Object.freeze([
  "certificateFingerprint",
  "certificatePem",
  "claimFingerprint",
  "expiresAtMs",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
  "status",
]);
const RELEASE = /^release-[A-Za-z0-9._-]{1,96}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^(?:0|[1-9][0-9]*)$/;
const MAX_BYTES = 131_072;

export class ApprovedPayerPublicError extends Error {
  constructor() {
    super("Approved Payer public projection failed safely.");
    this.name = "ApprovedPayerPublicError";
    this.code = "APPROVED_PAYER_PUBLIC_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new ApprovedPayerPublicError();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value))
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) => ownKeys[index] !== key)
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function timestamp(value) {
  if (
    typeof value !== "string" ||
    !TIMESTAMP.test(value) ||
    BigInt(value) > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail();
  }
  return Number(value);
}

function projection(value) {
  const checked = exact(value, KEYS);
  if (
    !SHA64.test(checked.certificateFingerprint) ||
    typeof checked.certificatePem !== "string" ||
    checked.certificatePem.length === 0 ||
    Buffer.byteLength(checked.certificatePem, "utf8") > 65_536 ||
    !SHA64.test(checked.claimFingerprint) ||
    checked.paymentMoved !== false ||
    !RELEASE.test(checked.releaseId) ||
    !SHA40.test(checked.repositorySha) ||
    checked.schema !== APPROVED_PAYER_PUBLIC_SCHEMA ||
    !SESSION.test(checked.sessionId) ||
    checked.status !== "APPROVED"
  ) {
    fail();
  }
  timestamp(checked.expiresAtMs);
  return Object.freeze({ ...checked });
}

export function createApprovedPayerPublicProjection(value) {
  try {
    const input = exact(value, INPUT_KEYS);
    const nowMs = input.nowMs;
    const expiresAtMs = timestamp(input.expiresAtMs);
    if (
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      expiresAtMs <= nowMs ||
      !SHA64.test(input.claimFingerprint) ||
      !RELEASE.test(input.releaseId) ||
      !SHA40.test(input.repositorySha) ||
      !SESSION.test(input.sessionId)
    ) {
      fail();
    }
    const claim = validatePayerBootstrapClaim(input.claim);
    if (
      claim.paymentMoved !== false ||
      claim.releaseId !== input.releaseId ||
      claim.repositorySha !== input.repositorySha ||
      claim.sessionId !== input.sessionId ||
      payerBootstrapClaimFingerprint(claim) !== input.claimFingerprint
    ) {
      fail();
    }
    return projection({
      certificateFingerprint: claim.mcpTlsFingerprint,
      certificatePem: claim.mcpTlsCertificatePem,
      claimFingerprint: input.claimFingerprint,
      expiresAtMs: input.expiresAtMs,
      paymentMoved: false,
      releaseId: input.releaseId,
      repositorySha: input.repositorySha,
      schema: APPROVED_PAYER_PUBLIC_SCHEMA,
      sessionId: input.sessionId,
      status: "APPROVED",
    });
  } catch (error) {
    if (error instanceof ApprovedPayerPublicError) throw error;
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

function validPath(path) {
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    normalize(path) !== path ||
    path.includes("\0")
  ) {
    fail();
  }
}

async function existingFile(path) {
  const metadata = await lstat(path).catch((error) => {
    if (error?.code === "ENOENT") return null;
    throw error;
  });
  if (metadata === null) return null;
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600 ||
    metadata.size <= 0 ||
    metadata.size > MAX_BYTES
  ) {
    fail();
  }
  return metadata;
}

export async function writeApprovedPayerPublicProjection(path, value) {
  try {
    validPath(path);
    const checked = projection(value);
    const body = `${JSON.stringify(checked)}\n`;
    if (Buffer.byteLength(body, "utf8") > MAX_BYTES) fail();
    const directory = dirname(path);
    await mkdir(directory, { mode: 0o700, recursive: true });
    const before = await existingFile(path);
    const temporary = join(
      directory,
      `.approved-payer-${process.pid}-${Date.now()}.next`,
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
      await handle.sync();
      await handle.close();
      handle = undefined;
      const current = await existingFile(path);
      if (
        (before === null && current !== null) ||
        (before !== null && (current === null || !sameFile(before, current)))
      ) {
        fail();
      }
      await rename(temporary, path);
      await chmod(path, 0o600);
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
      return checked;
    } catch (error) {
      await handle?.close().catch(() => {});
      await rm(temporary, { force: true }).catch(() => {});
      throw error;
    }
  } catch (error) {
    if (error instanceof ApprovedPayerPublicError) throw error;
    fail();
  }
}

export async function readApprovedPayerPublicProjection(path) {
  try {
    validPath(path);
    const before = await existingFile(path);
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
      const checked = projection(value);
      if (`${JSON.stringify(checked)}\n` !== text) fail();
      return checked;
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (error instanceof ApprovedPayerPublicError) throw error;
    fail();
  }
}
