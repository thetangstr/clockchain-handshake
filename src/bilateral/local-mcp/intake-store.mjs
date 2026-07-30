import { constants } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { link, lstat, mkdir, open, readdir, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";

import { canonicalBytes } from "../canonical.mjs";
import { DEMO_INTENT_POLICY } from "../demo-intent-policy.mjs";
import {
  buildPaymentIntakeToolResult,
  intakeDigest,
  validatePaymentIntakeInput,
  validatePaymentIntakeToolResult,
} from "./payment-intake.mjs";

export const PAYER_MCP_INTAKE_DIRECTORY_NAME = "payer-mcp-intake";
export const PAYER_MCP_INTAKE_RECORD_SCHEMA = "clockchain.payer-mcp-intake-record/v1";

const MAX_RECORD_BYTES = 1_048_576;
const UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const REPOSITORY_SHA_PATTERN = /^[0-9a-f]{40}$/;
const RECORD_NAME_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$/;
const RECORD_KEYS = Object.freeze([
  "digest",
  "intakeDigest",
  "intakeRequestId",
  "paymentMoved",
  "policy",
  "repositorySha",
  "request",
  "requestDigest",
  "response",
  "responseDigest",
  "schema",
]);
const POLICY_KEYS = Object.freeze(["amount", "invoiceReferencePrefix", "purpose"]);
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const expectedUid = process.getuid?.();

function fail() {
  throw new Error("Payer MCP intake store failed safely.");
}

function sanitize(error) {
  if (error?.code === "ENOENT" || error?.message === "Payer MCP intake store failed safely.") throw error;
  fail();
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "bigint" || value === undefined) fail();
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function recordBytes(value) {
  return Buffer.from(canonicalJson(value), "utf8");
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function privateDirectory(metadata) {
  return metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.uid === expectedUid && (metadata.mode & 0o777) === 0o700;
}

function privateFile(metadata) {
  return metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 && metadata.uid === expectedUid && (metadata.mode & 0o777) === 0o600;
}

function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function exactDataObject(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail();
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.length !== keys.length || keys.some((key, index) => ownKeys[index] !== key)) fail();
    const entries = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      entries[key] = descriptor.value;
    }
    return entries;
  } catch {
    fail();
  }
}

function exactUnorderedDataObject(value, keys) {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail();
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) fail();
    const ownKeys = Reflect.ownKeys(value);
    if (
      ownKeys.length !== keys.length ||
      keys.some((key) => !ownKeys.includes(key))
    ) {
      fail();
    }
    const entries = Object.create(null);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail();
      entries[key] = descriptor.value;
    }
    return entries;
  } catch {
    fail();
  }
}

function validatedPolicy(value) {
  const policy = exactDataObject(value, POLICY_KEYS);
  const amount = exactDataObject(policy.amount, ["currency", "value"]);
  if (
    amount.currency !== DEMO_INTENT_POLICY.amount.currency ||
    amount.value !== DEMO_INTENT_POLICY.amount.value ||
    policy.invoiceReferencePrefix !== DEMO_INTENT_POLICY.invoiceReferencePrefix ||
    policy.purpose !== DEMO_INTENT_POLICY.purpose
  ) {
    fail();
  }
  return {
    amount: { currency: amount.currency, value: amount.value },
    invoiceReferencePrefix: policy.invoiceReferencePrefix,
    purpose: policy.purpose,
  };
}

function normalizedResponse({ repositorySha, request, response }) {
  const supplied = response ?? buildPaymentIntakeToolResult({ repositorySha, toolInput: request });
  const structuredContent = validatePaymentIntakeToolResult({
    repositorySha,
    result: supplied,
    toolInput: request,
  });
  const normalized = {
    structuredContent,
    content: [{ type: "text", text: canonicalBytes(structuredContent).toString("utf8") }],
  };
  if (!recordBytes(normalized).equals(recordBytes(supplied))) fail();
  return normalized;
}

function storedResponseForValidation(value) {
  const response = exactUnorderedDataObject(value, ["content", "structuredContent"]);
  const content = Array.isArray(response.content) && response.content.length === 1
    ? response.content
    : fail();
  const block = exactUnorderedDataObject(content[0], ["text", "type"]);
  return {
    structuredContent: response.structuredContent,
    content: [{ type: block.type, text: block.text }],
  };
}

function buildRecord({ repositorySha, request, response }) {
  if (!REPOSITORY_SHA_PATTERN.test(repositorySha)) fail();
  const validatedRequest = validatePaymentIntakeInput(request);
  const validatedResponse = normalizedResponse({ repositorySha, request: validatedRequest, response });
  const digestBody = {
    paymentMoved: false,
    repositorySha,
    request: validatedRequest,
    response: validatedResponse,
  };
  return deepFreeze({
    digest: sha256(recordBytes(digestBody)),
    intakeDigest: intakeDigest(validatedRequest),
    intakeRequestId: validatedRequest.intakeRequestId,
    paymentMoved: false,
    policy: {
      amount: { ...DEMO_INTENT_POLICY.amount },
      invoiceReferencePrefix: DEMO_INTENT_POLICY.invoiceReferencePrefix,
      purpose: DEMO_INTENT_POLICY.purpose,
    },
    repositorySha,
    request: validatedRequest,
    requestDigest: sha256(canonicalBytes(validatedRequest)),
    response: validatedResponse,
    responseDigest: sha256(recordBytes(validatedResponse)),
    schema: PAYER_MCP_INTAKE_RECORD_SCHEMA,
  });
}

function validateRecord({ record, repositorySha }) {
  const value = exactDataObject(record, RECORD_KEYS);
  if (
    value.schema !== PAYER_MCP_INTAKE_RECORD_SCHEMA ||
    value.paymentMoved !== false ||
    value.repositorySha !== repositorySha ||
    !DIGEST_PATTERN.test(value.digest) ||
    !DIGEST_PATTERN.test(value.intakeDigest) ||
    !DIGEST_PATTERN.test(value.requestDigest) ||
    !DIGEST_PATTERN.test(value.responseDigest)
  ) {
    fail();
  }
  const request = validatePaymentIntakeInput(value.request);
  if (value.intakeRequestId !== request.intakeRequestId || value.intakeDigest !== intakeDigest(request)) fail();
  const response = normalizedResponse({ repositorySha, request, response: storedResponseForValidation(value.response) });
  if (value.requestDigest !== sha256(canonicalBytes(request)) || value.responseDigest !== sha256(recordBytes(response))) fail();
  const policy = validatedPolicy(value.policy);
  const expected = buildRecord({ repositorySha, request, response });
  if (!recordBytes(expected).equals(recordBytes({ ...value, policy, request, response }))) fail();
  if (value.digest !== expected.digest) fail();
  return expected;
}

function defaultFileSystem(value) {
  if (value === undefined) return Object.freeze({ link, lstat, mkdir, open, readdir, unlink });
  const keys = ["link", "lstat", "mkdir", "open", "readdir", "unlink"];
  if (!value || keys.some((key) => typeof value[key] !== "function")) fail();
  return value;
}

function validateStateRoot(stateRoot) {
  if (typeof stateRoot !== "string" || expectedUid === undefined || stateRoot.includes("\0")) fail();
  const resolved = resolve(stateRoot);
  if (resolved !== stateRoot) fail();
  return resolved;
}

function intakeDirectory(stateRoot) {
  return join(stateRoot, PAYER_MCP_INTAKE_DIRECTORY_NAME);
}

function recordPath(stateRoot, intakeRequestId) {
  if (typeof intakeRequestId !== "string" || !UUID_V4_PATTERN.test(intakeRequestId)) fail();
  return join(intakeDirectory(stateRoot), `${intakeRequestId}.json`);
}

async function pinDirectory(path, fs) {
  let handle;
  try {
    const before = await fs.lstat(path);
    if (!privateDirectory(before)) fail();
    handle = await fs.open(path, constants.O_RDONLY | constants.O_DIRECTORY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!privateDirectory(opened) || !sameIdentity(before, opened)) fail();
    const pinnedHandle = handle;
    const root = Object.freeze({
      before,
      handle: pinnedHandle,
      path,
      async assertPinned() {
        const current = await fs.lstat(path);
        const pinned = await pinnedHandle.stat();
        if (!privateDirectory(current) || !privateDirectory(pinned) || !sameIdentity(before, current) || !sameIdentity(before, pinned)) fail();
      },
    });
    handle = undefined;
    return root;
  } catch (error) {
    if (handle) await handle.close();
    sanitize(error);
  }
}

async function ensureDirectory(path, fs) {
  try {
    await fs.mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") sanitize(error);
  }
  return pinDirectory(path, fs);
}

async function readStableFile(path, fs) {
  let handle;
  try {
    const before = await fs.lstat(path);
    if (!privateFile(before) || before.size <= 0 || before.size > MAX_RECORD_BYTES) fail();
    handle = await fs.open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!privateFile(opened) || !sameIdentity(before, opened)) fail();
    const buffer = Buffer.allocUnsafe(before.size + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead !== before.size) fail();
    const after = await fs.lstat(path);
    if (!privateFile(after) || !sameIdentity(before, after)) fail();
    return buffer.subarray(0, bytesRead);
  } catch (error) {
    sanitize(error);
  } finally {
    if (handle) await handle.close();
  }
}

async function readRecordBytes(path, repositorySha, fs) {
  const bytes = await readStableFile(path, fs);
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!recordBytes(parsed).equals(bytes)) fail();
  const record = validateRecord({ record: parsed, repositorySha });
  if (!recordBytes(record).equals(bytes)) fail();
  return Object.freeze({ bytes, record });
}

async function scanDirectory({ allowMissing, repositorySha, stateRoot, fs }) {
  const directory = intakeDirectory(stateRoot);
  let root;
  try {
    root = await pinDirectory(directory, fs);
  } catch (error) {
    if (allowMissing && error?.code === "ENOENT") return null;
    throw error;
  }
  try {
    await root.assertPinned();
    const entries = await fs.readdir(directory);
    if (entries.length === 0) return null;
    if (entries.length !== 1 || !RECORD_NAME_PATTERN.test(entries[0])) fail();
    const recordFile = join(directory, entries[0]);
    const { record } = await readRecordBytes(recordFile, repositorySha, fs);
    if (recordFile !== recordPath(stateRoot, record.intakeRequestId)) fail();
    await root.assertPinned();
    return record;
  } finally {
    await root.handle.close();
  }
}

async function writeExclusiveRecord({ bytes, path, root, fs }) {
  const temporary = join(root.path, `.intake-record-${randomBytes(16).toString("hex")}.tmp`);
  let handle;
  try {
    await root.assertPinned();
    handle = await fs.open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    if (!privateFile(await handle.stat())) fail();
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await root.assertPinned();
    await fs.link(temporary, path);
    await root.handle.sync();
    await fs.unlink(temporary);
    await root.handle.sync();
    const readback = await readStableFile(path, fs);
    if (!readback.equals(bytes)) fail();
  } catch (error) {
    if (handle) await handle.close();
    await fs.unlink(temporary).catch(() => {});
    sanitize(error);
  }
}

async function persistRecord({ record, stateRoot, fs }) {
  const directory = intakeDirectory(stateRoot);
  const root = await ensureDirectory(directory, fs);
  try {
    const entries = await fs.readdir(directory);
    const expectedName = `${record.intakeRequestId}.json`;
    if (entries.length > 1 || entries.some((entry) => entry !== expectedName)) fail();
    const path = recordPath(stateRoot, record.intakeRequestId);
    const bytes = recordBytes(record);
    if (entries.length === 1) {
      const existing = await readRecordBytes(path, record.repositorySha, fs);
      if (!existing.bytes.equals(bytes)) fail();
      return existing.record;
    }
    await writeExclusiveRecord({ bytes, fs, path, root });
    return (await readRecordBytes(path, record.repositorySha, fs)).record;
  } finally {
    await root.handle.close();
  }
}

export async function scanPayerMcpIntakeDirectory({ repositorySha, stateRoot, fileSystem } = {}) {
  const fs = defaultFileSystem(fileSystem);
  const root = validateStateRoot(stateRoot);
  if (!REPOSITORY_SHA_PATTERN.test(repositorySha)) fail();
  try {
    await scanDirectory({ allowMissing: true, fs, repositorySha, stateRoot: root });
  } catch (error) {
    sanitize(error);
  }
  return true;
}

export async function createPayerMcpIntakeStore({ repositorySha, stateRoot, fileSystem } = {}) {
  const fs = defaultFileSystem(fileSystem);
  const root = validateStateRoot(stateRoot);
  if (!REPOSITORY_SHA_PATTERN.test(repositorySha)) fail();
  await ensureDirectory(root, fs).then((pinned) => pinned.handle.close());
  try {
    await scanDirectory({ allowMissing: true, fs, repositorySha, stateRoot: root });
  } catch (error) {
    sanitize(error);
  }
  return Object.freeze({
    async writeIntake({ request, response } = {}) {
      try {
        const record = buildRecord({ repositorySha, request, response });
        return await persistRecord({ fs, record, stateRoot: root });
      } catch (error) {
        sanitize(error);
      }
    },
    async readIntake({ intakeRequestId } = {}) {
      try {
        const path = recordPath(root, intakeRequestId);
        return (await readRecordBytes(path, repositorySha, fs)).record;
      } catch (error) {
        sanitize(error);
      }
    },
    async readStoredIntake() {
      try {
        return await scanDirectory({ allowMissing: true, fs, repositorySha, stateRoot: root });
      } catch (error) {
        sanitize(error);
      }
    },
  });
}
