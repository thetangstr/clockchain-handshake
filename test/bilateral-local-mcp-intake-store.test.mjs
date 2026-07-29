import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { canonicalBytes } from "../src/bilateral/canonical.mjs";
import { buildPaymentIntakeToolResult, intakeDigest } from "../src/bilateral/local-mcp/payment-intake.mjs";
import {
  PAYER_MCP_INTAKE_DIRECTORY_NAME,
  PAYER_MCP_INTAKE_RECORD_SCHEMA,
  createPayerMcpIntakeStore,
} from "../src/bilateral/local-mcp/intake-store.mjs";

const REPOSITORY_SHA = "a".repeat(40);
const OTHER_REPOSITORY_SHA = "b".repeat(40);
const INTAKE_REQUEST_ID = "00000000-0000-4000-8000-000000000000";
const OTHER_INTAKE_REQUEST_ID = "11111111-1111-4111-8111-111111111111";
const GENERIC_ERROR = /Payer MCP intake store failed safely\./;
const SECRET_WORDS = [
  "authorization",
  "capability",
  "token",
  "invitation",
  "private",
  "tls",
  "evidence",
  "secret-value",
];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object") throw new TypeError("invalid canonical value");
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

const storeBytes = (value) => Buffer.from(canonicalJson(value), "utf8");

function validInput(overrides = {}) {
  return {
    amount: { currency: "USD", value: "100" },
    intakeRequestId: INTAKE_REQUEST_ID,
    invoiceReference: "invoice-001",
    paymentMoved: false,
    purpose: "Handshake demo",
    schema: "clockchain.payer-mcp-payment-intake/v1",
    ...overrides,
  };
}

function expectedRecord(input = validInput(), result = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input })) {
  return {
    digest: sha256(storeBytes({
      paymentMoved: false,
      repositorySha: REPOSITORY_SHA,
      request: input,
      response: result,
    })),
    intakeDigest: intakeDigest(input),
    intakeRequestId: input.intakeRequestId,
    paymentMoved: false,
    policy: {
      amount: { currency: "USD", value: "100" },
      invoiceReferencePrefix: "invoice-",
      purpose: "Handshake demo",
    },
    repositorySha: REPOSITORY_SHA,
    request: input,
    requestDigest: sha256(canonicalBytes(input)),
    response: result,
    responseDigest: sha256(storeBytes(result)),
    schema: PAYER_MCP_INTAKE_RECORD_SCHEMA,
  };
}

async function tempRoot(t) {
  const root = await mkdtemp(join(tmpdir(), "payer-intake-store-"));
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

async function recordPath(root, intakeRequestId = INTAKE_REQUEST_ID) {
  return join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, `${intakeRequestId}.json`);
}

async function assertStoreRejects(operation) {
  await assert.rejects(operation, (error) => {
    assert.match(error.message, GENERIC_ERROR);
    const text = `${error.message}\n${error.stack ?? ""}`.toLowerCase();
    for (const word of SECRET_WORDS) assert.equal(text.includes(word), false, word);
    return true;
  });
}

test("first valid intake creates a private canonical record and byte-identical retry reuses it", async (t) => {
  const root = await tempRoot(t);
  const store = await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root });
  const input = validInput();
  const response = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });

  const created = await store.writeIntake({ request: input, response });
  assert.deepEqual(created, expectedRecord(input, response));
  assert.equal(Object.isFrozen(created), true);
  assert.equal(Object.isFrozen(created.request), true);
  assert.equal(Object.isFrozen(created.response), true);

  const directoryInfo = await stat(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME));
  const fileInfo = await stat(await recordPath(root));
  assert.equal(directoryInfo.mode & 0o777, 0o700);
  assert.equal(fileInfo.mode & 0o777, 0o600);
  assert.deepEqual(await readdir(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME)), [`${INTAKE_REQUEST_ID}.json`]);
  assert.deepEqual(await readFile(await recordPath(root)), storeBytes(created));

  const before = await stat(await recordPath(root));
  const retried = await store.writeIntake({ request: structuredClone(input), response: structuredClone(response) });
  const after = await stat(await recordPath(root));
  assert.deepEqual(retried, created);
  assert.equal(after.mtimeNs, before.mtimeNs);
  assert.equal(after.ctimeNs, before.ctimeNs);
});

test("restart fully revalidates the persisted canonical request, response, digests, policy, and repository", async (t) => {
  const root = await tempRoot(t);
  const input = validInput();
  const response = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });
  await (await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root })).writeIntake({ request: input, response });

  const restarted = await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root });
  assert.deepEqual(await restarted.readIntake({ intakeRequestId: INTAKE_REQUEST_ID }), expectedRecord(input, response));
  assert.deepEqual(await restarted.readStoredIntake(), expectedRecord(input, response));
  await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: OTHER_REPOSITORY_SHA, stateRoot: root }));

  const record = JSON.parse(await readFile(await recordPath(root), "utf8"));
  for (const tampered of [
    { ...record, schema: "wrong" },
    { ...record, paymentMoved: true },
    { ...record, repositorySha: OTHER_REPOSITORY_SHA },
    { ...record, intakeRequestId: OTHER_INTAKE_REQUEST_ID },
    { ...record, digest: "0".repeat(64) },
    { ...record, requestDigest: "0".repeat(64) },
    { ...record, responseDigest: "0".repeat(64) },
    { ...record, policy: { ...record.policy, purpose: "Other" } },
    { ...record, request: { ...record.request, intakeRequestId: OTHER_INTAKE_REQUEST_ID } },
    { ...record, response: { ...record.response, structuredContent: { ...record.response.structuredContent, paymentMoved: true } } },
    { ...record, unknown: true },
  ]) {
    const caseRoot = await tempRoot(t);
    await mkdir(join(caseRoot, PAYER_MCP_INTAKE_DIRECTORY_NAME), { mode: 0o700 });
    await writeFile(join(caseRoot, PAYER_MCP_INTAKE_DIRECTORY_NAME, `${INTAKE_REQUEST_ID}.json`), storeBytes(tampered), { mode: 0o600 });
    await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: caseRoot }));
  }
});

test("same intakeRequestId with changed canonical request or response bytes fails closed", async (t) => {
  const root = await tempRoot(t);
  const store = await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root });
  const input = validInput();
  const response = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: input });
  await store.writeIntake({ request: input, response });

  await assertStoreRejects(store.writeIntake({
    request: { ...input, invoiceReference: "invoice-002" },
    response,
  }));
  await assertStoreRejects(store.writeIntake({
    request: input,
    response: { ...response, content: [{ type: "text", text: "{}" }] },
  }));
});

test("rejects traversal, partial files, extras, and a second record", async (t) => {
  const root = await tempRoot(t);
  const store = await createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root });
  await store.writeIntake({
    request: validInput(),
    response: buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: validInput() }),
  });

  await assertStoreRejects(store.readIntake({ intakeRequestId: "../escape" }));
  await writeFile(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, ".intake-record-abandoned.tmp"), "{}", { mode: 0o600 });
  await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root }));
  await rm(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, ".intake-record-abandoned.tmp"));

  await writeFile(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, "notes.txt"), "x", { mode: 0o600 });
  await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root }));
  await rm(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME, "notes.txt"));

  const secondInput = validInput({ intakeRequestId: OTHER_INTAKE_REQUEST_ID });
  const secondResponse = buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: secondInput });
  await writeFile(await recordPath(root, OTHER_INTAKE_REQUEST_ID), storeBytes(expectedRecord(secondInput, secondResponse)), { mode: 0o600 });
  await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root }));
});

test("rejects unsafe filesystem metadata and noncanonical record bytes", async (t) => {
  for (const [name, setup] of [
    ["symlink", async (path, bytes) => {
      const target = `${path}.target`;
      await writeFile(target, bytes, { mode: 0o600 });
      await symlink(target, path);
    }],
    ["directory", async (path) => {
      await mkdir(path, { mode: 0o600 });
    }],
    ["hard link", async (path, bytes) => {
      const target = `${path}.target`;
      await writeFile(target, bytes, { mode: 0o600 });
      await link(target, path);
    }],
    ["wrong mode", async (path, bytes) => {
      await writeFile(path, bytes, { mode: 0o600 });
      await chmod(path, 0o644);
    }],
    ["oversized", async (path) => {
      await writeFile(path, Buffer.alloc(1_048_577, 0x20), { mode: 0o600 });
    }],
    ["noncanonical", async (path) => {
      await writeFile(path, `${JSON.stringify(expectedRecord(), null, 2)}\n`, { mode: 0o600 });
    }],
  ]) {
    assert.equal(typeof name, "string");
    const root = await tempRoot(t);
    await mkdir(join(root, PAYER_MCP_INTAKE_DIRECTORY_NAME), { mode: 0o700 });
    await setup(await recordPath(root), storeBytes(expectedRecord()));
    await assertStoreRejects(createPayerMcpIntakeStore({ repositorySha: REPOSITORY_SHA, stateRoot: root }));
  }
});

test("rejects pathname replacement during exclusive create", async (t) => {
  const root = await tempRoot(t);
  const seen = [];
  const fileSystem = {
    async lstat(path) {
      seen.push(["lstat", path]);
      return lstat(path);
    },
    mkdir,
    async open(path, flags, mode) {
      if (String(path).includes(INTAKE_REQUEST_ID) && !seen.some(([kind]) => kind === "replaced")) {
        seen.push(["replaced", path]);
        await rm(path, { force: true });
        await writeFile(path, storeBytes(expectedRecord()), { mode: 0o600 });
      }
      return (await import("node:fs/promises")).open(path, flags, mode);
    },
    readdir,
    rename: async (...args) => (await import("node:fs/promises")).rename(...args),
    unlink: async (...args) => (await import("node:fs/promises")).unlink(...args),
  };
  const store = await createPayerMcpIntakeStore({ fileSystem, repositorySha: REPOSITORY_SHA, stateRoot: root });
  await assertStoreRejects(store.writeIntake({
    request: validInput(),
    response: buildPaymentIntakeToolResult({ repositorySha: REPOSITORY_SHA, toolInput: validInput() }),
  }));
});
