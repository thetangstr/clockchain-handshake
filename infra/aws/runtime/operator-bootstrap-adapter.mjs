import {
  constants as fsConstants,
} from "node:fs";
import {
  lstat,
  mkdir,
  open,
} from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { types } from "node:util";

import {
  approveAndSealAwsBootstrapClaim,
} from "./operator-bootstrap-runtime.mjs";
import {
  buildAwsBootstrapSealedResponse,
} from "./operator-bootstrap-response.mjs";
import {
  approveBootstrapClaimState,
  createBootstrapState,
  sealBootstrapClaim,
  validateBootstrapState,
} from "../../../src/bilateral/aws/bootstrap-state.mjs";
import {
  createAwsBootstrapStateFileStore,
} from "../../../src/bilateral/aws/bootstrap-service.mjs";
import {
  validateTunnelGrantRecord,
} from "../../../src/bilateral/aws/tunnel-grant.mjs";
import {
  canonicalizeReceiptEventValue,
} from "../../../src/canonical.mjs";

const CONFIG_KEYS = Object.freeze([
  "bootstrapStatePath",
  "payerLaunchManifestPath",
  "payeeLaunchManifestPath",
  "tunnelGrantPath",
  "releaseId",
  "repositorySha",
  "sessionId",
  "operatorKeyId",
  "publicMcpHostname",
  "bootstrapBrokerUrl",
  "bootstrapBrokerCapability",
  "operatorPrivateKeyPem",
  "nowMs",
]);
const ASSERT_KEYS = Object.freeze([
  "claimFingerprint",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "role",
  "sessionId",
]);
const FINGERPRINT_INPUT_KEYS = Object.freeze([
  "releaseId",
  "sessionId",
  "state",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TIMESTAMP = /^(?:0|[1-9][0-9]*)$/;
const HOST =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_BYTES = 262_144;
const MAX_MANIFEST_BYTES = 131_072;

export class AwsOperatorBootstrapAdapterError extends Error {
  constructor() {
    super("AWS operator bootstrap adapter failed safely.");
    this.name = "AwsOperatorBootstrapAdapterError";
    this.code =
      "AWS_OPERATOR_BOOTSTRAP_ADAPTER_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorBootstrapAdapterError();
}

function sanitize(error) {
  if (
    error instanceof
    AwsOperatorBootstrapAdapterError
  ) {
    throw error;
  }
  fail();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !==
      Object.prototype ||
    Reflect.ownKeys(value).length !==
      keys.length ||
    keys.some(
      (key, index) =>
        Reflect.ownKeys(value)[index] !== key,
    )
  ) {
    fail();
  }
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
  }
  return value;
}

function absolutePath(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    resolve(value) !== value
  ) {
    fail();
  }
  return value;
}

function sameIdentity(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function canonicalBytes(value) {
  return Buffer.from(
    JSON.stringify(
      canonicalizeReceiptEventValue(value),
    ),
    "utf8",
  );
}

function config(value) {
  const input = exact(value, CONFIG_KEYS);
  for (const key of [
    "bootstrapStatePath",
    "payerLaunchManifestPath",
    "payeeLaunchManifestPath",
    "tunnelGrantPath",
  ]) {
    absolutePath(input[key]);
  }
  let brokerUrl;
  try {
    brokerUrl = new URL(input.bootstrapBrokerUrl);
  } catch {
    fail();
  }
  if (
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId) ||
    typeof input.operatorKeyId !== "string" ||
    input.operatorKeyId.length === 0 ||
    input.operatorKeyId.length > 128 ||
    !HOST.test(input.publicMcpHostname) ||
    brokerUrl.protocol !== "https:" ||
    brokerUrl.username !== "" ||
    brokerUrl.password !== "" ||
    brokerUrl.search !== "" ||
    brokerUrl.hash !== "" ||
    !SHA64.test(input.bootstrapBrokerCapability) ||
    typeof input.operatorPrivateKeyPem !== "string" ||
    input.operatorPrivateKeyPem.length === 0 ||
    typeof input.nowMs !== "function"
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function nowMs(active) {
  const value = active.nowMs();
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail();
  }
  return value;
}

function expected(value, active) {
  const input = exact(value, ASSERT_KEYS);
  if (
    !SHA64.test(input.claimFingerprint) ||
    input.paymentMoved !== false ||
    input.releaseId !== active.releaseId ||
    input.repositorySha !==
      active.repositorySha ||
    !["payer", "payee"].includes(input.role) ||
    input.sessionId !== active.sessionId
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function responseConfig(active, responseNowMs) {
  if (
    !Number.isSafeInteger(responseNowMs) ||
    responseNowMs < 0
  ) {
    fail();
  }
  return Object.freeze({
    bootstrapBrokerCapability:
      active.bootstrapBrokerCapability,
    bootstrapBrokerUrl:
      active.bootstrapBrokerUrl,
    nowMs: responseNowMs,
    operatorKeyId: active.operatorKeyId,
    operatorPrivateKeyPem:
      active.operatorPrivateKeyPem,
    publicMcpHostname:
      active.publicMcpHostname,
    releaseId: active.releaseId,
    repositorySha: active.repositorySha,
    sessionId: active.sessionId,
  });
}

function durableRole(role) {
  return role === "payee" ? "requestor" : role;
}

async function readApprovalNowMs({
  active,
  claimFingerprint,
  expiresAtMs,
  role,
}) {
  if (
    !SHA64.test(claimFingerprint) ||
    !TIMESTAMP.test(expiresAtMs)
  ) {
    fail();
  }
  const wallNowMs = nowMs(active);
  if (wallNowMs >= Number(expiresAtMs)) fail();
  const createStore =
    active.dependencies
      .createAwsBootstrapStateFileStore ??
    createAwsBootstrapStateFileStore;
  if (typeof createStore !== "function") fail();
  const store = await createStore({
    initialState: stateConfig(active),
    statePath: active.bootstrapStatePath,
  });
  const state = validateBootstrapState(
    await store.readState(),
  );
  const entry = state.claims[claimFingerprint];
  if (
    entry === undefined ||
    entry.claimFingerprint !== claimFingerprint ||
    entry.paymentMoved !== false ||
    entry.releaseId !== active.releaseId ||
    entry.sessionId !== active.sessionId ||
    entry.role !== durableRole(role) ||
    entry.status !== "APPROVED" ||
    entry.expiresAtMs !== expiresAtMs ||
    !TIMESTAMP.test(entry.updatedAtMs)
  ) {
    fail();
  }
  const approvalNowMs = Number(entry.updatedAtMs);
  if (
    !Number.isSafeInteger(approvalNowMs) ||
    approvalNowMs < 0 ||
    approvalNowMs >= Number(expiresAtMs)
  ) {
    fail();
  }
  return approvalNowMs;
}

function projectState(state, role) {
  const checked = validateBootstrapState(state);
  if (role !== "payee") return checked;
  const claims = Object.create(null);
  for (const [fingerprint, entry] of Object.entries(
    checked.claims,
  )) {
    claims[fingerprint] =
      entry.role === "requestor"
        ? Object.freeze({
            ...entry,
            role: "payee",
          })
        : entry;
  }
  return Object.freeze({
    ...checked,
    claims: Object.freeze(claims),
  });
}

function stateConfig(active) {
  return createBootstrapState({
    paymentMoved: false,
    releaseId: active.releaseId,
    repositorySha: active.repositorySha,
    schema: "clockchain.aws-bootstrap-state/v1",
    sessionId: active.sessionId,
  });
}

async function syncDirectory(path) {
  const handle = await open(
    path,
    fsConstants.O_RDONLY,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function prepareSecureDirectory(path) {
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== "EEXIST") {
      sanitize(error);
    }
  }
  let info;
  try {
    info = await lstat(path);
  } catch (error) {
    sanitize(error);
  }
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    (info.mode & 0o777) !== 0o700
  ) {
    fail();
  }
}

async function readStableFile(path, maximum) {
  let before;
  try {
    before = await lstat(path);
  } catch {
    fail();
  }
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1 ||
    before.size <= 0 ||
    before.size > maximum
  ) {
    fail();
  }
  let handle;
  try {
    handle = await open(
      path,
      fsConstants.O_RDONLY |
        (fsConstants.O_NOFOLLOW ?? 0) |
        fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (!sameIdentity(before, opened)) fail();
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      bytes.length !== before.size ||
      !sameIdentity(before, after)
    ) {
      fail();
    }
    return bytes;
  } catch (error) {
    sanitize(error);
  } finally {
    await handle?.close();
  }
}

function parseCanonical(bytes) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail();
  }
  if (!canonicalBytes(parsed).equals(bytes)) {
    fail();
  }
  return parsed;
}

async function readManifest(path) {
  return readStableFile(path, MAX_MANIFEST_BYTES);
}

async function readGrant(active) {
  const bytes = await readStableFile(
    active.tunnelGrantPath,
    MAX_BYTES,
  );
  return {
    bytes,
    grant: validateTunnelGrantRecord(
      parseCanonical(bytes),
    ),
  };
}

function assertGrantScope(grant, expectedInput, active) {
  if (
    grant.status !== "ACTIVE" ||
    grant.claimFingerprint !==
      expectedInput.claimFingerprint ||
    grant.paymentMoved !== false ||
    grant.claim?.releaseId !== active.releaseId ||
    grant.claim?.repositorySha !==
      active.repositorySha ||
    grant.claim?.sessionId !== active.sessionId
  ) {
    fail();
  }
}

async function persistGrant(active, grant) {
  const bytes = canonicalBytes(
    validateTunnelGrantRecord(grant),
  );
  const parent = dirname(active.tunnelGrantPath);
  let handle;
  try {
    await prepareSecureDirectory(parent);
    handle = await open(
      active.tunnelGrantPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    await handle.write(bytes, 0, bytes.length, 0);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await syncDirectory(parent);
  } catch (error) {
    await handle?.close();
    if (error?.code !== "EEXIST") {
      sanitize(error);
    }
    const existing = await readGrant(active);
    if (!existing.bytes.equals(bytes)) fail();
  }
}

async function openBootstrap(active, role) {
  const createStore =
    active.dependencies
      .createAwsBootstrapStateFileStore ??
    createAwsBootstrapStateFileStore;
  if (typeof createStore !== "function") fail();
  const store = await createStore({
    initialState: stateConfig(active),
    statePath: active.bootstrapStatePath,
  });
  if (
    store === null ||
    typeof store !== "object" ||
    typeof store.readState !== "function" ||
    typeof store.writeState !== "function"
  ) {
    fail();
  }
  async function readProjected() {
    return projectState(await store.readState(), role);
  }
  async function writeAndRead({
    expectedRevision,
    nextState,
  }) {
    const written = await store.writeState({
      expectedRevision,
      state: nextState,
    });
    if (written !== true) fail();
    return readProjected();
  }
  return Object.freeze({
    async approveClaim(input) {
      if (
        input?.paymentMoved !== false ||
        !SHA64.test(input.claimFingerprint)
      ) {
        fail();
      }
      const current = await store.readState();
      const next = approveBootstrapClaimState({
        claimFingerprint:
          input.claimFingerprint,
        expectedRevision:
          input.expectedRevision,
        nowMs: nowMs(active),
        state: current,
      });
      return writeAndRead({
        expectedRevision:
          input.expectedRevision,
        nextState: next,
      });
    },
    readState: readProjected,
    async sealClaim(input) {
      if (
        input?.paymentMoved !== false ||
        !SHA64.test(input.claimFingerprint)
      ) {
        fail();
      }
      const current = await store.readState();
      const next = sealBootstrapClaim({
        claimFingerprint:
          input.claimFingerprint,
        expectedRevision:
          input.expectedRevision,
        nowMs: nowMs(active),
        responseBytes: canonicalBytes(
          input.response,
        ),
        state: current,
      });
      return writeAndRead({
        expectedRevision:
          input.expectedRevision,
        nextState: next,
      });
    },
  });
}

function readExpectedRole(input) {
  const data = exact(
    input,
    FINGERPRINT_INPUT_KEYS,
  );
  if (
    data.releaseId === undefined ||
    data.sessionId === undefined ||
    data.state === null ||
    typeof data.state !== "object" ||
    Array.isArray(data.state)
  ) {
    fail();
  }
  if (data.state.status === "RUN_STARTED") {
    return "payer";
  }
  if (data.state.status === "PAYER_APPROVED") {
    return "requestor";
  }
  return null;
}

function findLiveClaim(state, role, active) {
  const checked = validateBootstrapState(state);
  if (
    checked.releaseId !== active.releaseId ||
    checked.repositorySha !==
      active.repositorySha ||
    checked.sessionId !== active.sessionId ||
    checked.paymentMoved !== false
  ) {
    fail();
  }
  const matches = Object.values(checked.claims)
    .filter(
      (entry) =>
        entry.role === role &&
        ["PENDING", "APPROVED"].includes(
          entry.status,
        ) &&
        Number(entry.expiresAtMs) > nowMs(active),
    );
  if (matches.length !== 1) fail();
  return matches[0].claimFingerprint;
}

export function createAwsOperatorBootstrapAdapter(
  value,
  dependencies = {},
) {
  try {
    if (
      dependencies === null ||
      typeof dependencies !== "object" ||
      Array.isArray(dependencies)
    ) {
      fail();
    }
    const active = Object.freeze({
      ...config(value),
      dependencies,
    });
    const approveAndSeal =
      dependencies
        .approveAndSealAwsBootstrapClaim ??
      approveAndSealAwsBootstrapClaim;
    const buildSealed =
      dependencies
        .buildAwsBootstrapSealedResponse ??
      buildAwsBootstrapSealedResponse;
    if (
      typeof approveAndSeal !== "function" ||
      typeof buildSealed !== "function"
    ) {
      fail();
    }
    return Object.freeze({
      async approveAndSeal(input) {
        try {
          const target = expected(input, active);
          return await approveAndSeal(target, {
            assertTunnelGrant:
              async (assertInput) =>
                this.assertTunnelGrant(assertInput),
            buildSealedResponse: async ({
              claim,
              claimFingerprint,
              expiresAtMs,
              role,
            }) => {
              const manifestPath =
                role === "payer"
                  ? active.payerLaunchManifestPath
                  : active.payeeLaunchManifestPath;
              const manifestBytes =
                await readManifest(manifestPath);
              const responseNowMs =
                await readApprovalNowMs({
                  active,
                  claimFingerprint,
                  expiresAtMs,
                  role,
                });
              return buildSealed({
                claim,
                claimFingerprint,
                config: responseConfig(
                  active,
                  responseNowMs,
                ),
                expiresAtMs,
                payeeLaunchManifestBytes:
                  role === "payee"
                    ? manifestBytes
                    : Buffer.from("unused"),
                payerLaunchManifestBytes:
                  role === "payer"
                    ? manifestBytes
                    : Buffer.from("unused"),
                role,
              });
            },
            openBootstrap: async () =>
              openBootstrap(active, target.role),
            persistTunnelGrant: async (grant) =>
              persistGrant(active, grant),
            ...(typeof dependencies.publishApprovedPayer === "function"
              ? {
                  publishApprovedPayer: async ({
                    claim,
                    claimFingerprint,
                    expiresAtMs,
                  }) =>
                    dependencies.publishApprovedPayer({
                      claim,
                      claimFingerprint,
                      expiresAtMs,
                      nowMs: nowMs(active),
                      releaseId: active.releaseId,
                      repositorySha: active.repositorySha,
                      sessionId: active.sessionId,
                    }),
                }
              : {}),
          });
        } catch (error) {
          sanitize(error);
        }
      },
      async assertTunnelGrant(input) {
        try {
          const target = expected(input, active);
          if (target.role !== "payer") fail();
          const { grant } = await readGrant(active);
          assertGrantScope(grant, target, active);
          return Object.freeze({
            paymentMoved: false,
            status: "APPROVED",
          });
        } catch (error) {
          sanitize(error);
        }
      },
      async readExpectedClaimFingerprint(input) {
        try {
          const role = readExpectedRole(input);
          if (role === null) return null;
          if (
            input.releaseId !== active.releaseId ||
            input.sessionId !== active.sessionId
          ) {
            fail();
          }
          const createStore =
            active.dependencies
              .createAwsBootstrapStateFileStore ??
            createAwsBootstrapStateFileStore;
          const store = await createStore({
            initialState: stateConfig(active),
            statePath: active.bootstrapStatePath,
          });
          return findLiveClaim(
            await store.readState(),
            role,
            active,
          );
        } catch (error) {
          sanitize(error);
        }
      },
    });
  } catch (error) {
    sanitize(error);
  }
}
