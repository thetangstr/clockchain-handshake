import {
  createHash,
} from "node:crypto";
import { types } from "node:util";

const IDENTITY_KEYS = Object.freeze([
  "actionId",
  "expectedRevision",
  "kind",
  "releaseId",
  "repositorySha",
  "sessionId",
]);
const RECORD_KEYS = Object.freeze([
  "actionAtMs",
  "attemptId",
  "clientToken",
  "identity",
  "intentDigest",
  "paymentMoved",
  "runtimeInputDigest",
  "schema",
  "status",
  "taskArn",
]);
const TOKEN_KEYS = Object.freeze([
  "childTask",
  "action",
  "fingerprint",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const SHA64 = /^[0-9a-f]{64}$/;
const RELEASE =
  /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V4_SHAPED =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TASK_ARN =
  /^arn:aws(?:-[a-z]+)?:ecs:[a-z0-9-]+:[0-9]{12}:task\/(?:[A-Za-z0-9_-]{1,255}\/)?[0-9a-f]{32}$/;
const SAFE_NAME = /^[a-z][a-z0-9-]{0,15}$/;
const KINDS = Object.freeze([
  "funding",
  "verifier",
]);

export class AwsOperatorLaunchRecordError extends Error {
  constructor() {
    super(
      "AWS operator launch record failed safely.",
    );
    this.name =
      "AwsOperatorLaunchRecordError";
    this.code =
      "AWS_OPERATOR_LAUNCH_RECORD_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorLaunchRecordError();
}

function sanitize(error) {
  if (
    error instanceof
    AwsOperatorLaunchRecordError
  ) {
    throw error;
  }
  fail();
}

function plain(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Object.getPrototypeOf(value) ===
      Object.prototype
  );
}

function exact(value, keys) {
  if (!plain(value)) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    keys.some((key, index) =>
      ownKeys[index] !== key)
  ) {
    fail();
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor =
      Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key] = descriptor.value;
  }
  return Object.freeze(snapshot);
}

function digest(value) {
  try {
    return createHash("sha256")
      .update(JSON.stringify(value), "utf8")
      .digest("hex");
  } catch {
    fail();
  }
}

function uuidFromDigest(value) {
  const hex = createHash("sha256")
    .update(value, "utf8")
    .digest("hex");
  const variant = (
    8 + (Number.parseInt(hex[16], 16) % 4)
  ).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function identity(value) {
  const input = exact(value, IDENTITY_KEYS);
  if (
    !UUID_V4_SHAPED.test(input.actionId) ||
    !Number.isSafeInteger(
      input.expectedRevision,
    ) ||
    input.expectedRevision < 0 ||
    !KINDS.includes(input.kind) ||
    !RELEASE.test(input.releaseId) ||
    !SHA40.test(input.repositorySha) ||
    !SESSION.test(input.sessionId)
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function snapshotRuntime(entry) {
  if (
    entry === null ||
    typeof entry !== "object"
  ) {
    return entry;
  }
  if (types.isProxy(entry)) {
    fail();
  }
  if (Array.isArray(entry)) {
    if (
      Object.getPrototypeOf(entry) !==
        Array.prototype
    ) {
      fail();
    }
    const lengthDescriptor =
      Object.getOwnPropertyDescriptor(
        entry,
        "length",
      );
    if (
      !lengthDescriptor ||
      !Object.hasOwn(lengthDescriptor, "value") ||
      !Number.isSafeInteger(
        lengthDescriptor.value,
      ) ||
      lengthDescriptor.value < 0
    ) {
      fail();
    }
    const ownKeys = Reflect.ownKeys(entry);
    const expectedKeys = [
      ...Array.from(
        { length: lengthDescriptor.value },
        (_, index) => String(index),
      ),
      "length",
    ];
    if (
      ownKeys.length !== expectedKeys.length ||
      expectedKeys.some((key, index) =>
        ownKeys[index] !== key)
    ) {
      fail();
    }
    const snapshot = [];
    for (
      let index = 0;
      index < lengthDescriptor.value;
      index += 1
    ) {
      const descriptor =
        Object.getOwnPropertyDescriptor(
          entry,
          String(index),
        );
      if (
        descriptor?.enumerable !== true ||
        !Object.hasOwn(
          descriptor,
          "value",
        )
      ) {
        fail();
      }
      snapshot.push(
        snapshotRuntime(descriptor.value),
      );
    }
    return Object.freeze(snapshot);
  }
  if (!plain(entry)) {
    fail();
  }
  const snapshot = {};
  for (const key of Reflect.ownKeys(entry)) {
    if (typeof key !== "string") fail();
    if (
      /^(?:capability|invitation|privateKey|secret|token|treasury)$/i.test(
        key,
      )
    ) {
      fail();
    }
    const descriptor =
      Object.getOwnPropertyDescriptor(entry, key);
    if (
      descriptor?.enumerable !== true ||
      !Object.hasOwn(descriptor, "value")
    ) {
      fail();
    }
    snapshot[key] = snapshotRuntime(
      descriptor.value,
    );
  }
  return Object.freeze(snapshot);
}

function runtimeInput(value) {
  const snapshot = snapshotRuntime(value);
  if (
    !plain(snapshot) ||
    snapshot.paymentMoved !== false ||
    snapshot.schema !==
      "clockchain.aws-runtime-input/v1"
  ) {
    fail();
  }
  return snapshot;
}

function recordKey(input) {
  return [
    "operator-launch",
    input.releaseId,
    input.actionId,
    input.kind,
  ].join("#");
}

function actionName(kind) {
  return kind === "verifier"
    ? "verify"
    : "fund";
}

export function deriveOperatorLaunchAttemptId(value) {
  try {
    return uuidFromDigest(
      digest(identity(value)),
    );
  } catch (error) {
    sanitize(error);
  }
}

function actionAtMs(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail();
  }
  return value;
}

function buildRecord(input, runtime, atMs) {
  const runtimeInputDigest = digest(runtime);
  const identityDigest = digest(input);
  const intentDigest = digest({
    identityDigest,
    runtimeInputDigest,
  });
  const attemptId =
    deriveOperatorLaunchAttemptId(input);
  return Object.freeze({
    actionAtMs: actionAtMs(atMs),
    attemptId,
    clientToken: Object.freeze({
      childTask: input.kind,
      action: actionName(input.kind),
      fingerprint:
        intentDigest.slice(0, 16),
    }),
    identity: input,
    intentDigest,
    paymentMoved: false,
    runtimeInputDigest,
    schema:
      "clockchain.aws-operator-launch-record/v1",
    status: "INTENT",
    taskArn: null,
  });
}

function validateToken(value) {
  const input = exact(value, TOKEN_KEYS);
  if (
    !SAFE_NAME.test(input.action) ||
    !SAFE_NAME.test(input.childTask) ||
    !/^[0-9a-f]{16}$/.test(
      input.fingerprint,
    )
  ) {
    fail();
  }
  return Object.freeze({ ...input });
}

function validateRecord(
  value,
  expected,
  { matchActionAtMs = true } = {},
) {
  const input = exact(value, RECORD_KEYS);
  const checkedIdentity = identity(
    input.identity,
  );
  const clientToken = validateToken(
    input.clientToken,
  );
  if (
    !Number.isSafeInteger(input.actionAtMs) ||
    input.actionAtMs < 0 ||
    (
      matchActionAtMs &&
      input.actionAtMs !== expected.actionAtMs
    ) ||
    JSON.stringify(checkedIdentity) !==
      JSON.stringify(expected.identity) ||
    input.attemptId !==
      expected.attemptId ||
    input.intentDigest !==
      expected.intentDigest ||
    input.paymentMoved !== false ||
    input.runtimeInputDigest !==
      expected.runtimeInputDigest ||
    input.schema !==
      expected.schema ||
    !["INTENT", "RUNNING"].includes(
      input.status,
    ) ||
    JSON.stringify(clientToken) !==
      JSON.stringify(expected.clientToken) ||
    !SHA64.test(input.intentDigest) ||
    !SHA64.test(
      input.runtimeInputDigest,
    ) ||
    !UUID_V4_SHAPED.test(
      input.attemptId,
    ) ||
    !(
      input.taskArn === null ||
      TASK_ARN.test(input.taskArn)
    )
  ) {
    fail();
  }
  return Object.freeze({
    ...input,
    clientToken,
    identity: checkedIdentity,
  });
}

function validateExistingRecord(value, expectedIdentity) {
  const input = exact(value, RECORD_KEYS);
  const checkedIdentity = identity(
    input.identity,
  );
  const clientToken = validateToken(
    input.clientToken,
  );
  if (
    JSON.stringify(checkedIdentity) !==
      JSON.stringify(expectedIdentity) ||
    !Number.isSafeInteger(input.actionAtMs) ||
    input.actionAtMs < 0 ||
    !UUID_V4_SHAPED.test(
      input.attemptId,
    ) ||
    !SHA64.test(input.intentDigest) ||
    input.paymentMoved !== false ||
    !SHA64.test(
      input.runtimeInputDigest,
    ) ||
    input.schema !==
      "clockchain.aws-operator-launch-record/v1" ||
    !["INTENT", "RUNNING"].includes(
      input.status,
    ) ||
    !(
      input.taskArn === null ||
      TASK_ARN.test(input.taskArn)
    )
  ) {
    fail();
  }
  return Object.freeze({
    ...input,
    clientToken,
    identity: checkedIdentity,
  });
}

async function readExact(store, key, expected) {
  const existing =
    await store.readRecord(key);
  if (existing === null) return null;
  return validateRecord(
    existing,
    expected,
    { matchActionAtMs: false },
  );
}

async function writeAndRead(store, key, record, expected) {
  await store.writeRecord(key, record);
  return validateRecord(
    await store.readRecord(key),
    expected,
  );
}

export function createDurableOperatorLaunchRecord(
  dependencies = {},
) {
  try {
    if (
      !plain(dependencies) ||
      typeof dependencies.readRecord !==
        "function" ||
      typeof dependencies.writeRecord !==
        "function"
    ) {
      fail();
    }
    return Object.freeze({
      async prepare(value = {}) {
        try {
          const input = exact(value, [
            "actionAtMs",
            "identity",
            "runtimeInput",
          ]);
          const checkedIdentity = identity(
            input.identity,
          );
          const checkedRuntime =
            runtimeInput(input.runtimeInput);
          const expected = buildRecord(
            checkedIdentity,
            checkedRuntime,
            input.actionAtMs,
          );
          const key = recordKey(
            checkedIdentity,
          );
          const existing = await readExact(
            dependencies,
            key,
            expected,
          );
          if (existing !== null) {
            return existing;
          }
          await dependencies.writeRecord(
            key,
            expected,
          );
          return validateRecord(
            await dependencies.readRecord(key),
            expected,
          );
        } catch (error) {
          sanitize(error);
        }
      },
      async read(value = {}) {
        try {
          const input = exact(value, ["identity"]);
          const checkedIdentity = identity(
            input.identity,
          );
          const existing =
            await dependencies.readRecord(
              recordKey(checkedIdentity),
            );
          return existing === null
            ? null
            : validateExistingRecord(
                existing,
                checkedIdentity,
              );
        } catch (error) {
          sanitize(error);
        }
      },
      async adoptTask(value = {}) {
        try {
          const input = exact(value, [
            "identity",
            "runtimeInput",
            "taskArn",
          ]);
          const checkedIdentity = identity(
            input.identity,
          );
          const checkedRuntime =
            runtimeInput(input.runtimeInput);
          const taskArn =
            typeof input.taskArn === "string" &&
            TASK_ARN.test(input.taskArn)
              ? input.taskArn
              : null;
          if (taskArn === null) fail();
          const key = recordKey(
            checkedIdentity,
          );
          const current =
            await dependencies.readRecord(key);
          if (current === null) fail();
          const expectedForInput =
            buildRecord(
              checkedIdentity,
              checkedRuntime,
              0,
            );
          const expected = validateRecord(
            current,
            expectedForInput,
            { matchActionAtMs: false },
          );
          if (
            JSON.stringify(expected.identity) !==
              JSON.stringify(
                checkedIdentity,
              ) ||
            !(
              expected.taskArn === null ||
              expected.taskArn === taskArn
            )
          ) {
            fail();
          }
          const next = Object.freeze({
            ...expected,
            status: "RUNNING",
            taskArn,
          });
          await dependencies.writeRecord(
            key,
            next,
          );
          return validateRecord(
            await dependencies.readRecord(key),
            next,
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
