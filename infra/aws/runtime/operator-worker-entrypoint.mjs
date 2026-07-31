#!/usr/bin/env node

import {
  createHash,
} from "node:crypto";
import {
  types,
} from "node:util";
import {
  DynamoDBDocumentClient,
} from "@aws-sdk/lib-dynamodb";

import {
  createAwsRuntimeClients,
} from "./aws-clients.mjs";
import {
  runAwsOperatorLoop,
} from "./operator-runtime.mjs";
import {
  parseRuntimeInput,
} from "./runtime-input.mjs";

const TOP_LEVEL_KEYS = Object.freeze([
  "operator",
  "paymentMoved",
  "schema",
]);
const OPERATOR_KEYS = Object.freeze([
  "actionQueueUrl",
  "actionTableName",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const RELEASE = /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SQS_QUEUE_PATH =
  /^\/[0-9]{12}\/(?:[A-Za-z0-9_-]{1,80}|[A-Za-z0-9_-]{1,75}\.fifo)$/;
const TABLE = /^[A-Za-z0-9_.-]{3,255}$/;

class AwsOperatorWorkerEntrypointError extends Error {
  constructor() {
    super(
      "AWS operator worker entrypoint failed safely.",
    );
    this.name =
      "AwsOperatorWorkerEntrypointError";
  }
}

function fail() {
  throw new AwsOperatorWorkerEntrypointError();
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
    keys.some(
      (key, index) => ownKeys[index] !== key,
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

function expectedReleaseId(sessionId) {
  return `release-${createHash("sha256").update(sessionId, "utf8").digest("hex").slice(0, 16)}`;
}

function validateQueueUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.href === value &&
      url.protocol === "https:" &&
      url.username === "" &&
      url.password === "" &&
      url.search === "" &&
      url.hash === "" &&
      SQS_QUEUE_PATH.test(url.pathname) &&
      /^sqs\.[a-z0-9-]+\.amazonaws\.com$/.test(
        url.hostname,
      )
    );
  } catch {
    return false;
  }
}

function validateOperator(value) {
  const operator = exact(value, OPERATOR_KEYS);
  if (
    !validateQueueUrl(operator.actionQueueUrl) ||
    !TABLE.test(operator.actionTableName) ||
    operator.paymentMoved !== false ||
    !RELEASE.test(operator.releaseId) ||
    !SHA40.test(operator.repositorySha) ||
    operator.schema !==
      "clockchain.aws-operator-runtime/v1" ||
    !SESSION.test(operator.sessionId) ||
    operator.releaseId !==
      expectedReleaseId(operator.sessionId)
  ) {
    fail();
  }
  return Object.freeze({
    actionQueueUrl: operator.actionQueueUrl,
    actionTableName: operator.actionTableName,
    paymentMoved: false,
    releaseId: operator.releaseId,
    repositorySha: operator.repositorySha,
    schema:
      "clockchain.aws-operator-runtime/v1",
    sessionId: operator.sessionId,
  });
}

function validateClients(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    value.dynamodb === null ||
    typeof value.dynamodb !== "object" ||
    typeof value.dynamodb.send !== "function" ||
    value.sqs === null ||
    typeof value.sqs !== "object" ||
    typeof value.sqs.send !== "function"
  ) {
    fail();
  }
  return value;
}

function validateDocumentClient(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.send !== "function"
  ) {
    fail();
  }
  return value;
}

export async function main({
  buildTransitions,
  createClients = createAwsRuntimeClients,
  createDocumentClient = (client) =>
    DynamoDBDocumentClient.from(client),
  env = process.env,
  run = runAwsOperatorLoop,
  signal,
} = {}) {
  try {
    const input = exact(
      parseRuntimeInput(env),
      TOP_LEVEL_KEYS,
    );
    const operator = validateOperator(
      input.operator,
    );
    if (
      typeof createClients !== "function" ||
      typeof createDocumentClient !==
        "function" ||
      !(
        buildTransitions === undefined ||
        typeof buildTransitions ===
          "function"
      ) ||
      typeof run !== "function"
    ) {
      fail();
    }
    const clients = validateClients(
      await createClients(),
    );
    const documentClient =
      validateDocumentClient(
        createDocumentClient(clients.dynamodb),
      );
    const activeBuildTransitions =
      buildTransitions ??
      (async () => {
        fail();
      });
    return await run(operator, {
      buildTransitions:
        activeBuildTransitions,
      documentClient,
      signal,
      sqs: clients.sqs,
    });
  } catch (error) {
    if (
      error instanceof
      AwsOperatorWorkerEntrypointError
    ) {
      throw error;
    }
    fail();
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url ===
    new URL(`file://${process.argv[1]}`).href
) {
  main().catch(() => {
    process.stderr.write(
      "AWS_OPERATOR_WORKER_ENTRYPOINT_FAILED\n",
    );
    process.exitCode = 1;
  });
}
