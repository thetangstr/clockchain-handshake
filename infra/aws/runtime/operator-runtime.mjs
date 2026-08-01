import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
} from "@aws-sdk/client-sqs";
import {
  PutObjectCommand,
} from "@aws-sdk/client-s3";
import {
  createHash,
} from "node:crypto";
import { types } from "node:util";
import {
  GetCommand,
  PutCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  processAwsOperatorMessage,
} from "../../../scripts/run-aws-operator-worker.mjs";
import {
  createInitialControlState,
  validateControlState,
} from "../../../src/bilateral/aws/control-actions.mjs";

const CONFIG_KEYS = Object.freeze([
  "actionQueueUrl",
  "actionTableName",
  "paymentMoved",
  "publicMonitorBucketName",
  "publicMonitorControlKey",
  "releaseId",
  "repositorySha",
  "schema",
  "sessionId",
]);
const SHA40 = /^[0-9a-f]{40}$/;
const RELEASE =
  /^release-[0-9a-f]{16}$/;
const SESSION =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const TABLE =
  /^[A-Za-z0-9_.-]{3,255}$/;
const BUCKET =
  /^(?!\d+\.\d+\.\d+\.\d+$)(?=.{3,63}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/;
const SHA64 = /^[0-9a-f]{64}$/;
const TRANSITION_NAMES = Object.freeze([
  "abortSession",
  "approveBootstrapClaim",
  "createSession",
  "launchCoordinator",
  "launchFundingTask",
  "launchVerifierTask",
  "readExpectedClaimFingerprint",
]);
const CONTROL_STATE_KEYS = Object.freeze([
  "actionHistory",
  "paymentMoved",
  "releaseId",
  "repositorySha",
  "revision",
  "schema",
  "sessionId",
  "status",
]);

export class AwsOperatorRuntimeError extends Error {
  constructor() {
    super("AWS operator runtime failed safely.");
    this.name = "AwsOperatorRuntimeError";
    this.code = "AWS_OPERATOR_RUNTIME_INVALID";
    this.category = "verification";
  }
}

function fail() {
  throw new AwsOperatorRuntimeError();
}

function exact(value, keys) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
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
  return value;
}

function runtimeConfig(value) {
  const input = exact(value, CONFIG_KEYS);
  let queue;
  try {
    queue = new URL(input.actionQueueUrl);
  } catch {
    fail();
  }
  if (
    queue.protocol !== "https:" ||
    queue.username !== "" ||
    queue.password !== "" ||
    queue.search !== "" ||
    queue.hash !== "" ||
    !/^sqs\.[a-z0-9-]+\.amazonaws\.com$/.test(
      queue.hostname,
    ) ||
    !TABLE.test(input.actionTableName) ||
    !BUCKET.test(input.publicMonitorBucketName) ||
    input.publicMonitorControlKey !==
      "control.json" ||
    input.paymentMoved !== false ||
    !SHA40.test(input.repositorySha) ||
    !RELEASE.test(input.releaseId) ||
    !SESSION.test(input.sessionId) ||
    input.releaseId !==
      `release-${createHash("sha256").update(input.sessionId, "utf8").digest("hex").slice(0, 16)}` ||
    input.schema !==
      "clockchain.aws-operator-runtime/v1"
  ) {
    fail();
  }
  return input;
}

function controlContextKey(input) {
  return contextKey({
    releaseId: input.releaseId,
    sessionId: null,
  });
}

function initialControlContext() {
  return Object.freeze({
    expectedClaimFingerprint: null,
    state: createInitialControlState(),
  });
}

function canonicalStoredActionHistory(value) {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      types.isProxy(value) ||
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !==
        Array.prototype
    ) {
      fail();
    }
    const lengthDescriptor =
      Object.getOwnPropertyDescriptor(
        value,
        "length",
      );
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      lengthDescriptor.enumerable !== false
    ) {
      fail();
    }
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length + 1 ||
      keys[length] !== "length" ||
      keys.slice(0, length).some(
        (key, index) => key !== String(index),
      )
    ) {
      fail();
    }
    const history = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor =
        Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true ||
        types.isProxy(descriptor.value)
      ) {
        fail();
      }
      history.push(descriptor.value);
    }
    return history;
  } catch {
    fail();
  }
}

function canonicalStoredControlState(value) {
  let keys;
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      types.isProxy(value) ||
      Array.isArray(value) ||
      Object.getPrototypeOf(value) !==
        Object.prototype
    ) {
      fail();
    }
    keys = Reflect.ownKeys(value);
    if (
      keys.length !== CONTROL_STATE_KEYS.length ||
      keys.some((key) => typeof key !== "string") ||
      CONTROL_STATE_KEYS.some(
        (key) => !keys.includes(key),
      )
    ) {
      fail();
    }
    const state = {};
    for (const key of CONTROL_STATE_KEYS) {
      const descriptor =
        Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        fail();
      }
      state[key] =
        key === "actionHistory"
          ? canonicalStoredActionHistory(
              descriptor.value,
            )
          : descriptor.value;
    }
    return state;
  } catch {
    fail();
  }
}

function validateStoredControlContext({
  input,
  stored,
}) {
  if (
    stored === null ||
    typeof stored !== "object" ||
    Array.isArray(stored) ||
    stored.state === null ||
    typeof stored.state !== "object" ||
    Array.isArray(stored.state) ||
    !(
      stored.expectedClaimFingerprint ===
        null ||
      typeof stored.expectedClaimFingerprint ===
        "string"
    ) ||
    (
      typeof stored.expectedClaimFingerprint ===
        "string" &&
      !SHA64.test(
        stored.expectedClaimFingerprint,
      )
    )
  ) {
    fail();
  }
  let state;
  try {
    state = validateControlState(
      canonicalStoredControlState(
        stored.state,
      ),
    );
  } catch {
    fail();
  }
  if (state.status === "EMPTY") {
    if (
      state.revision !== 0 ||
      state.releaseId !== null ||
      state.repositorySha !== null ||
      state.sessionId !== null
    ) {
      fail();
    }
  } else if (
    state.releaseId !== input.releaseId ||
    state.repositorySha !==
      input.repositorySha ||
    state.sessionId !== input.sessionId
  ) {
    fail();
  }
  return Object.freeze({
    expectedClaimFingerprint:
      stored.expectedClaimFingerprint,
    state,
  });
}

async function readRawControlContext({
  documentClient,
  input,
}) {
  const result = await documentClient.send(
    new GetCommand({
      ConsistentRead: true,
      Key: {
        actionId: controlContextKey(input),
      },
      TableName: input.actionTableName,
    }),
  );
  if (result.Item === undefined) {
    return null;
  }
  return validateStoredControlContext({
    input,
    stored: result.Item.controlContext,
  });
}

async function seedInitialControlContext({
  documentClient,
  input,
}) {
  const controlContext =
    initialControlContext();
  await documentClient.send(
    new PutCommand({
      ConditionExpression:
        "attribute_not_exists(actionId)",
      Item: {
        actionId:
          controlContextKey(input),
        controlContext,
        recordType: "CONTROL_CONTEXT",
      },
      TableName: input.actionTableName,
    }),
  );
}

function isConditionalCheckFailed(error) {
  return (
    error?.name ===
      "ConditionalCheckFailedException" ||
    error?.code ===
      "ConditionalCheckFailedException"
  );
}

function allowedActionsFor({
  expectedClaimFingerprint,
  status,
}) {
  if (status === "EMPTY") {
    return Object.freeze(["START_RUN"]);
  }
  if (status === "RUN_STARTED") {
    return Object.freeze([
      ...(SHA64.test(
        expectedClaimFingerprint ?? "",
      )
        ? ["APPROVE_PAYER"]
        : []),
      "ABORT",
    ]);
  }
  if (status === "PAYER_APPROVED") {
    return Object.freeze([
      ...(SHA64.test(
        expectedClaimFingerprint ?? "",
      )
        ? ["APPROVE_REQUESTOR"]
        : []),
      "ABORT",
    ]);
  }
  if (status === "REQUESTOR_APPROVED") {
    return Object.freeze(["FUND", "ABORT"]);
  }
  if (status === "FUND_REQUESTED") {
    return Object.freeze(["VERIFY", "ABORT"]);
  }
  return Object.freeze([]);
}

function claimViews({
  actionHistory,
  expectedClaimFingerprint,
  status,
}) {
  const exactClaim = SHA64.test(
    expectedClaimFingerprint ?? "",
  )
    ? expectedClaimFingerprint
    : null;
  const payerApproved = actionHistory.some(
    (entry) => entry?.type === "APPROVE_PAYER",
  );
  const requestorApproved = actionHistory.some(
    (entry) =>
      entry?.type === "APPROVE_REQUESTOR",
  );
  const payerStatus = payerApproved
    ? "APPROVED"
    : status === "RUN_STARTED" &&
        exactClaim !== null
      ? "PENDING"
      : "WAITING";
  const requestorStatus = requestorApproved
    ? "APPROVED"
    : status === "PAYER_APPROVED" &&
        exactClaim !== null
      ? "PENDING"
      : "WAITING";
  return Object.freeze({
    payer: Object.freeze({
      fingerprint:
        status === "RUN_STARTED"
          ? exactClaim
          : null,
      status: payerStatus,
    }),
    requestor: Object.freeze({
      fingerprint:
        status === "PAYER_APPROVED"
          ? exactClaim
          : null,
      status: requestorStatus,
    }),
  });
}

function currentStepFor(status) {
  if (status === "EMPTY") {
    return "Waiting for the operator to start the hosted run.";
  }
  if (status === "RUN_STARTED") {
    return "Waiting for the Payer claim fingerprint.";
  }
  if (status === "PAYER_APPROVED") {
    return "Waiting for the Requestor claim fingerprint.";
  }
  if (status === "REQUESTOR_APPROVED") {
    return "Waiting for funding.";
  }
  if (status === "FUND_REQUESTED") {
    return "Waiting for verification.";
  }
  if (status === "VERIFY_REQUESTED") {
    return "Verification completed.";
  }
  if (status === "ABORTED") {
    return "Run aborted.";
  }
  fail();
}

function runStatusFor(status) {
  if (status === "VERIFY_REQUESTED") {
    return "VERIFIED";
  }
  if (status === "ABORTED") return "FAILED";
  if (status === "EMPTY") return "WAITING";
  return "RUNNING";
}

function runIdFor(releaseId) {
  return `run-${releaseId.slice("release-".length)}`;
}

function controlSnapshot({
  context,
  input,
  nowMs = Date.now(),
}) {
  const state = context.state;
  if (
    state === null ||
    typeof state !== "object" ||
    state.paymentMoved !== false ||
    !Number.isSafeInteger(state.revision) ||
    typeof state.status !== "string"
  ) {
    fail();
  }
  return Object.freeze({
    control: Object.freeze({
      allowedActions: allowedActionsFor({
        expectedClaimFingerprint:
          context.expectedClaimFingerprint,
        status: state.status,
      }),
      claims: claimViews({
        actionHistory: state.actionHistory,
        expectedClaimFingerprint:
          context.expectedClaimFingerprint,
        status: state.status,
      }),
      releaseId: input.releaseId,
      repositorySha: input.repositorySha,
      revision: state.revision,
      sessionId: input.sessionId,
    }),
    currentStep: currentStepFor(
      state.status,
    ),
    paymentMoved: false,
    publishedAtMs: nowMs,
    runId: runIdFor(input.releaseId),
    runStatus: runStatusFor(state.status),
    staleAfterMs: 120_000,
  });
}

async function publishControlSnapshot({
  context,
  input,
  s3,
}) {
  await s3.send(
    new PutObjectCommand({
      Body: Buffer.from(
        `${JSON.stringify(
          controlSnapshot({
            context,
            input,
          }),
        )}\n`,
        "utf8",
      ),
      Bucket:
        input.publicMonitorBucketName,
      CacheControl: "no-store",
      ContentType:
        "application/json; charset=utf-8",
      Key: input.publicMonitorControlKey,
    }),
  );
}

async function readStoredControlContext({
  documentClient,
  input,
  releaseId,
  sessionId,
  transitions,
}) {
  if (releaseId !== input.releaseId) {
    fail();
  }
  if (sessionId !== null) {
    const result = await documentClient.send(
      new GetCommand({
        ConsistentRead: true,
        Key: {
          actionId: contextKey({
            releaseId,
            sessionId,
          }),
        },
        TableName: input.actionTableName,
      }),
    );
    if (result.Item === undefined) {
      fail();
    }
    const stored =
      validateStoredControlContext({
        input,
        stored: result.Item.controlContext,
      });
    const expectedClaimFingerprint =
      await transitions
        .readExpectedClaimFingerprint({
          releaseId,
          sessionId,
          state: stored.state,
        });
    return {
      expectedClaimFingerprint,
      state: stored.state,
    };
  }
  const stored = await readRawControlContext({
    documentClient,
    input,
  });
  if (stored === null) {
    fail();
  }
  if (stored.state.status === "EMPTY") {
    return {
      expectedClaimFingerprint: null,
      state: stored.state,
    };
  }
  const effectiveSessionId =
    stored.state.sessionId;
  const expectedClaimFingerprint =
    await transitions
      .readExpectedClaimFingerprint({
        releaseId,
        sessionId: effectiveSessionId,
        state: stored.state,
      });
  return {
    expectedClaimFingerprint,
    state: stored.state,
  };
}

async function resolveReleaseControlContext({
  documentClient,
  input,
  transitions,
}) {
  return await readStoredControlContext({
    documentClient,
    input,
    releaseId: input.releaseId,
    sessionId: null,
    transitions,
  });
}

async function initializeReleaseControlContext({
  documentClient,
  input,
  transitions,
}) {
  const existing =
    await readRawControlContext({
      documentClient,
      input,
    });
  if (existing !== null) {
    if (existing.state.status === "EMPTY") {
      return {
        expectedClaimFingerprint: null,
        state: existing.state,
      };
    }
    const expectedClaimFingerprint =
      await transitions
        .readExpectedClaimFingerprint({
          releaseId: input.releaseId,
          sessionId: existing.state.sessionId,
          state: existing.state,
        });
    return {
      expectedClaimFingerprint,
      state: existing.state,
    };
  }
  try {
    await seedInitialControlContext({
      documentClient,
      input,
    });
  } catch (error) {
    if (!isConditionalCheckFailed(error)) {
      throw error;
    }
    // Another operator may have won the startup race; the reread below decides.
  }
  return await resolveReleaseControlContext({
    documentClient,
    input,
    transitions,
  });
}

function transitionSet(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    TRANSITION_NAMES.some(
      (name) =>
        typeof value[name] !== "function",
    )
  ) {
    fail();
  }
  return value;
}

function queueMessage(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.Body !== "string" ||
    value.Body.length === 0 ||
    Buffer.byteLength(
      value.Body,
      "utf8",
    ) > 16_384 ||
    typeof value.MessageId !== "string" ||
    value.MessageId.length === 0 ||
    typeof value.ReceiptHandle !==
      "string" ||
    value.ReceiptHandle.length === 0
  ) {
    fail();
  }
  return {
    body: value.Body,
    messageId: value.MessageId,
    receiptHandle: value.ReceiptHandle,
  };
}

function contextKey({
  releaseId,
  sessionId,
}) {
  return sessionId === null
    ? `RELEASE#${releaseId}`
    : `SESSION#${releaseId}#${sessionId}`;
}

export async function runAwsOperatorOnce(
  value,
  dependencies = {},
) {
  try {
    const input = runtimeConfig(value);
    const sqs = dependencies.sqs;
    const s3 = dependencies.s3;
    const documentClient =
      dependencies.documentClient;
    const buildTransitions =
      dependencies.buildTransitions;
    const processMessage =
      dependencies.processMessage ??
      processAwsOperatorMessage;
    if (
      sqs === null ||
      typeof sqs !== "object" ||
      typeof sqs.send !== "function" ||
      s3 === null ||
      typeof s3 !== "object" ||
      typeof s3.send !== "function" ||
      documentClient === null ||
      typeof documentClient !== "object" ||
      typeof documentClient.send !==
        "function" ||
      typeof buildTransitions !==
        "function" ||
      typeof processMessage !== "function"
    ) {
      fail();
    }
    const transitions = transitionSet(
      await buildTransitions(input),
    );
    const startupContext =
      dependencies.initializeControlContext ===
      false
        ? null
        : await initializeReleaseControlContext({
            documentClient,
            input,
            transitions,
          });
    if (startupContext !== null) {
      await publishControlSnapshot({
        context: startupContext,
        input,
        s3,
      });
    }
    const response = await sqs.send(
      new ReceiveMessageCommand({
        AttributeNames: [],
        MaxNumberOfMessages: 1,
        MessageAttributeNames: [],
        QueueUrl: input.actionQueueUrl,
        VisibilityTimeout: 600,
        WaitTimeSeconds: 20,
      }),
    );
    const messages =
      response.Messages ?? [];
    if (
      !Array.isArray(messages) ||
      messages.length > 1
    ) {
      fail();
    }
    if (messages.length === 0) {
      if (startupContext !== null) {
        return Object.freeze({
          paymentMoved: false,
          status: "IDLE",
        });
      } else {
        const context =
          await resolveReleaseControlContext({
            documentClient,
            input,
            transitions,
          });
        await publishControlSnapshot({
          context,
          input,
          s3,
        });
      }
      return Object.freeze({
        paymentMoved: false,
        status: "IDLE",
      });
    }
    const activeMessage =
      queueMessage(messages[0]);
    const readControlContext = async ({
      releaseId,
      sessionId,
    }) =>
      await readStoredControlContext({
        documentClient,
        input,
        releaseId,
        sessionId,
        transitions,
      });
    const authorityDependencies = {
      ...Object.fromEntries(
        TRANSITION_NAMES
          .filter(
            (name) =>
              name !==
              "readExpectedClaimFingerprint",
          )
          .map((name) => [
            name,
            transitions[name],
          ]),
      ),
      async commitControlState({
        action,
        nextState,
        previousRevision,
      }) {
        const releaseKey =
          contextKey({
            releaseId:
              action.releaseId,
            sessionId: null,
          });
        const sessionKey =
          contextKey({
            releaseId:
              action.releaseId,
            sessionId:
              nextState.sessionId,
          });
        const controlContext = {
          expectedClaimFingerprint: null,
          state: nextState,
        };
        const condition =
          "#control.#state.#revision = :previous";
        const names = {
          "#control": "controlContext",
          "#revision": "revision",
          "#state": "state",
        };
        const values = {
          ":previous": previousRevision,
        };
        await documentClient.send(
          new TransactWriteCommand({
            TransactItems: [
              {
                Put: {
                  ConditionExpression:
                    condition,
                  ExpressionAttributeNames:
                    names,
                  ExpressionAttributeValues:
                    values,
                  Item: {
                    actionId:
                      releaseKey,
                    controlContext,
                    recordType:
                      "CONTROL_CONTEXT",
                  },
                  TableName:
                    input.actionTableName,
                },
              },
              {
                Put: {
                  ConditionExpression:
                    action.type ===
                    "START_RUN"
                      ? "attribute_not_exists(actionId)"
                      : condition,
                  ...(action.type ===
                  "START_RUN"
                    ? {}
                    : {
                        ExpressionAttributeNames:
                          names,
                        ExpressionAttributeValues:
                          values,
                      }),
                  Item: {
                    actionId:
                      sessionKey,
                    controlContext,
                    recordType:
                      "CONTROL_CONTEXT",
                  },
                  TableName:
                    input.actionTableName,
                },
              },
            ],
          }),
        );
      },
      async deleteMessage({
        receiptHandle,
      }) {
        await sqs.send(
          new DeleteMessageCommand({
            QueueUrl: input.actionQueueUrl,
            ReceiptHandle: receiptHandle,
          }),
        );
      },
      async readControlContext({
        releaseId,
        sessionId,
      }) {
        return await readControlContext({
          releaseId,
          sessionId,
        });
      },
      async recordRejection(record) {
        await documentClient.send(
          new PutCommand({
            ConditionExpression:
              "attribute_not_exists(actionId)",
            Item: {
              ...record,
              actionId:
                `REJECTION#${record.messageId}`,
              recordType: "REJECTION",
            },
            TableName:
              input.actionTableName,
          }),
        );
      },
    };
    const result = await processMessage(
      activeMessage,
      authorityDependencies,
    );
    const refreshedContext =
      await readControlContext({
        releaseId: input.releaseId,
        sessionId: null,
      });
    await publishControlSnapshot({
      context: refreshedContext,
      input,
      s3,
    });
    return result;
  } catch (error) {
    if (
      error instanceof
      AwsOperatorRuntimeError
    ) {
      throw error;
    }
    fail();
  }
}

export async function runAwsOperatorLoop(
  value,
  {
    signal,
    ...dependencies
  } = {},
) {
  runtimeConfig(value);
  let initializeControlContext = true;
  while (signal?.aborted !== true) {
    await runAwsOperatorOnce(
      value,
      {
        ...dependencies,
        initializeControlContext,
      },
    );
    initializeControlContext = false;
  }
}
