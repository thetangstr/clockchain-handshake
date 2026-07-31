import {
  DeleteMessageCommand,
  ReceiveMessageCommand,
} from "@aws-sdk/client-sqs";
import {
  createHash,
} from "node:crypto";
import {
  GetCommand,
  PutCommand,
  TransactWriteCommand,
} from "@aws-sdk/lib-dynamodb";

import {
  processAwsOperatorMessage,
} from "../../../scripts/run-aws-operator-worker.mjs";

const CONFIG_KEYS = Object.freeze([
  "actionQueueUrl",
  "actionTableName",
  "paymentMoved",
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
const TRANSITION_NAMES = Object.freeze([
  "abortSession",
  "approveBootstrapClaim",
  "createSession",
  "launchCoordinator",
  "launchFundingTask",
  "launchVerifierTask",
  "readExpectedClaimFingerprint",
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
      return Object.freeze({
        paymentMoved: false,
        status: "IDLE",
      });
    }
    const activeMessage =
      queueMessage(messages[0]);
    const transitions = transitionSet(
      await buildTransitions(input),
    );
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
        if (releaseId !== input.releaseId) {
          fail();
        }
        const result =
          await documentClient.send(
            new GetCommand({
              ConsistentRead: true,
              Key: {
                actionId: contextKey({
                  releaseId,
                  sessionId,
                }),
              },
              TableName:
                input.actionTableName,
            }),
          );
        const stored =
          result.Item?.controlContext;
        if (
          stored === null ||
          typeof stored !== "object" ||
          Array.isArray(stored) ||
          stored.state === null ||
          typeof stored.state !== "object"
        ) {
          fail();
        }
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
    return await processMessage(
      activeMessage,
      authorityDependencies,
    );
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
  while (signal?.aborted !== true) {
    await runAwsOperatorOnce(
      value,
      dependencies,
    );
  }
}
