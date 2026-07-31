import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsOperatorOnce,
} from "../infra/aws/runtime/operator-runtime.mjs";

const CONFIG = Object.freeze({
  actionQueueUrl:
    "https://sqs.us-west-2.amazonaws.com/123456789012/actions.fifo",
  actionTableName: "clockchain-actions",
  paymentMoved: false,
  releaseId: "release-bd7662a5eeb41614",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  schema:
    "clockchain.aws-operator-runtime/v1",
  sessionId:
    "11111111-1111-4111-8111-111111111111",
});

test("long-polls one exact FIFO action and passes only bounded dependencies to the authority adapter", async () => {
  const calls = [];
  const result = await runAwsOperatorOnce(
    CONFIG,
    {
      buildTransitions: () => ({
        abortSession: async () => ({
          paymentMoved: false,
          status: "ABORTED",
        }),
        approveBootstrapClaim: async () => ({
          paymentMoved: false,
          status: "APPROVED",
        }),
        createSession: async () =>
          "11111111-1111-4111-8111-111111111111",
        launchCoordinator: async () => ({
          paymentMoved: false,
          status: "RUNNING",
        }),
        launchFundingTask: async () => ({
          paymentMoved: false,
          status: "FUNDED",
        }),
        launchVerifierTask: async () => ({
          paymentMoved: false,
          publicationDigest:
            "a".repeat(64),
          status:
            "VERIFICATION_PASSED",
        }),
        readExpectedClaimFingerprint:
          async () => null,
      }),
      documentClient: {
        async send(command) {
          calls.push([
            "dynamo",
            command.constructor.name,
            command.input,
          ]);
          if (
            command.constructor.name ===
            "GetCommand"
          ) {
            return {
              Item: {
                controlContext: {
                  expectedClaimFingerprint:
                    null,
                  state: {
                    actionHistory: [],
                    paymentMoved: false,
                    releaseId: null,
                    repositorySha: null,
                    revision: 0,
                    schema:
                      "clockchain.aws-control-state/v1",
                    sessionId: null,
                    status: "EMPTY",
                  },
                },
              },
            };
          }
          return {};
        },
      },
      processMessage: async (
        message,
        dependencies,
      ) => {
        assert.deepEqual(message, {
          body: '{"action":"test"}',
          messageId: "message-1",
          receiptHandle: "receipt-1",
        });
        assert.equal(
          typeof dependencies
            .launchVerifierTask,
          "function",
        );
        assert.deepEqual(
          await dependencies
            .readControlContext({
              releaseId:
                CONFIG.releaseId,
              sessionId: null,
            }),
          {
            expectedClaimFingerprint: null,
            state: {
              actionHistory: [],
              paymentMoved: false,
              releaseId: null,
              repositorySha: null,
              revision: 0,
              schema:
                "clockchain.aws-control-state/v1",
              sessionId: null,
              status: "EMPTY",
            },
          },
        );
        await dependencies.deleteMessage({
          receiptHandle:
            message.receiptHandle,
        });
        return {
          paymentMoved: false,
          status: "COMMITTED",
        };
      },
      sqs: {
        async send(command) {
          calls.push([
            "sqs",
            command.constructor.name,
            command.input,
          ]);
          if (
            command.constructor.name ===
            "ReceiveMessageCommand"
          ) {
            return {
              Messages: [
                {
                  Body: '{"action":"test"}',
                  MessageId: "message-1",
                  ReceiptHandle: "receipt-1",
                },
              ],
            };
          }
          return {};
        },
      },
    },
  );
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "COMMITTED",
  });
  const receive = calls.find(
    ([kind, name]) =>
      kind === "sqs" &&
      name === "ReceiveMessageCommand",
  )[2];
  assert.deepEqual(receive, {
    AttributeNames: [],
    MaxNumberOfMessages: 1,
    MessageAttributeNames: [],
    QueueUrl: CONFIG.actionQueueUrl,
    VisibilityTimeout: 600,
    WaitTimeSeconds: 20,
  });
  const deletion = calls.find(
    ([kind, name]) =>
      kind === "sqs" &&
      name === "DeleteMessageCommand",
  )[2];
  assert.deepEqual(deletion, {
    QueueUrl: CONFIG.actionQueueUrl,
    ReceiptHandle: "receipt-1",
  });
});

test("returns an idle result without inventing an action", async () => {
  const result = await runAwsOperatorOnce(
    CONFIG,
    {
      buildTransitions: () => ({}),
      documentClient: {
        async send() {
          return {};
        },
      },
      processMessage: async () => {
        throw new Error("must not run");
      },
      sqs: {
        async send() {
          return { Messages: [] };
        },
      },
    },
  );
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "IDLE",
  });
});

test("rejects mismatched release identity and malformed queue messages before processing", async () => {
  await assert.rejects(
    runAwsOperatorOnce(
      {
        ...CONFIG,
        releaseId:
          "release-0123456789abcdef",
      },
      {},
    ),
    /AWS operator runtime failed safely/,
  );
  await assert.rejects(
    runAwsOperatorOnce(CONFIG, {
      buildTransitions: () => ({}),
      documentClient: {
        async send() {
          return {};
        },
      },
      processMessage: async () => {},
      sqs: {
        async send() {
          return {
            Messages: [
              {
                Body: "",
                MessageId: "message-1",
                ReceiptHandle: "receipt-1",
              },
            ],
          };
        },
      },
    }),
    /AWS operator runtime failed safely/,
  );
});
