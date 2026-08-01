import assert from "node:assert/strict";
import { test } from "node:test";

import {
  runAwsOperatorLoop,
  runAwsOperatorOnce,
} from "../infra/aws/runtime/operator-runtime.mjs";
import {
  createInitialControlState,
} from "../src/bilateral/aws/control-actions.mjs";

const CONFIG = Object.freeze({
  actionQueueUrl:
    "https://sqs.us-west-2.amazonaws.com/123456789012/actions.fifo",
  actionTableName: "clockchain-actions",
  paymentMoved: false,
  publicMonitorBucketName:
    "clockchain-public-monitor",
  publicMonitorControlKey: "control.json",
  releaseId: "release-bd7662a5eeb41614",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  schema:
    "clockchain.aws-operator-runtime/v1",
  sessionId:
    "11111111-1111-4111-8111-111111111111",
});

function runtimeTransitions(
  expectedClaimFingerprint = null,
) {
  return {
    abortSession: async () => {},
    approveBootstrapClaim: async () => {},
    createSession: async () => {},
    launchCoordinator: async () => {},
    launchFundingTask: async () => {},
    launchVerifierTask: async () => {},
    readExpectedClaimFingerprint:
      async () => expectedClaimFingerprint,
  };
}

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
      s3: {
        async send(command) {
          calls.push([
            "s3",
            command.constructor.name,
            command.input,
          ]);
          return {};
        },
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

test("seeds release control context and publishes a strict start-run snapshot before idle", async () => {
  const calls = [];
  const initialControlContext =
    Object.freeze({
      expectedClaimFingerprint: null,
      state: createInitialControlState(),
    });
  let seeded = false;
  let expectedClaimReads = 0;
  const result = await runAwsOperatorOnce(
    CONFIG,
    {
      buildTransitions: () => ({
        ...runtimeTransitions(),
        readExpectedClaimFingerprint:
          async () => {
            expectedClaimReads += 1;
            throw new Error(
              "EMPTY must not read expected claim fingerprint",
            );
          },
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
            "PutCommand"
          ) {
            seeded = true;
          }
          if (
            command.constructor.name ===
            "GetCommand"
          ) {
            if (!seeded) return {};
            return {
              Item: {
                controlContext:
                  initialControlContext,
              },
            };
          }
          return {};
        },
      },
      processMessage: async () => {
        throw new Error("must not run");
      },
      s3: {
        async send(command) {
          calls.push([
            "s3",
            command.constructor.name,
            command.input,
          ]);
          return {};
        },
      },
      sqs: {
        async send(command) {
          calls.push([
            "sqs",
            command.constructor.name,
            command.input,
          ]);
          return { Messages: [] };
        },
      },
    },
  );
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "IDLE",
  });
  assert.equal(expectedClaimReads, 0);
  const seed = calls.find(
    ([kind, name]) =>
      kind === "dynamo" &&
      name === "PutCommand",
  )[2];
  assert.deepEqual(seed, {
    ConditionExpression:
      "attribute_not_exists(actionId)",
    Item: {
      actionId:
        `RELEASE#${CONFIG.releaseId}`,
      controlContext: initialControlContext,
      recordType: "CONTROL_CONTEXT",
    },
    TableName: CONFIG.actionTableName,
  });
  const publish = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  )[2];
  assert.equal(
    publish.Bucket,
    CONFIG.publicMonitorBucketName,
  );
  assert.equal(
    publish.Key,
    CONFIG.publicMonitorControlKey,
  );
  assert.equal(
    publish.ContentType,
    "application/json; charset=utf-8",
  );
  const snapshot = JSON.parse(
    Buffer.from(publish.Body).toString("utf8"),
  );
  assert.deepEqual(snapshot.control, {
    allowedActions: ["START_RUN"],
    claims: {
      payer: {
        fingerprint: null,
        status: "WAITING",
      },
      requestor: {
        fingerprint: null,
        status: "WAITING",
      },
    },
    releaseId: CONFIG.releaseId,
    repositorySha: CONFIG.repositorySha,
    revision: 0,
    sessionId: CONFIG.sessionId,
  });
  assert.equal(
    snapshot.currentStep,
    "Waiting for the operator to start the hosted run.",
  );
  assert.equal(snapshot.paymentMoved, false);
  assert.equal(
    snapshot.runId,
    "run-bd7662a5eeb41614",
  );
  assert.equal(snapshot.runStatus, "WAITING");
  assert.equal(
    Number.isSafeInteger(snapshot.publishedAtMs),
    true,
  );
  assert.equal(snapshot.staleAfterMs, 120_000);
  assert.equal(
    JSON.stringify(snapshot).includes("authority"),
    false,
  );
  assert.equal(
    JSON.stringify(snapshot).includes("/var/"),
    false,
  );
  assert.equal(
    calls.filter(
      ([kind, name]) =>
        kind === "s3" &&
        name === "PutObjectCommand",
    ).length,
    1,
  );
});

test("normalizes a DynamoDB-reordered empty control state before validating and publishing", async () => {
  const calls = [];
  const result = await runAwsOperatorOnce(CONFIG, {
    buildTransitions: () => runtimeTransitions(),
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
                expectedClaimFingerprint: null,
                state: {
                  actionHistory: [],
                  schema:
                    "clockchain.aws-control-state/v1",
                  releaseId: null,
                  repositorySha: null,
                  sessionId: null,
                  paymentMoved: false,
                  revision: 0,
                  status: "EMPTY",
                },
              },
            },
          };
        }
        return {};
      },
    },
    s3: {
      async send(command) {
        calls.push([
          "s3",
          command.constructor.name,
          command.input,
        ]);
        return {};
      },
    },
    sqs: {
      async send() {
        return { Messages: [] };
      },
    },
  });
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "IDLE",
  });
  assert.equal(
    calls.some(
      ([kind, name]) =>
        kind === "dynamo" &&
        name === "PutCommand",
    ),
    false,
  );
  const publish = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  )[2];
  const snapshot = JSON.parse(
    Buffer.from(publish.Body).toString("utf8"),
  );
  assert.deepEqual(snapshot.control, {
    allowedActions: ["START_RUN"],
    claims: {
      payer: {
        fingerprint: null,
        status: "WAITING",
      },
      requestor: {
        fingerprint: null,
        status: "WAITING",
      },
    },
    releaseId: CONFIG.releaseId,
    repositorySha: CONFIG.repositorySha,
    revision: 0,
    sessionId: CONFIG.sessionId,
  });
  assert.equal(snapshot.paymentMoved, false);
});

test("accepts only ConditionalCheckFailedException as startup seed race", async () => {
  for (const [name, shouldReject] of [
    ["ConditionalCheckFailedException", false],
    ["AccessDeniedException", true],
  ]) {
    let seeded = false;
    const input = runAwsOperatorOnce(CONFIG, {
      buildTransitions: () =>
        runtimeTransitions(),
      documentClient: {
        async send(command) {
          if (
            command.constructor.name ===
            "PutCommand"
          ) {
            seeded = true;
            throw Object.assign(
              new Error(name),
              { name },
            );
          }
          if (
            command.constructor.name ===
            "GetCommand"
          ) {
            if (!seeded) return {};
            return {
              Item: {
                controlContext: {
                  expectedClaimFingerprint:
                    null,
                  state:
                    createInitialControlState(),
                },
              },
            };
          }
          return {};
        },
      },
      s3: {
        async send() {
          return {};
        },
      },
      sqs: {
        async send() {
          return { Messages: [] };
        },
      },
    });
    if (shouldReject) {
      await assert.rejects(
        input,
        /AWS operator runtime failed safely/,
      );
    } else {
      assert.deepEqual(await input, {
        paymentMoved: false,
        status: "IDLE",
      });
    }
  }
});

test("operator loop seeds initial control context only during startup", async () => {
  const calls = [];
  const controller = new AbortController();
  let seeded = false;
  const controlContext = {
    expectedClaimFingerprint: null,
    state: createInitialControlState(),
  };
  await runAwsOperatorLoop(CONFIG, {
    buildTransitions: () => ({
      abortSession: async () => {},
      approveBootstrapClaim: async () => {},
      createSession: async () => {},
      launchCoordinator: async () => {},
      launchFundingTask: async () => {},
      launchVerifierTask: async () => {},
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
          "PutCommand"
        ) {
          seeded = true;
        }
        if (
          command.constructor.name ===
          "GetCommand"
        ) {
          if (!seeded) return {};
          return {
            Item: {
              controlContext,
            },
          };
        }
        return {};
      },
    },
    s3: {
      async send(command) {
        calls.push([
          "s3",
          command.constructor.name,
          command.input,
        ]);
        return {};
      },
    },
    signal: controller.signal,
    sqs: {
      async send(command) {
        calls.push([
          "sqs",
          command.constructor.name,
          command.input,
        ]);
        if (
          calls.filter(
            ([kind, name]) =>
              kind === "sqs" &&
              name ===
                "ReceiveMessageCommand",
          ).length === 2
        ) {
          controller.abort();
        }
        return { Messages: [] };
      },
    },
  });
  assert.equal(
    calls.filter(
      ([kind, name]) =>
        kind === "dynamo" &&
        name === "PutCommand",
    ).length,
    1,
  );
  assert.equal(
    calls.filter(
      ([kind, name]) =>
        kind === "dynamo" &&
        name === "GetCommand",
    ).length,
    3,
  );
  assert.equal(
    calls.filter(
      ([kind, name]) =>
        kind === "s3" &&
        name === "PutObjectCommand",
    ).length,
    2,
  );
});

test("operator restart reads active release context before publishing control snapshot", async () => {
  const calls = [];
  const claimFingerprint = "a".repeat(64);
  await runAwsOperatorOnce(CONFIG, {
    buildTransitions: () => ({
      abortSession: async () => {},
      approveBootstrapClaim: async () => {},
      createSession: async () => {},
      launchCoordinator: async () => {},
      launchFundingTask: async () => {},
      launchVerifierTask: async () => {},
      readExpectedClaimFingerprint: async (
        input,
      ) => {
        assert.equal(
          input.sessionId,
          CONFIG.sessionId,
        );
        return claimFingerprint;
      },
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
                  actionHistory: [
                    {
                      actionDigest:
                        "b".repeat(64),
                      actionId:
                        "33333333-3333-4333-8333-333333333333",
                      type: "START_RUN",
                    },
                  ],
                  paymentMoved: false,
                  releaseId: CONFIG.releaseId,
                  repositorySha:
                    CONFIG.repositorySha,
                  revision: 1,
                  schema:
                    "clockchain.aws-control-state/v1",
                  sessionId: CONFIG.sessionId,
                  status: "RUN_STARTED",
                },
              },
            },
          };
        }
        return {};
      },
    },
    s3: {
      async send(command) {
        calls.push([
          "s3",
          command.constructor.name,
          command.input,
        ]);
        return {};
      },
    },
    sqs: {
      async send(command) {
        calls.push([
          "sqs",
          command.constructor.name,
          command.input,
        ]);
        return { Messages: [] };
      },
    },
  });
  assert.equal(
    calls.some(
      ([kind, name]) =>
        kind === "dynamo" &&
        name === "PutCommand",
    ),
    false,
  );
  const publish = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  )[2];
  const snapshot = JSON.parse(
    Buffer.from(publish.Body).toString("utf8"),
  );
  assert.equal(
    snapshot.runId,
    "run-bd7662a5eeb41614",
  );
  assert.deepEqual(
    snapshot.control.allowedActions,
    ["APPROVE_PAYER", "ABORT"],
  );
  assert.deepEqual(snapshot.control.claims, {
    payer: {
      fingerprint: claimFingerprint,
      status: "PENDING",
    },
    requestor: {
      fingerprint: null,
      status: "WAITING",
    },
  });
});

test("operator snapshot derives claim approval status from action history after abort", async () => {
  const calls = [];
  await runAwsOperatorOnce(CONFIG, {
    buildTransitions: () =>
      runtimeTransitions(),
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
                  actionHistory: [
                    {
                      actionDigest:
                        "b".repeat(64),
                      actionId:
                        "33333333-3333-4333-8333-333333333333",
                      type: "START_RUN",
                    },
                    {
                      actionDigest:
                        "c".repeat(64),
                      actionId:
                        "44444444-4444-4444-8444-444444444444",
                      type: "ABORT",
                    },
                  ],
                  paymentMoved: false,
                  releaseId: CONFIG.releaseId,
                  repositorySha:
                    CONFIG.repositorySha,
                  revision: 2,
                  schema:
                    "clockchain.aws-control-state/v1",
                  sessionId: CONFIG.sessionId,
                  status: "ABORTED",
                },
              },
            },
          };
        }
        return {};
      },
    },
    s3: {
      async send(command) {
        calls.push([
          "s3",
          command.constructor.name,
          command.input,
        ]);
        return {};
      },
    },
    sqs: {
      async send(command) {
        calls.push([
          "sqs",
          command.constructor.name,
          command.input,
        ]);
        return { Messages: [] };
      },
    },
  });
  const publish = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  )[2];
  const snapshot = JSON.parse(
    Buffer.from(publish.Body).toString("utf8"),
  );
  assert.deepEqual(snapshot.control.claims, {
    payer: {
      fingerprint: null,
      status: "WAITING",
    },
    requestor: {
      fingerprint: null,
      status: "WAITING",
    },
  });
  assert.deepEqual(
    snapshot.control.allowedActions,
    [],
  );
  assert.equal(snapshot.runStatus, "FAILED");
});

test("operator snapshot publishes verified after verifier passed", async () => {
  const calls = [];
  await runAwsOperatorOnce(CONFIG, {
    buildTransitions: () =>
      runtimeTransitions(),
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
                  actionHistory: [
                    {
                      actionDigest:
                        "b".repeat(64),
                      actionId:
                        "33333333-3333-4333-8333-333333333333",
                      type: "START_RUN",
                    },
                    {
                      actionDigest:
                        "c".repeat(64),
                      actionId:
                        "44444444-4444-4444-8444-444444444444",
                      type: "APPROVE_PAYER",
                    },
                    {
                      actionDigest:
                        "d".repeat(64),
                      actionId:
                        "55555555-5555-4555-8555-555555555555",
                      type: "APPROVE_REQUESTOR",
                    },
                    {
                      actionDigest:
                        "e".repeat(64),
                      actionId:
                        "66666666-6666-4666-8666-666666666666",
                      type: "FUND",
                    },
                    {
                      actionDigest:
                        "f".repeat(64),
                      actionId:
                        "77777777-7777-4777-8777-777777777777",
                      type: "VERIFY",
                    },
                  ],
                  paymentMoved: false,
                  releaseId: CONFIG.releaseId,
                  repositorySha:
                    CONFIG.repositorySha,
                  revision: 5,
                  schema:
                    "clockchain.aws-control-state/v1",
                  sessionId: CONFIG.sessionId,
                  status: "VERIFY_REQUESTED",
                },
              },
            },
          };
        }
        return {};
      },
    },
    s3: {
      async send(command) {
        calls.push([
          "s3",
          command.constructor.name,
          command.input,
        ]);
        return {};
      },
    },
    sqs: {
      async send(command) {
        calls.push([
          "sqs",
          command.constructor.name,
          command.input,
        ]);
        return { Messages: [] };
      },
    },
  });
  const publish = calls.find(
    ([kind, name]) =>
      kind === "s3" &&
      name === "PutObjectCommand",
  )[2];
  const snapshot = JSON.parse(
    Buffer.from(publish.Body).toString("utf8"),
  );
  assert.equal(snapshot.runStatus, "VERIFIED");
  assert.equal(
    snapshot.currentStep,
    "Verification completed.",
  );
  assert.doesNotMatch(
    snapshot.currentStep,
    /auth|authority|authorization/i,
  );
  assert.deepEqual(
    snapshot.control.allowedActions,
    [],
  );
});

test("operator runtime rejects forged stored control states before publishing", async () => {
  const baseStarted = {
    actionHistory: [
      {
        actionDigest: "b".repeat(64),
        actionId:
          "33333333-3333-4333-8333-333333333333",
        type: "START_RUN",
      },
    ],
    paymentMoved: false,
    releaseId: CONFIG.releaseId,
    repositorySha: CONFIG.repositorySha,
    revision: 1,
    schema: "clockchain.aws-control-state/v1",
    sessionId: CONFIG.sessionId,
    status: "RUN_STARTED",
  };
  const forgedStates = [
    {
      ...baseStarted,
      actionHistory: [],
      revision: 0,
      status: "VERIFY_REQUESTED",
    },
    {
      ...baseStarted,
      status: "AUTHORIZED",
    },
    {
      ...baseStarted,
      actionHistory: [
        {
          actionDigest: "b".repeat(64),
          actionId:
            "33333333-3333-4333-8333-333333333333",
        },
      ],
    },
    {
      ...baseStarted,
      actionHistory: [
        baseStarted.actionHistory[0],
        {
          ...baseStarted.actionHistory[0],
        },
      ],
      revision: 2,
    },
  ];
  for (const state of forgedStates) {
    await assert.rejects(
      runAwsOperatorOnce(CONFIG, {
        buildTransitions: () =>
          runtimeTransitions(),
        documentClient: {
          async send(command) {
            if (
              command.constructor.name ===
              "GetCommand"
            ) {
              return {
                Item: {
                  controlContext: {
                    expectedClaimFingerprint:
                      null,
                    state,
                  },
                },
              };
            }
            return {};
          },
        },
        s3: {
          async send() {
            assert.fail(
              "forged state must not publish",
            );
          },
        },
        sqs: {
          async send() {
            return { Messages: [] };
          },
        },
      }),
      /AWS operator runtime failed safely/,
    );
  }
});

test("returns an idle result without inventing an action", async () => {
  const result = await runAwsOperatorOnce(
    CONFIG,
    {
      buildTransitions: () =>
        runtimeTransitions(),
      documentClient: {
        async send(command) {
          if (
            command.constructor.name ===
            "GetCommand"
          ) {
            return {
              Item: {
                controlContext: {
                  expectedClaimFingerprint:
                    null,
                  state:
                    createInitialControlState(),
                },
              },
            };
          }
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
      s3: {
        async send() {
          return {};
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
