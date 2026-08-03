import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createOperatorChildLauncher,
} from "../infra/aws/runtime/operator-child-launcher.mjs";
import {
  launchPinnedTask,
} from "../infra/aws/runtime/ecs-task-runner.mjs";
import {
  createDurableOperatorLaunchRecord,
  deriveOperatorLaunchAttemptId,
} from "../infra/aws/runtime/operator-launch-record.mjs";

const RELEASE_ID = "release-bd7662a5eeb41614";
const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const SESSION_ID =
  "11111111-1111-4111-8111-111111111111";
const ACTION_ID =
  "22222222-2222-4222-8222-222222222222";
const TASK_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const COMMON = Object.freeze({
  actionId: ACTION_ID,
  expectedRevision: 7,
  paymentMoved: false,
  releaseId: RELEASE_ID,
  repositorySha: REPOSITORY_SHA,
  sessionId: SESSION_ID,
});

function fundingRecord() {
  const addresses = [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003",
    "0x0000000000000000000000000000000000000004",
  ];
  return {
    addresses,
    paymentMoved: false,
    participants: addresses.map((address) => ({
      address,
      balanceWei: "0",
      nonce: "0",
    })),
    schema:
      "clockchain.bilateral-funding-addresses/v1",
  };
}

function stakeholderHandoff() {
  const evidenceRoot =
    `/var/lib/clockchain/evidence/releases/${RELEASE_ID}/stakeholder`;
  return {
    descriptorDigest: "a".repeat(64),
    descriptorPath:
      `${evidenceRoot}/descriptor.json`,
    evidenceDigest: "b".repeat(64),
    mandateDigest: "c".repeat(64),
    payerMandatePath:
      `${evidenceRoot}/payer-mandate.json`,
    payeeResultsPath:
      `${evidenceRoot}/payee-results`,
    payerResultsPath:
      `${evidenceRoot}/payer-results`,
    paymentMoved: false,
    paymentRequestPath:
      `${evidenceRoot}/payment-request.json`,
    publicationPath:
      `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}/stakeholder-publication.json`,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    requestDigest: "d".repeat(64),
    schema: "clockchain.aws-verifier-handoff/v1",
    sessionDigest: "e".repeat(64),
    sessionId: SESSION_ID,
    subjectRun: "stakeholder",
  };
}

function fixture({ times = [1000, 9999] } = {}) {
  const calls = [];
  const records = new Map();
  const launcher = createOperatorChildLauncher({
    config: {
      clusterArn:
        "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
      funding: {
        containerName: "funding",
        createdAt:
          "2026-07-31T00:00:00.000Z",
        expectedTreasuryAddress:
          "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce",
        fundingRecordPath:
          `/var/lib/clockchain/funding-record/releases/${RELEASE_ID}/funding-record.json`,
        journalDirectory:
          `/var/lib/clockchain/funding-journal/releases/${RELEASE_ID}/journal`,
        keystoreSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
        passwordSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/funding:7",
      },
      rpcSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
      verifier: {
        clockchainTokenSecretArn:
          "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
        containerName: "verifier",
        securityGroupId:
          "sg-0123456789abcdef0",
        subnetIds: [
          "subnet-0123456789abcdef0",
          "subnet-11111111111111111",
        ],
        taskDefinitionArn:
          "arn:aws:ecs:us-west-2:123456789012:task-definition/verifier:7",
      },
    },
    launchRecord: {
      async prepare(input) {
        calls.push(["prepare", input]);
        const key = `${input.identity.kind}:${input.identity.actionId}`;
        const existing = records.get(key);
        if (existing !== undefined) return existing;
        const record = {
          actionAtMs: input.actionAtMs,
          attemptId: input.runtimeInput.verifier?.attemptId ??
            deriveOperatorLaunchAttemptId(
              input.identity,
            ),
          clientToken: {
            action:
              input.identity.kind === "funding"
                ? "fund"
                : "verify",
            childTask:
              input.identity.kind,
            fingerprint:
              "0123456789abcdef",
          },
          taskArn: null,
        };
        records.set(key, record);
        return record;
      },
      async read(input) {
        calls.push(["read", input]);
        return records.get(
          `${input.identity.kind}:${input.identity.actionId}`,
        ) ?? null;
      },
      async adoptTask(input) {
        calls.push(["adopt", input]);
        const key = `${input.identity.kind}:${input.identity.actionId}`;
        const next = {
          ...records.get(key),
          taskArn: input.taskArn,
        };
        records.set(key, next);
        return next;
      },
    },
    launchPinnedTask: async (input) => {
      calls.push(["launch", input]);
      return {
        paymentMoved: false,
        status: "RUNNING",
        taskArn: TASK_ARN,
      };
    },
    nowMs: () => times.shift(),
    readFundingRecord: async (input) => {
      calls.push(["fundingRecord", input]);
      return fundingRecord();
    },
    readFundingResult: async () => ({
      paymentMoved: false,
      status: "FUNDED",
    }),
    readVerifierHandoff: async (input) => {
      calls.push(["handoff", input]);
      return stakeholderHandoff();
    },
    readVerifierPublication: async (input) => {
      calls.push(["publication", input]);
      assert.deepEqual(
        Object.keys(input),
        ["expectedRevision", "handoff", "path"],
      );
      return {
        attemptId:
          deriveOperatorLaunchAttemptId({
            actionId: COMMON.actionId,
            expectedRevision:
              COMMON.expectedRevision,
            kind: "verifier",
            releaseId: COMMON.releaseId,
            repositorySha:
              COMMON.repositorySha,
            sessionId: COMMON.sessionId,
          }),
        evidenceDigest:
          input.handoff.evidenceDigest,
        paymentMoved: false,
        publicationDigest: "f".repeat(64),
        repositorySha: REPOSITORY_SHA,
        revision: input.expectedRevision,
        schema:
          "clockchain.aws-verifier-task-publication/v1",
        status: "VERIFICATION_PASSED",
        taskArn: TASK_ARN,
        writtenAtMs: "2000",
      };
    },
    waitForPinnedTask: async (input) => {
      calls.push(["wait", input]);
      return {
        paymentMoved: false,
        status: "SUCCEEDED",
        taskArn: input.taskArn,
      };
    },
  });
  return { calls, launcher };
}

function launcherConfig() {
  return {
    clusterArn:
      "arn:aws:ecs:us-west-2:123456789012:cluster/clockchain",
    funding: {
      containerName: "funding",
      createdAt:
        "2026-07-31T00:00:00.000Z",
      expectedTreasuryAddress:
        "0x157a377e4181f3f87c7f6efed5ddc340ccc00dce",
      fundingRecordPath:
        `/var/lib/clockchain/funding-record/releases/${RELEASE_ID}/funding-record.json`,
      journalDirectory:
        `/var/lib/clockchain/funding-journal/releases/${RELEASE_ID}/journal`,
      keystoreSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-keystore",
      passwordSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:treasury-password",
      securityGroupId:
        "sg-0123456789abcdef0",
      subnetIds: [
        "subnet-0123456789abcdef0",
        "subnet-11111111111111111",
      ],
      taskDefinitionArn:
        "arn:aws:ecs:us-west-2:123456789012:task-definition/funding:7",
    },
    rpcSecretArn:
      "arn:aws:secretsmanager:us-west-2:123456789012:secret:rpc-url",
    verifier: {
      clockchainTokenSecretArn:
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:clockchain-token",
      containerName: "verifier",
      securityGroupId:
        "sg-0123456789abcdef0",
      subnetIds: [
        "subnet-0123456789abcdef0",
        "subnet-11111111111111111",
      ],
      taskDefinitionArn:
        "arn:aws:ecs:us-west-2:123456789012:task-definition/verifier:7",
    },
  };
}

test("FUND creates one durable runtime input from the coordinator funding record and retries adopt it", async () => {
  const { calls, launcher } = fixture();
  assert.deepEqual(
    await launcher.launch("funding", COMMON),
    { paymentMoved: false, status: "FUNDED" },
  );
  assert.deepEqual(
    await launcher.launch("funding", COMMON),
    { paymentMoved: false, status: "FUNDED" },
  );
  assert.equal(
    calls.filter(([name]) => name === "launch").length,
    1,
  );
  assert.equal(
    calls.find(([name]) => name === "prepare")[1]
      .runtimeInput.funding.fundingRecordPath,
    `/var/lib/clockchain/funding-record/releases/${RELEASE_ID}/funding-record.json`,
  );
});

test("VERIFY retry adopts original actionAtMs and task after wall clock advances", async () => {
  const { calls, launcher } = fixture();
  assert.equal(
    (await launcher.launch("verifier", COMMON)).status,
    "VERIFICATION_PASSED",
  );
  assert.equal(
    (await launcher.launch("verifier", COMMON)).status,
    "VERIFICATION_PASSED",
  );
  assert.equal(
    calls.filter(([name]) => name === "launch").length,
    1,
  );
  const publications = calls.filter(
    ([name]) => name === "publication",
  );
  const prepares = calls.filter(
    ([name, input]) =>
      name === "prepare" &&
      input.identity.kind === "verifier",
  );
  assert.deepEqual(
    prepares.map(([, input]) => input.actionAtMs),
    [1000, 1000, 1000, 1000],
  );
  assert.equal(publications.length, 2);
});

test("VERIFY composition uses the durable record attempt id for runtime, launch, and publication across delayed retry", async () => {
  const records = new Map();
  const calls = [];
  const expectedAttemptId =
    deriveOperatorLaunchAttemptId({
      actionId: COMMON.actionId,
      expectedRevision:
        COMMON.expectedRevision,
      kind: "verifier",
      releaseId: COMMON.releaseId,
      repositorySha:
        COMMON.repositorySha,
      sessionId: COMMON.sessionId,
    });
  const launcher =
    createOperatorChildLauncher({
      config: launcherConfig(),
      launchPinnedTask: async (input) => {
        calls.push(["launch", input]);
        return {
          paymentMoved: false,
          status: "RUNNING",
          taskArn: TASK_ARN,
        };
      },
      launchRecord:
        createDurableOperatorLaunchRecord({
          async readRecord(key) {
            return records.get(key) ?? null;
          },
          async writeRecord(key, record) {
            records.set(key, record);
          },
        }),
      nowMs: (() => {
        const times = [1000, 9999];
        return () => times.shift();
      })(),
      readFundingRecord: async () => fundingRecord(),
      readFundingResult: async () => ({
        paymentMoved: false,
        status: "FUNDED",
      }),
      readVerifierHandoff: async () =>
        stakeholderHandoff(),
      readVerifierPublication: async (input) => {
        calls.push(["publication", input]);
        return {
          attemptId: expectedAttemptId,
          evidenceDigest:
            input.handoff.evidenceDigest,
          paymentMoved: false,
          publicationDigest: "f".repeat(64),
          repositorySha: REPOSITORY_SHA,
          revision: input.expectedRevision,
          schema:
            "clockchain.aws-verifier-task-publication/v1",
          status: "VERIFICATION_PASSED",
          taskArn: TASK_ARN,
          writtenAtMs: "2000",
        };
      },
      waitForPinnedTask: async (input) => {
        calls.push(["wait", input]);
        return {
          paymentMoved: false,
          status: "SUCCEEDED",
          taskArn: input.taskArn,
        };
      },
    });
  await launcher.launch("verifier", COMMON);
  await launcher.launch("verifier", COMMON);
  assert.equal(
    calls.filter(([name]) => name === "launch").length,
    1,
  );
  const launchRuntime = calls.find(
    ([name]) => name === "launch",
  )[1].runtimeInput.verifier;
  const publications = calls.filter(
    ([name]) => name === "publication",
  );
  assert.equal(
    launchRuntime.attemptId,
    expectedAttemptId,
  );
  assert.equal(
    launchRuntime.attemptRoot,
    `/var/lib/clockchain/verifier-output/releases/${RELEASE_ID}/attempts/${expectedAttemptId}`,
  );
  assert.deepEqual(
    publications.map(([, input]) =>
      Object.keys(input)),
    [
      ["expectedRevision", "handoff", "path"],
      ["expectedRevision", "handoff", "path"],
    ],
  );
});

test("FUND composition passes durable clientToken in ECS runner canonical key order and adopts on retry", async () => {
  const records = new Map();
  const runTaskCalls = [];
  const launcher =
    createOperatorChildLauncher({
      config: launcherConfig(),
      launchPinnedTask: async (input) =>
        launchPinnedTask(input, {
          ecs: {
            async send(command) {
              runTaskCalls.push(command.input);
              return {
                failures: [],
                tasks: [
                  {
                    taskArn: TASK_ARN,
                  },
                ],
              };
            },
          },
        }),
      launchRecord:
        createDurableOperatorLaunchRecord({
          async readRecord(key) {
            return records.get(key) ?? null;
          },
          async writeRecord(key, record) {
            records.set(key, record);
          },
        }),
      nowMs: (() => {
        const times = [1000, 9999];
        return () => times.shift();
      })(),
      readFundingRecord: async () => fundingRecord(),
      readFundingResult: async () => ({
        paymentMoved: false,
        status: "FUNDED",
      }),
      readVerifierHandoff: async () =>
        stakeholderHandoff(),
      readVerifierPublication: async () => {
        assert.fail("funding must not read verifier publication");
      },
      waitForPinnedTask: async (input) => ({
        paymentMoved: false,
        status: "SUCCEEDED",
        taskArn: input.taskArn,
      }),
    });
  await launcher.launch("funding", COMMON);
  await launcher.launch("funding", COMMON);
  assert.equal(runTaskCalls.length, 1);
  assert.match(
    runTaskCalls[0].clientToken,
    /^cc-funding-fund-[0-9a-f]{16}$/,
  );
});

test("VERIFY reads publication through the canonical handoff API and validates the returned publication", async () => {
  const calls = [];
  const records = new Map();
  const expectedAttemptId =
    deriveOperatorLaunchAttemptId({
      actionId: COMMON.actionId,
      expectedRevision:
        COMMON.expectedRevision,
      kind: "verifier",
      releaseId: COMMON.releaseId,
      repositorySha:
        COMMON.repositorySha,
      sessionId: COMMON.sessionId,
    });
  const handoff = stakeholderHandoff();
  const launcher =
    createOperatorChildLauncher({
      config: launcherConfig(),
      launchPinnedTask: async () => ({
        paymentMoved: false,
        status: "RUNNING",
        taskArn: TASK_ARN,
      }),
      launchRecord:
        createDurableOperatorLaunchRecord({
          async readRecord(key) {
            return records.get(key) ?? null;
          },
          async writeRecord(key, record) {
            records.set(key, record);
          },
        }),
      nowMs: () => 1000,
      readFundingRecord: async () => fundingRecord(),
      readFundingResult: async () => ({
        paymentMoved: false,
        status: "FUNDED",
      }),
      readVerifierHandoff: async () => handoff,
      readVerifierPublication: async (input) => {
        calls.push(["publication", input]);
        assert.deepEqual(input, {
          expectedRevision:
            COMMON.expectedRevision,
          handoff,
          path: handoff.publicationPath,
        });
        return {
          attemptId: expectedAttemptId,
          evidenceDigest:
            handoff.evidenceDigest,
          paymentMoved: false,
          publicationDigest: "f".repeat(64),
          repositorySha: REPOSITORY_SHA,
          revision:
            COMMON.expectedRevision,
          schema:
            "clockchain.aws-verifier-task-publication/v1",
          status: "VERIFICATION_PASSED",
          taskArn: TASK_ARN,
          writtenAtMs: "1001",
        };
      },
      waitForPinnedTask: async (input) => ({
        paymentMoved: false,
        status: "SUCCEEDED",
        taskArn: input.taskArn,
      }),
    });
  assert.equal(
    (await launcher.launch("verifier", COMMON)).status,
    "VERIFICATION_PASSED",
  );
  assert.equal(
    calls.filter(([name]) => name === "publication").length,
    1,
  );
});

test("child launcher fails closed on malformed wait, funding result, and verifier publication outputs", async () => {
  for (const mode of [
    "wait",
    "funding-result",
    "publication",
  ]) {
    const records = new Map();
    const launcher =
      createOperatorChildLauncher({
        config: launcherConfig(),
        launchPinnedTask: async () => ({
          paymentMoved: false,
          status: "RUNNING",
          taskArn: TASK_ARN,
        }),
        launchRecord:
          createDurableOperatorLaunchRecord({
            async readRecord(key) {
              return records.get(key) ?? null;
            },
            async writeRecord(key, record) {
              records.set(key, record);
            },
          }),
        nowMs: () => 1000,
        readFundingRecord: async () => fundingRecord(),
        readFundingResult: async () =>
          mode === "funding-result"
            ? {
                paymentMoved: false,
                status: "RUNNING",
              }
            : {
                paymentMoved: false,
                status: "FUNDED",
              },
        readVerifierHandoff: async () =>
          stakeholderHandoff(),
      readVerifierPublication: async (input) =>
          mode === "publication"
            ? {
                attemptId:
                  "11111111-1111-4111-8111-111111111111",
                evidenceDigest:
                  input.handoff.evidenceDigest,
                paymentMoved: false,
                publicationDigest: "f".repeat(64),
                repositorySha: REPOSITORY_SHA,
                revision:
                  COMMON.expectedRevision,
                schema:
                  "clockchain.aws-verifier-task-publication/v1",
                status: "VERIFICATION_PASSED",
                taskArn: TASK_ARN,
                writtenAtMs: "1001",
              }
            : {
                attemptId:
                  deriveOperatorLaunchAttemptId({
                    actionId:
                      COMMON.actionId,
                    expectedRevision:
                      COMMON.expectedRevision,
                    kind: "verifier",
                    releaseId:
                      COMMON.releaseId,
                    repositorySha:
                      COMMON.repositorySha,
                    sessionId:
                      COMMON.sessionId,
                  }),
                evidenceDigest:
                  input.handoff.evidenceDigest,
                paymentMoved: false,
                publicationDigest: "f".repeat(64),
                repositorySha: REPOSITORY_SHA,
                revision:
                  COMMON.expectedRevision,
                schema:
                  "clockchain.aws-verifier-task-publication/v1",
                status: "VERIFICATION_PASSED",
                taskArn: TASK_ARN,
                writtenAtMs: "1001",
              },
        waitForPinnedTask: async (input) =>
          mode === "wait"
            ? {
                paymentMoved: false,
                status: "SUCCEEDED",
                taskArn: TASK_ARN,
                extra: true,
              }
            : {
                paymentMoved: false,
                status: "SUCCEEDED",
                taskArn: input.taskArn,
              },
      });
    await assert.rejects(
      launcher.launch(
        mode === "funding-result"
          ? "funding"
          : "verifier",
        COMMON,
      ),
      /AWS operator child launcher failed safely/,
    );
  }
});

test("child launcher rejects proxy and accessor inputs before launch or store writes", async () => {
  let launches = 0;
  let writes = 0;
  let getterCalls = 0;
  const accessorAction = { ...COMMON };
  Object.defineProperty(accessorAction, "releaseId", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return RELEASE_ID;
    },
  });
  for (const value of [
    new Proxy(COMMON, {}),
    accessorAction,
  ]) {
    const launcher =
      createOperatorChildLauncher({
        config: launcherConfig(),
        launchPinnedTask: async () => {
          launches += 1;
          return {
            paymentMoved: false,
            status: "RUNNING",
            taskArn: TASK_ARN,
          };
        },
        launchRecord:
          createDurableOperatorLaunchRecord({
            async readRecord() {
              return null;
            },
            async writeRecord() {
              writes += 1;
            },
          }),
        nowMs: () => 1000,
        readFundingRecord: async () => fundingRecord(),
        readFundingResult: async () => ({
          paymentMoved: false,
          status: "FUNDED",
        }),
        readVerifierHandoff: async () =>
          stakeholderHandoff(),
        readVerifierPublication: async () => {
          assert.fail("publication must not be read");
        },
        waitForPinnedTask: async () => {
          assert.fail("wait must not start");
        },
      });
    await assert.rejects(
      launcher.launch("funding", value),
      /AWS operator child launcher failed safely/,
    );
  }
  assert.equal(launches, 0);
  assert.equal(writes, 0);
  assert.equal(getterCalls, 0);
});
