import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createEcsVerifierLauncher,
} from "../src/bilateral/aws/ecs-verifier-launcher.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const TASK_DEFINITION_ARN =
  "arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-verifier:42";
const TASK_A =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/11111111111111111111111111111111";
const TASK_B =
  "arn:aws:ecs:us-west-2:123456789012:task/clockchain/22222222222222222222222222222222";
const ATTEMPT_A =
  "11111111-1111-4111-8111-111111111111";
const ATTEMPT_B =
  "22222222-2222-4222-8222-222222222222";
const IMAGE_DIGEST = `sha256:${"a".repeat(64)}`;
const EVIDENCE_DIGEST = "b".repeat(64);
const PUBLICATION_DIGEST = "c".repeat(64);
const ACTION_AT_MS = 2_000_000_000_000;

function definition(overrides = {}) {
  return {
    containerName: "verifier",
    imageDigest: IMAGE_DIGEST,
    mounts: [
      {
        accessPointArn:
          "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/fsap-11111111111111111",
        containerPath: "/evidence",
        readOnly: true,
      },
      {
        accessPointArn:
          "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/fsap-22222222222222222",
        containerPath: "/verdict",
        readOnly: false,
      },
    ],
    secretNames: [
      "CLOCKCHAIN_TOKEN",
      "SEPOLIA_RPC_URL",
    ],
    taskDefinitionArn: TASK_DEFINITION_ARN,
    ...overrides,
  };
}

function evidenceDescriptor(overrides = {}) {
  return {
    descriptorDigest: "d".repeat(64),
    evidenceDigest: EVIDENCE_DIGEST,
    paymentMoved: false,
    schema: "clockchain.aws-verifier-evidence/v1",
    subjectRun: "stakeholder",
    ...overrides,
  };
}

function publication({
  attemptId = ATTEMPT_A,
  evidenceDigest = EVIDENCE_DIGEST,
  revision = 7,
  taskArn = TASK_A,
  writtenAtMs = ACTION_AT_MS + 1,
} = {}) {
  return {
    attemptId,
    evidenceDigest,
    paymentMoved: false,
    publicationDigest: PUBLICATION_DIGEST,
    repositorySha: REPOSITORY_SHA,
    revision,
    schema:
      "clockchain.aws-verifier-task-publication/v1",
    status: "VERIFICATION_PASSED",
    taskArn,
    writtenAtMs: String(writtenAtMs),
  };
}

function launcherFixture({
  definitions = [definition()],
  publications = [publication()],
  revisions = [7],
  runResults = [{
    failures: [],
    tasks: [{ taskArn: TASK_A }],
  }],
  waitResults = [{
    exitCode: 0,
    stoppedAtMs: String(ACTION_AT_MS + 2),
    taskArn: TASK_A,
  }],
} = {}) {
  const calls = [];
  const attempts = [ATTEMPT_A, ATTEMPT_B];
  const ecs = {
    async describeTaskDefinition(input) {
      calls.push(["describe", input]);
      return definitions.shift();
    },
    async runTask(input) {
      calls.push(["run", input]);
      const result = runResults.shift();
      if (result instanceof Error) throw result;
      return result;
    },
    async waitForTask(input) {
      calls.push(["wait", input]);
      const result = waitResults.shift();
      if (result instanceof Error) throw result;
      return result;
    },
  };
  const instance = createEcsVerifierLauncher({
    ecs,
    evidenceAccessPointArn:
      "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/fsap-11111111111111111",
    imageDigest: IMAGE_DIGEST,
    nowMs: () => ACTION_AT_MS,
    outputAccessPointArn:
      "arn:aws:elasticfilesystem:us-west-2:123456789012:access-point/fsap-22222222222222222",
    randomUUID: () => attempts.shift(),
    readCurrentRevision: async () =>
      revisions.shift(),
    readPublication: async (input) => {
      calls.push(["publication", input]);
      return publications.shift();
    },
    taskDefinitionArn: TASK_DEFINITION_ARN,
  });
  return { calls, instance };
}

const launchInput = Object.freeze({
  evidenceDescriptor: evidenceDescriptor(),
  expectedRevision: 7,
  releaseId: RELEASE_ID,
  repositorySha: REPOSITORY_SHA,
  sessionId: SESSION_ID,
});

test("launches one fresh digest-pinned verifier and accepts only its later publication", async () => {
  const { calls, instance } = launcherFixture();
  const result = await instance.launch(launchInput);
  assert.deepEqual(result, {
    attemptId: ATTEMPT_A,
    publicationDigest: PUBLICATION_DIGEST,
    status: "VERIFICATION_PASSED",
    taskArn: TASK_A,
  });
  assert.deepEqual(calls[0], [
    "describe",
    { taskDefinitionArn: TASK_DEFINITION_ARN },
  ]);
  assert.deepEqual(calls[1], [
    "run",
    {
      action: "VERIFY",
      attemptId: ATTEMPT_A,
      evidenceDescriptor: launchInput.evidenceDescriptor,
      expectedRevision: 7,
      releaseId: RELEASE_ID,
      repositorySha: REPOSITORY_SHA,
      sessionId: SESSION_ID,
      taskDefinitionArn: TASK_DEFINITION_ARN,
    },
  ]);
  assert.equal(
    JSON.stringify(calls).includes("operator"),
    false,
  );
  assert.equal(
    JSON.stringify(calls).includes("treasury"),
    false,
  );
});

test("uses a new attempt and task after an interrupted verifier", async () => {
  const { calls, instance } = launcherFixture({
    definitions: [definition(), definition()],
    publications: [publication({
      attemptId: ATTEMPT_B,
      taskArn: TASK_B,
    })],
    revisions: [7, 7],
    runResults: [
      { failures: [], tasks: [{ taskArn: TASK_A }] },
      { failures: [], tasks: [{ taskArn: TASK_B }] },
    ],
    waitResults: [
      new Error("interrupted"),
      {
        exitCode: 0,
        stoppedAtMs: String(ACTION_AT_MS + 2),
        taskArn: TASK_B,
      },
    ],
  });
  await assert.rejects(
    instance.launch(launchInput),
    /ECS verifier launch failed safely/,
  );
  const result = await instance.launch(launchInput);
  assert.equal(result.attemptId, ATTEMPT_B);
  assert.equal(result.taskArn, TASK_B);
  assert.deepEqual(
    calls.filter(([name]) => name === "run")
      .map(([, value]) => value.attemptId),
    [ATTEMPT_A, ATTEMPT_B],
  );
});

test("rejects stale revision, task reuse, multiple tasks, nonzero exit, and missing publication", async () => {
  for (const options of [
    { revisions: [6] },
    {
      runResults: [{
        failures: [],
        tasks: [{ taskArn: TASK_A }, { taskArn: TASK_B }],
      }],
    },
    {
      waitResults: [{
        exitCode: 1,
        stoppedAtMs: String(ACTION_AT_MS + 2),
        taskArn: TASK_A,
      }],
    },
    { publications: [null] },
  ]) {
    const { instance } = launcherFixture(options);
    await assert.rejects(
      instance.launch(launchInput),
      /ECS verifier launch failed safely/,
    );
  }

  const reused = launcherFixture({
    definitions: [definition(), definition()],
    publications: [publication(), publication()],
    revisions: [7, 7],
    runResults: [
      { failures: [], tasks: [{ taskArn: TASK_A }] },
      { failures: [], tasks: [{ taskArn: TASK_A }] },
    ],
    waitResults: [
      {
        exitCode: 0,
        stoppedAtMs: String(ACTION_AT_MS + 2),
        taskArn: TASK_A,
      },
      {
        exitCode: 0,
        stoppedAtMs: String(ACTION_AT_MS + 2),
        taskArn: TASK_A,
      },
    ],
  }).instance;
  await reused.launch(launchInput);
  await assert.rejects(
    reused.launch(launchInput),
    /ECS verifier launch failed safely/,
  );
});

test("rejects changed evidence, pre-action results, and publication scope mismatch", async () => {
  for (const changed of [
    publication({ evidenceDigest: "e".repeat(64) }),
    publication({ writtenAtMs: ACTION_AT_MS - 1 }),
    { ...publication(), repositorySha: "f".repeat(40) },
    { ...publication(), revision: 8 },
    { ...publication(), taskArn: TASK_B },
    { ...publication(), paymentMoved: true },
  ]) {
    const { instance } = launcherFixture({
      publications: [changed],
    });
    await assert.rejects(
      instance.launch(launchInput),
      /ECS verifier launch failed safely/,
    );
  }
});

test("rejects mutable or overprivileged task definitions", async () => {
  for (const changed of [
    definition({ imageDigest: "latest" }),
    definition({
      mounts: [definition().mounts[0]],
    }),
    definition({
      mounts: definition().mounts.map((mount) => ({
        ...mount,
        readOnly: false,
      })),
    }),
    definition({
      secretNames: [
        "CLOCKCHAIN_TOKEN",
        "OPERATOR_PRIVATE_KEY",
      ],
    }),
    definition({
      taskDefinitionArn:
        "arn:aws:ecs:us-west-2:123456789012:task-definition/clockchain-verifier:latest",
    }),
  ]) {
    const { instance } = launcherFixture({
      definitions: [changed],
    });
    await assert.rejects(
      instance.launch(launchInput),
      /ECS verifier launch failed safely/,
    );
  }
});
