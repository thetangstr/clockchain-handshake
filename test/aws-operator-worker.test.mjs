import assert from "node:assert/strict";
import { test } from "node:test";

import {
  applyControlAction,
  controlActionBytes,
  createInitialControlState,
} from "../src/bilateral/aws/control-actions.mjs";
import {
  processAwsOperatorMessage,
} from "../scripts/run-aws-operator-worker.mjs";

const REPOSITORY_SHA =
  "abcdef0123456789abcdef0123456789abcdef01";
const RELEASE_ID = "release-0123456789abcdef";
const SESSION_ID =
  "11111111-2222-4333-8444-555555555555";
const PAYER_FINGERPRINT = "a".repeat(64);
const REQUESTOR_FINGERPRINT = "b".repeat(64);
const IDS = Object.freeze([
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
  "33333333-3333-4333-8333-333333333333",
  "44444444-4444-4444-8444-444444444444",
  "55555555-5555-4555-8555-555555555555",
  "66666666-6666-4666-8666-666666666666",
]);

function start(overrides = {}) {
  return {
    actionId: IDS[0],
    expectedRevision: 0,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    type: "START_RUN",
    ...overrides,
  };
}

function later(type, revision, actionId, overrides = {}) {
  return {
    actionId,
    expectedRevision: revision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
    ...overrides,
  };
}

function approval(
  type,
  revision,
  actionId,
  claimFingerprint,
  overrides = {},
) {
  return {
    actionId,
    claimFingerprint,
    expectedRevision: revision,
    paymentMoved: false,
    releaseId: RELEASE_ID,
    repositorySha: REPOSITORY_SHA,
    sessionId: SESSION_ID,
    type,
    ...overrides,
  };
}

function message(action, index = 0) {
  return {
    body: controlActionBytes(action).toString("utf8"),
    messageId: `message-${index}`,
    receiptHandle: `receipt-${index}`,
  };
}

function fixture() {
  let state = createInitialControlState();
  const calls = [];
  const dependencies = {
    abortSession: async (input) => {
      calls.push(["abort", input]);
      return { paymentMoved: false, status: "ABORTED" };
    },
    approveBootstrapClaim: async (input) => {
      calls.push(["approve", input]);
      return { paymentMoved: false, status: "APPROVED" };
    },
    commitControlState: async (input) => {
      calls.push(["commit", input.action.type]);
      state = input.nextState;
    },
    createSession: async (input) => {
      calls.push(["session", input]);
      return SESSION_ID;
    },
    deleteMessage: async (input) => {
      calls.push(["delete", input.receiptHandle]);
    },
    launchCoordinator: async (input) => {
      calls.push(["coordinator", input]);
      return { paymentMoved: false, status: "RUNNING" };
    },
    launchFundingTask: async (input) => {
      calls.push(["fund", input]);
      return { paymentMoved: false, status: "FUNDED" };
    },
    launchVerifierTask: async (input) => {
      calls.push(["verify", input]);
      return {
        paymentMoved: false,
        publicationDigest: "c".repeat(64),
        status: "VERIFICATION_PASSED",
      };
    },
    readControlContext: async () => ({
      expectedClaimFingerprint:
        state.status === "RUN_STARTED"
          ? PAYER_FINGERPRINT
          : state.status === "PAYER_APPROVED"
            ? REQUESTOR_FINGERPRINT
            : null,
      state,
    }),
    recordRejection: async (input) => {
      calls.push(["reject", input.reason]);
    },
  };
  return {
    calls,
    dependencies,
    state: () => state,
  };
}

test("processes the exact sequence and deletes each message only after its durable transition", async () => {
  const fx = fixture();
  const actions = [
    start(),
    approval(
      "APPROVE_PAYER",
      1,
      IDS[1],
      PAYER_FINGERPRINT,
    ),
    approval(
      "APPROVE_REQUESTOR",
      2,
      IDS[2],
      REQUESTOR_FINGERPRINT,
    ),
    later("FUND", 3, IDS[3]),
    later("VERIFY", 4, IDS[4]),
  ];
  for (const [index, action] of actions.entries()) {
    const result = await processAwsOperatorMessage(
      message(action, index),
      fx.dependencies,
    );
    assert.equal(result.paymentMoved, false);
    assert.equal(result.status, "COMMITTED");
    const commitIndex = fx.calls.findLastIndex(
      ([name]) => name === "commit",
    );
    const deleteIndex = fx.calls.findLastIndex(
      ([name]) => name === "delete",
    );
    assert.ok(commitIndex >= 0);
    assert.ok(deleteIndex > commitIndex);
  }
  assert.equal(fx.state().status, "VERIFY_REQUESTED");
  assert.deepEqual(
    fx.calls
      .filter(([name]) =>
        [
          "session",
          "coordinator",
          "approve",
          "fund",
          "verify",
        ].includes(name))
      .map(([name]) => name),
    [
      "session",
      "coordinator",
      "approve",
      "approve",
      "fund",
      "verify",
    ],
  );
});

test("ABORT revokes the tunnel and terminates the session before commit", async () => {
  const fx = fixture();
  await processAwsOperatorMessage(
    message(start()),
    fx.dependencies,
  );
  await processAwsOperatorMessage(
    message(later("ABORT", 1, IDS[5]), 1),
    fx.dependencies,
  );
  assert.equal(fx.state().status, "ABORTED");
  const abortIndex = fx.calls.findIndex(
    ([name]) => name === "abort",
  );
  const finalCommitIndex = fx.calls.findLastIndex(
    ([name]) => name === "commit",
  );
  assert.ok(abortIndex >= 0);
  assert.ok(finalCommitIndex > abortIndex);
});

test("durably rejects malformed, duplicate, stale, cross-session, and out-of-order messages without child tasks", async () => {
  const cases = [
    {
      body: "{",
      messageId: "malformed",
      receiptHandle: "malformed-receipt",
    },
    message(
      later("FUND", 0, IDS[3]),
      1,
    ),
    message(
      later("FUND", 1, IDS[3], {
        sessionId:
          "77777777-7777-4777-8777-777777777777",
      }),
      2,
    ),
  ];
  for (const candidate of cases) {
    const fx = fixture();
    const result = await processAwsOperatorMessage(
      candidate,
      fx.dependencies,
    );
    assert.equal(result.status, "REJECTED");
    assert.equal(
      fx.calls.some(([name]) =>
        ["coordinator", "fund", "verify"].includes(name)),
      false,
    );
    assert.deepEqual(
      fx.calls.slice(-2).map(([name]) => name),
      ["reject", "delete"],
    );
  }

  const duplicate = fixture();
  await processAwsOperatorMessage(
    message(start()),
    duplicate.dependencies,
  );
  const childCount = duplicate.calls.filter(
    ([name]) => name === "coordinator",
  ).length;
  const result = await processAwsOperatorMessage(
    message(start(), 9),
    duplicate.dependencies,
  );
  assert.equal(result.status, "REJECTED");
  assert.equal(
    duplicate.calls.filter(
      ([name]) => name === "coordinator",
    ).length,
    childCount,
  );
});

test("leaves a message unacknowledged when a child transition is not durably complete", async () => {
  const fx = fixture();
  await processAwsOperatorMessage(
    message(start()),
    fx.dependencies,
  );
  const payer = approval(
    "APPROVE_PAYER",
    1,
    IDS[1],
    PAYER_FINGERPRINT,
  );
  await processAwsOperatorMessage(
    message(payer, 1),
    fx.dependencies,
  );
  const requestor = approval(
    "APPROVE_REQUESTOR",
    2,
    IDS[2],
    REQUESTOR_FINGERPRINT,
  );
  await processAwsOperatorMessage(
    message(requestor, 2),
    fx.dependencies,
  );
  fx.dependencies.launchFundingTask = async () => {
    throw new Error("ambiguous broadcast");
  };
  await assert.rejects(
    processAwsOperatorMessage(
      message(later("FUND", 3, IDS[3]), 3),
      fx.dependencies,
    ),
    /AWS operator worker failed safely/,
  );
  assert.equal(fx.state().status, "REQUESTOR_APPROVED");
  assert.equal(
    fx.calls.some(
      ([name, value]) =>
        name === "delete" && value === "receipt-3",
    ),
    false,
  );
});
