import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createAwsOperatorTransitions,
} from "../infra/aws/runtime/operator-transitions.mjs";

const COMMON = Object.freeze({
  paymentMoved: false,
  releaseId: "release-bd7662a5eeb41614",
  repositorySha:
    "abcdef0123456789abcdef0123456789abcdef01",
  sessionId:
    "11111111-1111-4111-8111-111111111111",
});

function fixture() {
  const calls = [];
  return {
    calls,
    dependencies: {
      abort: async (input) => {
        calls.push(["abort", input]);
        return {
          paymentMoved: false,
          status: "ABORTED",
        };
      },
      activateTunnel: async (input) => {
        calls.push(["tunnel", input]);
      },
      approveAndSeal: async (input) => {
        calls.push(["approve", input]);
        return {
          paymentMoved: false,
          status: "APPROVED",
        };
      },
      launch: async (kind, input) => {
        calls.push(["launch", kind, input]);
        return {
          paymentMoved: false,
          status: "RUNNING",
          taskArn:
            `arn:aws:ecs:us-west-2:123456789012:task/clockchain/${kind === "coordinator" ? "1" : kind === "funding" ? "2" : "3"}`.padEnd(
              106,
              kind === "coordinator"
                ? "1"
                : kind === "funding"
                  ? "2"
                  : "3",
            ),
        };
      },
      readExpectedClaimFingerprint:
        async (input) => {
          calls.push(["fingerprint", input]);
          return "a".repeat(64);
        },
      readResult: async (kind, input) => {
        calls.push(["result", kind, input]);
        return kind === "funding"
          ? {
              paymentMoved: false,
              status: "FUNDED",
            }
          : {
              paymentMoved: false,
              publicationDigest:
                "b".repeat(64),
              status:
                "VERIFICATION_PASSED",
            };
      },
      wait: async (kind, input) => {
        calls.push(["wait", kind, input]);
      },
    },
  };
}

test("runs coordinator detached and gates funding/verifier commits on durable results", async () => {
  const fx = fixture();
  const transitions =
    createAwsOperatorTransitions(
      COMMON,
      fx.dependencies,
    );
  assert.equal(
    await transitions.createSession({
      paymentMoved: false,
      releaseId: COMMON.releaseId,
      repositorySha:
        COMMON.repositorySha,
    }),
    COMMON.sessionId,
  );
  assert.equal(
    (
      await transitions.launchCoordinator({
        ...COMMON,
        actionId:
          "22222222-2222-4222-8222-222222222222",
        expectedRevision: 0,
      })
    ).status,
    "RUNNING",
  );
  assert.deepEqual(
    await transitions.launchFundingTask({
      ...COMMON,
      actionId:
        "33333333-3333-4333-8333-333333333333",
      expectedRevision: 3,
    }),
    {
      paymentMoved: false,
      status: "FUNDED",
    },
  );
  assert.deepEqual(
    await transitions.launchVerifierTask({
      ...COMMON,
      actionId:
        "44444444-4444-4444-8444-444444444444",
      expectedRevision: 4,
    }),
    {
      paymentMoved: false,
      publicationDigest: "b".repeat(64),
      status: "VERIFICATION_PASSED",
    },
  );
  assert.equal(
    fx.calls.some(
      ([name, kind]) =>
        name === "wait" &&
        kind === "coordinator",
    ),
    false,
  );
  assert.deepEqual(
    fx.calls
      .filter(([name]) =>
        [
          "launch",
          "wait",
          "result",
        ].includes(name))
      .map(([name, kindOrInput]) =>
        name === "launch" ||
        name === "wait" ||
        name === "result"
          ? `${name}:${kindOrInput}`
          : `${name}:${kindOrInput.identity.kind}`),
    [
      "launch:coordinator",
      "launch:funding",
      "wait:funding",
      "result:funding",
      "launch:verifier",
      "wait:verifier",
      "result:verifier",
    ],
  );
});

test("activates the tunnel only after the exact Payer claim is sealed", async () => {
  const fx = fixture();
  const transitions =
    createAwsOperatorTransitions(
      COMMON,
      fx.dependencies,
    );
  const result =
    await transitions
      .approveBootstrapClaim({
        ...COMMON,
        actionId:
          "55555555-5555-4555-8555-555555555555",
        claimFingerprint:
          "a".repeat(64),
        expectedRevision: 1,
        role: "payer",
      });
  assert.deepEqual(result, {
    paymentMoved: false,
    status: "APPROVED",
  });
  assert.deepEqual(
    fx.calls.map(([name]) => name),
    ["approve", "tunnel"],
  );
});

test("rejects any transition outside the bound release and session", async () => {
  const transitions =
    createAwsOperatorTransitions(
      COMMON,
      fixture().dependencies,
    );
  await assert.rejects(
    transitions.launchCoordinator({
      ...COMMON,
      actionId:
        "66666666-6666-4666-8666-666666666666",
      expectedRevision: 0,
      sessionId:
        "77777777-7777-4777-8777-777777777777",
    }),
    /AWS operator transitions failed safely/,
  );
});
